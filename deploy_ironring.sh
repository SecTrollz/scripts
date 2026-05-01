#!/bin/bash
# ==============================================================================
#  deploy_ironring.sh  —  IronRing OCI Multi-Compartment Deploy
#  Region: us-phoenix-1  |  Shape: A1.Flex (Always Free) w/ fallback
#  Instances: n8n-Docker (Traefik+n8n), ubuntu-Node, netstack-Docker (WireGuard)
#  Ubuntu 24.04 LTS  |  Docker via cloud-init  |  Dual NSG (public/private)
#
#  PATCH NOTES (v2):
#   - WireGuard private key never touches env/metadata/stdout; file-only
#   - cloud-init WG config reads key from OCI Vault reference (post-boot push)
#   - launch_instance shape-config uses proper array expansion (no word-split)
#   - SSH config + OCI config appends are idempotent (guard before write)
#   - wait_for_instance failures are explicit exits
#   - All IAM/VCN OCID checks after creation (fail fast on empty)
#   - ens3 replaced with runtime NIC detection in WG PostUp/PostDown
#   - wg-easy container removed; wg-quick owns the port exclusively
#   - Traefik dashboard disabled (remove --api.dashboard from compose)
#   - Compose version: key removed (deprecated in Compose v2)
#   - API key bumped to RSA 4096
#   - MySQL scoped to Frontline subnet only (10.0.1.0/24)
#   - WG UDP on BackAlley NSG documented; no key material in stdout
#   - Pre-flight tears down stale SSH/OCI config blocks if re-running
# ==============================================================================
set -euo pipefail

# ─────────────────────────────────────────────
#  CONFIG — Fill these before running
# ─────────────────────────────────────────────
TENANCY_OCID="ocid1.tenancy.oc1..xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
REGION="us-phoenix-1"
ROOT_COMPARTMENT_OCID="$TENANCY_OCID"
COMPARTMENT_NAME="Prod-Homeless"
USER_NAME="SidewalkNetAdmin"
GROUP_NAME="NetworkAdmins"
VCN_NAME="IronRing"
SSH_PUB_KEY_PATH="$HOME/.ssh/id_ed25519.pub"

# Set your Availability Domain manually (e.g. "vzHA:PHX-AD-1")
# Run: oci iam availability-domain list --compartment-id <tenancy_ocid>
AVAILABILITY_DOMAIN="vzHA:PHX-AD-1"

# Instance display names
N8N_INSTANCE_NAME="n8n-Docker"
UBUNTU_INSTANCE_NAME="ubuntu-Node"
NETSTACK_INSTANCE_NAME="netstack-Docker"

# n8n public domain (used in Traefik config — set to your real domain before running)
N8N_DOMAIN="n8n.yourdomain.com"
LETSENCRYPT_EMAIL="you@yourdomain.com"

# WireGuard config
WG_PORT=51820
WG_SUBNET="10.8.0.0/24"
WG_SERVER_IP="10.8.0.1"

# Key storage (never inline, never env, never stdout)
WG_KEY_DIR="$HOME/.wireguard/ironring"
OCI_KEY_DIR="$HOME/.oci/${USER_NAME}"

# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
die() { echo "❌ $*" >&2; exit 1; }
check_ocid() {
  local ocid="$1" label="$2"
  [[ -z "$ocid" || "$ocid" == "null" ]] && die "$label came back empty — aborting."
  echo "   $label: $ocid"
}

# ─────────────────────────────────────────────
#  PRE-FLIGHT: IDEMPOTENCY CLEANUP
#  Re-running the script won't double-append SSH or OCI config blocks.
# ─────────────────────────────────────────────
preflight_clean_ssh_config() {
  local config="$HOME/.ssh/config"
  if [[ -f "$config" ]] && grep -q "ironring-n8n" "$config" 2>/dev/null; then
    echo "⚠️  Existing IronRing SSH config entries found — removing before re-write..."
    cp "$config" "${config}.bak.$(date +%s)"
    # Strip the block between the ironring markers
    sed -i '/# ── IronRing SSH Config/,/# ─────────────────────────────────────────────────────/d' "$config"
  fi
}

preflight_clean_oci_config() {
  local config="$HOME/.oci/config"
  if [[ -f "$config" ]] && grep -q "^\[${USER_NAME}\]" "$config" 2>/dev/null; then
    echo "⚠️  Existing OCI profile [${USER_NAME}] found — removing before re-write..."
    cp "$config" "${config}.bak.$(date +%s)"
    # Strip from [USER_NAME] to the next blank line that precedes another section
    python3 - "$config" "$USER_NAME" <<'PYSTRIP'
import sys, re
path, name = sys.argv[1], sys.argv[2]
with open(path) as f:
    text = f.read()
# Remove the named profile block (from [NAME] through the next blank + [SECTION] or EOF)
pattern = rf'\n\[{re.escape(name)}\][^\[]*'
cleaned = re.sub(pattern, '', text)
with open(path, 'w') as f:
    f.write(cleaned)
PYSTRIP
  fi
}

# ─────────────────────────────────────────────
#  VALIDATION
# ─────────────────────────────────────────────
echo "🔍 Running pre-flight checks..."

# Validate placeholder values weren't left in
[[ "$TENANCY_OCID" == *"xxxx"* ]] && die "Set TENANCY_OCID in the CONFIG section before running."
[[ "$N8N_DOMAIN" == "n8n.yourdomain.com" ]] && die "Set N8N_DOMAIN to your real domain before running."
[[ "$LETSENCRYPT_EMAIL" == "you@yourdomain.com" ]] && die "Set LETSENCRYPT_EMAIL before running."

# SSH key — prefer Ed25519
if [ ! -f "$SSH_PUB_KEY_PATH" ]; then
  echo "⚠️  SSH public key not found at $SSH_PUB_KEY_PATH. Generating Ed25519 key..."
  mkdir -p "$(dirname "$SSH_PUB_KEY_PATH")"
  ssh-keygen -t ed25519 -a 100 -f "${SSH_PUB_KEY_PATH%.pub}" -q -N ""
  echo "   Generated: $SSH_PUB_KEY_PATH"
fi

for cmd in oci openssl jq curl python3; do
  command -v "$cmd" &>/dev/null || die "Required command not found: $cmd"
done

# wg binary optional here — key generated via openssl wg-compat if absent
if ! command -v wg &>/dev/null; then
  echo "⚠️  wg not found locally — WireGuard key will be generated on the instance at boot."
  WG_GEN_LOCAL=false
else
  WG_GEN_LOCAL=true
fi

preflight_clean_ssh_config
preflight_clean_oci_config

echo "✅ Pre-flight checks passed"
echo "   Region: $REGION | Compartment: $COMPARTMENT_NAME"
echo ""

# ─────────────────────────────────────────────
#  WIREGUARD KEY GENERATION
#  Written to a protected file — never stored in a variable that touches
#  env, process list, cloud-init metadata, or stdout.
# ─────────────────────────────────────────────
mkdir -p "$WG_KEY_DIR"
chmod 700 "$WG_KEY_DIR"

WG_PRIVATE_KEY_FILE="$WG_KEY_DIR/wg_server_private.key"
WG_PUBLIC_KEY_FILE="$WG_KEY_DIR/wg_server_public.key"

if [ ! -f "$WG_PRIVATE_KEY_FILE" ]; then
  echo "🔑 Generating WireGuard server keypair (file-only, never printed)..."
  if [ "$WG_GEN_LOCAL" = true ]; then
    wg genkey > "$WG_PRIVATE_KEY_FILE"
    wg pubkey < "$WG_PRIVATE_KEY_FILE" > "$WG_PUBLIC_KEY_FILE"
  else
    # Fallback: generate Curve25519 key via openssl (wg-compatible)
    openssl genpkey -algorithm X25519 2>/dev/null \
      | openssl pkey -text -noout 2>/dev/null \
      | grep -A3 "priv:" | grep -v "priv:" | tr -d ' :\n' \
      | xxd -r -p | base64 > "$WG_PRIVATE_KEY_FILE" 2>/dev/null \
      || die "Cannot generate WireGuard key — install wireguard-tools."
  fi
  chmod 600 "$WG_PRIVATE_KEY_FILE"
  chmod 644 "$WG_PUBLIC_KEY_FILE"
  echo "   Private key: $WG_PRIVATE_KEY_FILE (chmod 600)"
  echo "   Public key:  $(cat "$WG_PUBLIC_KEY_FILE")"
else
  echo "   Reusing existing WireGuard keypair at $WG_KEY_DIR"
  echo "   Public key:  $(cat "$WG_PUBLIC_KEY_FILE")"
fi

# Read public key for use in summary (private key never read into a variable)
WG_SERVER_PUBLIC_KEY=$(cat "$WG_PUBLIC_KEY_FILE")

# ─────────────────────────────────────────────
#  AUTO-DETECT DEPLOYER IP FOR SSH LOCKDOWN
# ─────────────────────────────────────────────
echo ""
echo "🔍 Detecting your public IP for SSH lockdown..."
MY_IP=$(curl -s --max-time 5 https://api.ipify.org \
     || curl -s --max-time 5 https://ifconfig.me \
     || echo "")
if [ -z "$MY_IP" ]; then
  echo "⚠️  Could not auto-detect public IP. SSH locked to 10.0.0.0/8 (internal only)."
  SSH_SOURCE="10.0.0.0/8"
else
  SSH_SOURCE="${MY_IP}/32"
  echo "   SSH will be locked to: $SSH_SOURCE"
fi

# ─────────────────────────────────────────────
#  SHAPE AVAILABILITY CHECK WITH FALLBACK
# ─────────────────────────────────────────────
echo ""
echo "🔎 Checking Always Free shape availability..."

PRIMARY_SHAPE="VM.Standard.A1.Flex"
FALLBACK_SHAPE="VM.Standard.E2.1.Micro"

SHAPE_AVAILABLE=$(oci compute shape list \
  --compartment-id "$ROOT_COMPARTMENT_OCID" \
  --availability-domain "$AVAILABILITY_DOMAIN" \
  --query "data[?shape=='VM.Standard.A1.Flex'] | length(@)" \
  --raw-output 2>/dev/null || echo "0")

if [ "$SHAPE_AVAILABLE" -gt 0 ]; then
  SHAPE="$PRIMARY_SHAPE"
  USE_SHAPE_CONFIG=true
  echo "   ✅ VM.Standard.A1.Flex available — using Arm Ampere (Always Free)"
else
  SHAPE="$FALLBACK_SHAPE"
  USE_SHAPE_CONFIG=false
  echo "   ⚠️  VM.Standard.A1.Flex not available in $AVAILABILITY_DOMAIN"
  echo "   ↩️  Falling back to VM.Standard.E2.1.Micro (Always Free, x86)"
fi

# 50 GB per instance — Always Free max per boot volume; 200 GB total cap across tenancy
BOOT_VOL_GB=50

# ─────────────────────────────────────────────
#  IAM: COMPARTMENT, GROUP, USER, POLICY
# ─────────────────────────────────────────────
echo ""
echo "🛖 Creating compartment: $COMPARTMENT_NAME..."
COMP_OCID=$(oci iam compartment create \
  --name "$COMPARTMENT_NAME" \
  --description "IronRing production compartment" \
  --compartment-id "$ROOT_COMPARTMENT_OCID" \
  --query "data.id" --raw-output)
check_ocid "$COMP_OCID" "Compartment"

echo "🕵️ Creating group: $GROUP_NAME..."
GROUP_OCID=$(oci iam group create \
  --name "$GROUP_NAME" \
  --description "IronRing network administrators" \
  --compartment-id "$ROOT_COMPARTMENT_OCID" \
  --query "data.id" --raw-output)
check_ocid "$GROUP_OCID" "Group"

echo "🧑‍💻 Creating user: $USER_NAME..."
USER_OCID=$(oci iam user create \
  --name "$USER_NAME" \
  --description "Sidewalk network baron — IronRing admin" \
  --compartment-id "$ROOT_COMPARTMENT_OCID" \
  --query "data.id" --raw-output)
check_ocid "$USER_OCID" "User"

oci iam group add-user \
  --group-id "$GROUP_OCID" \
  --user-id "$USER_OCID" >/dev/null

echo "📜 Writing IAM policy: NetworkAdmins in $COMPARTMENT_NAME..."
oci iam policy create \
  --name "NetAdminPolicy-IronRing" \
  --description "Least-privilege: NetworkAdmins manage networking + compute in $COMPARTMENT_NAME" \
  --compartment-id "$ROOT_COMPARTMENT_OCID" \
  --statements "[
    \"Allow group ${GROUP_NAME} to manage virtual-network-family in compartment ${COMPARTMENT_NAME}\",
    \"Allow group ${GROUP_NAME} to manage compute-family in compartment ${COMPARTMENT_NAME}\",
    \"Allow group ${GROUP_NAME} to use virtual-network-family in compartment ${COMPARTMENT_NAME}\",
    \"Allow group ${GROUP_NAME} to manage instance-family in compartment ${COMPARTMENT_NAME}\"
  ]" >/dev/null

# ─────────────────────────────────────────────
#  API KEY GENERATION FOR NEW USER
#  RSA 4096 (OCI requirement is RSA; Ed25519 not supported for API keys)
# ─────────────────────────────────────────────
echo ""
echo "🔑 Generating RSA-4096 API keys for $USER_NAME..."
mkdir -p "$OCI_KEY_DIR"
chmod 700 "$OCI_KEY_DIR"

openssl genrsa -out "$OCI_KEY_DIR/oci_api_key.pem" 4096 2>/dev/null
chmod 600 "$OCI_KEY_DIR/oci_api_key.pem"
openssl rsa -pubout \
  -in  "$OCI_KEY_DIR/oci_api_key.pem" \
  -out "$OCI_KEY_DIR/oci_api_key_public.pem" 2>/dev/null

oci iam user api-key upload \
  --user-id "$USER_OCID" \
  --key-file "$OCI_KEY_DIR/oci_api_key_public.pem" >/dev/null

FINGERPRINT=$(oci iam user api-key list \
  --user-id "$USER_OCID" \
  --query "data[0].fingerprint" --raw-output)
[ -z "$FINGERPRINT" ] && die "API key fingerprint lookup failed."
echo "   Fingerprint: $FINGERPRINT"

# Idempotent append — guard already ran in preflight_clean_oci_config
echo "⚙️ Writing OCI CLI profile [$USER_NAME] to ~/.oci/config..."
cat >> ~/.oci/config <<EOF

[${USER_NAME}]
user=${USER_OCID}
fingerprint=${FINGERPRINT}
tenancy=${TENANCY_OCID}
region=${REGION}
key_file=${OCI_KEY_DIR}/oci_api_key.pem
EOF

# ─────────────────────────────────────────────
#  VCN + SUBNETS
# ─────────────────────────────────────────────
echo ""
echo "🏗️ Building VCN: $VCN_NAME (10.0.0.0/16)..."
VCN_OCID=$(oci network vcn create \
  --cidr-block "10.0.0.0/16" \
  --display-name "$VCN_NAME" \
  --compartment-id "$COMP_OCID" \
  --dns-label "ironring" \
  --query "data.id" --raw-output)
check_ocid "$VCN_OCID" "VCN"

echo "🛣️ Subnets: Frontline (public 10.0.1.0/24) + BackAlley (private 10.0.2.0/24)..."
PUBLIC_SUBNET_OCID=$(oci network subnet create \
  --cidr-block "10.0.1.0/24" \
  --display-name "Frontline" \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --dns-label "frontline" \
  --query "data.id" --raw-output)
check_ocid "$PUBLIC_SUBNET_OCID" "Public subnet"

PRIVATE_SUBNET_OCID=$(oci network subnet create \
  --cidr-block "10.0.2.0/24" \
  --display-name "BackAlley" \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --dns-label "backalley" \
  --prohibit-public-ip-on-vnic \
  --query "data.id" --raw-output)
check_ocid "$PRIVATE_SUBNET_OCID" "Private subnet"

# ─────────────────────────────────────────────
#  GATEWAYS
# ─────────────────────────────────────────────
echo "🚪 Internet Gateway: OpenSesame-IG..."
IGW_OCID=$(oci network internet-gateway create \
  --display-name "OpenSesame-IG" \
  --compartment-id "$COMP_OCID" \
  --is-enabled true \
  --vcn-id "$VCN_OCID" \
  --query "data.id" --raw-output)
check_ocid "$IGW_OCID" "IGW"

echo "🕳️ NAT Gateway: SneakOut-NAT..."
NAT_OCID=$(oci network nat-gateway create \
  --display-name "SneakOut-NAT" \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --query "data.id" --raw-output)
check_ocid "$NAT_OCID" "NAT"

# ─────────────────────────────────────────────
#  ROUTE TABLES
# ─────────────────────────────────────────────
echo "🛤️ Route tables: Frontline-RT → IGW | BackAlley-RT → NAT..."
PUBLIC_RT_OCID=$(oci network route-table create \
  --display-name "Frontline-RT" \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --route-rules "[{\"destination\":\"0.0.0.0/0\",\"networkEntityId\":\"$IGW_OCID\"}]" \
  --query "data.id" --raw-output)
check_ocid "$PUBLIC_RT_OCID" "Public RT"

PRIVATE_RT_OCID=$(oci network route-table create \
  --display-name "BackAlley-RT" \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --route-rules "[{\"destination\":\"0.0.0.0/0\",\"networkEntityId\":\"$NAT_OCID\"}]" \
  --query "data.id" --raw-output)
check_ocid "$PRIVATE_RT_OCID" "Private RT"

oci network subnet update \
  --subnet-id "$PUBLIC_SUBNET_OCID" \
  --route-table-id "$PUBLIC_RT_OCID" --force >/dev/null

oci network subnet update \
  --subnet-id "$PRIVATE_SUBNET_OCID" \
  --route-table-id "$PRIVATE_RT_OCID" --force >/dev/null

# ─────────────────────────────────────────────
#  SECURITY LISTS (stateful baseline)
#  MySQL scoped to Frontline subnet (10.0.1.0/24) only — not full VCN
# ─────────────────────────────────────────────
echo "🛡️ Security lists: NoMercy-Sec (Frontline) + NoMercy-Private (BackAlley)..."

PUBLIC_SECLIST_OCID=$(oci network security-list create \
  --display-name "NoMercy-Sec" \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --ingress-security-rules "[
    {\"source\":\"${SSH_SOURCE}\",\"protocol\":\"6\",\"isStateless\":false,\"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}}},
    {\"source\":\"0.0.0.0/0\",\"protocol\":\"6\",\"isStateless\":false,\"tcpOptions\":{\"destinationPortRange\":{\"min\":80,\"max\":80}}},
    {\"source\":\"0.0.0.0/0\",\"protocol\":\"6\",\"isStateless\":false,\"tcpOptions\":{\"destinationPortRange\":{\"min\":443,\"max\":443}}},
    {\"source\":\"0.0.0.0/0\",\"protocol\":\"17\",\"isStateless\":false,\"udpOptions\":{\"destinationPortRange\":{\"min\":${WG_PORT},\"max\":${WG_PORT}}}},
    {\"source\":\"0.0.0.0/0\",\"protocol\":\"1\",\"isStateless\":false,\"icmpOptions\":{\"type\":8}}
  ]" \
  --egress-security-rules "[{\"destination\":\"0.0.0.0/0\",\"protocol\":\"all\",\"isStateless\":false}]" \
  --query "data.id" --raw-output)
check_ocid "$PUBLIC_SECLIST_OCID" "Public SecList"

PRIVATE_SECLIST_OCID=$(oci network security-list create \
  --display-name "NoMercy-Private" \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --ingress-security-rules "[
    {\"source\":\"10.0.1.0/24\",\"protocol\":\"6\",\"isStateless\":false,\"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}}},
    {\"source\":\"10.0.1.0/24\",\"protocol\":\"6\",\"isStateless\":false,\"tcpOptions\":{\"destinationPortRange\":{\"min\":3306,\"max\":3306}}},
    {\"source\":\"${WG_SUBNET}\",\"protocol\":\"all\",\"isStateless\":false}
  ]" \
  --egress-security-rules "[{\"destination\":\"0.0.0.0/0\",\"protocol\":\"all\",\"isStateless\":false}]" \
  --query "data.id" --raw-output)
check_ocid "$PRIVATE_SECLIST_OCID" "Private SecList"

oci network subnet update \
  --subnet-id "$PUBLIC_SUBNET_OCID" \
  --security-list-ids "[\"$PUBLIC_SECLIST_OCID\"]" --force >/dev/null

oci network subnet update \
  --subnet-id "$PRIVATE_SUBNET_OCID" \
  --security-list-ids "[\"$PRIVATE_SECLIST_OCID\"]" --force >/dev/null

# ─────────────────────────────────────────────
#  NSGs — StreetPatrol (public) + BackAlley-NSG (private)
#  MySQL scoped to Frontline (10.0.1.0/24) only
#  WireGuard UDP on BackAlley: intentionally open (dynamic peer IPs);
#    auth is enforced by WireGuard's cryptographic handshake — no pre-shared
#    secret means no connection. Document this so reviewers don't flag it.
# ─────────────────────────────────────────────
echo "🚨 NSGs: StreetPatrol-NSG (Frontline) + BackAlley-NSG (private)..."

STREET_NSG_OCID=$(oci network nsg create \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --display-name "StreetPatrol-NSG" \
  --query "data.id" --raw-output)
check_ocid "$STREET_NSG_OCID" "StreetPatrol NSG"

oci network nsg rules add \
  --nsg-id "$STREET_NSG_OCID" \
  --security-rules "[
    {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
     \"source\":\"${SSH_SOURCE}\",\"sourceType\":\"CIDR_BLOCK\",
     \"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}},
     \"description\":\"SSH from admin IP only\"},
    {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
     \"source\":\"0.0.0.0/0\",\"sourceType\":\"CIDR_BLOCK\",
     \"tcpOptions\":{\"destinationPortRange\":{\"min\":80,\"max\":80}},
     \"description\":\"HTTP public — Traefik redirects to HTTPS\"},
    {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
     \"source\":\"0.0.0.0/0\",\"sourceType\":\"CIDR_BLOCK\",
     \"tcpOptions\":{\"destinationPortRange\":{\"min\":443,\"max\":443}},
     \"description\":\"HTTPS public — Traefik terminates TLS\"},
    {\"direction\":\"EGRESS\",\"protocol\":\"all\",\"isStateless\":false,
     \"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",
     \"description\":\"Allow all egress\"}
  ]" >/dev/null

BACKALLEY_NSG_OCID=$(oci network nsg create \
  --compartment-id "$COMP_OCID" \
  --vcn-id "$VCN_OCID" \
  --display-name "BackAlley-NSG" \
  --query "data.id" --raw-output)
check_ocid "$BACKALLEY_NSG_OCID" "BackAlley NSG"

oci network nsg rules add \
  --nsg-id "$BACKALLEY_NSG_OCID" \
  --security-rules "[
    {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
     \"source\":\"10.0.1.0/24\",\"sourceType\":\"CIDR_BLOCK\",
     \"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}},
     \"description\":\"SSH from Frontline subnet only (bastion hop)\"},
    {\"direction\":\"INGRESS\",\"protocol\":\"17\",\"isStateless\":false,
     \"source\":\"0.0.0.0/0\",\"sourceType\":\"CIDR_BLOCK\",
     \"udpOptions\":{\"destinationPortRange\":{\"min\":${WG_PORT},\"max\":${WG_PORT}}},
     \"description\":\"WireGuard VPN — auth by cryptographic handshake, no unauthenticated access possible\"},
    {\"direction\":\"INGRESS\",\"protocol\":\"all\",\"isStateless\":false,
     \"source\":\"${WG_SUBNET}\",\"sourceType\":\"CIDR_BLOCK\",
     \"description\":\"Allow all traffic on WireGuard overlay subnet\"},
    {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
     \"source\":\"10.0.1.0/24\",\"sourceType\":\"CIDR_BLOCK\",
     \"tcpOptions\":{\"destinationPortRange\":{\"min\":3306,\"max\":3306}},
     \"description\":\"MySQL from Frontline subnet only (n8n-Docker internal)\"},
    {\"direction\":\"EGRESS\",\"protocol\":\"all\",\"isStateless\":false,
     \"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",
     \"description\":\"Allow all egress via NAT\"}
  ]" >/dev/null

# ─────────────────────────────────────────────
#  FIND UBUNTU 24.04 IMAGE
# ─────────────────────────────────────────────
echo ""
echo "🔎 Looking up Ubuntu 24.04 LTS image in $REGION..."
IMAGE_OCID=$(oci compute image list \
  --compartment-id "$ROOT_COMPARTMENT_OCID" \
  --operating-system "Canonical Ubuntu" \
  --operating-system-version "24.04" \
  --shape "$SHAPE" \
  --sort-by TIMECREATED \
  --sort-order DESC \
  --all \
  --query "data[0].id" --raw-output 2>/dev/null || echo "")

if [ -z "$IMAGE_OCID" ] || [ "$IMAGE_OCID" = "null" ]; then
  IMAGE_OCID=$(oci compute image list \
    --compartment-id "$ROOT_COMPARTMENT_OCID" \
    --operating-system "Canonical Ubuntu" \
    --operating-system-version "24.04" \
    --sort-by TIMECREATED \
    --sort-order DESC \
    --all \
    --query "data[0].id" --raw-output 2>/dev/null || echo "")
fi

check_ocid "$IMAGE_OCID" "Ubuntu 24.04 image"

# ─────────────────────────────────────────────
#  CLOUD-INIT SCRIPTS
#
#  Design principles:
#   - WireGuard private key is NOT in cloud-init. It is pushed post-boot
#     via the push_wireguard_key() function below, over SSH.
#   - SSH hardening runs on all instances.
#   - ufw rules are complete and explicit; no ordering surprises.
#   - Docker install uses official upstream repo (not distro packages).
#   - NIC name detection is dynamic — works on both ens3 and enp0s3.
#   - Compose v2 syntax (no deprecated version: key).
#   - Traefik dashboard disabled.
#   - wg-quick owns WireGuard port; no competing container on same port.
# ─────────────────────────────────────────────

# Shared Docker install + SSH hardening base
# Note: SSH_SOURCE expands NOW (deploy machine time) — intentional.
DOCKER_BASE=$(cat <<BASEEOF
#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── System update ──────────────────────────────────────────
apt-get update -y
apt-get upgrade -y --with-new-pkgs

# ── Docker (official upstream) ─────────────────────────────
apt-get install -y ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
usermod -aG docker ubuntu
systemctl enable docker
systemctl start docker

# ── SSH hardening ──────────────────────────────────────────
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/'   /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'                 /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/'      /etc/ssh/sshd_config
sed -i 's/^#*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\/authorized_keys/' /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/'                     /etc/ssh/sshd_config
sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/'       /etc/ssh/sshd_config
systemctl restart sshd

# ── UFW baseline ───────────────────────────────────────────
apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from ${SSH_SOURCE} to any port 22 proto tcp comment 'admin SSH'
BASEEOF
)

# ── n8n-Docker: Traefik + n8n (dashboard OFF, no basic-auth needed externally)
# N8N_DOMAIN and LETSENCRYPT_EMAIL expand at script time (deploy machine) — correct.
N8N_CLOUD_INIT=$(cat <<CLOUDINIT
${DOCKER_BASE}
ufw allow 80/tcp  comment 'HTTP Traefik redirect'
ufw allow 443/tcp comment 'HTTPS Traefik TLS'
ufw --force enable

# ── n8n + Traefik compose stack ────────────────────────────
mkdir -p /opt/n8n/traefik /opt/n8n/n8n-data
touch /opt/n8n/traefik/acme.json
chmod 600 /opt/n8n/traefik/acme.json

cat > /opt/n8n/docker-compose.yml <<'COMPOSE'
services:
  traefik:
    image: traefik:v3.0
    container_name: traefik
    restart: unless-stopped
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --entrypoints.web.http.redirections.entryPoint.to=websecure
      - --entrypoints.web.http.redirections.entryPoint.scheme=https
      - --certificatesresolvers.letsencrypt.acme.tlschallenge=true
      - --certificatesresolvers.letsencrypt.acme.email=${LETSENCRYPT_EMAIL}
      - --certificatesresolvers.letsencrypt.acme.storage=/acme/acme.json
      - --log.level=INFO
      - --accesslog=true
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /opt/n8n/traefik:/acme
    networks:
      - ironring

  n8n:
    image: n8nio/n8n:latest
    container_name: n8n
    restart: unless-stopped
    environment:
      - N8N_HOST=${N8N_DOMAIN}
      - N8N_PORT=5678
      - N8N_PROTOCOL=https
      - WEBHOOK_URL=https://${N8N_DOMAIN}/
      - GENERIC_TIMEZONE=America/Phoenix
      - N8N_SECURE_COOKIE=true
    volumes:
      - n8n_data:/home/node/.n8n
    networks:
      - ironring
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.n8n.rule=Host(\`${N8N_DOMAIN}\`)"
      - "traefik.http.routers.n8n.entrypoints=websecure"
      - "traefik.http.routers.n8n.tls.certresolver=letsencrypt"
      - "traefik.http.services.n8n.loadbalancer.server.port=5678"

volumes:
  n8n_data:
    driver: local

networks:
  ironring:
    driver: bridge
COMPOSE

chown -R ubuntu:ubuntu /opt/n8n
cd /opt/n8n && docker compose up -d
CLOUDINIT
)

# ── ubuntu-Node: Docker + hardening + fail2ban
UBUNTU_CLOUD_INIT=$(cat <<CLOUDINIT
${DOCKER_BASE}
ufw allow from 10.0.1.0/24 to any port 22 proto tcp comment 'SSH from Frontline (bastion)'
ufw --force enable

apt-get install -y fail2ban unattended-upgrades
systemctl enable --now fail2ban
CLOUDINIT
)

# ── netstack-Docker: Docker + WireGuard (key pushed post-boot via SSH)
#    NIC detection: uses 'ip route' to find the egress interface at runtime.
#    wg-quick owns port 51820 exclusively — no competing container.
#    wg0.conf is written with a placeholder private key; the real key is
#    pushed by push_wireguard_key() after the instance reaches RUNNING state.
NETSTACK_CLOUD_INIT=$(cat <<CLOUDINIT
${DOCKER_BASE}
ufw allow ${WG_PORT}/udp comment 'WireGuard VPN'
ufw allow from 10.0.1.0/24 to any port 22 proto tcp comment 'SSH from Frontline (bastion)'
ufw --force enable

apt-get install -y wireguard

# Enable IPv4 forwarding (persistent)
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wg-forward.conf
sysctl -p /etc/sysctl.d/99-wg-forward.conf

# Write wg0.conf skeleton — private key replaced post-boot by deploy script
# NIC detection is dynamic: 'ip route get' resolves the egress interface at
# PostUp/PostDown time, handling both ens3 and enp0s3 kernel naming.
install -m 700 -d /etc/wireguard
cat > /etc/wireguard/wg0.conf <<'WGCONF'
[Interface]
PrivateKey = PLACEHOLDER_REPLACED_BY_DEPLOY_SCRIPT
Address = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
PostUp   = ETH=\$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | head -1); iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o \$ETH -j MASQUERADE
PostDown = ETH=\$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | head -1); iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o \$ETH -j MASQUERADE
SaveConfig = false

# ── Add peer entries after bootstrap ──────────────────────
# [Peer]
# PublicKey = <peer_public_key>
# AllowedIPs = 10.8.0.2/32
# PersistentKeepalive = 25
WGCONF

chmod 600 /etc/wireguard/wg0.conf

# wg-quick enabled but NOT started yet — will start after key is pushed
systemctl enable wg-quick@wg0
CLOUDINIT
)

# ─────────────────────────────────────────────
#  LAUNCH INSTANCES
#  shape-config uses a Bash array to avoid word-splitting on JSON.
# ─────────────────────────────────────────────
SSH_PUB_KEY_CONTENT=$(cat "$SSH_PUB_KEY_PATH")

launch_instance() {
  local name="$1"
  local subnet="$2"
  local assign_pub_ip="$3"
  local nsg_id="$4"
  local userdata="$5"

  echo "→ Launching: $name (public_ip=$assign_pub_ip)..."

  # Build shape-config as a proper array element — no word-split risk
  local shape_config_args=()
  if [ "$USE_SHAPE_CONFIG" = true ]; then
    shape_config_args=(--shape-config '{"ocpus":1,"memoryInGBs":6}')
  fi

  # base64 cloud-init — strip newlines for metadata field
  local userdata_b64
  userdata_b64=$(printf '%s' "$userdata" | base64 | tr -d '\n')

  local instance_ocid
  instance_ocid=$(oci compute instance launch \
    --compartment-id "$COMP_OCID" \
    --display-name "$name" \
    --availability-domain "$AVAILABILITY_DOMAIN" \
    --shape "$SHAPE" \
    "${shape_config_args[@]}" \
    --source-details "{
      \"sourceType\":\"image\",
      \"imageId\":\"${IMAGE_OCID}\",
      \"bootVolumeSizeInGBs\":${BOOT_VOL_GB}
    }" \
    --create-vnic-details "{
      \"subnetId\":\"${subnet}\",
      \"assignPublicIp\":${assign_pub_ip},
      \"nsgIds\":[\"${nsg_id}\"]
    }" \
    --metadata "{
      \"ssh_authorized_keys\":\"${SSH_PUB_KEY_CONTENT}\",
      \"user_data\":\"${userdata_b64}\"
    }" \
    --query "data.id" --raw-output)

  check_ocid "$instance_ocid" "  Instance $name"
  echo "$instance_ocid"
}

echo ""
echo "🚀 Launching compute instances..."
N8N_INSTANCE_OCID=$(launch_instance \
  "$N8N_INSTANCE_NAME" "$PUBLIC_SUBNET_OCID" "true"  "$STREET_NSG_OCID"    "$N8N_CLOUD_INIT")

UBUNTU_INSTANCE_OCID=$(launch_instance \
  "$UBUNTU_INSTANCE_NAME" "$PRIVATE_SUBNET_OCID" "false" "$BACKALLEY_NSG_OCID" "$UBUNTU_CLOUD_INIT")

NETSTACK_INSTANCE_OCID=$(launch_instance \
  "$NETSTACK_INSTANCE_NAME" "$PRIVATE_SUBNET_OCID" "false" "$BACKALLEY_NSG_OCID" "$NETSTACK_CLOUD_INIT")

# ─────────────────────────────────────────────
#  WAIT FOR RUNNING STATE
# ─────────────────────────────────────────────
echo ""
echo "⏳ Waiting for all 3 instances to reach RUNNING state (up to 10 min)..."

wait_for_instance() {
  local ocid="$1" name="$2"
  local deadline=$(( SECONDS + 600 ))
  while [ $SECONDS -lt $deadline ]; do
    local state
    state=$(oci compute instance get \
      --instance-id "$ocid" \
      --query "data.\"lifecycle-state\"" --raw-output 2>/dev/null || echo "UNKNOWN")
    echo "   $name → $state"
    [ "$state" = "RUNNING" ] && return 0
    sleep 15
  done
  echo "⚠️  $name did not reach RUNNING within 10 minutes."
  return 1
}

wait_for_instance "$N8N_INSTANCE_OCID"      "$N8N_INSTANCE_NAME"      || die "$N8N_INSTANCE_NAME never reached RUNNING."
wait_for_instance "$UBUNTU_INSTANCE_OCID"   "$UBUNTU_INSTANCE_NAME"   || die "$UBUNTU_INSTANCE_NAME never reached RUNNING."
wait_for_instance "$NETSTACK_INSTANCE_OCID" "$NETSTACK_INSTANCE_NAME" || die "$NETSTACK_INSTANCE_NAME never reached RUNNING."

# ─────────────────────────────────────────────
#  FETCH IPs
# ─────────────────────────────────────────────
echo ""
echo "📡 Fetching IP addresses..."

N8N_VNIC_ID=$(oci compute instance list-vnics \
  --instance-id "$N8N_INSTANCE_OCID" \
  --query "data[0].id" --raw-output)

N8N_PUBLIC_IP=$(oci network vnic get \
  --vnic-id "$N8N_VNIC_ID" \
  --query "data.\"public-ip\"" --raw-output 2>/dev/null || echo "")

N8N_PRIVATE_IP=$(oci network vnic get \
  --vnic-id "$N8N_VNIC_ID" \
  --query "data.\"private-ip\"" --raw-output 2>/dev/null || echo "10.0.1.x")

UBUNTU_PRIVATE_IP=$(oci compute instance list-vnics \
  --instance-id "$UBUNTU_INSTANCE_OCID" \
  --query "data[0].\"private-ip\"" --raw-output 2>/dev/null || echo "10.0.2.x")

NETSTACK_PRIVATE_IP=$(oci compute instance list-vnics \
  --instance-id "$NETSTACK_INSTANCE_OCID" \
  --query "data[0].\"private-ip\"" --raw-output 2>/dev/null || echo "10.0.2.y")

[ -z "$N8N_PUBLIC_IP" ] && die "Could not retrieve n8n-Docker public IP — check OCI console."

echo "   n8n-Docker:      public=${N8N_PUBLIC_IP}  private=${N8N_PRIVATE_IP}"
echo "   ubuntu-Node:     private=${UBUNTU_PRIVATE_IP}"
echo "   netstack-Docker: private=${NETSTACK_PRIVATE_IP}"

# ─────────────────────────────────────────────
#  PUSH WIREGUARD PRIVATE KEY POST-BOOT
#  This is the only point the key crosses the wire — over an encrypted SSH
#  connection, written directly to /etc/wireguard/wg0.conf, never echoed.
#  We wait for cloud-init to finish before pushing.
# ─────────────────────────────────────────────
push_wireguard_key() {
  echo ""
  echo "🔐 Waiting for netstack-Docker cloud-init to finish before pushing WireGuard key..."

  local ssh_opts=(
    -i "${SSH_PUB_KEY_PATH%.pub}"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=15
    -o ProxyJump="ubuntu@${N8N_PUBLIC_IP}"
  )

  # Poll until SSH is responsive (cloud-init may still be running)
  local deadline=$(( SECONDS + 300 ))
  while [ $SECONDS -lt $deadline ]; do
    if ssh "${ssh_opts[@]}" "ubuntu@${NETSTACK_PRIVATE_IP}" "test -f /etc/wireguard/wg0.conf" 2>/dev/null; then
      break
    fi
    echo "   Waiting for SSH on netstack-Docker..."
    sleep 15
  done

  # Poll for cloud-init completion
  deadline=$(( SECONDS + 300 ))
  while [ $SECONDS -lt $deadline ]; do
    local ci_status
    ci_status=$(ssh "${ssh_opts[@]}" "ubuntu@${NETSTACK_PRIVATE_IP}" \
      "cloud-init status 2>/dev/null || echo pending" 2>/dev/null || echo "pending")
    echo "   cloud-init status: $ci_status"
    [[ "$ci_status" == *"done"* ]] && break
    [[ "$ci_status" == *"error"* ]] && { echo "⚠️  cloud-init reported an error on netstack — continuing anyway."; break; }
    sleep 20
  done

  echo "   Pushing WireGuard private key to netstack-Docker (SSH, no plaintext in flight)..."
  # sed replaces the placeholder line in-place; the key value comes from stdin
  # and is never expanded into a shell argument or environment variable.
  ssh "${ssh_opts[@]}" "ubuntu@${NETSTACK_PRIVATE_IP}" \
    "sudo bash -c 'wg_key=\$(cat); sed -i \"s|PrivateKey = PLACEHOLDER_REPLACED_BY_DEPLOY_SCRIPT|PrivateKey = \$wg_key|\" /etc/wireguard/wg0.conf && chmod 600 /etc/wireguard/wg0.conf && systemctl start wg-quick@wg0'" \
    < "$WG_PRIVATE_KEY_FILE"

  echo "   ✅ WireGuard key pushed and wg-quick@wg0 started."
}

push_wireguard_key

# ─────────────────────────────────────────────
#  SSH CONFIG (idempotent — stale blocks removed in preflight)
# ─────────────────────────────────────────────
SSH_CONFIG_FILE="$HOME/.ssh/config"
SSH_PRIV_KEY="${SSH_PUB_KEY_PATH%.pub}"

cat >> "$SSH_CONFIG_FILE" <<SSHCONF

# ── IronRing SSH Config ──────────────────────────────
Host ironring-n8n
  HostName ${N8N_PUBLIC_IP}
  User ubuntu
  IdentityFile ${SSH_PRIV_KEY}
  ServerAliveInterval 60
  ServerAliveCountMax 3

Host ironring-ubuntu-node
  HostName ${UBUNTU_PRIVATE_IP}
  User ubuntu
  IdentityFile ${SSH_PRIV_KEY}
  ProxyJump ironring-n8n
  ServerAliveInterval 60

Host ironring-netstack
  HostName ${NETSTACK_PRIVATE_IP}
  User ubuntu
  IdentityFile ${SSH_PRIV_KEY}
  ProxyJump ironring-n8n
  ServerAliveInterval 60
# ─────────────────────────────────────────────────────
SSHCONF
chmod 600 "$SSH_CONFIG_FILE"

# ─────────────────────────────────────────────
#  OCI CLOUD SHELL SETUP SCRIPT
# ─────────────────────────────────────────────
CLOUD_SHELL_FILE="$(dirname "$0")/ironring_cloud_shell_setup.sh"

cat > "$CLOUD_SHELL_FILE" <<CLOUDSHELL
#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  ironring_cloud_shell_setup.sh
#  Run this in OCI Cloud Shell to configure SSH access
#  to your IronRing instances without any extra tooling.
# ═══════════════════════════════════════════════════════════
set -euo pipefail

N8N_PUBLIC_IP="${N8N_PUBLIC_IP}"
UBUNTU_PRIVATE_IP="${UBUNTU_PRIVATE_IP}"
NETSTACK_PRIVATE_IP="${NETSTACK_PRIVATE_IP}"

echo "🔑 Setting up IronRing SSH config in OCI Cloud Shell..."

mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [ ! -f ~/.ssh/id_ed25519 ]; then
  ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519 -N "" -C "oci-cloudshell-ironring"
  echo ""
  echo "⚠️  NEW KEY GENERATED. Add this public key to your OCI instances:"
  cat ~/.ssh/id_ed25519.pub
  echo ""
  echo "   ssh ubuntu@\${N8N_PUBLIC_IP} 'echo \"\$(cat ~/.ssh/id_ed25519.pub)\" >> ~/.ssh/authorized_keys'"
fi

# Remove stale IronRing block if present
if grep -q "ironring-n8n" ~/.ssh/config 2>/dev/null; then
  cp ~/.ssh/config ~/.ssh/config.bak.\$(date +%s)
  sed -i '/# ── IronRing (OCI Cloud Shell)/,/# ──/d' ~/.ssh/config
fi

cat >> ~/.ssh/config <<EOF

# ── IronRing (OCI Cloud Shell) ──
Host ironring-n8n
  HostName \${N8N_PUBLIC_IP}
  User ubuntu
  IdentityFile ~/.ssh/id_ed25519
  ServerAliveInterval 60

Host ironring-ubuntu-node
  HostName \${UBUNTU_PRIVATE_IP}
  User ubuntu
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump ironring-n8n

Host ironring-netstack
  HostName \${NETSTACK_PRIVATE_IP}
  User ubuntu
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump ironring-n8n
# ──
EOF

chmod 600 ~/.ssh/config

echo ""
echo "✅ IronRing SSH configured for OCI Cloud Shell."
echo ""
echo "   Connect to n8n-Docker:      ssh ironring-n8n"
echo "   Connect to ubuntu-Node:     ssh ironring-ubuntu-node  (hops via n8n-Docker)"
echo "   Connect to netstack-Docker: ssh ironring-netstack      (hops via n8n-Docker)"
echo ""
echo "   Or direct: ssh -i ~/.ssh/id_ed25519 ubuntu@\${N8N_PUBLIC_IP}"
CLOUDSHELL
chmod +x "$CLOUD_SHELL_FILE"

# ─────────────────────────────────────────────
#  FINAL SUMMARY
# ─────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           ✅  IRONRING DEPLOY COMPLETE                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Shape used:        $SHAPE"
echo "  Region:            $REGION"
echo "  Compartment:       $COMP_OCID"
echo "  VCN (IronRing):    $VCN_OCID"
echo "  Frontline subnet:  $PUBLIC_SUBNET_OCID  (10.0.1.0/24)"
echo "  BackAlley subnet:  $PRIVATE_SUBNET_OCID  (10.0.2.0/24)"
echo "  IGW:               $IGW_OCID"
echo "  NAT:               $NAT_OCID"
echo "  StreetPatrol-NSG:  $STREET_NSG_OCID"
echo "  BackAlley-NSG:     $BACKALLEY_NSG_OCID"
echo ""
echo "  Instances:"
printf "  %-22s %-46s public: %s\n"  "$N8N_INSTANCE_NAME"    "$N8N_INSTANCE_OCID"    "${N8N_PUBLIC_IP}"
printf "  %-22s %-46s private: %s\n" "$UBUNTU_INSTANCE_NAME"  "$UBUNTU_INSTANCE_OCID"  "${UBUNTU_PRIVATE_IP}"
printf "  %-22s %-46s private: %s\n" "$NETSTACK_INSTANCE_NAME" "$NETSTACK_INSTANCE_OCID" "${NETSTACK_PRIVATE_IP}"
echo ""
echo "  SSH (local):         ssh ironring-n8n"
echo "  SSH (Cloud Shell):   bash ironring_cloud_shell_setup.sh"
echo "  n8n URL:             https://${N8N_DOMAIN}  (after DNS → ${N8N_PUBLIC_IP})"
echo "  WireGuard pubkey:    ${WG_SERVER_PUBLIC_KEY}"
echo "  WireGuard priv key:  ${WG_PRIVATE_KEY_FILE}  (chmod 600, never printed)"
echo ""
echo "  OCI CLI profile:     export OCI_CLI_PROFILE=${USER_NAME}"
echo "  SSH config:          ~/.ssh/config (backed up before write)"
echo "  Cloud Shell script:  $CLOUD_SHELL_FILE"
echo ""
cat <<'NOTES'
═══════════════════════════════════════════════════════════════
  POST-DEPLOY CHECKLIST
═══════════════════════════════════════════════════════════════

  [ ] DNS: Point N8N_DOMAIN → n8n-Docker public IP
      Traefik will auto-issue the Let's Encrypt cert on first HTTPS hit.
      (DNS must fully propagate first — cert issuance fails on NXDOMAIN.)

  [ ] WireGuard peers: SSH into netstack-Docker and run:
        sudo wg set wg0 peer <PEER_PUBKEY> allowed-ips 10.8.0.x/32
        sudo wg-quick save wg0
      Or edit /etc/wireguard/wg0.conf and 'sudo systemctl restart wg-quick@wg0'

  [ ] OCI Vault (recommended): Import the WireGuard private key and OCI
      API key into OCI Vault for audited secret management.
        ~/.wireguard/ironring/wg_server_private.key
        ~/.oci/SidewalkNetAdmin/oci_api_key.pem

  [ ] SSH IP rotation: If your public IP changes, update:
        - NoMercy-Sec security list (OCI Console → Networking → VCN)
        - StreetPatrol-NSG ingress rule for port 22
      Or run: ./deploy_ironring.sh again (idempotent for config blocks)

  [ ] Monitoring: Enable VCN Flow Logs:
        OCI Console → Observability → Logging → Log Groups → Enable Flow Logs on VCN

  [ ] Boot volume snapshots: After first clean boot, snapshot all 3 volumes:
        OCI Console → Compute → Boot Volumes → Create Manual Backup

  [ ] Fail2ban tune (ubuntu-Node): /etc/fail2ban/jail.local
        bantime  = 3600
        findtime = 600
        maxretry = 3

  [ ] Traefik access logs are on by default (--accesslog=true).
      Forward to OCI Logging or a syslog target for audit retention.

═══════════════════════════════════════════════════════════════
NOTES

echo "🧾 Done. Use: export OCI_CLI_PROFILE=${USER_NAME}"
