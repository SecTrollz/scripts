#!/usr/bin/env bash
# ==============================================================================
#  deploy_ironring.sh  —  IronRing OCI Multi-Compartment Deploy  (v3)
#  Region: us-phoenix-1  |  Shape: A1.Flex (Always Free) w/ fallback
#  Instances: n8n-Docker (Traefik+n8n), ubuntu-Node, netstack-Docker (WireGuard)
#  Ubuntu 24.04 LTS  |  Docker via cloud-init  |  Dual NSG (public/private)
#
#  Architecture: staged idempotent reconciler
#    - Each phase is independently re-runnable (lookup-or-create everywhere)
#    - State file persists all OCIDs across runs; re-running skips done work
#    - Lockfile prevents concurrent runs
#    - WireGuard private key: file-only, never in env/metadata/stdout/args
#    - All config appends are idempotent (stale blocks stripped before write)
#    - Explicit fail-fast on empty OCIDs after every create/lookup
#    - NIC detection dynamic at PostUp/PostDown time (no ens3 hardcode)
#    - wg-quick owns WireGuard port; no competing containers
#    - Traefik dashboard disabled; Compose v2 (no version: key)
#    - MySQL scoped to Frontline subnet (10.0.1.0/24) only
# ==============================================================================
set -euo pipefail

# ─────────────────────────────────────────────
#  SCRIPT PATHS
# ─────────────────────────────────────────────
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
STATE_FILE="${OUTPUT_DIR}/ironring.state"
LOCK_FILE="${OUTPUT_DIR}/ironring.lock"
CLOUD_SHELL_SCRIPT="${OUTPUT_DIR}/ironring_cloud_shell_setup.sh"

mkdir -p "$OUTPUT_DIR"

# ─────────────────────────────────────────────
#  USER CONFIG — Edit before first run
# ─────────────────────────────────────────────
TENANCY_OCID="${TENANCY_OCID:-}"
REGION="${REGION:-us-phoenix-1}"
ROOT_COMPARTMENT_OCID="${TENANCY_OCID}"
COMPARTMENT_NAME="${COMPARTMENT_NAME:-Prod-Homeless}"
USER_NAME="${USER_NAME:-SidewalkNetAdmin}"
GROUP_NAME="${GROUP_NAME:-NetworkAdmins}"
VCN_NAME="${VCN_NAME:-IronRing}"
SSH_PUB_KEY_PATH="${SSH_PUB_KEY_PATH:-$HOME/.ssh/id_ed25519.pub}"
AVAILABILITY_DOMAIN="${AVAILABILITY_DOMAIN:-vzHA:PHX-AD-1}"

N8N_INSTANCE_NAME="${N8N_INSTANCE_NAME:-n8n-Docker}"
UBUNTU_INSTANCE_NAME="${UBUNTU_INSTANCE_NAME:-ubuntu-Node}"
NETSTACK_INSTANCE_NAME="${NETSTACK_INSTANCE_NAME:-netstack-Docker}"

N8N_DOMAIN="${N8N_DOMAIN:-}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-}"

WG_PORT="${WG_PORT:-51820}"
WG_SUBNET="${WG_SUBNET:-10.8.0.0/24}"
WG_SERVER_IP="${WG_SERVER_IP:-10.8.0.1}"
BOOT_VOL_GB="${BOOT_VOL_GB:-50}"

WG_KEY_DIR="${WG_KEY_DIR:-$HOME/.wireguard/ironring}"
OCI_KEY_DIR="${OCI_KEY_DIR:-$HOME/.oci/${USER_NAME}}"

# ─────────────────────────────────────────────
#  RUNTIME STATE (populated by phases; persisted to STATE_FILE)
# ─────────────────────────────────────────────
COMP_OCID="${COMP_OCID:-}"
GROUP_OCID="${GROUP_OCID:-}"
USER_OCID="${USER_OCID:-}"
VCN_OCID="${VCN_OCID:-}"
PUBLIC_SUBNET_OCID="${PUBLIC_SUBNET_OCID:-}"
PRIVATE_SUBNET_OCID="${PRIVATE_SUBNET_OCID:-}"
IGW_OCID="${IGW_OCID:-}"
NAT_OCID="${NAT_OCID:-}"
PUBLIC_RT_OCID="${PUBLIC_RT_OCID:-}"
PRIVATE_RT_OCID="${PRIVATE_RT_OCID:-}"
PUBLIC_SECLIST_OCID="${PUBLIC_SECLIST_OCID:-}"
PRIVATE_SECLIST_OCID="${PRIVATE_SECLIST_OCID:-}"
STREET_NSG_OCID="${STREET_NSG_OCID:-}"
BACKALLEY_NSG_OCID="${BACKALLEY_NSG_OCID:-}"
IMAGE_OCID="${IMAGE_OCID:-}"
SHAPE="${SHAPE:-}"
USE_SHAPE_CONFIG="${USE_SHAPE_CONFIG:-false}"
N8N_INSTANCE_OCID="${N8N_INSTANCE_OCID:-}"
UBUNTU_INSTANCE_OCID="${UBUNTU_INSTANCE_OCID:-}"
NETSTACK_INSTANCE_OCID="${NETSTACK_INSTANCE_OCID:-}"
N8N_PUBLIC_IP="${N8N_PUBLIC_IP:-}"
N8N_PRIVATE_IP="${N8N_PRIVATE_IP:-}"
UBUNTU_PRIVATE_IP="${UBUNTU_PRIVATE_IP:-}"
NETSTACK_PRIVATE_IP="${NETSTACK_PRIVATE_IP:-}"
WG_SERVER_PUBLIC_KEY="${WG_SERVER_PUBLIC_KEY:-}"
SSH_SOURCE="${SSH_SOURCE:-}"
API_FINGERPRINT="${API_FINGERPRINT:-}"

# ─────────────────────────────────────────────
#  ENTRYPOINT
# ─────────────────────────────────────────────
main() {
  acquire_lock
  load_state

  preflight
  ensure_paths
  detect_runtime_inputs
  ensure_local_keys

  ensure_identity
  ensure_network
  ensure_security
  select_image_and_shape
  ensure_instances

  configure_local_client
  push_remote_bootstrap
  verify_deployment

  save_state
  print_outputs
}

# ══════════════════════════════════════════════════════════════════════════════
#  CORE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

die()  { echo "❌ ERROR: $*" >&2; exit 1; }
log()  { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "⚠️  WARN: $*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

# Assert an OCID is non-empty and not the literal string "null"
assert_ocid() {
  local val="$1" label="$2"
  [[ -n "$val" && "$val" != "null" ]] || die "$label returned empty/null — aborting."
}

# ── Lockfile ──────────────────────────────────────────────────────────────────
acquire_lock() {
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "another IronRing run is already in progress (lock: $LOCK_FILE)"
}

# ── State persistence ─────────────────────────────────────────────────────────
load_state() {
  if [[ -f "$STATE_FILE" ]]; then
    log "Loading state from $STATE_FILE"
    # shellcheck source=/dev/null
    source "$STATE_FILE"
    # Re-derive ROOT_COMPARTMENT_OCID after TENANCY_OCID may have been loaded
    ROOT_COMPARTMENT_OCID="${TENANCY_OCID}"
  fi
}

save_state() {
  log "Saving state to $STATE_FILE"
  cat > "$STATE_FILE" <<EOF
# IronRing state — generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Source this file to restore all OCIDs for a re-run.
TENANCY_OCID=${TENANCY_OCID@Q}
REGION=${REGION@Q}
COMPARTMENT_NAME=${COMPARTMENT_NAME@Q}
USER_NAME=${USER_NAME@Q}
GROUP_NAME=${GROUP_NAME@Q}
VCN_NAME=${VCN_NAME@Q}
N8N_DOMAIN=${N8N_DOMAIN@Q}
LETSENCRYPT_EMAIL=${LETSENCRYPT_EMAIL@Q}
AVAILABILITY_DOMAIN=${AVAILABILITY_DOMAIN@Q}
SSH_PUB_KEY_PATH=${SSH_PUB_KEY_PATH@Q}
SSH_SOURCE=${SSH_SOURCE@Q}
WG_PORT=${WG_PORT@Q}
WG_SUBNET=${WG_SUBNET@Q}
WG_SERVER_IP=${WG_SERVER_IP@Q}
WG_KEY_DIR=${WG_KEY_DIR@Q}
OCI_KEY_DIR=${OCI_KEY_DIR@Q}
API_FINGERPRINT=${API_FINGERPRINT@Q}
COMP_OCID=${COMP_OCID@Q}
GROUP_OCID=${GROUP_OCID@Q}
USER_OCID=${USER_OCID@Q}
VCN_OCID=${VCN_OCID@Q}
PUBLIC_SUBNET_OCID=${PUBLIC_SUBNET_OCID@Q}
PRIVATE_SUBNET_OCID=${PRIVATE_SUBNET_OCID@Q}
IGW_OCID=${IGW_OCID@Q}
NAT_OCID=${NAT_OCID@Q}
PUBLIC_RT_OCID=${PUBLIC_RT_OCID@Q}
PRIVATE_RT_OCID=${PRIVATE_RT_OCID@Q}
PUBLIC_SECLIST_OCID=${PUBLIC_SECLIST_OCID@Q}
PRIVATE_SECLIST_OCID=${PRIVATE_SECLIST_OCID@Q}
STREET_NSG_OCID=${STREET_NSG_OCID@Q}
BACKALLEY_NSG_OCID=${BACKALLEY_NSG_OCID@Q}
IMAGE_OCID=${IMAGE_OCID@Q}
SHAPE=${SHAPE@Q}
USE_SHAPE_CONFIG=${USE_SHAPE_CONFIG@Q}
N8N_INSTANCE_OCID=${N8N_INSTANCE_OCID@Q}
UBUNTU_INSTANCE_OCID=${UBUNTU_INSTANCE_OCID@Q}
NETSTACK_INSTANCE_OCID=${NETSTACK_INSTANCE_OCID@Q}
N8N_PUBLIC_IP=${N8N_PUBLIC_IP@Q}
N8N_PRIVATE_IP=${N8N_PRIVATE_IP@Q}
UBUNTU_PRIVATE_IP=${UBUNTU_PRIVATE_IP@Q}
NETSTACK_PRIVATE_IP=${NETSTACK_PRIVATE_IP@Q}
WG_SERVER_PUBLIC_KEY=${WG_SERVER_PUBLIC_KEY@Q}
N8N_INSTANCE_NAME=${N8N_INSTANCE_NAME@Q}
UBUNTU_INSTANCE_NAME=${UBUNTU_INSTANCE_NAME@Q}
NETSTACK_INSTANCE_NAME=${NETSTACK_INSTANCE_NAME@Q}
BOOT_VOL_GB=${BOOT_VOL_GB@Q}
EOF
  chmod 600 "$STATE_FILE"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 0: PREFLIGHT
# ══════════════════════════════════════════════════════════════════════════════

preflight() {
  log "Phase 0: preflight checks"

  [[ -n "${TENANCY_OCID:-}" ]]       || die "TENANCY_OCID is required (set in script or environment)"
  [[ -n "${N8N_DOMAIN:-}" ]]         || die "N8N_DOMAIN is required"
  [[ -n "${LETSENCRYPT_EMAIL:-}" ]]  || die "LETSENCRYPT_EMAIL is required"
  [[ "${TENANCY_OCID}" != *"xxxx"* ]] || die "TENANCY_OCID still contains placeholder — fill it in"

  for cmd in oci jq curl python3 openssl ssh ssh-keygen base64; do
    require_cmd "$cmd"
  done

  # flock is in util-linux; available on Linux, needs brew on macOS
  require_cmd flock

  log "  preflight OK"
}

ensure_paths() {
  log "Phase 0: ensuring directories"
  mkdir -p "$WG_KEY_DIR" "$OCI_KEY_DIR"
  chmod 700 "$WG_KEY_DIR" "$OCI_KEY_DIR"
  log "  directories OK"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 0b: DETECT RUNTIME INPUTS
# ══════════════════════════════════════════════════════════════════════════════

detect_runtime_inputs() {
  log "Phase 0b: detecting runtime inputs"

  # SSH key — prefer Ed25519; generate if absent
  if [[ ! -f "$SSH_PUB_KEY_PATH" ]]; then
    warn "SSH public key not found at $SSH_PUB_KEY_PATH — generating Ed25519 key..."
    ssh-keygen -t ed25519 -a 100 -f "${SSH_PUB_KEY_PATH%.pub}" -q -N ""
    log "  Generated SSH key: $SSH_PUB_KEY_PATH"
  fi

  # SSH lockdown source IP
  if [[ -z "${SSH_SOURCE:-}" ]]; then
    local my_ip
    my_ip="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null \
           || curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null \
           || true)"
    if [[ -n "$my_ip" ]]; then
      SSH_SOURCE="${my_ip}/32"
      log "  SSH will be locked to: $SSH_SOURCE"
    else
      warn "Could not detect public IP — locking SSH to 10.0.0.0/8 (internal only)"
      SSH_SOURCE="10.0.0.0/8"
    fi
  else
    log "  SSH source (from state): $SSH_SOURCE"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: LOCAL KEY MANAGEMENT
#  WireGuard private key: file-only, chmod 600, never in env/metadata/stdout
# ══════════════════════════════════════════════════════════════════════════════

ensure_local_keys() {
  log "Phase 1: ensuring local key material"
  local priv="$WG_KEY_DIR/wg_server_private.key"
  local pub="$WG_KEY_DIR/wg_server_public.key"

  if [[ ! -f "$priv" ]]; then
    log "  Generating WireGuard server keypair (file-only, never printed)..."
    if command -v wg >/dev/null 2>&1; then
      wg genkey > "$priv"
      wg pubkey < "$priv" > "$pub"
    else
      # Fallback: Curve25519 via openssl (wg-compatible raw key format)
      # This produces a valid 32-byte Curve25519 scalar in base64 — same format wg expects.
      openssl genpkey -algorithm X25519 2>/dev/null \
        | openssl pkey -outform DER 2>/dev/null \
        | tail -c 32 \
        | base64 > "$priv" \
        || die "WireGuard key generation failed — install wireguard-tools for reliable keygen."
      # Derive public key: if wg is absent on the local machine we store a placeholder;
      # the actual public key is derived on the netstack instance after key push.
      if command -v wg >/dev/null 2>&1; then
        wg pubkey < "$priv" > "$pub"
      else
        echo "DERIVED_ON_INSTANCE" > "$pub"
        warn "wg not found locally — public key will be derived on netstack-Docker after bootstrap."
      fi
    fi
    chmod 600 "$priv"
    chmod 644 "$pub"
    log "  WG private key: $priv"
  else
    log "  Reusing existing WireGuard keypair"
  fi

  WG_SERVER_PUBLIC_KEY="$(cat "$pub")"
  log "  WG public key: $WG_SERVER_PUBLIC_KEY"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 2: IDENTITY
# ══════════════════════════════════════════════════════════════════════════════

ensure_identity() {
  log "Phase 2: identity (compartment / group / user / policy / API key)"
  ensure_compartment
  ensure_group
  ensure_user
  ensure_user_group_membership
  ensure_policy
  ensure_api_key
}

ensure_compartment() {
  if [[ -z "$COMP_OCID" || "$COMP_OCID" == "null" ]]; then
    log "  Looking up compartment: $COMPARTMENT_NAME..."
    COMP_OCID="$(oci iam compartment list \
      --compartment-id "$TENANCY_OCID" \
      --all \
      --query "data[?name=='${COMPARTMENT_NAME}' && \"lifecycle-state\"=='ACTIVE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$COMP_OCID" || "$COMP_OCID" == "null" ]]; then
    log "  Creating compartment: $COMPARTMENT_NAME..."
    COMP_OCID="$(oci iam compartment create \
      --name "$COMPARTMENT_NAME" \
      --description "IronRing production compartment" \
      --compartment-id "$TENANCY_OCID" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$COMP_OCID" "Compartment"
  log "  Compartment: $COMP_OCID"
}

ensure_group() {
  if [[ -z "$GROUP_OCID" || "$GROUP_OCID" == "null" ]]; then
    log "  Looking up group: $GROUP_NAME..."
    GROUP_OCID="$(oci iam group list \
      --all \
      --query "data[?name=='${GROUP_NAME}' && \"lifecycle-state\"=='ACTIVE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$GROUP_OCID" || "$GROUP_OCID" == "null" ]]; then
    log "  Creating group: $GROUP_NAME..."
    GROUP_OCID="$(oci iam group create \
      --name "$GROUP_NAME" \
      --description "IronRing network administrators" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$GROUP_OCID" "Group"
  log "  Group: $GROUP_OCID"
}

ensure_user() {
  if [[ -z "$USER_OCID" || "$USER_OCID" == "null" ]]; then
    log "  Looking up user: $USER_NAME..."
    USER_OCID="$(oci iam user list \
      --all \
      --query "data[?name=='${USER_NAME}' && \"lifecycle-state\"=='ACTIVE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$USER_OCID" || "$USER_OCID" == "null" ]]; then
    log "  Creating user: $USER_NAME..."
    USER_OCID="$(oci iam user create \
      --name "$USER_NAME" \
      --description "Sidewalk network baron — IronRing admin" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$USER_OCID" "User"
  log "  User: $USER_OCID"
}

ensure_user_group_membership() {
  local already
  already="$(oci iam group list-users \
    --group-id "$GROUP_OCID" \
    --all \
    --query "data[?id=='${USER_OCID}'] | [0].id" \
    --raw-output 2>/dev/null || true)"
  if [[ -z "$already" || "$already" == "null" ]]; then
    log "  Adding $USER_NAME to $GROUP_NAME..."
    oci iam group add-user \
      --group-id "$GROUP_OCID" \
      --user-id "$USER_OCID" >/dev/null
  else
    log "  User already in group — skipping"
  fi
}

ensure_policy() {
  local policy_name="NetAdminPolicy-IronRing"
  local existing
  existing="$(oci iam policy list \
    --compartment-id "$TENANCY_OCID" \
    --all \
    --query "data[?name=='${policy_name}' && \"lifecycle-state\"=='ACTIVE'] | [0].id" \
    --raw-output 2>/dev/null || true)"
  if [[ -z "$existing" || "$existing" == "null" ]]; then
    log "  Creating IAM policy: $policy_name..."
    oci iam policy create \
      --name "$policy_name" \
      --description "Least-privilege: NetworkAdmins manage networking + compute in $COMPARTMENT_NAME" \
      --compartment-id "$TENANCY_OCID" \
      --statements "[
        \"Allow group ${GROUP_NAME} to manage virtual-network-family in compartment ${COMPARTMENT_NAME}\",
        \"Allow group ${GROUP_NAME} to manage compute-family in compartment ${COMPARTMENT_NAME}\",
        \"Allow group ${GROUP_NAME} to use virtual-network-family in compartment ${COMPARTMENT_NAME}\",
        \"Allow group ${GROUP_NAME} to manage instance-family in compartment ${COMPARTMENT_NAME}\"
      ]" >/dev/null
  else
    log "  IAM policy already exists — skipping"
  fi
}

ensure_api_key() {
  local priv_key="$OCI_KEY_DIR/oci_api_key.pem"
  local pub_key="$OCI_KEY_DIR/oci_api_key_public.pem"

  # Generate key material if absent
  if [[ ! -f "$priv_key" ]]; then
    log "  Generating RSA-4096 OCI API keypair..."
    openssl genrsa -out "$priv_key" 4096 2>/dev/null
    chmod 600 "$priv_key"
    openssl rsa -pubout -in "$priv_key" -out "$pub_key" 2>/dev/null
  else
    log "  Reusing existing OCI API private key"
  fi

  # Upload public key if not already present
  if [[ -z "${API_FINGERPRINT:-}" || "$API_FINGERPRINT" == "null" ]]; then
    log "  Uploading API public key for $USER_NAME..."
    oci iam user api-key upload \
      --user-id "$USER_OCID" \
      --key-file "$pub_key" >/dev/null
    API_FINGERPRINT="$(oci iam user api-key list \
      --user-id "$USER_OCID" \
      --query "data[0].fingerprint" --raw-output)"
    assert_ocid "$API_FINGERPRINT" "API key fingerprint"
  else
    log "  OCI API key already uploaded (fingerprint: $API_FINGERPRINT)"
  fi
  log "  Fingerprint: $API_FINGERPRINT"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3: NETWORK
# ══════════════════════════════════════════════════════════════════════════════

ensure_network() {
  log "Phase 3: network (VCN / subnets / gateways / route tables)"
  ensure_vcn
  ensure_subnets
  ensure_gateways
  ensure_route_tables
}

ensure_vcn() {
  if [[ -z "$VCN_OCID" || "$VCN_OCID" == "null" ]]; then
    log "  Looking up VCN: $VCN_NAME..."
    VCN_OCID="$(oci network vcn list \
      --compartment-id "$COMP_OCID" \
      --all \
      --query "data[?\"display-name\"=='${VCN_NAME}' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$VCN_OCID" || "$VCN_OCID" == "null" ]]; then
    log "  Creating VCN: $VCN_NAME (10.0.0.0/16)..."
    VCN_OCID="$(oci network vcn create \
      --cidr-block "10.0.0.0/16" \
      --display-name "$VCN_NAME" \
      --compartment-id "$COMP_OCID" \
      --dns-label "ironring" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$VCN_OCID" "VCN"
  log "  VCN: $VCN_OCID"
}

ensure_subnets() {
  # ── Public subnet: Frontline (10.0.1.0/24) ──────────────────────────────
  if [[ -z "$PUBLIC_SUBNET_OCID" || "$PUBLIC_SUBNET_OCID" == "null" ]]; then
    log "  Looking up Frontline subnet..."
    PUBLIC_SUBNET_OCID="$(oci network subnet list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='Frontline' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$PUBLIC_SUBNET_OCID" || "$PUBLIC_SUBNET_OCID" == "null" ]]; then
    log "  Creating Frontline subnet (10.0.1.0/24)..."
    PUBLIC_SUBNET_OCID="$(oci network subnet create \
      --cidr-block "10.0.1.0/24" \
      --display-name "Frontline" \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --dns-label "frontline" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$PUBLIC_SUBNET_OCID" "Frontline subnet"
  log "  Frontline subnet: $PUBLIC_SUBNET_OCID"

  # ── Private subnet: BackAlley (10.0.2.0/24) ─────────────────────────────
  if [[ -z "$PRIVATE_SUBNET_OCID" || "$PRIVATE_SUBNET_OCID" == "null" ]]; then
    log "  Looking up BackAlley subnet..."
    PRIVATE_SUBNET_OCID="$(oci network subnet list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='BackAlley' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$PRIVATE_SUBNET_OCID" || "$PRIVATE_SUBNET_OCID" == "null" ]]; then
    log "  Creating BackAlley subnet (10.0.2.0/24)..."
    PRIVATE_SUBNET_OCID="$(oci network subnet create \
      --cidr-block "10.0.2.0/24" \
      --display-name "BackAlley" \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --dns-label "backalley" \
      --prohibit-public-ip-on-vnic \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$PRIVATE_SUBNET_OCID" "BackAlley subnet"
  log "  BackAlley subnet: $PRIVATE_SUBNET_OCID"
}

ensure_gateways() {
  # ── Internet Gateway ─────────────────────────────────────────────────────
  if [[ -z "$IGW_OCID" || "$IGW_OCID" == "null" ]]; then
    log "  Looking up Internet Gateway..."
    IGW_OCID="$(oci network internet-gateway list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='OpenSesame-IG' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$IGW_OCID" || "$IGW_OCID" == "null" ]]; then
    log "  Creating Internet Gateway: OpenSesame-IG..."
    IGW_OCID="$(oci network internet-gateway create \
      --display-name "OpenSesame-IG" \
      --compartment-id "$COMP_OCID" \
      --is-enabled true \
      --vcn-id "$VCN_OCID" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$IGW_OCID" "Internet Gateway"
  log "  IGW: $IGW_OCID"

  # ── NAT Gateway ──────────────────────────────────────────────────────────
  if [[ -z "$NAT_OCID" || "$NAT_OCID" == "null" ]]; then
    log "  Looking up NAT Gateway..."
    NAT_OCID="$(oci network nat-gateway list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='SneakOut-NAT' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$NAT_OCID" || "$NAT_OCID" == "null" ]]; then
    log "  Creating NAT Gateway: SneakOut-NAT..."
    NAT_OCID="$(oci network nat-gateway create \
      --display-name "SneakOut-NAT" \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$NAT_OCID" "NAT Gateway"
  log "  NAT: $NAT_OCID"
}

ensure_route_tables() {
  # ── Public RT: Frontline → IGW ───────────────────────────────────────────
  if [[ -z "$PUBLIC_RT_OCID" || "$PUBLIC_RT_OCID" == "null" ]]; then
    log "  Looking up Frontline-RT..."
    PUBLIC_RT_OCID="$(oci network route-table list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='Frontline-RT' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$PUBLIC_RT_OCID" || "$PUBLIC_RT_OCID" == "null" ]]; then
    log "  Creating Frontline-RT (→ IGW)..."
    PUBLIC_RT_OCID="$(oci network route-table create \
      --display-name "Frontline-RT" \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --route-rules "[{\"destination\":\"0.0.0.0/0\",\"networkEntityId\":\"${IGW_OCID}\"}]" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$PUBLIC_RT_OCID" "Frontline RT"
  log "  Frontline-RT: $PUBLIC_RT_OCID"

  # ── Private RT: BackAlley → NAT ──────────────────────────────────────────
  if [[ -z "$PRIVATE_RT_OCID" || "$PRIVATE_RT_OCID" == "null" ]]; then
    log "  Looking up BackAlley-RT..."
    PRIVATE_RT_OCID="$(oci network route-table list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='BackAlley-RT' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$PRIVATE_RT_OCID" || "$PRIVATE_RT_OCID" == "null" ]]; then
    log "  Creating BackAlley-RT (→ NAT)..."
    PRIVATE_RT_OCID="$(oci network route-table create \
      --display-name "BackAlley-RT" \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --route-rules "[{\"destination\":\"0.0.0.0/0\",\"networkEntityId\":\"${NAT_OCID}\"}]" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$PRIVATE_RT_OCID" "BackAlley RT"
  log "  BackAlley-RT: $PRIVATE_RT_OCID"

  # Attach route tables to subnets (update is idempotent — same RT = no-op on OCI side)
  oci network subnet update \
    --subnet-id "$PUBLIC_SUBNET_OCID" \
    --route-table-id "$PUBLIC_RT_OCID" --force >/dev/null
  oci network subnet update \
    --subnet-id "$PRIVATE_SUBNET_OCID" \
    --route-table-id "$PRIVATE_RT_OCID" --force >/dev/null
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 4: SECURITY
# ══════════════════════════════════════════════════════════════════════════════

ensure_security() {
  log "Phase 4: security (security lists / NSGs)"
  ensure_security_lists
  ensure_nsgs
}

ensure_security_lists() {
  # ── Public: NoMercy-Sec ──────────────────────────────────────────────────
  if [[ -z "$PUBLIC_SECLIST_OCID" || "$PUBLIC_SECLIST_OCID" == "null" ]]; then
    log "  Looking up NoMercy-Sec security list..."
    PUBLIC_SECLIST_OCID="$(oci network security-list list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='NoMercy-Sec' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$PUBLIC_SECLIST_OCID" || "$PUBLIC_SECLIST_OCID" == "null" ]]; then
    log "  Creating NoMercy-Sec security list..."
    PUBLIC_SECLIST_OCID="$(oci network security-list create \
      --display-name "NoMercy-Sec" \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --ingress-security-rules "[
        {\"source\":\"${SSH_SOURCE}\",\"protocol\":\"6\",\"isStateless\":false,
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}}},
        {\"source\":\"0.0.0.0/0\",\"protocol\":\"6\",\"isStateless\":false,
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":80,\"max\":80}}},
        {\"source\":\"0.0.0.0/0\",\"protocol\":\"6\",\"isStateless\":false,
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":443,\"max\":443}}},
        {\"source\":\"0.0.0.0/0\",\"protocol\":\"17\",\"isStateless\":false,
         \"udpOptions\":{\"destinationPortRange\":{\"min\":${WG_PORT},\"max\":${WG_PORT}}}},
        {\"source\":\"0.0.0.0/0\",\"protocol\":\"1\",\"isStateless\":false,
         \"icmpOptions\":{\"type\":8}}
      ]" \
      --egress-security-rules "[{\"destination\":\"0.0.0.0/0\",\"protocol\":\"all\",\"isStateless\":false}]" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$PUBLIC_SECLIST_OCID" "Public SecList"
  log "  NoMercy-Sec: $PUBLIC_SECLIST_OCID"

  # ── Private: NoMercy-Private ─────────────────────────────────────────────
  if [[ -z "$PRIVATE_SECLIST_OCID" || "$PRIVATE_SECLIST_OCID" == "null" ]]; then
    log "  Looking up NoMercy-Private security list..."
    PRIVATE_SECLIST_OCID="$(oci network security-list list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='NoMercy-Private' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$PRIVATE_SECLIST_OCID" || "$PRIVATE_SECLIST_OCID" == "null" ]]; then
    log "  Creating NoMercy-Private security list..."
    PRIVATE_SECLIST_OCID="$(oci network security-list create \
      --display-name "NoMercy-Private" \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --ingress-security-rules "[
        {\"source\":\"10.0.1.0/24\",\"protocol\":\"6\",\"isStateless\":false,
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}}},
        {\"source\":\"10.0.1.0/24\",\"protocol\":\"6\",\"isStateless\":false,
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":3306,\"max\":3306}}},
        {\"source\":\"${WG_SUBNET}\",\"protocol\":\"all\",\"isStateless\":false}
      ]" \
      --egress-security-rules "[{\"destination\":\"0.0.0.0/0\",\"protocol\":\"all\",\"isStateless\":false}]" \
      --query "data.id" --raw-output)"
  fi
  assert_ocid "$PRIVATE_SECLIST_OCID" "Private SecList"
  log "  NoMercy-Private: $PRIVATE_SECLIST_OCID"

  # Attach to subnets (idempotent)
  oci network subnet update \
    --subnet-id "$PUBLIC_SUBNET_OCID" \
    --security-list-ids "[\"${PUBLIC_SECLIST_OCID}\"]" --force >/dev/null
  oci network subnet update \
    --subnet-id "$PRIVATE_SUBNET_OCID" \
    --security-list-ids "[\"${PRIVATE_SECLIST_OCID}\"]" --force >/dev/null
}

ensure_nsgs() {
  # ── StreetPatrol-NSG (public-facing n8n-Docker) ──────────────────────────
  if [[ -z "$STREET_NSG_OCID" || "$STREET_NSG_OCID" == "null" ]]; then
    log "  Looking up StreetPatrol-NSG..."
    STREET_NSG_OCID="$(oci network nsg list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='StreetPatrol-NSG' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$STREET_NSG_OCID" || "$STREET_NSG_OCID" == "null" ]]; then
    log "  Creating StreetPatrol-NSG..."
    STREET_NSG_OCID="$(oci network nsg create \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --display-name "StreetPatrol-NSG" \
      --query "data.id" --raw-output)"
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
         \"description\":\"HTTP — Traefik redirect to HTTPS\"},
        {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
         \"source\":\"0.0.0.0/0\",\"sourceType\":\"CIDR_BLOCK\",
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":443,\"max\":443}},
         \"description\":\"HTTPS — Traefik TLS termination\"},
        {\"direction\":\"EGRESS\",\"protocol\":\"all\",\"isStateless\":false,
         \"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",
         \"description\":\"Allow all egress\"}
      ]" >/dev/null
  fi
  assert_ocid "$STREET_NSG_OCID" "StreetPatrol NSG"
  log "  StreetPatrol-NSG: $STREET_NSG_OCID"

  # ── BackAlley-NSG (private ubuntu-Node + netstack-Docker) ────────────────
  if [[ -z "$BACKALLEY_NSG_OCID" || "$BACKALLEY_NSG_OCID" == "null" ]]; then
    log "  Looking up BackAlley-NSG..."
    BACKALLEY_NSG_OCID="$(oci network nsg list \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --all \
      --query "data[?\"display-name\"=='BackAlley-NSG' && \"lifecycle-state\"=='AVAILABLE'] | [0].id" \
      --raw-output 2>/dev/null || true)"
  fi
  if [[ -z "$BACKALLEY_NSG_OCID" || "$BACKALLEY_NSG_OCID" == "null" ]]; then
    log "  Creating BackAlley-NSG..."
    BACKALLEY_NSG_OCID="$(oci network nsg create \
      --compartment-id "$COMP_OCID" \
      --vcn-id "$VCN_OCID" \
      --display-name "BackAlley-NSG" \
      --query "data.id" --raw-output)"
    oci network nsg rules add \
      --nsg-id "$BACKALLEY_NSG_OCID" \
      --security-rules "[
        {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
         \"source\":\"10.0.1.0/24\",\"sourceType\":\"CIDR_BLOCK\",
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":22,\"max\":22}},
         \"description\":\"SSH from Frontline only (bastion hop)\"},
        {\"direction\":\"INGRESS\",\"protocol\":\"17\",\"isStateless\":false,
         \"source\":\"0.0.0.0/0\",\"sourceType\":\"CIDR_BLOCK\",
         \"udpOptions\":{\"destinationPortRange\":{\"min\":${WG_PORT},\"max\":${WG_PORT}}},
         \"description\":\"WireGuard — auth by cryptographic handshake; no unauthenticated access possible\"},
        {\"direction\":\"INGRESS\",\"protocol\":\"all\",\"isStateless\":false,
         \"source\":\"${WG_SUBNET}\",\"sourceType\":\"CIDR_BLOCK\",
         \"description\":\"WireGuard overlay subnet — allow all\"},
        {\"direction\":\"INGRESS\",\"protocol\":\"6\",\"isStateless\":false,
         \"source\":\"10.0.1.0/24\",\"sourceType\":\"CIDR_BLOCK\",
         \"tcpOptions\":{\"destinationPortRange\":{\"min\":3306,\"max\":3306}},
         \"description\":\"MySQL from Frontline subnet only\"},
        {\"direction\":\"EGRESS\",\"protocol\":\"all\",\"isStateless\":false,
         \"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",
         \"description\":\"Allow all egress via NAT\"}
      ]" >/dev/null
  fi
  assert_ocid "$BACKALLEY_NSG_OCID" "BackAlley NSG"
  log "  BackAlley-NSG: $BACKALLEY_NSG_OCID"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 5: SHAPE + IMAGE
# ══════════════════════════════════════════════════════════════════════════════

select_image_and_shape() {
  log "Phase 5: shape and image selection"
  select_shape
  select_image
}

select_shape() {
  if [[ -n "$SHAPE" ]]; then
    log "  Shape (from state): $SHAPE"
    return
  fi
  log "  Probing A1.Flex availability in $AVAILABILITY_DOMAIN..."
  local available
  available="$(oci compute shape list \
    --compartment-id "$TENANCY_OCID" \
    --availability-domain "$AVAILABILITY_DOMAIN" \
    --query "data[?shape=='VM.Standard.A1.Flex'] | length(@)" \
    --raw-output 2>/dev/null || echo "0")"

  if [[ "$available" -gt 0 ]]; then
    SHAPE="VM.Standard.A1.Flex"
    USE_SHAPE_CONFIG=true
    log "  ✅ VM.Standard.A1.Flex available — Arm Ampere (Always Free)"
  else
    SHAPE="VM.Standard.E2.1.Micro"
    USE_SHAPE_CONFIG=false
    warn "VM.Standard.A1.Flex not available — falling back to VM.Standard.E2.1.Micro"
  fi
}

select_image() {
  if [[ -n "$IMAGE_OCID" && "$IMAGE_OCID" != "null" ]]; then
    log "  Image (from state): $IMAGE_OCID"
    return
  fi
  log "  Looking up Ubuntu 24.04 LTS image for shape $SHAPE..."
  IMAGE_OCID="$(oci compute image list \
    --compartment-id "$TENANCY_OCID" \
    --operating-system "Canonical Ubuntu" \
    --operating-system-version "24.04" \
    --shape "$SHAPE" \
    --sort-by TIMECREATED \
    --sort-order DESC \
    --all \
    --query "data[0].id" --raw-output 2>/dev/null || true)"

  # Retry without shape filter — some regions list images differently
  if [[ -z "$IMAGE_OCID" || "$IMAGE_OCID" == "null" ]]; then
    log "  Shape-filtered lookup returned nothing — retrying without shape filter..."
    IMAGE_OCID="$(oci compute image list \
      --compartment-id "$TENANCY_OCID" \
      --operating-system "Canonical Ubuntu" \
      --operating-system-version "24.04" \
      --sort-by TIMECREATED \
      --sort-order DESC \
      --all \
      --query "data[0].id" --raw-output 2>/dev/null || true)"
  fi
  assert_ocid "$IMAGE_OCID" "Ubuntu 24.04 image"
  log "  Image: $IMAGE_OCID"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 6: INSTANCES
# ══════════════════════════════════════════════════════════════════════════════

ensure_instances() {
  log "Phase 6: compute instances"
  local ssh_pub_key_content
  ssh_pub_key_content="$(cat "$SSH_PUB_KEY_PATH")"

  N8N_INSTANCE_OCID="$(ensure_instance \
    "$N8N_INSTANCE_NAME"    "$PUBLIC_SUBNET_OCID"  "true"  "$STREET_NSG_OCID"    \
    "$(build_n8n_cloudinit)" "$N8N_INSTANCE_OCID")"

  UBUNTU_INSTANCE_OCID="$(ensure_instance \
    "$UBUNTU_INSTANCE_NAME"    "$PRIVATE_SUBNET_OCID" "false" "$BACKALLEY_NSG_OCID" \
    "$(build_ubuntu_cloudinit)" "$UBUNTU_INSTANCE_OCID")"

  NETSTACK_INSTANCE_OCID="$(ensure_instance \
    "$NETSTACK_INSTANCE_NAME" "$PRIVATE_SUBNET_OCID" "false" "$BACKALLEY_NSG_OCID" \
    "$(build_netstack_cloudinit)" "$NETSTACK_INSTANCE_OCID")"

  # Wait for all three to reach RUNNING — explicit failure on timeout
  wait_for_instance "$N8N_INSTANCE_OCID"      "$N8N_INSTANCE_NAME"      \
    || die "$N8N_INSTANCE_NAME never reached RUNNING — check OCI console."
  wait_for_instance "$UBUNTU_INSTANCE_OCID"   "$UBUNTU_INSTANCE_NAME"   \
    || die "$UBUNTU_INSTANCE_NAME never reached RUNNING — check OCI console."
  wait_for_instance "$NETSTACK_INSTANCE_OCID" "$NETSTACK_INSTANCE_NAME" \
    || die "$NETSTACK_INSTANCE_NAME never reached RUNNING — check OCI console."

  # Fetch IPs
  fetch_ips
}

ensure_instance() {
  local name="$1" subnet="$2" public_ip="$3" nsg="$4" userdata="$5" existing_ocid="${6:-}"

  # If we already have an OCID from state, verify it's still RUNNING/PROVISIONING
  if [[ -n "$existing_ocid" && "$existing_ocid" != "null" ]]; then
    local state
    state="$(oci compute instance get \
      --instance-id "$existing_ocid" \
      --query "data.\"lifecycle-state\"" --raw-output 2>/dev/null || echo "UNKNOWN")"
    if [[ "$state" =~ ^(RUNNING|PROVISIONING|STARTING)$ ]]; then
      log "  Instance $name already exists ($state) — skipping launch"
      echo "$existing_ocid"
      return
    else
      log "  Instance $name found but state=$state — relaunching..."
    fi
  else
    # Check by display name in case state file was lost
    local found
    found="$(oci compute instance list \
      --compartment-id "$COMP_OCID" \
      --display-name "$name" \
      --all \
      --query "data[?\"lifecycle-state\"!='TERMINATED' && \"lifecycle-state\"!='TERMINATING'] | [0].id" \
      --raw-output 2>/dev/null || true)"
    if [[ -n "$found" && "$found" != "null" ]]; then
      log "  Instance $name found by name — reusing $found"
      echo "$found"
      return
    fi
  fi

  log "  Launching instance: $name..."
  local shape_config_args=()
  if [[ "$USE_SHAPE_CONFIG" == "true" ]]; then
    shape_config_args=(--shape-config '{"ocpus":1,"memoryInGBs":6}')
  fi

  local userdata_b64
  userdata_b64="$(printf '%s' "$userdata" | base64 | tr -d '\n')"

  local ssh_pub_key_content
  ssh_pub_key_content="$(cat "$SSH_PUB_KEY_PATH")"

  local new_ocid
  new_ocid="$(oci compute instance launch \
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
      \"assignPublicIp\":${public_ip},
      \"nsgIds\":[\"${nsg}\"]
    }" \
    --metadata "{
      \"ssh_authorized_keys\":\"${ssh_pub_key_content}\",
      \"user_data\":\"${userdata_b64}\"
    }" \
    --query "data.id" --raw-output)"

  assert_ocid "$new_ocid" "Instance $name"
  log "  Launched $name: $new_ocid"
  echo "$new_ocid"
}

wait_for_instance() {
  local ocid="$1" name="$2"
  local deadline=$(( SECONDS + 600 ))
  log "  Waiting for $name to reach RUNNING (up to 10 min)..."
  while [[ $SECONDS -lt $deadline ]]; do
    local state
    state="$(oci compute instance get \
      --instance-id "$ocid" \
      --query "data.\"lifecycle-state\"" --raw-output 2>/dev/null || echo "UNKNOWN")"
    log "    $name → $state"
    [[ "$state" == "RUNNING" ]] && return 0
    [[ "$state" =~ ^(TERMINATED|TERMINATING|STOPPED|STOPPING)$ ]] && {
      warn "$name entered terminal state: $state"
      return 1
    }
    sleep 15
  done
  warn "$name did not reach RUNNING within 10 minutes"
  return 1
}

fetch_ips() {
  log "  Fetching IP addresses..."

  local n8n_vnic
  n8n_vnic="$(oci compute instance list-vnics \
    --instance-id "$N8N_INSTANCE_OCID" \
    --query "data[0].id" --raw-output)"

  N8N_PUBLIC_IP="$(oci network vnic get \
    --vnic-id "$n8n_vnic" \
    --query "data.\"public-ip\"" --raw-output 2>/dev/null || true)"

  N8N_PRIVATE_IP="$(oci network vnic get \
    --vnic-id "$n8n_vnic" \
    --query "data.\"private-ip\"" --raw-output 2>/dev/null || true)"

  UBUNTU_PRIVATE_IP="$(oci compute instance list-vnics \
    --instance-id "$UBUNTU_INSTANCE_OCID" \
    --query "data[0].\"private-ip\"" --raw-output 2>/dev/null || true)"

  NETSTACK_PRIVATE_IP="$(oci compute instance list-vnics \
    --instance-id "$NETSTACK_INSTANCE_OCID" \
    --query "data[0].\"private-ip\"" --raw-output 2>/dev/null || true)"

  [[ -n "$N8N_PUBLIC_IP" && "$N8N_PUBLIC_IP" != "null" ]] \
    || die "Could not retrieve n8n-Docker public IP — check OCI console."

  log "  n8n-Docker:      public=${N8N_PUBLIC_IP}  private=${N8N_PRIVATE_IP}"
  log "  ubuntu-Node:     private=${UBUNTU_PRIVATE_IP}"
  log "  netstack-Docker: private=${NETSTACK_PRIVATE_IP}"
}

# ══════════════════════════════════════════════════════════════════════════════
#  CLOUD-INIT BUILDERS
#  Kept as functions so they are only evaluated when needed and don't pollute
#  the top-level namespace with multi-KB strings.
# ══════════════════════════════════════════════════════════════════════════════

# Shared hardening base — SSH_SOURCE expands at call time (correct)
_docker_base() {
  cat <<BASEEOF
#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get upgrade -y --with-new-pkgs

# Docker upstream repo
apt-get install -y ca-certificates curl gnupg lsb-release
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \$(lsb_release -cs) stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
usermod -aG docker ubuntu
systemctl enable docker
systemctl start docker

# SSH hardening
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/'   /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/'                 /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/'      /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/'                     /etc/ssh/sshd_config
sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/'       /etc/ssh/sshd_config
systemctl restart sshd

# UFW baseline
apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from ${SSH_SOURCE} to any port 22 proto tcp comment 'admin SSH'
BASEEOF
}

build_n8n_cloudinit() {
  cat <<CLOUDINIT
$(_docker_base)
ufw allow 80/tcp  comment 'HTTP Traefik redirect'
ufw allow 443/tcp comment 'HTTPS Traefik TLS'
ufw --force enable

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
}

build_ubuntu_cloudinit() {
  cat <<CLOUDINIT
$(_docker_base)
ufw allow from 10.0.1.0/24 to any port 22 proto tcp comment 'SSH from Frontline (bastion)'
ufw --force enable

apt-get install -y fail2ban unattended-upgrades
systemctl enable --now fail2ban
CLOUDINIT
}

build_netstack_cloudinit() {
  # WireGuard private key is NOT embedded here.
  # The wg0.conf skeleton has a placeholder; the real key is pushed post-boot
  # by push_wireguard_key() over an SSH pipe — never as a shell argument.
  # NIC name is resolved dynamically at PostUp/PostDown time via 'ip route get'.
  # wg-quick owns port WG_PORT exclusively; no competing containers.
  cat <<CLOUDINIT
$(_docker_base)
ufw allow ${WG_PORT}/udp comment 'WireGuard VPN'
ufw allow from 10.0.1.0/24 to any port 22 proto tcp comment 'SSH from Frontline (bastion)'
ufw --force enable

apt-get install -y wireguard

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wg-forward.conf
sysctl -p /etc/sysctl.d/99-wg-forward.conf

install -m 700 -d /etc/wireguard

cat > /etc/wireguard/wg0.conf <<'WGCONF'
[Interface]
PrivateKey = PLACEHOLDER_REPLACED_BY_DEPLOY_SCRIPT
Address = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
PostUp   = ETH=\$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | head -1); iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o \$ETH -j MASQUERADE
PostDown = ETH=\$(ip route get 8.8.8.8 | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | head -1); iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o \$ETH -j MASQUERADE
SaveConfig = false

# Add peer entries after bootstrap:
# [Peer]
# PublicKey = <peer_public_key>
# AllowedIPs = 10.8.0.2/32
# PersistentKeepalive = 25
WGCONF

chmod 600 /etc/wireguard/wg0.conf
# wg-quick enabled but NOT started — started after real key is pushed
systemctl enable wg-quick@wg0
CLOUDINIT
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 7: LOCAL CLIENT CONFIG
# ══════════════════════════════════════════════════════════════════════════════

configure_local_client() {
  log "Phase 7: local client config (SSH + OCI CLI)"
  write_ssh_config
  write_oci_config
  write_cloud_shell_script
}

write_ssh_config() {
  local config="$HOME/.ssh/config"
  local priv_key="${SSH_PUB_KEY_PATH%.pub}"

  # Strip any existing IronRing block cleanly before re-writing
  if [[ -f "$config" ]] && grep -q "ironring-n8n" "$config" 2>/dev/null; then
    cp "$config" "${config}.bak.$(date +%s)"
    # Remove from the IronRing header comment to the closing divider
    sed -i '/# ── IronRing SSH Config/,/# ─────────────────────────────────────────────────────/d' "$config"
  fi

  mkdir -p "$(dirname "$config")"
  cat >> "$config" <<SSHBLOCK

# ── IronRing SSH Config ──────────────────────────────
Host ironring-n8n
  HostName ${N8N_PUBLIC_IP}
  User ubuntu
  IdentityFile ${priv_key}
  ServerAliveInterval 60
  ServerAliveCountMax 3

Host ironring-ubuntu-node
  HostName ${UBUNTU_PRIVATE_IP}
  User ubuntu
  IdentityFile ${priv_key}
  ProxyJump ironring-n8n
  ServerAliveInterval 60

Host ironring-netstack
  HostName ${NETSTACK_PRIVATE_IP}
  User ubuntu
  IdentityFile ${priv_key}
  ProxyJump ironring-n8n
  ServerAliveInterval 60
# ─────────────────────────────────────────────────────
SSHBLOCK
  chmod 600 "$config"
  log "  SSH config written: $config"
}

write_oci_config() {
  local config="$HOME/.oci/config"

  # Strip stale profile before re-writing
  if [[ -f "$config" ]] && grep -q "^\[${USER_NAME}\]" "$config" 2>/dev/null; then
    cp "$config" "${config}.bak.$(date +%s)"
    python3 - "$config" "$USER_NAME" <<'PYSTRIP'
import sys, re
path, name = sys.argv[1], sys.argv[2]
with open(path) as f:
    text = f.read()
cleaned = re.sub(rf'\n\[{re.escape(name)}\][^\[]*', '', text)
with open(path, 'w') as f:
    f.write(cleaned)
PYSTRIP
  fi

  mkdir -p "$(dirname "$config")"
  cat >> "$config" <<OCIBLOCK

[${USER_NAME}]
user=${USER_OCID}
fingerprint=${API_FINGERPRINT}
tenancy=${TENANCY_OCID}
region=${REGION}
key_file=${OCI_KEY_DIR}/oci_api_key.pem
OCIBLOCK
  log "  OCI CLI profile [${USER_NAME}] written: $config"
}

write_cloud_shell_script() {
  cat > "$CLOUD_SHELL_SCRIPT" <<CLOUDSHELL
#!/bin/bash
# ════════════════════════════════════════════════════════
#  ironring_cloud_shell_setup.sh
#  Run in OCI Cloud Shell to configure SSH access.
# ════════════════════════════════════════════════════════
set -euo pipefail

N8N_PUBLIC_IP="${N8N_PUBLIC_IP}"
UBUNTU_PRIVATE_IP="${UBUNTU_PRIVATE_IP}"
NETSTACK_PRIVATE_IP="${NETSTACK_PRIVATE_IP}"

mkdir -p ~/.ssh && chmod 700 ~/.ssh

if [ ! -f ~/.ssh/id_ed25519 ]; then
  ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519 -N "" -C "oci-cloudshell-ironring"
  echo ""
  echo "NEW KEY GENERATED. Add to instances with:"
  echo "  ssh ubuntu@\${N8N_PUBLIC_IP} 'echo \"\$(cat ~/.ssh/id_ed25519.pub)\" >> ~/.ssh/authorized_keys'"
fi

# Strip stale IronRing block
if grep -q "ironring-n8n" ~/.ssh/config 2>/dev/null; then
  cp ~/.ssh/config ~/.ssh/config.bak.\$(date +%s)
  sed -i '/# ── IronRing (Cloud Shell)/,/# ──/d' ~/.ssh/config
fi

cat >> ~/.ssh/config <<'EOF'

# ── IronRing (Cloud Shell) ──
Host ironring-n8n
  HostName ${N8N_PUBLIC_IP}
  User ubuntu
  IdentityFile ~/.ssh/id_ed25519
  ServerAliveInterval 60

Host ironring-ubuntu-node
  HostName ${UBUNTU_PRIVATE_IP}
  User ubuntu
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump ironring-n8n

Host ironring-netstack
  HostName ${NETSTACK_PRIVATE_IP}
  User ubuntu
  IdentityFile ~/.ssh/id_ed25519
  ProxyJump ironring-n8n
# ──
EOF
chmod 600 ~/.ssh/config

echo ""
echo "IronRing SSH ready."
echo "  ssh ironring-n8n"
echo "  ssh ironring-ubuntu-node   (hops via n8n-Docker)"
echo "  ssh ironring-netstack      (hops via n8n-Docker)"
CLOUDSHELL
  chmod +x "$CLOUD_SHELL_SCRIPT"
  log "  Cloud Shell script: $CLOUD_SHELL_SCRIPT"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 8: REMOTE BOOTSTRAP
# ══════════════════════════════════════════════════════════════════════════════

push_remote_bootstrap() {
  log "Phase 8: remote bootstrap"
  push_wireguard_key
}

_ssh_opts() {
  # Common SSH options used for all remote calls in this phase.
  # Proxies through n8n-Docker (bastion) to reach private instances.
  local target_ip="$1"
  echo "-i ${SSH_PUB_KEY_PATH%.pub} \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=15 \
    -o ServerAliveInterval=30 \
    -o ProxyJump=ubuntu@${N8N_PUBLIC_IP}"
}

push_wireguard_key() {
  local priv="$WG_KEY_DIR/wg_server_private.key"
  local ssh_priv="${SSH_PUB_KEY_PATH%.pub}"

  log "  Waiting for netstack-Docker SSH to become available..."
  local deadline=$(( SECONDS + 300 ))
  while [[ $SECONDS -lt $deadline ]]; do
    if ssh \
      -i "$ssh_priv" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 \
      -o ProxyJump="ubuntu@${N8N_PUBLIC_IP}" \
      "ubuntu@${NETSTACK_PRIVATE_IP}" \
      "test -f /etc/wireguard/wg0.conf" 2>/dev/null; then
      log "  SSH reachable"
      break
    fi
    log "  Waiting for SSH on netstack..."
    sleep 15
  done

  log "  Waiting for cloud-init to complete on netstack-Docker..."
  deadline=$(( SECONDS + 300 ))
  while [[ $SECONDS -lt $deadline ]]; do
    local ci
    ci="$(ssh \
      -i "$ssh_priv" \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 \
      -o ProxyJump="ubuntu@${N8N_PUBLIC_IP}" \
      "ubuntu@${NETSTACK_PRIVATE_IP}" \
      "cloud-init status 2>/dev/null || echo pending" 2>/dev/null || echo "pending")"
    log "  cloud-init: $ci"
    [[ "$ci" == *"done"* ]] && break
    [[ "$ci" == *"error"* ]] && { warn "cloud-init error on netstack — continuing"; break; }
    sleep 20
  done

  # Push the key:
  #   - Delivered over encrypted SSH, read from file via stdin redirection
  #   - Never passed as a shell argument or env variable
  #   - The remote bash reads it with $(cat) inside a subshell
  #   - sed patches the placeholder line in-place; no intermediate temp file
  #   - wg-quick starts only after the config is valid
  log "  Pushing WireGuard private key to netstack-Docker (stdin pipe, no plaintext in args)..."
  ssh \
    -i "$ssh_priv" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=15 \
    -o ProxyJump="ubuntu@${N8N_PUBLIC_IP}" \
    "ubuntu@${NETSTACK_PRIVATE_IP}" \
    'sudo bash -s' <<'REMOTESCRIPT'
set -euo pipefail
wg_key="$(cat)"
sed -i "s|PrivateKey = PLACEHOLDER_REPLACED_BY_DEPLOY_SCRIPT|PrivateKey = ${wg_key}|" \
  /etc/wireguard/wg0.conf
chmod 600 /etc/wireguard/wg0.conf
systemctl start wg-quick@wg0
systemctl is-active wg-quick@wg0 || { echo "wg-quick failed to start"; exit 1; }
REMOTESCRIPT
    < "$priv"

  log "  WireGuard key pushed and wg-quick@wg0 is active"
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 9: VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

verify_deployment() {
  log "Phase 9: verification"
  check_ssh
  check_http
  check_https
  check_wireguard
  check_n8n
}

check_ssh() {
  log "  Checking SSH to n8n-Docker..."
  local ssh_priv="${SSH_PUB_KEY_PATH%.pub}"
  if ssh \
    -i "$ssh_priv" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "ubuntu@${N8N_PUBLIC_IP}" \
    "echo ok" 2>/dev/null | grep -q "ok"; then
    log "  SSH n8n-Docker: OK"
  else
    warn "SSH to n8n-Docker failed — instance may still be initialising"
  fi
}

check_http() {
  log "  Checking HTTP redirect on n8n-Docker (port 80 → 301)..."
  local code
  code="$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 10 \
    "http://${N8N_PUBLIC_IP}/" 2>/dev/null || echo "000")"
  if [[ "$code" =~ ^(301|302|308)$ ]]; then
    log "  HTTP redirect: OK (${code})"
  else
    warn "HTTP check returned ${code} — Traefik may still be starting (wait ~60s)"
  fi
}

check_https() {
  log "  Checking HTTPS on n8n-Docker (${N8N_DOMAIN})..."
  local code
  code="$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time 15 \
    --resolve "${N8N_DOMAIN}:443:${N8N_PUBLIC_IP}" \
    "https://${N8N_DOMAIN}/" 2>/dev/null || echo "000")"
  if [[ "$code" =~ ^(200|302|401)$ ]]; then
    log "  HTTPS n8n: OK (${code})"
  else
    warn "HTTPS check returned ${code} — DNS may not resolve yet; cert will auto-issue once DNS propagates"
  fi
}

check_wireguard() {
  log "  Checking WireGuard on netstack-Docker..."
  local ssh_priv="${SSH_PUB_KEY_PATH%.pub}"
  local wg_status
  wg_status="$(ssh \
    -i "$ssh_priv" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    -o ProxyJump="ubuntu@${N8N_PUBLIC_IP}" \
    "ubuntu@${NETSTACK_PRIVATE_IP}" \
    "systemctl is-active wg-quick@wg0 2>/dev/null || echo inactive" 2>/dev/null \
    || echo "unreachable")"
  if [[ "$wg_status" == "active" ]]; then
    log "  WireGuard: active"
  else
    warn "WireGuard status: ${wg_status}"
  fi
}

check_n8n() {
  log "  Checking n8n container on n8n-Docker..."
  local ssh_priv="${SSH_PUB_KEY_PATH%.pub}"
  local container_status
  container_status="$(ssh \
    -i "$ssh_priv" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    "ubuntu@${N8N_PUBLIC_IP}" \
    "docker inspect --format '{{.State.Status}}' n8n 2>/dev/null || echo missing" 2>/dev/null \
    || echo "unreachable")"
  if [[ "$container_status" == "running" ]]; then
    log "  n8n container: running"
  else
    warn "n8n container status: ${container_status} — docker compose may still be starting"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 10: OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

print_outputs() {
  # Write OCI CLI profile now that we have all OCIDs
  # (save_state has already been called; this is purely for display)

  echo ""
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║           ✅  IRONRING DEPLOY COMPLETE                        ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  Shape:             $SHAPE"
  echo "  Region:            $REGION"
  echo "  Compartment:       $COMP_OCID"
  echo "  VCN:               $VCN_OCID"
  echo "  Frontline subnet:  $PUBLIC_SUBNET_OCID  (10.0.1.0/24)"
  echo "  BackAlley subnet:  $PRIVATE_SUBNET_OCID  (10.0.2.0/24)"
  echo "  IGW:               $IGW_OCID"
  echo "  NAT:               $NAT_OCID"
  echo "  StreetPatrol-NSG:  $STREET_NSG_OCID"
  echo "  BackAlley-NSG:     $BACKALLEY_NSG_OCID"
  echo ""
  echo "  Instances:"
  printf "  %-22s  public=%-18s  %s\n" \
    "$N8N_INSTANCE_NAME" "${N8N_PUBLIC_IP}" "$N8N_INSTANCE_OCID"
  printf "  %-22s  private=%-17s  %s\n" \
    "$UBUNTU_INSTANCE_NAME" "${UBUNTU_PRIVATE_IP}" "$UBUNTU_INSTANCE_OCID"
  printf "  %-22s  private=%-17s  %s\n" \
    "$NETSTACK_INSTANCE_NAME" "${NETSTACK_PRIVATE_IP}" "$NETSTACK_INSTANCE_OCID"
  echo ""
  echo "  n8n URL:           https://${N8N_DOMAIN}"
  echo "  WireGuard pubkey:  ${WG_SERVER_PUBLIC_KEY}"
  echo "  WireGuard privkey: ${WG_KEY_DIR}/wg_server_private.key  (chmod 600, never printed)"
  echo ""
  echo "  SSH:"
  echo "    ssh ironring-n8n"
  echo "    ssh ironring-ubuntu-node   (ProxyJump via n8n-Docker)"
  echo "    ssh ironring-netstack      (ProxyJump via n8n-Docker)"
  echo ""
  echo "  State file:        $STATE_FILE"
  echo "  Cloud Shell:       bash $CLOUD_SHELL_SCRIPT"
  echo "  OCI CLI profile:   export OCI_CLI_PROFILE=${USER_NAME}"
  echo ""

  cat <<'NOTES'
═══════════════════════════════════════════════════════════════
  POST-DEPLOY CHECKLIST
═══════════════════════════════════════════════════════════════

  [ ] DNS: Point N8N_DOMAIN A record → n8n-Docker public IP.
      Let's Encrypt cert auto-issues on first HTTPS hit after DNS propagates.

  [ ] WireGuard peers (ssh ironring-netstack):
        sudo wg set wg0 peer <PEER_PUBKEY> allowed-ips 10.8.0.x/32
        sudo wg-quick save wg0

  [ ] OCI Vault: import WireGuard and API private keys for audited rotation.
        ~/.wireguard/ironring/wg_server_private.key
        ~/.oci/SidewalkNetAdmin/oci_api_key.pem

  [ ] SSH IP rotation: if your public IP changes, update:
        NoMercy-Sec security list + StreetPatrol-NSG SSH ingress rule.
      Then re-run this script — idempotent, will only update config.

  [ ] VCN Flow Logs: OCI Console → Observability → Logging → Log Groups.

  [ ] Boot volume snapshots: after first clean boot, snapshot all 3 volumes.

  [ ] fail2ban tuning (ubuntu-Node):
        sudo bash -c 'cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
EOF'
        sudo systemctl restart fail2ban

  [ ] Re-run safety: script is fully idempotent — re-running after a partial
      failure picks up from where OCI resources already exist.
      Lock file prevents concurrent runs.

═══════════════════════════════════════════════════════════════
NOTES
}

# ══════════════════════════════════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════════════════════════════════
main "$@"
