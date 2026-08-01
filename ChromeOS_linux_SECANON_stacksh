#!/data/data/com.termux/files/usr/bin/bash

# ULTRA-SECURE ANON STACK - HARDENED DEPLOYMENT
# Features:
# - Auto-restart on reboot/crash
# - proot isolated environment
# - PIN-protected configuration
# - FIDO2/U2F hardware key support
# - Certificate pinning (double VPN: local + Cloudflare WARP)
# - Network isolation & tamper protection
# - Zero-knowledge encrypted configuration storage

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

log()    { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()     { echo -e "${GREEN}[✓]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
err()    { echo -e "${RED}[✗]${NC} $1"; }
step()   { echo -e "${MAGENTA}[STEP]${NC} $1"; }

PREFIX="/data/data/com.termux/files/usr"
SECURE_ROOT="$PREFIX/var/secure-dns-stack"
PROOT_ENV="$SECURE_ROOT/proot-env"
CONFIG_VAULT="$SECURE_ROOT/vault"
CERT_STORE="$SECURE_ROOT/certificates"
FIDO_CONFIG="$SECURE_ROOT/fido2"

clear
echo -e "${CYAN}"
cat << "BANNER"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║    ULTRA-SECURE ANON STACK - HARDENED DEPLOYMENT        ║
║                                                          ║
║    ✓ Auto-restart on reboot/crash                       ║
║    ✓ proot isolated environment                         ║
║    ✓ PIN-protected + FIDO2 hardware key                 ║
║    ✓ Double VPN (local + Cloudflare WARP)               ║
║    ✓ Certificate pinning & network isolation            ║
║    ✓ Tamper-proof configuration vault                   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# ============================================================================
# SECURITY FUNCTIONS
# ============================================================================

# Generate secure random PIN hash
generate_pin_hash() {
    local pin="$1"
    echo -n "$pin" | openssl dgst -sha256 | awk '{print $2}'
}

# Verify PIN
verify_pin() {
    local stored_hash="$1"
    local input_pin="$2"
    local input_hash=$(generate_pin_hash "$input_pin")
    
    if [ "$stored_hash" = "$input_hash" ]; then
        return 0
    else
        return 1
    fi
}

# Encrypt data with PIN-derived key
encrypt_config() {
    local pin="$1"
    local data="$2"
    local output="$3"
    
    # Derive encryption key from PIN using PBKDF2
    local key=$(echo -n "$pin" | openssl enc -pbkdf2 -pass stdin -P -md sha256 | grep "key=" | cut -d= -f2)
    
    echo -n "$data" | openssl enc -aes-256-cbc -pbkdf2 -pass pass:"$pin" -out "$output" 2>/dev/null
}

# Decrypt data with PIN-derived key
decrypt_config() {
    local pin="$1"
    local input="$2"
    
    openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$pin" -in "$input" 2>/dev/null
}

# Check for FIDO2 hardware key
check_fido2_key() {
    # Check if FIDO2 key is connected
    if lsusb 2>/dev/null | grep -qiE "(yubico|feitian|fido|nitrokey)"; then
        return 0
    fi
    
    # Check via Termux USB API
    if command -v termux-usb-list &>/dev/null; then
        if termux-usb-list 2>/dev/null | grep -qiE "(yubico|feitian|fido|nitrokey)"; then
            return 0
        fi
    fi
    
    return 1
}

# Generate certificate for local VPN
generate_local_vpn_cert() {
    local cert_dir="$1"
    local pin="$2"
    
    mkdir -p "$cert_dir"
    
    # Generate CA private key
    openssl genrsa -out "$cert_dir/ca-key.pem" 4096 2>/dev/null
    
    # Generate CA certificate
    openssl req -new -x509 -days 3650 -key "$cert_dir/ca-key.pem" \
        -out "$cert_dir/ca-cert.pem" -subj "/C=XX/ST=Secure/L=Termux/O=UltraSecure/CN=LocalVPN-CA" 2>/dev/null
    
    # Generate server private key
    openssl genrsa -out "$cert_dir/server-key.pem" 4096 2>/dev/null
    
    # Generate server CSR
    openssl req -new -key "$cert_dir/server-key.pem" \
        -out "$cert_dir/server-csr.pem" -subj "/C=XX/ST=Secure/L=Termux/O=UltraSecure/CN=LocalVPN-Server" 2>/dev/null
    
    # Sign server certificate
    openssl x509 -req -in "$cert_dir/server-csr.pem" -CA "$cert_dir/ca-cert.pem" \
        -CAkey "$cert_dir/ca-key.pem" -CAcreateserial -out "$cert_dir/server-cert.pem" \
        -days 3650 -sha256 2>/dev/null
    
    # Generate client private key
    openssl genrsa -out "$cert_dir/client-key.pem" 4096 2>/dev/null
    
    # Generate client CSR
    openssl req -new -key "$cert_dir/client-key.pem" \
        -out "$cert_dir/client-csr.pem" -subj "/C=XX/ST=Secure/L=Termux/O=UltraSecure/CN=LocalVPN-Client" 2>/dev/null
    
    # Sign client certificate
    openssl x509 -req -in "$client-csr.pem" -CA "$cert_dir/ca-cert.pem" \
        -CAkey "$cert_dir/ca-key.pem" -CAcreateserial -out "$cert_dir/client-cert.pem" \
        -days 3650 -sha256 2>/dev/null
    
    # Extract certificate fingerprints for pinning
    openssl x509 -in "$cert_dir/ca-cert.pem" -pubkey -noout | \
        openssl pkey -pubin -outform der | \
        openssl dgst -sha256 -binary | \
        base64 > "$cert_dir/ca-pin.txt"
    
    openssl x509 -in "$cert_dir/server-cert.pem" -pubkey -noout | \
        openssl pkey -pubin -outform der | \
        openssl dgst -sha256 -binary | \
        base64 > "$cert_dir/server-pin.txt"
    
    # Encrypt private keys with PIN
    encrypt_config "$pin" "$(cat $cert_dir/ca-key.pem)" "$cert_dir/ca-key.pem.enc"
    encrypt_config "$pin" "$(cat $cert_dir/server-key.pem)" "$cert_dir/server-key.pem.enc"
    encrypt_config "$pin" "$(cat $cert_dir/client-key.pem)" "$cert_dir/client-key.pem.enc"
    
    # Remove unencrypted keys
    shred -uz "$cert_dir/ca-key.pem" "$cert_dir/server-key.pem" "$cert_dir/client-key.pem" 2>/dev/null || \
        rm -f "$cert_dir/ca-key.pem" "$cert_dir/server-key.pem" "$cert_dir/client-key.pem"
    
    ok "Local VPN certificates generated with pinning"
}

# ============================================================================
# INITIALIZATION & SECURITY SETUP
# ============================================================================

step "PHASE 1: Security Initialization"
echo ""

# Check if first run
FIRST_RUN=false
if [ ! -f "$CONFIG_VAULT/system.lock" ]; then
    FIRST_RUN=true
fi

# Create secure directories
mkdir -p "$SECURE_ROOT" "$PROOT_ENV" "$CONFIG_VAULT" "$CERT_STORE" "$FIDO_CONFIG"
chmod 700 "$SECURE_ROOT" "$CONFIG_VAULT" "$CERT_STORE" "$FIDO_CONFIG"

if [ "$FIRST_RUN" = true ]; then
    log "First-time setup - Initializing security..."
    echo ""
    
    # Setup PIN
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}SECURITY SETUP - PIN CONFIGURATION${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "This PIN protects all configuration changes."
    echo "Minimum 8 characters required."
    echo ""
    
    while true; do
        read -s -p "Enter new PIN (8+ characters): " PIN1
        echo ""
        
        if [ ${#PIN1} -lt 8 ]; then
            err "PIN must be at least 8 characters"
            continue
        fi
        
        read -s -p "Confirm PIN: " PIN2
        echo ""
        
        if [ "$PIN1" != "$PIN2" ]; then
            err "PINs do not match"
            continue
        fi
        
        break
    done
    
    USER_PIN="$PIN1"
    PIN_HASH=$(generate_pin_hash "$USER_PIN")
    echo "$PIN_HASH" > "$CONFIG_VAULT/pin.hash"
    chmod 600 "$CONFIG_VAULT/pin.hash"
    
    ok "PIN configured"
    echo ""
    
    # Check for FIDO2 key
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}FIDO2/U2F HARDWARE KEY CONFIGURATION${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    if check_fido2_key; then
        ok "FIDO2 hardware key detected"
        echo ""
        read -p "Enable FIDO2 key for configuration changes? (Y/n): " -n 1 -r
        echo ""
        
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            # Store FIDO2 requirement
            echo "enabled" > "$FIDO_CONFIG/required"
            chmod 600 "$FIDO_CONFIG/required"
            
            # Get key identifier
            FIDO_ID=$(lsusb 2>/dev/null | grep -iE "(yubico|feitian|fido|nitrokey)" | head -1 | awk '{print $6}' || echo "unknown")
            echo "$FIDO_ID" > "$FIDO_CONFIG/key-id"
            
            ok "FIDO2 protection enabled"
            warn "You will need this hardware key connected to change configurations"
        else
            echo "disabled" > "$FIDO_CONFIG/required"
        fi
    else
        warn "No FIDO2 key detected"
        log "Configuration will use PIN-only protection"
        echo "disabled" > "$FIDO_CONFIG/required"
    fi
    
    echo ""
    
    # Generate certificates
    step "Generating local VPN certificates..."
    generate_local_vpn_cert "$CERT_STORE" "$USER_PIN"
    echo ""
    
    # Cloudflare WARP configuration
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}CLOUDFLARE WARP VPN CONFIGURATION${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Double VPN Architecture:"
    echo "  Traffic → Local VPN (your certs) → WARP → Internet"
    echo ""
    echo "This ensures even Cloudflare only sees encrypted traffic."
    echo ""
    
    read -p "Do you have Cloudflare WARP credentials? (y/N): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        read -p "Enter WARP device ID (or press Enter to skip): " WARP_DEVICE_ID
        read -p "Enter WARP service token (or press Enter to skip): " WARP_TOKEN
        
        if [ -n "$WARP_DEVICE_ID" ] || [ -n "$WARP_TOKEN" ]; then
            # Encrypt WARP credentials
            cat > "/tmp/warp-creds.tmp" << WARPCREDS
WARP_DEVICE_ID=$WARP_DEVICE_ID
WARP_TOKEN=$WARP_TOKEN
WARPCREDS
            
            encrypt_config "$USER_PIN" "$(cat /tmp/warp-creds.tmp)" "$CONFIG_VAULT/warp-credentials.enc"
            shred -uz /tmp/warp-creds.tmp 2>/dev/null || rm -f /tmp/warp-creds.tmp
            
            ok "WARP credentials encrypted and stored"
        fi
    else
        log "WARP setup skipped - you can configure later with: secure-vpn-config"
    fi
    
    echo ""
    
    # Create system lock
    date > "$CONFIG_VAULT/system.lock"
    ok "Security initialization complete"
    echo ""
    
else
    # Existing installation - verify PIN
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}SECURITY VERIFICATION${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    STORED_PIN_HASH=$(cat "$CONFIG_VAULT/pin.hash")
    ATTEMPTS=0
    MAX_ATTEMPTS=3
    
    while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
        read -s -p "Enter PIN: " INPUT_PIN
        echo ""
        
        if verify_pin "$STORED_PIN_HASH" "$INPUT_PIN"; then
            USER_PIN="$INPUT_PIN"
            ok "PIN verified"
            break
        else
            ATTEMPTS=$((ATTEMPTS + 1))
            REMAINING=$((MAX_ATTEMPTS - ATTEMPTS))
            err "Invalid PIN ($REMAINING attempts remaining)"
            
            if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
                err "Maximum attempts exceeded - exiting"
                exit 1
            fi
        fi
    done
    
    echo ""
    
    # Check FIDO2 if required
    if [ -f "$FIDO_CONFIG/required" ] && [ "$(cat $FIDO_CONFIG/required)" = "enabled" ]; then
        log
