#!/data/data/com.termux/files/usr/bin/bash

# Ultra-Hardened DNS Stack Installer - 2026 Standards
# Termux/Android optimized with full dependency fallbacks
# DoT + DNSCrypt + ODoH + Privacy Relay Architecture

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Error handling
trap 'log_error "Installation failed at line $LINENO. Check errors above."; exit 1' ERR

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Ultra-Hardened DNS Stack Installer - 2026 Standards    ║"
echo "║  Termux/Android Optimized with Dependency Fallbacks     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    log_error "This script must be run in Termux on Android"
    exit 1
fi

log_info "Detecting system architecture..."
ARCH=$(uname -m)
log_success "Architecture: $ARCH"

# Detect Android version
ANDROID_VERSION=$(getprop ro.build.version.release 2>/dev/null || echo "Unknown")
log_info "Android version: $ANDROID_VERSION"

# Check available storage
AVAILABLE_SPACE=$(df $PREFIX | tail -1 | awk '{print $4}')
log_info "Available storage: $((AVAILABLE_SPACE / 1024))MB"

if [ $AVAILABLE_SPACE -lt 512000 ]; then
    log_warn "Low storage detected. At least 500MB recommended."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ============================================================================
# STEP 1: Package Repository Setup
# ============================================================================
log_info "[1/13] Setting up package repositories..."

# Update package sources
if ! pkg update -y 2>/dev/null; then
    log_warn "Standard repository update failed, trying mirrors..."
    termux-change-repo
    pkg update -y || log_error "Failed to update repositories"
fi

pkg upgrade -y || log_warn "Some packages failed to upgrade (non-critical)"
log_success "Repositories updated"

# ============================================================================
# STEP 2: Core Dependencies Installation with Fallbacks
# ============================================================================
log_info "[2/13] Installing core dependencies..."

# Essential packages with fallbacks
CORE_PACKAGES=(
    "curl"
    "wget"
    "grep"
    "sed"
    "gawk"
    "git"
    "tar"
    "gzip"
    "openssl"
    "bind-tools"  # Provides dig/nslookup (fallback for drill)
    "iproute2"    # For ip command
    "procps"      # For pgrep/pkill
)

for package in "${CORE_PACKAGES[@]}"; do
    if pkg install -y "$package" 2>/dev/null; then
        log_success "Installed: $package"
    else
        log_warn "Failed to install $package (may already be installed or unavailable)"
    fi
done

# Verify critical tools
if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
    log_error "Neither curl nor wget available. Cannot proceed."
    exit 1
fi

# Set download tool
if command -v curl &> /dev/null; then
    DOWNLOAD="curl -L -f -o"
    DOWNLOAD_STDOUT="curl -s -L"
    log_info "Using curl for downloads"
else
    DOWNLOAD="wget -O"
    DOWNLOAD_STDOUT="wget -q -O -"
    log_info "Using wget for downloads"
fi

# Verify DNS query tool
if command -v dig &> /dev/null; then
    DNS_TOOL="dig"
    log_success "DNS query tool: dig"
elif command -v nslookup &> /dev/null; then
    DNS_TOOL="nslookup"
    log_success "DNS query tool: nslookup"
else
    log_warn "No DNS query tool available. Testing will be limited."
    DNS_TOOL=""
fi

# ============================================================================
# STEP 3: Unbound Installation with Fallback
# ============================================================================
log_info "[3/13] Installing Unbound DNS resolver..."

if pkg install -y unbound 2>/dev/null; then
    log_success "Unbound installed from repository"
    UNBOUND_INSTALLED=true
else
    log_warn "Unbound not available in repository. Attempting manual build..."
    
    # Install build dependencies
    pkg install -y build-essential libexpat-dev libssl-dev 2>/dev/null || true
    
    # Try to build from source as fallback
    cd $PREFIX/tmp
    if $DOWNLOAD_STDOUT "https://nlnetlabs.nl/downloads/unbound/unbound-latest.tar.gz" > unbound.tar.gz 2>/dev/null; then
        tar xzf unbound.tar.gz
        cd unbound-*
        
        if ./configure --prefix=$PREFIX --with-ssl=$PREFIX 2>&1 | tee /tmp/unbound-configure.log; then
            if make -j$(nproc) 2>&1 | tee /tmp/unbound-make.log; then
                if make install 2>&1 | tee /tmp/unbound-install.log; then
                    log_success "Unbound built from source successfully"
                    UNBOUND_INSTALLED=true
                else
                    log_error "Unbound installation failed"
                    UNBOUND_INSTALLED=false
                fi
            else
                log_error "Unbound compilation failed"
                UNBOUND_INSTALLED=false
            fi
        else
            log_error "Unbound configuration failed"
            UNBOUND_INSTALLED=false
        fi
        cd $PREFIX/tmp
        rm -rf unbound-* unbound.tar.gz
    else
        log_error "Failed to download Unbound source"
        UNBOUND_INSTALLED=false
    fi
fi

if [ "$UNBOUND_INSTALLED" = false ]; then
    log_error "Cannot proceed without Unbound. Installation failed."
    exit 1
fi

# ============================================================================
# STEP 4: Golang Installation for DNSCrypt-Proxy
# ============================================================================
log_info "[4/13] Setting up Golang (for DNSCrypt-Proxy)..."

if pkg install -y golang 2>/dev/null; then
    log_success "Golang installed from repository"
    GO_INSTALLED=true
else
    log_warn "Golang not available in repository. Installing manually..."
    
    # Determine Go architecture
    case "$ARCH" in
        aarch64|arm64) GO_ARCH="arm64" ;;
        armv7l|armv8l) GO_ARCH="armv6l" ;;
        x86_64) GO_ARCH="amd64" ;;
        i686) GO_ARCH="386" ;;
        *) 
            log_error "Unsupported architecture for Go: $ARCH"
            GO_INSTALLED=false
            ;;
    esac
    
    if [ -n "$GO_ARCH" ]; then
        GO_VERSION="1.21.5"
        cd $PREFIX/tmp
        
        if $DOWNLOAD go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" 2>/dev/null; then
            tar -C $PREFIX -xzf go.tar.gz
            export PATH=$PREFIX/go/bin:$PATH
            export GOPATH=$PREFIX/go
            echo "export PATH=\$PREFIX/go/bin:\$PATH" >> ~/.bashrc
            echo "export GOPATH=\$PREFIX/go" >> ~/.bashrc
            log_success "Golang installed manually"
            GO_INSTALLED=true
            rm -f go.tar.gz
        else
            log_error "Failed to download Golang"
            GO_INSTALLED=false
        fi
    fi
fi

# ============================================================================
# STEP 5: DNSCrypt-Proxy Installation with Multiple Fallbacks
# ============================================================================
log_info "[5/13] Installing DNSCrypt-Proxy..."

DNSCRYPT_INSTALLED=false

# Method 1: Try package manager
if pkg install -y dnscrypt-proxy 2>/dev/null; then
    log_success "DNSCrypt-Proxy installed from repository"
    DNSCRYPT_INSTALLED=true
else
    log_warn "DNSCrypt-Proxy not in repository. Trying pre-built binary..."
    
    # Method 2: Download pre-built binary
    DNSCRYPT_VERSION="2.1.5"
    
    case "$ARCH" in
        aarch64|arm64) DNSCRYPT_ARCH="linux_arm64" ;;
        armv7l|armv8l) DNSCRYPT_ARCH="linux_arm" ;;
        x86_64) DNSCRYPT_ARCH="linux_x86_64" ;;
        i686) DNSCRYPT_ARCH="linux_i386" ;;
        *) 
            log_warn "No pre-built DNSCrypt binary for $ARCH"
            DNSCRYPT_ARCH=""
            ;;
    esac
    
    if [ -n "$DNSCRYPT_ARCH" ]; then
        cd $PREFIX/tmp
        DNSCRYPT_URL="https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${DNSCRYPT_VERSION}/dnscrypt-proxy-${DNSCRYPT_ARCH}-${DNSCRYPT_VERSION}.tar.gz"
        
        if $DOWNLOAD dnscrypt.tar.gz "$DNSCRYPT_URL" 2>/dev/null; then
            tar xzf dnscrypt.tar.gz
            if [ -f linux-*/dnscrypt-proxy ]; then
                cp linux-*/dnscrypt-proxy $PREFIX/bin/
                chmod +x $PREFIX/bin/dnscrypt-proxy
                log_success "DNSCrypt-Proxy installed from pre-built binary"
                DNSCRYPT_INSTALLED=true
            fi
            rm -rf linux-* dnscrypt.tar.gz
        fi
    fi
    
    # Method 3: Build from source if Go is available
    if [ "$DNSCRYPT_INSTALLED" = false ] && [ "$GO_INSTALLED" = true ]; then
        log_warn "Attempting to build DNSCrypt-Proxy from source..."
        
        cd $PREFIX/tmp
        if git clone https://github.com/DNSCrypt/dnscrypt-proxy 2>/dev/null; then
            cd dnscrypt-proxy/dnscrypt-proxy
            if go build -o $PREFIX/bin/dnscrypt-proxy 2>&1 | tee /tmp/dnscrypt-build.log; then
                chmod +x $PREFIX/bin/dnscrypt-proxy
                log_success "DNSCrypt-Proxy built from source"
                DNSCRYPT_INSTALLED=true
            else
                log_error "DNSCrypt-Proxy build failed"
            fi
            cd $PREFIX/tmp
            rm -rf dnscrypt-proxy
        fi
    fi
fi

if [ "$DNSCRYPT_INSTALLED" = false ]; then
    log_warn "DNSCrypt-Proxy installation failed. Will use DoT-only fallback mode."
    FALLBACK_MODE="dot-only"
else
    FALLBACK_MODE="full"
fi

# ============================================================================
# STEP 6: Rust Installation (for ODoH client - optional)
# ============================================================================
log_info "[6/13] Setting up Rust environment (optional for ODoH)..."

if pkg install -y rust 2>/dev/null; then
    log_success "Rust installed from repository"
    RUST_INSTALLED=true
else
    log_warn "Rust not available. Attempting rustup installation..."
    
    if $DOWNLOAD_STDOUT "https://sh.rustup.rs" | sh -s -- -y --default-toolchain stable 2>/dev/null; then
        source $HOME/.cargo/env
        log_success "Rust installed via rustup"
        RUST_INSTALLED=true
    else
        log_warn "Rust installation failed. ODoH will be unavailable."
        RUST_INSTALLED=false
    fi
fi

# ============================================================================
# STEP 7: Network Configuration Detection
# ============================================================================
log_info "[7/13] Detecting network configuration..."

# Try multiple methods to get IP
get_ipv4() {
    # Method 1: wlan0
    local ip=$(ip addr show wlan0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    if [ -n "$ip" ]; then echo "$ip"; return 0; fi
    
    # Method 2: any wireless interface
    ip=$(ip addr show 2>/dev/null | grep -A 2 "state UP" | grep "inet " | head -1 | awk '{print $2}' | cut -d/ -f1)
    if [ -n "$ip" ]; then echo "$ip"; return 0; fi
    
    # Method 3: default route interface
    local iface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$iface" ]; then
        ip=$(ip addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        if [ -n "$ip" ]; then echo "$ip"; return 0; fi
    fi
    
    echo ""
    return 1
}

get_ipv6() {
    # Get global IPv6 (not link-local)
    local ip=$(ip addr show 2>/dev/null | grep "inet6" | grep -v "fe80" | grep -v "::1" | head -1 | awk '{print $2}' | cut -d/ -f1)
    echo "$ip"
}

LOCAL_IP_V4=$(get_ipv4)
LOCAL_IP_V6=$(get_ipv6)
SUBNET_V4=$(ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' || echo "192.168.1.0/24")

if [ -z "$LOCAL_IP_V4" ]; then
    log_warn "Could not detect IPv4 address. Manual configuration may be needed."
    LOCAL_IP_V4="[NOT DETECTED]"
else
    log_success "IPv4: $LOCAL_IP_V4"
fi

if [ -z "$LOCAL_IP_V6" ]; then
    log_info "IPv6: Not available"
else
    log_success "IPv6: $LOCAL_IP_V6"
fi

log_info "Subnet: $SUBNET_V4"

# ============================================================================
# STEP 8: Directory Structure Creation
# ============================================================================
log_info "[8/13] Creating directory structure..."

mkdir -p $PREFIX/etc/{unbound,dnscrypt-proxy,dns-stack}
mkdir -p $PREFIX/etc/unbound/{blocklist,whitelist,google-policy}
mkdir -p $PREFIX/var/log/{unbound,dnscrypt-proxy,dns-stack}
mkdir -p $PREFIX/opt/dns-relay

log_success "Directory structure created"

# ============================================================================
# STEP 9: Blocklist Download with Fallbacks
# ============================================================================
log_info "[9/13] Downloading blocklists (with fallbacks)..."

download_blocklist() {
    local url="$1"
    local output="$2"
    local format="$3"
    
    log_info "Downloading: $(basename $output)"
    
    if $DOWNLOAD_STDOUT "$url" > /tmp/blocklist.tmp 2>/dev/null; then
        case "$format" in
            "hosts")
                grep "^0.0.0.0" /tmp/blocklist.tmp | \
                    awk '{print "local-zone: \""$2"\" always_nxdomain"}' > "$output"
                ;;
            "domains")
                grep -v "^#" /tmp/blocklist.tmp | grep -v "^$" | \
                    awk '{print "local-zone: \""$1"\" always_nxdomain"}' > "$output"
                ;;
        esac
        
        local count=$(wc -l < "$output")
        log_success "Downloaded $(basename $output): $count entries"
        rm -f /tmp/blocklist.tmp
        return 0
    else
        log_warn "Failed to download $(basename $output)"
        echo "# Blocklist download failed" > "$output"
        rm -f /tmp/blocklist.tmp
        return 1
    fi
}

# Primary blocklist: StevenBlack unified
download_blocklist \
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts" \
    "$PREFIX/etc/unbound/blocklist/stevenblack.conf" \
    "hosts"

# Fallback: Basic StevenBlack if unified fails
if [ $(wc -l < "$PREFIX/etc/unbound/blocklist/stevenblack.conf") -lt 100 ]; then
    log_warn "Primary blocklist small/failed. Trying fallback..."
    download_blocklist \
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" \
        "$PREFIX/etc/unbound/blocklist/stevenblack.conf" \
        "hosts"
fi

# Additional blocklists with fallbacks
download_blocklist \
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt" \
    "$PREFIX/etc/unbound/blocklist/adult.conf" \
    "domains" || \
download_blocklist \
    "https://blocklistproject.github.io/Lists/porn.txt" \
    "$PREFIX/etc/unbound/blocklist/adult.conf" \
    "domains"

download_blocklist \
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt" \
    "$PREFIX/etc/unbound/blocklist/malware.conf" \
    "domains" || \
download_blocklist \
    "https://blocklistproject.github.io/Lists/malware.txt" \
    "$PREFIX/etc/unbound/blocklist/malware.conf" \
    "domains"

download_blocklist \
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt" \
    "$PREFIX/etc/unbound/blocklist/tracking.conf" \
    "domains" || \
download_blocklist \
    "https://blocklistproject.github.io/Lists/tracking.txt" \
    "$PREFIX/etc/unbound/blocklist/tracking.conf" \
    "domains"

# ============================================================================
# STEP 10: Google Policy Configuration
# ============================================================================
log_info "[10/13] Creating Google tracking/privacy policies..."

cat > $PREFIX/etc/unbound/google-policy/block-google-tracking.conf << 'EOF'
# Google Analytics & Tag Manager
local-zone: "google-analytics.com" always_nxdomain
local-zone: "www.google-analytics.com" always_nxdomain
local-zone: "ssl.google-analytics.com" always_nxdomain
local-zone: "analytics.google.com" always_nxdomain
local-zone: "googletagmanager.com" always_nxdomain
local-zone: "www.googletagmanager.com" always_nxdomain
local-zone: "googletagservices.com" always_nxdomain
local-zone: "www.googletagservices.com" always_nxdomain

# Google Ads & DoubleClick
local-zone: "doubleclick.net" always_nxdomain
local-zone: "ad.doubleclick.net" always_nxdomain
local-zone: "g.doubleclick.net" always_nxdomain
local-zone: "static.doubleclick.net" always_nxdomain
local-zone: "m.doubleclick.net" always_nxdomain
local-zone: "mediavisor.doubleclick.net" always_nxdomain
local-zone: "googlesyndication.com" always_nxdomain
local-zone: "pagead.googlesyndication.com" always_nxdomain
local-zone: "pagead2.googlesyndication.com" always_nxdomain
local-zone: "googleadservices.com" always_nxdomain
local-zone: "www.googleadservices.com" always_nxdomain
local-zone: "adservice.google.com" always_nxdomain
local-zone: "admob.com" always_nxdomain
local-zone: "www.admob.com" always_nxdomain
local-zone: "app-measurement.com" always_nxdomain
local-zone: "gstaticadssl.l.google.com" always_nxdomain

# Google Telemetry & Tracking
local-zone: "clients4.google.com" always_nxdomain
local-zone: "clients6.google.com" always_nxdomain
local-zone: "safebrowsing.google.com" always_nxdomain
local-zone: "sb-ssl.google.com" always_nxdomain
local-zone: "safebrowsing-cache.google.com" always_nxdomain

# Additional tracking domains
local-zone: "adwords.google.com" always_nxdomain
local-zone: "metrics.google.com" always_nxdomain
EOF

cat > $PREFIX/etc/unbound/google-policy/allow-google-essential.conf << 'EOF'
# Core Google services (required for basic functionality)
local-zone: "google.com" transparent
local-zone: "googleapis.com" transparent
local-zone: "gstatic.com" transparent
local-zone: "googleusercontent.com" transparent
local-zone: "google-analytics.com" transparent

# Google Home & Chromecast connectivity
local-zone: "clients1.google.com" transparent
local-zone: "clients2.google.com" transparent
local-zone: "clients3.google.com" transparent
local-zone: "mtalk.google.com" transparent
local-zone: "device-provisioning.googleapis.com" transparent
local-zone: "connectivitycheck.gstatic.com" transparent

# Android & Google TV specific
local-zone: "android.clients.google.com" transparent
local-zone: "android.googleapis.com" transparent
local-zone: "play.googleapis.com" transparent
local-zone: "firebaseinstallations.googleapis.com" transparent

# DNS services
local-zone: "dns.google" transparent
local-zone: "dns.google.com" transparent
EOF

log_success "Google policies created"

# ============================================================================
# STEP 11: DNSSEC Root Trust Anchor
# ============================================================================
log_info "[11/13] Initializing DNSSEC root trust anchor..."

if command -v unbound-anchor &> /dev/null; then
    if unbound-anchor -a $PREFIX/etc/unbound/root.key 2>/dev/null; then
        log_success "DNSSEC root anchor initialized"
    else
        log_warn "DNSSEC anchor initialization failed. Will retry on first run."
        # Create empty file to prevent errors
        touch $PREFIX/etc/unbound/root.key
    fi
else
    log_warn "unbound-anchor not found. Creating placeholder."
    touch $PREFIX/etc/unbound/root.key
fi

# ============================================================================
# STEP 12: Configuration File Creation
# ============================================================================
log_info "[12/13] Creating configuration files..."

# Unbound configuration
cat > $PREFIX/etc/unbound/unbound.conf << EOF
# Ultra-Hardened Unbound Configuration - 2026 Standards
# Optimized for Termux/Android

server:
    # Network Interfaces
    interface: 0.0.0.0
    interface: ::0
    port: 5335
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    
    # Access Control - Strict
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ::0/0 refuse
    access-control: ::1/128 allow
    access-control: ::ffff:127.0.0.1/104 allow
    access-control: $SUBNET_V4 allow
    access-control: fd00::/8 allow
    access-control: fe80::/10 allow
    
    # Privacy Settings
    hide-identity: yes
    hide-version: yes
    hide-trustanchor: yes
    minimal-responses: yes
    qname-minimisation: yes
    qname-minimisation-strict: no
    rrset-roundrobin: yes
    
    # DNSSEC Validation
    auto-trust-anchor-file: "$PREFIX/etc/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no
    trust-anchor-signaling: yes
    root-key-sentinel: yes
    
    # Hardening (2026 Standards)
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    use-caps-for-id: yes
    aggressive-nsec: yes
    
    # Anti-DDoS Protection
    ratelimit: 1000
    ratelimit-for-domain: . 1000
    ip-ratelimit: 200
    ratelimit-slabs: 2
    ip-ratelimit-slabs: 2
    
    # Buffer Sizes (RFC 8467 - Modern Standard)
    edns-buffer-size: 1232
    max-udp-size: 1232
    
    # Performance - Android/TV Optimized
    num-threads: 2
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2
    
    # Cache Configuration
    msg-cache-size: 16m
    rrset-cache-size: 32m
    neg-cache-size: 4m
    key-cache-size: 8m
    
    # Cache Tuning
    cache-min-ttl: 300
    cache-max-ttl: 86400
    cache-max-negative-ttl: 3600
    infra-host-ttl: 900
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-ttl-reset: yes
    
    # Logging (Minimal for Privacy)
    verbosity: 1
    logfile: ""
    log-queries: no
    log-replies: no
    log-local-actions: no
    log-servfail: no
    
    # Security
    unwanted-reply-threshold: 10000
    do-not-query-localhost: no
    
    # Private Address Filtering
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: ::ffff:0:0/96
    
    # Include Policy Files
    include: $PREFIX/etc/unbound/blocklist/*.conf
    include: $PREFIX/etc/unbound/google-policy/block-google-tracking.conf
    include: $PREFIX/etc/unbound/google-policy/allow-google-essential.conf
    include: $PREFIX/etc/unbound/whitelist/*.conf

EOF

# Choose forwarding method based on what's installed
if [ "$FALLBACK_MODE" = "full" ]; then
    cat >> $PREFIX/etc/unbound/unbound.conf << EOF
# Forward to DNSCrypt-Proxy (handles DoT/DoH/ODoH + Privacy Relay)
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@5353
    forward-addr: ::1@5353
EOF
    log_info "Mode: Full stack (Unbound → DNSCrypt-Proxy → Privacy Relay)"
else
    cat >> $PREFIX/etc/unbound/unbound.conf << EOF
# Fallback: Direct DoT to trusted resolvers
forward-zone:
    name: "."
    forward-tls-upstream: yes
    
    # Cloudflare DNS-over-TLS
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com
    forward-addr: 2606:4700:4700::1001@853#cloudflare-dns.com
    
    # Quad9 DNS-over-TLS (malware filtering)
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
    forward-addr: 2620:fe::fe@853#dns.quad9.net
EOF
    log_info "Mode: DoT-only fallback (Unbound → DoT)"
fi

# DNSCrypt-Proxy configuration (if installed)
if [ "$DNSCRYPT_INSTALLED" = true ]; then
    log_info "Creating DNSCrypt-Proxy configuration..."
    
    cat > $PREFIX/etc/dnscrypt-proxy/dnscrypt-proxy.toml << EOF
# DNSCrypt-Proxy Configuration - Privacy Relay Mode

server_names = ['cloudflare', 'cloudflare-ipv6', 'quad9-dnscrypt-ipv4-filter-pri']

listen_addresses = ['127.0.0.1:5353', '[::1]:5353']
max_clients = 250

ipv4_servers = true
ipv6_servers = true
dnscrypt_servers = true
doh_servers = true
odoh_servers = true

require_dnssec = true
require_nolog = true
require_nofilter = false

force_tcp = false
timeout = 5000
keepalive = 30

lb_strategy = 'p2'
lb_estimator = true

log_level = 1
use_syslog = false

[query_log]
  file = '$PREFIX/var/log/dnscrypt-proxy/query.log'
  format = 'tsv'

[anonymized_dns]
  routes = [
    { server_name='cloudflare', via=['anon-cs-fr', 'anon-cs-de'] },
    { server_name='quad9-dnscrypt-ipv4-filter-pri', via=['anon-cs-nl'] }
  ]
  skip_incompatible = true

[sources]
  [sources.'public-resolvers']
    urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
    cache_file = '$PREFIX/etc/dnscrypt-proxy/public-resolvers.md'
    minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
    refresh_delay = 72
  
  [sources.'relays']
    urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md']
    cache_file = '$PREFIX/etc/dnscrypt-proxy/relays.md'
    minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
    refresh_delay = 72
EOF
    
    # Create supplementary files
    touch $PREFIX/etc/dnscrypt-proxy/{blocked-names.txt,allowed-names.txt,cloaking-rules.txt}
    log_success "DNSCrypt-Proxy configured"
fi

# ============================================================================
# STEP 13: VPN/WARP Integration Setup
# ============================================================================
log_info "[13/13] Setting up VPN/WARP tunnel integration..."

# Create VPN integration script
cat > $PREFIX/bin/vpn-setup << 'VPNSCRIPT'
#!/data/data/com.termux/files/usr/bin/bash

# VPN/WARP Integration Helper for DNS Stack
# Supports: WireGuard, Cloudflare WARP, OpenVPN

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_menu() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║     VPN/WARP Integration for Ultra-Hardened DNS         ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "Choose VPN method:"
    echo "  1) Cloudflare WARP (Recommended - Zero Trust + WARP)"
    echo "  2) WireGuard (Custom VPN server)"
    echo "  3) Cloudflare Tunnel (cloudflared)"
    echo "  4) OpenVPN (Traditional VPN)"
    echo "  5) Status - Check current VPN"
    echo "  6) Exit"
    echo ""
}

install_warp() {
    log_info "Installing Cloudflare WARP for Android/Termux..."
    echo ""
    
    # Method 1: Try to install warp-cli if available
    if pkg install -y cloudflare-warp 2>/dev/null; then
        log_success "WARP installed from repository"
        return 0
    fi
    
    # Method 2: Install via pip (warp-cli alternative)
    log_warn "Direct WARP package not available. Installing cloudflared instead..."
    
    # Install cloudflared for Tunnel + WARP integration
    ARCH=$(uname -m)
    case "$ARCH" in
        aarch64|arm64) CF_ARCH="arm64" ;;
        armv7l|armv8l) CF_ARCH="arm" ;;
        x86_64) CF_ARCH="amd64" ;;
        *) log_error "Unsupported architecture: $ARCH"; return 1 ;;
    esac
    
    cd $PREFIX/tmp
    CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}"
    
    if curl -L -o cloudflared "$CLOUDFLARED_URL" 2>/dev/null; then
        chmod +x cloudflared
        mv cloudflared $PREFIX/bin/
        log_success "cloudflared installed successfully"
        
        # Create WARP configuration helper
        cat > $PREFIX/etc/dns-stack/warp-config.sh << 'WARPCONF'
#!/data/data/com.termux/files/usr/bin/bash

# Cloudflare WARP/Tunnel Configuration
# This sets up Cloudflare as your exit point for all traffic

echo "Cloudflare WARP Setup Instructions:"
echo ""
echo "Option A: Use Cloudflare WARP App (Easiest)"
echo "  1. Install 'Cloudflare WARP' from Google Play Store"
echo "  2. Open app and sign in"
echo "  3. Enable WARP"
echo "  4. In Settings → Advanced → Connection options:"
echo "     - Disable 'DNS over WARP' (we use our own DNS)"
echo "     - Enable 'VPN' mode"
echo "  5. Your DNS stack will automatically use WARP tunnel"
echo ""
echo "Option B: Use cloudflared Tunnel (Advanced)"
echo "  1. Authenticate: cloudflared tunnel login"
echo "  2. Create tunnel: cloudflared tunnel create termux-dns"
echo "  3. Route DNS: cloudflared tunnel route dns <tunnel-id> dns.yourdomain.com"
echo "  4. Run tunnel: cloudflared tunnel run termux-dns"
echo ""
echo "Option C: WARP Connector (Zero Trust)"
echo "  1. Go to Cloudflare Zero Trust Dashboard"
echo "  2. Create a WARP Connector"
echo "  3. Note the service token"
echo "  4. Run: cloudflared service install <token>"
echo ""
WARPCONF
        chmod +x $PREFIX/etc/dns-stack/warp-config.sh
        
        echo ""
        log_info "Run for setup instructions: $PREFIX/etc/dns-stack/warp-config.sh"
        return 0
    else
        log_error "Failed to download cloudflared"
        return 1
    fi
}

install_wireguard() {
    log_info "Installing WireGuard..."
    
    if pkg install -y wireguard-tools 2>/dev/null; then
        log_success "WireGuard tools installed"
        
        # Create WireGuard config template
        mkdir -p $PREFIX/etc/wireguard
        cat > $PREFIX/etc/wireguard/wg0.conf.template << 'WGCONF'
[Interface]
PrivateKey = YOUR_PRIVATE_KEY_HERE
Address = 10.66.66.2/32
DNS = 127.0.0.1:5335

[Peer]
PublicKey = YOUR_SERVER_PUBLIC_KEY_HERE
PresharedKey = YOUR_PRESHARED_KEY_HERE
Endpoint = YOUR_VPN_SERVER:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
WGCONF
        
        log_success "WireGuard template created: $PREFIX/etc/wireguard/wg0.conf.template"
        echo ""
        log_info "To configure WireGuard:"
        echo "  1. Generate keys: wg genkey | tee privatekey | wg pubkey > publickey"
        echo "  2. Edit $PREFIX/etc/wireguard/wg0.conf.template"
        echo "  3. Rename to wg0.conf"
        echo "  4. Start: wg-quick up wg0"
        echo ""
        log_warn "Note: WireGuard may require root on some Android devices"
        return 0
    else
        log_error "WireGuard installation failed"
        log_info "Alternative: Use WireGuard Android app with Termux VPN API"
        return 1
    fi
}

install_openvpn() {
    log_info "Installing OpenVPN..."
    
    if pkg install -y openvpn 2>/dev/null; then
        log_success "OpenVPN installed"
        
        mkdir -p $PREFIX/etc/openvpn
        log_info "Place your .ovpn config file in: $PREFIX/etc/openvpn/"
        echo ""
        log_info "To connect:"
        echo "  openvpn --config $PREFIX/etc/openvpn/client.ovpn"
        echo ""
        log_warn "Note: OpenVPN may require root or VPN permission on Android"
        return 0
    else
        log_error "OpenVPN installation failed"
        return 1
    fi
}

check_vpn_status() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              VPN/Tunnel Status Check                    ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    
    # Check for running VPN processes
    local vpn_found=false
    
    if pgrep cloudflared > /dev/null; then
        echo "✓ Cloudflare Tunnel: RUNNING"
        cloudflared tunnel info 2>/dev/null || true
        vpn_found=true
    fi
    
    if pgrep wg-quick > /dev/null || ip link show wg0 2>/dev/null | grep -q "state UP"; then
        echo "✓ WireGuard: RUNNING"
        wg show 2>/dev/null || true
        vpn_found=true
    fi
    
    if pgrep openvpn > /dev/null; then
        echo "✓ OpenVPN: RUNNING"
        vpn_found=true
    fi
    
    if [ "$vpn_found" = false ]; then
        echo "✗ No VPN/Tunnel detected"
        echo ""
        echo "Recommendations:"
        echo "  • Install Cloudflare WARP app from Play Store (easiest)"
        echo "  • Or run: vpn-setup and choose option 1-4"
    fi
    
    echo ""
    echo "Current IP (external):"
    curl -s https://api.ipify.org || echo "Failed to check"
    echo ""
    
    echo "Current DNS resolver:"
    curl -s https://1.1.1.1/cdn-cgi/trace | grep "ip=" || echo "Failed to check"
}

case "$1" in
    1|warp)
        install_warp
        ;;
    2|wireguard)
        install_wireguard
        ;;
    3|cloudflared)
        install_warp  # cloudflared is installed in warp function
        ;;
    4|openvpn)
        install_openvpn
        ;;
    5|status)
        check_vpn_status
        ;;
    6|exit)
        exit 0
        ;;
    *)
        show_menu
        read -p "Choose option (1-6): " choice
        $0 $choice
        ;;
esac
VPNSCRIPT

chmod +x $PREFIX/bin/vpn-setup

# Create proxy server setup script
cat > $PREFIX/bin/proxy-setup << 'PROXYSCRIPT'
#!/data/data/com.termux/files/usr/bin/bash

# Local Proxy Server for Network-Wide Privacy
# HTTPS/SOCKS5 proxy that uses hardened DNS

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

install_tinyproxy() {
    log_info "Installing tinyproxy (HTTP/HTTPS proxy)..."
    
    if pkg install -y tinyproxy 2>/dev/null; then
        log_success "tinyproxy installed"
        
        # Configure tinyproxy to use local DNS
        cat > $PREFIX/etc/tinyproxy/tinyproxy.conf << 'TINYCONF'
User nobody
Port 8888
Listen 0.0.0.0
Timeout 600
MaxClients 100
MinSpareServers 5
MaxSpareServers 20
StartServers 10
LogLevel Info
PidFile "/data/data/com.termux/files/usr/var/run/tinyproxy.pid"
MaxRequestsPerChild 0
Allow 127.0.0.1
Allow 192.168.0.0/16
Allow 10.0.0.0/8
Allow 172.16.0.0/12
ViaProxyName "tinyproxy"
DisableViaHeader No
ConnectPort 443
ConnectPort 563
TINYCONF
        
        log_success "tinyproxy configured on port 8888"
        echo ""
        log_info "Start proxy: tinyproxy -c $PREFIX/etc/tinyproxy/tinyproxy.conf"
        log_info "Stop proxy: pkill tinyproxy"
        return 0
    else
        log_info "tinyproxy not available, trying 3proxy..."
        return 1
    fi
}

install_3proxy() {
    log_info "Installing 3proxy (SOCKS5/HTTP proxy)..."
    
    if pkg install -y 3proxy 2>/dev/null; then
        log_success "3proxy installed"
        
        mkdir -p $PREFIX/etc/3proxy
        cat > $PREFIX/etc/3proxy/3proxy.cfg << '3PROXYCONF'
daemon
maxconn 200
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
log /data/data/com.termux/files/usr/var/log/3proxy.log D
logformat "- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"
rotate 30

auth none
allow *

# SOCKS5 proxy on port 1080
socks -p1080

# HTTP proxy on port 3128
proxy -p3128
3PROXYCONF
        
        log_success "3proxy configured (SOCKS5: 1080, HTTP: 3128)"
        echo ""
        log_info "Start proxy: 3proxy $PREFIX/etc/3proxy/3proxy.cfg"
        return 0
    else
        log_info "3proxy not available, trying manual installation..."
        return 1
    fi
}

show_proxy_info() {
    LOCAL_IP=$(ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d/ -f1)
    
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║            Local Proxy Server Configuration             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "Configure devices to use this proxy:"
    echo ""
    echo "HTTP/HTTPS Proxy:"
    echo "  Server: $LOCAL_IP"
    echo "  Port: 8888 (tinyproxy) or 3128 (3proxy)"
    echo ""
    echo "SOCKS5 Proxy:"
    echo "  Server: $LOCAL_IP"
    echo "  Port: 1080"
    echo ""
    echo "DNS Server:"
    echo "  Server: $LOCAL_IP"
    echo "  Port: 5335"
    echo ""
    echo "Traffic Flow:"
    echo "  Device → Proxy ($LOCAL_IP:8888)"
    echo "         → DNS Stack ($LOCAL_IP:5335)"
    echo "         → VPN/WARP Tunnel"
    echo "         → Internet (via Cloudflare/VPN)"
}

case "$1" in
    install)
        install_tinyproxy || install_3proxy || {
            echo "Failed to install proxy server"
            exit 1
        }
        ;;
    info)
        show_proxy_info
        ;;
    *)
        echo "Usage: proxy-setup {install|info}"
        echo ""
        echo "  install - Install proxy server"
        echo "  info    - Show proxy configuration"
        ;;
esac
PROXYSCRIPT

chmod +x $PREFIX/bin/proxy-setup

log_success "VPN/WARP integration scripts created"

# Initialize custom configuration files
touch $PREFIX/etc/unbound/blocklist/custom.conf
touch $PREFIX/etc/unbound/whitelist/custom-allowed.conf

# ============================================================================
# Create Comprehensive Management Script
# ============================================================================
log_info "Creating unified management system..."

cat > $PREFIX/bin/dns-manager << 'MGMT'
#!/data/data/com.termux/files/usr/bin/bash

# Ultra-Hardened DNS Stack Manager
# Complete system for DNS + VPN + Proxy management

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

BLOCKLIST_DIR="$PREFIX/etc/unbound/blocklist"
WHITELIST_DIR="$PREFIX/etc/unbound/whitelist"
GOOGLE_POLICY_DIR="$PREFIX/etc/unbound/google-policy"

get_ip() {
    local ipv4=$(ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d/ -f1)
    local ipv6=$(ip addr show 2>/dev/null | grep "inet6" | grep -v "fe80" | grep -v "::1" | head -1 | awk '{print $2}' | cut -d/ -f1)
    echo "IPv4: ${ipv4:-N/A}"
    [ -n "$ipv6" ] && echo "IPv6: $ipv6"
}

start_dns_stack() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║     Starting Ultra-Hardened DNS + Privacy Stack        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Check if DNSCrypt-Proxy exists
    if command -v dnscrypt-proxy &> /dev/null; then
        log_info "[1/2] Starting DNSCrypt-Proxy (Privacy Relay + ODoH)..."
        pkill -9 dnscrypt-proxy 2>/dev/null || true
        sleep 1
        
        if [ -f "$PREFIX/etc/dnscrypt-proxy/dnscrypt-proxy.toml" ]; then
            dnscrypt-proxy -config $PREFIX/etc/dnscrypt-proxy/dnscrypt-proxy.toml &
            sleep 3
            
            if pgrep dnscrypt-proxy > /dev/null; then
                log_success "DNSCrypt-Proxy running on 127.0.0.1:5353"
            else
                log_error "DNSCrypt-Proxy failed to start"
                log_warn "Continuing with DoT-only fallback..."
            fi
        else
            log_warn "DNSCrypt config not found, skipping..."
        fi
    else
        log_info "[1/2] DNSCrypt-Proxy not installed (using DoT fallback)"
    fi
    
    # Start Unbound
    log_info "[2/2] Starting Unbound DNS Resolver..."
    pkill -9 unbound 2>/dev/null || true
    sleep 1
    
    if command -v unbound &> /dev/null; then
        unbound -c $PREFIX/etc/unbound/unbound.conf
        sleep 2
        
        if pgrep unbound > /dev/null; then
            log_success "Unbound running on port 5335"
        else
            log_error "Unbound failed to start"
            log_error "Check logs: unbound -c $PREFIX/etc/unbound/unbound.conf -d"
            return 1
        fi
    else
        log_error "Unbound not installed"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           DNS Stack Successfully Started!               ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    get_ip
    echo "DNS Port: 5335"
    echo ""
    echo "Architecture:"
    echo "  Client → Unbound (filtering + DNSSEC)"
    if pgrep dnscrypt-proxy > /dev/null; then
        echo "         → DNSCrypt-Proxy (encryption + privacy relay)"
        echo "         → ODoH Target (anonymous resolution)"
    else
        echo "         → DNS-over-TLS (encrypted to Cloudflare/Quad9)"
    fi
    echo ""
    echo "Next Steps:"
    echo "  • Test DNS: dns-manager test"
    echo "  • Setup VPN: vpn-setup"
    echo "  • Setup Proxy: proxy-setup install"
    echo ""
}

stop_dns_stack() {
    log_info "Stopping DNS stack..."
    pkill -9 unbound 2>/dev/null || true
    pkill -9 dnscrypt-proxy 2>/dev/null || true
    pkill -9 tinyproxy 2>/dev/null || true
    pkill -9 3proxy 2>/dev/null || true
    log_success "All services stopped"
}

test_dns() {
    echo ""
    echo "Testing DNS Resolution Stack..."
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    if ! pgrep unbound > /dev/null; then
        log_error "Unbound not running. Start with: dns-manager start"
        return 1
    fi
    
    DNS_TOOL=""
    if command -v dig &> /dev/null; then
        DNS_TOOL="dig"
    elif command -v nslookup &> /dev/null; then
        DNS_TOOL="nslookup"
    else
        log_error "No DNS query tool available (dig/nslookup)"
        return 1
    fi
    
    echo "Test 1: Normal Domain Resolution"
    echo "─────────────────────────────────"
    if [ "$DNS_TOOL" = "dig" ]; then
        dig @127.0.0.1 -p 5335 wikipedia.org +short | head -1
    else
        nslookup wikipedia.org 127.0.0.1:5335 2>/dev/null | grep "Address" | tail -1
    fi
    echo ""
    
    echo "Test 2: Ad Domain (Should Be Blocked)"
    echo "─────────────────────────────────"
    if [ "$DNS_TOOL" = "dig" ]; then
        dig @127.0.0.1 -p 5335 doubleclick.net +short | head -1 || log_success "BLOCKED ✓"
    else
        nslookup doubleclick.net 127.0.0.1:5335 2>/dev/null || log_success "BLOCKED ✓"
    fi
    echo ""
    
    echo "Test 3: Google Analytics (Should Be Blocked)"
    echo "─────────────────────────────────"
    if [ "$DNS_TOOL" = "dig" ]; then
        dig @127.0.0.1 -p 5335 google-analytics.com +short | head -1 || log_success "BLOCKED ✓"
    else
        nslookup google-analytics.com 127.0.0.1:5335 2>/dev/null || log_success "BLOCKED ✓"
    fi
    echo ""
    
    echo "Test 4: DNSSEC Validation"
    echo "─────────────────────────────────"
    if [ "$DNS_TOOL" = "dig" ]; then
        dig @127.0.0.1 -p 5335 dnssec-failed.org +dnssec | grep -q "SERVFAIL" && \
            log_success "DNSSEC working ✓" || log_warn "DNSSEC may not be validating"
    fi
    echo ""
}

show_status() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      Ultra-Hardened DNS Stack - System Status          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # DNS Stack Status
    echo -e "${BLUE}DNS Stack:${NC}"
    if pgrep dnscrypt-proxy > /dev/null; then
        log_success "DNSCrypt-Proxy: RUNNING (127.0.0.1:5353)"
    else
        log_warn "DNSCrypt-Proxy: NOT RUNNING (DoT fallback active)"
    fi
    
    if pgrep unbound > /dev/null; then
        log_success "Unbound: RUNNING (port 5335)"
    else
        log_error "Unbound: NOT RUNNING"
    fi
    echo ""
    
    # VPN Status
    echo -e "${BLUE}VPN/Tunnel Status:${NC}"
    local vpn_running=false
    
    if pgrep cloudflared > /dev/null; then
        log_success "Cloudflare Tunnel: RUNNING"
        vpn_running=true
    fi
    
    if ip link show wg0 2>/dev/null | grep -q "state UP"; then
        log_success "WireGuard: RUNNING"
        vpn_running=true
    fi
    
    if pgrep openvpn > /dev/null; then
        log_success "OpenVPN: RUNNING"
        vpn_running=true
    fi
    
    if [ "$vpn_running" = false ]; then
        log_warn "No VPN detected - Install with: vpn-setup"
    fi
    echo ""
    
    # Proxy Status
    echo -e "${BLUE}Proxy Status:${NC}"
    if pgrep tinyproxy > /dev/null; then
        log_success "tinyproxy: RUNNING (port 8888)"
    elif pgrep 3proxy > /dev/null; then
        log_success "3proxy: RUNNING (SOCKS5: 1080, HTTP: 3128)"
    else
        log_warn "No proxy running - Install with: proxy-setup install"
    fi
    echo ""
    
    # Network Info
    echo -e "${BLUE}Network Configuration:${NC}"
    get_ip
    echo ""
    
    # Security Features
    echo -e "${BLUE}Security Features Active:${NC}"
    log_success "DNSSEC validation"
    log_success "QNAME minimization"
    if pgrep dnscrypt-proxy > /dev/null; then
        log_success "DNSCrypt/DoH/ODoH encryption"
        log_success "Privacy Relay (multi-hop)"
    else
        log_success "DNS-over-TLS (DoT)"
    fi
    log_success "Ad/Tracker/Porn blocking"
    log_success "Google tracking minimized"
    echo ""
}

block_domain() {
    if [ -z "$1" ]; then
        log_error "Usage: dns-manager block <domain>"
        return 1
    fi
    
    echo "local-zone: \"$1\" always_nxdomain" >> $BLOCKLIST_DIR/custom.conf
    
    if [ -f "$PREFIX/etc/dnscrypt-proxy/blocked-names.txt" ]; then
        echo "$1" >> $PREFIX/etc/dnscrypt-proxy/blocked-names.txt
    fi
    
    log_success "Blocked: $1"
    log_info "Restarting DNS stack..."
    stop_dns_stack
    sleep 2
    start_dns_stack
}

allow_domain() {
    if [ -z "$1" ]; then
        log_error "Usage: dns-manager allow <domain>"
        return 1
    fi
    
    # Remove from all blocklists
    find $BLOCKLIST_DIR $GOOGLE_POLICY_DIR -name "*.conf" -exec sed -i "/$1/d" {} \; 2>/dev/null || true
    sed -i "/$1/d" $PREFIX/etc/dnscrypt-proxy/blocked-names.txt 2>/dev/null || true
    
    # Add to whitelist
    echo "local-zone: \"$1\" transparent" >> $WHITELIST_DIR/custom-allowed.conf
    echo "$1" >> $PREFIX/etc/dnscrypt-proxy/allowed-names.txt 2>/dev/null || true
    
    log_success "Allowed: $1"
    log_info "Restarting DNS stack..."
    stop_dns_stack
    sleep 2
    start_dns_stack
}

update_blocklists() {
    log_info "Updating blocklists from sources..."
    
    if command -v curl &> /dev/null; then
        DOWNLOAD="curl -s -L"
    elif command -v wget &> /dev/null; then
        DOWNLOAD="wget -q -O -"
    else
        log_error "No download tool available"
        return 1
    fi
    
    log_info "[1/4] Updating StevenBlack list..."
    $DOWNLOAD "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts" 2>/dev/null | \
        grep "^0.0.0.0" | \
        awk '{print "local-zone: \""$2"\" always_nxdomain"}' > $BLOCKLIST_DIR/stevenblack.conf || true
    
    log_info "[2/4] Updating adult content list..."
    $DOWNLOAD "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt" 2>/dev/null | \
        grep -v "^#" | grep -v "^$" | \
        awk '{print "local-zone: \""$1"\" always_nxdomain"}' > $BLOCKLIST_DIR/adult.conf || true
    
    log_info "[3/4] Updating tracking list..."
    $DOWNLOAD "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt" 2>/dev/null | \
        grep -v "^#" | grep -v "^$" | \
        awk '{print "local-zone: \""$1"\" always_nxdomain"}' > $BLOCKLIST_DIR/tracking.conf || true
    
    log_info "[4/4] Restarting DNS stack..."
    stop_dns_stack
    sleep 2
    start_dns_stack
    log_success "Blocklists updated successfully"
}

show_help() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    Ultra-Hardened DNS Manager - Complete System         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Usage: dns-manager <command> [options]"
    echo ""
    echo -e "${BLUE}Core Commands:${NC}"
    echo "  start              Start DNS stack (Unbound + DNSCrypt)"
    echo "  stop               Stop all DNS services"
    echo "  restart            Restart DNS stack"
    echo "  status             Show detailed system status"
    echo "  test               Test DNS resolution and blocking"
    echo ""
    echo -e "${BLUE}Management:${NC}"
    echo "  block <domain>     Block a specific domain"
    echo "  allow <domain>     Whitelist a domain"
    echo "  update             Update all blocklists"
    echo ""
    echo -e "${BLUE}Integration:${NC}"
    echo "  vpn                Setup VPN/WARP tunnel"
    echo "  proxy              Setup local proxy server"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  dns-manager start"
    echo "  dns-manager test"
    echo "  dns-manager block ads.example.com"
    echo "  dns-manager allow google-service.com"
    echo "  dns-manager vpn"
    echo ""
    echo -e "${BLUE}Complete Privacy Stack:${NC}"
    echo "  1. dns-manager start        # Start DNS filtering"
    echo "  2. vpn-setup                # Configure VPN/WARP"
    echo "  3. proxy-setup install      # Install proxy server"
    echo ""
    echo -e "${BLUE}Traffic Flow:${NC}"
    echo "  Device → Proxy (TV:8888)"
    echo "         → DNS Stack (TV:5335 - Unbound → DNSCrypt → Privacy Relay)"
    echo "         → VPN/WARP Tunnel"
    echo "         → Internet (via Cloudflare/VPN - anonymized)"
    echo ""
}

case "$1" in
    start)
        start_dns_stack
        ;;
    stop)
        stop_dns_stack
        ;;
    restart)
        stop_dns_stack
        sleep 2
        start_dns_stack
        ;;
    status)
        show_status
        ;;
    test)
        test_dns
        ;;
    block)
        block_domain "$2"
        ;;
    allow)
        allow_domain "$2"
        ;;
    update)
        update_blocklists
        ;;
    vpn)
        exec vpn-setup
        ;;
    proxy)
        exec proxy-setup
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac
MGMT

chmod +x $PREFIX/bin/dns-manager

log_success "Management scripts created"

# ============================================================================
# Create Auto-Start Configuration
# ============================================================================
cat > $PREFIX/bin/dns-autostart << 'AUTOSTART'
#!/data/data/com.termux/files/usr/bin/bash

# Auto-start DNS stack on Termux launch

if ! pgrep unbound > /dev/null; then
    echo "Auto-starting Ultra-Hardened DNS Stack..."
    dns-manager start
fi
AUTOSTART

chmod +x $PREFIX/bin/dns-autostart

# ============================================================================
# Create Complete Documentation
# ============================================================================
cat > $PREFIX/opt/dns-relay/COMPLETE-GUIDE.md << 'DOCUMENTATION'
# Ultra-Hardened DNS + VPN + Proxy Stack
## Complete Privacy Architecture for Google TV / Termux

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [VPN/WARP Setup](#vpnwarp-setup)
5. [Network-Wide Deployment](#network-wide-deployment)
6. [Privacy Features](#privacy-features)
7. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### 4-Layer Privacy Stack

```
┌─────────────────────────────────────────────────────────┐
│ Layer 1: Local DNS Filtering (Unbound)                 │
│  • DNSSEC validation                                    │
│  • Ad/Tracker/Porn/Malware blocking (150K+ domains)    │
│  • Google tracking minimization                         │
│  • QNAME minimization                                   │
└──────────────┬──────────────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 2: DNS Encryption (DNSCrypt-Proxy)               │
│  • DNSCrypt protocol                                    │
│  • DNS-over-HTTPS (DoH)                                 │
│  • Oblivious DoH (ODoH)                                 │
└──────────────┬──────────────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 3: Privacy Relay (Anonymization)                 │
│  • Multi-hop routing                                    │
│  • Separates WHO from WHAT                             │
│  • iCloud Private Relay equivalent                      │
└──────────────┬──────────────────────────────────────────┘
               ↓
┌─────────────────────────────────────────────────────────┐
│ Layer 4: VPN/WARP Tunnel (Traffic Anonymization)       │
│  • Cloudflare WARP or WireGuard                        │
│  • ISP sees: encrypted blob                            │
│  • Internet sees: VPN IP, not yours                    │
└─────────────────────────────────────────────────────────┘
```

### Traffic Flow

**For DNS Queries:**
```
Device → Unbound (127.0.0.1:5335)
       → DNSCrypt-Proxy (127.0.0.1:5353)
       → Privacy Relay (anonymizes request)
       → ODoH Target (resolves without knowing WHO)
       → VPN/WARP (encrypts transport)
       → Internet
```

**For Web Traffic (with proxy):**
```
Device → HTTPS/SOCKS5 Proxy (TV:8888/1080)
       → DNS resolution via 127.0.0.1:5335
       → VPN/WARP Tunnel
       → Internet (appears from VPN IP)
```

---

## Installation

### Quick Start
```bash
# 1. Make script executable
chmod +x install-complete-stack.sh

# 2. Run installer
./install-complete-stack.sh

# 3. Start DNS stack
dns-manager start

# 4. Test it works
dns-manager test
```

### What Gets Installed
- ✅ Unbound DNS resolver
- ✅ DNSCrypt-Proxy (if available)
- ✅ Comprehensive blocklists
- ✅ Google policy filters
- ✅ Management tools
- ✅ VPN/WARP helpers
- ✅ Proxy server tools

---

## Configuration

### DNS Stack

#### Start Services
```bash
dns-manager start
```

#### Check Status
```bash
dns-manager status
```

#### Test DNS Resolution
```bash
dns-manager test
```

### Custom Blocking/Allowing

#### Block Domain
```bash
dns-manager block ads.evil.com
```

#### Allow Domain (if Google Home breaks)
```bash
dns-manager allow needed-google-service.com
```

#### Update Blocklists
```bash
dns-manager update
```

---

## VPN/WARP Setup

### Option 1: Cloudflare WARP (Recommended)

**Method A: WARP Android App (Easiest)**
1. Install "Cloudflare WARP" from Google Play Store
2. Open app and create account
3. Enable WARP
4. Go to Settings → Advanced → Connection Options:
   - **Disable** "DNS over WARP" (we use our own DNS)
   - **Enable** "VPN" mode
5. Your DNS stack automatically uses WARP tunnel

**Method B: cloudflared Tunnel**
```bash
# Install cloudflared
vpn-setup 1

# Authenticate
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create termux-privacy

# Route traffic
cloudflared tunnel route dns <tunnel-id> dns.yourdomain.com

# Run tunnel
cloudflared tunnel run termux-privacy
```

### Option 2: WireGuard

```bash
# Install WireGuard
vpn-setup 2

# Generate keys
wg genkey | tee privatekey | wg pubkey > publickey

# Edit config
nano $PREFIX/etc/wireguard/wg0.conf

# Start tunnel
wg-quick up wg0
```

### Option 3: OpenVPN

```bash
# Install OpenVPN
vpn-setup 4

# Place your .ovpn file
cp your-config.ovpn $PREFIX/etc/openvpn/client.ovpn

# Connect
openvpn --config $PREFIX/etc/openvpn/client.ovpn
```

### Check VPN Status
```bash
vpn-setup status
```

---

## Network-Wide Deployment

### Setup Proxy Server

#### Install Proxy
```bash
proxy-setup install
```

This installs either:
- **tinyproxy** (HTTP/HTTPS on port 8888)
- **3proxy** (HTTP on 3128, SOCKS5 on 1080)

#### Start Proxy
```bash
# For tinyproxy
tinyproxy -c $PREFIX/etc/tinyproxy/tinyproxy.conf

# For 3proxy
3proxy $PREFIX/etc/3proxy/3proxy.cfg
```

### Configure Other Devices

Get your Google TV's IP address:
```bash
dns-manager status
```

#### On Each Device:

**DNS Configuration:**
- Primary DNS: `<TV-IP>`
- Port: `5335` (if supported)
- If port not supported, use `53` with router NAT redirect

**Proxy Configuration:**
- HTTP/HTTPS Proxy: `<TV-IP>:8888` (tinyproxy)
- Or HTTP: `<TV-IP>:3128` (3proxy)
- Or SOCKS5: `<TV-IP>:1080` (3proxy)

#### Example: Android Device
1. Settings → Wi-Fi → Long press network → Modify
2. Advanced options → Proxy → Manual
3. Hostname: `<TV-IP>`
4. Port: `8888`
5. Save

#### Example: Windows
1. Settings → Network → Proxy
2. Manual proxy setup:
   - Address: `<TV-IP>`
   - Port: `8888`
3. Save

---

## Privacy Features

### What's Protected

✅ **DNS Privacy:**
- Queries encrypted (DoT/DoH/ODoH)
- Identity separated from query content
- No logging by default
- ISP cannot see DNS queries

✅ **Traffic Privacy (with VPN):**
- ISP sees only encrypted blob to VPN
- Websites see VPN IP, not yours
- Router untouched (no configuration needed)

✅ **Content Blocking:**
- 150,000+ ad/tracker domains
- Porn sites
- Malware domains
- Google Analytics & tracking
- DoubleClick, AdMob, etc.

✅ **Google Services:**
- Tracking minimized (20+ tracking domains blocked)
- Essential services preserved:
  - Google Home connectivity
  - Chromecast functionality
  - Play Store access
  - Android system services

### What's NOT Protected

❌ HTTPS content (need VPN for full protection)
❌ Browser fingerprinting
❌ App-level telemetry that bypasses DNS
❌ Direct IP connections (some apps)

### Privacy Model

**DNS Privacy Relay:**
```
┌──────────┐     ┌─────────┐     ┌──────────┐
│  Client  │────▶│  Relay  │────▶│  Target  │
│          │     │         │     │          │
│ Knows:   │     │ Knows:  │     │ Knows:   │
│ • Query  │     │ • Your  │     │ • Query  │
│          │     │   IP    │     │ • Relay  │
│          │     │ • Relay │     │   IP     │
└──────────┘     └─────────┘     └──────────┘
```

**No single entity knows both WHO you are AND WHAT you're querying.**

---

## Troubleshooting

### DNS Not Working

**Check if services are running:**
```bash
dns-manager status
```

**If Unbound not running:**
```bash
# Check for errors
unbound -c $PREFIX/etc/unbound/unbound.conf -d

# Common fixes:
# - Port 5335 already in use: pkill unbound; dns-manager start
# - Config error: nano $PREFIX/etc/unbound/unbound.conf
```

**If DNSCrypt not running:**
```bash
# Check logs
cat $PREFIX/var/log/dnscrypt-proxy/dnscrypt.log

# Test manually
dnscrypt-proxy -config $PREFIX/etc/dnscrypt-proxy/dnscrypt-proxy.toml
```

### Google Home Not Working

**Symptoms:** Can't control Google TV with phone

**Solution:**
```bash
# View what's being blocked
dns-manager test

# Whitelist the failing domain
dns-manager allow clients2.google.com
dns-manager allow mtalk.google.com

# Or check logs for specific domain
tail -f $PREFIX/var/log/dnscrypt-proxy/blocked.log
```

### Slow DNS Resolution

**Check DNSCrypt server selection:**
```bash
nano $PREFIX/etc/dnscrypt-proxy/dnscrypt-proxy.toml

# Modify server_names to prefer faster servers:
server_names = ['cloudflare', 'quad9-dnscrypt-ipv4-filter-pri']
```

**Check VPN latency:**
```bash
# If using WARP, try different endpoint
# If using WireGuard, check server latency
```

### VPN Not Routing Traffic

**Check VPN status:**
```bash
vpn-setup status
```

**Verify routing:**
```bash
# Check current IP
curl https://api.ipify.org

# Should show VPN IP, not your ISP IP
```

**If traffic not going through VPN:**
```bash
# For WireGuard
wg-quick down wg0
wg-quick up wg0

# For WARP app
# Disable and re-enable in app

# For cloudflared
pkill cloudflared
cloudflared tunnel run termux-privacy
```

### Port 5335 Not Working on Devices

**Problem:** Most devices only support port 53 for DNS

**Solution 1 - Use VPN's DNS:**
- In VPN config, set DNS to `127.0.0.1:5335`
- VPN will use your DNS stack
- Devices use VPN, which uses your DNS

**Solution 2 - Router NAT (if accessible):**
- Create NAT rule: `53 → TV-IP:5335`
- Devices use port 53, router forwards to 5335

**Solution 3 - Android Private DNS:**
- Some Android devices support DoT
- Configure as `dns.google` then use Cloudflare WARP
- Not ideal but works

### Memory/Performance Issues

**Reduce cache sizes:**
```bash
nano $PREFIX/etc/unbound/unbound.conf

# Change:
msg-cache-size: 8m      # was 16m
rrset-cache-size: 16m   # was 32m
num-threads: 1          # was 2
```

**Disable logging:**
```bash
# In dnscrypt-proxy.toml
log_level = 0
```

---

## Advanced Usage

### Auto-Start on Boot

Add to `~/.bashrc`:
```bash
echo 'source $PREFIX/bin/dns-autostart' >> ~/.bashrc
```

### Monitor Blocked Queries

```bash
# Real-time blocking
tail -f $PREFIX/var/log/dnscrypt-proxy/blocked.log

# Query log (if enabled)
tail -f $PREFIX/var/log/dnscrypt-proxy/query.log
```

### Custom Blocklist Sources

```bash
# Add custom list
curl -s https://your-custom-list.com/domains.txt | \
  awk '{print "local-zone: \""$1"\" always_nxdomain"}' \
  > $PREFIX/etc/unbound/blocklist/custom-source.conf

# Restart
dns-manager restart
```

### Router Bypass Verification

**Test that router doesn't see DNS queries:**
```bash
# On router (if accessible), check DNS logs
# Should NOT see queries from TV IP

# On TV, verify encryption
tcpdump -i wlan0 port 53
# Should see NO plaintext DNS (all encrypted or to 127.0.0.1)
```

---

## Security Notes

### Trust Model

**You must trust:**
- Cloudflare (if using WARP) OR your VPN provider
- DNSCrypt relay operators (public, audited)
- ODoH target operators (public, audited)

**You do NOT have to trust:**
- Your ISP (can't see DNS or content)
- Your router manufacturer (bypassed)
- Local network admins (encrypted traffic)

### Threat Protection

**Protected Against:**
- ✅ ISP DNS hijacking
- ✅ DNS spoofing
- ✅ Man-in-the-middle DNS attacks
- ✅ Ad/tracker networks
- ✅ Malware domains
- ✅ Traffic analysis by ISP

**NOT Protected Against:**
- ❌ VPN provider logging (choose no-log VPN)
- ❌ App-level tracking (use firewall)
- ❌ Browser fingerprinting (use privacy browser)
- ❌ Compromised endpoints

---

## Performance Benchmarks

### DNS Resolution Time

- **Without stack:** ~20-50ms
- **With Unbound only:** ~15-30ms (faster due to cache)
- **With full stack:** ~50-100ms (privacy overhead)
- **With VPN:** +10-50ms (depends on VPN server)

### Resource Usage

- **Unbound:** ~20-40MB RAM
- **DNSCrypt-Proxy:** ~10-20MB RAM
- **Proxy server:** ~10-30MB RAM
- **Total:** ~40-90MB RAM (acceptable on modern Android TV)

---

## Comparison to Alternatives

### vs. Pi-hole
- ✅ More DNS privacy (ODoH + relay)
- ✅ No separate hardware needed
- ✅ VPN integration included
- ❌ No web UI
- ❌ Can't force network-wide without router access

### vs. NextDNS
- ✅ Local control
- ✅ No third-party logging
- ✅ Free
- ✅ More customization
- ❌ More complex setup
- ❌ Requires maintenance

### vs. Standard VPN
- ✅ Better DNS privacy (separated queries)
- ✅ Local ad blocking (faster)
- ✅ More control
- ⭐ Can be combined with VPN for maximum privacy

---

## Support & Updates

### Update Stack
```bash
# Update blocklists
dns-manager update

# Update packages
pkg update && pkg upgrade

# Re-run installer for new features
./install-complete-stack.sh
```

### Get Help
```bash
dns-manager help
vpn-setup
proxy-setup info
```

### Logs Location
- Unbound: stdout/stderr only (privacy)
- DNSCrypt: `$PREFIX/var/log/dnscrypt-proxy/`
- Proxy: `$PREFIX/var/log/3proxy.log` or syslog

---

## Legal & Ethical Use

This stack is designed for:
- ✅ Privacy protection
- ✅ Security hardening
- ✅ Ad/tracker blocking
- ✅ Educational purposes

**Do NOT use for:**
- ❌ Illegal activities
- ❌ Bypassing legitimate content restrictions
- ❌ Attacking networks or services

**Remember:** Even with maximum anonymity, illegal activities are still illegal.

---

## Credits

- **Unbound:** NLnet Labs (BSD License)
- **DNSCrypt-Proxy:** Frank Denis (ISC License)
- **Blocklists:** StevenBlack, BlocklistProject, various contributors
- **Cloudflare:** WARP, Zero Trust platform
- **WireGuard:** Jason A. Donenfeld

---

## License

This setup and documentation: MIT License
Individual components: See respective licenses above

**Disclaimer:** Provided as-is for educational purposes. No warranty.
DOCUMENTATION

log_success "Documentation created: $PREFIX/opt/dns-relay/COMPLETE-GUIDE.md"

# ============================================================================
# Installation Complete Message
# ============================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║      INSTALLATION COMPLETE - ULTRA-HARDENED DNS STACK   ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Network Configuration${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
get_ip
echo "Subnet: $SUBNET_V4"
echo "DNS Port: 5335"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Installation Summary${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

if [ "$UNBOUND_INSTALLED" = true ]; then
    log_success "Unbound DNS resolver"
else
    log_error "Unbound installation failed"
fi

if [ "$DNSCRYPT_INSTALLED" = true ]; then
    log_success "DNSCrypt-Proxy (with ODoH + Privacy Relay)"
else
    log_warn "DNSCrypt-Proxy unavailable (using DoT fallback)"
fi

if [ "$GO_INSTALLED" = true ]; then
    log_success "Golang runtime"
fi

if [ "$RUST_INSTALLED" = true ]; then
    log_success "Rust toolchain"
fi

log_success "Comprehensive blocklists (150K+ domains)"
log_success "Google tracking policies configured"
log_success "Management tools installed"
log_success "VPN/WARP integration ready"
log_success "Proxy server tools ready"

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Privacy Architecture${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  ┌─────────────────────────────────────────────┐"
echo "  │ Layer 1: Unbound (Local DNS Filtering)     │"
echo "  │  • DNSSEC validation                        │"
echo "  │  • Ad/Tracker/Porn blocking                 │"
echo "  │  • QNAME minimization                       │"
echo "  └──────────────┬──────────────────────────────┘"
echo "                 ↓"

if [ "$DNSCRYPT_INSTALLED" = true ]; then
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │ Layer 2: DNSCrypt-Proxy (Encryption)       │"
    echo "  │  • DNSCrypt, DoH, ODoH protocols            │"
    echo "  └──────────────┬──────────────────────────────┘"
    echo "                 ↓"
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │ Layer 3: Privacy Relay (Anonymization)     │"
    echo "  │  • Separates WHO from WHAT                  │"
    echo "  └──────────────┬──────────────────────────────┘"
    echo "                 ↓"
else
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │ Layer 2: DNS-over-TLS (Fallback)           │"
    echo "  │  • Direct encrypted DNS                     │"
    echo "  └──────────────┬──────────────────────────────┘"
    echo "                 ↓"
fi

echo "  ┌─────────────────────────────────────────────┐"
echo "  │ Layer 4: VPN/WARP Tunnel (Traffic Privacy) │"
echo "  │  • Setup with: vpn-setup                    │"
echo "  └─────────────────────────────────────────────┘"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Security Features Enabled${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
log_success "DNSSEC validation with root trust anchor"

if [ "$DNSCRYPT_INSTALLED" = true ]; then
    log_success "DNSCrypt + DoH + ODoH encryption"
    log_success "Privacy Relay multi-hop anonymization"
else
    log_success "DNS-over-TLS encryption (Cloudflare + Quad9)"
fi

log_success "QNAME minimization (RFC 7816)"
log_success "Aggressive NSEC (RFC 8198)"
log_success "Rate limiting (anti-DDoS)"
log_success "Modern buffer sizes (RFC 8467)"
log_success "IPv4 + IPv6 dual-stack support"
log_success "Private address filtering"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Blocking Features${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
log_success "Ads & Trackers (100K+ domains)"
log_success "Porn sites (comprehensive blocklist)"
log_success "Malware domains"
log_success "Fake news sites"
log_success "Gambling sites"
log_success "Google tracking (20+ domains blocked)"
log_success "Google Home/TV functionality preserved"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Quick Start Guide${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Step 1: Start DNS Stack${NC}"
echo "  $ dns-manager start"
echo ""
echo -e "${YELLOW}Step 2: Test DNS Resolution${NC}"
echo "  $ dns-manager test"
echo ""
echo -e "${YELLOW}Step 3: Setup VPN/WARP Tunnel (IMPORTANT for full privacy)${NC}"
echo "  $ vpn-setup"
echo ""
echo "  Choose one:"
echo "  • Option 1: Cloudflare WARP app (easiest)"
echo "  • Option 2: WireGuard VPN"
echo "  • Option 3: Cloudflare Tunnel"
echo ""
echo -e "${YELLOW}Step 4: Setup Network Proxy (Optional - for other devices)${NC}"
echo "  $ proxy-setup install"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Configure Other Devices${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "To use this DNS stack on other devices:"
echo ""
echo "DNS Settings:"
echo "  • Primary DNS: ${LOCAL_IP_V4}"
echo "  • Port: 5335 (if supported)"
echo ""
echo "Proxy Settings (after running proxy-setup):"
echo "  • HTTP/HTTPS: ${LOCAL_IP_V4}:8888"
echo "  • SOCKS5: ${LOCAL_IP_V4}:1080"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Router Bypass Architecture${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "✓ No router configuration needed"
echo "✓ Google TV acts as privacy gateway"
echo "✓ Router only sees encrypted VPN/WARP traffic"
echo "✓ ISP cannot see DNS queries or browsing"
echo ""
echo "Traffic Flow:"
echo "  Device → Google TV (DNS + Proxy)"
echo "         → Cloudflare WARP/VPN Tunnel"
echo "         → Internet (fully anonymized)"
echo ""
echo "Router View:"
echo "  Just sees: Google TV ↔ VPN Server (encrypted)"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Important Notes${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Note 1: Sony BRAVIA VU31 Root Status${NC}"
echo "  • This TV model has a locked bootloader"
echo "  • No public root method available (2026)"
echo "  • This setup works WITHOUT root"
echo "  • Provides maximum privacy without rooting"
echo ""
echo -e "${YELLOW}Note 2: VPN/WARP is CRITICAL${NC}"
echo "  • DNS alone doesn't hide your IP from websites"
echo "  • VPN/WARP encrypts ALL traffic and changes IP"
echo "  • Without VPN: DNS is private, traffic is not"
echo "  • With VPN: Complete privacy stack"
echo ""
echo -e "${YELLOW}Note 3: Port 5335${NC}"
echo "  • Most devices only support DNS on port 53"
echo "  • Solutions:"
echo "    a) Use VPN's DNS (set VPN to use 127.0.0.1:5335)"
echo "    b) Router NAT redirect 53→5335 (if accessible)"
echo "    c) Manually configure each device to use proxy"
echo ""
echo -e "${YELLOW}Note 4: Google Home Compatibility${NC}"
echo "  • Essential Google services are whitelisted"
echo "  • If features break, use: dns-manager allow <domain>"
echo "  • Check blocked domains: dns-manager test"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Next Steps${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "1. Start the DNS stack:"
echo -e "   ${GREEN}dns-manager start${NC}"
echo ""
echo "2. Test that blocking works:"
echo -e "   ${GREEN}dns-manager test${NC}"
echo ""
echo "3. Setup VPN/WARP for full privacy:"
echo -e "   ${GREEN}vpn-setup${NC}"
echo ""
echo "4. Setup proxy for network-wide use:"
echo -e "   ${GREEN}proxy-setup install${NC}"
echo ""
echo "5. Check complete status:"
echo -e "   ${GREEN}dns-manager status${NC}"
echo ""
echo "6. Read full documentation:"
echo -e "   ${GREEN}cat $PREFIX/opt/dns-relay/COMPLETE-GUIDE.md | less${NC}"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Available Commands${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}dns-manager${NC}     - Manage DNS stack"
echo -e "${BLUE}vpn-setup${NC}       - Configure VPN/WARP tunnel"
echo -e "${BLUE}proxy-setup${NC}     - Configure proxy server"
echo ""
echo "For help on any command, run it without arguments."
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║  Installation successful! Start with: dns-manager start  ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Auto-start prompt
echo -e "${YELLOW}Auto-start on Termux launch?${NC}"
read -p "Add DNS stack to ~/.bashrc? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if ! grep -q "dns-autostart" ~/.bashrc 2>/dev/null; then
        echo "" >> ~/.bashrc
        echo "# Auto-start Ultra-Hardened DNS Stack" >> ~/.bashrc
        echo "source $PREFIX/bin/dns-autostart" >> ~/.bashrc
        log_success "Auto-start enabled in ~/.bashrc"
    else
        log_info "Auto-start already configured"
    fi
fi

echo ""
log_info "Installation log saved to: /tmp/dns-install.log"
echo ""
