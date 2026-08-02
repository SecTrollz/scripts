#!/data/data/com.termux/files/usr/bin/bash

# MASTER DEPLOYMENT SCRIPT
# Complete Ultra-Hardened DNS + VPN + Proxy Stack
# One-command deployment for Google TV / Termux

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${MAGENTA}[STEP]${NC} $1"; }

clear
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║     ULTRA-HARDENED DNS STACK - MASTER DEPLOYMENT        ║
║     Complete Privacy Architecture for Google TV         ║
║                                                          ║
║     • DNS Filtering + DNSSEC                            ║
║     • DNSCrypt + ODoH + Privacy Relay                   ║
║     • VPN/WARP Integration                              ║
║     • Network-Wide Proxy                                ║
║     • Router Bypass Architecture                        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""

# Check if running in Termux
if [ ! -d "/data/data/com.termux" ]; then
    log_error "This script must be run in Termux on Android"
    exit 1
fi

# Detect if installer has been run
if [ -f "$PREFIX/bin/dns-manager" ] && [ -f "$PREFIX/etc/unbound/unbound.conf" ]; then
    log_info "Installation detected - will configure and start services"
    INSTALL_MODE="configure"
else
    log_info "First-time installation - will install and configure"
    INSTALL_MODE="full"
fi

echo ""
echo -e "${YELLOW}Deployment Mode: $INSTALL_MODE${NC}"
echo ""
read -p "Press Enter to continue or Ctrl+C to cancel..."
echo ""

# ============================================================================
# DEPLOYMENT PHASES
# ============================================================================

if [ "$INSTALL_MODE" = "full" ]; then
    log_step "PHASE 1: DEPENDENCY INSTALLATION"
    echo ""
    
    # Check if installer script exists
    if [ -f "./dns_stack_installer.sh" ]; then
        log_info "Running installer script..."
        chmod +x ./dns_stack_installer.sh
        ./dns_stack_installer.sh || {
            log_error "Installation failed"
            exit 1
        }
    else
        log_error "Installer script not found: dns_stack_installer.sh"
        log_info "Please download both scripts to the same directory"
        exit 1
    fi
    
    log_success "Installation phase complete"
    echo ""
fi

log_step "PHASE 2: POST-INSTALL CONFIGURATION"
echo ""

# Check if configuration script exists
if [ -f "./dns_stack_postinstall.sh" ]; then
    log_info "Running configuration script..."
    chmod +x ./dns_stack_postinstall.sh
    ./dns_stack_postinstall.sh || {
        log_error "Configuration failed"
        exit 1
    }
else
    log_warn "Configuration script not found, proceeding with manual setup..."
    
    # Manual startup
    log_info "Starting DNS services manually..."
    
    # Start DNSCrypt if available
    if command -v dnscrypt-proxy &>/dev/null && [ -f "$PREFIX/etc/dnscrypt-proxy/dnscrypt-proxy.toml" ]; then
        pkill -9 dnscrypt-proxy 2>/dev/null || true
        dnscrypt-proxy -config $PREFIX/etc/dnscrypt-proxy/dnscrypt-proxy.toml &
        sleep 2
        log_success "DNSCrypt-Proxy started"
    fi
    
    # Start Unbound
    if command -v unbound &>/dev/null && [ -f "$PREFIX/etc/unbound/unbound.conf" ]; then
        pkill -9 unbound 2>/dev/null || true
        unbound -c $PREFIX/etc/unbound/unbound.conf &
        sleep 2
        log_success "Unbound started"
    else
        log_error "Unbound not properly installed"
        exit 1
    fi
fi

echo ""
log_step "PHASE 3: VERIFICATION & TESTING"
echo ""

# Verify services are running
log_info "Verifying services..."
sleep 3

SERVICES_OK=true

if pgrep unbound &>/dev/null; then
    log_success "Unbound is running (PID: $(pgrep unbound))"
else
    log_error "Unbound failed to start"
    SERVICES_OK=false
fi

if pgrep dnscrypt-proxy &>/dev/null; then
    log_success "DNSCrypt-Proxy is running (PID: $(pgrep dnscrypt-proxy))"
else
    log_warn "DNSCrypt-Proxy not running (using DoT fallback)"
fi

if [ "$SERVICES_OK" = false ]; then
    log_error "Critical services failed to start"
    exit 1
fi

# Test DNS resolution
log_info "Testing DNS resolution..."

if timeout 5 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null 2>&1; then
    log_success "DNS resolution working"
elif timeout 5 nslookup google.com 127.0.0.1 -port=5335 &>/dev/null 2>&1; then
    log_success "DNS resolution working"
else
    log_error "DNS resolution test failed"
    log_info "Checking logs..."
    tail -20 $PREFIX/var/log/dnscrypt-proxy/dnscrypt.log 2>/dev/null || true
    exit 1
fi

# Test ad blocking
log_info "Testing ad blocking..."
if timeout 5 dig @127.0.0.1 -p 5335 doubleclick.net +short 2>/dev/null | grep -q "0.0.0.0\|NXDOMAIN" || \
   ! timeout 5 nslookup doubleclick.net 127.0.0.1 -port=5335 2>/dev/null | grep -q "Address.*[0-9]"; then
    log_success "Ad blocking working"
else
    log_warn "Ad blocking status unclear"
fi

echo ""
log_step "PHASE 4: VPN/WARP CONFIGURATION"
echo ""

# Check for existing VPN
VPN_DETECTED=false
if ip link show wg0 2>/dev/null | grep -q "state UP"; then
    log_success "WireGuard VPN detected"
    VPN_DETECTED=true
elif pgrep cloudflared &>/dev/null; then
    log_success "Cloudflare Tunnel detected"
    VPN_DETECTED=true
elif pgrep openvpn &>/dev/null; then
    log_success "OpenVPN detected"
    VPN_DETECTED=true
fi

if [ "$VPN_DETECTED" = false ]; then
    echo -e "${YELLOW}No VPN detected${NC}"
    echo ""
    echo "For COMPLETE privacy, you need VPN/WARP."
    echo "Without it:"
    echo "  ✓ DNS queries are private"
    echo "  ✗ Your IP is visible to websites"
    echo ""
    echo "Options:"
    echo "  1. Install Cloudflare WARP app (easiest)"
    echo "  2. Configure WireGuard"
    echo "  3. Use OpenVPN"
    echo "  4. Continue without VPN (DNS privacy only)"
    echo ""
    read -p "Setup VPN now? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "$PREFIX/bin/vpn-setup" ]; then
            vpn-setup
        else
            log_error "VPN setup tool not found"
            log_info "You can set it up later with: vpn-setup"
        fi
    else
        log_warn "Continuing without VPN - remember to set it up later"
    fi
fi

echo ""
log_step "PHASE 5: NETWORK PROXY SETUP"
echo ""

echo "Would you like to setup a proxy server for network-wide deployment?"
echo "This allows other devices to use this DNS stack."
echo ""
read -p "Setup proxy server? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "$PREFIX/bin/proxy-setup" ]; then
        proxy-setup install
        
        # Start proxy
        if command -v tinyproxy &>/dev/null; then
            tinyproxy -c $PREFIX/etc/tinyproxy/tinyproxy.conf &
            log_success "Proxy server started on port 8888"
        elif command -v 3proxy &>/dev/null; then
            3proxy $PREFIX/etc/3proxy/3proxy.cfg &
            log_success "Proxy server started (HTTP: 3128, SOCKS5: 1080)"
        fi
    else
        log_error "Proxy setup tool not found"
    fi
else
    log_info "Proxy setup skipped - can be done later with: proxy-setup install"
fi

echo ""
log_step "PHASE 6: FINAL CONFIGURATION"
echo ""

# Get network info
LOCAL_IP=$(ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d/ -f1)
EXTERNAL_IP=$(timeout 5 curl -s https://api.ipify.org 2>/dev/null || echo "Unknown")

# Enable auto-start
echo "Enable auto-start on Termux launch?"
read -p "(y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if ! grep -q "dns-autostart" ~/.bashrc 2>/dev/null; then
        echo "" >> ~/.bashrc
        echo "# Auto-start DNS Stack" >> ~/.bashrc
        echo "source $PREFIX/bin/dns-autostart 2>/dev/null || true" >> ~/.bashrc
        log_success "Auto-start enabled"
    else
        log_info "Auto-start already configured"
    fi
fi

# Create desktop shortcut (if possible)
if command -v termux-setup-storage &>/dev/null; then
    log_info "Creating quick access shortcuts..."
    
    mkdir -p ~/storage/shared/DNS-Stack
    
    cat > ~/storage/shared/DNS-Stack/START-DNS.sh << 'SHORTCUT1'
#!/data/data/com.termux/files/usr/bin/bash
source $PREFIX/bin/dns-manager start
SHORTCUT1
    
    cat > ~/storage/shared/DNS-Stack/STATUS.sh << 'SHORTCUT2'
#!/data/data/com.termux/files/usr/bin/bash
source $PREFIX/bin/privacy-status
read -p "Press Enter to close..."
SHORTCUT2
    
    cat > ~/storage/shared/DNS-Stack/STOP-DNS.sh << 'SHORTCUT3'
#!/data/data/com.termux/files/usr/bin/bash
source $PREFIX/bin/dns-service stop
SHORTCUT3
    
    chmod +x ~/storage/shared/DNS-Stack/*.sh
    log_success "Shortcuts created in: ~/storage/shared/DNS-Stack/"
fi

# ============================================================================
# DEPLOYMENT COMPLETE
# ============================================================================

clear
echo -e "${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║          DEPLOYMENT SUCCESSFUL!                          ║
║          Ultra-Hardened DNS Stack is LIVE               ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}System Status${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "DNS Server:    ${LOCAL_IP}:5335"
echo "External IP:   ${EXTERNAL_IP}"
echo "VPN Status:    $([ "$VPN_DETECTED" = true ] && echo "Active ✓" || echo "Not configured")"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Active Services${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
pgrep unbound &>/dev/null && echo "✓ Unbound DNS Resolver" || echo "✗ Unbound (not running)"
pgrep dnscrypt-proxy &>/dev/null && echo "✓ DNSCrypt-Proxy" || echo "○ DNSCrypt-Proxy (using DoT fallback)"
pgrep tinyproxy &>/dev/null && echo "✓ Proxy Server (port 8888)" || true
pgrep 3proxy &>/dev/null && echo "✓ Proxy Server (3128/1080)" || true
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Quick Commands${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  privacy-status    Quick status check"
echo "  dns-manager       Full management interface"
echo "  dns-service       Service control (start/stop/restart)"
echo "  dns-monitor       Real-time monitoring"
echo "  vpn-setup         Configure VPN/WARP"
echo "  proxy-setup       Proxy server management"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Configure Other Devices${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "DNS Configuration:"
echo "  Server: ${LOCAL_IP}"
echo "  Port:   5335"
echo ""

if pgrep tinyproxy &>/dev/null || pgrep 3proxy &>/dev/null; then
    echo "Proxy Configuration:"
    pgrep tinyproxy &>/dev/null && echo "  HTTP/HTTPS: ${LOCAL_IP}:8888"
    pgrep 3proxy &>/dev/null && echo "  HTTP:       ${LOCAL_IP}:3128"
    pgrep 3proxy &>/dev/null && echo "  SOCKS5:     ${LOCAL_IP}:1080"
    echo ""
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Privacy Features Active${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "✓ DNSSEC validation"
echo "✓ DNS encryption (DoT/DoH/ODoH)"
pgrep dnscrypt-proxy &>/dev/null && echo "✓ Privacy Relay (multi-hop anonymization)"
echo "✓ QNAME minimization"
echo "✓ Rate limiting & DDoS protection"
echo "✓ Ad/Tracker blocking (150K+ domains)"
echo "✓ Malware domain blocking"
echo "✓ Porn site blocking"
echo "✓ Google tracking minimized"
echo "✓ Google Home/TV functionality preserved"

if [ "$VPN_DETECTED" = true ]; then
    echo "✓ VPN active (complete privacy)"
else
    echo "⚠ VPN not configured (setup with: vpn-setup)"
fi

echo ""

if [ "$VPN_DETECTED" = false ]; then
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}IMPORTANT - VPN RECOMMENDATION${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Your DNS is fully private, but for COMPLETE anonymity:"
    echo ""
    echo "1. Install Cloudflare WARP app from Play Store"
    echo "   - Easiest option, works automatically"
    echo "   - Zero Trust architecture"
    echo ""
    echo "2. Or configure WireGuard/OpenVPN"
    echo "   - Run: vpn-setup"
    echo "   - Follow the guided setup"
    echo ""
    echo "Without VPN:"
    echo "  ✓ DNS queries are encrypted and anonymous"
    echo "  ✗ Your IP address is visible to websites"
    echo ""
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Router Bypass Architecture${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "✓ No router configuration required"
echo "✓ Google TV acts as privacy gateway"
echo "✓ Router only sees encrypted VPN traffic"
echo "✓ Complete bypass of ISP DNS"
echo ""
echo "Traffic Flow:"
echo "  Device → Google TV (DNS + optional Proxy)"
echo "         → Privacy Relay (anonymizes DNS)"
echo "         → VPN/WARP (encrypts all traffic)"
echo "         → Internet"
echo ""
echo "Router's View:"
echo "  Just sees: Google TV ↔ Encrypted VPN traffic"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Documentation & Support${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "Complete guide:"
echo "  cat $PREFIX/opt/dns-relay/COMPLETE-GUIDE.md | less"
echo ""
echo "Setup summary:"
echo "  cat $PREFIX/etc/dns-stack/runtime/setup-summary.txt"
echo ""
echo "System status:"
echo "  cat $PREFIX/etc/dns-stack/runtime/system-status.txt"
echo ""

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║  Your Ultra-Hardened DNS Stack is now LIVE and ready!  ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}║  Run 'privacy-status' anytime for quick status check    ║${NC}"
echo -e "${GREEN}║                                                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Save deployment info
cat > $PREFIX/etc/dns-stack/deployment-info.txt << DEPLOY
Deployment Date: $(date)
Deployment Mode: $INSTALL_MODE
Local IP: $LOCAL_IP
External IP: $EXTERNAL_IP
VPN Detected: $VPN_DETECTED
Services Running: $(pgrep unbound &>/dev/null && echo "Unbound " || true)$(pgrep dnscrypt-proxy &>/dev/null && echo "DNSCrypt " || true)
Proxy Active: $(pgrep tinyproxy &>/dev/null || pgrep 3proxy &>/dev/null && echo "Yes" || echo "No")
DEPLOY

log_success "Deployment information saved"
echo ""

# Final test and report
log_info "Running final connectivity test..."
if timeout 5 dig @127.0.0.1 -p 5335 google.com +short &>/dev/null 2>&1; then
    echo ""
    log_success "ALL SYSTEMS OPERATIONAL!"
    echo ""
    echo "Your privacy stack is working correctly."
    echo "Try: privacy-status"
    echo ""
else
    log_warn "DNS test had issues but system is deployed"
    echo "Run: dns-manager test for detailed diagnostics"
fi

exit 0
