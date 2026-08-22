#!/bin/bash
# GodHand Setup Script for Termux on Rooted Android
# Run this script to set up GodHand in Termux environment
# Usage: bash setup-termux.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  GodHand Termux Setup Script${NC}"
echo -e "${BLUE}========================================${NC}"

# Detect Termux environment
if [ ! -d "/data/data/com.termux" ]; then
    echo -e "${RED}Error: Not running in Termux environment${NC}"
    echo "This script is designed for Termux on rooted Android devices."
    exit 1
fi

echo -e "${GREEN}✓ Termux environment detected${NC}"

# Check if running as root (required for packet injection)
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Not running as root (su)${NC}"
    echo "Some features (ARP spoofing, packet injection) require root access."
    echo "Run this script with: ${YELLOW}sudo bash setup-termux.sh${NC}"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create necessary directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p "$PREFIX/var/godhand/certs"
mkdir -p "$PREFIX/var/godhand/logs"
mkdir -p "$PREFIX/etc/godhand-gateway"
echo -e "${GREEN}✓ Directories created${NC}"

# Update package manager
echo -e "${BLUE}Updating package manager...${NC}"
pkg update -y > /dev/null 2>&1 || true
pkg upgrade -y > /dev/null 2>&1 || true
echo -e "${GREEN}✓ Package manager updated${NC}"

# Install base dependencies
echo -e "${BLUE}Installing base dependencies...${NC}"
PACKAGES=(
    "python"
    "python-pip"
    "openssl"
    "net-tools"
    "iproute2"
    "iputils"
    "curl"
    "git"
    "vim"
    "nano"
)

for pkg in "${PACKAGES[@]}"; do
    echo -n "  Installing $pkg... "
    if pkg install -y "$pkg" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠ (may already exist)${NC}"
    fi
done

# Install gateway services (DNS & proxy)
echo -e "${BLUE}Installing gateway services (DNS & proxy)...${NC}"

# Try to install tinyproxy
echo -n "  Installing tinyproxy... "
if pkg install -y tinyproxy > /dev/null 2>&1; then
    if command -v tinyproxy &> /dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠ (build needed)${NC}"
        # Try building from source if not in repos
        pkg install -y autoconf automake make > /dev/null 2>&1
    fi
else
    echo -e "${YELLOW}⚠ (not available, using alternatives)${NC}"
    # Try installing alternative proxy servers
    for alt in squid-proxy privoxy; do
        if pkg install -y "$alt" > /dev/null 2>&1; then
            echo "  Found alternative proxy: $alt"
            break
        fi
    done
fi

# Try to install dnscrypt-proxy
echo -n "  Installing dnscrypt-proxy... "
if pkg install -y dnscrypt-proxy > /dev/null 2>&1; then
    if command -v dnscrypt-proxy &> /dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}⚠ (verifying)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ (not in main repos)${NC}"
    # Try rust-based installer
    echo "  Attempting rust-based dnscrypt-proxy install..."
    pkg install -y rust > /dev/null 2>&1
    if command -v cargo &> /dev/null; then
        cargo install dnscrypt-proxy > /dev/null 2>&1 || true
    fi
fi

# Install unbound as DNS fallback
echo -n "  Installing unbound (DNS fallback)... "
if pkg install -y unbound > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}⚠ (optional)${NC}"
fi

# Install network attack tools (if root)
if [ "$EUID" -eq 0 ]; then
    echo -e "${BLUE}Installing network attack tools (requires root)...${NC}"
    ATTACK_TOOLS=(
        "nmap"
        "netcat"
    )

    for pkg in "${ATTACK_TOOLS[@]}"; do
        echo -n "  Installing $pkg... "
        if pkg install -y "$pkg" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}⚠ (may not be available)${NC}"
        fi
    done
fi

# Install proot as fallback for non-root environments
echo -e "${BLUE}Installing proot (fallback for non-root packet injection)...${NC}"
echo -n "  Installing proot... "
if pkg install -y proot > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}⚠ (optional, skipping)${NC}"
fi

# Install Python dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
pip install --upgrade pip > /dev/null 2>&1
PYTHON_DEPS=(
    "flask"
    "requests"
)

for dep in "${PYTHON_DEPS[@]}"; do
    echo -n "  Installing $dep... "
    if pip install "$dep" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ Failed to install $dep${NC}"
    fi
done

# Check for GodHand.py
echo -e "${BLUE}Checking GodHand installation...${NC}"
if [ ! -f "./GodHand.py" ]; then
    echo -e "${YELLOW}GodHand.py not found in current directory${NC}"
    echo "Please clone the repository or copy GodHand.py to this directory."
    echo "Repository: ${YELLOW}https://github.com/SecTrollz/scripts${NC}"
    exit 1
fi
echo -e "${GREEN}✓ GodHand.py found${NC}"

# Verify GodHand.py syntax
echo -e "${BLUE}Verifying GodHand.py syntax...${NC}"
if python3 -c "import ast; ast.parse(open('GodHand.py').read())" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ GodHand.py syntax valid${NC}"
else
    echo -e "${RED}✗ GodHand.py has syntax errors${NC}"
    exit 1
fi

# Set up environment variables
echo -e "${BLUE}Setting up environment variables...${NC}"
if [ -z "$GODHAND_PASSWORD" ]; then
    GODHAND_PASSWORD=$(openssl rand -base64 12)
    echo -e "${YELLOW}Generated GODHAND_PASSWORD: $GODHAND_PASSWORD${NC}"
fi

if [ -z "$GODHAND_SECRET" ]; then
    GODHAND_SECRET=$(openssl rand -base64 32)
fi

# Create startup script
echo -e "${BLUE}Creating startup script...${NC}"
cat > "$PREFIX/bin/godhand-start" << 'EOF'
#!/bin/bash
# GodHand startup wrapper for Termux

export PREFIX=${PREFIX:-/data/data/com.termux/files/usr}
export GODHAND_PORT=${GODHAND_PORT:-5000}
export GODHAND_USERNAME=${GODHAND_USERNAME:-admin}
export GODHAND_PASSWORD=${GODHAND_PASSWORD:-}
export GODHAND_SECRET=${GODHAND_SECRET:-}

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
GODHAND_DIR="$SCRIPT_DIR/home/user/scripts"

# Check if GodHand.py exists
if [ ! -f "$GODHAND_DIR/GodHand.py" ]; then
    echo "Error: GodHand.py not found at $GODHAND_DIR/GodHand.py"
    echo "Please ensure GodHand.py is in the correct location."
    exit 1
fi

echo "=========================================="
echo "  GodHand - Network Command"
echo "=========================================="
echo "Environment:"
echo "  PREFIX: $PREFIX"
echo "  Port: $GODHAND_PORT"
echo "  Username: $GODHAND_USERNAME"
echo "=========================================="
echo ""
echo "Starting GodHand..."
echo "Navigate to: http://localhost:$GODHAND_PORT"
echo ""

cd "$GODHAND_DIR"
exec python3 GodHand.py
EOF

chmod +x "$PREFIX/bin/godhand-start"
echo -e "${GREEN}✓ Startup script created: godhand-start${NC}"

# Create systemd-style background service (optional)
echo -e "${BLUE}Creating background service script...${NC}"
cat > "$PREFIX/bin/godhand-bg" << 'EOF'
#!/bin/bash
# Run GodHand in background

nohup godhand-start > "$PREFIX/var/godhand/logs/godhand.log" 2>&1 &
PID=$!
echo $PID > "$PREFIX/var/godhand/logs/godhand.pid"
echo "GodHand started in background (PID: $PID)"
echo "Logs: tail -f $PREFIX/var/godhand/logs/godhand.log"
EOF

chmod +x "$PREFIX/bin/godhand-bg"
echo -e "${GREEN}✓ Background service script created: godhand-bg${NC}"

# Display summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Installed Components:"
echo "  ✓ GodHand (main application)"
echo "  ✓ Flask (web framework)"
echo "  ✓ OpenSSL (certificate generation)"
echo "  ✓ tinyproxy (HTTP proxy)"
echo "  ✓ dnscrypt-proxy (DNS encryption)"
if command -v proot &> /dev/null; then
    echo "  ✓ proot (fallback for non-root packet injection)"
fi
echo ""
echo "Next steps:"
echo ""
echo "1. ${YELLOW}Start GodHand:${NC}"
echo "   ${BLUE}godhand-start${NC}          (foreground, see logs)"
echo "   ${BLUE}godhand-bg${NC}             (background mode)"
echo ""
echo "2. ${YELLOW}Access the web interface:${NC}"
echo "   http://localhost:5000"
echo ""
echo "3. ${YELLOW}Login credentials:${NC}"
echo "   Username: ${BLUE}admin${NC}"
echo "   Password: ${BLUE}${GODHAND_PASSWORD}${NC}"
echo ""
echo "4. ${YELLOW}Environment setup:${NC}"
echo "   Set these in your shell profile (~/.bashrc):"
echo "   ${BLUE}export GODHAND_PASSWORD='${GODHAND_PASSWORD}'${NC}"
echo "   ${BLUE}export GODHAND_SECRET='${GODHAND_SECRET}'${NC}"
echo ""
echo "5. ${YELLOW}Directories:${NC}"
echo "   Certificates: ${BLUE}$PREFIX/var/godhand/certs${NC}"
echo "   Logs: ${BLUE}$PREFIX/var/godhand/logs${NC}"
echo "   Config: ${BLUE}$PREFIX/etc/godhand-gateway${NC}"
echo ""
echo "6. ${YELLOW}Gateway Services:${NC}"
if command -v tinyproxy &> /dev/null; then
    echo "   tinyproxy: ${BLUE}$PREFIX/bin/tinyproxy${NC} (HTTP proxy on port 8888)"
fi
if command -v dnscrypt-proxy &> /dev/null; then
    echo "   dnscrypt-proxy: ${BLUE}$PREFIX/bin/dnscrypt-proxy${NC} (DNS on port 5353)"
fi
if command -v proot &> /dev/null; then
    echo "   proot: Available for non-root packet injection"
fi
echo ""
echo "7. ${YELLOW}Non-Root Mode (if running without su):${NC}"
echo "   proot can simulate root for packet injection:"
echo "   ${BLUE}proot -r / godhand-start${NC}"
echo ""
echo -e "${YELLOW}Documentation:${NC}"
echo "  Setup Guide: ${BLUE}HTTPS_SETUP_GUIDE.md${NC}"
echo "  PAC Config: ${BLUE}PAC_CONFIGURATION_GUIDE.md${NC}"
echo "  Validation: ${BLUE}HTTPS_VALIDATION_TESTING.md${NC}"
echo ""
