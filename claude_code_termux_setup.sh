#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "=== Termux Claude Code Installer (Ubuntu PRoot) ==="

# 1. Update Termux and install proot-distro
pkg update -y && pkg upgrade -y
pkg install -y proot-distro

# 2. Install Ubuntu container
if ! proot-distro list | grep -q "ubuntu (installed)"; then
    echo "[+] Installing Ubuntu PRoot environment..."
    proot-distro install ubuntu
fi

# 3. Provision Node.js LTS and Claude Code inside Ubuntu glibc environment
echo "[+] Provisioning Node.js and Claude Code inside Ubuntu..."
proot-distro login ubuntu -- bash -c "
    set -e
    apt update && apt upgrade -y
    apt install -y curl git
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
        apt install -y nodejs
    fi
    npm install -g @anthropic-ai/claude-code
"

# 4. Create transparent global host launcher
LAUNCHER="/data/data/com.termux/files/usr/bin/claude"
cat << 'EOF' > "$LAUNCHER"
#!/data/data/com.termux/files/usr/bin/bash
exec proot-distro login ubuntu --bind /data/data/com.termux/files/home:/root -- claude "$@"
EOF

chmod +x "$LAUNCHER"

echo "=== Installation Complete ==="
echo "Execute 'claude' directly from any directory to launch."
