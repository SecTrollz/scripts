#!/data/data/com.termux/files/usr/bin/bash
set -e

echo "=== Termux Claude Code Installer ==="

# 1. Update package lists and upgrade core packages
pkg update -y && pkg upgrade -y

# 2. Install required runtime dependencies
pkg install -y nodejs-lts git proot

# 3. Ensure Termux tmp directory exists
mkdir -p /data/data/com.termux/files/usr/tmp

# 4. Install Claude Code globally via npm
npm install -g @anthropic-ai/claude-code

# 5. Configure persistent proot wrapper alias in .bashrc
BASHRC="$HOME/.bashrc"
ALIAS_CMD='alias claude="proot -b /data/data/com.termux/files/usr/tmp:/tmp claude"'

if ! grep -q "proot -b /data/data/com.termux/files/usr/tmp:/tmp claude" "$BASHRC" 2>/dev/null; then
    echo "" >> "$BASHRC"
    echo "# Claude Code Termux tmp binding wrapper" >> "$BASHRC"
    echo "$ALIAS_CMD" >> "$BASHRC"
    echo "[+] Alias added to $BASHRC"
fi

echo "=== Installation Complete ==="
echo "Run 'source ~/.bashrc' or restart Termux, then execute 'claude' to launch."
