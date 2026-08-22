#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

IMAGE_URL="https://ci.ubports.com/job/rootfs/job/rootfs-generic-amd64/lastSuccessfulBuild/artifact/ubuntu-touch-mainline-generic-amd64.img.xz"
IMAGE_XZ="ubuntu-touch-mainline-generic-amd64.img.xz"
IMAGE_IMG="ubuntu-touch-mainline-generic-amd64.img"
QEMU_MEMORY="2048"
QEMU_SMP="2"

print_green() { echo -e "\e[32m[+]\e[0m $1"; }
print_red()   { echo -e "\e[31m[-]\e[0m $1"; }
print_yellow() { echo -e "\e[33m[!]\e[0m $1"; }

# ---- 1. Install dependencies ----
print_green "Installing QEMU and tools..."
pkg update -y
pkg install -y qemu-system-x86-64 xz-utils curl

# ---- 2. Download ----
print_green "Downloading Ubuntu Touch image (~2GB)..."
[ -f "$IMAGE_XZ" ] && print_yellow "File exists – skipping download" || curl -L --progress-bar "$IMAGE_URL" -o "$IMAGE_XZ"

# ---- 3. Extract ----
print_green "Extracting image (may take several minutes)..."
[ -f "$IMAGE_IMG" ] && print_yellow "Image already extracted – skipping" || unxz -v "$IMAGE_XZ"

# ---- 4. Create launcher with corrected QEMU command ----
cat > run-utouch.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
IMAGE="ubuntu-touch-mainline-generic-amd64.img"
echo "[+] Booting Ubuntu Touch with serial console..."
echo "[+] Press Ctrl+A then X to exit QEMU."
echo "[+] To switch to VNC, replace '-nographic' with '-vnc :0'."
exec qemu-system-x86_64 \
    -smp 2 \
    -m 2048 \
    -drive file="$IMAGE",format=raw \
    -vga virtio \
    -nographic \
    -netdev user,id=net0,hostfwd=tcp::10022-:22 \
    -device e1000,netdev=net0 \
    -machine type=pc
EOF
chmod +x run-utouch.sh

# ---- 5. Auto-run ----
print_green "Setup complete – launching VM now..."
print_yellow "VM boot will take 2‑3 minutes. You'll see kernel logs and then a login prompt."
print_yellow "To SSH later: ssh -p 10022 phablet@localhost (pass: phablet)"
echo
sleep 2
./run-utouch.sh
