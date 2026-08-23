#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

IMAGE_URL="https://ci.ubports.com/job/rootfs/job/rootfs-generic-amd64/lastSuccessfulBuild/artifact/ubuntu-touch-mainline-generic-amd64.img.xz"
IMAGE_XZ="ubuntu-touch-mainline-generic-amd64.img.xz"
IMAGE_IMG="ubuntu-touch-mainline-generic-amd64.img"

MEMORY=2048
CPUS=2
SSH_PORT=10022

green(){ printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
yellow(){ printf "\033[1;33m[!]\033[0m %s\n" "$*"; }
red(){ printf "\033[1;31m[-]\033[0m %s\n" "$*"; exit 1; }

command -v pkg >/dev/null || red "Run this inside Termux."

green "Updating packages..."
pkg update -y

green "Installing dependencies..."
pkg install -y qemu-system-x86_64 xz curl || \
pkg install -y qemu-system xz curl

command -v qemu-system-x86_64 >/dev/null || red "qemu-system-x86_64 not found."

if [ ! -f "$IMAGE_XZ" ] && [ ! -f "$IMAGE_IMG" ]; then
    green "Downloading Ubuntu Touch image..."
    curl -L --fail --progress-bar "$IMAGE_URL" -o "$IMAGE_XZ"
fi

if [ -f "$IMAGE_XZ" ] && [ ! -f "$IMAGE_IMG" ]; then
    green "Extracting image..."
    unxz -v "$IMAGE_XZ"
fi

[ -f "$IMAGE_IMG" ] || red "Image extraction failed."

cat > run-utouch.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
set -e

exec qemu-system-x86_64 \
    -machine q35 \
    -cpu max \
    -smp ${CPUS} \
    -m ${MEMORY} \
    -drive if=virtio,file="${IMAGE_IMG}",format=raw \
    -device virtio-vga \
    -netdev user,id=n1,hostfwd=tcp::${SSH_PORT}-:22 \
    -device virtio-net-pci,netdev=n1 \
    -rtc base=utc \
    -serial mon:stdio \
    -display gtk
EOF

chmod +x run-utouch.sh

green "Done."
echo
echo "Launch:"
echo "  ./run-utouch.sh"
echo
echo "If GTK is unavailable, edit run-utouch.sh and replace:"
echo "    -display gtk"
echo "with:"
echo "    -nographic"
echo
echo "SSH (if enabled in guest):"
echo "    ssh -p ${SSH_PORT} phablet@127.0.0.1"

exec ./run-utouch.sh
