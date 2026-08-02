#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail

BASE="$HOME/debian-arm64-qemu"

IMAGE="$BASE/debian-arm64.qcow2"
EFI="$BASE/edk2-aarch64-code.fd"
PY="$BASE/launch.py"

RAM=1536
CPU=2

mkdir -p "$BASE"
cd "$BASE"

say() {
    echo -e "\033[1;33m☠ CAPTAIN:\033[0m $1"
}

ok() {
    echo -e "\033[1;32m⚓ SECURED:\033[0m $1"
}

fail() {
    echo -e "\033[1;31m💀 FAILURE:\033[0m $1"
    exit 1
}


say "Preparing Termux..."

pkg update -y
pkg install -y python curl wget qemu-utils || true


say "Searching for QEMU..."

QEMU=""

for x in qemu-system-aarch64 qemu-system-arm; do
    if command -v "$x" >/dev/null 2>&1; then
        QEMU="$(command -v "$x")"
        break
    fi
done


if [ -z "$QEMU" ]; then
    say "Trying available QEMU packages..."

    pkg search qemu || true

    fail "
QEMU ARM64 binary is missing.
Install the package that provides:
qemu-system-aarch64
then rerun.
"
fi


ok "QEMU found: $QEMU"


IMAGE_URL=$(curl -fsSL \
"https://cloud.debian.org/images/cloud/bookworm/latest/" \
| grep -o 'href="[^"]*arm64[^"]*qcow2"' \
| head -1 \
| sed 's/href="//;s/"//' \
)


if [ -z "$IMAGE_URL" ]; then
    fail "Could not locate Debian ARM64 image."
fi


if [[ "$IMAGE_URL" != http* ]]; then
    IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/$IMAGE_URL"
fi


if [ ! -f "$IMAGE" ]; then

    say "Downloading Debian ARM64 image..."

    curl -L \
    --fail \
    --progress-bar \
    "$IMAGE_URL" \
    -o "$IMAGE"

else
    ok "Image already exists."
fi


qemu-img info "$IMAGE" >/dev/null \
|| fail "Image validation failed."


ok "Disk image verified."


say "Searching for ARM64 UEFI..."


FOUND_EFI=$(find "$PREFIX" \
-name "edk2-aarch64*.fd" \
2>/dev/null \
| head -1 || true)


if [ -n "$FOUND_EFI" ]; then

    EFI="$FOUND_EFI"

else

    fail "
No ARM64 UEFI firmware found.

Install the Termux QEMU firmware package,
then rerun.
"

fi


ok "Firmware found: $EFI"



cat > "$PY" <<EOF
#!/data/data/com.termux/files/usr/bin/python

import subprocess
import os
import sys

QEMU="$QEMU"
IMAGE="$IMAGE"
EFI="$EFI"

for f in [QEMU, IMAGE, EFI]:
    if not os.path.exists(f):
        print("Missing:", f)
        sys.exit(1)

cmd = [
    QEMU,

    "-machine",
    "virt",

    "-cpu",
    "max",

    "-m",
    "$RAM",

    "-smp",
    "$CPU",

    "-bios",
    EFI,

    "-drive",
    f"file={IMAGE},if=virtio,format=qcow2",

    "-device",
    "virtio-net-device,netdev=net0",

    "-netdev",
    "user,id=net0",

    "-nographic"
]

print("☠ PYTHON CAPTAIN: Launching Debian ARM64")

subprocess.run(cmd)
EOF


chmod +x "$PY"


ok "Build complete."

echo
echo "Launch:"
echo
echo "python $PY"
echo


python "$PY"
