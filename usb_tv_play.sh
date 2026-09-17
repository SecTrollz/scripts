#!/data/data/com.termux/files/usr/bin/bash
# usb_tv_play.sh
#
# Root Termux script for a rooted moto g 5G (or similar): ask for a video
# URL, download it, pack it into a FAT32 disk image, then rebind the
# phone's USB gadget so it enumerates as a plain USB flash drive over the
# USB-C->USB-A cable. A "dumb" TV with only USB-A media playback will see
# it exactly like a thumb drive and let you play the file from its own
# on-screen file browser.
#
# This does NOT do live streaming/mirroring - the TV's USB port has no
# such protocol. It downloads first, then presents a finished file.
#
# REQUIRES:
#   - root (su)
#   - kernel with configfs USB gadget support incl. mass_storage function
#     (ls /config/usb_gadget should exist; most Android 8+ kernels have it,
#     but some vendors strip it - if setup fails, this device can't do it)
#   - curl (or yt-dlp if you paste a site URL instead of a direct file)
#   - toybox/busybox mkfs.vfat (Android ships toybox; check with `which mkfs.vfat`)
#
# USAGE:
#   bash usb_tv_play.sh
#   (paste a direct video URL when asked, or a yt-dlp-supported page URL)
#
# To go back to normal (adb/mtp) after unplugging from the TV:
#   bash usb_tv_play.sh --restore

set -euo pipefail

# su wipes the environment, so Termux's own bin dir (curl, ffmpeg, yt-dlp)
# drops out of PATH even though it's the same phone/user. Force it back in.
export PATH="/data/data/com.termux/files/usr/bin:$PATH"

WORKDIR="/data/local/tmp/usb_tv"
IMG="$WORKDIR/video.img"
MOUNTPOINT="$WORKDIR/mnt"
GADGET_DIR="/config/usb_gadget/g1"      # standard name on most stock kernels
BACKUP_FILE="$WORKDIR/gadget_backup.txt"

need_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "Re-run as root: 'su -c bash $0 $*'" >&2
        exit 1
    fi
}

find_udc() {
    ls /sys/class/udc 2>/dev/null | head -n1
}

restore_gadget() {
    need_root
    echo "[*] Restoring default USB gadget (adb/mtp)..."
    local udc
    udc=$(find_udc)
    [ -n "$udc" ] && echo "" > "$GADGET_DIR/UDC" 2>/dev/null || true

    # remove our mass_storage function link if present
    for cfg in "$GADGET_DIR"/configs/*/; do
        [ -e "${cfg}mass_storage.usb0" ] && rm -f "${cfg}mass_storage.usb0"
    done
    [ -d "$GADGET_DIR/functions/mass_storage.usb0" ] && \
        rmdir "$GADGET_DIR/functions/mass_storage.usb0" 2>/dev/null || true

    # rebind — this normally kicks the persist.sys usb service back to
    # its configured mode (adb/mtp) automatically; if not, reboot.
    [ -n "$udc" ] && echo "$udc" > "$GADGET_DIR/UDC" 2>/dev/null || true
    echo "[*] Done. If USB doesn't come back to normal, reboot the phone."
}

check_gadget_support() {
    if [ ! -d "$GADGET_DIR" ]; then
        # some kernels name the gadget dir differently; try to find any
        local alt
        alt=$(ls -d /config/usb_gadget/*/ 2>/dev/null | head -n1 || true)
        if [ -n "$alt" ]; then
            GADGET_DIR="${alt%/}"
        else
            echo "error: no /config/usb_gadget/* found. This kernel likely" >&2
            echo "doesn't expose configfs USB gadget control — mass storage" >&2
            echo "export isn't possible on this device. Use an HDMI/Miracast" >&2
            echo "dongle route instead." >&2
            exit 1
        fi
    fi
}

download_video() {
    local url="$1" out="$2"
    # curl only — this expects a direct file URL (ends in .mp4 etc, or at
    # least serves video bytes, not an HTML player page).
    curl -L --fail -o "$out" "$url"
}

attach_loop() {
    local img="$1"
    local dev
    dev=$(losetup -f 2>/dev/null)
    [ -z "$dev" ] && { echo "error: no free loop device (losetup -f)" >&2; exit 1; }
    losetup "$dev" "$img"
    echo "$dev"
}

detach_loop() {
    local dev="$1"
    losetup -d "$dev" 2>/dev/null || true
}

build_image() {
    local src="$1"
    local size_mb
    size_mb=$(( ($(stat -c%s "$src") / 1024 / 1024) + 64 ))  # file + 64MB headroom
    echo "[*] Building a ${size_mb}MB FAT32 image..."
    dd if=/dev/zero of="$IMG" bs=1M count="$size_mb" status=none
    mkfs.vfat "$IMG" >/dev/null

    mkdir -p "$MOUNTPOINT"
    local dev
    dev=$(attach_loop "$IMG")
    mount "$dev" "$MOUNTPOINT"
    cp "$src" "$MOUNTPOINT/video.mp4"
    sync
    umount "$MOUNTPOINT"
    detach_loop "$dev"
}

build_image_stream_start() {
    # Preallocate the FAT image + a full-size (zero-filled) target file
    # BEFORE any data has downloaded, so the gadget can bind right away.
    local total_bytes="$1"
    local size_mb=$(( (total_bytes / 1024 / 1024) + 64 ))
    echo "[*] Preallocating a ${size_mb}MB FAT32 image for a ${total_bytes}-byte file..."
    dd if=/dev/zero of="$IMG" bs=1M count="$size_mb" status=none
    mkfs.vfat "$IMG" >/dev/null

    mkdir -p "$MOUNTPOINT"
    STREAM_LOOP_DEV=$(attach_loop "$IMG")
    mount "$STREAM_LOOP_DEV" "$MOUNTPOINT"
    # zero-fill the file to its FINAL size now — the TV needs to see the
    # correct file length the moment it enumerates the drive.
    dd if=/dev/zero of="$MOUNTPOINT/video.mp4" bs=1M \
       count=$(( (total_bytes / 1024 / 1024) + 1 )) status=none
    sync
    # deliberately leave $MOUNTPOINT mounted / loop attached — stream_fill
    # keeps writing into it below while the gadget is already exported
}

stream_fill() {
    local url="$1"
    echo "[*] Downloading into the already-exported file in the background..."
    curl -sL --fail "$url" \
        | dd of="$MOUNTPOINT/video.mp4" bs=1M conv=notrunc status=progress
    sync
    umount "$MOUNTPOINT" 2>/dev/null || true
    [ -n "${STREAM_LOOP_DEV:-}" ] && detach_loop "$STREAM_LOOP_DEV"
    echo "[*] Download finished — file is fully populated now."
}

run_stream_mode() {
    local url="$1"
    local total_bytes
    total_bytes=$(curl -sIL "$url" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-length"{v=$2} END{print v}')
    if [ -z "${total_bytes:-}" ]; then
        echo "[!] Server didn't report Content-Length — can't preallocate."
        echo "    Falling back to download-first mode."
        local raw="$WORKDIR/download.mp4"
        download_video "$url" "$raw"
        build_image "$raw"
        setup_gadget
        return
    fi

    build_image_stream_start "$total_bytes"
    setup_gadget          # bind NOW, before content has finished downloading
    stream_fill "$url"    # fill the file live while it's already exported

    echo "[*] NOTE: if the file's metadata (moov atom) is stored at the end"
    echo "    — common for plain web MP4s — the TV may refuse to play it"
    echo "    until the download above finishes, even though it appeared"
    echo "    instantly. That's a property of the file, not this pipeline."
}

setup_gadget() {
    echo "[*] Backing up current gadget config to $BACKUP_FILE..."
    ls "$GADGET_DIR/configs/"*/ > "$BACKUP_FILE" 2>/dev/null || true

    local udc
    udc=$(find_udc)
    [ -z "$udc" ] && { echo "error: no UDC found under /sys/class/udc" >&2; exit 1; }

    echo "[*] Unbinding current gadget from UDC ($udc)..."
    echo "" > "$GADGET_DIR/UDC" 2>/dev/null || true

    echo "[*] Adding mass_storage function..."
    mkdir -p "$GADGET_DIR/functions/mass_storage.usb0"
    echo 1 > "$GADGET_DIR/functions/mass_storage.usb0/lun.0/removable" 2>/dev/null || true
    echo 1 > "$GADGET_DIR/functions/mass_storage.usb0/lun.0/ro" 2>/dev/null || true
    echo "$IMG" > "$GADGET_DIR/functions/mass_storage.usb0/lun.0/file"

    # attach the function into the first available config
    local cfg
    cfg=$(ls -d "$GADGET_DIR"/configs/*/ 2>/dev/null | head -n1)
    [ -z "$cfg" ] && { echo "error: no gadget config dir to attach to" >&2; exit 1; }
    ln -sf "$GADGET_DIR/functions/mass_storage.usb0" "${cfg}mass_storage.usb0"

    echo "[*] Rebinding to UDC..."
    echo "$udc" > "$GADGET_DIR/UDC"

    echo "[*] Done. The phone should now enumerate as a USB drive."
    echo "    Plug/replug into the TV's USB-A port and use its file"
    echo "    browser to open video.mp4."
    echo "    Run: bash $0 --restore   (when done, to get adb/mtp back)"
}

main() {
    if [ "${1:-}" = "--restore" ]; then
        restore_gadget
        exit 0
    fi

    need_root
    check_gadget_support
    mkdir -p "$WORKDIR"

    read -rp "Video URL: " url
    [ -z "$url" ] && { echo "no URL given"; exit 1; }

    if [ "${1:-}" = "--stream" ]; then
        run_stream_mode "$url"
        return
    fi

    local raw="$WORKDIR/download.mp4"
    download_video "$url" "$raw"
    build_image "$raw"
    setup_gadget
}

main "$@"
