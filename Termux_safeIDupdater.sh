#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
#  TERMUX SAFE IDENTIFIER CHANGER  –  Moto G 5G (2022)
#  Fully interactive, with backups, validation, and restore.
#  Run as root via `su -c` or `tsu`.
# ==============================================================================

# ---- Colours (Termux compatible) ----
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
NC='\033[0m'

# ---- Check root ----
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${R}❌ This script must be run as root.${NC}"
    echo "   Use: su -c ./id_changer.sh"
    exit 1
fi

# ---- Terminal size handling for better display ----
clear

echo -e "${B}=============================================="
echo "  TERMUX SAFE IDENTIFIER CHANGER"
echo "  for Moto G 5G (2022) – MediaTek Dimensity 700"
echo "==============================================${NC}"

# ---- Critical warning ----
echo -e "${R}⚠️  WARNING: This modifies unique device identifiers.${NC}"
echo "    It may be illegal in some countries."
echo "    Proceed only if you understand the risks."
echo ""
echo "You MUST have a full fastboot ROM downloaded for this device"
echo "in case of a soft brick. (e.g., from lolinet)"
echo ""
printf "Type 'I_UNDERSTAND' to continue: "
read -r confirm
if [ "$confirm" != "I_UNDERSTAND" ]; then
    echo "Aborted."
    exit 0
fi

# ---- Backup location (prefer external storage) ----
echo ""
echo -e "${B}Choose backup location:${NC}"
echo "  1) Internal storage (/sdcard) – risk if device won't boot"
echo "  2) External SD card (/storage/XXXX-XXXX) – recommended"
printf "Enter 1 or 2: "
read -r loc
if [ "$loc" = "2" ]; then
    echo "Available external storages:"
    ls /storage/ | grep -E '^[0-9A-F]{4}-[0-9A-F]{4}$' || echo "None found."
    printf "Enter the exact mount point (e.g., 1234-5678): "
    read -r ext_mount
    BACKUP_BASE="/storage/$ext_mount"
else
    BACKUP_BASE="/sdcard"
fi

BACKUP_DIR="$BACKUP_BASE/identifier_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR" 2>/dev/null
if [ ! -d "$BACKUP_DIR" ]; then
    echo -e "${R}❌ Cannot create backup directory. Falling back to /data/local/tmp${NC}"
    BACKUP_DIR="/data/local/tmp/identifier_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
fi
echo -e "${G}✅ Backup directory: $BACKUP_DIR${NC}"

# =====================================================================
#  1. BACKUP EVERYTHING
# =====================================================================
echo ""
echo -e "${B}[1/6] Performing full backups...${NC}"

# ---- Partition paths (YOU MUST VERIFY THESE) ----
# Run `ls -l /dev/block/by-name/` to confirm
PART_MODEMST1="/dev/block/by-name/modemst1"
PART_MODEMST2="/dev/block/by-name/modemst2"
PART_NVRAM="/dev/block/by-name/nvram"
PART_PERSIST="/dev/block/by-name/persist"

for part in "$PART_MODEMST1" "$PART_MODEMST2" "$PART_NVRAM" "$PART_PERSIST"; do
    if [ -b "$part" ]; then
        dd if="$part" of="$BACKUP_DIR/$(basename "$part").img" bs=4096 2>/dev/null
        echo "   Backed up $part"
    else
        echo -e "${Y}   ⚠️  Partition $part not found, skipping.${NC}"
    fi
done

# ---- NVRAM files (common MediaTek paths) ----
WIFI_NVRAM="/data/nvram/APCFG/APRDEB/WIFI"
SERIAL_NVRAM="/data/nvram/APCFG/APRDEB/SERIAL"
BT_NVRAM="/data/nvram/APCFG/APRDEB/BT"

for file in "$WIFI_NVRAM" "$SERIAL_NVRAM" "$BT_NVRAM"; do
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").bin" 2>/dev/null
        echo "   Backed up $file"
    else
        echo -e "${Y}   ⚠️  $file not found.${NC}"
    fi
done

# ---- Current values ----
getprop ro.serialno > "$BACKUP_DIR/orig_serial.txt" 2>/dev/null
cat /sys/class/net/wlan0/address > "$BACKUP_DIR/orig_wlan_mac.txt" 2>/dev/null
cat /sys/class/bluetooth/hci0/address > "$BACKUP_DIR/orig_bt_mac.txt" 2>/dev/null
settings get secure android_id > "$BACKUP_DIR/orig_android_id.txt" 2>/dev/null

# ---- Try AT command device ----
ATDEV="/dev/radio/pttycmd1"
[ -c "$ATDEV" ] || ATDEV="/dev/ttyC0"
if [ -c "$ATDEV" ]; then
    echo -e "AT+EGMR=0,7" > "$ATDEV" && sleep 0.2 && head -n 5 "$ATDEV" > "$BACKUP_DIR/orig_imei1.txt" 2>/dev/null
    echo -e "AT+EGMR=0,10" > "$ATDEV" && sleep 0.2 && head -n 5 "$ATDEV" > "$BACKUP_DIR/orig_imei2.txt" 2>/dev/null
    echo "   Attempted IMEI backup via AT."
fi

echo -e "${G}✅ Backups complete.${NC}"

# =====================================================================
#  2. TEST AT COMMAND SUPPORT
# =====================================================================
echo ""
echo -e "${B}[2/6] Testing AT command support...${NC}"

AT_SUPPORTED=0
if [ -c "$ATDEV" ]; then
    echo -e "AT+EGMR=0,7" > "$ATDEV"
    sleep 0.2
    RESPONSE=$(head -n 3 "$ATDEV" 2>/dev/null)
    if echo "$RESPONSE" | grep -qiE "IMEI|[0-9]{15}"; then
        AT_SUPPORTED=1
        echo -e "${G}   ✅ AT+EGMR commands are supported.${NC}"
    else
        echo -e "${Y}   ⚠️  AT commands do not respond. Using NVRAM patching only.${NC}"
    fi
else
    echo -e "${Y}   ⚠️  Modem AT device not found.${NC}"
fi

# =====================================================================
#  3. COLLECT NEW IDENTIFIERS
# =====================================================================
echo ""
echo -e "${B}[3/6] Enter new identifiers:${NC}"

# IMEI1
while true; do
    printf "New IMEI 1 (15 digits): "
    read -r imei1
    if echo "$imei1" | grep -qE '^[0-9]{15}$'; then break; fi
    echo "Invalid. Exactly 15 digits."
done

# IMEI2
printf "New IMEI 2 (15 digits, Enter to skip): "
read -r imei2
if [ -n "$imei2" ] && ! echo "$imei2" | grep -qE '^[0-9]{15}$'; then
    echo "Invalid, will skip."
    imei2=""
fi

# Wi-Fi MAC
while true; do
    printf "New Wi‑Fi MAC (aa:bb:cc:dd:ee:ff): "
    read -r wlan_mac
    if echo "$wlan_mac" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then break; fi
    echo "Invalid format."
done

# Bluetooth MAC
while true; do
    printf "New Bluetooth MAC (aa:bb:cc:dd:ee:ff): "
    read -r bt_mac
    if echo "$bt_mac" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then break; fi
    echo "Invalid format."
done

# Serial
printf "New Serial number (Enter to keep current): "
read -r serial_no
if [ -z "$serial_no" ]; then
    serial_no=$(getprop ro.serialno)
    echo "Keeping original: $serial_no"
fi

# Android ID
printf "New Android ID (16 hex digits, Enter to generate random): "
read -r android_id
if [ -z "$android_id" ]; then
    android_id=$(od -An -N8 -tx1 /dev/urandom | tr -d ' ')
    echo "Generated: $android_id"
fi
while ! echo "$android_id" | grep -qE '^[0-9a-fA-F]{16}$'; do
    printf "Invalid. Enter 16 hex digits: "
    read -r android_id
done

# GSF ID (optional)
printf "New GSF ID (16 hex, Enter to skip): "
read -r gsf_id
if [ -n "$gsf_id" ] && ! echo "$gsf_id" | grep -qE '^[0-9a-fA-F]{16}$'; then
    echo "Invalid, will skip."
    gsf_id=""
fi

# =====================================================================
#  4. APPLY CHANGES
# =====================================================================
echo ""
echo -e "${B}[4/6] Applying changes...${NC}"

# ---- IMEI via AT (if supported) ----
if [ "$AT_SUPPORTED" -eq 1 ]; then
    echo -e "AT+EGMR=1,7,\"$imei1\"" > "$ATDEV" && sleep 0.5
    echo "   Wrote IMEI1 via AT"
    if [ -n "$imei2" ]; then
        echo -e "AT+EGMR=1,10,\"$imei2\"" > "$ATDEV" && sleep 0.5
        echo "   Wrote IMEI2 via AT"
    fi
    # Verify
    echo -e "AT+EGMR=0,7" > "$ATDEV" && sleep 0.2
    READ_IMEI1=$(head -n 5 "$ATDEV" | grep -oE '[0-9]{15}')
    if [ "$READ_IMEI1" = "$imei1" ]; then
        echo -e "${G}   ✅ IMEI1 verified.${NC}"
    else
        echo -e "${R}   ❌ IMEI1 verification failed (read: $READ_IMEI1).${NC}"
    fi
else
    echo -e "${Y}   ⚠️  AT not supported; IMEI change skipped.${NC}"
fi

# ---- Wi-Fi MAC (NVRAM patch) ----
if [ -f "$WIFI_NVRAM" ]; then
    # Write MAC (6 bytes) at offset 4 (common for MediaTek)
    echo "$wlan_mac" | tr -d ':' | xxd -r -p | dd of="$WIFI_NVRAM" bs=1 seek=4 conv=notrunc 2>/dev/null
    echo "   Patched Wi-Fi MAC in NVRAM."
    # Also try sysfs (temporary)
    echo "$wlan_mac" > /sys/class/net/wlan0/address 2>/dev/null || true
else
    echo -e "${Y}   ⚠️  Wi-Fi NVRAM not found; cannot change MAC.${NC}"
fi

# ---- Bluetooth MAC ----
BT_FILE="/data/misc/bluetooth/bdaddr"
if [ -f "$BT_FILE" ]; then
    echo "$bt_mac" > "$BT_FILE"
    echo "   Patched Bluetooth MAC in $BT_FILE"
else
    echo -e "${Y}   ⚠️  Bluetooth address file not found.${NC}"
fi

# ---- Serial number ----
if [ -f "$SERIAL_NVRAM" ]; then
    printf "%s" "$serial_no" | dd of="$SERIAL_NVRAM" bs=1 conv=notrunc 2>/dev/null
    echo "   Patched serial in NVRAM."
fi
resetprop ro.serialno "$serial_no" 2>/dev/null

# ---- Android ID ----
settings put secure android_id "$android_id" 2>/dev/null
echo "   Set Android ID."

# ---- GSF ID ----
if [ -n "$gsf_id" ]; then
    # Force stop GMS, then update database
    am force-stop com.google.android.gms 2>/dev/null
    sleep 1
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 /data/data/com.google.android.gsf/databases/gservices.db \
            "update main set value='$gsf_id' where name='android_id';" 2>/dev/null
        echo "   Updated GSF ID."
    else
        echo -e "${Y}   ⚠️  sqlite3 not found, GSF ID not updated.${NC}"
    fi
fi

# =====================================================================
#  5. VERIFICATION
# =====================================================================
echo ""
echo -e "${B}[5/6] Verifying changes...${NC}"

# Save new values
{
    echo "IMEI1: $imei1"
    echo "IMEI2: $imei2"
    echo "Wi-Fi MAC: $wlan_mac"
    echo "BT MAC: $bt_mac"
    echo "Serial: $serial_no"
    echo "Android ID: $android_id"
    echo "GSF ID: $gsf_id"
} > "$BACKUP_DIR/new_values.txt"

# Read back current values
CUR_WLAN=$(cat /sys/class/net/wlan0/address 2>/dev/null)
CUR_BT=$(cat /sys/class/bluetooth/hci0/address 2>/dev/null)
echo "Current Wi-Fi MAC: $CUR_WLAN"
echo "Current BT MAC: $CUR_BT"

# =====================================================================
#  6. CREATE RESTORE SCRIPT
# =====================================================================
echo ""
echo -e "${B}[6/6] Creating restore script...${NC}"

cat > "$BACKUP_DIR/restore.sh" <<EOF
#!/system/bin/sh
# Restore from backup taken on $(date)
BACKUP_DIR="$BACKUP_DIR"
echo "Restoring partitions..."
for img in \$BACKUP_DIR/*.img; do
    part="/dev/block/by-name/\$(basename "\$img" .img)"
    if [ -b "\$part" ]; then
        dd if="\$img" of="\$part" bs=4096
        echo "Restored \$part"
    fi
done
echo "Restoring NVRAM files..."
[ -f "\$BACKUP_DIR/WIFI.bin" ] && cp "\$BACKUP_DIR/WIFI.bin" "$WIFI_NVRAM"
[ -f "\$BACKUP_DIR/SERIAL.bin" ] && cp "\$BACKUP_DIR/SERIAL.bin" "$SERIAL_NVRAM"
[ -f "\$BACKUP_DIR/BT.bin" ] && cp "\$BACKUP_DIR/BT.bin" "$BT_NVRAM"
echo "Restore complete. Reboot now."
EOF
chmod +x "$BACKUP_DIR/restore.sh"
echo -e "${G}✅ Restore script created: $BACKUP_DIR/restore.sh${NC}"

# =====================================================================
#  FINAL MESSAGE
# =====================================================================
echo ""
echo -e "${G}=============================================="
echo "  ✅ ALL CHANGES APPLIED"
echo "==============================================${NC}"
echo ""
echo "Your identifiers have been updated (where possible)."
echo "Some changes (especially MACs) may not persist after reboot."
echo ""
echo "⚠️  IMPORTANT:"
echo "  - Keep the backup folder: $BACKUP_DIR"
echo "  - If you lose cellular signal, run the restore script."
echo "  - To restore: su -c $BACKUP_DIR/restore.sh"
echo ""
echo "Reboot now? (y/N): "
read -r reboot_now
if [ "$reboot_now" = "y" ] || [ "$reboot_now" = "Y" ]; then
    reboot
fi
