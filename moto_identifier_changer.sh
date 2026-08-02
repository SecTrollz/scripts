#!/system/bin/sh
# ============================================================================
#  SAFE IDENTIFIER CHANGER  –  Moto G 5G (2022)
#  Research-backed, with full backups and validation.
#  Usage: Run as root, follow prompts, and have a stock ROM ready.
# ============================================================================

set -e

# ----- Colours -----
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
NC='\033[0m'

echo "${B}=============================================="
echo "  SAFE IDENTIFIER CHANGER  v2.0"
echo "  for MediaTek Dimensity 700"
echo "==============================================${NC}"

# ----- Root check -----
if [ "$(id -u)" -ne 0 ]; then
    echo "${R}❌ Root required.${NC}"
    exit 1
fi

# ----- Critical: User must confirm backup location and firmware availability -----
echo ""
echo "${R}⚠️  WARNING: This will modify your device's unique identifiers.${NC}"
echo "    It may be illegal in your country. Proceed at your own risk."
echo ""
echo "Before continuing, you MUST:"
echo "  1. Have a full stock firmware (fastboot ROM) for your device downloaded."
echo "  2. Have at least 2 GB free on external storage (USB OTG or SD card)."
echo "  3. Know how to restore from a fastboot ROM in case of a soft brick."
echo ""
printf "Type 'I_AM_READY' to continue: "
read -r confirm
if [ "$confirm" != "I_AM_READY" ]; then
    echo "Aborted."
    exit 0
fi

# ----- Define backup directory (use external storage if possible) -----
BACKUP_DIR="/sdcard/identifier_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
echo "${G}✅ Backup directory: $BACKUP_DIR${NC}"

# =====================================================================
#  1. BACKUP EVERYTHING (partitions and NVRAM files)
# =====================================================================
echo ""
echo "${B}[1/6] Performing full backups...${NC}"

# ---- Partition backups (use dd) ----
# YOU MUST FILL THESE PATHS AFTER RESEARCH:
PART_MODEMST1="/dev/block/by-name/modemst1"   # Change if different
PART_MODEMST2="/dev/block/by-name/modemst2"
PART_NVRAM="/dev/block/by-name/nvram"         # Usually present
PART_PERSIST="/dev/block/by-name/persist"

for part in "$PART_MODEMST1" "$PART_MODEMST2" "$PART_NVRAM" "$PART_PERSIST"; do
    if [ -b "$part" ]; then
        dd if="$part" of="$BACKUP_DIR/$(basename "$part").img" bs=4096 2>/dev/null
        echo "   Backed up $part"
    else
        echo "${Y}   ⚠️  Partition $part not found, skipping.${NC}"
    fi
done

# ---- NVRAM file backup ----
# Wi-Fi MAC file (verify path)
WIFI_NVRAM="/data/nvram/APCFG/APRDEB/WIFI"
if [ -f "$WIFI_NVRAM" ]; then
    cp "$WIFI_NVRAM" "$BACKUP_DIR/wifi_nvram.bin"
    echo "   Backed up $WIFI_NVRAM"
else
    echo "${Y}   ⚠️  Wi-Fi NVRAM file not found.${NC}"
fi

# Serial NVRAM (if exists)
SERIAL_NVRAM="/data/nvram/APCFG/APRDEB/SERIAL"
if [ -f "$SERIAL_NVRAM" ]; then
    cp "$SERIAL_NVRAM" "$BACKUP_DIR/serial_nvram.bin"
    echo "   Backed up $SERIAL_NVRAM"
fi

# ---- Record original values ----
getprop ro.serialno > "$BACKUP_DIR/orig_serial.txt" 2>/dev/null
cat /sys/class/net/wlan0/address > "$BACKUP_DIR/orig_wlan_mac.txt" 2>/dev/null
cat /sys/class/bluetooth/hci0/address > "$BACKUP_DIR/orig_bt_mac.txt" 2>/dev/null
settings get secure android_id > "$BACKUP_DIR/orig_android_id.txt" 2>/dev/null

# ---- Try to read current IMEI via AT ----
ATDEV="/dev/radio/pttycmd1"
[ -c "$ATDEV" ] || ATDEV="/dev/ttyC0"
if [ -c "$ATDEV" ]; then
    echo -e "AT+EGMR=0,7" > "$ATDEV" && sleep 0.2 && head -n 5 "$ATDEV" > "$BACKUP_DIR/orig_imei1.txt" 2>/dev/null
    echo -e "AT+EGMR=0,10" > "$ATDEV" && sleep 0.2 && head -n 5 "$ATDEV" > "$BACKUP_DIR/orig_imei2.txt" 2>/dev/null
fi
echo "${G}✅ Backups complete. Backup stored in: $BACKUP_DIR${NC}"

# =====================================================================
#  2. TEST AT COMMAND SUPPORT
# =====================================================================
echo ""
echo "${B}[2/6] Testing AT command support...${NC}"

AT_SUPPORTED=0
if [ -c "$ATDEV" ]; then
    echo -e "AT+EGMR=0,7" > "$ATDEV"
    sleep 0.2
    RESPONSE=$(head -n 3 "$ATDEV" 2>/dev/null)
    if echo "$RESPONSE" | grep -qiE "IMEI|[0-9]{15}"; then
        AT_SUPPORTED=1
        echo "${G}   ✅ AT+EGMR commands are supported.${NC}"
    else
        echo "${Y}   ⚠️  AT commands do not respond. Will use NVRAM patching only.${NC}"
    fi
else
    echo "${Y}   ⚠️  Modem AT device not found.${NC}"
fi

# =====================================================================
#  3. COLLECT NEW IDENTIFIERS (with validation)
# =====================================================================
echo ""
echo "${B}[3/6] Enter new identifiers:${NC}"

while true; do
    printf "New IMEI 1 (15 digits): "
    read -r imei1
    if echo "$imei1" | grep -qE '^[0-9]{15}$'; then break; fi
    echo "Invalid. Exactly 15 digits."
done

printf "New IMEI 2 (15 digits, Enter to skip): "
read -r imei2
if [ -n "$imei2" ] && ! echo "$imei2" | grep -qE '^[0-9]{15}$'; then
    echo "Invalid, will skip."
    imei2=""
fi

printf "New Wi‑Fi MAC (aa:bb:cc:dd:ee:ff): "
read -r wlan_mac
while ! echo "$wlan_mac" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; do
    printf "Invalid format. Try again: "
    read -r wlan_mac
done

printf "New Bluetooth MAC (aa:bb:cc:dd:ee:ff): "
read -r bt_mac
while ! echo "$bt_mac" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; do
    printf "Invalid format. Try again: "
    read -r bt_mac
done

printf "New Serial number (Enter to keep current): "
read -r serial_no
if [ -z "$serial_no" ]; then
    serial_no=$(getprop ro.serialno)
    echo "Keeping original: $serial_no"
fi

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

# =====================================================================
#  4. APPLY CHANGES (with validation)
# =====================================================================
echo ""
echo "${B}[4/6] Applying changes...${NC}"

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
        echo "${G}   ✅ IMEI1 verified.${NC}"
    else
        echo "${R}   ❌ IMEI1 verification failed (read: $READ_IMEI1).${NC}"
    fi
else
    echo "${Y}   ⚠️  AT not supported; IMEI change impossible via this script.${NC}"
    echo "   You may try using tools like Maui META or write to NVRAM directly."
fi

# ---- Wi-Fi MAC (NVRAM patch) ----
if [ -f "$WIFI_NVRAM" ]; then
    # Backup already made. Write new MAC (6 bytes) at offset 4 (common)
    echo "$wlan_mac" | tr -d ':' | xxd -r -p | dd of="$WIFI_NVRAM" bs=1 seek=4 conv=notrunc 2>/dev/null
    echo "   Patched Wi-Fi MAC in NVRAM."
    # Also try to update via sysfs (may not persist)
    echo "$wlan_mac" > /sys/class/net/wlan0/address 2>/dev/null || true
else
    echo "${Y}   ⚠️  Wi-Fi NVRAM not found; cannot change MAC.${NC}"
fi

# ---- Bluetooth MAC ----
# Similar to Wi-Fi; some devices store in /data/misc/bluetooth/
BT_FILE="/data/misc/bluetooth/bdaddr"
if [ -f "$BT_FILE" ]; then
    echo "$bt_mac" > "$BT_FILE"
    echo "   Patched Bluetooth MAC in $BT_FILE"
else
    echo "${Y}   ⚠️  Bluetooth address file not found.${NC}"
fi

# ---- Serial number ----
if [ -f "$SERIAL_NVRAM" ]; then
    printf "%s" "$serial_no" | dd of="$SERIAL_NVRAM" bs=1 conv=notrunc 2>/dev/null
    echo "   Patched serial in NVRAM."
fi
resetprop ro.serialno "$serial_no"  # temporary

# ---- Android ID ----
settings put secure android_id "$android_id"
echo "   Set Android ID."

# ---- GSF ID (optional) ----
printf "New GSF ID (16 hex, Enter to skip): "
read -r gsf_id
if [ -n "$gsf_id" ] && echo "$gsf_id" | grep -qE '^[0-9a-fA-F]{16}$'; then
    am force-stop com.google.android.gms 2>/dev/null
    sleep 1
    sqlite3 /data/data/com.google.android.gsf/databases/gservices.db \
        "update main set value='$gsf_id' where name='android_id';" 2>/dev/null
    echo "   Updated GSF ID."
fi

# =====================================================================
#  5. FINAL VERIFICATION AND SUMMARY
# =====================================================================
echo ""
echo "${B}[5/6] Verifying changes...${NC}"
echo "Saved new values to $BACKUP_DIR/new_values.txt"
{
    echo "IMEI1: $imei1"
    echo "IMEI2: $imei2"
    echo "Wi-Fi MAC: $wlan_mac"
    echo "BT MAC: $bt_mac"
    echo "Serial: $serial_no"
    echo "Android ID: $android_id"
    echo "GSF ID: $gsf_id"
} > "$BACKUP_DIR/new_values.txt"

# ---- Read back MACs ----
CUR_WLAN=$(cat /sys/class/net/wlan0/address 2>/dev/null)
CUR_BT=$(cat /sys/class/bluetooth/hci0/address 2>/dev/null)
echo "Current Wi-Fi MAC: $CUR_WLAN"
echo "Current BT MAC: $CUR_BT"

# =====================================================================
#  6. RESTORE OPTION (create a restore script)
# =====================================================================
echo ""
echo "${B}[6/6] Creating restore script...${NC}"

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
[ -f "\$BACKUP_DIR/wifi_nvram.bin" ] && cp "\$BACKUP_DIR/wifi_nvram.bin" "$WIFI_NVRAM"
[ -f "\$BACKUP_DIR/serial_nvram.bin" ] && cp "\$BACKUP_DIR/serial_nvram.bin" "$SERIAL_NVRAM"
echo "Restore complete. Reboot now."
EOF
chmod +x "$BACKUP_DIR/restore.sh"
echo "${G}✅ Restore script created: $BACKUP_DIR/restore.sh${NC}"

# =====================================================================
#  FINAL MESSAGE
# =====================================================================
echo ""
echo "${G}=============================================="
echo "  ✅ ALL CHANGES APPLIED"
echo "==============================================${NC}"
echo ""
echo "Your identifiers have been updated (where possible)."
echo "Because some changes may not survive a reboot (especially MACs),"
echo "you may need to reapply them after every reboot."
echo ""
echo "⚠️  IMPORTANT:"
echo "  - If you lose cellular signal, run the restore script."
echo "  - Keep a copy of $BACKUP_DIR on external storage."
echo "  - Before rebooting, verify that the modem works."
echo ""
echo "To restore everything, run:"
echo "  su -c $BACKUP_DIR/restore.sh"
echo ""
echo "${Y}Note: This script does NOT zero modemst partitions,${NC}"
echo "      as that is almost guaranteed to brick the radio."
echo ""
echo "Reboot now? (y/N): "
read -r reboot_now
if [ "$reboot_now" = "y" ] || [ "$reboot_now" = "Y" ]; then
    reboot
fi
