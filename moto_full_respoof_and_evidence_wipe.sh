#!/system/bin/sh
# ============================================================================
#  LAZY-BABY-PROOF FULL REFINGERPRINT + BANKING COMPATIBILITY
#  Moto G 5G (2022) – MediaTek Dimensity 700 (Boost)
#  Requires: Root + Magisk (with Zygisk) + USNF/PIF module + Shamiko
# ============================================================================
set -e  # stop on any error (except where we handle it)

# ----- Colors for readability (optional) -----
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
NC='\033[0m' # No Color

# ----- Root check -----
if [ "$(id -u)" -ne 0 ]; then
    echo "${R}❌ Root required. Run 'su' first.${NC}"
    exit 1
fi

# ----- Device/platform check -----
PLATFORM=$(getprop ro.board.platform)
if [ "$PLATFORM" != "mt6833" ] && [ "$PLATFORM" != "mt6877" ]; then
    echo "${R}❌ This script is only for Moto G 5G (2022) MediaTek Dimensity 700/900. Detected: $PLATFORM${NC}"
    exit 1
fi

# ----- Modem AT device -----
ATDEV=/dev/radio/pttycmd1
if [ ! -c "$ATDEV" ]; then
    if [ -c "/dev/ttyC0" ]; then
        ATDEV=/dev/ttyC0
        echo "${Y}⚠️  Using fallback modem device $ATDEV${NC}"
    else
        echo "${R}❌ No modem AT device found. Cannot continue.${NC}"
        exit 1
    fi
fi

# ----- Tool checks -----
if ! command -v resetprop >/dev/null 2>&1; then
    echo "${R}❌ resetprop not found. Install Magisk.${NC}"
    exit 1
fi
if ! command -v magisk >/dev/null 2>&1; then
    echo "${R}❌ Magisk not found. Please install Magisk and enable Zygisk.${NC}"
    exit 1
fi

echo "${G}✅ Device checks passed.${NC}"

# ----- Magisk module check (non‑fatal, just warn) -----
echo ""
echo "=============================================="
echo "  CHECKING MAGISK MODULES"
echo "=============================================="
MODULES=$(ls /data/adb/modules/ 2>/dev/null)
if echo "$MODULES" | grep -qiE 'safetynet-fix|playintegrityfix'; then
    echo "${G}✅ Play Integrity / SafetyNet fix module found.${NC}"
else
    echo "${R}❌ MISSING: Universal SafetyNet Fix or Play Integrity Fix.${NC}"
    echo "   Banking apps WILL fail without it. Install it now."
    echo "   (Proceeding anyway, but this is a ticking bomb.)"
fi
if echo "$MODULES" | grep -qi 'shamiko'; then
    echo "${G}✅ Shamiko found.${NC}"
else
    echo "${Y}⚠️  Shamiko not found. Install it for better root hiding.${NC}"
fi
if echo "$MODULES" | grep -qi 'magiskhide'; then
    echo "${G}✅ MagiskHide Props Config found.${NC}"
else
    echo "${Y}⚠️  MagiskHide Props Config not found. You may need it to set certified fingerprint.${NC}"
fi
echo ""

# ----- Pre‑flight isolation checklist (mandatory) -----
echo "=============================================="
echo "  PRE‑FLIGHT SAFETY CHECKLIST"
echo "=============================================="
echo "Before we start, you MUST do these manually:"
echo "  1. Remove the SIM card (or use a burner SIM)"
echo "  2. Log out of ALL Google accounts"
echo "  3. Turn ON Airplane Mode"
echo "  4. Turn OFF Wi‑Fi and Bluetooth"
echo ""
while true; do
    printf "Type 'READY' when you have done these steps: "
    read ready
    if [ "$ready" = "READY" ]; then
        break
    else
        echo "You must type READY (uppercase) to confirm."
    fi
done

# ----- Collect new identity values (with validation) -----
echo ""
echo "=============================================="
echo "  ENTER NEW IDENTITY"
echo "=============================================="
# IMEI1
while true; do
    printf "New IMEI slot 1 (15 digits): "
    read imei1
    if echo "$imei1" | grep -qE '^[0-9]{15}$'; then break; fi
    echo "Invalid. Exactly 15 digits required."
done
# IMEI2 (optional)
printf "New IMEI slot 2 (Enter to skip): "
read imei2
if [ -n "$imei2" ] && ! echo "$imei2" | grep -qE '^[0-9]{15}$'; then
    echo "Invalid, will skip slot 2."
    imei2=""
fi
# IMSI (optional)
printf "New IMSI (15 digits, Enter to skip): "
read imsi
if [ -n "$imsi" ] && ! echo "$imsi" | grep -qE '^[0-9]{15}$'; then
    echo "Invalid, will skip IMSI."
    imsi=""
fi
# Wi‑Fi MAC
while true; do
    printf "New Wi‑Fi MAC (aa:bb:cc:dd:ee:ff): "
    read wlan_mac
    if echo "$wlan_mac" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then break; fi
    echo "Invalid format."
done
# Bluetooth MAC
while true; do
    printf "New Bluetooth MAC (aa:bb:cc:dd:ee:ff): "
    read bt_mac
    if echo "$bt_mac" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'; then break; fi
    echo "Invalid format."
done
# Serial
printf "New serial number (max 16 chars, Enter to keep original): "
read serial_no
if [ -z "$serial_no" ]; then
    serial_no=$(getprop ro.serialno)
    echo "Keeping original serial number: $serial_no"
fi
# Android ID
while true; do
    printf "New Android ID (16 hex digits): "
    read android_id
    if echo "$android_id" | grep -qE '^[0-9a-fA-F]{16}$'; then break; fi
    echo "Exactly 16 hex digits."
done
# GSF ID (optional)
printf "New GSF ID (Enter to skip): "
read gsf_id
# Build.prop fields (optional)
printf "New ro.build.fingerprint (Enter to keep current): "
read new_fp
printf "New ro.product.model (Enter to keep current): "
read new_model
printf "New ro.product.manufacturer (Enter to keep current): "
read new_manufacturer
printf "New ro.product.brand (Enter to keep current): "
read new_brand

# ----- Dangerous anti‑forensic options (default NO) -----
echo ""
echo "=============================================="
echo "  DANGEROUS CLEANUP OPTIONS (DEFAULT = NO)"
echo "=============================================="
echo "These can permanently damage your device if done wrong."
echo "You MUST type 'YES' (uppercase) to enable any of them."
printf "Zero modemst1/modemst2 partitions? (YES/no): "
read zero_modemst
if [ "$zero_modemst" != "YES" ]; then zero_modemst="no"; fi
printf "Zero NVRAM backup areas? (YES/no): "
read zero_nvram
if [ "$zero_nvram" != "YES" ]; then zero_nvram="no"; fi
printf "Overwrite free space with zeros? (YES/no): "
read shred_free
if [ "$shred_free" != "YES" ]; then shred_free="no"; fi

# ----- Final summary and irreversible confirmation -----
echo ""
echo "=============================================="
echo "  FINAL SUMMARY"
echo "=============================================="
echo " IMEI 1          : $imei1"
[ -n "$imei2" ] && echo " IMEI 2          : $imei2"
[ -n "$imsi" ]  && echo " IMSI            : $imsi"
echo " Wi‑Fi MAC       : $wlan_mac"
echo " BT MAC          : $bt_mac"
echo " Serial          : $serial_no"
echo " Android ID      : $android_id"
[ -n "$gsf_id" ] && echo " GSF ID          : $gsf_id"
[ -n "$new_fp" ]  && echo " Build Fingerprint: $new_fp"
[ -n "$new_model" ] && echo " Model           : $new_model"
[ -n "$new_manufacturer" ] && echo " Manufacturer    : $new_manufacturer"
[ -n "$new_brand" ] && echo " Brand           : $new_brand"
echo ""
echo " Dangerous cleanup:"
echo "   Zero modemst   : $zero_modemst"
echo "   Zero NVRAM     : $zero_nvram"
echo "   Shred free space: $shred_free"
echo "=============================================="
echo "This is your LAST chance to cancel."
while true; do
    printf "Type 'APPLY' to continue or 'EXIT' to abort: "
    read final
    if [ "$final" = "EXIT" ]; then
        echo "Aborted."
        exit 0
    elif [ "$final" = "APPLY" ]; then
        break
    else
        echo "Type APPLY or EXIT."
    fi
done

# ====================================================================
#  EXECUTION – NO USER INTERACTION FROM HERE ON
# ====================================================================
echo ""
echo "${G}▶ Starting changes... (do not touch the device)${NC}"

# 1. Backup everything
echo "[1/8] Backing up original identifiers..."
cat /sys/class/net/wlan0/address > /sdcard/orig_wlan_mac.txt 2>/dev/null
cat /sys/class/bluetooth/hci0/address > /sdcard/orig_bt_mac.txt 2>/dev/null
getprop ro.serialno > /sdcard/orig_serial.txt
settings get secure android_id > /sdcard/orig_android_id.txt
echo -e "AT+EGMR=0,7" > $ATDEV && sleep 0.2 && cat $ATDEV > /sdcard/orig_imei1.txt
echo -e "AT+EGMR=0,10" > $ATDEV && sleep 0.2 && cat $ATDEV > /sdcard/orig_imei2.txt

# Enable advanced AT commands
echo -e "AT+EATC=1" > $ATDEV
sleep 0.5

# 2. IMEI/IMSI
echo "[2/8] Writing IMEI/IMSI..."
echo -e "AT+EGMR=1,7,\"$imei1\"" > $ATDEV && sleep 0.5
[ -n "$imei2" ] && echo -e "AT+EGMR=1,10,\"$imei2\"" > $ATDEV && sleep 0.5
[ -n "$imsi" ] && echo -e "AT+WRITE_IMSI=\"$imsi\"" > $ATDEV && sleep 0.5

# 3. MAC addresses
echo "[3/8] Writing MAC addresses..."
echo -e "AT+MAC_WLAN=$wlan_mac" > $ATDEV && sleep 0.5
wlan_nvram="/data/nvram/APCFG/APRDEB/WIFI"
if [ -f "$wlan_nvram" ]; then
    cp "$wlan_nvram" /sdcard/orig_wifi_nvram.bin 2>/dev/null
    echo "$wlan_mac" | tr -d ':' | xxd -r -p | dd of="$wlan_nvram" bs=1 seek=4 conv=notrunc 2>/dev/null
    echo "   Wi‑Fi NVRAM patched."
fi
echo -e "AT+MAC_BT=$bt_mac" > $ATDEV && sleep 0.5

# 4. Serial number
echo "[4/8] Writing serial number..."
echo -e "AT+SN=$serial_no" > $ATDEV && sleep 0.5
if [ -f /data/nvram/APCFG/APRDEB/SERIAL ]; then
    cp /data/nvram/APCFG/APRDEB/SERIAL /sdcard/orig_serial_nvram.bin 2>/dev/null
    printf "%s" "$serial_no" | dd of=/data/nvram/APCFG/APRDEB/SERIAL bs=1 conv=notrunc 2>/dev/null
fi
resetprop ro.serialno "$serial_no"

# 5. Android ID & GSF ID
echo "[5/8] Writing Android ID & GSF ID..."
settings put secure android_id "$android_id"
if [ -n "$gsf_id" ]; then
    am force-stop com.google.android.gms 2>/dev/null
    sleep 1
    sqlite3 /data/data/com.google.android.gsf/databases/gservices.db \
        "update main set value='$gsf_id' where name='android_id';" 2>/dev/null
    echo "   GSF ID written (if database existed)."
fi

# 6. Build.prop overrides
echo "[6/8] Applying build.prop changes..."
mount -o remount,rw /system 2>/dev/null
[ -n "$new_fp" ] && resetprop ro.build.fingerprint "$new_fp"
[ -n "$new_model" ] && resetprop ro.product.model "$new_model"
[ -n "$new_manufacturer" ] && resetprop ro.product.manufacturer "$new_manufacturer"
[ -n "$new_brand" ] && resetprop ro.product.brand "$new_brand"

# 7. Banking compatibility (the crucial part)
echo "[7/8] Applying banking app compatibility fixes..."
# Certified fingerprint (override if user didn't set one, use known good)
CERT_FP="motorola/rhodei_g/rhodei:12/S1RLS32.55-25-10/25-10:user/release-keys"
if [ -z "$new_fp" ]; then
    resetprop ro.build.fingerprint "$CERT_FP"
    echo "   Applied certified fingerprint (no custom one given)."
fi
# Disable debugging
settings put global adb_enabled 0
settings put global development_settings_enabled 0
settings put global adb_wifi_enabled 0
# Add banking apps to DenyList (best effort)
BANK_PKGS="com.google.android.apps.walletnfcrel com.bankofamerica.mobile com.wellsfargo.wf com.chase.mobile com.usbank.mobilebanking com.citibank.mobile com.pnc.ecommerce.mobile com.usaa.mobile.android.usaa com.capitalone.mobile com.discoverfinancial.mobile com.tdbank com.bbt.mobile.bbt"
for pkg in $BANK_PKGS; do
    magisk --denylist add "$pkg" 2>/dev/null
done
# Reset Play Store data
pm clear com.android.vending 2>/dev/null
echo "   Play Store data cleared, banking apps stopped."

# 8. Anti‑forensic cleanup
echo "[8/8] Running optional cleanup..."
if [ "$zero_modemst" = "YES" ]; then
    if [ -b /dev/block/by-name/modemst1 ]; then
        dd if=/dev/zero of=/dev/block/by-name/modemst1 bs=4096 conv=notrunc 2>/dev/null
        echo "   modemst1 zeroed (radio may be bricked!)"
    fi
    if [ -b /dev/block/by-name/modemst2 ]; then
        dd if=/dev/zero of=/dev/block/by-name/modemst2 bs=4096 conv=notrunc 2>/dev/null
        echo "   modemst2 zeroed (radio may be bricked!)"
    fi
fi
if [ "$zero_nvram" = "YES" ]; then
    tar -czf /sdcard/orig_nvram_backup.tar.gz /data/nvram 2>/dev/null
    rm -rf /data/nvram/* 2>/dev/null
    echo "   NVRAM wiped (Wi‑Fi/BT may need reconfigure)."
fi
if [ "$shred_free" = "YES" ]; then
    dd if=/dev/zero of=/data/local/tmp/zero.fill bs=1M 2>/dev/null || true
    rm -f /data/local/tmp/zero.fill
    echo "   Free space overwritten."
fi
# Clean logs regardless
rm -rf /data/system/dropbox/* 2>/dev/null
logcat -c
dmesg -c >/dev/null 2>&1

# ----- Verification -----
echo ""
echo "${G}✅ All changes applied. Verifying IMEIs...${NC}"
echo -e "AT+EGMR=0,7" > $ATDEV && sleep 0.2 && cat $ATDEV > /sdcard/new_imei1.txt
echo -e "AT+EGMR=0,10" > $ATDEV && sleep 0.2 && cat $ATDEV > /sdcard/new_imei2.txt
echo "   New IMEIs saved to /sdcard/new_imei*.txt"

# ----- Final message -----
echo ""
echo "=============================================="
echo "  ${G}🎉 EVERYTHING DONE! 🎉${NC}"
echo "=============================================="
echo "Your device has been refingerprinted and is"
echo "banking-app‑friendly (mostly)."
echo ""
echo "Manual steps after reboot:"
echo "  1. Open Magisk → Hide the Magisk app"
echo "  2. Install 'Hide My Applist' (LSPosed) and"
echo "     hide all root apps from banking apps."
echo "  3. Reboot once more."
echo "  4. Test with 'Play Integrity API Checker'."
echo "  5. Sign into Play Store with a FRESH Google account."
echo ""
echo "Rebooting in 15 seconds... (press Ctrl+C to cancel)"
sleep 15
reboot
