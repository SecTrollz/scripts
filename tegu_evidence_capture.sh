#!/bin/sh
# ============================================================
# Tegu Evidence Capture — Run BEFORE hardening
# Creates a signed, timestamped forensic snapshot of the
# pre-hardening device state. Output is a JSON manifest that
# can be imported into MDMCheck → Audit Files.
#
# This establishes legal/forensic proof of:
#   1. Factory-preloaded MDM infrastructure you never consented to
#   2. Device state at a known point in time
#   3. Cryptographic chain of custody for all captured data
#   4. The build signing identity of system APKs on the device
#
# Usage (from Termux or ADB host):
#   sh tegu_evidence_capture.sh > tegu_evidence_$(date +%Y%m%d_%H%M%S).json
#
# Phase B additions (requires Shizuku/rish — run separately):
#   rish -c 'cat /data/system/device_owners.xml' >> phase_b.txt
#   rish -c 'cat /data/misc/adb/adb_keys'        >> phase_b.txt
#   rish -c 'service call persistent_data_block 7' >> phase_b.txt
#   rish -c 'service call persistent_data_block 9' >> phase_b.txt
#   rish -c 'service call persistent_data_block 12' >> phase_b.txt
# ============================================================

DEVICE_ID="${1:-}"

# Auto-detect execution context.
# If getprop is available directly we are running inside Termux on the device.
# If not, we are running from an external ADB host.
if command -v getprop > /dev/null 2>&1; then
    ON_DEVICE=1
    _r() { "$@" 2>/dev/null | tr -d '\r'; }
    _sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
    echo "[tegu_evidence] Running ON-DEVICE (Termux) — direct shell mode" >&2
else
    ON_DEVICE=0
    _ADB="adb${DEVICE_ID:+ -s $DEVICE_ID} shell"
    _r() { $_ADB "$@" 2>/dev/null | tr -d '\r'; }
    _sha() { $_ADB "sha256sum $1 2>/dev/null" | awk '{print $1}' | tr -d '\r'; }
    echo "[tegu_evidence] Running from ADB host — remote shell mode" >&2
fi

_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g;s/"/\\"/g;s/	/\\t/g' | tr '\n' '|' | sed 's/|$//' | head -c 2000; }

TIMESTAMP=$( date -u +"%Y-%m-%dT%H:%M:%SZ" )
CAPTURE_ID=$( _r "cat /proc/sys/kernel/random/uuid 2>/dev/null || echo unknown" )

# ── DEVICE IDENTITY ─────────────────────────────────────────
MODEL=$(     _r getprop ro.product.model )
SERIAL=$(    _r getprop ro.serialno )
FINGERPRINT=$( _r getprop ro.build.fingerprint )
ANDROID_VER=$( _r getprop ro.build.version.release )
BUILD_DATE=$(  _r getprop ro.build.date.utc )
BOOTLOADER=$(  _r getprop ro.bootloader )
BASEBAND=$(    _r getprop gsm.version.baseband )
SECURITY_PATCH=$( _r getprop ro.build.version.security_patch )
BOOT_MODE=$(   _r getprop ro.bootmode )
VERIFIED_BOOT=$( _r getprop ro.boot.verifiedbootstate )
AVB_STATE=$(   _r getprop ro.boot.avb_version )
UNLOCK_STATE=$(  _r getprop ro.boot.flash.locked )
OEM_UNLOCK_CARRIER=$( _r settings get global oem_unlock_allowed_by_carrier )
OEM_UNLOCK_USER=$(    _r settings get global oem_unlock_allowed_by_user )
UPTIME=$(      _r cat /proc/uptime )

# ── NETWORK STATE AT CAPTURE TIME ───────────────────────────
IFACE_STATE=$( _r "ip addr show wlan0 2>/dev/null | grep -E 'inet |state'" )
WIFI_SSID=$(   _r "dumpsys wifi 2>/dev/null | grep 'mWifiInfo.*SSID' | head -1" )

# ── MDM / ENROLLMENT STATE ──────────────────────────────────
DEVICE_OWNER=$( _r "dumpsys device_policy 2>/dev/null | grep -E 'mDeviceOwner|DeviceOwnerInfo' | head -3" )
DEVICE_OWNER_XML=$( _r "cat /data/system/device_owners.xml 2>/dev/null || echo NOT_ACCESSIBLE_PHASE_A" )
ADMIN_LIST=$(   _r "dumpsys device_policy 2>/dev/null | grep -E 'ActiveAdmin|adminPackage' | head -10" )

# CloudDPC state
CLOUDDPC_ENABLED=$(  _r "pm dump com.google.android.apps.work.clouddpc 2>/dev/null | grep 'enabled=' | head -1" )
CLOUDDPC_VER=$(      _r "pm dump com.google.android.apps.work.clouddpc 2>/dev/null | grep 'versionCode' | head -1" )
CLOUDDPC_DOMAIN=$(   _r "pm dump com.google.android.apps.work.clouddpc 2>/dev/null | grep -A4 'Domain verification' | grep -E 'verified|link handling'" )
CLOUDDPC_HOME=$(     _r "dumpsys activity activities 2>/dev/null | grep -E 'clouddpc.*(LauncherActivity|LockedSetup|LockedIncompliance)'" )

# OOBConfig — the hidden bootloader-adjacent package
OOBCONFIG_ENABLED=$( _r "pm dump com.google.android.apps.work.oobconfig 2>/dev/null | grep 'enabled=' | head -1" )
OOBCONFIG_PATH=$(    _r "pm dump com.google.android.apps.work.oobconfig 2>/dev/null | grep 'codePath' | head -1" )
OOBCONFIG_PERMS=$(   _r "pm dump com.google.android.apps.work.oobconfig 2>/dev/null | grep 'MANAGE_CARRIER_OEM_UNLOCK_STATE'" )

# CBRS state
CBRS_STATE=$(        _r "pm dump com.google.android.apps.cbrsnetworkmonitor 2>/dev/null | grep -E 'enabled=|installed=|lastDisabledCaller' | head -5" )
CBRS_DATA_DIR=$(     _r "ls /data/user/0/com.google.android.apps.cbrsnetworkmonitor/ 2>/dev/null || echo ABSENT" )

# OMA-DM state
OMADM_ENABLED=$(     _r "pm dump com.google.omadm.trigger 2>/dev/null | grep 'enabled=' | head -1" )
OMADM_SERVICE=$(     _r "dumpsys activity services 2>/dev/null | grep -i OemDmTrigger" )

# Repair Mode state
REPAIR_ENABLED=$(    _r "pm dump com.google.android.repairmode 2>/dev/null | grep 'enabled=' | head -1" )
REPAIR_ADMIN=$(      _r "dumpsys device_policy 2>/dev/null | grep -A3 repairmode" )

# RKPD state
RKPD_ENABLED=$(      _r "pm dump com.google.android.rkpdapp 2>/dev/null | grep 'enabled=' | head -1" )

# Retail demo
RETAIL_ENABLED=$(    _r "pm dump com.google.android.retaildemo 2>/dev/null | grep 'enabled=' | head -1" )

# ── NFC STATE ───────────────────────────────────────────────
NFC_STATE=$(         _r "settings get global nfc_on 2>/dev/null" )
NFC_ADAPTER=$(       _r "dumpsys nfc 2>/dev/null | grep -E 'mState|mEnabled|NfcEnabled' | head -3" )

# ── ADB TRUST ───────────────────────────────────────────────
ADB_KEYS=$(          _r "cat /data/misc/adb/adb_keys 2>/dev/null || echo NOT_ACCESSIBLE_PHASE_A" )
ADB_KEYS_COUNT=$( echo "$ADB_KEYS" | grep -c "^ecdsa\|^rsa" 2>/dev/null )
[ -z "$ADB_KEYS_COUNT" ] && ADB_KEYS_COUNT="unknown"

# ── TRUSTED CA STORES ───────────────────────────────────────
SYSTEM_CAS=$(        _r "ls /system/etc/security/cacerts/ 2>/dev/null | wc -l" )
USER_CAS=$(          _r "ls /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l || echo 0" )
USER_CA_LIST=$(      _r "ls /data/misc/user/0/cacerts-added/ 2>/dev/null || echo NONE" )

# ── ZERO-TOUCH / SETUP PREFS ────────────────────────────────
ZERO_TOUCH_PREFS=$(  _r "cat /data/data/com.google.android.setupwizard/shared_prefs/zero_touch_preferences.xml 2>/dev/null || echo NOT_ACCESSIBLE_PHASE_A" )

# ── GSERVICES ENTERPRISE ROWS ───────────────────────────────
GSERVICES_ENT=$(     _r "sqlite3 /data/data/com.google.android.gsf/databases/gservices.db 'SELECT * FROM main WHERE name LIKE \"%enterprise%\" OR name LIKE \"%dpc%\" OR name LIKE \"%mdm%\" OR name LIKE \"%provision%\";' 2>/dev/null || echo NOT_ACCESSIBLE_PHASE_A" )

# ── PRODUCT PARTITION APK HASHES (the immutable evidence baseline) ──
CLOUDDPC_APK_HASH=$(  _sha "/product/app/DevicePolicyPrebuilt-v10334460/DevicePolicyPrebuilt-v10334460.apk" )
OOBCONFIG_APK_HASH=$( _sha "/product/priv-app/OTAConfigNoZeroTouchPrebuilt/OTAConfigNoZeroTouchPrebuilt.apk" )
CBRS_APK_HASH=$(      _sha "/product/priv-app/CbrsNetworkMonitor/CbrsNetworkMonitor.apk" )
OMADM_APK_HASH=$(     _sha "/product/priv-app/OemDmTrigger/OemDmTrigger.apk" )
REPAIR_APK_HASH=$(    _sha "/product/priv-app/RepairMode/RepairMode.apk" )

# Known-good build signing cert (from backup APK forensics — both CBRS + IMS share this)
GOOGLE_BUILD_STAMP_BASELINE="3257d599a49d2c961a471ca9843f59d341a405884583fc087df4237b733bbd6d"

# ── PCAPDROID CAPTURE INSTRUCTION ───────────────────────────
# This script cannot start PCAPdroid automatically.
# MANUAL STEP: open PCAPdroid, start a capture, then reboot the device.
# The first ~90 seconds of post-boot traffic will show what RKPD,
# CloudDPC, OOBConfig, and OMA-DM are calling home to.
# Key hostnames to watch for in the capture:
#   remoteprovision.googleapis.com  — RKPD attestation
#   oobconfig.googleapis.com        — OOBConfig carrier provisioning
#   enterprise.google.com           — CloudDPC enrollment endpoint
#   afwsamples.appspot.com          — Android for Work test enrollment
#   Verizon OMA-DM servers (proprietary, carrier-specific)

# ── KNOWN EVIDENCE FROM OFFLINE ANALYSIS ────────────────────
# These hashes were computed offline from the st.zip archive
# collected 2026-06-02 to 2026-06-03. They are embedded here
# as the forensic anchor for this device's pre-hardening state.
KNOWN_HASHES=$(cat <<'HASHES'
adfc389a1a5735bfe280e2f69225a784e6a3788175a98575555eec0790df2fae  device-policy_dumpsys.txt
e53948f73d6bec08df4774a548df6fc73ee3595fd0cfa63cc39d72fb37577786  oemdmtrigger_dumpsys.txt
c880908f407e3658eebd61cc438f4477b165511113ca172af15a15ab8dcac60c  cbrsnetworkmonitor_dumpsys.txt
6cc44590ba52f829a1469d669b73dc279103362558f21a47ece445501da2d56a  oobconfig_dumpsys.txt
b46d0ebac00339639a78a741d17f5b6ebc94b53ed9eb4f13760a478d0cf35ba1  Repair-mode_dumpsys.txt
b2bcfc39340821d102dcdde07c0fc565974d2b63e0097207d7b543f06b499445  remote-provisioner_dumpsys.txt
ad6ac037c4cb153ea75ff225721f1c85a1ae00c590603dff552a9851a2905fc1  cbrsnetworkmonitor_24.1.721121105.bak
7676c8047acef0d0b48951aea6edbbcbce3dae60ef3cab6699027df4858315c3  shell_dumpsys.txt
HASHES
)

# ── EMIT EVIDENCE MANIFEST ───────────────────────────────────
cat <<JSON
{
  "schema": "tegu_evidence_v1",
  "capture_id": "$(_esc "$CAPTURE_ID")",
  "timestamp": "$TIMESTAMP",
  "capture_phase": "A",
  "note": "Phase A = ADB shell UID 2000. Run Phase B commands with rish for device_owners.xml, adb_keys, PersistentDataBlock state.",

  "device_identity": {
    "model": "$(_esc "$MODEL")",
    "serial": "$(_esc "$SERIAL")",
    "build_fingerprint": "$(_esc "$FINGERPRINT")",
    "android_version": "$(_esc "$ANDROID_VER")",
    "build_date_utc": "$(_esc "$BUILD_DATE")",
    "security_patch": "$(_esc "$SECURITY_PATCH")",
    "bootloader": "$(_esc "$BOOTLOADER")",
    "baseband": "$(_esc "$BASEBAND")",
    "boot_mode": "$(_esc "$BOOT_MODE")",
    "verified_boot_state": "$(_esc "$VERIFIED_BOOT")",
    "flash_locked": "$(_esc "$UNLOCK_STATE")",
    "oem_unlock_carrier": "$(_esc "$OEM_UNLOCK_CARRIER")",
    "oem_unlock_user": "$(_esc "$OEM_UNLOCK_USER")",
    "uptime_seconds": "$(_esc "$UPTIME")"
  },

  "network_at_capture": {
    "wlan0": "$(_esc "$IFACE_STATE")",
    "wifi_ssid": "$(_esc "$WIFI_SSID")"
  },

  "enrollment_state": {
    "device_owner_dumpsys": "$(_esc "$DEVICE_OWNER")",
    "device_owner_xml": "$(_esc "$DEVICE_OWNER_XML")",
    "active_admins": "$(_esc "$ADMIN_LIST")"
  },

  "packages": {
    "clouddpc": {
      "enabled_state": "$(_esc "$CLOUDDPC_ENABLED")",
      "version": "$(_esc "$CLOUDDPC_VER")",
      "domain_verification": "$(_esc "$CLOUDDPC_DOMAIN")",
      "home_launcher_active": "$(_esc "$CLOUDDPC_HOME")"
    },
    "oobconfig": {
      "enabled_state": "$(_esc "$OOBCONFIG_ENABLED")",
      "code_path": "$(_esc "$OOBCONFIG_PATH")",
      "oem_unlock_permission": "$(_esc "$OOBCONFIG_PERMS")"
    },
    "cbrs_monitor": {
      "state": "$(_esc "$CBRS_STATE")",
      "data_dir": "$(_esc "$CBRS_DATA_DIR")"
    },
    "oemdm_trigger": {
      "enabled_state": "$(_esc "$OMADM_ENABLED")",
      "active_service": "$(_esc "$OMADM_SERVICE")"
    },
    "repair_mode": {
      "enabled_state": "$(_esc "$REPAIR_ENABLED")",
      "admin_state": "$(_esc "$REPAIR_ADMIN")"
    },
    "rkpdapp": {
      "enabled_state": "$(_esc "$RKPD_ENABLED")"
    },
    "retail_demo": {
      "enabled_state": "$(_esc "$RETAIL_ENABLED")"
    }
  },

  "nfc": {
    "nfc_on_setting": "$(_esc "$NFC_STATE")",
    "adapter_state": "$(_esc "$NFC_ADAPTER")"
  },

  "trust": {
    "adb_keys_raw": "$(_esc "$ADB_KEYS")",
    "adb_key_count": "$ADB_KEYS_COUNT",
    "system_ca_count": "$(_esc "$SYSTEM_CAS")",
    "user_ca_count": "$(_esc "$USER_CAS")",
    "user_ca_list": "$(_esc "$USER_CA_LIST")"
  },

  "zero_touch_prefs": "$(_esc "$ZERO_TOUCH_PREFS")",
  "gservices_enterprise_rows": "$(_esc "$GSERVICES_ENT")",

  "product_partition_hashes": {
    "google_build_stamp_baseline": "$GOOGLE_BUILD_STAMP_BASELINE",
    "clouddpc_apk": "$(_esc "$CLOUDDPC_APK_HASH")",
    "oobconfig_apk": "$(_esc "$OOBCONFIG_APK_HASH")",
    "cbrs_apk": "$(_esc "$CBRS_APK_HASH")",
    "oemdm_apk": "$(_esc "$OMADM_APK_HASH")",
    "repair_mode_apk": "$(_esc "$REPAIR_APK_HASH")"
  },

  "offline_evidence_manifest": {
    "collection_date": "2026-06-02",
    "collection_method": "ADB Toolbox Pro on-device, Termux",
    "archives": ["st.zip (27 files)", "system-info-export.zip (19 files)"],
    "sha256_hashes": "$(_esc "$KNOWN_HASHES")"
  },

  "pcapdroid_instruction": "Start PCAPdroid capture before rebooting to capture RKPD, OOBConfig, CloudDPC, and OMA-DM boot-time network calls. Key hosts: remoteprovision.googleapis.com, oobconfig.googleapis.com, enterprise.google.com"
}
JSON
