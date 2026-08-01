#!/bin/sh
# ============================================================
# MDMCheck Collector — Pixel 9a / Android 16 / Verizon
# Baseline: stock factory image, user-disabled CBRS
# Run from Termux on-device or from a connected ADB host
#
# Usage:
#   ./mdmcheck_collector.sh              # auto-detect device
#   ./mdmcheck_collector.sh <device_id>  # specific ADB target
#   ./mdmcheck_collector.sh | curl -s -X POST https://your-worker.dev/ingest \
#       -H "Content-Type: application/json" --data-binary @-
#
# Output: JSON to stdout
# ============================================================

DEVICE_ID="${1:-}"

if [ -n "$DEVICE_ID" ]; then
    ADB_PREFIX="adb -s $DEVICE_ID shell"
else
    ADB_PREFIX="adb shell"
fi

# Run a shell command via ADB, strip carriage returns
_r() { $ADB_PREFIX "$@" 2>/dev/null | tr -d '\r'; }

# Escape double quotes for JSON embedding
_esc() { echo "$1" | sed 's/"/\\"/g' | head -c 600; }

# Collect device metadata
timestamp=$( date -u +"%Y-%m-%dT%H:%M:%SZ" )
device_model=$(  _r getprop ro.product.model   )
android_ver=$(   _r getprop ro.build.version.release )
build_fp=$(      _r getprop ro.build.fingerprint )
serial=$(        _r getprop ro.serialno )

findings=""
_add() {
    if [ -n "$findings" ]; then findings="${findings},"; fi
    findings="${findings}${1}"
}

# Build one JSON finding object
# _finding <tier> <severity> <id> <label> <status> <evidence>
_finding() {
    printf '{"tier":%d,"severity":"%s","id":"%s","label":"%s","status":"%s","evidence":"%s"}' \
        "$1" "$2" "$3" "$(_esc "$4")" "$5" "$(_esc "$6")"
}

# ============================================================
# TIER 1  —  ACTIVATION GATES
# The HOME launcher check is the trip wire. If CloudDPC has
# claimed HOME, the device is locked and under MDM control.
# Every other check is downstream of this one.
# ============================================================

# --- T1-A: CloudDPC Device Owner set ---
t1a=$( _r dumpsys device_policy | grep -E "mDeviceOwner|DeviceOwnerInfo|ActiveAdmin.*clouddpc" )
if [ -n "$t1a" ]; then
    _add "$(_finding 1 CRITICAL t1_device_owner \
        "CloudDPC IS SET AS DEVICE OWNER" \
        ALERT "$t1a")"
else
    _add "$(_finding 1 CRITICAL t1_device_owner \
        "CloudDPC Device Owner" \
        CLEAR "No device owner set — dormant")"
fi

# --- T1-B: CloudDPC HOME launcher active (THE KEY CHECK) ---
# If any of CloudDPC's HOME-category activities are the current
# or resumed HOME, the device's UI is under MDM control.
# Activities to watch: LauncherActivity, LockedSetupActivity,
# LockedIncomplianceActivity, NetworkEscapeHatchActivity,
# PostEncryptionActivity, TrampolineActivity
t1b=$( _r dumpsys activity activities \
    | grep -E "clouddpc.*(LauncherActivity|LockedSetup|LockedIncompliance|NetworkEscape|PostEncrypt|TrampolineActivity)" )
if [ -n "$t1b" ]; then
    _add "$(_finding 1 CRITICAL t1_home_launcher \
        "*** CloudDPC HOME LAUNCHER IS ACTIVE — DEVICE IS LOCKED ***" \
        ALERT "$t1b")"
else
    _add "$(_finding 1 CRITICAL t1_home_launcher \
        "CloudDPC HOME Launcher" \
        CLEAR "CloudDPC not claiming HOME — device not in lockdown")"
fi

# --- T1-C: Active provisioning / enrollment in logcat ---
t1c=$( _r logcat -d -t 300 \
    | grep "com.google.android.apps.work.clouddpc" \
    | grep -iE "provision|enroll|LockedSetup|SetupActivity|ROLE_HOLDER" )
if [ -n "$t1c" ]; then
    _add "$(_finding 1 CRITICAL t1_enrollment \
        "CloudDPC ENROLLMENT EVENT IN LOGCAT" \
        ALERT "$t1c")"
else
    _add "$(_finding 1 CRITICAL t1_enrollment \
        "CloudDPC Enrollment State" \
        CLEAR "No active enrollment in recent logcat")"
fi

# --- T1-D: NFC enrollment intercept armed ---
# Domain verification state: if enterprise.google.com is VERIFIED
# and link handling is enabled, any NFC tap or enrollment URL
# auto-routes to CloudDPC with zero user confirmation.
t1d=$( _r dumpsys package com.google.android.apps.work.clouddpc \
    | grep -A4 "Domain verification" \
    | grep -E "verified|Verification link handling.*true" )
if echo "$t1d" | grep -q "verified"; then
    _add "$(_finding 1 CRITICAL t1_nfc_domain \
        "enterprise.google.com domain VERIFIED — NFC enrollment intercept ARMED" \
        WARN "$t1d")"
else
    _add "$(_finding 1 CRITICAL t1_nfc_domain \
        "CloudDPC Domain Verification" \
        CLEAR "enterprise.google.com not verified")"
fi

# ============================================================
# TIER 2  —  SURFACE INTEGRITY
# Components you've already neutralized. If any of these flip,
# an OTA or remote action reversed your work.
# ============================================================

# --- T2-A: CBRS re-enable ---
# You disabled this via adb shell. It confirmed: installed=false,
# enabled=3, ceDataInode=-1. If it reappears, OTA re-enabled it.
t2a=$( _r pm list packages -e | grep cbrsnetworkmonitor )
if [ -n "$t2a" ]; then
    _add "$(_finding 2 HIGH t2_cbrs_reenable \
        "CBRS Monitor RE-ENABLED — was user-disabled, OTA may have reversed this" \
        ALERT "$t2a")"
else
    _add "$(_finding 2 HIGH t2_cbrs_reenable \
        "CBRS Monitor Disable State" \
        CLEAR "Still disabled — not in enabled package list")"
fi

# --- T2-B: Repair Mode active as Device Admin ---
# RepairMode has mPriority=999 and can bypass PIN for Google
# service technician access. Should never be an active admin
# on a personally-owned device.
t2b=$( _r dumpsys device_policy \
    | grep -A5 "repairmode" \
    | grep -iE "active|admin|enabled=1" )
if [ -n "$t2b" ]; then
    _add "$(_finding 2 HIGH t2_repair_mode \
        "Repair Mode ACTIVE as Device Admin — technician access enabled" \
        ALERT "$t2b")"
else
    _add "$(_finding 2 HIGH t2_repair_mode \
        "Repair Mode Admin State" \
        CLEAR "Not active as device admin")"
fi

# --- T2-C: OOBConfig SIMLOCK dialer code invoked ---
# Secret code 7465625 (= SIMLOCK on dialpad) gives carrier
# access to SIM lock state via com.google.android.apps.work.oobconfig.
# Also has MANAGE_CARRIER_OEM_UNLOCK_STATE — can affect bootloader.
t2c=$( _r logcat -d -t 300 \
    | grep -iE "simlock|SimLockProvider|7465625|oobconfig.*sim" )
if [ -n "$t2c" ]; then
    _add "$(_finding 2 HIGH t2_simlock \
        "OOBConfig SIMLOCK code invoked or SIM lock activity detected" \
        ALERT "$t2c")"
else
    _add "$(_finding 2 HIGH t2_simlock \
        "OOBConfig SIMLOCK Dialer Code (7465625)" \
        CLEAR "No SIMLOCK invocation in recent logcat")"
fi

# --- T2-D: OOBConfig bootloader unlock state ---
# MANAGE_CARRIER_OEM_UNLOCK_STATE is granted=true in this package.
# Cross-check the actual OEM unlock setting.
t2d=$( _r settings get global oem_unlock_allowed_by_carrier 2>/dev/null )
t2d2=$( _r settings get global oem_unlock_allowed_by_user 2>/dev/null )
if [ "$t2d" = "0" ] || [ "$t2d" = "null" ]; then
    _add "$(_finding 2 HIGH t2_oem_unlock \
        "OEM Unlock (Carrier)" \
        CLEAR "oem_unlock_allowed_by_carrier=${t2d} — carrier lock active")"
else
    _add "$(_finding 2 HIGH t2_oem_unlock \
        "OEM Unlock carrier flag is ENABLED" \
        WARN "oem_unlock_allowed_by_carrier=${t2d} user=${t2d2}")"
fi

# ============================================================
# TIER 3  —  CARRIER LAYER ACTIVITY
# ============================================================

# --- T3-A: OMA-DM active service binding ---
t3a=$( _r dumpsys activity services \
    | grep -iE "OemDmTrigger|omadm\.trigger|omadm\.service" )
if [ -n "$t3a" ]; then
    _add "$(_finding 3 MEDIUM t3_omadm_active \
        "OMA-DM service ACTIVE — carrier management session in progress" \
        WARN "$t3a")"
else
    _add "$(_finding 3 MEDIUM t3_omadm_active \
        "OMA-DM Service Activity" \
        CLEAR "No active OMA-DM service binding")"
fi

# --- T3-B: OOBConfig FCM provisioning push received ---
t3b=$( _r logcat -d -t 300 \
    | grep "ProvisioningConfigChangedFcmListenerService" )
if [ -n "$t3b" ]; then
    _add "$(_finding 3 MEDIUM t3_oob_fcm \
        "OOBConfig received remote provisioning config push via FCM" \
        WARN "$t3b")"
else
    _add "$(_finding 3 MEDIUM t3_oob_fcm \
        "OOBConfig FCM Provisioning Push" \
        CLEAR "No FCM provisioning push detected")"
fi

# --- T3-C: RKPD attestation failure ---
t3c=$( _r logcat -d -s rkpdapp \
    | grep -iE "error|fail|expired|revoked|abort" )
if [ -n "$t3c" ]; then
    _add "$(_finding 3 MEDIUM t3_rkpd \
        "RKPD attestation error — hardware trust chain may be broken" \
        WARN "$t3c")"
else
    _add "$(_finding 3 MEDIUM t3_rkpd \
        "RKPD Attestation Health" \
        CLEAR "No attestation failures in rkpdapp log")"
fi

# ============================================================
# TIER 4  —  PACKAGE FINGERPRINT INTEGRITY
# Detects version drift or path changes outside known OTA cycles
# ============================================================

# Baselines captured 2026-03-24 from Pixel 9a Verizon Android 16
BASELINE_CLOUDDPC_VER="10334460"
BASELINE_CLOUDDPC_DATE="2026-03-24"
BASELINE_OOB_PATH="OTAConfigNoZeroTouchPrebuilt"

# --- T4-A: CloudDPC version ---
t4a=$( _r pm dump com.google.android.apps.work.clouddpc \
    | grep -E "versionCode|lastUpdateTime" | head -2 )
if echo "$t4a" | grep -q "$BASELINE_CLOUDDPC_VER"; then
    _add "$(_finding 4 LOW t4_clouddpc_version \
        "CloudDPC Version Integrity" \
        CLEAR "$t4a — matches baseline $BASELINE_CLOUDDPC_VER")"
else
    _add "$(_finding 4 LOW t4_clouddpc_version \
        "CloudDPC version CHANGED from baseline" \
        WARN "$t4a — baseline was $BASELINE_CLOUDDPC_VER")"
fi

# --- T4-B: OOBConfig codepath ---
t4b=$( _r pm dump com.google.android.apps.work.oobconfig \
    | grep "codePath" | head -1 )
if echo "$t4b" | grep -q "$BASELINE_OOB_PATH"; then
    _add "$(_finding 4 LOW t4_oobconfig_path \
        "OOBConfig Package Path Integrity" \
        CLEAR "$t4b")"
else
    _add "$(_finding 4 LOW t4_oobconfig_path \
        "OOBConfig path CHANGED from baseline" \
        WARN "$t4b — baseline was $BASELINE_OOB_PATH")"
fi

# --- T4-C: Qualcomm QCRIL permission on Tensor hardware ---
# OMA-DM trigger requests com.qualcomm.permission.USE_QCRIL_MSG_TUNNEL.
# On Tensor (non-Qualcomm) this should NEVER be granted=true.
# If it is, a Qualcomm modem layer has appeared from nowhere.
t4c=$( _r pm dump com.google.omadm.trigger \
    | grep "USE_QCRIL_MSG_TUNNEL" )
if echo "$t4c" | grep -q "granted=true"; then
    _add "$(_finding 4 LOW t4_qcril_anomaly \
        "Qualcomm QCRIL tunnel GRANTED on Tensor device — hardware anomaly" \
        ALERT "$t4c")"
else
    _add "$(_finding 4 LOW t4_qcril_anomaly \
        "Qualcomm QCRIL Permission (Tensor baseline)" \
        CLEAR "Not granted — expected on non-Qualcomm hardware")"
fi

# ============================================================
# TIER 5  —  BEHAVIORAL / INFORMATIONAL
# ============================================================

# --- T5-A: CBRS data directory resurrection ---
# After disable + data clear, ceDataInode=-1. If dir reappears,
# something re-initialized the CBRS monitor.
t5a=$( _r ls /data/user/0/com.google.android.apps.cbrsnetworkmonitor/ 2>/dev/null )
if [ -n "$t5a" ]; then
    _add "$(_finding 5 LOW t5_cbrs_resurrected \
        "CBRS data directory RECREATED after disable/wipe" \
        WARN "$t5a")"
else
    _add "$(_finding 5 LOW t5_cbrs_resurrected \
        "CBRS Data Directory State" \
        CLEAR "Data directory absent — consistent with disabled state")"
fi

# --- T5-B: CloudDPC social app query targets (informational) ---
# CloudDPC's manifest explicitly declares com.facebook.katana and
# com.grindrapp.android as interaction-queryable targets.
# This is baked into the product partition system image.
# Not inherently malicious — documents the surface as-is.
t5b=$( _r pm dump com.google.android.apps.work.clouddpc \
    | grep -E "facebook\.katana|grindrapp\.android" )
if [ -n "$t5b" ]; then
    _add "$(_finding 5 LOW t5_social_mdm_targets \
        "CloudDPC hardcodes Facebook and Grindr as MDM query targets (informational)" \
        WARN "Baked into product partition — cannot be removed without bootloader unlock")"
else
    _add "$(_finding 5 LOW t5_social_mdm_targets \
        "CloudDPC Social App Query Targets" \
        CLEAR "Not found in package dump")"
fi

# --- T5-C: SIM Toolkit active session ---
t5c=$( _r dumpsys activity services | grep -i "stk\|StkCmd" )
if [ -n "$t5c" ]; then
    _add "$(_finding 5 LOW t5_stk_active \
        "SIM Toolkit active service session" \
        WARN "$t5c")"
else
    _add "$(_finding 5 LOW t5_stk_active \
        "SIM Toolkit Session" \
        CLEAR "No active STK service")"
fi

# ============================================================
# SCORE AND EMIT
# ============================================================

alert_count=$( printf '%s' "$findings" | grep -o '"status":"ALERT"' | wc -l | tr -d ' ' )
warn_count=$(  printf '%s' "$findings" | grep -o '"status":"WARN"'  | wc -l | tr -d ' ' )
clear_count=$( printf '%s' "$findings" | grep -o '"status":"CLEAR"' | wc -l | tr -d ' ' )

if [ "$alert_count" -gt 0 ]; then
    overall="COMPROMISED"
elif [ "$warn_count" -gt 0 ]; then
    overall="ELEVATED"
else
    overall="CLEAN"
fi

cat <<JSON
{
  "schema": "mdmcheck_v1",
  "timestamp": "${timestamp}",
  "device": {
    "model": "${device_model}",
    "android_version": "${android_ver}",
    "build_fingerprint": "${build_fp}",
    "serial": "${serial}",
    "baseline": "pixel9a_verizon_stock_android16_20260324"
  },
  "summary": {
    "overall": "${overall}",
    "alert_count": ${alert_count},
    "warn_count": ${warn_count},
    "clear_count": ${clear_count},
    "total_checks": $(( alert_count + warn_count + clear_count ))
  },
  "findings": [${findings}]
}
JSON
