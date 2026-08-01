#!/bin/sh
# ============================================================
# Tegu Watchdog — Termux:Boot persistent monitor
# Detects OTA-triggered state reversions and new MDM activation.
# Runs at every device boot via Termux:Boot.
#
# Install:
#   mkdir -p ~/.termux/boot/
#   cp tegu_watchdog.sh ~/.termux/boot/tegu_watchdog.sh
#   chmod +x ~/.termux/boot/tegu_watchdog.sh
#
# Requires: Termux:Boot app installed + enabled
# Log file: ~/storage/downloads/tegu_tamper.log (readable from Files)
# ============================================================

LOG="$HOME/storage/downloads/tegu_tamper.log"

# Watchdog runs as a Termux:Boot script — on-device context.
# If is accidentally used, replace with direct call.
# All commands below use direct shell (no adb prefix needed).
TIMESTAMP=$( date -u +"%Y-%m-%dT%H:%M:%SZ" )
DEVICE=$( getprop ro.product.model 2>/dev/null | tr -d '\r' )
ANDROID=$( getprop ro.build.version.release 2>/dev/null | tr -d '\r' )
FP=$( getprop ro.build.fingerprint 2>/dev/null | tr -d '\r' )

log() { printf '[%s] %s\n' "$TIMESTAMP" "$*" | tee -a "$LOG"; }
alert() { printf '[%s] *** TAMPER ALERT: %s ***\n' "$TIMESTAMP" "$*" | tee -a "$LOG"; }

# Ensure log dir exists
mkdir -p "$HOME/storage/downloads" 2>/dev/null

log "=== Tegu Watchdog Boot Check ==="
log "Device: $DEVICE | Android: $ANDROID"
log "Build: $FP"

ALERTS=0

# ── TIER 1: HOME LAUNCHER TRIP WIRE ─────────────────────────
home=$( dumpsys activity activities 2>/dev/null \
    | grep -E "clouddpc.*(LauncherActivity|LockedSetup|LockedIncompliance)" \
    | tr -d '\r' )
if [ -n "$home" ]; then
    alert "DEVICE LOCKED — CloudDPC HOME launcher is ACTIVE: $home"
    ALERTS=$(( ALERTS + 1 ))
else
    log "T1-HOME: CLEAR"
fi

# ── DEVICE OWNER ACTIVATION ─────────────────────────────────
do_check=$( dumpsys device_policy 2>/dev/null | grep -E 'mDeviceOwner|DeviceOwnerInfo' \
    | tr -d '\r' )
if echo "$do_check" | grep -q "ComponentName"; then
    alert "DEVICE OWNER SET: $do_check"
    ALERTS=$(( ALERTS + 1 ))
else
    log "T1-DO: CLEAR"
fi

# ── CBRS RE-ENABLE DETECTION ────────────────────────────────
cbrs=$( pm list packages -e 2>/dev/null | grep cbrsnetworkmonitor | tr -d '\r' )
if [ -n "$cbrs" ]; then
    alert "CBRS MONITOR RE-ENABLED after user-disable: $cbrs"
    ALERTS=$(( ALERTS + 1 ))
else
    log "T2-CBRS: CLEAR (still disabled)"
fi

# ── OOBCONFIG RE-ENABLE DETECTION ───────────────────────────
oob=$( pm list packages -e 2>/dev/null | grep oobconfig | tr -d '\r' )
if [ -n "$oob" ]; then
    alert "OOBCONFIG RE-ENABLED after hardening disable: $oob"
    ALERTS=$(( ALERTS + 1 ))
else
    log "T2-OOB: CLEAR (still disabled)"
fi

# ── REPAIR MODE RE-ENABLE ───────────────────────────────────
repair=$( pm list packages -e 2>/dev/null | grep repairmode | tr -d '\r' )
if [ -n "$repair" ]; then
    alert "REPAIR MODE RE-ENABLED: $repair"
    ALERTS=$(( ALERTS + 1 ))
else
    log "T2-REPAIR: CLEAR"
fi

# ── NFC RE-ENABLE ───────────────────────────────────────────
nfc=$( settings get global nfc_on 2>/dev/null | tr -d '\r' )
if [ "$nfc" = "1" ]; then
    alert "NFC RE-ENABLED (nfc_on=1) — enrollment tap vector restored"
    ALERTS=$(( ALERTS + 1 ))
else
    log "T2-NFC: CLEAR (nfc_on=$nfc)"
fi

# ── OMA-DM ACTIVE SESSION ───────────────────────────────────
omadm=$( dumpsys activity services 2>/dev/null | grep -i OemDmTrigger | tr -d '\r' )
if [ -n "$omadm" ]; then
    alert "OMA-DM ACTIVE SERVICE SESSION DETECTED: $omadm"
    ALERTS=$(( ALERTS + 1 ))
else
    log "T3-OMADM: CLEAR"
fi

# ── PRODUCT PARTITION HASH DRIFT ────────────────────────────
# These baselines are from the 2026-03-24 factory image.
# If ANY hash changes, an APK in the product partition was swapped.
check_apk_hash() {
    label="$1"; path="$2"; expected="$3"
    actual=$( sha256sum $path 2>/dev/null | awk '{print $1}' | tr -d '\r' )
    if [ -z "$actual" ]; then
        log "T4-$label: hash unavailable (normal for Phase A)"
    elif [ "$actual" != "$expected" ]; then
        alert "PRODUCT PARTITION APK HASH CHANGED: $label | expected=$expected | got=$actual"
        ALERTS=$(( ALERTS + 1 ))
    else
        log "T4-$label: hash OK ($actual)"
    fi
}

# Note: baselines must be populated from first run of tegu_evidence_capture.sh
# Replace FILL_FROM_EVIDENCE_CAPTURE with actual hashes after first capture
CLOUDDPC_BASELINE="${CLOUDDPC_HASH:-FILL_FROM_EVIDENCE_CAPTURE}"
OOBCONFIG_BASELINE="${OOBCONFIG_HASH:-FILL_FROM_EVIDENCE_CAPTURE}"

check_apk_hash "CLOUDDPC"  "/product/app/DevicePolicyPrebuilt-v10334460/DevicePolicyPrebuilt-v10334460.apk" "$CLOUDDPC_BASELINE"
check_apk_hash "OOBCONFIG" "/product/priv-app/OTAConfigNoZeroTouchPrebuilt/OTAConfigNoZeroTouchPrebuilt.apk" "$OOBCONFIG_BASELINE"

# ── OTA BUILD FINGERPRINT CHANGE ────────────────────────────
LAST_FP_FILE="$HOME/.tegu_last_fp"
if [ -f "$LAST_FP_FILE" ]; then
    last_fp=$( cat "$LAST_FP_FILE" )
    if [ "$FP" != "$last_fp" ]; then
        alert "BUILD FINGERPRINT CHANGED — OTA may have reversed hardening"
        alert "  Previous: $last_fp"
        alert "  Current:  $FP"
        alert "  ACTION REQUIRED: re-run tegu_harden.sh immediately"
        ALERTS=$(( ALERTS + 1 ))
    else
        log "T4-FP: unchanged ($FP)"
    fi
fi
printf '%s' "$FP" > "$LAST_FP_FILE"

# ── FCMDOMAIN REARM CHECK ────────────────────────────────────
domain_check=$( pm dump com.google.android.apps.work.clouddpc 2>/dev/null \
    | grep -A4 'Domain verification' | grep 'verified' | tr -d '\r' )
if [ -n "$domain_check" ]; then
    log "T4-DOMAIN: enterprise.google.com still verified (NFC intercept potentially rearmed post-OTA)"
    # Don't ALERT here — this is the permanent state; only alert if link-handling was re-enabled
    lh=$( pm dump com.google.android.apps.work.clouddpc 2>/dev/null \
        | grep 'Verification link handling allowed: true' | tr -d '\r' )
    if [ -n "$lh" ]; then
        alert "NFC DOMAIN LINK HANDLING RE-ENABLED for enterprise.google.com"
        ALERTS=$(( ALERTS + 1 ))
    fi
fi

# ── FINAL SUMMARY ───────────────────────────────────────────
log "--- Boot check complete: $ALERTS alert(s) ---"

if [ "$ALERTS" -gt 0 ]; then
    log "ACTION: $ALERTS anomaly(s) detected. Review $LOG."
    log "ACTION: Run tegu_harden.sh if OTA reversed hardening."
    log "ACTION: Run tegu_evidence_capture.sh to snapshot new state."
    # Termux notification (requires termux-api package)
    if command -v termux-notification > /dev/null 2>&1; then
        termux-notification \
            --title "Tegu Watchdog: $ALERTS ALERT(s)" \
            --content "MDM state anomaly detected at boot. Open tegu_tamper.log." \
            --priority high \
            --id tegu_watchdog \
            2>/dev/null
    fi
fi

log "=== End watchdog ==="
