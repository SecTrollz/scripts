#!/bin/sh
# ============================================================
# Tegu Hardening — Run AFTER tegu_evidence_capture.sh
# Disables every attack surface that can be neutralized without
# bootloader unlock. Logs every action with timestamp.
#
# What this cannot fix (requires bootloader unlock + custom ROM):
#   - Removing APKs from /product partition
#   - Revoking SYSTEM_FIXED location grants on CBRS
#   - Removing Samsung SLSI RIL hooks
#   - Removing RKPD from the APEX module
#   - Removing CloudDPC entirely
#
# What this does fix:
#   - Disables 4 additional attack-surface packages
#   - Clears CloudDPC and OOBConfig FCM tokens + stored state
#   - Revokes enterprise.google.com domain verification (disarms NFC intercept)
#   - Disables NFC radio (cuts physical enrollment tap vector)
#   - Writes a full action log for MDMCheck → Audit Files import
#
# Usage:
#   sh tegu_harden.sh 2>&1 | tee tegu_harden_$(date +%Y%m%d_%H%M%S).log
# ============================================================

DEVICE_ID="${1:-}"

# Auto-detect: Termux on-device vs. external ADB host
if command -v getprop > /dev/null 2>&1; then
    _r()  { "$@" 2>/dev/null | tr -d '\r'; }
    _rr() { "$@" 2>&1 | tr -d '\r'; }
    echo "[tegu_harden] Running ON-DEVICE (Termux) — direct shell mode" >&2
else
    _ADB="adb${DEVICE_ID:+ -s $DEVICE_ID} shell"
    _r()  { $_ADB "$@" 2>/dev/null | tr -d '\r'; }
    _rr() { $_ADB "$@" 2>&1 | tr -d '\r'; }
    echo "[tegu_harden] Running from ADB host — remote shell mode" >&2
fi

TIMESTAMP=$( date -u +"%Y-%m-%dT%H:%M:%SZ" )
PASS=0
FAIL=0
SKIP=0

log() {
    printf '[%s] %s\n' "$(date -u +"%H:%M:%S")" "$*"
}

ok() {
    PASS=$(( PASS + 1 ))
    printf '  ✓ %s\n' "$*"
}

fail() {
    FAIL=$(( FAIL + 1 ))
    printf '  ✗ %s\n' "$*"
}

skip() {
    SKIP=$(( SKIP + 1 ))
    printf '  — %s\n' "$*"
}

# Check a package state before acting
pkg_enabled() {
    result=$( _r "pm list packages -e 2>/dev/null | grep $1" )
    [ -n "$result" ]
}

pkg_exists() {
    result=$( _r "pm list packages -a 2>/dev/null | grep $1" )
    [ -n "$result" ]
}

echo "═══════════════════════════════════════════════════════"
echo "  Tegu Hardening Script — $TIMESTAMP"
echo "  Device: $( _r getprop ro.product.model )"
echo "  Android: $( _r getprop ro.build.version.release )"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "PRECONDITION: tegu_evidence_capture.sh must have been run first."
echo "This script changes device state. Evidence must exist before hardening."
echo ""

# ── SECTION 1: VERIFY EVIDENCE WAS CAPTURED ─────────────────
log "Section 1 — Pre-flight checks"

# Check CBRS is still disabled from prior work
if ! pkg_enabled "cbrsnetworkmonitor"; then
    ok "CBRS monitor already disabled (prior work preserved)"
else
    fail "CBRS monitor is ENABLED — was it re-enabled by OTA? Run evidence capture first."
fi

# Verify we're not in MDM lockdown before proceeding
home_check=$( _r "dumpsys activity activities 2>/dev/null | grep 'clouddpc.*HOME'" )
if [ -n "$home_check" ]; then
    echo ""
    echo "  *** ABORT: CloudDPC HOME launcher is ACTIVE ***"
    echo "  *** The device is already under MDM control ***"
    echo "  *** Hardening cannot proceed — document this state ***"
    exit 1
fi
ok "CloudDPC HOME launcher not active — safe to proceed"

echo ""

# ── SECTION 2: DISABLE ATTACK-SURFACE PACKAGES ──────────────
log "Section 2 — Disabling attack-surface packages"

# OOBConfig — has MANAGE_CARRIER_OEM_UNLOCK_STATE + SIMLOCK dialer + LPA + FCM provisioning
# The name says NoZeroTouch but it's a full carrier provisioning channel
log "  2-A: com.google.android.apps.work.oobconfig (OTAConfigNoZeroTouchPrebuilt)"
if pkg_enabled "com.google.android.apps.work.oobconfig"; then
    result=$( _rr "pm disable-user --user 0 com.google.android.apps.work.oobconfig" )
    if echo "$result" | grep -qi "disabled"; then
        ok "OOBConfig disabled — SIMLOCK dialer code 7465625 neutralized"
        ok "OOBConfig disabled — MANAGE_CARRIER_OEM_UNLOCK_STATE channel cut"
        ok "OOBConfig disabled — FCM provisioning push listener gone"
    else
        fail "OOBConfig disable failed: $result"
    fi
else
    skip "OOBConfig already disabled"
fi

# RepairMode — mPriority=999 Device Admin entry point for Google technicians
log "  2-B: com.google.android.repairmode"
if pkg_enabled "com.google.android.repairmode"; then
    result=$( _rr "pm disable-user --user 0 com.google.android.repairmode" )
    if echo "$result" | grep -qi "disabled"; then
        ok "RepairMode disabled — priority-999 device admin entry point closed"
    else
        fail "RepairMode disable failed: $result"
    fi
else
    skip "RepairMode already disabled"
fi

# RetailDemo — should be inert but listed as enabled; close it
log "  2-C: com.google.android.retaildemo"
if pkg_enabled "com.google.android.retaildemo"; then
    result=$( _rr "pm disable-user --user 0 com.google.android.retaildemo" )
    if echo "$result" | grep -qi "disabled"; then
        ok "RetailDemo disabled"
    else
        fail "RetailDemo disable failed: $result"
    fi
else
    skip "RetailDemo already disabled"
fi

echo ""

# ── SECTION 3: CUT CloudDPC FCM ENROLLMENT CHANNEL ──────────
log "Section 3 — Cutting CloudDPC remote push channel"

# Clearing CloudDPC data invalidates its FCM registration token.
# An FCM token is how OTA enrollment pushes reach the app without NFC/QR.
# Without a valid token, a remote enrollment push has no delivery address.
# NOTE: this does NOT remove the app or its permissions. It only clears
# the stored token and any cached enrollment state. The app re-registers
# on next launch if it is ever invoked.
log "  3-A: Clear CloudDPC data (FCM token + enrollment state)"
result=$( _rr "pm clear com.google.android.apps.work.clouddpc" )
if echo "$result" | grep -qi "success"; then
    ok "CloudDPC data cleared — FCM token invalidated"
    ok "CloudDPC cleared — any cached enrollment state erased"
else
    fail "CloudDPC clear failed: $result"
fi

# Clear OOBConfig data — cuts its FCM provisioning token too
log "  3-B: Clear OOBConfig data (FCM provisioning token)"
result=$( _rr "pm clear com.google.android.apps.work.oobconfig" )
if echo "$result" | grep -qi "success"; then
    ok "OOBConfig data cleared — FCM provisioning token invalidated"
else
    fail "OOBConfig clear failed: $result"
fi

echo ""

# ── SECTION 4: DISARM NFC ENROLLMENT INTERCEPT ──────────────
log "Section 4 — Disarming NFC enrollment intercept"

# The raw data confirms enterprise.google.com is VERIFIED for CloudDPC.
# This means any NFC tag carrying the managed provisioning MIME type
# (application/com.android.managedprovisioning) auto-routes to CloudDPC
# with zero browser confirmation prompt.
#
# Step 4-A: Revoke the domain link handling for the enterprise domains.
# This sets the user's domain selection to "disallow" for CloudDPC,
# overriding the system-verified state at the user level.
log "  4-A: Revoke enterprise.google.com domain link handling for CloudDPC"
result1=$( _rr "pm set-app-links-user-selection --package com.google.android.apps.work.clouddpc --user 0 --link-handling disallow enterprise.google.com" )
result2=$( _rr "pm set-app-links-user-selection --package com.google.android.apps.work.clouddpc --user 0 --link-handling disallow *.enterprise.google.com" )
if echo "$result1$result2" | grep -qi "error\|exception\|unknown"; then
    fail "Domain link revocation failed (may require Android 12+ API): $result1 $result2"
    log "  4-A fallback: try pm set-app-links state"
    _rr "pm set-app-links --package com.google.android.apps.work.clouddpc 1024 enterprise.google.com"
    _rr "pm set-app-links --package com.google.android.apps.work.clouddpc 1024 enterprise-staging.sandbox.google.com"
else
    ok "enterprise.google.com link handling set to DISALLOW for CloudDPC"
    ok "*.enterprise.google.com link handling set to DISALLOW for CloudDPC"
fi

# Step 4-B: Disable NFC radio entirely.
# The physical NFC enrollment tap cannot work if the NFC radio is off.
# NFC is a rarely-needed feature on a privacy-focused device.
# Re-enable with: adb shell svc nfc enable (or from Settings)
log "  4-B: Disable NFC radio (physical enrollment tap vector)"
nfc_before=$( _r "settings get global nfc_on" )
_rr "svc nfc disable" > /dev/null
nfc_after=$( _r "settings get global nfc_on" )
if [ "$nfc_after" = "0" ] || [ "$nfc_after" = "null" ]; then
    ok "NFC radio disabled (was: $nfc_before)"
else
    fail "NFC disable command ran but state is: $nfc_after — check NFC settings manually"
fi

echo ""

# ── SECTION 5: RESTRICT CloudDPC PERMISSIONS ────────────────
log "Section 5 — Restricting CloudDPC runtime permissions"

# CloudDPC's runtime location permissions were granted=false at capture time.
# Explicitly revoke them to prevent any future grant without user interaction.
for perm in \
    android.permission.ACCESS_FINE_LOCATION \
    android.permission.ACCESS_COARSE_LOCATION \
    android.permission.ACCESS_BACKGROUND_LOCATION \
    android.permission.CAMERA \
    android.permission.READ_PHONE_STATE \
    android.permission.READ_PHONE_NUMBERS \
    android.permission.CALL_PHONE \
    android.permission.GET_ACCOUNTS
do
    result=$( _rr "pm revoke com.google.android.apps.work.clouddpc $perm" )
    if echo "$result" | grep -qi "error\|not granted\|unknown"; then
        skip "$perm — not granted or already revoked"
    else
        ok "Revoked: $perm"
    fi
done

echo ""

# ── SECTION 6: VERIFY POST-HARDENING STATE ───────────────────
log "Section 6 — Post-hardening verification"

CHECKS_PASS=0
CHECKS_FAIL=0

_check() {
    label="$1"
    cmd="$2"
    expected_absent="$3"  # if non-empty, result should NOT contain this
    result=$( _r "$cmd" )
    if [ -n "$expected_absent" ] && echo "$result" | grep -q "$expected_absent"; then
        printf '  ✗ POST-CHECK FAIL: %s — found: %s\n' "$label" "$result"
        CHECKS_FAIL=$(( CHECKS_FAIL + 1 ))
    else
        printf '  ✓ %s\n' "$label"
        CHECKS_PASS=$(( CHECKS_PASS + 1 ))
    fi
}

_check "CloudDPC: no active Device Owner"      "dumpsys device_policy | grep mDeviceOwner"       "ComponentName"
_check "CloudDPC: HOME launcher not active"    "dumpsys activity activities | grep 'clouddpc.*HOME'"  "LauncherActivity"
_check "CBRS: still disabled"                  "pm list packages -e | grep cbrsnetworkmonitor"    "cbrsnetworkmonitor"
_check "OOBConfig: now disabled"               "pm list packages -e | grep oobconfig"             "oobconfig"
_check "RepairMode: now disabled"              "pm list packages -e | grep repairmode"            "repairmode"
_check "RetailDemo: now disabled"              "pm list packages -e | grep retaildemo"            "retaildemo"
_check "NFC: radio off"                        "settings get global nfc_on"                        "1"

echo ""

# ── SUMMARY ─────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo "  Hardening Summary — $( date -u +"%Y-%m-%dT%H:%M:%SZ" )"
echo "  Actions passed:  $PASS"
echo "  Actions failed:  $FAIL"
echo "  Actions skipped: $SKIP"
echo "  Post-checks OK:  $CHECKS_PASS"
echo "  Post-checks FAIL:$CHECKS_FAIL"
echo ""
echo "  WHAT REMAINS (requires bootloader unlock to fix):"
echo "  - CloudDPC APK still in /product/app — cannot remove"
echo "  - OOBConfig APK still in /product/priv-app — cannot remove"
echo "  - CBRS APK still in /product/priv-app — cannot remove"
echo "  - SLSI RIL hooks still present at modem layer"
echo "  - RKPD still contacts Google on every boot"
echo "  - CBRS SYSTEM_FIXED location perms still in package metadata"
echo "    (cannot be revoked because app is disabled — perms never execute)"
echo ""
echo "  NEXT STEP: Run tegu_watchdog.sh via Termux:Boot to monitor"
echo "  for state reversions after OTA updates."
echo "═══════════════════════════════════════════════════════"
