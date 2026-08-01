#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# TEGU KNUCKLER — PERSISTENT BOOT WATCHDOG
# Runs on every boot via Termux:Boot
# Hammers every target before the system settles
# OTA updates cannot outrun this
# ============================================================
# INSTALL:
#   1. pkg install termux-boot
#   2. Open Termux:Boot app once to register it
#   3. mkdir -p ~/.termux/boot
#   4. cp tegu_knuckler.sh ~/.termux/boot/tegu_knuckler.sh
#   5. chmod +x ~/.termux/boot/tegu_knuckler.sh
#   Done. Runs on every boot automatically.
# ============================================================

LOG="/data/data/com.termux/files/home/tegu_knuckler.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

log() {
    echo "[$DATE] $1" | tee -a "$LOG"
}

log "============================================"
log "TEGU KNUCKLER BOOT SEQUENCE INITIATED"
log "============================================"

# Wait for system to be ready
sleep 10

# ============================================================
# ROUND 1 — pm disable-user (confirmed working targets)
# ============================================================

DISABLE_TARGETS=(
    "com.google.android.apps.work.clouddpc"
    "com.google.omadm.trigger"
    "com.google.android.devicelockcontroller"
    "com.google.android.turboadapter"
    "com.google.android.retaildemo"
    "com.google.android.apps.retaildemo.preload"
    "com.google.android.repairmode"
    "com.google.android.federatedcompute"
    "com.google.android.adservices.api"
    "com.google.android.gms.location.history"
    "com.google.android.apps.diagnosticstool"
    "com.google.android.wfcactivation"
    "com.google.android.apps.carrier.log"
    "com.google.android.apps.setupwizard.searchselector"
    "com.android.omadm.service"
    "com.verizon.mips.services"
    "com.verizon.services"
    "com.google.android.gms.supervision"
    "com.google.android.projection.gearhead"
    "com.google.android.apps.restore"
    "com.google.android.glasses.core"
    "com.google.android.apps.pixel.dcservice"
)

log "--- ROUND 1: pm disable-user ---"
for pkg in "${DISABLE_TARGETS[@]}"; do
    result=$(pm disable-user --user 0 "$pkg" 2>&1)
    state=$(pm list packages -d "$pkg" 2>/dev/null)
    if echo "$state" | grep -q "$pkg"; then
        log "  DISABLED: $pkg"
    else
        log "  SKIP/FAIL: $pkg ($result)"
    fi
done

# ============================================================
# ROUND 2 — pm suspend (hits differently, bypasses some
# protections that block pm disable-user)
# This is what gets OOBConfig
# ============================================================

SUSPEND_TARGETS=(
    "com.google.android.apps.work.oobconfig"
    "com.google.android.apps.work.clouddpc"
    "com.google.omadm.trigger"
    "com.google.android.devicelockcontroller"
    "com.google.android.repairmode"
    "com.google.android.turboadapter"
    "com.google.android.carriersetup"
    "com.google.android.partnersetup"
    "com.google.android.apps.carrier.log"
    "com.google.android.gms.supervision"
)

log "--- ROUND 2: pm suspend ---"
for pkg in "${SUSPEND_TARGETS[@]}"; do
    result=$(pm suspend --user 0 "$pkg" 2>&1)
    log "  SUSPEND: $pkg — $result"
done

# ============================================================
# ROUND 3 — force-stop all targets
# ============================================================

FORCESTOP_TARGETS=(
    "com.google.android.apps.work.oobconfig"
    "com.google.android.apps.work.clouddpc"
    "com.google.omadm.trigger"
    "com.google.android.apps.cbrsnetworkmonitor"
    "com.google.android.devicelockcontroller"
    "com.google.android.turboadapter"
    "com.google.android.repairmode"
    "com.google.android.apps.diagnosticstool"
    "com.google.android.carriersetup"
    "com.google.android.partnersetup"
)

log "--- ROUND 3: am force-stop ---"
for pkg in "${FORCESTOP_TARGETS[@]}"; do
    am force-stop "$pkg" 2>&1
    log "  STOPPED: $pkg"
done

# ============================================================
# ROUND 4 — AppOps denials
# These re-apply after every reboot
# ============================================================

log "--- ROUND 4: AppOps denials ---"

appops_deny() {
    cmd appops set "$1" "$2" deny 2>&1
    result=$(cmd appops get "$1" "$2" 2>&1)
    log "  APPOP: $1 / $2 => $result"
}

appops_deny "com.google.android.apps.scone"       "RUN_IN_BACKGROUND"
appops_deny "com.google.android.apps.scone"       "RUN_ANY_IN_BACKGROUND"
appops_deny "com.google.android.apps.scone"       "MONITOR_LOCATION"
appops_deny "com.google.android.apps.scone"       "MONITOR_HIGH_POWER_LOCATION"
appops_deny "com.google.android.gms"              "MONITOR_LOCATION"
appops_deny "com.google.android.gms"              "MONITOR_HIGH_POWER_LOCATION"
appops_deny "com.google.android.apps.work.clouddpc" "MONITOR_LOCATION"
appops_deny "com.google.android.apps.work.clouddpc" "READ_PHONE_STATE"
appops_deny "com.google.android.apps.work.clouddpc" "CAMERA"
appops_deny "com.google.android.apps.work.oobconfig" "READ_PHONE_STATE"
appops_deny "com.google.android.apps.work.oobconfig" "MONITOR_LOCATION"
appops_deny "com.google.android.turboadapter"    "READ_DEVICE_IDENTIFIERS"
appops_deny "com.google.android.partnersetup"    "MONITOR_LOCATION"
appops_deny "com.google.android.partnersetup"    "READ_PHONE_STATE"
appops_deny "com.google.android.carriersetup"    "READ_PHONE_STATE"
appops_deny "com.google.android.carriersetup"    "MONITOR_LOCATION"
appops_deny "com.google.android.repairmode"      "RUN_IN_BACKGROUND"
appops_deny "com.google.android.apps.diagnosticstool" "RUN_IN_BACKGROUND"

# ============================================================
# ROUND 5 — device_config persistent flags
# These write to system-level configuration storage
# Survive reboots natively
# ============================================================

log "--- ROUND 5: device_config flags ---"

# Disable OMA-DM trigger functionality
device_config put telephony omadm_trigger_enabled false 2>&1
log "  FLAG: omadm_trigger_enabled = false"

# Disable CBRS monitoring
device_config put connectivity cbrs_enabled false 2>&1
log "  FLAG: cbrs_enabled = false"

# Disable federated compute
device_config put on_device_personalization federated_compute_kill_switch true 2>&1
log "  FLAG: federated_compute_kill_switch = true"

# Disable ad services measurement
device_config put adservices global_kill_switch true 2>&1
log "  FLAG: adservices global_kill_switch = true"

# Disable ambient streaming
device_config put ambient_streaming enabled false 2>&1
log "  FLAG: ambient_streaming = false"

# Disable repair mode auto-activation
device_config put repair_mode auto_enabled false 2>&1
log "  FLAG: repair_mode auto_enabled = false"

# ============================================================
# ROUND 6 — settings global/secure overrides
# These persist to the settings database
# ============================================================

log "--- ROUND 6: settings overrides ---"

# Disable OEM unlock check
settings put global oem_unlock_allowed_by_carrier 0 2>&1
log "  SETTING: oem_unlock_allowed_by_carrier = 0"

# Disable development over WiFi for non-authorized sessions
settings put global adb_wifi_enabled 0 2>&1
log "  SETTING: adb_wifi_enabled = 0 (re-enable manually when needed)"

# Restrict background data for key packages
settings put global bg_data_restricted_mode 1 2>&1
log "  SETTING: bg_data_restricted_mode = 1"

# ============================================================
# ROUND 7 — INVESTIGATE com.codespaceapps.listeningapp
# This appeared after June 2 — watch it on every boot
# ============================================================

log "--- ROUND 7: LISTENINGAPP WATCHDOG ---"

LISTENING="com.codespaceapps.listeningapp"
listen_check=$(pm list packages "$LISTENING" 2>/dev/null)

if echo "$listen_check" | grep -q "$LISTENING"; then
    log "  WARNING: $LISTENING IS PRESENT"
    # Force stop it
    am force-stop "$LISTENING" 2>&1
    log "  STOPPED: $LISTENING"
    # Disable it
    pm disable-user --user 0 "$LISTENING" 2>&1
    # Revoke all runtime permissions
    for perm in \
        android.permission.RECORD_AUDIO \
        android.permission.ACCESS_FINE_LOCATION \
        android.permission.ACCESS_COARSE_LOCATION \
        android.permission.READ_CONTACTS \
        android.permission.READ_PHONE_STATE \
        android.permission.CAMERA \
        android.permission.READ_CALL_LOG \
        android.permission.PROCESS_OUTGOING_CALLS; do
        pm revoke "$LISTENING" "$perm" 2>/dev/null
        log "  REVOKED: $LISTENING / $perm"
    done
    # Dump its current state to log for evidence
    pm dump "$LISTENING" >> "$LOG" 2>&1
    log "  DUMPED: $LISTENING state saved to log"
else
    log "  OK: $LISTENING not present"
fi

# ============================================================
# ROUND 8 — VERIFY AND REPORT
# ============================================================

log "--- ROUND 8: VERIFICATION ---"

# Count still-enabled targets
still_enabled=0
for pkg in "${DISABLE_TARGETS[@]}"; do
    check=$(pm list packages -e "$pkg" 2>/dev/null)
    if echo "$check" | grep -q "$pkg"; then
        log "  STILL ENABLED: $pkg"
        still_enabled=$((still_enabled + 1))
    fi
done

log "Still-enabled count: $still_enabled"

# Report network request count as a health indicator
net_count=$(dumpsys connectivity 2>/dev/null | grep -c "NetworkRequest" || echo "0")
log "Active network requests: $net_count"

# Report FCM receivers still active
fcm_count=$(dumpsys package 2>/dev/null | grep -c "firebase.MESSAGING_EVENT" || echo "0")
log "FCM receivers active: $fcm_count"

log "============================================"
log "KNUCKLER COMPLETE"
log "============================================"
