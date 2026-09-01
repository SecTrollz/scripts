#!/usr/bin/env bash
set -euo pipefail

# satellite_api_unlock.sh
#
# Android's Satellite framework (android.telephony.satellite.SatelliteManager)
# is gated in two different ways depending on the build:
#
#   - Older-style: CarrierConfigManager KEY_*SATELLITE*_BOOL flags that a real
#     carrier normally has to provision remotely.
#   - Newer-style (confirmed on a real Pixel 9a / Android 17 / SDK 37): the
#     aconfig feature flags (device_config telephony oem_enabled_satellite_flag
#     etc.) are already compiled in and enabled, but the device's runtime
#     "OEM-enabled satellite provision status" is a separate bit, normally set
#     by an OEM provisioning app/flow — not by CarrierConfigManager at all.
#     TelephonyShellCommand exposes it directly for local dev/CTS testing:
#     `cmd phone set-oem-enabled-satellite-provision-status -p true/false`.
#
# The exact surface has grown/changed every Android release (14 -> 15 -> 16 ->
# 17), so hardcoding one mechanism would rot. This script discovers both live
# off the connected device instead of assuming which one applies:
#   - carrier_config keys are read from `dumpsys carrier_config` and verified
#     via `cmd phone cc get-value` before ever being written.
#   - the OEM provision-status lever is discovered by parsing `cmd phone help`
#     for the `set-oem-enabled-satellite-provision-status` subcommand — it's
#     only used if the connected build actually advertises it.
#
# `cmd phone cc set-value/clear-values` and `cmd phone set-oem-enabled-
# satellite-provision-status` are AOSP's own documented shell-level dev-
# override paths (TelephonyShellCommand) — what `shell` identity is granted
# for local dev/CTS testing, no root or bootloader unlock required. Neither
# grants real satellite RF — that still needs modem/OEM hardware and a live
# satellite backend — they only remove the software gate so SatelliteManager's
# APIs and Settings > Satellite UI stop short-circuiting to "unsupported"
# during development/testing.
#
# Modes:
#   (default)      recon only — discover + print current satellite-related
#                  carrier_config keys, cmd phone satellite subcommands
#                  (flagging the OEM provision-status lever if present), and
#                  device_config telephony flags. No writes.
#   --apply        back up current state, then set every discovered carrier
#                  config satellite *_bool key to true, AND, if the build
#                  advertises it, set OEM-enabled satellite provision status
#                  to true. Non-boolean carrier_config keys are only reported,
#                  never auto-written.
#   --reset        clear ALL cc test overrides (cmd phone cc clear-values)
#                  and clear the OEM provision-status override (if present),
#                  then re-dump to confirm.
#   --backup-dir D directory for backups (default: ./satellite_backups)

show_help() {
  cat <<'EOF'
satellite_api_unlock.sh

Discovers and unlocks Android's SatelliteManager developer APIs on a
connected device, using whichever gating mechanism that build actually
exposes rather than a hardcoded one:

  - CarrierConfigManager KEY_*SATELLITE*_BOOL flags (older-style), read from
    dumpsys carrier_config and verified via `cmd phone cc get-value` before
    any write.
  - OEM-enabled satellite provision status (confirmed on Android 17 / SDK 37),
    set via `cmd phone set-oem-enabled-satellite-provision-status`, only used
    if `cmd phone help` on the connected device actually advertises it.

Does NOT grant real satellite RF — that still needs modem/OEM hardware and a
live satellite backend. It only removes the software gate for testing.

Modes:
  (default)      recon only — discover and print current state. No writes.
  --apply        back up current state, then enable every lever discovered.
  --reset        revert every override this script can make (cc clear-values
                 plus clearing the OEM provision-status override).
  --backup-dir D directory for backups (default: ./satellite_backups)
EOF
}

MODE="recon"
BACKUP_DIR="./satellite_backups"

for arg in "$@"; do
  case "$arg" in
    --apply) MODE="apply" ;;
    --reset) MODE="reset" ;;
    --backup-dir=*) BACKUP_DIR="${arg#*=}" ;;
    -h|--help) show_help; exit 0 ;;
  esac
done

# ---------- Colors ----------
GREEN="" BLUE="" YELLOW="" RED="" BOLD="" RESET=""
if [ -t 1 ]; then
  GREEN=$(tput setaf 2 2>/dev/null || true)
  BLUE=$(tput setaf 4 2>/dev/null || true)
  YELLOW=$(tput setaf 3 2>/dev/null || true)
  RED=$(tput setaf 1 2>/dev/null || true)
  BOLD=$(tput bold 2>/dev/null || true)
  RESET=$(tput sgr0 2>/dev/null || true)
fi

log()  { echo "$*"; }
ok()   { log "${GREEN}✓${RESET} $*"; }
info() { log "${BLUE}◇${RESET} $*"; }
warn() { log "${YELLOW}⚠${RESET} $*"; }
err()  { log "${RED}✗${RESET} $*"; }

# ---------- ADB Check ----------
command -v adb >/dev/null 2>&1 || { err "adb not found"; exit 1; }

adb devices | grep -qE "^[^[:space:]]+\s+device$" || {
  err "No authorized device connected"
  exit 1
}

sdk=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
release=$(adb shell getprop ro.build.version.release | tr -d '\r')
model=$(adb shell getprop ro.product.model | tr -d '\r')
info "Device: ${BOLD}${model}${RESET}  Android ${release} (SDK ${sdk})"

mkdir -p "$BACKUP_DIR"
ts=$(date +%Y%m%d_%H%M%S)

# Scratch files live under BACKUP_DIR rather than /tmp: on Termux (a common
# host for this script) the real /tmp is not guaranteed writable, while
# BACKUP_DIR was just proven writable above.
SCRATCH_DIR="${BACKUP_DIR}/.scratch"
mkdir -p "$SCRATCH_DIR"
trap 'rm -rf "$SCRATCH_DIR"' EXIT
scratch() { mktemp "${SCRATCH_DIR}/$1.XXXXXX"; }

dump_carrier_config() {
  adb shell dumpsys carrier_config 2>/dev/null
}

dump_satellite_state() {
  {
    adb shell dumpsys telephony.registry 2>/dev/null | grep -i satellite
    adb shell dumpsys isub 2>/dev/null | grep -i satellite
  } 2>/dev/null || true
}

phone_help="$(adb shell cmd phone help 2>&1 || true)"
has_oem_provision_cmd=0
if echo "$phone_help" | grep -q 'set-oem-enabled-satellite-provision-status'; then
  has_oem_provision_cmd=1
fi

# ---------- Reset mode ----------
if [[ "$MODE" == "reset" ]]; then
  before_cc="${BACKUP_DIR}/carrier_config_before_reset_${ts}.txt"
  before_state="${BACKUP_DIR}/satellite_state_before_reset_${ts}.txt"
  dump_carrier_config > "$before_cc"
  dump_satellite_state > "$before_state"
  info "Pre-reset snapshots: $before_cc, $before_state"

  cc_reset_out="$(scratch cc_reset_out)"
  if adb shell cmd phone cc clear-values >"$cc_reset_out" 2>&1; then
    ok "Cleared all carrier_config test overrides (cmd phone cc clear-values)"
  else
    err "clear-values failed:"
    cat "$cc_reset_out"
    exit 1
  fi

  if [[ "$has_oem_provision_cmd" -eq 1 ]]; then
    oem_reset_out="$(scratch oem_reset_out)"
    if adb shell cmd phone set-oem-enabled-satellite-provision-status >"$oem_reset_out" 2>&1; then
      ok "Cleared OEM-enabled satellite provision-status override"
    else
      warn "Could not clear provision-status override (may not support no-arg clear on this build):"
      cat "$oem_reset_out" | sed 's/^/    /'
    fi
  fi

  after_cc="${BACKUP_DIR}/carrier_config_after_reset_${ts}.txt"
  after_state="${BACKUP_DIR}/satellite_state_after_reset_${ts}.txt"
  dump_carrier_config > "$after_cc"
  dump_satellite_state > "$after_state"

  diff "$before_cc" "$after_cc" | grep -i satellite || info "No carrier_config satellite-key diff"
  diff "$before_state" "$after_state" || info "No satellite-state diff"
  exit 0
fi

# ---------- Recon ----------
info "Discovering satellite-related carrier_config keys on this device..."
cc_dump="$(dump_carrier_config)"

# Lines look like: "  KEY_SATELLITE_ATTACH_SUPPORTED_BOOL = true"
mapfile -t sat_keys < <(echo "$cc_dump" | grep -oE '\bKEY_[A-Z0-9_]*SATELLITE[A-Z0-9_]*' | sort -u)

if [[ "${#sat_keys[@]}" -eq 0 ]]; then
  info "No KEY_*SATELLITE* entries in dumpsys carrier_config (expected on newer builds — see below)."
else
  ok "Found ${#sat_keys[@]} satellite-related carrier_config key(s):"
  for k in "${sat_keys[@]}"; do
    val=$(echo "$cc_dump" | grep -E "^\s*${k}\s*=" | head -n1 | sed -E 's/^\s*[A-Z0-9_]+\s*=\s*//')
    printf '    %-70s %s\n' "$k" "${val:-<unset>}"
  done
fi

info "Discovering 'cmd phone' satellite subcommands..."
sat_cmds="$(echo "$phone_help" | grep -i satellite || true)"
if [[ -n "$sat_cmds" ]]; then
  echo "$sat_cmds" | sed 's/^/    /'
else
  info "No dedicated satellite subcommands surfaced in 'cmd phone help' on this build."
fi

if [[ "$has_oem_provision_cmd" -eq 1 ]]; then
  ok "Primary lever available: cmd phone set-oem-enabled-satellite-provision-status"
fi

info "Checking device_config telephony namespace for satellite flags..."
dc_sat="$(adb shell device_config list telephony 2>/dev/null | grep -i satellite || true)"
if [[ -n "$dc_sat" ]]; then
  echo "$dc_sat" | sed 's/^/    /'
else
  info "None found in the telephony namespace."
fi

if [[ "$MODE" == "recon" ]]; then
  echo
  info "Recon only — re-run with --apply to enable the levers discovered above."
  exit 0
fi

# ---------- Apply mode ----------
if [[ "${#sat_keys[@]}" -eq 0 && "$has_oem_provision_cmd" -eq 0 ]]; then
  err "Nothing discovered to apply — no carrier_config *SATELLITE* keys and no"
  err "set-oem-enabled-satellite-provision-status subcommand on this build."
  exit 1
fi

backup_cc="${BACKUP_DIR}/carrier_config_before_${ts}.txt"
backup_state="${BACKUP_DIR}/satellite_state_before_${ts}.txt"
echo "$cc_dump" > "$backup_cc"
dump_satellite_state > "$backup_state"
ok "Backed up current state to $backup_cc / $backup_state (restore anytime with --reset)"

applied=0
skipped=0

for k in "${sat_keys[@]}"; do
  if [[ "$k" != *_BOOL ]]; then
    warn "Skipping non-boolean key (review manually): $k"
    ((skipped++)) || true
    continue
  fi

  # Verify the key is actually recognized by this build before writing it.
  cc_probe="$(scratch cc_probe)"
  if ! adb shell cmd phone cc get-value -k "$k" >"$cc_probe" 2>&1; then
    warn "Skipping $k — device rejected get-value (not a real key on this build)"
    ((skipped++)) || true
    continue
  fi

  cc_set_out="$(scratch cc_set_out)"
  if adb shell cmd phone cc set-value -k "$k" -v true >"$cc_set_out" 2>&1; then
    ok "Set $k = true"
    ((applied++)) || true
  else
    warn "Failed to set $k:"
    cat "$cc_set_out" | sed 's/^/    /'
    ((skipped++)) || true
  fi
done

if [[ "$has_oem_provision_cmd" -eq 1 ]]; then
  oem_set_out="$(scratch oem_set_out)"
  if adb shell cmd phone set-oem-enabled-satellite-provision-status -p true >"$oem_set_out" 2>&1; then
    ok "Set OEM-enabled satellite provision status = true"
    ((applied++)) || true
  else
    warn "Failed to set OEM provision status:"
    cat "$oem_set_out" | sed 's/^/    /'
    ((skipped++)) || true
  fi
fi

echo
new_cc="$(dump_carrier_config)"
after_cc="${BACKUP_DIR}/carrier_config_after_${ts}.txt"
after_state="${BACKUP_DIR}/satellite_state_after_${ts}.txt"
echo "$new_cc" > "$after_cc"
dump_satellite_state > "$after_state"

ok "Applied ${applied} lever(s), skipped ${skipped}. Snapshots: $after_cc, $after_state"
info "carrier_config diff:"
diff "$backup_cc" "$after_cc" | grep -i satellite | sed 's/^/    /' || true
info "satellite-state diff:"
diff "$backup_state" "$after_state" | sed 's/^/    /' || true
info "Revert anytime with: $0 --reset"
