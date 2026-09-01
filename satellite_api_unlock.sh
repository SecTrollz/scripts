#!/usr/bin/env bash
set -euo pipefail

# satellite_api_unlock.sh
#
# Android's Satellite framework (android.telephony.satellite.SatelliteManager)
# is gated by CarrierConfigManager flags — KEY_SATELLITE_*, KEY_CARRIER_*SATELLITE*,
# KEY_CARRIER_ROAMING_NTN_* — that a real carrier normally has to provision
# remotely before the APIs light up. The exact key set has grown/changed every
# Android release (14 -> 15 -> 16 -> 17), so hardcoding names here would just
# rot. Instead this script reads them straight off the connected device via
# `dumpsys carrier_config` (the ground truth for *this* build) and only
# touches keys it has just verified exist via `cmd phone cc get-value` —
# never a blind write.
#
# `cmd phone cc set-value` / `clear-values` is AOSP's own documented developer
# override path for carrier config (Telephony's TelephonyShellCommand `cc`
# group) — it's what `shell` identity is granted for local dev/CTS testing,
# no root or bootloader unlock required. It does NOT grant real satellite RF —
# that still needs modem/OEM hardware and a live satellite backend — it only
# removes the config gate so SatelliteManager's APIs and Settings > Satellite
# UI stop short-circuiting to "unsupported" during development/testing.
#
# Modes:
#   (default)      recon only — discover + print current satellite-related
#                  carrier_config keys, cmd phone satellite subcommands, and
#                   device_config telephony flags. No writes.
#   --apply        back up current carrier_config, then set every discovered
#                  satellite *_bool key to true (int/other keys are only
#                  reported, never auto-written).
#   --reset        clear ALL cc test overrides (cmd phone cc clear-values)
#                  and re-dump to confirm.
#   --backup-dir D directory for backups (default: ./satellite_backups)

MODE="recon"
BACKUP_DIR="./satellite_backups"

for arg in "$@"; do
  case "$arg" in
    --apply) MODE="apply" ;;
    --reset) MODE="reset" ;;
    --backup-dir=*) BACKUP_DIR="${arg#*=}" ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
  esac
done

# ---------- Colors ----------
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

dump_carrier_config() {
  adb shell dumpsys carrier_config 2>/dev/null
}

# ---------- Reset mode ----------
if [[ "$MODE" == "reset" ]]; then
  before_file="${BACKUP_DIR}/carrier_config_before_reset_${ts}.txt"
  dump_carrier_config > "$before_file"
  info "Pre-reset snapshot: $before_file"

  if adb shell cmd phone cc clear-values >/tmp/cc_reset_out 2>&1; then
    ok "Cleared all carrier_config test overrides (cmd phone cc clear-values)"
  else
    err "clear-values failed:"
    cat /tmp/cc_reset_out
    exit 1
  fi

  after_file="${BACKUP_DIR}/carrier_config_after_reset_${ts}.txt"
  dump_carrier_config > "$after_file"
  diff "$before_file" "$after_file" | grep -i satellite || info "No satellite-key diff (already clean or never overridden)"
  exit 0
fi

# ---------- Recon ----------
info "Discovering satellite-related carrier_config keys on this device..."
cc_dump="$(dump_carrier_config)"

# Lines look like: "  KEY_SATELLITE_ATTACH_SUPPORTED_BOOL = true"
mapfile -t sat_keys < <(echo "$cc_dump" | grep -oE '\bKEY_[A-Z0-9_]*SATELLITE[A-Z0-9_]*' | sort -u)

if [[ "${#sat_keys[@]}" -eq 0 ]]; then
  warn "No KEY_*SATELLITE* entries found in dumpsys carrier_config for this build/SIM state."
  warn "Some OEMs only populate these once a SIM with any carrier profile is present."
else
  ok "Found ${#sat_keys[@]} satellite-related carrier_config key(s):"
  for k in "${sat_keys[@]}"; do
    val=$(echo "$cc_dump" | grep -E "^\s*${k}\s*=" | head -n1 | sed -E 's/^\s*[A-Z0-9_]+\s*=\s*//')
    printf '    %-70s %s\n' "$k" "${val:-<unset>}"
  done
fi

info "Discovering 'cmd phone' satellite subcommands..."
sat_cmds="$(adb shell cmd phone help 2>&1 | grep -i satellite || true)"
if [[ -n "$sat_cmds" ]]; then
  echo "$sat_cmds" | sed 's/^/    /'
else
  info "No dedicated satellite subcommands surfaced in 'cmd phone help' on this build."
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
  info "Recon only — re-run with --apply to enable the discovered *_bool keys."
  exit 0
fi

# ---------- Apply mode ----------
if [[ "${#sat_keys[@]}" -eq 0 ]]; then
  err "Nothing discovered to apply. Insert a SIM (even an inactive one) and re-run recon first."
  exit 1
fi

backup_file="${BACKUP_DIR}/carrier_config_before_${ts}.txt"
echo "$cc_dump" > "$backup_file"
ok "Backed up current carrier_config to $backup_file (restore anytime with --reset)"

applied=0
skipped=0
for k in "${sat_keys[@]}"; do
  if [[ "$k" != *_BOOL ]]; then
    warn "Skipping non-boolean key (review manually): $k"
    ((skipped++)) || true
    continue
  fi

  # Verify the key is actually recognized by this build before writing it.
  if ! adb shell cmd phone cc get-value -k "$k" >/tmp/cc_probe 2>&1; then
    warn "Skipping $k — device rejected get-value (not a real key on this build)"
    ((skipped++)) || true
    continue
  fi

  if adb shell cmd phone cc set-value -k "$k" -v true >/tmp/cc_set_out 2>&1; then
    ok "Set $k = true"
    ((applied++)) || true
  else
    warn "Failed to set $k:"
    cat /tmp/cc_set_out | sed 's/^/    /'
    ((skipped++)) || true
  fi
done

echo
new_dump="$(dump_carrier_config)"
after_file="${BACKUP_DIR}/carrier_config_after_${ts}.txt"
echo "$new_dump" > "$after_file"

ok "Applied ${applied} key(s), skipped ${skipped}. Snapshot: $after_file"
info "Diff:"
diff "$backup_file" "$after_file" | grep -i satellite | sed 's/^/    /' || true
info "Revert anytime with: $0 --reset"
