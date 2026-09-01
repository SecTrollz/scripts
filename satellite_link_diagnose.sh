#!/usr/bin/env bash
set -euo pipefail

# satellite_link_diagnose.sh
#
# satellite_api_unlock.sh flips the OEM-enabled satellite provision-status
# software gate so SatelliteManager's APIs and the Settings > Satellite UI
# stop hard-refusing with "unsupported". That gate is real, but it is only
# one of several independent layers a real satellite link needs:
#
#   1. Modem/RF hardware — a satellite-capable radio path actually has to
#      exist on this specific SKU. No shell command can add a radio that
#      isn't there.
#   2. The software gate (provision status) — what satellite_api_unlock.sh
#      touches.
#   3. Geofence / service area — real P2P satellite sessions are restricted
#      to wherever the satellite provider is actually licensed to operate
#      (an S2-cell geometry file + country-code list), independent of the
#      provision-status bit.
#   4. Physical requirements — clear sky view, a satellite actually
#      overhead, and (for anything beyond basic SOS) a carrier plan that
#      includes satellite service.
#
# None of (1), (3), or (4) can be produced by software. This script's job is
# to tell you, empirically, how far down that list this device actually
# gets — rather than continuing to chase further shell tricks against a
# radio that may not exist on this build at all. It only reads state; it
# makes no changes.

show_help() {
  cat <<'EOF'
satellite_link_diagnose.sh

Checks, in order, how far this connected device actually gets toward a real
satellite link:

  1. Modem/HAL hardware — is a satellite radio service even registered with
     the system (service list / dumpsys -l / vendor properties)? If not, no
     software change of any kind will produce RF connectivity on this SKU.
  2. Software gate — is OEM-enabled satellite provision status currently on
     (what satellite_api_unlock.sh --apply sets)?
  3. Geofence / service-area config — is there any S2-cell/country-code
     access-control config present on this build at all?
  4. Related system packages — any satellite-branded packages/activities
     you can launch directly to drive the real UI instead of guessing.

Prints a plain-language verdict at the end. Read-only — makes no changes.
EOF
}

for arg in "$@"; do
  case "$arg" in
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
echo

# ---------- 1. HAL / hardware ----------
info "1. Checking for a registered satellite radio service (hardware path)..."

svc_list="$(adb shell service list 2>/dev/null | grep -i satellite || true)"
dumpsys_list="$(adb shell dumpsys -l 2>/dev/null | grep -i satellite || true)"
vendor_props="$(adb shell getprop 2>/dev/null | grep -i satellite || true)"

hw_signal=0
if [[ -n "$svc_list" ]]; then
  ok "Found in 'service list':"
  echo "$svc_list" | sed 's/^/    /'
  hw_signal=1
fi
if [[ -n "$dumpsys_list" ]]; then
  ok "Found in 'dumpsys -l' (registered system services):"
  echo "$dumpsys_list" | sed 's/^/    /'
  hw_signal=1
fi
if [[ -n "$vendor_props" ]]; then
  ok "Found vendor/system properties:"
  echo "$vendor_props" | sed 's/^/    /'
  hw_signal=1
fi
if [[ "$hw_signal" -eq 0 ]]; then
  warn "No satellite-named service or property found. This is not 100%"
  warn "conclusive (some stacks route through generic RIL commands instead"
  warn "of a dedicated named service), but it's the strongest signal"
  warn "available from userspace that no vendor satellite radio path exists"
  warn "on this build."
fi
echo

# ---------- 2. Software gate ----------
info "2. Checking current satellite framework state (software gate)..."
state_dump="$( { adb shell dumpsys telephony.registry 2>/dev/null | grep -i satellite; adb shell dumpsys isub 2>/dev/null | grep -i satellite; } 2>/dev/null || true)"
if [[ -n "$state_dump" ]]; then
  echo "$state_dump" | sed 's/^/    /'
else
  info "No satellite state currently reported by telephony.registry/isub."
  info "(Run satellite_api_unlock.sh recon/--apply first if you haven't.)"
fi
echo

# ---------- 3. Geofence / service area ----------
info "3. Checking for geofence / service-area access-control config..."
geofence_help="$(adb shell cmd phone help 2>&1 | grep -i -A3 'access-control-overlay' || true)"
if [[ -n "$geofence_help" ]]; then
  ok "Device exposes a geofence override command:"
  echo "$geofence_help" | sed 's/^/    /'
  info "This only lets you point at an S2 geometry file/country-code list —"
  info "it doesn't create real coverage data. Actual service-area data comes"
  info "from the carrier/OEM, not from this device."
else
  info "No geofence override command surfaced on this build."
fi
echo

# ---------- 4. Related packages ----------
info "4. Looking for satellite-related system packages to launch directly..."
sat_pkgs="$(adb shell pm list packages 2>/dev/null | grep -iE 'satellite|starlink|skylo|ntn' || true)"
if [[ -n "$sat_pkgs" ]]; then
  ok "Found:"
  echo "$sat_pkgs" | sed 's/^/    /'
else
  info "No obviously satellite-branded packages found by name."
fi

info "Attempting to open the Settings satellite page directly (best-effort)..."
if adb shell am start -a android.settings.SATELLITE_SETTING >/dev/null 2>&1; then
  ok "Launched — check the device screen."
else
  info "That intent didn't resolve on this build; navigate Settings manually if it exists."
fi
echo

# ---------- Verdict ----------
info "---------------------------------------------------------------"
if [[ "$hw_signal" -eq 0 ]]; then
  err "VERDICT: no evidence of a satellite radio path on this device."
  err "The provision-status flip removes a software refusal, but there is"
  err "nothing found to actually carry the signal. Further shell tricks are"
  err "very unlikely to produce a real link on this specific unit — that's a"
  err "hardware/SKU question, not a config one."
else
  ok "VERDICT: hardware path found — a real link is at least physically"
  ok "possible on this unit. What's still required, and out of adb's reach:"
  ok "  - clear sky view with an actual satellite overhead in your area,"
  ok "  - your carrier's satellite service actually covering your location,"
  ok "  - a plan/entitlement that includes it."
  ok "None of that can be produced from a shell — it's a coverage-map and"
  ok "billing-plan question at this point, not a software one."
fi
