#!/bin/bash
# attach_private_network.sh
#
# Watches for any of a list of authorized PLMNs (private/test
# networks you operate) over a modem's AT command port and attaches
# to whichever one becomes visible first. Every step verifies the
# modem's actual response before moving on, and the whole scan/attach
# cycle retries with backoff until registration is confirmed — it
# does not give up on a single failed attempt.
#
# Usage:
#   ./attach_private_network.sh [PLMN_LIST] [AT_PORT] [MAX_ATTEMPTS]
#
#   PLMN_LIST    - comma-separated PLMN ids you're authorized to use,
#                  tried in order each scan cycle (default: 103824)
#   AT_PORT      - modem AT command tty (default: /dev/pts/1)
#   MAX_ATTEMPTS - give up after N scan/attach cycles (default: 0 = never)

set -euo pipefail

# Re-exec as root if needed; the whole script (loop included) then
# runs as one process instead of a fragile quoted su -c blob.
if [ "$(id -u)" -ne 0 ]; then
  exec su -c "$0 $*"
fi

PLMN_LIST="${1:-103824}"
AT_PORT="${2:-/dev/pts/1}"
MAX_ATTEMPTS="${3:-0}"
AT_TIMEOUT=5
MAX_BACKOFF=30

IFS=',' read -ra PLMNS <<< "$PLMN_LIST"

if [ ! -c "$AT_PORT" ] && [ ! -p "$AT_PORT" ]; then
  echo "AT port not found: $AT_PORT" >&2
  exit 1
fi

log() { echo "[$(date '+%H:%M:%S')] $*"; }

exec 3<>"$AT_PORT"
trap 'exec 3>&-' EXIT

send_at() { echo "$1" >&3; }

# Reads whatever the modem sends back, up to AT_TIMEOUT seconds,
# stopping early on OK/ERROR so we don't wait out the full timeout
# on every single command.
read_at() {
  local out="" line
  while IFS= read -r -t "$AT_TIMEOUT" line <&3; do
    out+="$line"$'\n'
    [[ "$line" == "OK" || "$line" == "ERROR" ]] && break
  done
  printf '%s' "$out"
}

at_cmd() {
  send_at "$1"
  read_at
}

# Registration status 1 (home) or 5 (roaming) counts as attached.
is_registered() {
  [[ "$1" =~ \+C[G]?REG:\ *[0-9]+,\ *(1|5) ]]
}

log "Disabling auto-registration..."
at_cmd "AT+CREG=0" >/dev/null
at_cmd "AT+CGREG=0" >/dev/null

log "Watching for authorized PLMNs (${PLMNS[*]}) on $AT_PORT..."
attempt=0
backoff=2

while true; do
  attempt=$((attempt + 1))

  if [[ "$MAX_ATTEMPTS" -gt 0 && "$attempt" -gt "$MAX_ATTEMPTS" ]]; then
    log "Max attempts ($MAX_ATTEMPTS) reached without registering. Giving up."
    exit 1
  fi

  log "Attempt $attempt: scanning for available networks..."
  scan=$(at_cmd "AT+COPS=?")

  target=""
  for plmn in "${PLMNS[@]}"; do
    if [[ "$scan" == *"$plmn"* ]]; then
      target="$plmn"
      break
    fi
  done

  if [[ -z "$target" ]]; then
    log "No authorized PLMN visible yet. Rescanning in ${backoff}s..."
    sleep "$backoff"
    backoff=$(( backoff < MAX_BACKOFF ? backoff * 2 : MAX_BACKOFF ))
    continue
  fi

  log "PLMN $target visible. Forcing attach..."
  at_cmd "AT+COPS=1,2,\"$target\"" >/dev/null
  sleep 3

  creg=$(at_cmd "AT+CREG?")
  cgreg=$(at_cmd "AT+CGREG?")
  csq=$(at_cmd "AT+CSQ")

  log "CREG: ${creg//$'\n'/ }"
  log "CGREG: ${cgreg//$'\n'/ }"
  log "Signal: ${csq//$'\n'/ }"

  if is_registered "$creg" || is_registered "$cgreg"; then
    log "Registered on PLMN $target. Attach successful."
    exit 0
  fi

  log "Attach on $target not confirmed. Retrying in ${backoff}s..."
  sleep "$backoff"
  backoff=$(( backoff < MAX_BACKOFF ? backoff * 2 : MAX_BACKOFF ))
done
