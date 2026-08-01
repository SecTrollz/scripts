#!/usr/bin/env bash
set -euo pipefail

# ---------- Flags ----------
DRY_RUN=0
FORCE=0

for arg in "$@"; do
  case "$arg" in
    -n|--dry-run) DRY_RUN=1 ;;
    -f|--force)   FORCE=1 ;;
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

log() { echo "$*"; }
ok() { log "${GREEN}✓${RESET} $*"; }
warn() { log "${YELLOW}⚠${RESET} $*"; }
err() { log "${RED}✗${RESET} $*"; }

# ---------- ADB Check ----------
command -v adb >/dev/null 2>&1 || {
  err "adb not found"
  exit 1
}

adb devices | grep -qE "^[^[:space:]]+\s+device$" || {
  err "No authorized device connected"
  exit 1
}

# ---------- Cache Measurement ----------
raw=$(adb shell "du -s /data/data/*/cache 2>/dev/null" 2>/dev/null || true)

total_kb=$(echo "$raw" | awk '{s+=$1} END {print s+0}')

if [[ "${total_kb:-0}" -eq 0 ]]; then
  ok "Already clean (0 KB cache)"
  exit 0
fi

human_size() {
  local kb=$1
  if (( kb > 1048576 )); then
    echo "$((kb / 1048576)) GB"
  elif (( kb > 1024 )); then
    echo "$((kb / 1024)) MB"
  else
    echo "${kb} KB"
  fi
}

size_hr=$(human_size "$total_kb")

# ---------- Dry Run ----------
if [[ "$DRY_RUN" -eq 1 ]]; then
  log "${BLUE}◇${RESET} Cache reclaimable: ${BOLD}${size_hr}${RESET}"
  exit 0
fi

# ---------- Confirm ----------
if [[ "$FORCE" -eq 0 ]]; then
  warn "About to clean ~${size_hr} cache"
  read -r -p "Continue? (y/N): " reply
  [[ ! "$reply" =~ ^[Yy]$ ]] && { warn "Cancelled"; exit 0; }
fi

# ---------- Cleanup Pipeline ----------
log "Running cleanup..."

adb shell pm trim-caches 999G >/dev/null 2>&1 || true
adb shell cmd package trim-caches 999G >/dev/null 2>&1 || true

# Root attempt (only if actually available)
if adb root >/dev/null 2>&1; then
  sleep 1
  adb shell "rm -rf /data/system/package_cache/*" 2>/dev/null || true
  adb shell "rm -rf /data/cache/*" 2>/dev/null || true
fi

# su cleanup (real check, not blind execution)
if adb shell "command -v su" 2>/dev/null | grep -q "su"; then
  adb shell su -c "rm -rf /data/data/*/cache/* /data/data/*/code_cache/*" 2>/dev/null || true
fi

# External cache (safe)
adb shell "rm -rf /sdcard/Android/data/*/cache" 2>/dev/null || true

# ---------- Verify ----------
new_raw=$(adb shell "du -s /data/data/*/cache 2>/dev/null" 2>/dev/null || true)
new_kb=$(echo "$new_raw" | awk '{s+=$1} END {print s+0}')

freed_kb=$(( total_kb - new_kb ))

freed_hr=$(human_size "$freed_kb")
remaining_hr=$(human_size "$new_kb")

if [[ "${new_kb:-0}" -eq 0 ]]; then
  ok "Freed ${freed_hr} — fully cleared"
else
  ok "Freed ${freed_hr} — ${remaining_hr} remains (system protected)"
fi
