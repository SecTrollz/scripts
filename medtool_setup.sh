#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  GOLDEN MASTER STUDIO — setup.sh
#  One installer for medtool_web.py (v4.0) on a Pixel 9a.
#
#  It detects where it is running and installs the right things:
#    • Termux            → ffmpeg, yt-dlp, python, Flask, Pillow, whisper
#                          (fast lane: download + master + video + slow-tape)
#    • Debian AVF VM     → everything above PLUS torch + Demucs + rubberband
#                          (the heavy lane: AI stem separation, pitch-safe slow)
#    • Generic Linux     → treated like the Debian lane
#
#  Nothing here is destructive. Re-running only fills gaps. Every step is
#  optional-aware: if a component can't install, the app still runs and
#  just greys out that feature.
#
#  Usage:
#    bash setup.sh                 # install for the current environment
#    bash setup.sh --run           # install, then launch the server
#    bash setup.sh --heavy         # also install torch+demucs (VM/Linux only)
#    bash setup.sh --minimal       # skip pillow/whisper/demucs (core only)
#    bash setup.sh --no-color
# ═══════════════════════════════════════════════════════════════════

set -u  # unset vars are errors; we deliberately do NOT set -e so one
        # failed optional dep never aborts the whole install.

# ── Args ───────────────────────────────────────────────────────────
DO_RUN=0
WANT_HEAVY=0
MINIMAL=0
USE_COLOR=1
for a in "$@"; do
  case "$a" in
    --run)      DO_RUN=1 ;;
    --heavy)    WANT_HEAVY=1 ;;
    --minimal)  MINIMAL=1 ;;
    --no-color) USE_COLOR=0 ;;
    -h|--help)
      grep '^#' "$0" | grep -v '^#!' | sed 's/^# \{0,1\}//' | head -n 27
      exit 0 ;;
    *) echo "Unknown arg: $a (try --help)"; exit 2 ;;
  esac
done

# ── Colors / logging ───────────────────────────────────────────────
if [ "$USE_COLOR" = 1 ] && [ -t 1 ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
  GRN=$'\033[32m'; YLW=$'\033[33m'; RED=$'\033[31m'; CYN=$'\033[36m'; MAG=$'\033[35m'
else
  B=""; DIM=""; R=""; GRN=""; YLW=""; RED=""; CYN=""; MAG=""
fi
say()  { printf "%s\n" "$*"; }
step() { printf "\n${B}${MAG}▶ %s${R}\n" "$*"; }
ok()   { printf "  ${GRN}✓${R} %s\n" "$*"; }
warn() { printf "  ${YLW}⚠${R} %s\n" "$*"; }
err()  { printf "  ${RED}✗${R} %s\n" "$*"; }
info() { printf "  ${DIM}%s${R}\n" "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }
pyhas() { python3 -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('$1') else 1)" 2>/dev/null; }

# ── Locate the app file (script lives next to it, ideally) ─────────
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
APP=""
for cand in "$SCRIPT_DIR/medtool_web.py" "./medtool_web.py" "$HOME/medtool_web.py"; do
  [ -f "$cand" ] && { APP="$cand"; break; }
done

# ── Environment detection ──────────────────────────────────────────
ENVIRON="linux"
PKG=""; PKG_INSTALL=""; PKG_UPDATE=""; SUDO=""

if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux/files/usr" ]; then
  ENVIRON="termux"
  PKG="pkg"
  PKG_UPDATE="pkg update -y"
  PKG_INSTALL="pkg install -y"
elif have apt-get; then
  ENVIRON="debian"
  PKG="apt-get"
  have sudo && [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  PKG_UPDATE="$SUDO apt-get update -y"
  PKG_INSTALL="$SUDO apt-get install -y"
elif have pacman; then
  ENVIRON="arch"
  have sudo && [ "$(id -u)" -ne 0 ] && SUDO="sudo"
  PKG_UPDATE="$SUDO pacman -Sy"
  PKG_INSTALL="$SUDO pacman -S --noconfirm"
fi

# Heavy lane (torch/demucs) is only sane off Termux.
HEAVY_OK=0
if [ "$ENVIRON" != "termux" ]; then HEAVY_OK=1; fi
if [ "$WANT_HEAVY" = 1 ] && [ "$ENVIRON" = "termux" ]; then
  WANT_HEAVY=0
  TERMUX_HEAVY_REQUESTED=1
fi
# On the VM/Linux, install heavy by default unless --minimal.
if [ "$HEAVY_OK" = 1 ] && [ "$MINIMAL" = 0 ]; then WANT_HEAVY=1; fi

PIP_BREAK=""
[ "$ENVIRON" = "termux" ] || PIP_BREAK="--break-system-packages"

# ── Banner ─────────────────────────────────────────────────────────
say ""
say "${B}${CYN}  ╔══════════════════════════════════════════════╗${R}"
say "${B}${CYN}  ║   GOLDEN MASTER STUDIO · setup                ║${R}"
say "${B}${CYN}  ║   Garbage Noise · Meditation With Attitude    ║${R}"
say "${B}${CYN}  ╚══════════════════════════════════════════════╝${R}"
say ""
info "environment : ${ENVIRON}"
info "app file    : ${APP:-<not found — will still install deps>}"
info "heavy lane  : $([ "$WANT_HEAVY" = 1 ] && echo 'yes (torch + demucs)' || echo 'no')"
[ "${TERMUX_HEAVY_REQUESTED:-0}" = 1 ] && \
  warn "--heavy ignored on Termux: torch has no working aarch64 Termux wheel. Run the heavy lane inside your Debian VM instead (instructions at the end)."

# ═══════════════════════════════════════════════════════════════════
#  1. System packages
# ═══════════════════════════════════════════════════════════════════
step "System packages"

if [ -z "$PKG_INSTALL" ]; then
  warn "No known package manager detected; skipping system packages."
  warn "Make sure these exist on PATH: python3, pip, ffmpeg, ffprobe, yt-dlp"
else
  info "updating package index ..."
  eval "$PKG_UPDATE" >/dev/null 2>&1 || warn "package index update had warnings (continuing)"

  # Base packages differ slightly per environment.
  case "$ENVIRON" in
    termux)
      BASE_PKGS="python ffmpeg"
      # yt-dlp is packaged in Termux; fall back to pip if missing.
      ;;
    debian)
      # ffmpeg on Debian includes rubberband + all FX filters we use.
      BASE_PKGS="python3 python3-pip python3-venv ffmpeg"
      ;;
    arch)
      BASE_PKGS="python python-pip ffmpeg rubberband"
      ;;
    *)
      BASE_PKGS="python3 ffmpeg"
      ;;
  esac

  for p in $BASE_PKGS; do
    if eval "$PKG_INSTALL $p" >/dev/null 2>&1; then
      ok "$p"
    else
      warn "could not install '$p' via $PKG (may already be present)"
    fi
  done
fi

# Verify the non-negotiables.
step "Verifying core tools"
CORE_OK=1
for bin in python3 ffmpeg ffprobe; do
  if have "$bin"; then ok "$bin — $("$bin" -version 2>/dev/null | head -n1 | cut -c1-48)"
  else err "$bin missing"; CORE_OK=0; fi
done
if have pip3 || python3 -m pip --version >/dev/null 2>&1; then
  ok "pip"
else
  warn "pip not found — trying ensurepip"
  python3 -m ensurepip --upgrade >/dev/null 2>&1 && ok "pip bootstrapped" || err "pip unavailable"
fi

# rubberband: confirm it made it into ffmpeg's filter list (pitch-safe slow)
if ffmpeg -hide_banner -filters 2>/dev/null | grep -q ' rubberband '; then
  ok "ffmpeg has rubberband (pitch-preserving slow)"
else
  warn "ffmpeg lacks rubberband — tempo-slow will fall back to atempo (still pitch-safe, slightly lower quality). Tape-slow unaffected."
fi

# ═══════════════════════════════════════════════════════════════════
#  2. Python deps — core
# ═══════════════════════════════════════════════════════════════════
step "Python — core (Flask, yt-dlp)"

pip_install() {
  # $1 = pip name, $2 = import name (optional), rest = extra pip args
  local name="$1"; shift
  local imp="${1:-}"; [ -n "$imp" ] && shift || true
  if [ -n "$imp" ] && pyhas "$imp"; then ok "$name (already present)"; return 0; fi
  if python3 -m pip install -U $PIP_BREAK "$@" "$name" >/dev/null 2>&1; then
    ok "$name"
  else
    warn "failed to install $name"
    return 1
  fi
}

pip_install flask flask
# yt-dlp: prefer system binary; pip as fallback / to get latest.
if have yt-dlp; then ok "yt-dlp (system binary)"; else pip_install yt-dlp yt_dlp; fi

# ═══════════════════════════════════════════════════════════════════
#  3. Python deps — media/creator (optional, graceful)
# ═══════════════════════════════════════════════════════════════════
if [ "$MINIMAL" = 1 ]; then
  step "Python — optional (skipped: --minimal)"
  info "logo, thumbnail, breathing pacer, and word-captions will be greyed out."
else
  step "Python — creator pack (Pillow) + captions (faster-whisper)"
  pip_install pillow PIL
  # faster-whisper is CPU-friendly (ctranslate2). Heavy-ish but no torch needed.
  pip_install faster-whisper faster_whisper
fi

# ═══════════════════════════════════════════════════════════════════
#  4. Heavy lane — torch + Demucs (VM / Linux only)
# ═══════════════════════════════════════════════════════════════════
if [ "$WANT_HEAVY" = 1 ]; then
  step "AI stem separation — PyTorch + Demucs (heavy)"
  info "this pulls a few hundred MB; first Demucs run downloads the model too."

  if pyhas torch; then
    ok "torch (already present)"
  else
    info "installing CPU torch (aarch64) ..."
    # CPU wheels; if a CUDA box, torch will still detect the GPU at runtime.
    if python3 -m pip install -U $PIP_BREAK torch >/dev/null 2>&1; then
      ok "torch"
    else
      warn "default torch wheel failed — trying the CPU index"
      python3 -m pip install -U $PIP_BREAK torch \
        --index-url https://download.pytorch.org/whl/cpu >/dev/null 2>&1 \
        && ok "torch (cpu index)" \
        || err "torch install failed — Demucs will stay disabled. See notes below."
    fi
  fi

  if pyhas torch; then
    if have demucs || pyhas demucs; then
      ok "demucs (already present)"
    else
      python3 -m pip install -U $PIP_BREAK demucs >/dev/null 2>&1 \
        && ok "demucs" \
        || err "demucs install failed"
    fi
    # rubberband CLI (used by demucs augmentation on some builds) — harmless if absent
    if [ -n "$PKG_INSTALL" ] && ! have rubberband; then
      case "$ENVIRON" in
        debian) eval "$PKG_INSTALL rubberband-cli" >/dev/null 2>&1 && ok "rubberband-cli" || true ;;
        arch)   eval "$PKG_INSTALL rubberband" >/dev/null 2>&1 || true ;;
      esac
    fi
  fi
fi

# ═══════════════════════════════════════════════════════════════════
#  5. Directories + Termux storage
# ═══════════════════════════════════════════════════════════════════
step "Workspace"
mkdir -p "$HOME/.medtool/tmp" "$HOME/.medtool/assets" 2>/dev/null \
  && ok "config dir: ~/.medtool" || warn "could not create ~/.medtool"

if [ "$ENVIRON" = "termux" ]; then
  if [ ! -d "$HOME/storage" ]; then
    info "requesting Termux storage access (approve the Android prompt) ..."
    termux-setup-storage 2>/dev/null || warn "termux-setup-storage unavailable"
  fi
  if [ -d "$HOME/storage/downloads" ]; then
    mkdir -p "$HOME/storage/downloads/MedTool" 2>/dev/null \
      && ok "output dir: ~/storage/downloads/MedTool" \
      || warn "could not create output dir"
  else
    warn "shared storage not linked yet — the app will still write to ~/.medtool; set an Output directory in Settings once storage is granted."
  fi
fi

# Optional: adopt a cursive font if the user dropped one in ~/.medtool/assets
if ls "$HOME/.medtool/assets/"*.ttf "$HOME/.medtool/assets/"*.otf >/dev/null 2>&1; then
  ok "custom cursive font detected in ~/.medtool/assets (will be used for logos/captions)"
else
  info "tip: drop a cursive .ttf (e.g. DancingScript) into ~/.medtool/assets for on-brand text."
fi

# ═══════════════════════════════════════════════════════════════════
#  6. Capability summary (asks the app what it sees)
# ═══════════════════════════════════════════════════════════════════
step "Capability check"
capline() { # name, condition-cmd
  if eval "$2" >/dev/null 2>&1; then ok "$1"; else warn "$1 — disabled (feature greys out)"; fi
}
capline "download (yt-dlp)"        "have yt-dlp || pyhas yt_dlp"
capline "master + FX + loops"      "have ffmpeg"
capline "tape slow"                "have ffmpeg"
capline "pitch-safe slow"          "ffmpeg -hide_banner -filters 2>/dev/null | grep -q ' rubberband '"
capline "video render"             "have ffmpeg"
capline "logo + thumbnail (Pillow)" "pyhas PIL"
capline "breathing pacer (Pillow)" "pyhas PIL"
capline "word captions (whisper)"  "pyhas faster_whisper"
capline "stem separation (Demucs)" "have demucs || pyhas demucs"

# ═══════════════════════════════════════════════════════════════════
#  7. Next steps / launch
# ═══════════════════════════════════════════════════════════════════
step "Done"

if [ "$ENVIRON" = "termux" ] && ! { have demucs || pyhas demucs; }; then
  say ""
  say "${B}${YLW}  Stem separation (Demucs) needs the Debian VM.${R}"
  say "  Torch has no working Termux/aarch64 wheel, so run the heavy lane there:"
  say ""
  say "    ${CYN}# one-time: install the Linux Terminal / Debian VM from Android Settings${R}"
  say "    ${CYN}# then, inside that VM shell:${R}"
  say "    ${B}cp ~/medtool_web.py ~/setup.sh  <into the VM's shared folder>${R}"
  say "    ${B}bash setup.sh --heavy --run${R}"
  say ""
  say "  Everything else (download, master, video, slow, breathing, packs)"
  say "  works right here in Termux with no VM."
fi

LAUNCH_CMD="python3 \"${APP:-medtool_web.py}\""
say ""
say "  Launch the studio:"
say "    ${B}${LAUNCH_CMD}${R}"
say "  then open ${B}http://127.0.0.1:8800${R} in your browser."
say "  (change the port with MEDTOOL_PORT=9000 python3 medtool_web.py)"
say ""

if [ "$DO_RUN" = 1 ]; then
  if [ -z "$APP" ]; then
    err "--run requested but medtool_web.py not found next to this script."
    exit 1
  fi
  if [ "$CORE_OK" != 1 ]; then
    err "core tools missing; not launching. Fix the ✗ items above first."
    exit 1
  fi
  step "Launching"
  exec python3 "$APP"
fi
