#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  GOLDEN MASTER STUDIO  (medtool web v4.0)
#  Garbage Noise · "calming the garbage within"
#  Meditation With Attitude · "sit down. shut up. breathe."
#
#  Pipeline (all stages optional, all streamed over SSE, no timeouts):
#    yt-dlp download
#      -> compilation remix   (silence-split + reorder + reassemble)
#      -> FX rack             (slowed+reverb, screwed, nightcore, dub,
#                              8D, vaporwave — applied PRE-master so
#                              loudness analysis measures reality)
#      -> 2-pass mastering    (the proven v2.0 chain + binaural)
#      -> loop extension      (single-graph crossfade chain -> one
#                              encode; 30min .. 8h+ with zero
#                              generational loss)
#      -> creator pack        (YouTube thumbnail PNG + metadata txt)
#      -> video render        (audio-reactive viz incl. electric
#                              geometry, randomized brand logo,
#                              breathing pacer overlay + cue tones,
#                              whisper word captions)
#      -> video extension     (-c copy concat = instant 8h video,
#                              seamless extended audio muxed over it)
#
#  Run:   python3 medtool_web.py   ->  http://127.0.0.1:8800
#
#  Optional deps:
#     pip install pillow faster-whisper
#     any cursive TTF in ~/.medtool/assets/ is auto-adopted
# ═══════════════════════════════════════════════════════════════════

import os
import sys
import re
import json
import glob
import math
import time
import wave
import queue
import random
import shutil
import struct
import unicodedata
import threading
import subprocess
import importlib.util
import uuid

from flask import (
    Flask, request, jsonify, Response, send_file, abort
)

# ── Paths / config ─────────────────────────────────────────────────
CFG_DIR = os.path.expanduser("~/.medtool")
CFG_FILE = os.path.join(CFG_DIR, "web_config.json")
TMP_DIR = os.path.join(CFG_DIR, "tmp")
ASSET_DIR = os.path.join(CFG_DIR, "assets")
LOG_FILE = os.path.join(CFG_DIR, "medtool-web.log")
os.makedirs(CFG_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)
os.makedirs(ASSET_DIR, exist_ok=True)

# ── Brands ─────────────────────────────────────────────────────────
BRANDS = {
    "garbage": {
        "channel": "GARBAGE NOISE",
        "slogan": "calming the garbage within",
        "top": "Garbage", "bottom": "Noise",
        "faces": ("classic", "wink", "zen"),
        "tag": "GN",
    },
    "attitude": {
        "channel": "MEDITATION WITH ATTITUDE",
        "slogan": "sit down. shut up. breathe.",
        "top": "Meditation", "bottom": "w/ Attitude",
        "faces": ("shades",),
        "tag": "MWA",
    },
}

DEFAULTS = {
    "profile": "med",
    "binaural": True,
    "fade_in": 3,
    "fade_out": 6,
    "lufs": -14,
    "true_peak": -1,
    "bitrate": "320k",
    "skip_existing": True,
    "out_dir": os.path.expanduser("~/storage/downloads/MedTool"),
    # ── v4 golden master ──
    "brand": "garbage",       # garbage | attitude
    "fx": "none",             # see FX_RACK
    "polish": True,           # crystalizer + subtle stereo widen
    "video": False,
    "captions": True,
    "viz": "auto",            # auto|cqt|spectrum|waves|bars|geometry
    "breathing": "none",      # see BREATHING
    "creator_pack": True,     # thumbnail + youtube metadata txt
    "extend_min": 0,          # 0 = off, else target minutes
    "comp_order": "off",      # off|shuffle|reverse|short|long
    "video_res": "1280x720",
    "video_fps": 30,
    "whisper_model": "base",  # tiny | base | small
    "loop_xfade": 8,          # seconds of crossfade between loop units
    # ── slow + stem separation ──
    "slow": "off",            # off | tempo | tape  (see SLOW_MODES)
    "slow_pct": 85,           # target tempo/speed as % of original (50..100)
    "stems": "off",           # off | vocals | 4 | 6   (Demucs)
    "stem_model": "htdemucs", # htdemucs | htdemucs_ft | htdemucs_6s
    "stem_source": "mix",     # which layer feeds the pipeline after split:
                              # mix|vocals|drums|bass|other|instrumental|acapella
    "stem_pipeline": False,   # run master/extend/video on stem_source
}

PROFILES = {
    "sleep": {"label": "Sleep", "beat": "2hz-delta",  "hz": (200, 202),
              "desc": "2 Hz Delta — deep sleep / healing"},
    "med":   {"label": "Med",   "beat": "6hz-theta",  "hz": (200, 206),
              "desc": "6 Hz Theta — meditation"},
    "focus": {"label": "Focus", "beat": "10hz-alpha", "hz": (200, 210),
              "desc": "10 Hz Alpha — focus / flow"},
}

VIZ_MODES = ("cqt", "spectrum", "waves", "bars", "geometry")

# ── FX rack ────────────────────────────────────────────────────────
# Each entry: label, chain-builder(sr) -> ffmpeg audio filter string,
# and the filters it requires (checked against this build at startup).
FX_RACK = {
    "none": {
        "label": "Clean", "needs": (),
        "chain": lambda sr: None,
    },
    "slowed": {
        "label": "Slowed + Reverb", "needs": ("asetrate", "aecho"),
        # authentic slowed+reverb: pitch and tempo drop together
        "chain": lambda sr: (
            f"asetrate={sr}*0.85,aresample={sr},"
            "aecho=0.72:0.68:60|110|180:0.32|0.24|0.16,"
            "lowpass=f=14000"
        ),
    },
    "screwed": {
        "label": "Chopped & Screwed", "needs": ("asetrate", "flanger",
                                                "aecho", "vibrato"),
        # deep slow, syrupy flange, slow wobble, tape-warm lowpass
        "chain": lambda sr: (
            f"asetrate={sr}*0.75,aresample={sr},"
            "flanger=delay=4:depth=6:speed=0.18:width=64,"
            "vibrato=f=0.35:d=0.06,"
            "aecho=0.7:0.6:140|260:0.28|0.18,"
            "equalizer=f=80:t=q:width=1:g=3,lowpass=f=11000"
        ),
    },
    "nightcore": {
        "label": "Nightcore", "needs": ("asetrate",),
        "chain": lambda sr: f"asetrate={sr}*1.25,aresample={sr}",
    },
    "dub": {
        "label": "Dub Echo", "needs": ("aecho",),
        "chain": lambda sr: (
            "aecho=0.78:0.68:380|540|760:0.42|0.30|0.20,"
            "equalizer=f=70:t=q:width=1.2:g=4,"
            "equalizer=f=3200:t=q:width=2:g=-2"
        ),
    },
    "8d": {
        "label": "8D Orbit", "needs": ("apulsator",),
        "chain": lambda sr: "apulsator=hz=0.125:amount=0.85",
    },
    "vapor": {
        "label": "Vaporwave", "needs": ("asetrate", "chorus"),
        "chain": lambda sr: (
            f"asetrate={sr}*0.80,aresample={sr},"
            "chorus=0.6:0.9:50|60:0.4|0.32:0.25|0.4:2|1.3,"
            "lowpass=f=13000"
        ),
    },
}

# ── Standalone slow ────────────────────────────────────────────────
# tempo = rubberband time-stretch, pitch preserved (the "proper" slow —
#         vocals stay on key). Falls back to atempo if rubberband is
#         absent in this ffmpeg build.
# tape  = asetrate resample, pitch drops with speed (vinyl / classic
#         "slowed" sound). Always available.
SLOW_MODES = {
    "off":   {"label": "No slow", "needs": ()},
    "tempo": {"label": "Slow — keep pitch (rubberband)",
              "needs": ()},   # graceful atempo fallback, so no hard need
    "tape":  {"label": "Slow — tape / pitch-down (asetrate)",
              "needs": ("asetrate",)},
}

# ── Stem separation (Demucs v4 — Hybrid Transformer) ───────────────
# The Princeton-grade right way: Meta/FAIR's Demucs v4 (htdemucs),
# ~9 dB SDR on MUSDB, waveform-domain hybrid transformer, MIT license.
STEM_MODELS = {
    "htdemucs":    {"label": "htdemucs (4-stem, default)", "sources": 4},
    "htdemucs_ft": {"label": "htdemucs_ft (4-stem, fine-tuned, 4× slower)",
                    "sources": 4},
    "htdemucs_6s": {"label": "htdemucs_6s (6-stem +guitar +piano)",
                    "sources": 6},
}
STEM_MODES = {
    "off":     {"label": "No separation"},
    "vocals":  {"label": "Vocals + Instrumental (fast 2-stem)"},
    "4":       {"label": "4 stems — vocals / drums / bass / other"},
    "6":       {"label": "6 stems — + guitar / piano"},
}
# canonical stem order per model
STEM_LAYERS_4 = ("vocals", "drums", "bass", "other")
STEM_LAYERS_6 = ("vocals", "drums", "bass", "guitar", "piano", "other")


# ── Breathing techniques (researched patterns) ─────────────────────
# Sources noted per technique. Cycle = list of (phase, seconds).
BREATHING = {
    "box": {
        "label": "Box 4·4·4·4",
        "cycle": [("Inhale", 4), ("Hold", 4), ("Exhale", 4), ("Hold", 4)],
        "desc": "Tactical / box breathing — used by Navy SEALs and "
                "first responders to steady the autonomic nervous "
                "system under stress.",
    },
    "478": {
        "label": "4·7·8 Sleep",
        "cycle": [("Inhale", 4), ("Hold", 7), ("Exhale", 8)],
        "desc": "Dr. Andrew Weil's 4-7-8. The extended exhale drives "
                "a parasympathetic (rest-and-digest) response — "
                "widely used for sleep onset and acute anxiety.",
    },
    "coherent": {
        "label": "Coherent 5.5",
        "cycle": [("Inhale", 5.5), ("Exhale", 5.5)],
        "desc": "Resonance / coherent breathing at ~5.5 breaths per "
                "minute — the rate shown to maximize heart-rate "
                "variability (HRV) and baroreflex sensitivity.",
    },
    "sigh": {
        "label": "Physiological Sigh",
        "cycle": [("Inhale", 2), ("Top-up", 1), ("Exhale", 7)],
        "desc": "Double inhale + long exhale. Stanford research "
                "(Huberman/Spiegel labs) found cyclic sighing the "
                "fastest real-time way to downshift stress and "
                "improve mood.",
    },
    "downshift": {
        "label": "4·6 Downshift",
        "cycle": [("Inhale", 4), ("Exhale", 6)],
        "desc": "Exhale-biased breathing. Exhalation slows the heart "
                "via vagal tone, so a longer out-breath is a direct "
                "lever on calm.",
    },
    "energize": {
        "label": "6·2 Energize",
        "cycle": [("Inhale", 6), ("Exhale", 2)],
        "desc": "Inhale-biased pattern for gentle alertness — the "
                "inverse of downshift. Practice seated; stop if "
                "light-headed.",
    },
}

# accent palette for randomized branding
ACCENTS = [
    ("classic",  "#ffd23f", "#ffb03f"),
    ("magenta",  "#d946ef", "#a855f7"),
    ("cyan",     "#34d2ee", "#38bdf8"),
    ("mint",     "#34d399", "#6ee7b7"),
    ("ember",    "#fb7185", "#fbbf24"),
    ("violet",   "#a78bfa", "#818cf8"),
]

EXTEND_PRESETS = (0, 30, 60, 120, 180, 480)
COMP_ORDERS = ("off", "shuffle", "reverse", "short", "long")


def load_cfg():
    cfg = dict(DEFAULTS)
    if os.path.isfile(CFG_FILE):
        try:
            with open(CFG_FILE) as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def save_cfg(cfg):
    with open(CFG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")


CFG = load_cfg()

# ── Job registry ───────────────────────────────────────────────────
JOBS = {}
JOBS_LOCK = threading.Lock()


# ── Helpers ────────────────────────────────────────────────────────
def have(binary):
    return shutil.which(binary) is not None


def have_module(name):
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


_ff_filters = None


def ff_filters():
    """Set of audio/video filter names compiled into this ffmpeg."""
    global _ff_filters
    if _ff_filters is None:
        try:
            out = subprocess.run(["ffmpeg", "-hide_banner", "-filters"],
                                 capture_output=True, text=True).stdout
            _ff_filters = set(re.findall(r"^\s*[A-Z.]+\s+(\S+)", out,
                                         re.MULTILINE))
        except Exception:
            _ff_filters = set()
    return _ff_filters


def fx_available(fx_key):
    fx = FX_RACK.get(fx_key)
    if not fx:
        return False
    return all(n in ff_filters() for n in fx["needs"])


_ff_encoders = None


def ff_encoders():
    """Set of video encoder names compiled into this ffmpeg."""
    global _ff_encoders
    if _ff_encoders is None:
        try:
            out = subprocess.run(["ffmpeg", "-hide_banner", "-encoders"],
                                 capture_output=True, text=True).stdout
            _ff_encoders = set(re.findall(r"^\s*V[A-Z.]{5}\s+(\S+)", out,
                                          re.MULTILINE))
        except Exception:
            _ff_encoders = set()
    return _ff_encoders


# Ordered by preference. Hardware encoders on a phone SoC are typically
# 10-20x faster than software libx264 at the same resolution, which is
# the difference between a video finishing in minutes vs. hours on a
# CPU like the Pixel 9a's. We probe once and cache the pick.
_video_encoder = None


def pick_video_encoder():
    """Return (codec_args, is_hardware). codec_args is the -c:v value
    plus any encoder-specific speed/quality flags. Prefers hardware:
      h264_mediacodec  — Android/Termux hardware encoder (fastest here)
      h264_v4l2m2m     — Linux SBC/some ARM hardware paths
      h264_nvenc/qsv/vaapi — desktop GPU hardware (VM/desktop use)
    Falls back to libx264 with a speed-first preset."""
    global _video_encoder
    if _video_encoder is not None:
        return _video_encoder
    enc = ff_encoders()
    if "h264_mediacodec" in enc:
        _video_encoder = (["h264_mediacodec", "-bitrate", "6M"], True,
                          "h264_mediacodec (Android hardware)")
    elif "h264_v4l2m2m" in enc:
        _video_encoder = (["h264_v4l2m2m", "-b:v", "6M"], True,
                          "h264_v4l2m2m (Linux hardware)")
    elif "h264_nvenc" in enc:
        _video_encoder = (["h264_nvenc", "-preset", "p4", "-cq", "23"],
                          True, "h264_nvenc (NVIDIA hardware)")
    elif "h264_qsv" in enc:
        _video_encoder = (["h264_qsv", "-global_quality", "23"], True,
                          "h264_qsv (Intel hardware)")
    elif "h264_vaapi" in enc:
        _video_encoder = (["h264_vaapi", "-qp", "23"], True,
                          "h264_vaapi (VAAPI hardware)")
    else:
        _video_encoder = (["libx264", "-preset", "ultrafast", "-crf", "26"],
                          False, "libx264 ultrafast (software — slowest "
                                 "path; consider 480p or shorter video)")
    return _video_encoder


def profile_slug(p):
    return PROFILES.get(p, {}).get("label", p).upper() if p in PROFILES else p.upper()


def slugify(title):
    s = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    s = s.lower()
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    return s.strip("-")[:55] or "track"


def gen_filename(title, cfg):
    beat = PROFILES.get(cfg["profile"], PROFILES["med"])["beat"]
    tag = BRANDS[cfg.get("brand", "garbage")]["tag"]
    parts = [tag, profile_slug(cfg["profile"]), beat, slugify(title)]
    if cfg.get("fx", "none") != "none":
        parts.append(cfg["fx"])
    if int(cfg.get("extend_min") or 0) > 0:
        parts.append(f"{int(cfg['extend_min'])}min")
    return "_".join(parts) + ".mp3"


def video_filename(audio_filename):
    return os.path.splitext(audio_filename)[0] + ".mp4"


def human_size(num):
    for unit in ["B", "K", "M", "G"]:
        if num < 1024:
            return f"{num:.0f}{unit}" if unit == "B" else f"{num:.1f}{unit}"
        num /= 1024
    return f"{num:.1f}T"


def fmt_hms(seconds):
    s = int(seconds)
    return f"{s//3600}:{(s%3600)//60:02d}:{s%60:02d}"


def get_duration(path):
    try:
        out = subprocess.run(
            ["ffprobe", "-v", "quiet", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", path],
            capture_output=True, text=True,
        ).stdout.strip()
        return float(out)
    except Exception:
        return None


def parse_time(s):
    try:
        h, m, sec = s.split(":")
        return int(h) * 3600 + int(m) * 60 + float(sec)
    except Exception:
        return None


def read_tail(path, n=8):
    try:
        with open(path) as f:
            return "\n".join(f.read().splitlines()[-n:])
    except Exception:
        return ""


def run_ff_progress(job_id, cmd, duration, emit, state, errname):
    """Run an ffmpeg command with -progress pipe:1, streaming % to UI."""
    errlog = os.path.join(TMP_DIR, f"{errname}_{job_id}.log")
    with open(errlog, "w") as ef:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=ef,
                                text=True)
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["proc"] = proc
        for line in proc.stdout:
            line = line.strip()
            if line.startswith("out_time="):
                t = parse_time(line.split("=", 1)[1])
                if t is not None and duration and duration > 0:
                    emit(state=state,
                         progress=min(99.0, t / duration * 100))
        proc.wait()
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id]["proc"] = None
    if proc.returncode != 0:
        raise RuntimeError(f"ffmpeg failed (exit {proc.returncode})\n"
                           + read_tail(errlog, 6))


# ── Font discovery ─────────────────────────────────────────────────
FONT_DIRS = [
    os.environ.get("PREFIX", "/usr") + "/share/fonts",
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    os.path.expanduser("~/.fonts"),
    os.path.expanduser("~/.local/share/fonts"),
    "/system/fonts",           # Android
    ASSET_DIR,                 # drop your own TTF here to force it
]

CURSIVE_HINTS = (
    "dancingscript", "dancing", "pacifico", "greatvibes", "satisfy",
    "lobster", "yellowtail", "sacramento", "caveat", "allura",
    "cookie", "kaushan", "script", "cursive", "handwrit", "comic",
)

_font_cache = {}


def _scan_fonts():
    if "all" in _font_cache:
        return _font_cache["all"]
    found = []
    for d in FONT_DIRS:
        if os.path.isdir(d):
            for ext in ("ttf", "otf", "TTF", "OTF"):
                found.extend(glob.glob(os.path.join(d, "**", f"*.{ext}"),
                                       recursive=True))
    _font_cache["all"] = found
    return found


def find_font(kind="cursive"):
    """Return (path, guessed_family) or (None, None)."""
    key = f"pick_{kind}"
    if key in _font_cache:
        return _font_cache[key]
    fonts = _scan_fonts()
    pick = None
    if kind == "cursive":
        for hint in CURSIVE_HINTS:
            for f in fonts:
                if hint in os.path.basename(f).lower():
                    pick = f
                    break
            if pick:
                break
    if not pick:
        for pref in ("DejaVuSans-Bold", "Roboto-Bold", "NotoSans-Bold",
                     "DejaVuSans", "Roboto-Regular"):
            for f in fonts:
                if pref.lower() in os.path.basename(f).lower():
                    pick = f
                    break
            if pick:
                break
    if not pick and fonts:
        pick = fonts[0]
    family = None
    if pick:
        stem = os.path.splitext(os.path.basename(pick))[0]
        stem = re.split(r"[-_]", stem)[0]
        family = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", stem)
    _font_cache[key] = (pick, family)
    return pick, family


def _hex_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _hex_rgba(h, a=255):
    return _hex_rgb(h) + (a,)


# ── Logo generation (parody box, per-brand, randomized) ───────────
def make_logo(title_seed, brand_key, emit=None, rnd=None):
    """Black box, white border, brand text bands, smiley center.
    garbage: classic/wink/zen face.  attitude: shades + smirk.
    Randomized accent, tilt (and face for garbage) every render."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        if emit:
            emit(log="⚠ pillow not installed — skipping logo overlay "
                     "(pip install pillow)")
        return None, None

    brand = BRANDS.get(brand_key, BRANDS["garbage"])
    rnd = rnd or random.Random(f"{title_seed}:{time.time_ns()}")
    accent_name, accent, accent2 = rnd.choice(ACCENTS)
    face = rnd.choice(brand["faces"])
    tilt = rnd.uniform(-2.5, 2.5)

    S = 1000
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    m = 24
    try:
        d.rounded_rectangle([m, m, S - m, S - m], radius=46,
                            fill=(8, 7, 12, 255))
        d.rounded_rectangle([m, m, S - m, S - m], radius=46,
                            outline=(255, 255, 255, 255), width=12)
    except AttributeError:
        d.rectangle([m, m, S - m, S - m], fill=(8, 7, 12, 255),
                    outline=(255, 255, 255, 255), width=12)

    font_path, _family = find_font("cursive")

    def load_font(size):
        if font_path:
            try:
                return ImageFont.truetype(font_path, size)
            except Exception:
                pass
        try:
            return ImageFont.load_default(size=size)
        except TypeError:
            return ImageFont.load_default()

    def center_text(text, y, size, fill=(255, 255, 255, 255)):
        f = load_font(size)
        # shrink to fit box width
        while size > 40:
            try:
                bb = d.textbbox((0, 0), text, font=f)
                if bb[2] - bb[0] <= S - 120:
                    break
            except Exception:
                break
            size = int(size * 0.92)
            f = load_font(size)
        try:
            bb = d.textbbox((0, 0), text, font=f)
            w = bb[2] - bb[0]
            d.text(((S - w) / 2 - bb[0], y - bb[1]), text, font=f,
                   fill=fill)
        except Exception:
            d.text((S / 2, y), text, font=f, fill=fill, anchor="mm")

    center_text(brand["top"], 70, 175)
    center_text(brand["bottom"], S - 300, 175)
    center_text(brand["slogan"], S - 108, 50, fill=(200, 196, 214, 255))

    # smiley — pure geometry, no emoji font required
    cx, cy, r = S / 2, S / 2 - 20, 185
    ink = (8, 7, 12, 255)
    d.ellipse([cx - r, cy - r, cx + r, cy + r],
              fill=_hex_rgba(accent), outline=(255, 255, 255, 255),
              width=10)

    ew, eh = r * 0.16, r * 0.30
    ey = cy - r * 0.28
    exl, exr = cx - r * 0.40, cx + r * 0.40
    lw = 16

    def open_eye(x):
        d.ellipse([x - ew, ey - eh / 2, x + ew, ey + eh / 2], fill=ink)

    def closed_eye(x):
        d.arc([x - r * 0.22, ey - r * 0.10, x + r * 0.22, ey + r * 0.22],
              start=200, end=340, fill=ink, width=lw)

    if face == "classic":
        open_eye(exl); open_eye(exr)
    elif face == "wink":
        open_eye(exl); closed_eye(exr)
    elif face == "zen":
        closed_eye(exl); closed_eye(exr)
    else:  # shades — Meditation With Attitude
        gy = ey - r * 0.12
        gh = r * 0.30
        gw = r * 0.34
        d.rounded_rectangle([exl - gw, gy, exl + gw, gy + gh],
                            radius=14, fill=ink)
        d.rounded_rectangle([exr - gw, gy, exr + gw, gy + gh],
                            radius=14, fill=ink)
        d.line([exl + gw, gy + gh * 0.3, exr - gw, gy + gh * 0.3],
               fill=ink, width=lw)
        d.line([exl - gw, gy + gh * 0.25, cx - r * 0.96, gy - r * 0.05],
               fill=ink, width=lw - 4)
        d.line([exr + gw, gy + gh * 0.25, cx + r * 0.96, gy - r * 0.05],
               fill=ink, width=lw - 4)

    # mouth: smirk for attitude, smile otherwise
    if face == "shades":
        d.arc([cx - r * 0.50, cy + r * 0.02, cx + r * 0.34, cy + r * 0.56],
              start=15, end=125, fill=ink, width=lw + 4)
    else:
        sw = r * 0.62
        d.arc([cx - sw, cy - r * 0.20, cx + sw, cy + r * 0.66],
              start=25, end=155, fill=ink, width=lw + 4)

    img = img.rotate(tilt, expand=True,
                     resample=getattr(Image, "BICUBIC", 0))
    out = os.path.join(TMP_DIR, f"logo_{uuid.uuid4().hex[:8]}.png")
    img.save(out)
    if emit:
        emit(log=f"Logo: {brand['channel']} · {face} face · "
                 f"{accent_name} accent · {tilt:+.1f}° tilt")
    return out, accent


# ── Electric geometry mandala (spun procedurally by ffmpeg) ────────
def make_mandala(accent, size=760):
    """Transparent PNG: concentric polygons + spokes + rings in the
    accent color with a soft glow. ffmpeg rotates it over time, the
    avectorscope lissajous pulses inside it."""
    try:
        from PIL import Image, ImageDraw, ImageFilter
    except ImportError:
        return None
    S = size
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx = cy = S / 2
    col = _hex_rgba(accent, 200)
    dim = _hex_rgba(accent, 90)

    def poly(n, r, rot, width, color):
        pts = [(cx + r * math.cos(rot + 2 * math.pi * i / n),
                cy + r * math.sin(rot + 2 * math.pi * i / n))
               for i in range(n)]
        d.line(pts + [pts[0]], fill=color, width=width, joint="curve")

    poly(6, S * 0.46, 0, 5, col)
    poly(6, S * 0.46, math.pi / 6, 5, dim)
    poly(3, S * 0.34, math.pi / 2, 4, col)
    poly(3, S * 0.34, -math.pi / 2, 4, dim)
    for rr in (0.475, 0.30, 0.145):
        d.ellipse([cx - S * rr, cy - S * rr, cx + S * rr, cy + S * rr],
                  outline=dim, width=3)
    for i in range(12):
        a = 2 * math.pi * i / 12
        d.line([cx + S * 0.145 * math.cos(a), cy + S * 0.145 * math.sin(a),
                cx + S * 0.475 * math.cos(a), cy + S * 0.475 * math.sin(a)],
               fill=_hex_rgba(accent, 60), width=2)

    glow = img.filter(ImageFilter.GaussianBlur(6))
    img = Image.alpha_composite(glow, img)
    out = os.path.join(TMP_DIR, f"mandala_{uuid.uuid4().hex[:8]}.png")
    img.save(out)
    return out


# ── Breathing pacer (PIL frame loop) + cue tones (stdlib wave) ─────
PACER_FPS = 12


def make_breath_pacer(technique, accent, emit=None):
    """Render one full breathing cycle as a transparent PNG sequence.
    ffmpeg stream-loops it for the whole video, so it stays perfectly
    periodic no matter the duration. Returns (pattern_glob, cycle_secs,
    n_frames) or (None, 0, 0)."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        if emit:
            emit(log="⚠ pillow not installed — breathing pacer skipped")
        return None, 0, 0

    tech = BREATHING[technique]
    cycle = tech["cycle"]
    total = sum(s for _, s in cycle)
    n = max(1, int(round(total * PACER_FPS)))
    S = 460
    cx = cy = S / 2
    rmin, rmax = S * 0.14, S * 0.40
    col = _hex_rgba(accent)
    ring = _hex_rgba(accent, 120)

    font_path, _ = find_font("cursive")

    def load_font(size):
        if font_path:
            try:
                return ImageFont.truetype(font_path, size)
            except Exception:
                pass
        try:
            return ImageFont.load_default(size=size)
        except TypeError:
            return ImageFont.load_default()

    f_phase = load_font(46)
    f_count = load_font(34)

    seq_id = uuid.uuid4().hex[:8]
    pattern = os.path.join(TMP_DIR, f"pacer_{seq_id}_%04d.png")

    for i in range(n):
        t = (i / PACER_FPS) % total
        # locate phase
        acc = 0.0
        phase, plen, pt = cycle[0][0], cycle[0][1], 0.0
        for name, secs in cycle:
            if t < acc + secs:
                phase, plen, pt = name, secs, t - acc
                break
            acc += secs
        prog = pt / plen if plen else 0
        low = phase.lower()
        if "inhale" in low or "top" in low:
            r = rmin + (rmax - rmin) * (0.5 - 0.5 * math.cos(math.pi * prog))
        elif "exhale" in low:
            r = rmax - (rmax - rmin) * (0.5 - 0.5 * math.cos(math.pi * prog))
        else:  # hold — gentle shimmer at current extreme
            base = rmax if "exhale" in cycle[(next(
                j for j, c in enumerate(cycle) if c[0] == phase
            ) + 1) % len(cycle)][0].lower() else rmin
            r = base + math.sin(pt * 2 * math.pi) * 3

        img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        # outer guide ring + cycle progress arc
        d.ellipse([cx - rmax - 14, cy - rmax - 14,
                   cx + rmax + 14, cy + rmax + 14], outline=ring, width=4)
        d.arc([cx - rmax - 14, cy - rmax - 14,
               cx + rmax + 14, cy + rmax + 14],
              start=-90, end=-90 + 360 * (t / total), fill=col, width=8)
        # breathing orb
        d.ellipse([cx - r, cy - r, cx + r, cy + r],
                  fill=_hex_rgba(accent, 70), outline=col, width=6)
        # phase label + countdown
        remain = max(1, math.ceil(plen - pt))
        for text, font, dy in ((phase, f_phase, -12),
                               (str(remain), f_count, 40)):
            try:
                bb = d.textbbox((0, 0), text, font=font)
                w, h = bb[2] - bb[0], bb[3] - bb[1]
                d.text((cx - w / 2 - bb[0], cy - h / 2 - bb[1] + dy),
                       text, font=font, fill=(255, 255, 255, 235))
            except Exception:
                d.text((cx, cy + dy), text, font=font,
                       fill=(255, 255, 255, 235), anchor="mm")
        img.save(pattern % i)

    if emit:
        emit(log=f"Breathing pacer: {tech['label']} — "
                 f"{total:g}s cycle, {n} frames")
    return pattern, total, n


def make_breath_cues(technique):
    """Soft sine cue at each phase boundary, one full cycle, written
    with the stdlib wave module (no numpy). Descending pitch into the
    exhale. Loops via -stream_loop. Returns wav path or None."""
    tech = BREATHING.get(technique)
    if not tech:
        return None
    sr = 44100
    cycle = tech["cycle"]
    total = sum(s for _, s in cycle)
    n = int(total * sr)
    buf = bytearray(n * 2)  # mono s16, zero-filled

    def blip(start_s, freq):
        dur = 0.22
        amp = 0.30
        s0 = int(start_s * sr)
        for i in range(int(dur * sr)):
            idx = s0 + i
            if idx >= n:
                break
            env = math.sin(math.pi * i / (dur * sr))  # hann-ish
            v = int(amp * env * 32767 *
                    math.sin(2 * math.pi * freq * i / sr))
            struct.pack_into("<h", buf, idx * 2, v)

    t = 0.0
    for name, secs in cycle:
        low = name.lower()
        if "inhale" in low or "top" in low:
            blip(t, 523.25)   # C5 — up
        elif "exhale" in low:
            blip(t, 261.63)   # C4 — down
        else:
            blip(t, 392.00)   # G4 — hold
        t += secs

    out = os.path.join(TMP_DIR, f"cues_{uuid.uuid4().hex[:8]}.wav")
    with wave.open(out, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sr)
        w.writeframes(bytes(buf))
    return out


# ── Compilation remix (silence split -> reorder -> reassemble) ─────
def detect_segments(path, emit, noise_db=-30, min_sil=0.6):
    dur = get_duration(path)
    if not dur:
        raise RuntimeError("Could not read duration for split")
    out = subprocess.run(
        ["ffmpeg", "-i", path, "-af",
         f"silencedetect=noise={noise_db}dB:d={min_sil}",
         "-f", "null", "-"],
        capture_output=True, text=True,
    ).stderr
    starts = [float(x) for x in re.findall(r"silence_start:\s*([\d.]+)", out)]
    ends = [float(x) for x in re.findall(r"silence_end:\s*([\d.]+)", out)]
    # segments = audio between silences
    bounds = [0.0]
    for s, e in zip(starts, ends):
        mid_pad = 0.12
        bounds.append(max(0.0, s + mid_pad))
        bounds.append(max(0.0, e - mid_pad))
    bounds.append(dur)
    segs = []
    it = iter(bounds)
    for a, b in zip(it, it):
        if b - a >= 1.5:  # ignore blips
            segs.append((a, b))
    emit(log=f"Compilation split: {len(segs)} segments detected "
             f"(silence {noise_db} dB / {min_sil}s)")
    return segs


def remix_compilation(job_id, src, order, emit, cancel):
    """Split on silence, reorder, reassemble with click-free micro
    fades. Returns new wav path (or src unchanged if <2 segments)."""
    emit(state="splitting", step="Compilation remix — detecting segments",
         progress=0, log=f"Remix order: {order}")
    segs = detect_segments(src, emit)
    if len(segs) < 2:
        emit(log="⚠ Fewer than 2 segments found — remix skipped")
        return src

    segs = segs[:200]
    if order == "shuffle":
        random.shuffle(segs)
    elif order == "reverse":
        segs.reverse()
    elif order == "short":
        segs.sort(key=lambda s: s[1] - s[0])
    elif order == "long":
        segs.sort(key=lambda s: -(s[1] - s[0]))

    parts, labels = [], []
    for i, (a, b) in enumerate(segs):
        ln = b - a
        parts.append(
            f"[0:a]atrim=start={a:.3f}:end={b:.3f},asetpts=PTS-STARTPTS,"
            f"afade=t=in:d=0.05,afade=t=out:st={max(0, ln-0.05):.3f}:d=0.05"
            f"[s{i}]"
        )
        labels.append(f"[s{i}]")
    parts.append("".join(labels) + f"concat=n={len(segs)}:v=0:a=1[out]")

    out = os.path.join(TMP_DIR, f"remix_{uuid.uuid4().hex[:8]}.wav")
    total = sum(b - a for a, b in segs)
    emit(step=f"Compilation remix — reassembling {len(segs)} segments")
    run_ff_progress(job_id,
                    ["ffmpeg", "-y", "-i", src,
                     "-filter_complex", ";".join(parts),
                     "-map", "[out]", "-c:a", "pcm_s16le",
                     "-progress", "pipe:1", "-nostats", out],
                    total, emit, "splitting", "remix")
    emit(log=f"✓ Remixed {len(segs)} segments ({fmt_hms(total)})")
    return out


# ── FX rack pre-pass ───────────────────────────────────────────────
# ── Standalone slow (pitch-preserving OR tape) ─────────────────────
def apply_slow(job_id, src, mode, pct, emit, cancel):
    """Slow a track to `pct`% of original speed.
    tempo: rubberband time-stretch (pitch preserved); atempo fallback.
    tape : asetrate resample (pitch drops, classic slowed sound).
    Returns new wav path, or src unchanged if mode is off."""
    if mode == "off" or mode not in SLOW_MODES:
        return src
    pct = max(50, min(100, int(pct)))
    if pct >= 100:
        return src
    ratio = pct / 100.0        # 0.85 => 85% speed
    dur = get_duration(src) or 0
    est = dur / ratio if ratio else dur

    if mode == "tape":
        chain = f"asetrate=44100*{ratio:.4f},aresample=44100"
        how = "tape / pitch-down"
    else:
        # rubberband stretches by a time ratio: >1 = longer/slower
        stretch = 1.0 / ratio
        if "rubberband" in ff_filters():
            chain = (f"rubberband=tempo={ratio:.4f}"
                     f":pitch=1:pitchq=quality")
            how = "rubberband, pitch preserved"
        else:
            # atempo valid range 0.5..100; our ratio is >=0.5, fine
            chain = f"atempo={ratio:.4f}"
            how = "atempo fallback, pitch preserved"

    emit(state="slowing", step=f"Slow — {pct}% ({how})", progress=0,
         log=f"Slow pre-pass: {pct}% speed · {how}")
    out = os.path.join(TMP_DIR, f"slow_{uuid.uuid4().hex[:8]}.wav")
    run_ff_progress(job_id,
                    ["ffmpeg", "-y", "-i", src, "-af",
                     f"aformat=channel_layouts=stereo,aresample=44100,"
                     f"{chain}",
                     "-c:a", "pcm_s16le",
                     "-progress", "pipe:1", "-nostats", out],
                    est, emit, "slowing", "slow")
    emit(log=f"✓ Slowed to {pct}% ({fmt_hms(get_duration(out) or 0)})")
    return out


# ── Stem separation (Demucs v4) ────────────────────────────────────
def demucs_available():
    return have("demucs") or have_module("demucs")


def _mix_stems(job_id, stem_paths, out_path, emit, weights=None):
    """Sum a set of stem wavs into one file (equal weight unless given).
    Used to build instrumental (all but vocals) and custom blends."""
    n = len(stem_paths)
    if n == 0:
        raise RuntimeError("no stems to mix")
    if n == 1 and not weights:
        shutil.copy(stem_paths[0], out_path)
        return out_path
    inputs = []
    for p in stem_paths:
        inputs += ["-i", p]
    if weights:
        w = " ".join(f"{weights.get(os.path.basename(p), 1):.3f}"
                     for p in stem_paths)
    else:
        w = " ".join("1" for _ in stem_paths)
    fc = (f"amix=inputs={n}:duration=longest:normalize=0:weights={w}"
          if n > 1 else "anull")
    labels = "".join(f"[{i}:a]" for i in range(n))
    cmd = ["ffmpeg", "-y"] + inputs + [
        "-filter_complex", f"{labels}{fc}[out]", "-map", "[out]",
        "-c:a", "pcm_s16le", out_path]
    subprocess.run(cmd, capture_output=True)
    return out_path


def separate_stems(job_id, src, title, cfg, out_root, emit, cancel):
    """Run Demucs, publish each isolated stem + instrumental + acapella
    to the library, and return {layer: wav_path} plus the derived
    'instrumental'/'acapella'/'mix' entries for pipeline routing."""
    if not demucs_available():
        emit(log="⚠ Demucs not installed — stem separation skipped. "
                 "Install in your Debian VM:  pip install -U demucs "
                 "(needs torch; first run downloads the model).")
        return None

    mode = cfg.get("stems", "off")
    if mode == "vocals":
        model = "htdemucs"
        two_stems = "vocals"
        layers = ("vocals", "no_vocals")
    else:
        model = cfg.get("stem_model", "htdemucs")
        if mode == "6" or model == "htdemucs_6s":
            model = "htdemucs_6s"
            layers = STEM_LAYERS_6
        else:
            layers = STEM_LAYERS_4
        two_stems = None

    dur = get_duration(src) or 0
    device = "cpu"
    try:
        import torch  # noqa
        if torch.cuda.is_available():
            device = "cuda"
    except Exception:
        pass

    emit(state="separating",
         step=f"Stem separation — Demucs {model} ({device})",
         progress=0,
         log=f"Demucs {model} on {device} — {'2-stem' if two_stems else mode+'-stem'}. "
             f"This is the slow part on CPU (~5-15× track length).")

    work = os.path.join(TMP_DIR, f"demucs_{uuid.uuid4().hex[:8]}")
    os.makedirs(work, exist_ok=True)

    cmd = ["demucs", "-n", model, "-o", work,
           "--filename", "{stem}.{ext}"]
    if device == "cpu":
        cmd += ["-d", "cpu", "-j", "2"]   # 2 workers keeps the 9a sane
    else:
        cmd += ["-d", "cuda"]
    if two_stems:
        cmd += ["--two-stems", two_stems]
    cmd += [src]
    if not have("demucs"):
        cmd = ["python3", "-m", "demucs"] + cmd[1:]

    # Demucs prints a % progress bar to stderr; stream it through.
    errlog = os.path.join(TMP_DIR, f"demucs_{job_id}.log")
    with open(errlog, "w") as ef:
        proc = subprocess.Popen(cmd, stdout=ef, stderr=subprocess.PIPE,
                                text=True)
        with JOBS_LOCK:
            if job_id in JOBS:
                JOBS[job_id]["proc"] = proc
        for line in proc.stderr:
            mt = re.search(r"(\d+)%", line)
            if mt:
                emit(state="separating", progress=min(99.0,
                                                      float(mt.group(1))))
        proc.wait()
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id]["proc"] = None
    if cancel.is_set():
        shutil.rmtree(work, ignore_errors=True)
        raise RuntimeError("Cancelled")
    if proc.returncode != 0:
        shutil.rmtree(work, ignore_errors=True)
        raise RuntimeError("Demucs failed\n" + read_tail(errlog, 6))

    # Demucs writes work/<model>/<trackname>/<stem>.wav
    found = {}
    for wav in glob.glob(os.path.join(work, "**", "*.wav"),
                         recursive=True):
        found[os.path.splitext(os.path.basename(wav))[0]] = wav
    if not found:
        # some builds emit mp3
        for m3 in glob.glob(os.path.join(work, "**", "*.mp3"),
                            recursive=True):
            found[os.path.splitext(os.path.basename(m3))[0]] = m3
    if not found:
        shutil.rmtree(work, ignore_errors=True)
        raise RuntimeError("Demucs produced no stems")

    stem_dir = os.path.join(out_root, "stems", slugify(title))
    os.makedirs(stem_dir, exist_ok=True)
    tag = BRANDS[cfg.get("brand", "garbage")]["tag"]
    result = {"mix": src}
    br = cfg["bitrate"]

    def publish(layer, wavpath):
        name = f"{tag}_{slugify(title)}_{layer}.mp3"
        dest = os.path.join(stem_dir, name)
        subprocess.run(["ffmpeg", "-y", "-i", wavpath, "-b:a", br,
                        "-metadata", f"title={title} [{layer}]", dest],
                       capture_output=True)
        emit(log=f"✓ stem: {layer}  ({human_size(os.path.getsize(dest))})")
        return dest

    if two_stems:
        # vocals + no_vocals(instrumental)
        if "vocals" in found:
            result["vocals"] = found["vocals"]
            publish("vocals", found["vocals"])
        inst = found.get("no_vocals")
        if inst:
            result["instrumental"] = inst
            publish("instrumental", inst)
    else:
        present = [l for l in layers if l in found]
        for l in present:
            result[l] = found[l]
            publish(l, found[l])
        # derived: instrumental = everything but vocals
        non_vox = [found[l] for l in present if l != "vocals"]
        if non_vox:
            inst = os.path.join(work, "instrumental.wav")
            _mix_stems(job_id, non_vox, inst, emit)
            result["instrumental"] = inst
            publish("instrumental", inst)
        if "vocals" in result:
            result["acapella"] = result["vocals"]
            publish("acapella", result["vocals"])

    result["_workdir"] = work
    result["_stem_dir"] = stem_dir
    emit(state="separating", progress=100,
         log=f"✓ Stems written to {os.path.relpath(stem_dir, cfg['out_dir'])}")
    return result


def apply_fx(job_id, src, fx_key, emit, cancel):
    """Apply the FX chain to a WAV BEFORE mastering, so loudness
    analysis measures the sound that actually ships."""
    fx = FX_RACK.get(fx_key)
    if not fx or fx_key == "none":
        return src
    if not fx_available(fx_key):
        missing = [n for n in fx["needs"] if n not in ff_filters()]
        emit(log=f"⚠ FX '{fx['label']}' unavailable in this ffmpeg "
                 f"(missing: {', '.join(missing)}) — skipped")
        return src
    chain = fx["chain"](44100)
    dur = get_duration(src) or 0
    # rate FX change output duration; estimate for the progress bar
    mt = re.search(r"asetrate=44100\*([\d.]+)", chain)
    est = dur / float(mt.group(1)) if mt else dur
    emit(state="fx", step=f"FX — {fx['label']}", progress=0,
         log=f"FX pre-pass: {fx['label']}")
    out = os.path.join(TMP_DIR, f"fx_{uuid.uuid4().hex[:8]}.wav")
    run_ff_progress(job_id,
                    ["ffmpeg", "-y", "-i", src, "-af",
                     f"aformat=channel_layouts=stereo,aresample=44100,"
                     f"{chain}",
                     "-c:a", "pcm_s16le",
                     "-progress", "pipe:1", "-nostats", out],
                    est, emit, "fx", "fx")
    emit(log=f"✓ FX applied ({fmt_hms(get_duration(out) or 0)})")
    return out


# ── Loop extension (single graph, single encode, zero gen loss) ────
def extend_audio(job_id, unit_mp3, target_secs, cfg, out_path, emit,
                 cancel):
    """Crossfade N copies of the mastered unit in ONE filtergraph and
    encode once. Global fade in/out applied on the final output."""
    unit_dur = get_duration(unit_mp3)
    if not unit_dur:
        raise RuntimeError("Could not read unit duration")
    xf = min(float(cfg.get("loop_xfade", 8)), max(1.0, unit_dur / 3))
    step = unit_dur - xf
    n = max(2, math.ceil((target_secs - unit_dur) / step) + 1)
    if n > 400:
        raise RuntimeError(f"extension needs {n} loop units — source "
                           "too short for that target")
    total = unit_dur + (n - 1) * step
    emit(state="extending",
         step=f"Extending — {n}× loop → {fmt_hms(target_secs)}",
         progress=0,
         log=f"Loop extension: {n} units, {xf:.0f}s crossfades, "
             f"single encode (no generational loss)")

    inputs = []
    for _ in range(n):
        inputs += ["-i", unit_mp3]
    fc = []
    prev = "0:a"
    for i in range(1, n):
        lab = f"x{i}"
        fc.append(f"[{prev}][{i}:a]acrossfade=d={xf:.2f}:c1=tri:c2=tri"
                  f"[{lab}]")
        prev = lab
    fade_out_start = max(0.0, target_secs - float(cfg["fade_out"]))
    fc.append(f"[{prev}]atrim=end={target_secs:.2f},"
              f"afade=t=in:st=0:d={cfg['fade_in']},"
              f"afade=t=out:st={fade_out_start:.2f}:d={cfg['fade_out']}"
              f"[out]")

    cmd = (["ffmpeg", "-y"] + inputs + [
        "-filter_complex", ";".join(fc), "-map", "[out]",
        "-b:a", cfg["bitrate"], "-map_metadata", "0",
        "-progress", "pipe:1", "-nostats", out_path])
    run_ff_progress(job_id, cmd, target_secs, emit, "extending", "ext")
    return human_size(os.path.getsize(out_path)), fmt_hms(target_secs)


def extend_video(job_id, unit_mp4, ext_audio, target_secs, out_path,
                 emit, cancel):
    """Instant long-form video: concat the unit render with -c copy
    (no re-encode) and mux the seamless extended audio over it."""
    unit_dur = get_duration(unit_mp4) or 1
    n = math.ceil(target_secs / unit_dur) + 1
    lst = os.path.join(TMP_DIR, f"vlist_{uuid.uuid4().hex[:8]}.txt")
    with open(lst, "w") as f:
        for _ in range(n):
            f.write(f"file '{unit_mp4}'\n")
    emit(state="extending",
         step=f"Extending video — {n}× concat (stream copy)",
         progress=0,
         log=f"Video extension: {n} unit copies, -c copy (instant), "
             "audio muxed from extended master")
    cmd = ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", lst,
           "-i", ext_audio,
           "-map", "0:v", "-map", "1:a",
           "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
           "-t", f"{target_secs:.2f}", "-movflags", "+faststart",
           "-progress", "pipe:1", "-nostats", out_path]
    run_ff_progress(job_id, cmd, target_secs, emit, "extending", "vext")
    try:
        os.remove(lst)
    except Exception:
        pass
    return human_size(os.path.getsize(out_path)), fmt_hms(target_secs)


# ── Creator pack: thumbnail + YouTube metadata ─────────────────────
def wrap_words(text, limit):
    out, line = [], ""
    for w in text.split():
        if len(line) + len(w) + 1 > limit and line:
            out.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out[:4]


def make_thumbnail(title, cfg, logo_path, accent, out_png, emit):
    """1280x720 YouTube-ready thumbnail: dark canvas, accent glow,
    wrapped title, brand logo, info badges."""
    try:
        from PIL import Image, ImageDraw, ImageFont, ImageFilter
    except ImportError:
        emit(log="⚠ pillow not installed — thumbnail skipped")
        return False
    W, H = 1280, 720
    img = Image.new("RGB", (W, H), (10, 9, 18))
    d = ImageDraw.Draw(img)

    # accent glow blobs
    glow = Image.new("RGB", (W, H), (10, 9, 18))
    gd = ImageDraw.Draw(glow)
    ar, ag, ab = _hex_rgb(accent or "#a855f7")
    gd.ellipse([W * 0.55, -H * 0.35, W * 1.25, H * 0.55],
               fill=(ar // 3, ag // 3, ab // 3))
    gd.ellipse([-W * 0.25, H * 0.55, W * 0.35, H * 1.35],
               fill=(ar // 5, ag // 5, ab // 5))
    glow = glow.filter(ImageFilter.GaussianBlur(120))
    img = Image.blend(img, glow, 0.85)
    d = ImageDraw.Draw(img)

    font_path, _ = find_font("cursive")

    def load_font(size):
        if font_path:
            try:
                return ImageFont.truetype(font_path, size)
            except Exception:
                pass
        try:
            return ImageFont.load_default(size=size)
        except TypeError:
            return ImageFont.load_default()

    brand = BRANDS[cfg.get("brand", "garbage")]
    # brand line
    d.text((56, 42), brand["channel"], font=load_font(46),
           fill=_hex_rgb(accent or "#a855f7"))
    d.text((58, 104), brand["slogan"], font=load_font(30),
           fill=(210, 206, 224))

    # title, wrapped
    y = 200
    for line in wrap_words(title, 20):
        f = load_font(88)
        d.text((56, y), line, font=f, fill=(255, 255, 255),
               stroke_width=4, stroke_fill=(0, 0, 0))
        y += 100

    # badges
    prof = PROFILES.get(cfg["profile"], PROFILES["med"])
    badges = [prof["desc"].split("—")[0].strip()]
    if cfg.get("binaural"):
        badges.append("BINAURAL")
    if cfg.get("fx", "none") != "none":
        badges.append(FX_RACK[cfg["fx"]]["label"].upper())
    if cfg.get("breathing", "none") != "none":
        badges.append(BREATHING[cfg["breathing"]]["label"].upper())
    if int(cfg.get("extend_min") or 0) > 0:
        h = int(cfg["extend_min"]) // 60
        mnt = int(cfg["extend_min"]) % 60
        badges.append((f"{h} HOUR" + ("S" if h > 1 else "")) if h and not mnt
                      else f"{int(cfg['extend_min'])} MIN")
    bx = 56
    f = load_font(34)
    for b in badges[:4]:
        try:
            bb = d.textbbox((0, 0), b, font=f)
            bw = bb[2] - bb[0] + 36
        except Exception:
            bw = len(b) * 20 + 36
        d.rounded_rectangle([bx, H - 110, bx + bw, H - 50], radius=14,
                            outline=_hex_rgb(accent or "#a855f7"),
                            width=3)
        d.text((bx + 18, H - 100), b, font=f, fill=(255, 255, 255))
        bx += bw + 18

    # logo
    if logo_path and os.path.exists(logo_path):
        try:
            lg = Image.open(logo_path).convert("RGBA")
            lg.thumbnail((330, 330))
            img.paste(lg, (W - lg.width - 44, H - lg.height - 44), lg)
        except Exception:
            pass

    img.save(out_png, quality=92)
    emit(log=f"✓ Thumbnail: {os.path.basename(out_png)}")
    return True


TITLE_BANK = {
    "garbage": [
        "{title} — {beat} Binaural | GARBAGE NOISE",
        "Calm The Garbage Within — {title} ({beat})",
        "{hours}{title} | Garbage Noise {beat} Session",
    ],
    "attitude": [
        "{title} — Meditation With Attitude ({beat})",
        "Sit Down. Shut Up. Breathe. — {title}",
        "{hours}{title} | {beat} Binaural With Attitude",
    ],
}


def make_metadata(title, cfg, out_txt, emit):
    brand = BRANDS[cfg.get("brand", "garbage")]
    prof = PROFILES.get(cfg["profile"], PROFILES["med"])
    hours = ""
    if int(cfg.get("extend_min") or 0) >= 60:
        hours = f"{int(cfg['extend_min']) // 60} Hour "
    titles = [t.format(title=title, beat=prof["desc"].split("—")[0].strip(),
                       hours=hours)
              for t in TITLE_BANK[cfg.get("brand", "garbage")]]

    lines = [f"=== {brand['channel']} — upload pack ===", "",
             "TITLE OPTIONS:"]
    lines += [f"  {i+1}. {t}" for i, t in enumerate(titles)]
    lines += ["", "DESCRIPTION:", "-" * 40,
              f"{brand['channel']} — {brand['slogan']}", ""]
    lines.append(f"Remastered and enhanced session: {title}")
    lines.append(f"Brainwave layer: {prof['desc']}"
                 + (" (binaural — wear headphones)"
                    if cfg.get("binaural") else ""))
    if cfg.get("fx", "none") != "none":
        lines.append(f"Texture: {FX_RACK[cfg['fx']]['label']}")
    if cfg.get("breathing", "none") != "none":
        b = BREATHING[cfg["breathing"]]
        lines += ["", f"BREATHE WITH THE SCREEN — {b['label']}",
                  b["desc"],
                  "Follow the expanding circle: "
                  + " → ".join(f"{p} {s:g}s" for p, s in b["cycle"])]
    lines += ["",
              "⚠ Do not listen to binaural audio while driving or "
              "operating machinery. Not a substitute for medical "
              "care. If you have epilepsy or a seizure condition, "
              "consult a professional before using entrainment audio.",
              "",
              "TAGS:",
              ", ".join([
                  "meditation music", "binaural beats", prof["beat"],
                  "sleep music" if cfg["profile"] == "sleep"
                  else "focus music" if cfg["profile"] == "focus"
                  else "deep meditation",
                  "breathing exercise", "breathwork", "calm",
                  "stress relief", "relaxation", "ambient",
                  brand["channel"].lower(),
                  "slowed and reverb" if cfg.get("fx") == "slowed"
                  else "lofi",
                  "hrv", "vagus nerve", "nervous system regulation",
                  "study music", "asmr ambient", "soundscape",
                  "conscious breathing", "decompress",
              ]),
              "",
              "HASHTAGS: #meditation #binauralbeats #breathwork "
              "#calm #" + brand["channel"].replace(" ", "").lower()]
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    emit(log=f"✓ Upload pack: {os.path.basename(out_txt)}")


# ── Word detection -> ASS captions (faster-whisper) ────────────────
def _ass_time(t):
    t = max(0.0, t)
    h = int(t // 3600)
    m = int((t % 3600) // 60)
    s = int(t % 60)
    cs = min(99, int(round((t - int(t)) * 100)))
    return f"{h}:{m:02d}:{s:02d}.{cs:02d}"


def transcribe_to_ass(audio_path, duration, cfg, emit, cancel):
    if not have_module("faster_whisper"):
        emit(log="⚠ faster-whisper not installed — captions skipped "
                 "(pip install faster-whisper)")
        return None, 0

    from faster_whisper import WhisperModel

    emit(state="transcribing", step="Detecting words (whisper)",
         progress=0, log=f"Whisper: model={cfg['whisper_model']} (cpu/int8)")
    model = WhisperModel(cfg["whisper_model"], device="cpu",
                         compute_type="int8")
    segments, info = model.transcribe(
        audio_path, vad_filter=True, word_timestamps=True, beam_size=1,
    )

    lines = []
    buf, buf_start, last_end = [], None, None
    wc = 0

    def flush(end):
        nonlocal buf, buf_start
        if buf:
            lines.append((buf_start, end, " ".join(buf)))
        buf, buf_start = [], None

    for seg in segments:
        if cancel.is_set():
            return None, 0
        for w in (seg.words or []):
            word = w.word.strip()
            if not word:
                continue
            wc += 1
            if buf_start is None:
                buf_start = w.start
            if last_end is not None and w.start - last_end > 0.8:
                flush(last_end)
                buf_start = w.start
            buf.append(word)
            last_end = w.end
            if len(buf) >= 6 or (w.end - buf_start) > 3.5:
                flush(w.end)
        if duration:
            emit(state="transcribing",
                 progress=min(99.0, seg.end / duration * 100))
    if last_end is not None:
        flush(last_end)

    if not lines:
        emit(log="No words detected — rendering without captions.")
        return None, 0

    font_path, family = find_font("cursive")
    fontname = family or "DejaVu Sans"

    W, H = cfg["video_res"].split("x")
    ass = [
        "[Script Info]",
        "ScriptType: v4.00+",
        f"PlayResX: {W}",
        f"PlayResY: {H}",
        "WrapStyle: 0",
        "",
        "[V4+ Styles]",
        "Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, "
        "OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, "
        "ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, "
        "Alignment, MarginL, MarginR, MarginV, Encoding",
        f"Style: GN,{fontname},58,&H00FFFFFF,&H00FFFFFF,&H00000000,"
        "&H96000000,-1,0,0,0,100,100,0,0,1,3,2,5,60,60,40,1",
        "",
        "[Events]",
        "Format: Layer, Start, End, Style, Name, MarginL, MarginR, "
        "MarginV, Effect, Text",
    ]
    for start, end, text in lines:
        text = text.replace("{", "(").replace("}", ")").replace("\n", " ")
        ass.append(
            f"Dialogue: 0,{_ass_time(start)},{_ass_time(end)},GN,,0,0,0,,"
            f"{{\\fad(120,120)}}{text}"
        )

    ass_path = os.path.join(TMP_DIR, f"cap_{uuid.uuid4().hex[:8]}.ass")
    with open(ass_path, "w", encoding="utf-8") as f:
        f.write("\n".join(ass) + "\n")
    emit(progress=100, log=f"✓ {wc} words detected → captions ready "
                           f"({len(lines)} lines)")
    return ass_path, wc


# ── ffmpeg escaping helpers ────────────────────────────────────────
def esc_drawtext(s):
    return (s.replace("\\", "\\\\").replace(":", "\\:")
             .replace("'", "\\\u2019").replace("%", "\\%")
             .replace(",", "\\,"))


def esc_filterpath(p):
    return (p.replace("\\", "\\\\").replace(":", "\\:")
             .replace("'", "\\'").replace(",", "\\,"))


# ── Visualizer filter builder ──────────────────────────────────────
def build_viz_filter(viz, W, H, fps, accent, accent2):
    """Return (filter producing [viz] from [0:a], viz_height).
    NOTE: never chain the fps filter after these — the timebase
    mismatch duplicates frames without bound and the render gets
    OOM-killed. Native rate options + output -r only."""
    vh = int(H * 0.48)
    vh -= vh % 2
    a1 = accent or "#a855f7"
    a2 = accent2 or "#d946ef"
    if viz == "cqt":
        f = (f"showcqt=s={W}x{vh}:r={fps}:count=2:bar_g=2:sono_g=4:"
             f"bar_v=9:sono_v=17:axis=0")
    elif viz == "spectrum":
        # showspectrum has no rate option; output -r normalizes it
        f = (f"showspectrum=s={W}x{vh}:slide=scroll:mode=combined:"
             f"color=magma:scale=cbrt:legend=0")
    elif viz == "waves":
        f = (f"showwaves=s={W}x{vh}:r={fps}:mode=cline:colors={a1}|{a2}:"
             f"scale=sqrt:draw=full")
    else:  # bars
        f = (f"showfreqs=s={W}x{vh}:rate={fps}:mode=bar:ascale=log:"
             f"fscale=log:colors={a1}|{a2}")
    return f"[0:a]{f},format=rgba[viz]", vh


# ── Video render pass ──────────────────────────────────────────────
def render_video(job_id, audio_in, video_out, title, cfg, emit, cancel):
    duration = get_duration(audio_in)
    if not duration:
        raise RuntimeError("Could not read mastered audio duration")

    W, H = (int(x) for x in cfg["video_res"].split("x"))
    fps = int(cfg.get("video_fps", 30))
    brand = BRANDS.get(cfg.get("brand", "garbage"), BRANDS["garbage"])

    rnd = random.Random(f"{title}:{time.time_ns()}")
    viz = cfg["viz"]
    if viz == "auto" or viz not in VIZ_MODES:
        viz = rnd.choice(VIZ_MODES)

    # captions (optional)
    ass_path, _wc = (None, 0)
    if cfg["captions"]:
        ass_path, _wc = transcribe_to_ass(audio_in, duration, cfg,
                                          emit, cancel)
    if cancel.is_set():
        raise RuntimeError("Cancelled")

    # logo (randomized every render)
    logo_path, accent = make_logo(title, cfg.get("brand", "garbage"),
                                  emit, rnd)
    _n, a1, a2 = next((a for a in ACCENTS if a[1] == accent),
                      rnd.choice(ACCENTS))
    cfg["_accent"] = a1
    cfg["_logo"] = logo_path

    # breathing (optional)
    breathing = cfg.get("breathing", "none")
    pacer_pattern = cue_wav = None
    if breathing != "none" and breathing in BREATHING:
        pacer_pattern, _cyc, _n_frames = make_breath_pacer(breathing, a1,
                                                           emit)
        cue_wav = make_breath_cues(breathing)

    emit(state="rendering",
         step=f"Video pass — {viz} · {W}x{H} · {brand['tag']}",
         progress=0,
         log=f"Rendering: viz={viz}, res={W}x{H}@{fps}, "
             f"captions={'on' if ass_path else 'off'}, "
             f"logo={'on' if logo_path else 'off'}, "
             f"breathing={breathing}")

    # ── inputs (indices tracked dynamically) ──
    inputs = ["-i", audio_in,
              "-f", "lavfi", "-t", f"{duration + 1:.2f}", "-i",
              f"color=c=0x07060b:s={W}x{H}:r={fps}"]
    idx = 2
    logo_idx = mandala_idx = pacer_idx = cue_idx = None
    mandala_path = None

    if logo_path:
        inputs += ["-i", logo_path]
        logo_idx = idx
        idx += 1
    if viz == "geometry":
        mandala_path = make_mandala(a1, size=min(H - 40, 760))
        if mandala_path:
            inputs += ["-i", mandala_path]
            mandala_idx = idx
            idx += 1
    if pacer_pattern:
        inputs += ["-stream_loop", "-1", "-framerate", str(PACER_FPS),
                   "-i", pacer_pattern]
        pacer_idx = idx
        idx += 1
    if cue_wav:
        inputs += ["-stream_loop", "-1", "-i", cue_wav]
        cue_idx = idx
        idx += 1

    brand_font, _fam = find_font("cursive")
    fontfile = f":fontfile='{esc_filterpath(brand_font)}'" if brand_font else ""

    t_title = esc_drawtext(title[:70])
    t_brand = esc_drawtext(brand["channel"])
    t_slog = esc_drawtext(brand["slogan"])

    fc = [f"[1:v]vignette=PI/4.6[bg]"]

    if viz == "geometry":
        # electric geometry: rotating mandala + audio-driven lissajous
        rr, gg, bb = _hex_rgb(a1)
        side = min(H - 60, 700)
        side -= side % 2
        fc.append(
            f"[0:a]avectorscope=s={side}x{side}:r={fps}:"
            f"mode=lissajous_xy:draw=line:scale=cbrt:zoom=1.6:"
            f"rc={rr}:gc={gg}:bc={bb}:rf=4:gf=4:bf=4,format=rgba[scope]"
        )
        last = "bg"
        if mandala_idx is not None:
            fc.append(f"[{mandala_idx}:v]format=rgba,"
                      f"rotate=0.12*t:c=black@0:ow=iw:oh=ih[mand]")
            fc.append(f"[{last}][mand]overlay="
                      f"(W-w)/2:(H-h)/2:shortest=0[g1]")
            last = "g1"
        fc.append(f"[{last}][scope]overlay=(W-w)/2:(H-h)/2:"
                  f"shortest=1[v1]")
    else:
        viz_filter, vh = build_viz_filter(viz, W, H, fps, a1, a2)
        fc.append(viz_filter)
        fc.append(f"[bg][viz]overlay=0:{H - vh}:shortest=1[v1]")
    last = "v1"

    if logo_idx is not None:
        lw = int(W * 0.155)
        fc.append(f"[{logo_idx}:v]scale={lw}:-1[logo]")
        fc.append(f"[{last}][logo]overlay=W-w-26:26[v2]")
        last = "v2"

    if pacer_idx is not None:
        ps = int(H * 0.44)
        # bottom-left, above nothing when geometry; same spot always
        fc.append(f"[{pacer_idx}:v]scale={ps}:-1[pacer]")
        fc.append(f"[{last}][pacer]overlay=34:H-h-34:shortest=1[v2b]")
        last = "v2b"

    fc.append(
        f"[{last}]"
        f"drawtext=text='{t_title}'{fontfile}:fontsize={int(H*0.075)}:"
        f"fontcolor=white:borderw=3:bordercolor=black@0.85:"
        f"x=(w-text_w)/2:y=h*0.16:"
        f"alpha='if(lt(t,1),t,if(lt(t,5.5),1,max(0,(7-t)/1.5)))',"
        f"drawtext=text='{t_brand}'{fontfile}:fontsize={int(H*0.045)}:"
        f"fontcolor={a1}:borderw=2:bordercolor=black@0.85:x=30:y=26,"
        f"drawtext=text='{t_slog}'{fontfile}:fontsize={int(H*0.028)}:"
        f"fontcolor=white@0.85:borderw=2:bordercolor=black@0.8:"
        f"x=32:y=26+{int(H*0.06)}"
        f"[v3]"
    )
    last = "v3"

    if ass_path:
        fontsdir = ""
        if brand_font:
            fontsdir = f":fontsdir='{esc_filterpath(os.path.dirname(brand_font))}'"
        fc.append(f"[{last}]subtitles=filename='{esc_filterpath(ass_path)}'"
                  f"{fontsdir}[vout]")
        last = "vout"

    # audio: mix breathing cues in quietly if present
    audio_map = "0:a"
    if cue_idx is not None:
        fc.append(f"[0:a][{cue_idx}:a]amix=inputs=2:duration=first:"
                  f"weights=1 0.14:normalize=0[aout]")
        audio_map = "[aout]"

    enc_args, is_hw, enc_label = pick_video_encoder()
    emit(log=f"Video encoder: {enc_label}")

    cmd = (["ffmpeg", "-y"] + inputs + [
        "-filter_complex", ";".join(fc),
        "-map", f"[{last}]", "-map", audio_map,
        "-r", str(fps),
        "-c:v"] + enc_args + [
        "-g", str(fps * 2),  # 2s GOP -> precise -c copy cuts on extend
        "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "192k",
        "-shortest", "-movflags", "+faststart",
        "-metadata", f"title={title}",
        "-metadata", f"artist={brand['channel']}",
        "-metadata", f"comment={brand['channel']} | {brand['slogan']} | "
                     f"viz={viz} | {cfg['profile']}",
        "-progress", "pipe:1", "-nostats", video_out,
    ])

    try:
        try:
            run_ff_progress(job_id, cmd, duration, emit, "rendering", "ffv")
        except RuntimeError:
            if is_hw:
                global _video_encoder
                emit(log=f"⚠ {enc_label} failed on this device — "
                         "falling back to software libx264 for the rest "
                         "of this session (slower but always works)")
                _video_encoder = (["libx264", "-preset", "ultrafast",
                                   "-crf", "26"], False,
                                  "libx264 ultrafast (fallback)")
                sw_args, _, _ = _video_encoder
                cv_idx = cmd.index("-c:v")
                # splice out the old -c:v args up to -g, put software in
                g_idx = cmd.index("-g")
                cmd = cmd[:cv_idx + 1] + sw_args + cmd[g_idx:]
                run_ff_progress(job_id, cmd, duration, emit, "rendering",
                                "ffv")
            else:
                raise
    finally:
        for p in (ass_path, mandala_path, cue_wav):
            if p:
                try:
                    os.remove(p)
                except Exception:
                    pass
        if pacer_pattern:
            for f in glob.glob(pacer_pattern.replace("%04d", "*")):
                try:
                    os.remove(f)
                except Exception:
                    pass

    if not os.path.exists(video_out):
        raise RuntimeError("video render produced no output")
    return human_size(os.path.getsize(video_out)), fmt_hms(duration)


# ── ffmpeg audio mastering (the proven v2.0 chain + polish) ────────
def analyze_loudness(inp, cfg):
    cmd = ["ffmpeg", "-i", inp, "-af",
           f"loudnorm=I={cfg['lufs']}:TP={cfg['true_peak']}:LRA=11:print_format=json",
           "-f", "null", "-"]
    txt = subprocess.run(cmd, capture_output=True, text=True).stderr
    blocks = re.findall(r"\{[^{}]+\}", txt, re.DOTALL)
    if not blocks:
        return dict(i="0", tp="0", lra="0", thresh="0", offset="0")
    try:
        d = json.loads(blocks[-1])
        return dict(
            i=d.get("input_i", "0"), tp=d.get("input_tp", "0"),
            lra=d.get("input_lra", "0"), thresh=d.get("input_thresh", "0"),
            offset=d.get("target_offset", "0"),
        )
    except Exception:
        return dict(i="0", tp="0", lra="0", thresh="0", offset="0")


def loudnorm_filter(cfg, m):
    return (f"loudnorm=I={cfg['lufs']}:TP={cfg['true_peak']}:LRA=11"
            f":measured_I={m['i']}:measured_TP={m['tp']}:measured_LRA={m['lra']}"
            f":measured_thresh={m['thresh']}:offset={m['offset']}:linear=true")


def build_chain(cfg, duration, lnf, unit_fades=True):
    hpf = "highpass=f=40"
    eq = ("equalizer=f=280:t=q:width=1.5:g=-2.5,"
          "equalizer=f=6000:t=q:width=1.5:g=-1.5")
    gate = "agate=threshold=0.002:attack=10:release=500:makeup=1"
    comp = ("acompressor=threshold=0.125:ratio=2:attack=200:"
            "release=1000:makeup=1:knee=4")
    parts = [hpf, eq, gate, comp]
    # golden polish: gentle harmonic sheen + subtle width (only when
    # this ffmpeg build has the filters)
    if cfg.get("polish"):
        if "crystalizer" in ff_filters():
            parts.append("crystalizer=i=1.2")
        if "extrastereo" in ff_filters():
            parts.append("extrastereo=m=1.12:c=1")
    if unit_fades:
        fade_out_start = max(0.0, duration - float(cfg["fade_out"]))
        parts.append(f"afade=t=in:st=0:d={cfg['fade_in']},"
                     f"afade=t=out:st={fade_out_start}:d={cfg['fade_out']}")
    parts.append(lnf)
    return ",".join(parts)


def process_audio(job_id, inp, out, title, cfg, emit, unit_fades=True):
    emit(state="analyzing", step="Analyzing input", progress=0,
         log=f"Analyzing {os.path.basename(inp)} ...")
    duration = get_duration(inp)
    if not duration:
        raise RuntimeError("Could not read duration")

    emit(step="Pass 1 — loudness analysis", log="Pass 1: measuring loudness ...")
    m = analyze_loudness(inp, cfg)
    lnf = loudnorm_filter(cfg, m)
    chain = build_chain(cfg, duration, lnf, unit_fades=unit_fades)

    emit(step="Pass 2 — mastering", log=f"Pass 2: encoding ({fmt_hms(duration)}) ...")
    brand = BRANDS.get(cfg.get("brand", "garbage"), BRANDS["garbage"])
    meta_comment = (f"{brand['channel']} | {cfg['profile']} | "
                    f"{cfg['lufs']} LUFS | "
                    f"Binaural {'ON' if cfg['binaural'] else 'OFF'}"
                    + (f" | FX {cfg['fx']}" if cfg.get('fx', 'none') != 'none'
                       else ""))

    if cfg["binaural"]:
        fl, fr = PROFILES.get(cfg["profile"], PROFILES["med"])["hz"]
        # normalize=0 keeps main at 0.96 (no clipping); 0.04 binaural ≈ -28dBFS
        fc = (
            "[0:a]aformat=channel_layouts=stereo[main];"
            f"[1:a]atrim=end={duration}[bin];"
            "[main]channelsplit=channel_layout=stereo[mL][mR];"
            "[bin]channelsplit=channel_layout=stereo[bL][bR];"
            "[mL][bL]amix=inputs=2:weights=0.96 0.04:normalize=0[oL];"
            "[mR][bR]amix=inputs=2:weights=0.96 0.04:normalize=0[oR];"
            "[oL][oR]amerge=inputs=2[merged];"
            f"[merged]{chain}[out]"
        )
        cmd = ["ffmpeg", "-y", "-i", inp,
               "-f", "lavfi", "-i",
               f"aevalsrc=sin(2*PI*{fl}*t)|sin(2*PI*{fr}*t):c=stereo:s=44100",
               "-filter_complex", fc, "-map", "[out]",
               "-b:a", cfg["bitrate"], "-map_metadata", "0",
               "-metadata", f"title={title}",
               "-metadata", f"comment={meta_comment}",
               "-progress", "pipe:1", "-nostats", out]
    else:
        fc = f"[0:a]aformat=channel_layouts=stereo[main];[main]{chain}[out]"
        cmd = ["ffmpeg", "-y", "-i", inp,
               "-filter_complex", fc, "-map", "[out]",
               "-b:a", cfg["bitrate"], "-map_metadata", "0",
               "-metadata", f"title={title}",
               "-metadata", f"comment={meta_comment}",
               "-progress", "pipe:1", "-nostats", out]

    run_ff_progress(job_id, cmd, duration, emit, "encoding", "ff")

    if not os.path.exists(out):
        raise RuntimeError("mastering produced no output")
    size = human_size(os.path.getsize(out))
    return size, fmt_hms(duration)


# ── Download (yt-dlp) ──────────────────────────────────────────────
_ytdlp_cmd = None


def ytdlp_base():
    """Resolve how to invoke yt-dlp on THIS machine, once.
    Tries: yt-dlp on PATH → ~/.local/bin/yt-dlp (pip user installs land
    here and are often off PATH) → `python3 -m yt_dlp` module fallback.
    Returns a command-prefix list, or None if yt-dlp is truly absent."""
    global _ytdlp_cmd
    if _ytdlp_cmd is not None:
        return _ytdlp_cmd or None
    # 1) on PATH
    p = shutil.which("yt-dlp")
    if p:
        _ytdlp_cmd = [p]
        return _ytdlp_cmd
    # 2) common pip --user location that isn't on PATH
    for cand in (os.path.expanduser("~/.local/bin/yt-dlp"),
                 os.path.join(os.environ.get("PREFIX", ""), "bin", "yt-dlp")):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            _ytdlp_cmd = [cand]
            return _ytdlp_cmd
    # 3) installed as a module but no console script on PATH
    if have_module("yt_dlp"):
        _ytdlp_cmd = [sys.executable, "-m", "yt_dlp"]
        return _ytdlp_cmd
    _ytdlp_cmd = []  # cache the negative
    return None


def ytdlp_ok():
    return ytdlp_base() is not None


def download(url, emit):
    base = ytdlp_base()
    if base is None:
        raise RuntimeError(
            "yt-dlp is not installed in this environment. Install it where "
            "the server runs:  pip install -U yt-dlp  (Termux: pkg install "
            "python-yt-dlp).  If pip put it in ~/.local/bin, add that to PATH "
            "or just restart the server — it also finds it there.")

    tmp_id = uuid.uuid4().hex[:8]
    template = os.path.join(TMP_DIR, f"dl_{tmp_id}.%(ext)s")

    title_out = subprocess.run(
        base + ["--no-playlist", "--print", "%(title)s", url],
        capture_output=True, text=True,
    ).stdout.strip().splitlines()
    title = title_out[0] if title_out else f"unknown-{int(time.time())}"
    emit(state="downloading", progress=0, log=f"Title: {title}")

    proc = subprocess.Popen(
        base + ["--no-playlist", "-x", "--audio-format", "wav",
                "--audio-quality", "0", "--newline", "-o", template, url],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    for line in proc.stdout:
        mt = re.search(r"\[download\]\s+([\d.]+)%", line)
        if mt:
            emit(state="downloading", progress=float(mt.group(1)))
    proc.wait()

    files = glob.glob(os.path.join(TMP_DIR, f"dl_{tmp_id}.*"))
    if not files:
        raise RuntimeError(
            "yt-dlp downloaded nothing — the URL may be unavailable, "
            "region-locked, age-gated, or need a cookies file. Try the "
            "URL in a browser, or update yt-dlp (sites change often): "
            "pip install -U yt-dlp")
    return files[0], title, tmp_id


def clean_tmp(tmp_id):
    for f in glob.glob(os.path.join(TMP_DIR, f"dl_{tmp_id}.*")):
        try:
            os.remove(f)
        except Exception:
            pass


def expand_sources(payload):
    """Return list of (kind, value) work items. kind in {url, file}."""
    t = payload.get("type")
    if t == "url":
        return [("url", payload["url"].strip())]
    if t == "local":
        return [("file", payload["path"])]
    if t == "batch":
        raw = payload.get("urls", "")
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                items.append(("url", line))
        if len(items) == 1 and items[0][1].startswith("http"):
            base = ytdlp_base()
            if base:
                try:
                    flat = subprocess.run(
                        base + ["--flat-playlist", "--print", "url",
                                items[0][1]],
                        capture_output=True, text=True,
                    ).stdout.strip().splitlines()
                    if len(flat) > 1:
                        return [("url", u) for u in flat]
                except Exception:
                    pass
        return items
    return []


# ── Job runner (the golden pipeline) ───────────────────────────────
JOB_KEYS = ("profile", "binaural", "brand", "fx", "polish", "video",
            "captions", "viz", "breathing", "creator_pack", "extend_min",
            "comp_order", "slow", "slow_pct", "stems", "stem_model",
            "stem_source", "stem_pipeline")


def run_job(job_id, payload):
    q = JOBS[job_id]["q"]
    cancel = JOBS[job_id]["cancel"]

    def emit(**kw):
        q.put(kw)

    cfg = dict(CFG)
    for k in JOB_KEYS:
        if k in payload:
            cfg[k] = payload[k]

    extend_secs = max(0, int(cfg.get("extend_min") or 0)) * 60

    out_root = os.path.join(cfg["out_dir"], profile_slug(cfg["profile"]))
    os.makedirs(out_root, exist_ok=True)

    items = expand_sources(payload)
    total = len(items)
    if total == 0:
        emit(state="error", message="No input provided")
        q.put(None)
        return

    ok = fail = skip = 0
    for idx, (kind, value) in enumerate(items, 1):
        if cancel.is_set():
            emit(log="Cancelled.")
            break
        emit(state="track", index=idx, total=total,
             log=f"── [{idx}/{total}] ──")
        tmp_id = None
        scratch = []
        try:
            # 1) source
            if kind == "url":
                emit(state="downloading", log=f"Downloading: {value}")
                src, title, tmp_id = download(value, emit)
                if not src:
                    raise RuntimeError("Download failed")
            else:
                src = value
                if not os.path.isfile(src):
                    raise RuntimeError(f"File not found: {src}")
                title = os.path.splitext(os.path.basename(src))[0]

            # 1b) standalone slow (pre-everything). tempo keeps pitch;
            #     tape drops it. This is separate from the "screwed" FX.
            if cfg.get("slow", "off") != "off":
                if cancel.is_set():
                    raise RuntimeError("Cancelled")
                slowed = apply_slow(job_id, src, cfg["slow"],
                                    cfg.get("slow_pct", 85), emit, cancel)
                if slowed != src:
                    scratch.append(slowed)
                    src = slowed

            # 1c) stem separation (Demucs). Publishes all layers +
            #     instrumental + acapella. Optionally routes one layer
            #     into the rest of the golden pipeline.
            if cfg.get("stems", "off") != "off":
                if cancel.is_set():
                    raise RuntimeError("Cancelled")
                emit(state="separating", index=idx, total=total,
                     title=title)
                stems_res = separate_stems(job_id, src, title, cfg,
                                           out_root, emit, cancel)
                if stems_res:
                    workdir = stems_res.pop("_workdir", None)
                    stems_res.pop("_stem_dir", None)
                    if workdir:
                        scratch.append(("_dir", workdir))
                    if cfg.get("stem_pipeline"):
                        pick = cfg.get("stem_source", "mix")
                        chosen = stems_res.get(pick) or stems_res.get("mix")
                        if chosen and chosen != src:
                            src = chosen
                            title = f"{title} ({pick})"
                            emit(log=f"Routing '{pick}' stem into the "
                                     "golden pipeline")
                    else:
                        # stems-only run: done with this track
                        emit(state="track_done", index=idx, total=total,
                             log=f"✓ {title} — stems complete")
                        ok += 1
                        continue

            filename = gen_filename(title, cfg)
            stem = os.path.splitext(filename)[0]
            out_path = os.path.join(out_root, filename)
            vid_path = os.path.join(out_root, stem + ".mp4")

            audio_exists = os.path.exists(out_path)
            video_needed = bool(cfg.get("video"))
            video_exists = os.path.exists(vid_path)

            if cfg["skip_existing"] and audio_exists and \
                    (not video_needed or video_exists):
                emit(log=f"Exists, skipping: {filename}")
                skip += 1
                continue

            if not (cfg["skip_existing"] and audio_exists):
                # 2) compilation remix
                if cfg.get("comp_order", "off") != "off":
                    if cancel.is_set():
                        raise RuntimeError("Cancelled")
                    new = remix_compilation(job_id, src,
                                            cfg["comp_order"], emit,
                                            cancel)
                    if new != src:
                        scratch.append(new)
                        src = new

                # 3) FX rack (pre-master)
                if cancel.is_set():
                    raise RuntimeError("Cancelled")
                fxd = apply_fx(job_id, src, cfg.get("fx", "none"),
                               emit, cancel)
                if fxd != src:
                    scratch.append(fxd)
                    src = fxd

                # 4) master. When extending, unit gets NO end fades —
                #    global fades go on the final long file instead.
                if cancel.is_set():
                    raise RuntimeError("Cancelled")
                if extend_secs > 0:
                    unit_path = os.path.join(TMP_DIR,
                                             f"unit_{uuid.uuid4().hex[:8]}.mp3")
                    scratch.append(unit_path)
                    emit(state="processing", filename=filename, title=title)
                    size, dur = process_audio(job_id, src, unit_path,
                                              title, cfg, emit,
                                              unit_fades=False)
                    emit(log=f"✓ unit mastered ({size}, {dur})")
                    # 5) loop-extend to target in one encode
                    if cancel.is_set():
                        raise RuntimeError("Cancelled")
                    esize, edur = extend_audio(job_id, unit_path,
                                               extend_secs, cfg,
                                               out_path, emit, cancel)
                    emit(state="track_done", index=idx, total=total,
                         filename=filename, size=esize, duration=edur,
                         log=f"✓ {filename}  ({esize}, {edur})")
                    log(f"OK {title} -> {out_path} ({edur}, {esize})")
                    audio_unit_for_video = unit_path
                else:
                    emit(state="processing", filename=filename, title=title)
                    size, dur = process_audio(job_id, src, out_path,
                                              title, cfg, emit)
                    emit(state="track_done", index=idx, total=total,
                         filename=filename, size=size, duration=dur,
                         log=f"✓ {filename}  ({size}, {dur})")
                    log(f"OK {title} -> {out_path} ({dur}, {size})")
                    audio_unit_for_video = out_path
            else:
                emit(log=f"Audio exists — reusing {filename}")
                audio_unit_for_video = out_path

            if cancel.is_set():
                raise RuntimeError("Cancelled")

            # 6) video (+ breathing, geometry, captions, brand)
            if video_needed:
                if extend_secs > 0:
                    unit_vid = os.path.join(TMP_DIR,
                                            f"uvid_{uuid.uuid4().hex[:8]}.mp4")
                    scratch.append(unit_vid)
                    emit(state="rendering", filename=os.path.basename(vid_path),
                         title=title)
                    render_video(job_id, audio_unit_for_video, unit_vid,
                                 title, cfg, emit, cancel)
                    if cancel.is_set():
                        raise RuntimeError("Cancelled")
                    vsize, vdur = extend_video(job_id, unit_vid,
                                               out_path, extend_secs,
                                               vid_path, emit, cancel)
                else:
                    emit(state="rendering",
                         filename=os.path.basename(vid_path), title=title)
                    vsize, vdur = render_video(job_id,
                                               audio_unit_for_video,
                                               vid_path, title, cfg,
                                               emit, cancel)
                emit(state="track_done", index=idx, total=total,
                     filename=os.path.basename(vid_path), size=vsize,
                     duration=vdur,
                     log=f"✓ {os.path.basename(vid_path)}  ({vsize}, {vdur})")
                log(f"OK VIDEO {title} -> {vid_path} ({vdur}, {vsize})")

            # 7) creator pack: thumbnail + upload metadata
            if cfg.get("creator_pack"):
                emit(state="packing", step="Creator pack",
                     log="Building thumbnail + upload metadata ...")
                accent = cfg.get("_accent")
                logo = cfg.get("_logo")
                if not logo:
                    logo, accent = make_logo(title,
                                             cfg.get("brand", "garbage"),
                                             emit)
                    if logo:
                        scratch.append(logo)
                make_thumbnail(title, cfg, logo,
                               accent or "#a855f7",
                               os.path.join(out_root, stem + "_thumb.png"),
                               emit)
                make_metadata(title, cfg,
                              os.path.join(out_root, stem + "_youtube.txt"),
                              emit)
            # logo from render_video lives in TMP; clean it
            if cfg.get("_logo"):
                scratch.append(cfg.pop("_logo"))
                cfg.pop("_accent", None)

            ok += 1
        except Exception as e:
            emit(state="track_fail", index=idx, total=total,
                 log=f"✗ {str(e).splitlines()[0]}")
            log(f"FAIL {value}: {e}")
            fail += 1
        finally:
            if tmp_id:
                clean_tmp(tmp_id)
            for p in scratch:
                try:
                    if isinstance(p, tuple) and p[0] == "_dir":
                        shutil.rmtree(p[1], ignore_errors=True)
                    else:
                        os.remove(p)
                except Exception:
                    pass

    emit(state="done", ok=ok, fail=fail, skip=skip,
         out_dir=out_root,
         log=f"Complete — {ok} ok, {skip} skipped, {fail} failed")
    q.put(None)


# ── Flask app ──────────────────────────────────────────────────────
app = Flask(__name__)

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
  <title>Golden Master · Garbage Noise / Meditation With Attitude</title>
  <style>
:root {
  --bg:        #0a0912;
  --bg-2:      #0f0d1a;
  --panel:     #151221;
  --panel-2:   #1b1730;
  --border:    rgba(168, 85, 247, 0.14);
  --border-2:  rgba(168, 85, 247, 0.28);
  --text:      #e9e6f4;
  --muted:     #8b85a6;
  --faint:     #5c5675;

  --primary:   #a855f7;
  --primary-2: #d946ef;
  --cyan:      #34d2ee;
  --green:     #34d399;
  --red:       #f87171;
  --amber:     #fbbf24;

  --grad: linear-gradient(135deg, #a855f7 0%, #d946ef 100%);
  --glow: 0 0 24px rgba(168, 85, 247, 0.35);
  --radius: 16px;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, system-ui, sans-serif;
  --script: "Dancing Script", "Pacifico", "Segoe Script", "Comic Sans MS", cursive;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }

body {
  font-family: var(--sans);
  background:
    radial-gradient(1200px 600px at 80% -10%, rgba(217,70,239,0.10), transparent 60%),
    radial-gradient(900px 500px at -10% 110%, rgba(52,210,238,0.08), transparent 55%),
    var(--bg);
  color: var(--text);
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
}

.app { display: flex; height: 100vh; }

/* ── Sidebar ───────────────────────────────────────────────────── */
.sidebar {
  width: 232px; flex-shrink: 0;
  background: linear-gradient(180deg, var(--bg-2), var(--bg));
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column; padding: 22px 16px;
}
.brand { display: flex; align-items: center; gap: 12px; padding: 4px 6px 26px; }
.brand-orb {
  width: 34px; height: 34px; border-radius: 50%;
  background: var(--grad); box-shadow: var(--glow);
  animation: breathe 5s ease-in-out infinite;
  display: grid; place-items: center; font-size: 17px; line-height: 1;
}
.brand-orb::after { content: "☻"; color: #0a0912; }
.brand-text { display: flex; flex-direction: column; line-height: 1.1; }
.brand-name { font-weight: 700; letter-spacing: 1px; font-size: 14px; }
.brand-sub { font-size: 11px; color: var(--muted); letter-spacing: 0.5px; font-family: var(--script); }

.nav { display: flex; flex-direction: column; gap: 4px; }
.nav-item {
  display: flex; align-items: center; gap: 12px;
  background: transparent; border: none; cursor: pointer;
  color: var(--muted); font-size: 14px; font-family: var(--sans);
  padding: 11px 14px; border-radius: 11px; text-align: left;
  transition: all 0.16s ease;
}
.nav-item:hover { background: var(--panel); color: var(--text); }
.nav-item.active {
  background: var(--panel-2); color: var(--text);
  box-shadow: inset 0 0 0 1px var(--border-2);
}
.nav-ico { font-size: 16px; width: 18px; text-align: center; opacity: 0.9; }

.sidebar-foot { margin-top: auto; padding: 10px 6px 0; }
.dep-row { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
.dep {
  font-family: var(--mono); font-size: 10.5px; padding: 3px 8px;
  border-radius: 6px; background: var(--panel); color: var(--faint);
  border: 1px solid var(--border);
}
.dep.ok  { color: var(--green); border-color: rgba(52,211,153,0.3); }
.dep.bad { color: var(--red);   border-color: rgba(248,113,113,0.3); }
.ver { font-size: 11px; color: var(--faint); font-family: var(--mono); }

/* ── Main / views ──────────────────────────────────────────────── */
.main { flex: 1; overflow-y: auto; padding: 34px 40px 60px; }
.view { display: none; max-width: 920px; margin: 0 auto; animation: fade 0.3s ease; }
.view.active { display: block; }
.view-head { margin-bottom: 24px; }
.view-head h1 { font-size: 26px; font-weight: 700; letter-spacing: -0.3px; }
.view-head .muted { margin-top: 4px; font-size: 14px; }
.muted { color: var(--muted); }

.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
.card {
  background: linear-gradient(180deg, var(--panel), var(--bg-2));
  border: 1px solid var(--border);
  border-radius: var(--radius); padding: 20px;
}
.card.span2 { grid-column: 1 / -1; }
.card-title {
  font-size: 12px; text-transform: uppercase; letter-spacing: 1.2px;
  color: var(--muted); margin-bottom: 14px; font-weight: 600;
}
.card-title .accent { color: var(--primary-2); font-family: var(--script);
  text-transform: none; letter-spacing: 0; font-size: 14px; }

/* ── Controls ──────────────────────────────────────────────────── */
.seg {
  display: flex; gap: 4px; background: var(--bg);
  padding: 4px; border-radius: 11px; margin-bottom: 14px;
  border: 1px solid var(--border);
}
.seg.tight { margin-bottom: 0; }
.seg-btn {
  flex: 1; background: transparent; border: none; cursor: pointer;
  color: var(--muted); font-size: 13px; font-family: var(--sans);
  padding: 8px; border-radius: 8px; transition: all 0.15s ease;
}
.seg-btn.active { background: var(--panel-2); color: var(--text); box-shadow: var(--glow); }

.src-pane { display: none; }
.src-pane.active { display: block; animation: fade 0.2s ease; }

.field {
  width: 100%; background: var(--bg); color: var(--text);
  border: 1px solid var(--border); border-radius: 10px;
  padding: 12px 14px; font-size: 14px; font-family: var(--sans);
  transition: border 0.15s ease, box-shadow 0.15s ease;
}
.field:focus { outline: none; border-color: var(--primary); box-shadow: var(--glow); }
.field::placeholder { color: var(--faint); }
.field.area { resize: vertical; font-family: var(--mono); font-size: 13px; line-height: 1.5; }
.field.sm { width: 130px; }
.field.xs { width: 92px; }
select.field { appearance: none; }

.drop {
  display: flex; flex-direction: column; align-items: center; gap: 8px;
  padding: 26px; border: 1.5px dashed var(--border-2); border-radius: 12px;
  cursor: pointer; transition: all 0.18s ease; text-align: center;
}
.drop:hover, .drop.over { border-color: var(--primary); background: rgba(168,85,247,0.05); }
.drop-ico { font-size: 24px; color: var(--primary); }
.drop-text { font-size: 13px; color: var(--muted); }
.or { text-align: center; font-size: 12px; color: var(--faint); margin: 12px 0; }

.profiles { display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }
.prof {
  display: flex; align-items: center; gap: 12px; cursor: pointer;
  padding: 12px 14px; border-radius: 11px; border: 1px solid var(--border);
  background: var(--bg); transition: all 0.16s ease;
}
.prof:hover { border-color: var(--border-2); }
.prof.active { border-color: var(--primary); background: rgba(168,85,247,0.08); box-shadow: var(--glow); }
.prof-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.prof-dot.sleep { background: #6366f1; }
.prof-dot.med   { background: var(--primary); }
.prof-dot.focus { background: var(--cyan); }
.prof-info { display: flex; flex-direction: column; line-height: 1.25; }
.prof-name { font-size: 14px; font-weight: 600; }
.prof-desc { font-size: 11.5px; color: var(--muted); }

.toggle { display: flex; align-items: center; gap: 11px; cursor: pointer; user-select: none; }
.toggle input { display: none; }
.toggle-track {
  width: 42px; height: 24px; border-radius: 12px; background: var(--bg-2);
  border: 1px solid var(--border); position: relative; transition: all 0.2s ease;
  flex-shrink: 0;
}
.toggle-thumb {
  position: absolute; top: 2px; left: 2px; width: 18px; height: 18px;
  border-radius: 50%; background: var(--faint); transition: all 0.2s ease;
}
.toggle input:checked + .toggle-track { background: var(--grad); border-color: transparent; }
.toggle input:checked + .toggle-track .toggle-thumb { left: 21px; background: #fff; }
.toggle-label { font-size: 14px; }
.toggle.compact .toggle-label { display: none; }

.chip {
  background: var(--panel); border: 1px solid var(--border); color: var(--muted);
  padding: 8px 16px; border-radius: 20px; cursor: pointer; font-size: 13px;
  font-family: var(--sans); transition: all 0.15s ease;
}
.chip:hover { color: var(--text); }
.chip.active { background: var(--panel-2); color: var(--text); border-color: var(--border-2); box-shadow: var(--glow); }
.chip.dead { opacity: 0.35; cursor: not-allowed; text-decoration: line-through; }
.chip.ghost { margin-left: auto; }
.chiprow { display: flex; gap: 8px; flex-wrap: wrap; }

.rows { display: flex; flex-direction: column; gap: 14px; }
.row { display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
.row .toggle { min-width: 200px; }
.hintline { font-size: 12px; color: var(--faint); line-height: 1.5; }
.subgroup { opacity: 0.5; transition: opacity 0.2s ease; pointer-events: none; }
.subgroup.on { opacity: 1; pointer-events: auto; }
.breath-desc { font-size: 12px; color: var(--muted); line-height: 1.55; margin-top: 8px; }
.breath-cycle { font-family: var(--mono); font-size: 11.5px; color: var(--primary-2); }

.run-btn {
  width: 100%; margin-top: 20px; padding: 16px;
  background: var(--grad); color: #fff; border: none; cursor: pointer;
  border-radius: 14px; font-size: 15px; font-weight: 600; font-family: var(--sans);
  display: flex; align-items: center; justify-content: center; gap: 10px;
  box-shadow: 0 8px 28px rgba(168,85,247,0.32); transition: all 0.18s ease;
}
.run-btn:hover { transform: translateY(-1px); box-shadow: 0 12px 34px rgba(168,85,247,0.42); }
.run-btn:active { transform: translateY(0); }
.run-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
.run-btn.slim { width: auto; padding: 12px 24px; margin-top: 0; }
.run-ico { font-size: 12px; }

/* ── Progress ──────────────────────────────────────────────────── */
.progress-card { margin-top: 20px; }
.prog-head { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }
.orb-wrap { width: 44px; height: 44px; flex-shrink: 0; display: grid; place-items: center; }
.orb {
  width: 36px; height: 36px; border-radius: 50%;
  background: var(--grad); box-shadow: var(--glow);
  animation: breathe 4s ease-in-out infinite;
}
.orb.idle { animation: none; opacity: 0.4; }
.prog-meta { flex: 1; }
.prog-step { font-size: 15px; font-weight: 600; }
.prog-sub { font-size: 12px; margin-top: 2px; }
.cancel-btn {
  background: transparent; border: 1px solid var(--border-2); color: var(--muted);
  padding: 7px 14px; border-radius: 9px; cursor: pointer; font-size: 13px;
  font-family: var(--sans); transition: all 0.15s ease;
}
.cancel-btn:hover { color: var(--red); border-color: var(--red); }
.bar { height: 7px; background: var(--bg); border-radius: 4px; overflow: hidden; margin-bottom: 16px; }
.bar-fill {
  height: 100%; width: 0%; background: var(--grad); border-radius: 4px;
  transition: width 0.3s ease; box-shadow: var(--glow);
}
.console {
  font-family: var(--mono); font-size: 12px; line-height: 1.7;
  background: #060509; border: 1px solid var(--border); border-radius: 10px;
  padding: 14px; max-height: 220px; overflow-y: auto; color: var(--muted);
}
.console .ln { white-space: pre-wrap; word-break: break-word; }
.console .ln.ok   { color: var(--green); }
.console .ln.err  { color: var(--red); }
.console .ln.warn { color: var(--amber); }
.console .ln.sep  { color: var(--primary); }

/* ── Library ───────────────────────────────────────────────────── */
.lib-filter { display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap; }
.lib-list { display: flex; flex-direction: column; gap: 10px; }
.lib-item {
  display: flex; align-items: center; gap: 14px;
  background: linear-gradient(180deg, var(--panel), var(--bg-2));
  border: 1px solid var(--border); border-radius: 13px; padding: 14px 16px;
  transition: border 0.15s ease;
}
.lib-item:hover { border-color: var(--border-2); }
.lib-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.lib-info { flex: 1; min-width: 0; }
.lib-name { font-size: 13.5px; font-family: var(--mono); word-break: break-all; }
.lib-meta { font-size: 11.5px; color: var(--muted); margin-top: 3px; }
.lib-kind {
  font-family: var(--mono); font-size: 9.5px; padding: 2px 7px;
  border-radius: 5px; margin-right: 6px; letter-spacing: 0.5px;
  border: 1px solid var(--border-2); color: var(--primary-2);
}
.lib-kind.audio { color: var(--cyan); }
.lib-kind.thumb { color: var(--amber); }
.lib-kind.meta  { color: var(--green); }
.lib-actions { display: flex; gap: 6px; flex-shrink: 0; }
.icon-btn {
  background: var(--bg); border: 1px solid var(--border); color: var(--muted);
  width: 36px; height: 36px; border-radius: 9px; cursor: pointer; font-size: 15px;
  display: grid; place-items: center; transition: all 0.15s ease;
}
.icon-btn:hover { color: var(--text); border-color: var(--border-2); }
.icon-btn.danger:hover { color: var(--red); border-color: var(--red); }
.empty { text-align: center; padding: 60px 20px; color: var(--faint); font-size: 14px; }
#player { width: 100%; margin-top: 18px; border-radius: 12px; background: #000; max-height: 420px; }

/* ── Settings ──────────────────────────────────────────────────── */
.set-card { display: flex; flex-direction: column; gap: 18px; }
.set-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
.set-row.wide { flex-direction: column; align-items: stretch; gap: 8px; }
.set-row label { font-size: 14px; min-width: 170px; }
.set-row.wide label { min-width: 0; }
.hint { font-size: 11px; color: var(--faint); font-family: var(--mono); margin-left: 4px; }
.err { font-size: 12px; color: var(--red); margin-left: 8px; }

@keyframes breathe {
  0%, 100% { transform: scale(1); opacity: 0.85; }
  50%      { transform: scale(1.14); opacity: 1; }
}
@keyframes fade {
  from { opacity: 0; transform: translateY(4px); }
  to   { opacity: 1; transform: translateY(0); }
}

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-thumb { background: var(--border-2); border-radius: 4px; }
::-webkit-scrollbar-track { background: transparent; }

@media (max-width: 780px) {
  .sidebar { width: 76px; }
  .brand-text, .nav-item span:last-child { display: none; }
  .grid { grid-template-columns: 1fr; }
  .main { padding: 24px 18px 50px; }
}
  </style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-orb"></div>
      <div class="brand-text">
        <div class="brand-name" id="brand-name">GARBAGE NOISE</div>
        <div class="brand-sub" id="brand-sub">calming the garbage within</div>
      </div>
    </div>
    <nav class="nav">
      <button class="nav-item active" data-view="create"><span class="nav-ico">&#9782;</span><span>Create</span></button>
      <button class="nav-item" data-view="library"><span class="nav-ico">&#9638;</span><span>Library</span></button>
      <button class="nav-item" data-view="settings"><span class="nav-ico">&#9881;</span><span>Settings</span></button>
    </nav>
    <div class="sidebar-foot">
      <div class="dep-row" id="dep-row"></div>
      <div class="ver">medtool web v4.0</div>
    </div>
  </aside>

  <main class="main">
    <section class="view active" id="view-create">
      <div class="view-head">
        <h1>Create</h1>
        <div class="muted">yt-dlp &rarr; remix &rarr; FX &rarr; master &rarr; extend &rarr; video, one pipeline.</div>
      </div>
      <div class="grid">

        <div class="card span2">
          <div class="card-title">Source</div>
          <div class="seg" id="src-seg">
            <button class="seg-btn active" data-src="url">URL</button>
            <button class="seg-btn" data-src="batch">Batch / Playlist</button>
            <button class="seg-btn" data-src="local">Upload file</button>
          </div>
          <div class="src-pane active" data-pane="url">
            <input class="field" id="src-url" placeholder="https://www.youtube.com/watch?v=..." />
          </div>
          <div class="src-pane" data-pane="batch">
            <textarea class="field area" id="src-batch" rows="5" placeholder="One URL per line (or a single playlist URL). Lines starting with # are ignored."></textarea>
          </div>
          <div class="src-pane" data-pane="local">
            <label class="drop" id="drop-zone">
              <div class="drop-ico">&#8683;</div>
              <div class="drop-text" id="drop-text">Drop an audio/video file here, or click to choose</div>
              <input type="file" id="file-input" accept="audio/*,video/*" style="display:none" />
            </label>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Profile</div>
          <div class="profiles" id="profiles"></div>
        </div>

        <div class="card">
          <div class="card-title">Brand &amp; Extras</div>
          <div class="rows">
            <div class="row">
              <span>Brand</span>
              <select class="field sm" id="opt-brand"></select>
            </div>
            <div class="row">
              <label class="toggle"><input type="checkbox" id="opt-binaural" checked><span class="toggle-track"><span class="toggle-thumb"></span></span><span class="toggle-label">Binaural beat</span></label>
            </div>
            <div class="row">
              <label class="toggle"><input type="checkbox" id="opt-polish" checked><span class="toggle-track"><span class="toggle-thumb"></span></span><span class="toggle-label">Polish (crystalizer + widen)</span></label>
            </div>
            <div class="row">
              <label class="toggle"><input type="checkbox" id="opt-creator_pack" checked><span class="toggle-track"><span class="toggle-thumb"></span></span><span class="toggle-label">Creator pack (thumb + metadata)</span></label>
            </div>
            <div class="row">
              <label class="toggle"><input type="checkbox" id="opt-skip_existing" checked><span class="toggle-track"><span class="toggle-thumb"></span></span><span class="toggle-label">Skip existing files</span></label>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">FX Rack</div>
          <div class="chiprow" id="fx-chips"></div>
        </div>

        <div class="card">
          <div class="card-title">Slow &amp; Stem Separation</div>
          <div class="rows">
            <div class="row">
              <span>Slow</span>
              <select class="field sm" id="opt-slow"></select>
            </div>
            <div class="row subgroup" id="slow-pct-row">
              <span>Speed %</span>
              <input class="field xs" type="number" id="opt-slow_pct" min="50" max="100" value="85" />
            </div>
            <div class="row">
              <span>Stems (Demucs)</span>
              <select class="field sm" id="opt-stems"></select>
            </div>
            <div class="row subgroup" id="stem-sub">
              <label class="toggle"><input type="checkbox" id="opt-stem_pipeline"><span class="toggle-track"><span class="toggle-thumb"></span></span><span class="toggle-label">Route a stem into the pipeline</span></label>
              <select class="field sm" id="opt-stem_source">
                <option value="mix">Mix</option>
                <option value="vocals">Vocals</option>
                <option value="instrumental">Instrumental</option>
                <option value="drums">Drums</option>
                <option value="bass">Bass</option>
                <option value="other">Other</option>
              </select>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Video</div>
          <div class="rows">
            <div class="row">
              <label class="toggle"><input type="checkbox" id="opt-video"><span class="toggle-track"><span class="toggle-thumb"></span></span><span class="toggle-label">Render video</span></label>
            </div>
            <div class="row subgroup" id="video-sub1">
              <span>Visualizer</span>
              <select class="field sm" id="opt-viz"></select>
            </div>
            <div class="row subgroup" id="video-sub2">
              <label class="toggle"><input type="checkbox" id="opt-captions" checked><span class="toggle-track"><span class="toggle-thumb"></span></span><span class="toggle-label">Whisper captions</span></label>
            </div>
            <div class="row subgroup" id="video-sub3">
              <span>Breathing overlay</span>
              <select class="field sm" id="opt-breathing"></select>
            </div>
            <div class="breath-desc" id="breath-desc"></div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Compilation &amp; Extend</div>
          <div class="rows">
            <div class="row">
              <span>Track order</span>
              <select class="field sm" id="opt-comp_order">
                <option value="off">Off (single track)</option>
                <option value="shuffle">Shuffle</option>
                <option value="reverse">Reverse</option>
                <option value="short">Shortest first</option>
                <option value="long">Longest first</option>
              </select>
            </div>
            <div class="row">
              <span>Extend to</span>
              <select class="field sm" id="opt-extend_min"></select>
            </div>
          </div>
        </div>

        <div class="card span2">
          <button class="run-btn" id="run-btn"><span class="run-ico">&#9654;</span> Run pipeline</button>
          <div class="progress-card" id="progress-card" style="display:none">
            <div class="prog-head">
              <div class="orb-wrap"><div class="orb idle" id="prog-orb"></div></div>
              <div class="prog-meta">
                <div class="prog-step" id="prog-step">Idle</div>
                <div class="prog-sub muted" id="prog-sub"></div>
              </div>
              <button class="cancel-btn" id="cancel-btn">Cancel</button>
            </div>
            <div class="bar"><div class="bar-fill" id="bar-fill"></div></div>
            <div class="console" id="console"></div>
          </div>
        </div>

      </div>
    </section>

    <section class="view" id="view-library">
      <div class="view-head">
        <h1>Library</h1>
        <div class="muted">Everything the pipeline has produced, grouped by track.</div>
      </div>
      <div class="lib-filter" id="lib-filter">
        <button class="chip active" data-filter="all">All</button>
        <button class="chip" data-filter="sleep">Sleep</button>
        <button class="chip" data-filter="med">Med</button>
        <button class="chip" data-filter="focus">Focus</button>
        <button class="chip ghost" id="lib-refresh">&#8635; Refresh</button>
      </div>
      <div class="lib-list" id="lib-list"><div class="empty">Loading&hellip;</div></div>
      <video id="player" controls style="display:none"></video>
    </section>

    <section class="view" id="view-settings">
      <div class="view-head">
        <h1>Settings</h1>
        <div class="muted">Saved to ~/.medtool/web_config.json.</div>
      </div>
      <div class="card set-card">
        <div class="set-row wide">
          <label>Output directory</label>
          <input class="field" id="set-out_dir" />
        </div>
        <div class="set-row">
          <label>Target LUFS</label>
          <input class="field xs" type="number" id="set-lufs" step="1" />
          <label>True peak (dBTP)</label>
          <input class="field xs" type="number" id="set-true_peak" step="0.5" />
        </div>
        <div class="set-row">
          <label>Bitrate</label>
          <select class="field sm" id="set-bitrate">
            <option value="192k">192k</option>
            <option value="256k">256k</option>
            <option value="320k">320k</option>
          </select>
        </div>
        <div class="set-row">
          <label>Fade in / out (s)</label>
          <input class="field xs" type="number" id="set-fade_in" />
          <input class="field xs" type="number" id="set-fade_out" />
        </div>
        <div class="set-row">
          <label>Whisper model</label>
          <select class="field sm" id="set-whisper_model">
            <option value="tiny">tiny</option>
            <option value="base">base</option>
            <option value="small">small</option>
          </select>
        </div>
        <div class="set-row">
          <label>Stem model</label>
          <select class="field sm" id="set-stem_model">
            <option value="htdemucs">htdemucs</option>
            <option value="htdemucs_ft">htdemucs_ft</option>
            <option value="htdemucs_6s">htdemucs_6s</option>
          </select>
        </div>
        <div class="set-row">
          <label>Loop crossfade (s)</label>
          <input class="field xs" type="number" id="set-loop_xfade" />
        </div>
        <div class="set-row">
          <button class="run-btn slim" id="save-settings-btn">Save settings</button>
          <span class="err" id="settings-msg"></span>
        </div>
      </div>
    </section>
  </main>
</div>

<script>
(function () {
  "use strict";

  var META = null;
  var CFG = null;
  var state = {
    view: "create",
    src: "url",
    profile: "med",
    fx: "none",
    uploadPath: null,
    uploadName: null,
    jobId: null,
    es: null,
    libFilter: "all",
    libItems: [],
  };

  function $(id) { return document.getElementById(id); }
  function qsa(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  // ── Views / nav ─────────────────────────────────────────────────
  qsa(".nav-item").forEach(function (btn) {
    btn.addEventListener("click", function () { switchView(btn.dataset.view); });
  });

  function switchView(view) {
    state.view = view;
    qsa(".nav-item").forEach(function (b) { b.classList.toggle("active", b.dataset.view === view); });
    qsa(".view").forEach(function (v) { v.classList.toggle("active", v.id === "view-" + view); });
    if (view === "library") loadLibrary();
    if (view === "settings") loadConfigIntoSettings();
  }

  // ── Source tabs ─────────────────────────────────────────────────
  qsa("#src-seg .seg-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      state.src = btn.dataset.src;
      qsa("#src-seg .seg-btn").forEach(function (b) { b.classList.toggle("active", b === btn); });
      qsa(".src-pane").forEach(function (p) { p.classList.toggle("active", p.dataset.pane === state.src); });
    });
  });

  var dropZone = $("drop-zone"), fileInput = $("file-input");
  dropZone.addEventListener("click", function () { fileInput.click(); });
  fileInput.addEventListener("change", function () {
    if (fileInput.files[0]) uploadFile(fileInput.files[0]);
  });
  ["dragover", "dragenter"].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    dropZone.addEventListener(ev, function (e) { e.preventDefault(); dropZone.classList.remove("over"); });
  });
  dropZone.addEventListener("drop", function (e) {
    var f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) uploadFile(f);
  });

  function uploadFile(file) {
    $("drop-text").textContent = "Uploading " + file.name + " …";
    var fd = new FormData();
    fd.append("file", file);
    fetch("/api/upload", { method: "POST", body: fd })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { $("drop-text").textContent = "Upload failed: " + data.error; return; }
        state.uploadPath = data.path;
        state.uploadName = data.name;
        $("drop-text").textContent = "✓ " + data.name + " (click to replace)";
      })
      .catch(function () { $("drop-text").textContent = "Upload failed."; });
  }

  // ── Meta-driven controls ────────────────────────────────────────
  function loadMeta() {
    return fetch("/api/meta").then(function (r) { return r.json(); }).then(function (meta) {
      META = meta;
      CFG = meta.cfg;
      renderDeps(meta.deps);
      renderProfiles(meta.profiles);
      renderBrands(meta.brands);
      renderFx(meta.fx);
      renderSelect("opt-slow", meta.slow, function (k, v) { return v.label + (v.available ? "" : " (unavailable)"); });
      renderSelect("opt-stems", meta.stems, function (k, v) {
        return v + (k !== "off" && !meta.stems_available ? " (Demucs not installed)" : "");
      });
      renderSelect("opt-viz", meta.viz.reduce(function (o, v) { o[v] = v; return o; }, {}), function (k) { return k; });
      renderSelect("opt-breathing", Object.assign({ none: { label: "None" } }, meta.breathing),
        function (k, v) { return v.label; });
      renderExtend(meta.extend_presets);
      applyCfgDefaults();
      wireSubgroups();
    }).catch(function (e) { console.error("meta load failed", e); });
  }

  function renderDeps(deps) {
    var row = $("dep-row");
    row.innerHTML = "";
    Object.keys(deps).forEach(function (k) {
      var span = document.createElement("span");
      span.className = "dep " + (deps[k] ? "ok" : "bad");
      span.textContent = k;
      row.appendChild(span);
    });
  }

  function renderProfiles(profiles) {
    var wrap = $("profiles");
    wrap.innerHTML = "";
    Object.keys(profiles).forEach(function (key) {
      var p = profiles[key];
      var el = document.createElement("div");
      el.className = "prof" + (key === state.profile ? " active" : "");
      el.dataset.profile = key;
      el.innerHTML =
        '<span class="prof-dot ' + key + '"></span>' +
        '<span class="prof-info"><span class="prof-name">' + p.label +
        '</span><span class="prof-desc">' + p.desc + "</span></span>";
      el.addEventListener("click", function () {
        state.profile = key;
        qsa("#profiles .prof").forEach(function (e2) { e2.classList.toggle("active", e2 === el); });
      });
      wrap.appendChild(el);
    });
  }

  function renderBrands(brands) {
    var sel = $("opt-brand");
    sel.innerHTML = "";
    Object.keys(brands).forEach(function (key) {
      var o = document.createElement("option");
      o.value = key;
      o.textContent = brands[key].channel;
      sel.appendChild(o);
    });
    sel.addEventListener("change", function () {
      var b = brands[sel.value];
      if (b) { $("brand-name").textContent = b.channel; $("brand-sub").textContent = b.slogan; }
    });
  }

  function renderFx(fx) {
    var wrap = $("fx-chips");
    wrap.innerHTML = "";
    Object.keys(fx).forEach(function (key) {
      var f = fx[key];
      var chip = document.createElement("button");
      chip.type = "button";
      chip.className = "chip" + (key === "none" ? " active" : "") + (f.available ? "" : " dead");
      chip.textContent = f.label;
      chip.dataset.fx = key;
      if (f.available) {
        chip.addEventListener("click", function () {
          state.fx = key;
          qsa("#fx-chips .chip").forEach(function (c) { c.classList.toggle("active", c === chip); });
        });
      } else {
        chip.title = "Not supported by this ffmpeg build";
      }
      wrap.appendChild(chip);
    });
  }

  function renderSelect(id, obj, labelFn) {
    var sel = $(id);
    sel.innerHTML = "";
    Object.keys(obj).forEach(function (k) {
      var o = document.createElement("option");
      o.value = k;
      o.textContent = labelFn(k, obj[k]);
      sel.appendChild(o);
    });
  }

  function renderExtend(presets) {
    var sel = $("opt-extend_min");
    sel.innerHTML = "";
    presets.forEach(function (m) {
      var o = document.createElement("option");
      o.value = m;
      o.textContent = m === 0 ? "Off (single unit)" :
        (m >= 60 ? (m / 60) + "h" : m + "m");
      sel.appendChild(o);
    });
  }

  function applyCfgDefaults() {
    if (!CFG) return;
    setChecked("opt-binaural", CFG.binaural);
    setChecked("opt-polish", CFG.polish);
    setChecked("opt-creator_pack", CFG.creator_pack);
    setChecked("opt-skip_existing", CFG.skip_existing);
    setChecked("opt-video", CFG.video);
    setChecked("opt-captions", CFG.captions);
    setChecked("opt-stem_pipeline", CFG.stem_pipeline);
    setValue("opt-brand", CFG.brand);
    setValue("opt-viz", CFG.viz);
    setValue("opt-breathing", CFG.breathing);
    setValue("opt-comp_order", CFG.comp_order);
    setValue("opt-extend_min", CFG.extend_min);
    setValue("opt-slow", CFG.slow);
    setValue("opt-slow_pct", CFG.slow_pct);
    setValue("opt-stems", CFG.stems);
    setValue("opt-stem_source", CFG.stem_source);
    state.fx = CFG.fx || "none";
    qsa("#fx-chips .chip").forEach(function (c) { c.classList.toggle("active", c.dataset.fx === state.fx); });
    state.profile = CFG.profile || "med";
    qsa("#profiles .prof").forEach(function (e2) { e2.classList.toggle("active", e2.dataset.profile === state.profile); });
    var b = META.brands[CFG.brand];
    if (b) { $("brand-name").textContent = b.channel; $("brand-sub").textContent = b.slogan; }
    updateBreathDesc();
  }

  function setChecked(id, v) { $(id).checked = !!v; }
  function setValue(id, v) { if (v !== undefined && v !== null) $(id).value = v; }

  function wireSubgroups() {
    function sync() {
      $("slow-pct-row").classList.toggle("on", $("opt-slow").value !== "off");
      $("stem-sub").classList.toggle("on", $("opt-stems").value !== "off");
      var videoOn = $("opt-video").checked;
      ["video-sub1", "video-sub2", "video-sub3"].forEach(function (id) {
        $(id).classList.toggle("on", videoOn);
      });
    }
    $("opt-slow").addEventListener("change", sync);
    $("opt-stems").addEventListener("change", sync);
    $("opt-video").addEventListener("change", sync);
    $("opt-breathing").addEventListener("change", updateBreathDesc);
    sync();
  }

  function updateBreathDesc() {
    var key = $("opt-breathing").value;
    var el = $("breath-desc");
    var b = META && META.breathing[key];
    if (!b) { el.textContent = ""; return; }
    var cycle = b.cycle.map(function (c) { return c[0] + " " + c[1] + "s"; }).join(" · ");
    el.innerHTML = b.desc + '<div class="breath-cycle">' + cycle + "</div>";
  }

  // ── Run pipeline ────────────────────────────────────────────────
  $("run-btn").addEventListener("click", runPipeline);
  $("cancel-btn").addEventListener("click", function () {
    if (state.jobId) fetch("/api/cancel/" + state.jobId, { method: "POST" });
  });

  function buildPayload() {
    var payload = {
      type: state.src,
      profile: state.profile,
      brand: $("opt-brand").value,
      binaural: $("opt-binaural").checked,
      polish: $("opt-polish").checked,
      creator_pack: $("opt-creator_pack").checked,
      skip_existing: $("opt-skip_existing").checked,
      fx: state.fx,
      slow: $("opt-slow").value,
      slow_pct: parseInt($("opt-slow_pct").value, 10) || 85,
      stems: $("opt-stems").value,
      stem_pipeline: $("opt-stem_pipeline").checked,
      stem_source: $("opt-stem_source").value,
      video: $("opt-video").checked,
      viz: $("opt-viz").value,
      captions: $("opt-captions").checked,
      breathing: $("opt-breathing").value,
      comp_order: $("opt-comp_order").value,
      extend_min: parseInt($("opt-extend_min").value, 10) || 0,
    };
    if (state.src === "url") payload.url = $("src-url").value.trim();
    else if (state.src === "batch") payload.urls = $("src-batch").value;
    else if (state.src === "local") payload.path = state.uploadPath;
    return payload;
  }

  function validPayload(p) {
    if (p.type === "url") return !!p.url;
    if (p.type === "batch") return !!(p.urls && p.urls.trim());
    if (p.type === "local") return !!p.path;
    return false;
  }

  function runPipeline() {
    var payload = buildPayload();
    if (!validPayload(payload)) {
      alert("Add a URL, batch list, or upload a file first.");
      return;
    }
    $("run-btn").disabled = true;
    $("progress-card").style.display = "block";
    $("console").innerHTML = "";
    $("bar-fill").style.width = "0%";
    $("prog-orb").classList.remove("idle");
    $("prog-step").textContent = "Starting…";
    $("prog-sub").textContent = "";

    fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.error) { finishRun("Error: " + data.error); return; }
      state.jobId = data.job_id;
      openStream(data.job_id);
    }).catch(function (e) { finishRun("Error: " + e); });
  }

  function openStream(jobId) {
    var es = new EventSource("/api/stream/" + jobId);
    state.es = es;
    es.onmessage = function (ev) { handleEvent(JSON.parse(ev.data)); };
    es.addEventListener("end", function () { es.close(); });
    es.onerror = function () { es.close(); finishRun(null); };
  }

  var STEP_LABELS = {
    downloading: "Downloading", analyzing: "Analyzing", encoding: "Mastering",
    rendering: "Rendering video", packing: "Creator pack",
    separating: "Separating stems", track: "Track", track_done: "Track complete",
    track_fail: "Track failed", done: "Complete", error: "Error",
  };

  function handleEvent(ev) {
    if (ev.state) {
      var label = STEP_LABELS[ev.state] || ev.state;
      if (ev.state === "track") label += " " + ev.index + "/" + ev.total;
      $("prog-step").textContent = ev.step || label;
    } else if (ev.step) {
      $("prog-step").textContent = ev.step;
    }
    if (ev.title || ev.filename) {
      $("prog-sub").textContent = ev.title || ev.filename || "";
    }
    if (typeof ev.progress === "number") {
      $("bar-fill").style.width = Math.max(0, Math.min(100, ev.progress)) + "%";
    }
    if (ev.state === "track_done" || ev.state === "done") {
      $("bar-fill").style.width = "100%";
    }
    if (ev.log) appendLog(ev.log);
    if (ev.message) appendLog(ev.message);
    if (ev.state === "done") {
      finishRun(ev.log || ("Complete — " + ev.ok + " ok, " + ev.skip + " skipped, " + ev.fail + " failed"));
    } else if (ev.state === "error") {
      finishRun(ev.message || "Error");
    }
  }

  function appendLog(text) {
    var line = document.createElement("div");
    var cls = "ln";
    if (text.indexOf("✓") === 0) cls += " ok";
    else if (text.indexOf("✗") === 0) cls += " err";
    else if (text.indexOf("Cancel") !== -1 || text.indexOf("⚠") !== -1) cls += " warn";
    else if (text.indexOf("──") === 0) cls += " sep";
    line.className = cls;
    line.textContent = text;
    var box = $("console");
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
  }

  function finishRun(finalMsg) {
    if (finalMsg) appendLog(finalMsg);
    $("run-btn").disabled = false;
    $("prog-orb").classList.add("idle");
    if (state.es) { state.es.close(); state.es = null; }
    state.jobId = null;
  }

  // ── Library ─────────────────────────────────────────────────────
  $("lib-refresh").addEventListener("click", loadLibrary);
  qsa("#lib-filter .chip[data-filter]").forEach(function (chip) {
    chip.addEventListener("click", function () {
      state.libFilter = chip.dataset.filter;
      qsa("#lib-filter .chip[data-filter]").forEach(function (c) { c.classList.toggle("active", c === chip); });
      renderLibrary();
    });
  });

  var PROFILE_COLORS = { sleep: "#6366f1", med: "#a855f7", focus: "#34d2ee" };

  function loadLibrary() {
    $("lib-list").innerHTML = '<div class="empty">Loading…</div>';
    fetch("/api/library").then(function (r) { return r.json(); }).then(function (data) {
      state.libItems = data.items || [];
      renderLibrary();
    }).catch(function () { $("lib-list").innerHTML = '<div class="empty">Failed to load library.</div>'; });
  }

  function renderLibrary() {
    var list = $("lib-list");
    var items = state.libItems.filter(function (g) {
      return state.libFilter === "all" || g.profile === state.libFilter;
    });
    if (!items.length) { list.innerHTML = '<div class="empty">Nothing here yet — run the pipeline first.</div>'; return; }
    list.innerHTML = "";
    items.forEach(function (g) {
      var kinds = Object.keys(g.files);
      var main = g.files.video || g.files.audio;
      var size = main ? main.size : "";
      var when = main ? new Date(main.mtime * 1000).toLocaleString() : "";
      var el = document.createElement("div");
      el.className = "lib-item";
      el.innerHTML =
        '<span class="lib-dot" style="background:' + (PROFILE_COLORS[g.profile] || "#8b85a6") + '"></span>' +
        '<div class="lib-info">' +
        '<div class="lib-name">' + g.stem + "</div>" +
        '<div class="lib-meta">' +
        kinds.map(function (k) { return '<span class="lib-kind ' + k + '">' + k + "</span>"; }).join("") +
        size + (when ? " · " + when : "") +
        "</div></div>" +
        '<div class="lib-actions"></div>';
      var actions = el.querySelector(".lib-actions");
      if (main) {
        var playBtn = document.createElement("button");
        playBtn.className = "icon-btn";
        playBtn.title = "Play";
        playBtn.textContent = "▶";
        playBtn.addEventListener("click", function () { playFile(main.path, !!g.files.video); });
        actions.appendChild(playBtn);

        var dlBtn = document.createElement("a");
        dlBtn.className = "icon-btn";
        dlBtn.title = "Download";
        dlBtn.textContent = "⇩";
        dlBtn.href = "/api/file?path=" + encodeURIComponent(main.path);
        actions.appendChild(dlBtn);
      }
      var delBtn = document.createElement("button");
      delBtn.className = "icon-btn danger";
      delBtn.title = "Delete";
      delBtn.textContent = "✖";
      delBtn.addEventListener("click", function () { deleteGroup(g); });
      actions.appendChild(delBtn);
      list.appendChild(el);
    });
  }

  function playFile(path, isVideo) {
    var player = $("player");
    player.src = "/api/file?path=" + encodeURIComponent(path);
    player.style.display = "block";
    player.style.background = isVideo ? "#000" : "transparent";
    player.play().catch(function () {});
    player.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function deleteGroup(g) {
    if (!confirm("Delete all files for “" + g.stem + "”?")) return;
    var paths = Object.keys(g.files).map(function (k) { return g.files[k].path; });
    fetch("/api/library/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paths: paths }),
    }).then(function () { loadLibrary(); });
  }

  // ── Settings ────────────────────────────────────────────────────
  function loadConfigIntoSettings() {
    fetch("/api/config").then(function (r) { return r.json(); }).then(function (cfg) {
      CFG = cfg;
      setValue("set-out_dir", cfg.out_dir);
      setValue("set-lufs", cfg.lufs);
      setValue("set-true_peak", cfg.true_peak);
      setValue("set-bitrate", cfg.bitrate);
      setValue("set-fade_in", cfg.fade_in);
      setValue("set-fade_out", cfg.fade_out);
      setValue("set-whisper_model", cfg.whisper_model);
      setValue("set-stem_model", cfg.stem_model);
      setValue("set-loop_xfade", cfg.loop_xfade);
    });
  }

  $("save-settings-btn").addEventListener("click", function () {
    var update = {
      out_dir: $("set-out_dir").value,
      lufs: parseFloat($("set-lufs").value),
      true_peak: parseFloat($("set-true_peak").value),
      bitrate: $("set-bitrate").value,
      fade_in: parseFloat($("set-fade_in").value),
      fade_out: parseFloat($("set-fade_out").value),
      whisper_model: $("set-whisper_model").value,
      stem_model: $("set-stem_model").value,
      loop_xfade: parseFloat($("set-loop_xfade").value),
    };
    fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(update),
    }).then(function (r) { return r.json(); }).then(function () {
      $("settings-msg").textContent = "Saved.";
      setTimeout(function () { $("settings-msg").textContent = ""; }, 2500);
    }).catch(function () { $("settings-msg").textContent = "Save failed."; });
  });

  loadMeta();
})();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/api/meta")
def api_meta():
    filters = ff_filters()
    return jsonify({
        "profiles": {k: {"label": v["label"], "desc": v["desc"]}
                     for k, v in PROFILES.items()},
        "brands": {k: {"channel": v["channel"], "slogan": v["slogan"]}
                   for k, v in BRANDS.items()},
        "fx": {k: {"label": v["label"], "available": fx_available(k)}
               for k, v in FX_RACK.items()},
        "viz": list(VIZ_MODES),
        "breathing": {k: {"label": v["label"], "desc": v["desc"],
                          "cycle": v["cycle"]}
                      for k, v in BREATHING.items()},
        "slow": {k: {"label": v["label"],
                     "available": all(n in filters for n in v["needs"])}
                 for k, v in SLOW_MODES.items()},
        "stems": {k: v["label"] for k, v in STEM_MODES.items()},
        "stems_available": demucs_available(),
        "extend_presets": list(EXTEND_PRESETS),
        "comp_orders": list(COMP_ORDERS),
        "deps": {
            "ffmpeg": have("ffmpeg"),
            "yt-dlp": ytdlp_ok(),
            "pillow": have_module("PIL"),
            "whisper": have_module("faster_whisper"),
            "demucs": demucs_available(),
            "font": find_font() is not None,
        },
        "cfg": CFG,
    })


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    global CFG
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        for k, v in data.items():
            if k in DEFAULTS:
                CFG[k] = v
        save_cfg(CFG)
        return jsonify(ok=True, cfg=CFG)
    return jsonify(CFG)


@app.route("/api/upload", methods=["POST"])
def api_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="No file provided"), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if not re.fullmatch(r"\.[a-z0-9]{1,5}", ext or ""):
        ext = ".bin"
    tmp_id = uuid.uuid4().hex[:8]
    path = os.path.join(TMP_DIR, f"up_{tmp_id}{ext}")
    f.save(path)
    return jsonify(path=path, name=f.filename)


@app.route("/api/run", methods=["POST"])
def api_run():
    payload = request.get_json(force=True, silent=True) or {}
    t = payload.get("type")
    if t not in ("url", "local", "batch"):
        return jsonify(error="Invalid source type"), 400
    if t == "url" and not str(payload.get("url", "")).strip():
        return jsonify(error="Missing url"), 400
    if t == "batch" and not str(payload.get("urls", "")).strip():
        return jsonify(error="Missing urls"), 400
    if t == "local":
        p = str(payload.get("path", "")).strip()
        real_tmp = os.path.realpath(TMP_DIR)
        real_p = os.path.realpath(p) if p else ""
        if not p or not real_p.startswith(real_tmp + os.sep) or \
                not os.path.isfile(real_p):
            return jsonify(error="Invalid or missing upload path"), 400
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {"q": queue.Queue(), "cancel": threading.Event()}
    t = threading.Thread(target=run_job, args=(job_id, payload), daemon=True)
    t.start()
    return jsonify(job_id=job_id)


@app.route("/api/cancel/<job_id>", methods=["POST"])
def api_cancel(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify(error="Unknown job"), 404
    job["cancel"].set()
    return jsonify(ok=True)


@app.route("/api/stream/<job_id>")
def api_stream(job_id):
    job = JOBS.get(job_id)
    if not job:
        abort(404)
    q = job["q"]

    def gen():
        try:
            while True:
                item = q.get()
                if item is None:
                    yield "event: end\ndata: {}\n\n"
                    break
                yield "data: " + json.dumps(item) + "\n\n"
        finally:
            with JOBS_LOCK:
                JOBS.pop(job_id, None)

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


def _safe_library_path(path):
    out_dir = os.path.realpath(CFG.get("out_dir", DEFAULTS["out_dir"]))
    real = os.path.realpath(path)
    if real == out_dir or not real.startswith(out_dir + os.sep):
        return None
    return real


@app.route("/api/library")
def api_library():
    out_dir = CFG.get("out_dir", DEFAULTS["out_dir"])
    groups = {}
    if os.path.isdir(out_dir):
        for prof_dir in sorted(glob.glob(os.path.join(out_dir, "*"))):
            if not os.path.isdir(prof_dir):
                continue
            prof_label = os.path.basename(prof_dir)
            prof_key = next((k for k in PROFILES
                             if profile_slug(k) == prof_label), prof_label)
            for path in glob.glob(os.path.join(prof_dir, "*")):
                name = os.path.basename(path)
                if name.endswith("_thumb.png"):
                    stem, kind = name[:-len("_thumb.png")], "thumb"
                elif name.endswith("_youtube.txt"):
                    stem, kind = name[:-len("_youtube.txt")], "meta"
                elif name.endswith(".mp4"):
                    stem, kind = name[:-4], "video"
                elif name.endswith(".mp3"):
                    stem, kind = name[:-4], "audio"
                else:
                    continue
                key = (prof_dir, stem)
                g = groups.setdefault(key, {"stem": stem, "profile": prof_key,
                                            "files": {}})
                st = os.stat(path)
                g["files"][kind] = {"path": path, "name": name,
                                    "size": human_size(st.st_size),
                                    "mtime": st.st_mtime}
    items = list(groups.values())
    items.sort(key=lambda g: max(f["mtime"] for f in g["files"].values()),
              reverse=True)
    return jsonify(items=items)


@app.route("/api/file")
def api_file():
    real = _safe_library_path(request.args.get("path", ""))
    if not real or not os.path.isfile(real):
        abort(404)
    return send_file(real)


@app.route("/api/library/delete", methods=["POST"])
def api_library_delete():
    data = request.get_json(force=True, silent=True) or {}
    removed = []
    for p in data.get("paths", []):
        real = _safe_library_path(p)
        if real and os.path.isfile(real):
            try:
                os.remove(real)
                removed.append(p)
            except Exception:
                pass
    return jsonify(removed=removed)


if __name__ == "__main__":
    port = int(os.environ.get("MEDTOOL_PORT", 8800))
    host = os.environ.get("MEDTOOL_HOST", "127.0.0.1")
    print(f"Golden Master Studio — http://{host}:{port}")
    app.run(host=host, port=port, threaded=True)

