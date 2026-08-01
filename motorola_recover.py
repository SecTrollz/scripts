#!/data/data/com.termux/files/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
motorola_recover.py  --  Rootless Termux recovery tool for Motorola devices that
got locked into a managed-profile / kiosk state by a misconfigured TestDPC
(device owner), with a forgotten lock PIN.

WHO THIS IS FOR
---------------
You own the device(s). You (or "Buster") provisioned TestDPC as device owner,
set a PIN nobody remembers, and now you're locked out. This tool runs on a
HOST Pixel (Termux, aarch64, Android 16) and talks to the TARGET Motorola over
USB-C OTG while the target sits in fastboot / fastbootd / recovery-sideload.

THE FOUR HARD TRUTHS (read these or waste an afternoon)
------------------------------------------------------
1. A device owner CANNOT be removed by `dpm`/`pm`. The only supported removal
   is a factory reset. A reset triggered from RECOVERY or the BOOTLOADER is
   below the OS and bypasses the DISALLOW_FACTORY_RESET policy your DPC set.
   ==> `kill-dpc` (recovery wipe) is the reliable kill. It needs NO unlock.

2. Stock adb/fastboot can't touch /dev/bus/usb on an unrooted Pixel. This tool
   ships its own fastboot client (ctypes -> libusb-1.0) and gets a USB file
   descriptor from `termux-usb -e`, then uses libusb_wrap_sys_device(). No root
   on the HOST required. (Root on the host still works too: pass --system.)

3. `fastboot flash` / `fastboot -w` / `erase` require an UNLOCKED bootloader.
   `fastboot flashing unlock` requires the on-device "OEM unlocking" toggle to
   be ON. You can't reach it while locked out, and a device owner can hard-off
   it via setOemUnlockEnabled(false). If that bit is off:
       full-firmware flash  = IMPOSSIBLE
       root                 = IMPOSSIBLE
       your only kill       = recovery wipe (truth #1) or EDL/blankflash on a PC.

4. After ANY wipe, Factory Reset Protection asks for the Google account that
   was last on the device. Sign in with YOUR account. This tool does not, and
   will not, bypass FRP.

USAGE
-----
    python3 motorola_recover.py                 # interactive menu
    python3 motorola_recover.py bootstrap       # install pkgs (Termux)
    python3 motorola_recover.py detect          # read-only: identity + verdict
    python3 motorola_recover.py kill-dpc        # guided recovery wipe (safe path)
    python3 motorola_recover.py unlock          # get_unlock_data + portal + unlock
    python3 motorola_recover.py pull-firmware   # download stock firmware (lolinet)
    python3 motorola_recover.py flash-stock DIR  # flash a flashfile.xml package
    python3 motorola_recover.py root            # patch + flash Magisk (needs unlock)
    python3 motorola_recover.py usb-test        # raw USB sanity check

Add --system to use the OS `fastboot` binary instead of the built-in libusb
client (only useful if your HOST Pixel is rooted). Add --yes to skip the typed
confirmations on destructive operations (don't, until detect looks right).
"""

import argparse
import ctypes
import ctypes.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# --------------------------------------------------------------------------- #
#  Small console helpers
# --------------------------------------------------------------------------- #

class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    C_ = "\033[36m"; BOLD = "\033[1m"; DIM = "\033[2m"; X = "\033[0m"

def info(m):  print(f"{C.C_}[*]{C.X} {m}")
def good(m):  print(f"{C.G}[+]{C.X} {m}")
def warn(m):  print(f"{C.Y}[!]{C.X} {m}")
def err(m):   print(f"{C.R}[x]{C.X} {m}")
def head(m):  print(f"\n{C.BOLD}{C.B}== {m} =={C.X}")

def die(m, code=1):
    err(m)
    sys.exit(code)

def confirm(prompt, auto_yes=False):
    """Typed confirmation for destructive ops. Requires the word WIPE."""
    if auto_yes:
        warn(f"--yes given, auto-confirming: {prompt}")
        return True
    print(f"{C.Y}{prompt}{C.X}")
    ans = input(f"    Type {C.BOLD}WIPE{C.X} to proceed (anything else aborts): ").strip()
    return ans == "WIPE"

PREFIX = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
HOME = os.environ.get("HOME", os.path.expanduser("~"))
WORK = os.path.join(HOME, "fbr_work")
LAUNCHER = os.path.join(WORK, "fbr_usb_launch.sh")

def ensure_work():
    os.makedirs(WORK, exist_ok=True)

def have(cmd):
    return shutil.which(cmd) is not None

def run(cmd, **kw):
    """Run a shell command, return CompletedProcess. Never raises on nonzero."""
    return subprocess.run(cmd, shell=isinstance(cmd, str),
                          capture_output=True, text=True, **kw)

# --------------------------------------------------------------------------- #
#  Environment bootstrap (Termux)
# --------------------------------------------------------------------------- #

def in_termux():
    return "com.termux" in PREFIX or have("termux-usb")

def cmd_bootstrap(_args):
    head("Environment bootstrap")
    if not in_termux():
        warn("This doesn't look like Termux. On a desktop Linux just install "
             "`android-tools` (adb/fastboot) and `libusb` from your package "
             "manager, then run with --system.")
        return
    pkgs = ["android-tools", "libusb", "python", "termux-api", "unzip", "tar"]
    info("Updating package lists ...")
    run("pkg update -y")
    for p in pkgs:
        info(f"Installing {p} ...")
        r = run(f"pkg install -y {p}")
        if r.returncode != 0:
            warn(f"pkg install {p} returned {r.returncode}: {r.stderr.strip()[:200]}")
    print()
    good("Packages requested.")
    print(f"""
{C.BOLD}One thing pkg can't do for you:{C.X} the Termux:API *app* must also be
installed (it backs `termux-usb`). Get it from F-Droid (recommended) or Play,
same signature as your Termux app. Then re-run `detect`.

Verify libusb is present:
    ls {PREFIX}/lib/libusb-1.0.so*
Verify the USB bridge:
    termux-usb -l
""")

# --------------------------------------------------------------------------- #
#  libusb ctypes binding + minimal fastboot protocol  (the rootless core)
# --------------------------------------------------------------------------- #

# libusb option / error constants we care about
LIBUSB_OPTION_NO_DEVICE_DISCOVERY = 2     # Android: don't scan sysfs/udev
LIBUSB_ERROR_BUSY = -6
LIBUSB_ERROR_NOT_SUPPORTED = -12

_LE_NAMES = {
    0: "OK", -1: "IO", -2: "INVALID_PARAM", -3: "ACCESS", -4: "NO_DEVICE",
    -5: "NOT_FOUND", -6: "BUSY", -7: "TIMEOUT", -8: "OVERFLOW", -9: "PIPE",
    -10: "INTERRUPTED", -11: "NO_MEM", -12: "NOT_SUPPORTED", -99: "OTHER",
}

def _load_libusb():
    cands = [
        os.path.join(PREFIX, "lib", "libusb-1.0.so"),
        os.path.join(PREFIX, "lib", "libusb-1.0.so.0"),
        "libusb-1.0.so", "libusb-1.0.so.0",
    ]
    fl = ctypes.util.find_library("usb-1.0")
    if fl:
        cands.append(fl)
    for c in cands:
        try:
            return ctypes.CDLL(c, use_errno=True)
        except OSError:
            continue
    die("libusb-1.0 shared object not found. Run: pkg install libusb")

class FastbootError(Exception):
    pass

class FastbootUSB:
    """
    Minimal fastboot-protocol client over a USB fd handed in by `termux-usb`.
    Implements: getvar, oem, erase, download, flash, reboot.

    The fastboot wire protocol is dead simple: ASCII commands (<=64 bytes) on a
    bulk-OUT endpoint, replies are 4-byte-prefixed (OKAY/FAIL/INFO/DATA) on
    bulk-IN. download:%08x -> DATA%08x -> raw bytes -> OKAY.
    """

    def __init__(self, fd):
        self.lib = _load_libusb()
        self._setup_proto()
        self.ctx = ctypes.c_void_p()
        self.handle = ctypes.c_void_p()
        self.ep_in = None
        self.ep_out = None
        self.iface = 0
        self._open(fd)

    def _setup_proto(self):
        L = self.lib
        L.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        L.libusb_init.restype = ctypes.c_int
        L.libusb_exit.argtypes = [ctypes.c_void_p]
        # set_option is variadic; declare loosely
        L.libusb_set_option.restype = ctypes.c_int
        L.libusb_wrap_sys_device.argtypes = [
            ctypes.c_void_p, ctypes.c_ssize_t, ctypes.POINTER(ctypes.c_void_p)]
        L.libusb_wrap_sys_device.restype = ctypes.c_int
        L.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_claim_interface.restype = ctypes.c_int
        L.libusb_release_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_detach_kernel_driver.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_kernel_driver_active.argtypes = [ctypes.c_void_p, ctypes.c_int]
        L.libusb_control_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint16,
            ctypes.c_uint16, ctypes.c_char_p, ctypes.c_uint16, ctypes.c_uint]
        L.libusb_control_transfer.restype = ctypes.c_int
        L.libusb_bulk_transfer.argtypes = [
            ctypes.c_void_p, ctypes.c_uint8, ctypes.c_void_p, ctypes.c_int,
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
        L.libusb_bulk_transfer.restype = ctypes.c_int

    def _chk(self, r, what):
        if r < 0:
            name = _LE_NAMES.get(r, str(r))
            raise FastbootError(f"{what} failed: libusb error {name} ({r})")
        return r

    def _open(self, fd):
        L = self.lib
        # Must precede init on Android so libusb won't try to enumerate via sysfs.
        try:
            L.libusb_set_option(None, ctypes.c_int(LIBUSB_OPTION_NO_DEVICE_DISCOVERY))
        except Exception:
            pass
        self._chk(L.libusb_init(ctypes.byref(self.ctx)), "libusb_init")
        self._chk(L.libusb_wrap_sys_device(self.ctx, ctypes.c_ssize_t(int(fd)),
                                           ctypes.byref(self.handle)),
                  "libusb_wrap_sys_device")
        self._find_endpoints()
        # detach a kernel driver if one grabbed the interface (rare here)
        try:
            if L.libusb_kernel_driver_active(self.handle, self.iface) == 1:
                L.libusb_detach_kernel_driver(self.handle, self.iface)
        except Exception:
            pass
        r = L.libusb_claim_interface(self.handle, self.iface)
        if r == LIBUSB_ERROR_BUSY:
            try:
                L.libusb_detach_kernel_driver(self.handle, self.iface)
            except Exception:
                pass
            r = L.libusb_claim_interface(self.handle, self.iface)
        self._chk(r, "libusb_claim_interface")

    def _get_config_descriptor(self):
        # GET_DESCRIPTOR(config, index 0): bmRequestType=0x80, bRequest=0x06,
        # wValue=(0x02<<8)|0. First read 9 bytes for wTotalLength, then full.
        buf = ctypes.create_string_buffer(9)
        n = self.lib.libusb_control_transfer(
            self.handle, 0x80, 0x06, (0x02 << 8) | 0, 0, buf, 9, 1000)
        self._chk(n, "GET_DESCRIPTOR(config,len)")
        if n < 4:
            raise FastbootError("short config descriptor")
        total = struct.unpack_from("<H", buf.raw, 2)[0]
        full = ctypes.create_string_buffer(total)
        n = self.lib.libusb_control_transfer(
            self.handle, 0x80, 0x06, (0x02 << 8) | 0, 0, full, total, 1000)
        self._chk(n, "GET_DESCRIPTOR(config,full)")
        return full.raw[:n]

    def _find_endpoints(self):
        data = self._get_config_descriptor()
        i = 0
        cur_iface = None
        fastboot_iface = None
        fallback = None
        eps = {}  # iface_num -> {"in":..,"out":..,"class":..}
        while i + 1 < len(data):
            blen = data[i]
            btype = data[i + 1]
            if blen == 0:
                break
            if btype == 0x04 and i + 8 < len(data):       # INTERFACE
                cur_iface = data[i + 2]
                icls, isub, iproto = data[i + 5], data[i + 6], data[i + 7]
                eps.setdefault(cur_iface, {"in": None, "out": None})
                eps[cur_iface]["class"] = (icls, isub, iproto)
                if (icls, isub, iproto) == (0xFF, 0x42, 0x03):
                    fastboot_iface = cur_iface
            elif btype == 0x05 and cur_iface is not None:  # ENDPOINT
                addr = data[i + 2]
                attr = data[i + 3]
                if attr & 0x03 == 0x02:                    # bulk
                    if addr & 0x80:
                        eps[cur_iface]["in"] = addr
                    else:
                        eps[cur_iface]["out"] = addr
                    if eps[cur_iface]["in"] and eps[cur_iface]["out"]:
                        fallback = fallback if fallback is not None else cur_iface
            i += blen

        pick = fastboot_iface if fastboot_iface is not None else fallback
        if pick is None or not eps.get(pick, {}).get("in") or not eps[pick].get("out"):
            raise FastbootError(
                "No fastboot bulk interface found. Is the device actually in "
                "fastboot/fastbootd? (recovery-sideload speaks adb, not fastboot)")
        self.iface = pick
        self.ep_in = eps[pick]["in"]
        self.ep_out = eps[pick]["out"]

    # ---- low level transfers ------------------------------------------------
    def _bulk_out(self, data, timeout=20000):
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        sent = ctypes.c_int(0)
        self._chk(self.lib.libusb_bulk_transfer(
            self.handle, self.ep_out, buf, len(data),
            ctypes.byref(sent), timeout), "bulk_out")
        return sent.value

    def _bulk_in(self, n=256, timeout=20000):
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_int(0)
        self._chk(self.lib.libusb_bulk_transfer(
            self.handle, self.ep_in, buf, n,
            ctypes.byref(got), timeout), "bulk_in")
        return buf.raw[:got.value]

    def _read_response(self, timeout=20000):
        """Loop reading INFO lines until terminal OKAY/FAIL. Returns dict."""
        info_lines = []
        while True:
            resp = self._bulk_in(256, timeout)
            tag, rest = resp[:4], resp[4:]
            if tag == b"INFO":
                info_lines.append(rest.decode("utf-8", "replace"))
            elif tag == b"OKAY":
                return {"status": "OKAY",
                        "payload": rest.decode("utf-8", "replace"),
                        "info": info_lines}
            elif tag == b"FAIL":
                return {"status": "FAIL",
                        "payload": rest.decode("utf-8", "replace"),
                        "info": info_lines}
            elif tag == b"DATA":
                # caller should have handled DATA explicitly
                return {"status": "DATA",
                        "payload": rest.decode("utf-8", "replace"),
                        "info": info_lines}
            else:
                return {"status": "TEXT",
                        "payload": resp.decode("utf-8", "replace"),
                        "info": info_lines}

    # ---- protocol commands --------------------------------------------------
    def command(self, cmd, timeout=20000):
        self._bulk_out(cmd.encode("utf-8"), timeout)
        return self._read_response(timeout)

    def getvar(self, name):
        r = self.command(f"getvar:{name}")
        if r["status"] == "OKAY":
            return r["payload"] or (r["info"][-1] if r["info"] else "")
        return None

    def oem(self, sub, timeout=20000):
        return self.command(f"oem {sub}", timeout)

    def get_unlock_data(self):
        r = self.oem("get_unlock_data")
        # Moto returns the blob across INFO lines like "(bootloader) <chunk>"
        chunks = [re.sub(r"^\(bootloader\)\s*", "", ln).strip()
                  for ln in r["info"]]
        blob = "".join(chunks).replace(" ", "")
        return blob, r

    def download(self, data, timeout=120000):
        self._bulk_out(f"download:{len(data):08x}".encode(), timeout)
        first = self._bulk_in(256, timeout)
        if first[:4] != b"DATA":
            raise FastbootError(
                f"expected DATA, got {first[:64]!r} "
                "(locked bootloader rejects downloads/flashing)")
        # send raw payload in chunks with progress
        view = memoryview(data)
        total = len(data)
        sent = 0
        chunk = 1 << 20  # 1 MiB
        while sent < total:
            end = min(sent + chunk, total)
            self._bulk_out(view[sent:end].tobytes(), timeout)
            sent = end
            pct = sent * 100 // total
            print(f"\r    upload {pct:3d}%  ({sent}/{total})", end="", flush=True)
        print()
        return self._read_response(timeout)

    def flash(self, partition, path, max_dl=None, timeout=300000):
        size = os.path.getsize(path)
        if max_dl and size > max_dl:
            raise FastbootError(
                f"{os.path.basename(path)} is {size} bytes > device "
                f"max-download-size {max_dl}. This file must be sparse-split; "
                "use a PC fastboot or a pre-chunked Motorola package.")
        with open(path, "rb") as f:
            data = f.read()
        r = self.download(data, timeout)
        if r["status"] != "OKAY":
            raise FastbootError(f"download of {path} -> {r['status']} {r['payload']}")
        return self.command(f"flash:{partition}", timeout)

    def erase(self, partition, timeout=120000):
        return self.command(f"erase:{partition}", timeout)

    def reboot(self, target=None, timeout=8000):
        cmd = {None: "reboot", "bootloader": "reboot-bootloader",
               "fastboot": "reboot-fastboot", "recovery": "reboot-recovery"}[target]
        try:
            return self.command(cmd, timeout)
        except FastbootError:
            # device usually drops the link as it reboots; treat as success
            return {"status": "OKAY", "payload": "(link dropped on reboot)", "info": []}

    def close(self):
        try:
            self.lib.libusb_release_interface(self.handle, self.iface)
        except Exception:
            pass
        try:
            self.lib.libusb_exit(self.ctx)
        except Exception:
            pass

# --------------------------------------------------------------------------- #
#  Worker mode: invoked under `termux-usb -e`, receives the fd as last argv.
#  Reads one action from $FBR_ACTION (JSON), writes result to $FBR_RESULT.
# --------------------------------------------------------------------------- #

def worker_main(fd):
    action = json.loads(os.environ.get("FBR_ACTION", "{}"))
    result_path = os.environ["FBR_RESULT"]
    out = {"ok": False}
    fb = None
    try:
        fb = FastbootUSB(fd)
        op = action.get("op")
        if op == "info":
            out["vars"] = {v: fb.getvar(v) for v in action["vars"]}
            out["ok"] = True
        elif op == "get_unlock_data":
            blob, raw = fb.get_unlock_data()
            out.update(ok=True, blob=blob, raw=raw)
        elif op == "oem":
            out["resp"] = fb.oem(action["arg"]); out["ok"] = True
        elif op == "erase":
            out["resp"] = fb.erase(action["partition"]); out["ok"] = True
        elif op == "flash":
            out["resp"] = fb.flash(action["partition"], action["path"],
                                   max_dl=action.get("max_dl")); out["ok"] = True
        elif op == "reboot":
            out["resp"] = fb.reboot(action.get("target")); out["ok"] = True
        elif op == "command":
            out["resp"] = fb.command(action["cmd"]); out["ok"] = True
        else:
            out["error"] = f"unknown op {op!r}"
    except Exception as e:  # noqa
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        if fb:
            fb.close()
    with open(result_path, "w") as f:
        json.dump(out, f)
    # termux-usb swallows our exit status; the controller reads the JSON file.

# --------------------------------------------------------------------------- #
#  Controller-side fastboot: routes each action through termux-usb (rootless)
#  or through the OS `fastboot` binary (--system, host must be rooted).
# --------------------------------------------------------------------------- #

class Fastboot:
    def __init__(self, system=False, devnode=None):
        self.system = system
        self.devnode = devnode
        if not system:
            self._write_launcher()
            if self.devnode is None:
                self.devnode = self._pick_devnode()
            self._request_permission()

    # ---- rootless plumbing --------------------------------------------------
    def _write_launcher(self):
        ensure_work()
        with open(LAUNCHER, "w") as f:
            f.write(f"#!{PREFIX}/bin/sh\n"
                    f'exec {PREFIX}/bin/python3 "{os.path.abspath(__file__)}" '
                    f'--worker "$1"\n')
        os.chmod(LAUNCHER, 0o755)

    def _list_devnodes(self):
        if not have("termux-usb"):
            die("termux-usb not found. Run `bootstrap` and install the "
                "Termux:API app, or use --system on a rooted host.")
        r = run("termux-usb -l")
        try:
            return json.loads(r.stdout.strip() or "[]")
        except json.JSONDecodeError:
            return [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("/dev")]

    def _pick_devnode(self):
        nodes = self._list_devnodes()
        if not nodes:
            die("No USB devices visible to termux-usb. Plug the Motorola into "
                "the Pixel with an OTG-capable USB-C cable, put it in "
                "fastboot/fastbootd, and retry. (Check the cable supports data.)")
        if len(nodes) == 1:
            info(f"USB device: {nodes[0]}")
            return nodes[0]
        print("Multiple USB devices:")
        for i, n in enumerate(nodes):
            print(f"  [{i}] {n}")
        sel = input("Pick the Motorola index: ").strip()
        return nodes[int(sel)]

    def _request_permission(self):
        info(f"Requesting USB permission for {self.devnode} "
             "(tap OK on the Android dialog if it appears) ...")
        run(f'termux-usb -r "{self.devnode}"')

    def _invoke(self, action):
        fd_result = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        fd_result.close()
        env = dict(os.environ)
        env["FBR_ACTION"] = json.dumps(action)
        env["FBR_RESULT"] = fd_result.name
        cmd = ["termux-usb", "-e", LAUNCHER, self.devnode]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        try:
            with open(fd_result.name) as f:
                out = json.load(f)
        except Exception:
            out = {"ok": False,
                   "error": "no result file; termux-usb stderr: "
                            + (proc.stderr.strip()[:300] or "(empty)")}
        finally:
            try: os.unlink(fd_result.name)
            except OSError: pass
        if not out.get("ok"):
            raise FastbootError(out.get("error", "unknown worker failure"))
        return out

    # ---- system (rooted host) fastboot --------------------------------------
    def _sys(self, args, timeout=600):
        r = subprocess.run(["fastboot", *args], capture_output=True,
                           text=True, timeout=timeout)
        return r

    # ---- public API (mirrors worker ops) ------------------------------------
    def info_vars(self, names):
        if self.system:
            d = {}
            for n in names:
                r = self._sys(["getvar", n])
                m = re.search(rf"{re.escape(n)}:\s*(.*)", (r.stderr + r.stdout))
                d[n] = (m.group(1).strip() if m else None)
            return d
        return self._invoke({"op": "info", "vars": names})["vars"]

    def get_unlock_data(self):
        if self.system:
            r = self._sys(["oem", "get_unlock_data"])
            txt = r.stderr + r.stdout
            chunks = re.findall(r"\(bootloader\)\s*([0-9A-Za-z]+)", txt)
            return "".join(chunks), {"raw": txt}
        out = self._invoke({"op": "get_unlock_data"})
        return out["blob"], out["raw"]

    def oem(self, arg):
        if self.system:
            return {"raw": (self._sys(["oem", arg]).stderr)}
        return self._invoke({"op": "oem", "arg": arg})["resp"]

    def erase(self, partition):
        if self.system:
            return {"raw": self._sys(["erase", partition]).stderr}
        return self._invoke({"op": "erase", "partition": partition})["resp"]

    def flash(self, partition, path, max_dl=None):
        if self.system:
            return {"raw": self._sys(["flash", partition, path]).stderr}
        return self._invoke({"op": "flash", "partition": partition,
                             "path": path, "max_dl": max_dl})["resp"]

    def reboot(self, target=None):
        if self.system:
            arg = {None: "reboot", "bootloader": "reboot-bootloader",
                   "fastboot": "reboot fastboot", "recovery": "reboot recovery"}[target]
            return {"raw": self._sys(arg.split()).stderr}
        return self._invoke({"op": "reboot", "target": target})["resp"]

# --------------------------------------------------------------------------- #
#  Device verdict
# --------------------------------------------------------------------------- #

DETECT_VARS = ["product", "unlocked", "secure", "securestate",
               "max-download-size", "version-bootloader", "serialno",
               "current-slot", "is-userspace"]

def read_identity(fb):
    v = fb.info_vars(DETECT_VARS)
    return v

def print_verdict(v):
    head("Device")
    codename = v.get("product")
    unlocked = (v.get("unlocked") or "").lower()
    print(f"  codename (product) : {codename}")
    print(f"  bootloader unlocked: {v.get('unlocked')}")
    print(f"  secure/securestate : {v.get('secure')} / {v.get('securestate')}")
    print(f"  userspace fastboot : {v.get('is-userspace')}  "
          f"(yes = you're in fastbootd)")
    print(f"  slot               : {v.get('current-slot')}")
    print(f"  bootloader ver     : {v.get('version-bootloader')}")
    print(f"  max-download-size  : {v.get('max-download-size')}")

    head("Verdict")
    if unlocked in ("yes", "true", "1"):
        good("Bootloader is UNLOCKED. Everything is on the table:")
        print("    - kill-dpc via `fastboot -w` OR recovery wipe")
        print("    - flash-stock (full firmware)")
        print("    - root (Magisk init_boot/boot patch)")
    else:
        warn("Bootloader is LOCKED.")
        print("    - flash/erase/unlock will be REJECTED unless you can enable")
        print("      the on-device 'OEM unlocking' toggle, which you can't reach")
        print("      while locked out, and which a device owner may have killed.")
        print(f"    {C.G}- Your reliable kill is `kill-dpc` (recovery wipe). It")
        print(f"      does NOT need an unlock and bypasses DISALLOW_FACTORY_RESET.{C.X}")
        print("    - If you must reflash/root: try `unlock` (it may still be")
        print("      refused), else EDL/blankflash on a PC is the only deep path.")
    print()

# --------------------------------------------------------------------------- #
#  Commands
# --------------------------------------------------------------------------- #

def cmd_usbtest(args):
    head("USB sanity (read-only)")
    fb = Fastboot(system=args.system, devnode=args.dev)
    v = fb.info_vars(["product", "serialno"])
    if v.get("product"):
        good(f"Talked to fastboot. product={v['product']} serial={v.get('serialno')}")
    else:
        err("Got a connection but no 'product' var. If you're in recovery "
            "(adb sideload) you'll see this — that mode speaks adb, not "
            "fastboot. Reboot the target to fastboot/fastbootd.")

def cmd_detect(args):
    fb = Fastboot(system=args.system, devnode=args.dev)
    v = read_identity(fb)
    if not v.get("product"):
        die("No fastboot identity. Make sure the target is in FASTBOOT or "
            "FASTBOOTD (not recovery/sideload), the OTG cable carries data, "
            "and you approved the termux-usb permission dialog.")
    print_verdict(v)

def cmd_killdpc(args):
    head("Kill TestDPC / device owner  (the safe path, no unlock needed)")
    fb = Fastboot(system=args.system, devnode=args.dev)
    v = read_identity(fb)
    print_verdict(v)
    unlocked = (v.get("unlocked") or "").lower() in ("yes", "true", "1")

    print(f"""{C.BOLD}How the kill works{C.X}
A device owner lives in /data. Wiping userdata removes it. There is no
'dpm remove' for a device owner -- the supported removal IS a factory reset.

You have two ways to wipe, depending on the bootloader:
""")
    if unlocked:
        print(f"  {C.G}A) UNLOCKED bootloader -> wipe right now over fastboot:{C.X}")
        print("       erase userdata + metadata, then reboot. Fast, no menus.")
        print("  B) Or boot to recovery and use the on-device wipe menu.\n")
        choice = input("    [A]=fastboot wipe now, [B]=recovery menu, [q]=quit: ").strip().lower()
        if choice == "a":
            if not confirm("This ERASES ALL DATA on the target (both partitions "
                           "of userdata). The device owner dies with it.",
                           auto_yes=args.yes):
                return warn("Aborted.")
            for part in ("userdata", "metadata"):
                info(f"erase {part} ...")
                r = fb.erase(part)
                st = r.get("status", "?")
                payload = r.get("payload", "")
                if st == "OKAY":
                    good(f"{part}: erased")
                else:
                    warn(f"{part}: {st} {payload} "
                         "(metadata may not exist on all devices -- ok)")
            info("Rebooting target ...")
            fb.reboot(None)
            _frp_note()
            return
        elif choice == "q":
            return

    # Recovery-menu path (works on LOCKED bootloaders too)
    print(f"""{C.G}Recovery-menu wipe (works on locked bootloaders){C.X}
I'll reboot the target into recovery. Then ON THE TARGET:
  1. You'll likely see an Android logo / "No command".
       -> Hold POWER, tap VOLUME-UP once, release. The recovery menu appears.
  2. Volume keys to highlight {C.BOLD}Wipe data/factory reset{C.X}, POWER to select.
  3. Confirm {C.BOLD}Factory data reset{C.X}.
  4. Back on the main menu -> {C.BOLD}Reboot system now{C.X}.
This removes TestDPC/device owner. Then see the FRP note below.
""")
    if input("    Reboot target into recovery now? [y/N]: ").strip().lower() == "y":
        info("Sending reboot-recovery ...")
        fb.reboot("recovery")
        good("Sent. Finish the wipe on the device screen (steps above).")
    _frp_note()

def _frp_note():
    print(f"""
{C.BOLD}After the wipe -- Factory Reset Protection{C.X}
On first boot the device asks for the Google account that was last signed in.
Enter YOUR credentials (the account that owned the device). If you wiped a
device that had no Google account synced, there's no FRP lock to clear.
""")

def cmd_unlock(args):
    head("Bootloader unlock (Motorola portal)")
    fb = Fastboot(system=args.system, devnode=args.dev)
    v = read_identity(fb)
    if (v.get("unlocked") or "").lower() in ("yes", "true", "1"):
        return good("Already unlocked. Nothing to do.")

    info("Fetching unlock data from the device ...")
    blob, raw = fb.get_unlock_data()
    if not blob:
        err("Device returned no unlock data. On most Moto devices this means "
            "the on-device 'OEM unlocking' toggle is OFF (or disabled by your "
            "device owner). You cannot reach that toggle while locked out, so "
            "fastboot unlock is a dead end here -- use kill-dpc (recovery wipe) "
            "for the DPC, and EDL/blankflash on a PC if you truly need to "
            "reflash. Raw response below:")
        print(json.dumps(raw, indent=2)[:1500])
        return
    print(f"\n{C.BOLD}Your device unlock data:{C.X}\n{blob}\n")
    print(f"""Steps:
  1. Go to Motorola's bootloader unlock page (search "Motorola bootloader
     unlock" -> the official lenovo/motorola standalone portal). Sign in.
  2. Paste the string above, check "Can my device be unlocked?", and if eligible
     they email you an unlock KEY.
  3. Re-run:  python3 {os.path.basename(__file__)} unlock --key YOURKEY
""")
    if not args.key:
        return
    if not confirm("Unlocking ERASES ALL DATA and voids warranty.", auto_yes=args.yes):
        return warn("Aborted.")
    info("Sending unlock key ...")
    r = fb.oem(f"unlock {args.key}")
    print(json.dumps(r, indent=2)[:1500])
    # newer devices use `flashing unlock` instead of `oem unlock`
    info("If that FAILED, trying `flashing unlock` ...")
    r2 = fb.oem("unlock")  # harmless if unsupported; many take the key form above
    good("If the device rebooted and shows an 'unlocked' warning, you're done. "
         "Re-run `detect` to confirm.")

def _http_get(url, timeout=30):
    req = Request(url, headers={"User-Agent": "motorola_recover/1.0"})
    return urlopen(req, timeout=timeout)

def _list_dir(url):
    """Parse an h5ai / autoindex directory page for child hrefs."""
    try:
        html = _http_get(url).read().decode("utf-8", "replace")
    except (URLError, HTTPError) as e:
        return None, f"{e}"
    hrefs = re.findall(r'href="([^"?]+)"', html)
    items = []
    for h in hrefs:
        if h.startswith("?") or h.startswith("/") or h.startswith("http"):
            continue
        if h in ("../", "./"):
            continue
        items.append(h)
    return sorted(set(items)), None

def cmd_pull(args):
    head("Pull stock firmware (community mirror)")
    if args.url:
        return _download_to_work(args.url)

    fb = Fastboot(system=args.system, devnode=args.dev)
    codename = (fb.info_vars(["product"]) or {}).get("product")
    if not codename:
        die("Couldn't read the device codename via fastboot. You can still "
            "pass --url <direct firmware zip link>.")
    codename = codename.strip()
    good(f"Device codename: {codename}")
    # Variant matters to avoid bricks; show it if available
    try:
        carrier = fb.info_vars(["ro.carrier"]).get("ro.carrier")
        if carrier:
            info(f"carrier/variant hint: {carrier}")
    except Exception:
        pass

    bases = [
        f"https://mirrors.lolinet.com/firmware/moto/{codename}/official/",
        f"https://mirrors.lolinet.com/firmware/moto/{codename}/",
    ]
    found = None
    for b in bases:
        items, e = _list_dir(b)
        if items:
            found = (b, items)
            break
    if not found:
        warn("Couldn't auto-locate this codename under the legacy /moto/ tree.")
        print(f"""Newer Motos live under the year-organised tree:
    https://mirrors.lolinet.com/firmware/lenomola/
Open it, drill into the year, find {C.BOLD}{codename}{C.X}, pick your variant,
copy the .zip link, then run:
    python3 {os.path.basename(__file__)} pull-firmware --url <that-zip-link>
(MotoUpdatesTracker on Telegram indexes codenames too.)
{C.Y}Match your exact variant (e.g. RETUS/RETBR). A wrong variant can brick.{C.X}""")
        return

    base, items = found
    info(f"Index: {base}")
    # let the user navigate one or two levels to a .zip
    cur = base
    while True:
        items, e = _list_dir(cur)
        if e:
            return err(f"listing failed: {e}")
        zips = [i for i in items if i.lower().endswith(".zip")]
        dirs = [i for i in items if i.endswith("/")]
        for idx, z in enumerate(zips):
            print(f"  [z{idx}] {z}")
        for idx, d in enumerate(dirs):
            print(f"  [d{idx}] {d}")
        sel = input("Pick z<N> to download, d<N> to enter, b=back, q=quit: ").strip().lower()
        if sel == "q":
            return
        if sel == "b":
            cur = base
            continue
        if sel.startswith("z") and sel[1:].isdigit():
            return _download_to_work(cur + zips[int(sel[1:])])
        if sel.startswith("d") and sel[1:].isdigit():
            cur = cur + dirs[int(sel[1:])]
            continue

def _download_to_work(url):
    ensure_work()
    name = url.rstrip("/").split("/")[-1]
    dest = os.path.join(WORK, name)
    info(f"Downloading {url}")
    info(f"     -> {dest}")
    try:
        resp = _http_get(url, timeout=60)
    except (URLError, HTTPError) as e:
        return err(f"download failed: {e}")
    total = int(resp.headers.get("Content-Length") or 0)
    got = 0
    t0 = time.time()
    with open(dest, "wb") as f:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            got += len(chunk)
            if total:
                pct = got * 100 // total
                spd = got / max(time.time() - t0, 0.1) / 1e6
                print(f"\r    {pct:3d}%  {got/1e6:7.1f}/{total/1e6:.1f} MB  "
                      f"{spd:5.1f} MB/s", end="", flush=True)
    print()
    good(f"Saved {dest}")
    if dest.lower().endswith(".zip"):
        outdir = dest[:-4]
        info(f"Unzipping -> {outdir}")
        try:
            with zipfile.ZipFile(dest) as z:
                z.extractall(outdir)
            ff = _find_flashfile(outdir)
            if ff:
                good(f"Found flash script: {ff}")
                print(f"Now flash with:\n    python3 "
                      f"{os.path.basename(__file__)} flash-stock {os.path.dirname(ff)}")
            else:
                warn("No flashfile.xml found inside. You may have a payload.bin "
                     "(A/B OTA) package instead -- those need a payload-dumper, "
                     "which is a separate step.")
        except zipfile.BadZipFile:
            warn("Not a zip after all; left the file as-is.")
    return dest

def _find_flashfile(root):
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.lower() in ("flashfile.xml", "servicefile.xml"):
                return os.path.join(dirpath, f)
    return None

def cmd_flashstock(args):
    head("Flash stock firmware (Motorola flashfile.xml)")
    folder = args.folder
    ff = _find_flashfile(folder) if os.path.isdir(folder) else folder
    if not ff or not os.path.exists(ff):
        die("Give me the folder containing flashfile.xml (the unzipped firmware).")
    info(f"Using {ff}")

    fb = Fastboot(system=args.system, devnode=args.dev)
    v = read_identity(fb)
    if (v.get("unlocked") or "").lower() not in ("yes", "true", "1"):
        die("Bootloader is LOCKED. Flashing will be rejected. Run `unlock` first "
            "(if your device even allows it), or use kill-dpc for the DPC.")
    max_dl = None
    try:
        max_dl = int(v.get("max-download-size"), 0) if v.get("max-download-size") else None
    except (TypeError, ValueError):
        max_dl = None

    steps = _parse_flashfile(ff)
    base = os.path.dirname(ff)
    head(f"{len(steps)} flash steps parsed")
    for s in steps:
        print(f"  {s['operation']:16} {s.get('partition') or s.get('var') or ''} "
              f"{s.get('filename') or ''}")
    print()
    if not confirm("This reflashes the device and ERASES DATA. A wrong-variant "
                   "package can BRICK it. Confirm you matched the variant.",
                   auto_yes=args.yes):
        return warn("Aborted.")

    for s in steps:
        op = s["operation"]
        if op == "flash":
            path = os.path.join(base, s["filename"])
            if not os.path.exists(path):
                warn(f"skip flash {s['partition']}: missing {s['filename']}")
                continue
            info(f"flash {s['partition']}  <-  {s['filename']}")
            r = fb.flash(s["partition"], path, max_dl=max_dl)
            _report_step(r, f"flash {s['partition']}")
        elif op == "erase":
            info(f"erase {s['partition']}")
            _report_step(fb.erase(s["partition"]), f"erase {s['partition']}")
        elif op == "oem":
            info(f"oem {s.get('var')}")
            _report_step(fb.oem(s.get("var", "")), f"oem {s.get('var')}")
        elif op in ("getvar",):
            val = fb.info_vars([s.get("var", "")]).get(s.get("var", ""))
            info(f"getvar {s.get('var')} = {val}")
        elif op in ("reboot-bootloader",):
            info("reboot-bootloader"); fb.reboot("bootloader"); time.sleep(6)
        elif op in ("reboot",):
            info("reboot"); fb.reboot(None)
        else:
            warn(f"unhandled flashfile op '{op}' -- skipping")
    good("Flash sequence complete. If the device boots, see the FRP note.")
    _frp_note()

def _report_step(r, label):
    st = (r or {}).get("status", "?")
    if st == "OKAY":
        good(f"{label}: OKAY")
    else:
        warn(f"{label}: {st} {(r or {}).get('payload','')} "
             f"{(r or {}).get('raw','')[:160]}")

def _parse_flashfile(path):
    import xml.etree.ElementTree as ET
    txt = open(path, "r", errors="replace").read()
    # flashfile.xml sometimes has a stray header; be lenient
    m = re.search(r"<flashing>.*</flashing>", txt, re.S)
    xml = m.group(0) if m else txt
    steps = []
    try:
        root = ET.fromstring(xml)
        for el in root.iter("step"):
            steps.append({k: el.attrib[k] for k in el.attrib})
    except ET.ParseError:
        # fall back to regex over <step .../>
        for mm in re.finditer(r"<step\s+([^/>]+)/?>", txt):
            attrs = dict(re.findall(r'(\w+)="([^"]*)"', mm.group(1)))
            steps.append(attrs)
    # normalize key name
    for s in steps:
        s["operation"] = s.get("operation") or s.get("op") or ""
    return steps

def cmd_root(args):
    head("Root via Magisk  (EXPERIMENTAL -- needs UNLOCKED bootloader)")
    fb = Fastboot(system=args.system, devnode=args.dev)
    v = read_identity(fb)
    if (v.get("unlocked") or "").lower() not in ("yes", "true", "1"):
        die("Bootloader is LOCKED. Root is impossible until it's unlocked.")
    if not args.firmware:
        die("Pass --firmware <unzipped firmware dir> so I can grab the stock "
            "init_boot.img / boot.img to patch.")
    src_dir = args.firmware
    boot_img = None
    for cand in ("init_boot.img", "boot.img"):
        for dp, _d, fs in os.walk(src_dir):
            if cand in fs:
                boot_img = os.path.join(dp, cand)
                break
        if boot_img:
            partition = cand[:-4]  # init_boot or boot
            break
    if not boot_img:
        die("Couldn't find init_boot.img or boot.img in the firmware dir. "
            "Android 16 / GKI devices use init_boot for the Magisk patch.")
    good(f"Will patch {os.path.basename(boot_img)} (partition: {partition})")

    ensure_work()
    apk = os.path.join(WORK, "magisk.apk")
    if not os.path.exists(apk):
        info("Resolving latest Magisk release from GitHub ...")
        try:
            data = json.loads(_http_get(
                "https://api.github.com/repos/topjohnwu/Magisk/releases/latest"
            ).read().decode())
            asset = next(a for a in data["assets"]
                         if a["name"].lower().endswith(".apk"))
            info(f"Downloading {asset['name']} ...")
            with open(apk, "wb") as f:
                f.write(_http_get(asset["browser_download_url"], 120).read())
        except Exception as e:
            die(f"Magisk download failed: {e}. You can drop a Magisk APK at "
                f"{apk} manually and re-run.")
    good(f"Magisk APK: {apk}")

    # Extract magiskboot + boot_patch.sh + libs from the APK
    pdir = os.path.join(WORK, "magisk_patch")
    shutil.rmtree(pdir, ignore_errors=True)
    os.makedirs(pdir)
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        wanted_libs = [n for n in names if n.startswith("lib/arm64-v8a/")]
        wanted_assets = [n for n in names
                         if n.startswith("assets/") and
                         (n.endswith(".sh") or n.endswith(".apk") or
                          "stub" in n or "init-ld" in n)]
        for n in wanted_libs + wanted_assets:
            tgt = os.path.join(pdir, os.path.basename(n))
            with z.open(n) as s, open(tgt, "wb") as o:
                shutil.copyfileobj(s, o)
    # rename libfoo.so -> foo
    for fn in list(os.listdir(pdir)):
        if fn.startswith("lib") and fn.endswith(".so"):
            os.rename(os.path.join(pdir, fn),
                      os.path.join(pdir, fn[3:-3]))
            os.chmod(os.path.join(pdir, fn[3:-3]), 0o755)
    shutil.copy(boot_img, os.path.join(pdir, os.path.basename(boot_img)))

    bps = os.path.join(pdir, "boot_patch.sh")
    if not os.path.exists(bps):
        die("boot_patch.sh not found in this Magisk APK layout. Reliable "
            "fallback: install the Magisk app on ANY working Android phone, use "
            "'Install > Select and Patch a File' on this img, then run "
            f"`flash-stock`-style: fastboot flash {partition} <magisk_patched.img>.")

    info("Running Magisk boot_patch.sh (no root needed for patching) ...")
    env = dict(os.environ, KEEPVERITY="true", KEEPFORCEENCRYPT="true",
               RECOVERYMODE="false")
    r = subprocess.run(["sh", "boot_patch.sh", os.path.basename(boot_img)],
                       cwd=pdir, env=env, capture_output=True, text=True)
    print(r.stdout[-1500:])
    if r.returncode != 0:
        err(r.stderr[-1500:])
        die("boot_patch.sh failed (Magisk's internal layout shifts between "
            "versions). Use the Magisk-app patch method described above, then "
            f"fastboot flash {partition} the result.")
    patched = os.path.join(pdir, "new-boot.img")
    if not os.path.exists(patched):
        die("Patch produced no new-boot.img. Use the Magisk-app method.")
    good(f"Patched image: {patched}")

    if not confirm(f"Flash patched image to '{partition}'? (Wrong partition can "
                   "soft-brick; you can recover via flash-stock.)",
                   auto_yes=args.yes):
        return warn("Aborted; patched image left at " + patched)
    max_dl = None
    try:
        max_dl = int(v.get("max-download-size"), 0)
    except (TypeError, ValueError):
        pass
    info(f"flash {partition} <- new-boot.img")
    _report_step(fb.flash(partition, patched, max_dl=max_dl), f"flash {partition}")
    info("Rebooting ...")
    fb.reboot(None)
    good("If it boots, open the Magisk app to finish setup. You now own root. "
         "Use it more carefully than Buster used TestDPC.")

# --------------------------------------------------------------------------- #
#  Interactive menu
# --------------------------------------------------------------------------- #

MENU = [
    ("detect",        "Read device identity + what's possible (start here)", cmd_detect),
    ("kill-dpc",      "Remove TestDPC/device owner via wipe (safe, no unlock)", cmd_killdpc),
    ("unlock",        "Get unlock data + Motorola portal + unlock", cmd_unlock),
    ("pull-firmware", "Download stock firmware from the mirror", cmd_pull),
    ("flash-stock",   "Flash an unzipped firmware folder", None),
    ("root",          "Patch + flash Magisk (needs unlock)", None),
    ("usb-test",      "Raw USB sanity check", cmd_usbtest),
    ("bootstrap",     "Install Termux packages", cmd_bootstrap),
]

def interactive(args):
    head("Motorola TestDPC recovery -- interactive")
    print("Target should be in fastboot / fastbootd, plugged into the Pixel "
          "via OTG.\n")
    for i, (name, desc, _fn) in enumerate(MENU):
        print(f"  [{i}] {C.BOLD}{name:<14}{C.X} {desc}")
    print("  [q] quit")
    sel = input("\nChoose: ").strip().lower()
    if sel == "q":
        return
    try:
        name, _desc, fn = MENU[int(sel)]
    except (ValueError, IndexError):
        return err("bad choice")
    if name == "flash-stock":
        args.folder = input("Path to unzipped firmware folder: ").strip()
        return cmd_flashstock(args)
    if name == "root":
        args.firmware = input("Path to unzipped firmware folder: ").strip()
        return cmd_root(args)
    return fn(args)

# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Rootless Termux recovery for TestDPC-locked Motorola devices.")
    p.add_argument("--worker", metavar="FD",
                   help="(internal) USB worker invoked by termux-usb")
    p.add_argument("--system", action="store_true",
                   help="use OS fastboot binary (rooted host) instead of libusb")
    p.add_argument("--dev", help="USB devnode (skip auto-pick)")
    p.add_argument("--yes", action="store_true",
                   help="skip typed confirmations (dangerous)")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("bootstrap")
    sub.add_parser("detect")
    sub.add_parser("usb-test")
    sub.add_parser("kill-dpc")

    up = sub.add_parser("unlock")
    up.add_argument("--key", help="unlock key emailed by Motorola")

    pp = sub.add_parser("pull-firmware")
    pp.add_argument("--url", help="direct firmware zip URL")

    fp = sub.add_parser("flash-stock")
    fp.add_argument("folder", help="unzipped firmware folder (has flashfile.xml)")

    rp = sub.add_parser("root")
    rp.add_argument("--firmware", help="unzipped firmware folder with init_boot/boot")
    return p

def main():
    args = build_parser().parse_args()

    # Worker mode short-circuits everything (runs under termux-usb -e).
    if args.worker is not None:
        worker_main(int(args.worker))
        return

    dispatch = {
        "bootstrap": cmd_bootstrap, "detect": cmd_detect, "usb-test": cmd_usbtest,
        "kill-dpc": cmd_killdpc, "unlock": cmd_unlock, "pull-firmware": cmd_pull,
        "flash-stock": cmd_flashstock, "root": cmd_root,
    }
    if not args.cmd:
        # default-init firmware/folder attrs so menu can fill them
        args.folder = None
        args.firmware = None
        args.url = getattr(args, "url", None)
        args.key = getattr(args, "key", None)
        return interactive(args)
    return dispatch[args.cmd](args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
    except FastbootError as e:
        err(str(e))
        sys.exit(2)
