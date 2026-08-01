#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
moto_recover_avf.py
===================
Recovery + prep tool for a Motorola device that a misconfigured TestDPC (device
owner) locked into a managed/kiosk state with a forgotten PIN.

Target runtime: the Android 16 "Linux Terminal" -- i.e. the AVF Debian VM
(crosvm / pKVM), toggled at Settings > System > Developer options > Linux
development environment. This is REAL Debian: apt, glibc, real fastboot/adb.
NOT Termux. The script uses the stock Debian `fastboot`/`adb` packages.

=============================  READ THIS FIRST  ============================
THE USB WALL (the thing that decides if this can flash at all):

  The Terminal VM only has virtio devices. There is NO host-USB passthrough
  exposed by the Terminal app, and no UI to attach an OTG device to the guest.
  On a STOCK, UNROOTED Pixel, `fastboot`/`adb` inside this VM will see ZERO
  devices no matter what you plug in -- the bits never enter the VM.

  Therefore this tool runs in two halves:
    * PREP (works in the VM today, no device link needed):
        pull-firmware, unzip, parse flashfile.xml, magisk-patch init_boot/boot.
    * DEVICE (only works once a USB path exists -- see `bridge`):
        detect, kill-dpc, unlock, flash-stock, root.

  Run `python3 moto_recover_avf.py bridge` for the three ways to actually get
  the Motorola in front of fastboot. The honest short version:
    - Stock VM            -> impossible. Prep here, flash on a real machine.
    - Rooted host + DIY crosvm with --usb + `crosvm usb attach` -> advanced.
    - A real Linux PC, OR the Android host via a libusb fastboot (e.g.
      nohajc/termux-fastboot) -> the only no-PC, no-host-root USB route, and it
      lives OUTSIDE this VM.
    - Motorola + LOCKED bootloader deep recovery -> EDL/blankflash on a PC.
===========================================================================

THE OTHER WALLS:
  * A device owner can't be removed by dpm/pm. The supported removal is a
    factory reset; a reset from RECOVERY or the BOOTLOADER bypasses the
    DISALLOW_FACTORY_RESET policy your DPC set. -> `kill-dpc`.
  * fastboot flash/erase/unlock need an UNLOCKED bootloader. Unlock needs the
    on-device "OEM unlocking" toggle ON -- unreachable while locked out, and a
    device owner can hard-off it. If so: reflash/root are impossible; only the
    recovery wipe (or EDL on a PC) gets you out.
  * After any wipe, FRP asks for the Google account last on the device. Sign in
    with YOUR account. This tool does not bypass FRP.

USAGE
  python3 moto_recover_avf.py                 # interactive menu
  python3 moto_recover_avf.py setup           # apt install fastboot adb + udev
  python3 moto_recover_avf.py bridge          # how to connect the device
  python3 moto_recover_avf.py detect          # read-only identity + verdict
  python3 moto_recover_avf.py kill-dpc        # recovery/fastboot wipe (the fix)
  python3 moto_recover_avf.py unlock [--key K]
  python3 moto_recover_avf.py pull-firmware [--url URL]
  python3 moto_recover_avf.py flash-stock DIR
  python3 moto_recover_avf.py root --firmware DIR
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# --------------------------------------------------------------------------- #
#  console
# --------------------------------------------------------------------------- #
class C:
    R="\033[31m"; G="\033[32m"; Y="\033[33m"; B="\033[34m"; CY="\033[36m"
    BD="\033[1m"; DIM="\033[2m"; X="\033[0m"

def info(m): print(f"{C.CY}[*]{C.X} {m}")
def good(m): print(f"{C.G}[+]{C.X} {m}")
def warn(m): print(f"{C.Y}[!]{C.X} {m}")
def err(m):  print(f"{C.R}[x]{C.X} {m}")
def head(m): print(f"\n{C.BD}{C.B}== {m} =={C.X}")
def die(m, code=1): err(m); sys.exit(code)

HOME = os.environ.get("HOME", os.path.expanduser("~"))
WORK = os.path.join(HOME, "moto_work")

def ensure_work(): os.makedirs(WORK, exist_ok=True)
def have(c): return shutil.which(c) is not None

def sh(cmd, sudo=False, timeout=None, check=False):
    if isinstance(cmd, str):
        cmd = cmd.split()
    if sudo and os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {r.returncode}\n{r.stderr}")
    return r

def confirm(prompt, auto_yes=False):
    if auto_yes:
        warn(f"--yes given, auto-confirming: {prompt}"); return True
    print(f"{C.Y}{prompt}{C.X}")
    return input(f"    Type {C.BD}WIPE{C.X} to proceed: ").strip() == "WIPE"


# --------------------------------------------------------------------------- #
#  environment / setup
# --------------------------------------------------------------------------- #
def is_debian():
    return os.path.exists("/etc/debian_version")

def in_avf_vm():
    # best-effort: AVF guest reports a hypervisor; also check for the kvm hint
    try:
        v = sh(["systemd-detect-virt"]).stdout.strip()
        return v not in ("", "none")
    except Exception:
        return False

def cmd_setup(_a):
    head("Setup (Debian / AVF Terminal VM)")
    if not is_debian():
        warn("This isn't Debian. On the Android 16 Terminal you ARE in Debian; "
             "elsewhere just install fastboot/adb from your package manager.")
    info("apt-get update ...")
    sh("apt-get update", sudo=True)
    pkgs = ["fastboot", "adb", "android-sdk-platform-tools-common",
            "unzip", "curl", "python3"]
    info(f"Installing: {' '.join(pkgs)}")
    r = sh(["apt-get", "install", "-y", *pkgs], sudo=True, timeout=900)
    if r.returncode != 0:
        warn("apt install hiccup:\n" + r.stderr.strip()[:400])
        warn("If 'fastboot'/'adb' aren't found as packages on your release, try "
             "`apt-get install -y android-tools-adb android-tools-fastboot`.")
    # udev rules only matter once a USB device is actually attached to the VM
    info("Ensuring Android udev rules + plugdev membership (for when USB works)...")
    sh(["usermod", "-aG", "plugdev", os.environ.get("USER", "droid")], sudo=True)
    sh(["udevadm", "control", "--reload-rules"], sudo=True)
    sh(["udevadm", "trigger"], sudo=True)
    print()
    if have("fastboot"):
        good(f"fastboot present: {sh(['fastboot','--version']).stdout.splitlines()[0]}")
    else:
        err("fastboot still not on PATH -- check the apt output above.")
    print(f"\nNext: {C.BD}python3 {os.path.basename(__file__)} bridge{C.X} "
          "to understand the USB situation, then `detect`.")


# --------------------------------------------------------------------------- #
#  the USB bridge explainer (the crux)
# --------------------------------------------------------------------------- #
def cmd_bridge(_a):
    head("Getting the Motorola in front of fastboot (the hard part)")
    print(f"""The Terminal VM has only virtio devices -- it does NOT receive USB from the
Pixel's OTG port, and there's no toggle to attach one. So inside a STOCK,
unrooted VM, `fastboot devices` is empty by design. Your options:

{C.BD}1) Stock, unrooted VM  ->  PREP ONLY{C.X}
   Do everything that needs no device here:
       pull-firmware, flash-stock --prep-only (stage files), root (patch image)
   Then flash from a machine that can actually see the phone (options 2-4).

{C.BD}2) Rooted host + your OWN crosvm with USB  ->  advanced, on-device{C.X}
   The managed Terminal VM won't let you attach USB (its control socket is
   system-owned). With ROOT on the Pixel you can launch your own crosvm with a
   USB controller and hot-attach the OTG device:
       # on the rooted Android host (adb root / su), after starting crosvm:
       crosvm usb attach <bus>:<addr>:<vid>:<pid> /dev/bus/usb/BBB/DDD \\
              /path/to/your-crosvm.sock
   Reading /dev/bus/usb/* and owning the socket both require host root. Exact
   `usb attach` syntax shifts between crosvm builds -- see
   crosvm.dev/book/devices/usb.html. Your Pixel being under a Device-Owner with
   factory-reset blocked makes rooting the host its own fight.

{C.BD}3) A real Linux PC (or the Android host via libusb fastboot){C.X}
   - Any Linux/Windows/Mac PC with platform-tools: copy the prepped files over
     and flash. Simplest, most reliable.
   - No PC and won't root the Pixel? The ONLY on-device USB-fastboot path runs
     OUTSIDE this VM, on the Android host, using a libusb build that takes a
     termux-usb file descriptor (e.g. `nohajc/termux-fastboot`, a drop-in
     fastboot that works unrooted via the USB host API). That's an Android-host
     tool, not a Debian-VM tool -- but it's the genuine no-PC, no-root route.

{C.BD}4) Motorola + LOCKED bootloader, deep recovery  ->  EDL/blankflash on a PC{C.X}
   If the bootloader is locked AND OEM-unlock is off (likely, given the DPC),
   neither fastboot flashing nor unlock will work anywhere. The Qualcomm EDL
   (9008) blankflash route on a PC is then the only deep fix. Lolinet hosts
   per-device blankflash packages.

This tool's PREP commands work in case 1; its DEVICE commands (detect/kill-dpc/
unlock/flash-stock/root) light up automatically in cases 2-3 once
`fastboot devices` shows the Motorola.
""")


# --------------------------------------------------------------------------- #
#  fastboot wrappers (real binary)
# --------------------------------------------------------------------------- #
class Fastboot:
    def __init__(self):
        if not have("fastboot"):
            die("`fastboot` not found. Run `setup` first.")

    def _run(self, args, timeout=600):
        return sh(["fastboot", *args], timeout=timeout)

    def devices(self):
        out = self._run(["devices"]).stdout.strip()
        return [l.split()[0] for l in out.splitlines() if l.strip()]

    def getvar(self, name):
        r = self._run(["getvar", name])
        blob = r.stderr + r.stdout  # fastboot prints getvar to stderr
        m = re.search(rf"^{re.escape(name)}:\s*(.*)$", blob, re.M)
        return m.group(1).strip() if m else None

    def getvars(self, names):
        return {n: self.getvar(n) for n in names}

    def get_unlock_data(self):
        r = self._run(["oem", "get_unlock_data"])
        blob = r.stderr + r.stdout
        chunks = re.findall(r"(?:\(bootloader\)\s*)?([0-9A-Fa-f]{4,})", blob)
        return "".join(chunks), blob

    def oem(self, arg, timeout=120):
        return self._run(["oem", *arg.split()], timeout=timeout)

    def flashing(self, arg, timeout=120):
        return self._run(["flashing", *arg.split()], timeout=timeout)

    def erase(self, part, timeout=120):
        return self._run(["erase", part], timeout=timeout)

    def wipe(self, timeout=300):
        return self._run(["-w"], timeout=timeout)

    def flash(self, part, path, timeout=1200):
        # real fastboot handles sparse splitting itself; no manual chunking.
        return self._run(["flash", part, path], timeout=timeout)

    def reboot(self, target=None, timeout=30):
        arg = {None: ["reboot"], "bootloader": ["reboot", "bootloader"],
               "fastboot": ["reboot", "fastboot"],
               "recovery": ["reboot", "recovery"]}[target]
        return self._run(arg, timeout=timeout)


def require_device(fb, what="this operation"):
    devs = fb.devices()
    if not devs:
        err(f"No fastboot device visible -- {what} can't run.")
        print(f"{C.Y}Expected on a stock VM: there's no USB passthrough.{C.X} "
              f"Run `python3 {os.path.basename(__file__)} bridge`.")
        return None
    if len(devs) > 1:
        warn(f"Multiple fastboot devices: {devs} -- using the first.")
    good(f"fastboot device: {devs[0]}")
    return devs[0]


DETECT_VARS = ["product", "unlocked", "secure", "securestate",
               "max-download-size", "version-bootloader", "serialno",
               "current-slot", "is-userspace", "ro.carrier"]

def print_verdict(v):
    head("Device")
    print(f"  codename (product) : {v.get('product')}")
    print(f"  bootloader unlocked: {v.get('unlocked')}")
    print(f"  secure / state     : {v.get('secure')} / {v.get('securestate')}")
    print(f"  userspace fastboot : {v.get('is-userspace')} (yes = fastbootd)")
    print(f"  slot / variant     : {v.get('current-slot')} / {v.get('ro.carrier')}")
    print(f"  bootloader / maxdl : {v.get('version-bootloader')} / "
          f"{v.get('max-download-size')}")
    head("Verdict")
    if (v.get("unlocked") or "").lower() in ("yes", "true", "1"):
        good("Bootloader UNLOCKED -- kill-dpc (fastboot -w), flash-stock and root "
             "are all available.")
    else:
        warn("Bootloader LOCKED -- flash/erase/unlock will be refused unless you "
             "can enable on-device 'OEM unlocking' (unreachable while locked, and "
             "a device owner may have killed it).")
        print(f"    {C.G}Reliable kill: `kill-dpc` (recovery wipe) -- no unlock "
              f"needed.{C.X}  Deep reflash on a locked BL = EDL/blankflash (PC).")


# --------------------------------------------------------------------------- #
#  DEVICE commands
# --------------------------------------------------------------------------- #
def cmd_detect(a):
    fb = Fastboot()
    if require_device(fb, "detect") is None:
        return
    v = fb.getvars(DETECT_VARS)
    if not v.get("product"):
        return err("Connected but no 'product' var. If you're in recovery/"
                   "sideload that's adb, not fastboot -- reboot to bootloader.")
    print_verdict(v)

def _frp_note():
    print(f"""
{C.BD}After the wipe -- Factory Reset Protection{C.X}
First boot will ask for the Google account last synced on the device. Enter
YOUR credentials. (No synced account -> no FRP lock.)""")

def cmd_killdpc(a):
    head("Kill TestDPC / device owner")
    fb = Fastboot()
    if require_device(fb, "kill-dpc") is None:
        return
    v = fb.getvars(["unlocked"])
    unlocked = (v.get("unlocked") or "").lower() in ("yes", "true", "1")
    print("A device owner lives in /data; wiping userdata removes it. There is "
          "no 'dpm remove' for a device owner.\n")
    if unlocked:
        choice = input("  [A] fastboot -w wipe now   [B] recovery menu wipe   "
                       "[q] quit: ").strip().lower()
        if choice == "a":
            if not confirm("This ERASES ALL DATA on the target. The device owner "
                           "dies with it.", auto_yes=a.yes):
                return warn("Aborted.")
            info("fastboot -w ...")
            r = fb.wipe()
            print((r.stderr + r.stdout).strip()[-600:])
            good("Wipe issued."); fb.reboot(None); return _frp_note()
        elif choice == "q":
            return
    print(f"""{C.G}Recovery-menu wipe (works on LOCKED bootloaders too){C.X}
Rebooting target to recovery. ON THE TARGET:
  1. At the Android/"No command" screen: hold POWER, tap VOLUME-UP, release.
  2. Highlight {C.BD}Wipe data/factory reset{C.X} (vol keys), select (power).
  3. Confirm, then {C.BD}Reboot system now{C.X}.
""")
    if input("  Reboot target into recovery now? [y/N]: ").strip().lower() == "y":
        fb.reboot("recovery")
        good("Sent. Finish the wipe on the device screen.")
    _frp_note()

def cmd_unlock(a):
    head("Bootloader unlock (Motorola portal)")
    fb = Fastboot()
    if require_device(fb, "unlock") is None:
        return
    if (fb.getvar("unlocked") or "").lower() in ("yes", "true", "1"):
        return good("Already unlocked.")
    info("Reading unlock data from device ...")
    blob, raw = fb.get_unlock_data()
    if not blob:
        err("No unlock data returned. Almost always means on-device 'OEM "
            "unlocking' is OFF / disabled by the device owner -- fastboot unlock "
            "is a dead end here. Use kill-dpc for the DPC; EDL on a PC to reflash.")
        print(raw.strip()[:800]); return
    print(f"\n{C.BD}Device unlock data:{C.X}\n{blob}\n")
    print(f"""Steps:
  1. Open Motorola's official bootloader-unlock portal, sign in, paste the
     string, check eligibility -> they email an unlock KEY.
  2. Re-run:  python3 {os.path.basename(__file__)} unlock --key YOURKEY
""")
    if not a.key:
        return
    if not confirm("Unlocking ERASES ALL DATA and voids warranty.", auto_yes=a.yes):
        return warn("Aborted.")
    info("oem unlock <key> ...")
    print((fb.oem(f"unlock {a.key}").stderr + "").strip()[-400:])
    info("If that failed, trying `flashing unlock` ...")
    print((fb.flashing("unlock").stderr or "").strip()[-400:])
    good("If the device shows an unlocked warning and reboots, re-run `detect`.")


# --------------------------------------------------------------------------- #
#  PREP commands (work in the VM, no device)
# --------------------------------------------------------------------------- #
def _http(url, timeout=60):
    return urlopen(Request(url, headers={"User-Agent": "moto_recover/2.0"}),
                   timeout=timeout)

def _listdir(url):
    try:
        html = _http(url).read().decode("utf-8", "replace")
    except (URLError, HTTPError) as e:
        return None, str(e)
    items = [h for h in re.findall(r'href="([^"?]+)"', html)
             if not h.startswith(("?", "/", "http")) and h not in ("../", "./")]
    return sorted(set(items)), None

def cmd_pull(a):
    head("Pull stock firmware (lolinet mirror)")
    if a.url:
        return _download(a.url)
    codename = None
    if not a.codename:
        fb = Fastboot()
        if fb.devices():
            codename = (fb.getvar("product") or "").strip()
    codename = a.codename or codename
    if not codename:
        codename = input("Device codename (e.g. 'rhode', 'devon'): ").strip()
    if not codename:
        return err("Need a codename or --url. (Fastboot can't read it with no "
                   "device, which is expected in the VM.)")
    good(f"codename: {codename}")
    bases = [f"https://mirrors.lolinet.com/firmware/moto/{codename}/official/",
             f"https://mirrors.lolinet.com/firmware/moto/{codename}/"]
    cur = None
    for b in bases:
        items, _e = _listdir(b)
        if items:
            cur = b; break
    if not cur:
        warn("Not under the legacy /moto/ tree. Newer Motos live under the "
             "year-organised tree:")
        print(f"    https://mirrors.lolinet.com/firmware/lenomola/")
        print(f"Find {C.BD}{codename}{C.X} + your exact variant (RETUS/RETBR/...),"
              f" copy the .zip link, then:\n    python3 "
              f"{os.path.basename(__file__)} pull-firmware --url <zip>")
        print(f"{C.Y}Wrong variant can brick. Match it exactly.{C.X}")
        return
    base = cur
    while True:
        items, e = _listdir(cur)
        if e: return err(f"listing failed: {e}")
        zips = [i for i in items if i.lower().endswith(".zip")]
        dirs = [i for i in items if i.endswith("/")]
        for i, z in enumerate(zips): print(f"  [z{i}] {z}")
        for i, d in enumerate(dirs): print(f"  [d{i}] {d}")
        sel = input("z<N>=download, d<N>=enter, b=back, q=quit: ").strip().lower()
        if sel == "q": return
        if sel == "b": cur = base; continue
        if sel.startswith("z") and sel[1:].isdigit(): return _download(cur+zips[int(sel[1:])])
        if sel.startswith("d") and sel[1:].isdigit(): cur = cur+dirs[int(sel[1:])]

def _download(url):
    ensure_work()
    dest = os.path.join(WORK, url.rstrip("/").split("/")[-1])
    info(f"Downloading {url}\n     -> {dest}")
    try:
        resp = _http(url, timeout=120)
    except (URLError, HTTPError) as e:
        return err(f"download failed: {e}")
    total = int(resp.headers.get("Content-Length") or 0); got = 0; t0 = time.time()
    with open(dest, "wb") as f:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk: break
            f.write(chunk); got += len(chunk)
            if total:
                print(f"\r    {got*100//total:3d}%  {got/1e6:7.1f}/{total/1e6:.1f} MB"
                      f"  {got/max(time.time()-t0,.1)/1e6:5.1f} MB/s", end="", flush=True)
    print(); good(f"Saved {dest}")
    if dest.lower().endswith(".zip"):
        outdir = dest[:-4]; info(f"Unzipping -> {outdir}")
        try:
            with zipfile.ZipFile(dest) as z: z.extractall(outdir)
            ff = _find_flashfile(outdir)
            if ff:
                good(f"flash script: {ff}")
                print(f"Flash with:\n    python3 {os.path.basename(__file__)} "
                      f"flash-stock {os.path.dirname(ff)}")
            else:
                warn("No flashfile.xml inside (maybe a payload.bin A/B OTA -- "
                     "needs a payload dumper, separate step).")
        except zipfile.BadZipFile:
            warn("Not a zip; left as-is.")
    return dest

def _find_flashfile(root):
    for dp, _d, fs in os.walk(root):
        for f in fs:
            if f.lower() in ("flashfile.xml", "servicefile.xml"):
                return os.path.join(dp, f)
    return None

def _parse_flashfile(path):
    import xml.etree.ElementTree as ET
    txt = open(path, errors="replace").read()
    steps = []
    try:
        root = ET.fromstring(txt)
        for el in root.iter("step"):
            steps.append(dict(el.attrib))
    except ET.ParseError:
        for mm in re.finditer(r"<step\s+([^/>]+)/?>", txt):
            steps.append(dict(re.findall(r'(\w+)="([^"]*)"', mm.group(1))))
    for s in steps:
        s["operation"] = s.get("operation") or s.get("op") or ""
    return steps

def cmd_flashstock(a):
    head("Flash stock firmware (Motorola flashfile.xml)")
    folder = a.folder
    ff = _find_flashfile(folder) if folder and os.path.isdir(folder) else folder
    if not ff or not os.path.exists(ff):
        die("Give the unzipped firmware folder (containing flashfile.xml).")
    base = os.path.dirname(ff); info(f"Using {ff}")
    steps = _parse_flashfile(ff)
    head(f"{len(steps)} steps")
    for s in steps:
        print(f"  {s['operation']:16} {s.get('partition') or s.get('var') or ''} "
              f"{s.get('filename') or ''}")
    if a.prep_only:
        return good("--prep-only: files staged, nothing flashed. Copy this folder "
                    "to a machine that can see the device (see `bridge`).")
    fb = Fastboot()
    if require_device(fb, "flash-stock") is None:
        return
    if (fb.getvar("unlocked") or "").lower() not in ("yes", "true", "1"):
        die("Bootloader LOCKED -- flashing will be refused. `unlock` first, or EDL.")
    if not confirm("Reflash + ERASE DATA. A wrong-variant package can BRICK it. "
                   "Confirm you matched the variant.", auto_yes=a.yes):
        return warn("Aborted.")
    for s in steps:
        op = s["operation"]
        if op == "flash":
            p = os.path.join(base, s["filename"])
            if not os.path.exists(p):
                warn(f"skip flash {s['partition']}: missing {s['filename']}"); continue
            info(f"flash {s['partition']} <- {s['filename']}")
            _report(fb.flash(s["partition"], p), f"flash {s['partition']}")
        elif op == "erase":
            info(f"erase {s['partition']}"); _report(fb.erase(s["partition"]),
                                                     f"erase {s['partition']}")
        elif op == "oem":
            info(f"oem {s.get('var')}"); _report(fb.oem(s.get("var","")),
                                                 f"oem {s.get('var')}")
        elif op == "getvar":
            info(f"getvar {s.get('var')} = {fb.getvar(s.get('var',''))}")
        elif op in ("reboot-bootloader",):
            info("reboot-bootloader"); fb.reboot("bootloader"); time.sleep(6)
        elif op in ("reboot",):
            info("reboot"); fb.reboot(None)
        else:
            warn(f"unhandled op '{op}' -- skipping")
    good("Flash sequence complete."); _frp_note()

def _report(r, label):
    blob = ((r.stderr or "") + (r.stdout or "")).strip()
    ok = r.returncode == 0 and "FAIL" not in blob.upper()
    (good if ok else warn)(f"{label}: {'OK' if ok else 'check'} {blob[-200:]}")


# --------------------------------------------------------------------------- #
#  root (Magisk) -- patch in VM, flash where USB exists
# --------------------------------------------------------------------------- #
def cmd_root(a):
    head("Root via Magisk (EXPERIMENTAL -- needs UNLOCKED bootloader)")
    if not a.firmware:
        die("Pass --firmware <unzipped firmware dir> (for stock init_boot/boot).")
    boot_img = partition = None
    for cand in ("init_boot.img", "boot.img"):
        for dp, _d, fs in os.walk(a.firmware):
            if cand in fs:
                boot_img = os.path.join(dp, cand); partition = cand[:-4]; break
        if boot_img: break
    if not boot_img:
        die("No init_boot.img / boot.img found. Android 16/GKI uses init_boot.")
    good(f"Patching {os.path.basename(boot_img)} (partition: {partition})")
    ensure_work()
    apk = os.path.join(WORK, "magisk.apk")
    if not os.path.exists(apk):
        info("Resolving latest Magisk release ...")
        try:
            data = json.loads(_http(
                "https://api.github.com/repos/topjohnwu/Magisk/releases/latest"
            ).read().decode())
            asset = next(x for x in data["assets"] if x["name"].lower().endswith(".apk"))
            info(f"Downloading {asset['name']} ...")
            with open(apk, "wb") as f:
                f.write(_http(asset["browser_download_url"], 180).read())
        except Exception as e:
            die(f"Magisk download failed: {e}. Drop a Magisk APK at {apk} and retry.")
    pdir = os.path.join(WORK, "magisk_patch")
    shutil.rmtree(pdir, ignore_errors=True); os.makedirs(pdir)
    with zipfile.ZipFile(apk) as z:
        for n in z.namelist():
            if (n.startswith("lib/arm64-v8a/") or
                (n.startswith("assets/") and (n.endswith(".sh") or "stub" in n
                                              or n.endswith(".apk") or "init-ld" in n))):
                with z.open(n) as s, open(os.path.join(pdir, os.path.basename(n)), "wb") as o:
                    shutil.copyfileobj(s, o)
    for fn in list(os.listdir(pdir)):
        if fn.startswith("lib") and fn.endswith(".so"):
            new = os.path.join(pdir, fn[3:-3]); os.rename(os.path.join(pdir, fn), new)
            os.chmod(new, 0o755)
    shutil.copy(boot_img, os.path.join(pdir, os.path.basename(boot_img)))
    if not os.path.exists(os.path.join(pdir, "boot_patch.sh")):
        die("boot_patch.sh not in this Magisk layout. Reliable fallback: patch "
            f"{os.path.basename(boot_img)} with the Magisk APP on any working "
            f"phone, then fastboot flash {partition} the result.")
    info("Running Magisk boot_patch.sh ...")
    env = dict(os.environ, KEEPVERITY="true", KEEPFORCEENCRYPT="true", RECOVERYMODE="false")
    r = subprocess.run(["sh", "boot_patch.sh", os.path.basename(boot_img)],
                       cwd=pdir, env=env, capture_output=True, text=True)
    print((r.stdout or "")[-1200:])
    patched = os.path.join(pdir, "new-boot.img")
    if r.returncode != 0 or not os.path.exists(patched):
        err((r.stderr or "")[-1200:])
        die("Patch failed (Magisk layout shifts between versions). Use the "
            f"Magisk-app method, then fastboot flash {partition} new-boot.img.")
    good(f"Patched image: {patched}")
    out = os.path.join(WORK, f"magisk_patched_{partition}.img")
    shutil.copy(patched, out); good(f"Copy for transfer: {out}")
    fb = Fastboot()
    if not fb.devices():
        warn("No device here (expected in VM). Copy the patched image to a "
             f"machine that can flash, then: fastboot flash {partition} {os.path.basename(out)}")
        return
    if (fb.getvar("unlocked") or "").lower() not in ("yes", "true", "1"):
        die("Bootloader LOCKED -- can't flash root.")
    if not confirm(f"Flash patched image to '{partition}'?", auto_yes=a.yes):
        return warn("Aborted; image at " + out)
    info(f"flash {partition} <- new-boot.img")
    _report(fb.flash(partition, patched), f"flash {partition}")
    fb.reboot(None)
    good("If it boots, open Magisk to finish. You own root now -- handle it "
         "better than Buster handled TestDPC.")


# --------------------------------------------------------------------------- #
#  menu / entry
# --------------------------------------------------------------------------- #
MENU = [
    ("bridge",        "How to connect the Motorola (read this)", cmd_bridge),
    ("setup",         "apt install fastboot/adb + udev", cmd_setup),
    ("detect",        "Read identity + verdict (needs device)", cmd_detect),
    ("kill-dpc",      "Wipe to remove TestDPC (the fix)", cmd_killdpc),
    ("unlock",        "Unlock data + Motorola portal", cmd_unlock),
    ("pull-firmware", "Download stock firmware (no device needed)", cmd_pull),
    ("flash-stock",   "Flash an unzipped firmware folder", None),
    ("root",          "Patch + (maybe) flash Magisk", None),
]

def interactive(a):
    head("Motorola TestDPC recovery -- AVF Debian VM")
    for i, (n, d, _f) in enumerate(MENU):
        print(f"  [{i}] {C.BD}{n:<14}{C.X} {d}")
    print("  [q] quit")
    s = input("\nChoose: ").strip().lower()
    if s == "q": return
    try:
        n, _d, f = MENU[int(s)]
    except (ValueError, IndexError):
        return err("bad choice")
    if n == "flash-stock":
        a.folder = input("Unzipped firmware folder: ").strip(); return cmd_flashstock(a)
    if n == "root":
        a.firmware = input("Unzipped firmware folder: ").strip(); return cmd_root(a)
    return f(a)

def build_parser():
    p = argparse.ArgumentParser(description="Recover a TestDPC-locked Motorola "
                                "from the Android 16 Linux Terminal (AVF Debian VM).")
    p.add_argument("--yes", action="store_true", help="skip typed confirmations")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("setup"); sub.add_parser("bridge")
    sub.add_parser("detect"); sub.add_parser("kill-dpc")
    up = sub.add_parser("unlock"); up.add_argument("--key")
    pp = sub.add_parser("pull-firmware"); pp.add_argument("--url"); pp.add_argument("--codename")
    fp = sub.add_parser("flash-stock"); fp.add_argument("folder")
    fp.add_argument("--prep-only", action="store_true",
                    help="stage/validate only, don't flash")
    rp = sub.add_parser("root"); rp.add_argument("--firmware")
    return p

def main():
    a = build_parser().parse_args()
    for attr in ("folder", "firmware", "url", "codename", "key", "prep_only"):
        if not hasattr(a, attr): setattr(a, attr, None)
    dispatch = {"setup": cmd_setup, "bridge": cmd_bridge, "detect": cmd_detect,
                "kill-dpc": cmd_killdpc, "unlock": cmd_unlock,
                "pull-firmware": cmd_pull, "flash-stock": cmd_flashstock,
                "root": cmd_root}
    if not a.cmd:
        return interactive(a)
    return dispatch[a.cmd](a)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(); warn("Interrupted.")
