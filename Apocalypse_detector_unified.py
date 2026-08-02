#!/data/data/com.termux/files/usr/bin/python3
"""
Apocalypse Detector (Unified) v6.0 - The Professional's Choice

One script, three privilege tiers, auto-detected at startup — nothing to
choose, nothing dropped to make it fit:

- root: literal `su`/euid==0. Every check runs at full strength,
  commands exec directly.
- rish: no root, but Shizuku's `rish` shell is available and working.
  Commands route through it, running as whatever UID Shizuku was
  started with (root via Magisk, or shell/2000 via wireless-debugging
  pairing). The Python process itself is never elevated even when rish
  grants root for subprocess calls — this matters for OUTPUT_DIR, which
  always has to be somewhere Python's own file I/O can write directly.
- lite: no root, no rish. Commands exec directly as whatever regular
  app/shell UID is running the script. Whatever needs more than that
  reports itself as unavailable rather than silently guessing.

Every check from all three prior variants is present here; the ones
that need real privilege (raw iptables/nftables tables, bpftool, lsmod,
full process visibility) attempt to run regardless of tier and report
"unavailable at this privilege level" (SKIP, weight 0 — distinct from
both a finding and a clean result) if the underlying command fails,
rather than being silently omitted or misread as evidence of anything.
"""

import subprocess
import os
import sys
import re
import json
import time
import hashlib
import socket
import struct
import ssl
import random
import ipaddress
import shlex
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from cryptography import x509 as _x509
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

# ----------------------------------------------------------------------
# Colours & helpers
# ----------------------------------------------------------------------
C = {'red':'\033[91m','green':'\033[92m','yellow':'\033[93m','cyan':'\033[96m','magenta':'\033[95m','bold':'\033[1m','reset':'\033[0m','grey':'\033[90m'}
def p(t, c=''): print(f"{c}{t}{C['reset']}")
def ps(t):
    # Clear any stranded progress-bar remnant on the current line first —
    # progress() ends its output with \r to overwrite itself in place on
    # the *next* progress() call, but if a check finds nothing to alert
    # on, nothing else prints on that line afterward and the percentage
    # would otherwise sit there orphaned once this header's leading \n
    # moves past it.
    print('\r\033[K', end='')
    p(f"\n{C['cyan']}{C['bold']}{t}{C['reset']}")
def pl(l, w, msg, evidence=''):
    icons = {'OK':'✓','CAUTION':'⚠','CRITICAL':'✗','SKIP':'○'}
    colours = {'OK':C['green'],'CAUTION':C['yellow'],'CRITICAL':C['red'],'SKIP':C['grey']}
    print(f"  {colours[l]}{icons[l]}{C['reset']} [{l}] (w:{w}) {msg}")
    if evidence: print(f"    {C['grey']}  → {evidence[:120]}{C['reset']}")
    return {'level': l, 'weight': w, 'message': msg, 'evidence': evidence}

def unavailable(msg, err=''):
    """A check that needed more privilege than this session has —
    reported distinctly from both a finding and a clean result, weight
    0, never scored either way."""
    return pl('SKIP', 0, f"{msg} — unavailable at this privilege level", err[:100])

VERBOSE = False
MODE = None            # 'root' | 'rish' | 'lite', set by bootstrap()
RISH_PATH = None
RISH_IDENTITY = None

def _find_rish():
    """rish is installed by Shizuku's own setup one-liner, typically into
    wherever you ran it from — usually Termux's home directory."""
    if '--rish-path' in sys.argv:
        idx = sys.argv.index('--rish-path')
        if idx + 1 < len(sys.argv):
            candidate = sys.argv[idx + 1]
            if os.path.isfile(candidate):
                return candidate
    on_path = shutil.which('rish')
    if on_path:
        return on_path
    home = os.path.expanduser('~')
    for candidate in (f"{home}/rish", f"{home}/.rish",
                      "/data/data/com.termux/files/home/rish",
                      "/data/data/com.termux/files/home/.rish"):
        if os.path.isfile(candidate):
            return candidate
    return None

def run(cmd, timeout=12):
    """Run a command with list arguments – no shell=True at the Python
    level either way. In 'rish' mode, routes through Shizuku instead of
    exec'ing directly; the string handed to `rish -c` is built with
    shlex so remote shell metacharacters in any argument can't do
    anything unexpected. In 'root'/'lite' modes, execs directly."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    try:
        if MODE == 'rish' and RISH_PATH:
            shell_cmd = shlex.join(cmd) if hasattr(shlex, 'join') else ' '.join(shlex.quote(c) for c in cmd)
            r = subprocess.run([RISH_PATH, "-c", shell_cmd], capture_output=True, text=True, timeout=timeout)
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if VERBOSE and r.stderr:
            print(f"{C['grey']}[DEBUG] stderr: {r.stderr[:200]}{C['reset']}")
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        if VERBOSE:
            print(f"{C['red']}[DEBUG] Exception: {e}{C['reset']}")
        return "", str(e), -1

# ----------------------------------------------------------------------
#  Config & whitelist — resolved by bootstrap() once MODE is known,
#  since OUTPUT_DIR depends on it (a root-only path looks writable
#  through rish's elevated shell while this Python process's own file
#  I/O, which never goes through rish, still can't touch it).
# ----------------------------------------------------------------------
OUTPUT_DIR = None
WHITELIST_PATH = None
DEFAULT_WHITELIST = {
    "vpn_apps": ["com.android.vpndialogs", "org.openvpn", "com.wireguard"],
    "vpn_interfaces": ["tun0", "wg0", "ppp0"],
    "safe_kernel_modules": ["nf_nat", "nf_conntrack", "iptable_filter", "bridge", "ip_tunnel", "xfrm", "tun"],
    "safe_processes": ["netd", "dnsmasq", "sshd", "keystore", "servicemanager", "logd", "vold", "healthd", "adb"],
    "trusted_ca_orgs": ["DigiCert", "Let's Encrypt", "GlobalSign", "Amazon", "Cloudflare", "Google Trust Services",
                        "Microsoft Corporation", "Sectigo", "Entrust", "GoDaddy", "IdenTrust", "ISRG"],
    "cdn_prefixes": ["104.16.", "172.64.", "162.159.", "151.101.", "142.250.", "172.217.", "142.251.", "34.120.", "35.186.", "34.64."],
    "system_binaries": ["/system/bin/sh", "/system/bin/netd", "/system/bin/su", "/system/bin/init", "/system/bin/app_process64"],
    "score_thresholds": {"low": 30, "medium": 60},
    "expected_selinux_contexts": {
        "/system/bin/sh": ["u:object_r:shell_exec:s0"],
        "/system/bin/netd": ["u:object_r:netd_exec:s0"],
        "/system/bin/su": ["u:object_r:su_exec:s0", "u:object_r:magisk_file:s0", "u:object_r:system_file:s0"],
    }
}

def load_whitelist():
    if os.path.exists(WHITELIST_PATH):
        try:
            with open(WHITELIST_PATH) as f:
                data = json.load(f)
                for k,v in data.items():
                    if k in DEFAULT_WHITELIST and isinstance(v, list):
                        DEFAULT_WHITELIST[k].extend(v)
                    elif k in DEFAULT_WHITELIST and isinstance(v, dict):
                        DEFAULT_WHITELIST[k].update(v)
        except Exception as e:
            print(f"[!] Error loading whitelist: {e}")
    return DEFAULT_WHITELIST

WL = None  # set by bootstrap()

def bootstrap():
    """Runs at the very start of main(): detect privilege tier (root,
    rish, or lite), resolve a writable OUTPUT_DIR for it, and load the
    whitelist from there. Everything downstream reads MODE/OUTPUT_DIR/
    WHITELIST_PATH/WL as plain module globals — safe, since Python
    resolves them at call time and nothing calls a check function
    before this has run."""
    global MODE, RISH_PATH, RISH_IDENTITY, OUTPUT_DIR, WHITELIST_PATH, WL

    if os.geteuid() == 0:
        MODE = 'root'
        print(f"{C['grey']}Running as root.{C['reset']}\n")
    else:
        candidate = _find_rish()
        if candidate:
            RISH_PATH = candidate
            MODE = 'rish'  # tentative — verify below
            out, err, rc = run(["id"], timeout=10)
            if rc == 0 and out:
                RISH_IDENTITY = out
                is_root = 'uid=0(' in out
                print(f"{C['grey']}Running via Shizuku (rish) as: {out}{C['reset']}")
                if not is_root:
                    print(f"{C['yellow']}[*] Shizuku granted shell-level access, not root. Some checks (raw{C['reset']}")
                    print(f"{C['yellow']}    iptables/nftables, bpftool, lsmod) may report unavailable rather than a result.{C['reset']}")
                print()
            else:
                MODE = 'lite'
                RISH_PATH = None
        else:
            MODE = 'lite'
        if MODE == 'lite':
            print(f"{C['grey']}Running unprivileged (no root, no working Shizuku/rish found).{C['reset']}")
            print(f"{C['grey']}Checks needing more privilege will report themselves unavailable rather than guess.{C['reset']}\n")

    if '--output-dir' in sys.argv:
        idx = sys.argv.index('--output-dir')
        OUTPUT_DIR = sys.argv[idx + 1].rstrip('/') if idx + 1 < len(sys.argv) else None
    if not OUTPUT_DIR:
        if MODE == 'root':
            OUTPUT_DIR = "/data/local/apocalypse"
        else:
            # rish only elevates commands routed through it — this
            # Python process's own file I/O (open(), os.makedirs())
            # never goes through Shizuku and stays at the unprivileged
            # UID regardless of what UID rish grants for shell commands.
            # A root-only path would look writable (rish could mkdir it
            # fine) while our own writes to it still fail.
            home = os.path.expanduser('~')
            OUTPUT_DIR = f"{home}/.apocalypse_detector" if home != '~' else "/data/data/com.termux/files/home/.apocalypse_detector"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if MODE == 'root':
        os.chmod(OUTPUT_DIR, 0o750)

    WHITELIST_PATH = f"{OUTPUT_DIR}/whitelist.json"
    WL = load_whitelist()
    print(f"{C['grey']}State/output directory: {OUTPUT_DIR}{C['reset']}\n")

# ----------------------------------------------------------------------
#  Baseline creation
# ----------------------------------------------------------------------
def create_baseline():
    print(f"{C['yellow']}[*] Creating baseline...{C['reset']}")
    baseline = {}
    for path in WL["system_binaries"]:
        # Direct Python read, not routed through rish — hashing needs
        # exact bytes, and rish's subprocess capture is text-mode
        # (would corrupt binary content). Most /system/bin/* is
        # world-readable at the DAC level so this generally works even
        # unprivileged; SELinux can still deny it for some domains.
        try:
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    baseline[path] = hashlib.sha256(f.read()).hexdigest()
                print(f"  {path} -> {baseline[path][:8]}...")
            else:
                baseline[path] = None
        except PermissionError:
            baseline[path] = None
            print(f"  {path} -> {C['yellow']}permission denied at this privilege level{C['reset']}")

    init_dir_listings = {}
    for location in ["/etc/init.d", "/system/etc/init", "/vendor/etc/init"]:
        out, _, _ = run(["ls", "-1", location])
        init_dir_listings[location] = sorted(out.splitlines()) if out else []
        print(f"  {location}: {len(init_dir_listings[location])} file(s) snapshotted")
    baseline["init_dir_listings"] = init_dir_listings

    out, _, _ = run(["find", "/system", "/vendor", "/data", "-xdev", "-name", "*.rc", "-type", "f",
                      "-exec", "grep", "-l", "service", "{}", "+"], timeout=30)
    rc_files = sorted(out.splitlines()) if out else []
    baseline["rc_files_with_service"] = rc_files
    print(f"  .rc files defining services: {len(rc_files)} file(s) snapshotted")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(f"{OUTPUT_DIR}/baseline.json", "w") as f:
        json.dump(baseline, f, indent=2)
    if MODE == 'root':
        os.chmod(OUTPUT_DIR, 0o750)
    print(f"{C['green']}[+] Baseline saved to {OUTPUT_DIR}/baseline.json{C['reset']}")
    sys.exit(0)

# ----------------------------------------------------------------------
#  Progress indicator
# ----------------------------------------------------------------------
PROGRESS = 0
TOTAL_CHECKS = 0
def progress():
    global PROGRESS
    PROGRESS += 1
    if TOTAL_CHECKS > 0:
        pct = int(PROGRESS * 100 / TOTAL_CHECKS)
        print(f"{C['grey']}  [ {pct}% ]{C['reset']}", end='\r')

def set_total_checks(n):
    global TOTAL_CHECKS
    TOTAL_CHECKS = n

# ----------------------------------------------------------------------
#  Check functions
# ----------------------------------------------------------------------

def check_capabilities():
    """Reports the detected privilege tier plainly at the top of every
    scan, so the alerts that follow can be read in context."""
    alerts = []
    ps("🔎 Capability Probe")
    progress()
    if MODE == 'root':
        alerts.append(pl('OK', 0, "Running as root", ""))
    elif MODE == 'rish':
        alerts.append(pl('OK', 0, f"Running via Shizuku (rish) as: {RISH_IDENTITY}", ""))
    else:
        alerts.append(pl('OK', 0, "Running unprivileged (no root, no working Shizuku/rish) — checks needing more access will report themselves unavailable rather than guess", ""))
    return alerts

def check_root_presence():
    """Informational root-presence signals — not a risk-score
    contributor. Even under confirmed root/rish access, this is useful
    context (which root manager, custom-build signals); under lite mode
    it's the only lens available on device root status at all."""
    alerts = []
    ps("🔓 Root Presence (informational)")
    progress()
    signals = []

    out, _, rc = run(["su", "-c", "id"])
    if rc == 0 and out:
        signals.append("su is callable and grants elevated identity")

    out, _, _ = run(["ls", "-l", "/system/bin/su", "/system/xbin/su", "/sbin/su"])
    if out and 'No such file' not in out:
        signals.append("su binary present at a legacy path")

    out, _, rc = run(["pm", "list", "packages"])
    if rc == 0 and out:
        root_pkgs = [line for line in out.splitlines()
                     if re.search(r'magisk|kernelsu|apatch|supersu|superuser', line, re.I)]
        if root_pkgs:
            signals.append(f"root-manager app(s) installed: {', '.join(pkg.replace('package:', '') for pkg in root_pkgs[:3])}")
    elif MODE == 'lite':
        alerts.append(unavailable("Installed package list", out))

    tags, _, _ = run(["getprop", "ro.build.tags"])
    if tags and "test-keys" in tags:
        signals.append(f"build tags = {tags} (custom/test-signed build, common on rooted/custom ROMs)")

    if signals:
        alerts.append(pl('OK', 0, f"Device shows {len(signals)} root-presence signal(s) — informational only, not a risk finding", '; '.join(signals)))
    else:
        alerts.append(pl('OK', 0, "No root-presence signals detected from this session"))
    return alerts

def check_self_integrity():
    """Anti-tamper check on the tool's own process. Complements
    check_frida's all-process TracerPid scan (which needs read access
    to other processes' /proc/<pid>/status — full strength under
    root/rish, partial under lite) with a check that's always available
    regardless of privilege: your own /proc/self/status is always
    readable by you."""
    alerts = []
    ps("🔬 Self-Process Integrity")
    progress()
    try:
        with open('/proc/self/status') as f:
            for line in f:
                if line.startswith('TracerPid:'):
                    tracer = line.split(':', 1)[1].strip()
                    if tracer not in ('0', ''):
                        alerts.append(pl('CRITICAL', 7, "This script's own process has a non-zero TracerPid — something is attached to it (debugger/ptrace)", f"TracerPid: {tracer}"))
                    else:
                        alerts.append(pl('OK', 0, "No debugger attached to this process"))
                    break
            else:
                alerts.append(unavailable("Self TracerPid check", "TracerPid field not found"))
    except Exception as e:
        alerts.append(unavailable("Self TracerPid check", str(e)))
    return alerts

def check_common_inspection_ports():
    """A connect-attempt against default ports for common inspection/
    hooking tools (Frida server, unauthenticated ADB-over-TCP, common
    local proxy ports) — doesn't need process-listing visibility to be
    meaningful, so it's a useful corroborating signal at every privilege
    tier, including lite mode where check_frida's ps-based detection may
    have limited visibility. A successful connect is real evidence; a
    refused/timed-out one tells us nothing (most of the time nothing is
    there), so only successes get scored."""
    alerts = []
    ps("🔬 Common Inspection-Tool Ports")
    progress()
    targets = {
        27042: "Frida server default port",
        5555: "ADB over TCP default port",
        8080: "common local proxy port",
        8888: "common local proxy port",
    }
    found = []
    for port, label in targets.items():
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                found.append(f"{port} ({label})")
        except Exception:
            continue
    if found:
        alerts.append(pl('CRITICAL', 7, f"Local service(s) responding on inspection-tool port(s): {', '.join(found)}", "Connect and identify what's listening before assuming compromise — some of these are also used by legitimate dev tools"))
    else:
        alerts.append(pl('OK', 0, "No response on common inspection-tool ports (127.0.0.1)"))
    return alerts

def check_system():
    alerts = []
    ps("🔍 System Integrity")
    progress()
    out,_,_ = run(["getenforce"])
    if out not in ("Enforcing", "Permissive"):
        raw, _, _ = run(["cat", "/sys/fs/selinux/enforce"])
        if raw == "1":
            out = "Enforcing"
        elif raw == "0":
            out = "Permissive"
    if out == "Enforcing":
        alerts.append(pl('OK', 0, f"SELinux: {out}"))
    elif out == "Permissive":
        alerts.append(pl('CAUTION', 3, f"SELinux permissive (common on custom ROMs)", out))
    else:
        alerts.append(pl('CAUTION', 2, "SELinux status could not be determined", out))

    # SELinux contexts – compare against a whitelist of expected contexts
    # rather than just flagging the literal string "unconfined" (custom
    # ROMs sometimes use different-but-legitimate contexts).
    expected_contexts = WL.get("expected_selinux_contexts", {
        "/system/bin/sh": ["u:object_r:shell_exec:s0"],
        "/system/bin/netd": ["u:object_r:netd_exec:s0"],
        "/system/bin/su": ["u:object_r:su_exec:s0", "u:object_r:magisk_file:s0", "u:object_r:system_file:s0"],
    })
    out,_,_ = run(["ls", "-Z", "/system/bin/sh", "/system/bin/netd", "/system/bin/su"])
    if out:
        if "unconfined" in out:
            alerts.append(pl('CAUTION', 4, "SELinux contexts are unconfined for critical binaries", out[:100]))
        mismatches = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ctx, fpath = parts[0], parts[-1]
            expected = expected_contexts.get(fpath)
            if expected and ctx not in expected and "unconfined" not in ctx:
                mismatches.append(f"{fpath}={ctx}")
        if mismatches:
            alerts.append(pl('CAUTION', 4, f"SELinux context mismatch vs expected policy ({len(mismatches)})", '; '.join(mismatches[:3])))
        elif not any('unconfined' in l for l in out.splitlines()):
            alerts.append(pl('OK', 0, "SELinux contexts match expected policy"))

    baseline_file = f"{OUTPUT_DIR}/baseline.json"
    if os.path.exists(baseline_file):
        try:
            with open(baseline_file) as f:
                baseline = json.load(f)
            for path in WL["system_binaries"]:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        actual = hashlib.sha256(f.read()).hexdigest()
                    expected = baseline.get(path)
                    if expected and actual != expected:
                        alerts.append(pl('CRITICAL', 8, f"Integrity mismatch for {path}", f"expected {expected[:8]}... got {actual[:8]}..."))
                    elif expected:
                        alerts.append(pl('OK', 0, f"{path} matches baseline"))
                else:
                    alerts.append(pl('CAUTION', 2, f"Binary {path} missing", "not found"))
        except Exception as e:
            alerts.append(pl('CAUTION', 2, f"Error reading baseline: {e}"))
    else:
        alerts.append(pl('CAUTION', 2, "No baseline file; run with --create-baseline", "Integrity checks skipped"))

    out,_,_ = run(["ls", "-l", "/system/bin/su", "/system/xbin/su", "/sbin/su"])
    ps_out,_,_ = run(["ps", "-A"])
    root_daemon = re.search(r'\b(magiskd|ksud|apd|apatch)\b', ps_out, re.I)
    have_confirmed_root = (MODE == 'root') or (MODE == 'rish' and RISH_IDENTITY and 'uid=0(' in RISH_IDENTITY)
    if out:
        alerts.append(pl('OK', 0, "SU binaries present"))
    elif root_daemon:
        alerts.append(pl('OK', 0, f"No su at legacy paths, but a root-manager daemon is running ({root_daemon.group(1)}) — normal for modern Magisk/KernelSU/APatch, which broker su via daemon rather than a persistent binary"))
    elif have_confirmed_root:
        alerts.append(pl('CAUTION', 2, "No su binaries at legacy paths and no known root-manager daemon found, despite this session confirmed running as root — worth understanding how root was granted here", out))
    else:
        alerts.append(pl('OK', 0, "No su binaries or root-manager daemon found — expected, since this session doesn't have confirmed root, so device root status can't be determined from here"))
    return alerts

def check_network():
    alerts = []
    ps("🌐 Network Interfaces & Routes")
    progress()
    out,_,rc = run(["ip", "link", "show"])
    if rc != 0:
        alerts.append(unavailable("Network interface listing ('ip link' failed/denied)", out))
    else:
        ifaces = re.findall(r': (tun|tap|ppp|wg|vpn|br)[0-9]+:', out, re.I)
        suspicious = [i for i in ifaces if i not in WL["vpn_interfaces"]]
        if suspicious:
            alerts.append(pl('CAUTION', 4, f"Non-standard interfaces: {', '.join(suspicious)}", out[:100]))
        else:
            alerts.append(pl('OK', 0, "No unexpected VPN interfaces"))

    out,_,rc = run(["ip", "route", "show", "default"])
    if rc != 0:
        alerts.append(unavailable("Default route check ('ip route' failed/denied)", out))
    elif any(x in out for x in WL["vpn_interfaces"]):
        alerts.append(pl('CAUTION', 3, f"Default route via VPN: {out}", out))
    else:
        alerts.append(pl('OK', 0, "Default route normal"))

    out,_,rc = run(["ip", "-6", "route", "show", "default"])
    if rc != 0:
        alerts.append(unavailable("IPv6 default route check ('ip -6 route' failed/denied)", out))
    elif out and "fe80" in out:
        alerts.append(pl('CAUTION', 3, "IPv6 default via link-local (possible ND spoofing)", out))
    elif out:
        alerts.append(pl('OK', 0, "IPv6 default route normal"))
    else:
        alerts.append(pl('OK', 0, "No IPv6 route"))
    return alerts

def check_hidden_network():
    """Deep checks for network-hiding tricks that a basic 'ip link' / 'iptables -t nat'
    pass can miss: interfaces present in sysfs but absent from netlink tools (or vice
    versa), policy routing rules that silently reroute traffic without a visible tunnel
    interface, network namespaces hiding an entire second network stack, mangle/raw
    table TPROXY/MARK/NOTRACK rules (transparent proxying doesn't require the nat
    table), sockets visible in /proc/net but not in ss/netstat output, DNS
    configuration mismatches between the resolver Android reports and what's actually
    in effect, and ARP table anomalies consistent with a MITM gateway."""
    alerts = []
    ps("🕳️  Deep Hidden Network Analysis")
    progress()

    # 1. sysfs vs netlink interface list – a rootkit that hooks the netlink
    # socket (what `ip`/`ifconfig` use) may still leave a real entry in sysfs,
    # or vice versa if it patches sysfs but not netlink.
    try:
        sysfs_ifaces = set(os.listdir('/sys/class/net'))
    except Exception:
        sysfs_ifaces = set()
    out,_,ip_rc = run(["ip", "-o", "link", "show"])
    if ip_rc != 0:
        alerts.append(unavailable("sysfs-vs-netlink interface comparison ('ip link' failed/denied)", out))
        netlink_ifaces = sysfs_ifaces  # nothing to compare against — treat as agreeing rather than flagging every sysfs interface as "hidden"
    else:
        netlink_ifaces = set(re.findall(r'^\d+:\s+([^:@]+)[:@]', out, re.M))
    only_sysfs = sysfs_ifaces - netlink_ifaces
    only_netlink = netlink_ifaces - sysfs_ifaces
    if only_sysfs:
        alerts.append(pl('CRITICAL', 8, f"Interfaces in /sys/class/net but hidden from 'ip link' (possible netlink hooking)", f"{', '.join(only_sysfs)}"))
    if only_netlink:
        alerts.append(pl('CAUTION', 4, f"Interfaces reported by 'ip link' but missing from sysfs", f"{', '.join(only_netlink)}"))
    if ip_rc == 0 and not only_sysfs and not only_netlink:
        alerts.append(pl('OK', 0, "sysfs and netlink interface lists agree"))

    # 2. Policy routing – traffic can be silently rerouted via `ip rule` without
    # ever creating an obvious tun/wg interface.
    out,_,ip_rule_rc = run(["ip", "rule", "show"])
    default_rules = {"0:\tfrom all lookup local", "32766:\tfrom all lookup main", "32767:\tfrom all lookup default"}
    # Android's netd manages a substantial set of its own standard policy
    # routing rules (per-UID app routing, legacy VPN compatibility tables,
    # explicit per-network socket binding, etc.) at several different
    # priority bands and table names — this is stock infrastructure on
    # every real device, not evidence of tampering. Only the 3 kernel-
    # default rules were previously recognized, so this fired on every
    # single scan; a second real-device scan then showed a valid pattern
    # (iif lo lookup <ifname>, Android's explicit-network-selection rule)
    # falling outside the priority range initially allowed for here.
    android_standard_rule = re.compile(
        r'lookup (legacy_system|legacy_network|local_network)\b|^1\d{4}:\s|from all unreachable\s*$'
    )
    # "iif lo lookup <ifname>" is recognized only when <ifname> is a real
    # interface actually present on the device (cross-checked against the
    # sysfs/netlink interface list from step 1) — keeps this from blindly
    # whitelisting a rule that points at something that doesn't exist.
    iif_lo_rule = re.compile(r'iif lo(?: fwmark \S+)? lookup (\S+)')
    known_ifaces = sysfs_ifaces | netlink_ifaces
    _table_cache = {}
    def numeric_table_is_real(n):
        if n not in _table_cache:
            t_out, _, _ = run(["ip", "route", "show", "table", n])
            _table_cache[n] = bool(t_out.strip())
        return _table_cache[n]
    numeric_lookup_rule = re.compile(r'lookup (\d+)\b')
    def is_standard_rule(line):
        if android_standard_rule.search(line):
            return True
        m = iif_lo_rule.search(line)
        if m and m.group(1) in known_ifaces:
            return True
        m = numeric_lookup_rule.search(line)
        return bool(m and numeric_table_is_real(m.group(1)))
    extra_rules = [l for l in out.splitlines()
                   if l.strip() and l.strip() not in default_rules
                   and not is_standard_rule(l)]
    if ip_rule_rc != 0:
        alerts.append(unavailable("Policy routing check ('ip rule show' failed/denied)", out))
    elif extra_rules:
        alerts.append(pl('CAUTION', 5, f"Non-default, non-standard policy routing rules present ({len(extra_rules)})", extra_rules[0][:100]))
    else:
        alerts.append(pl('OK', 0, "No unexpected policy routing rules"))

    # 3. Network namespaces – a full second network stack (own interfaces,
    # own routes) can be hidden entirely from the default namespace's `ip`/`ss` view.
    # Many Android kernels are built without CONFIG_NET_NS, so a failed/absent
    # `ip netns` doesn't mean "clean" — it means the check couldn't run.
    ns_out, ns_err, ns_rc = run(["ip", "netns", "list"])
    if ns_rc != 0:
        alerts.append(pl('CAUTION', 1, "Network namespace check unavailable (ip netns not supported on this kernel)", ns_err[:100]))
    elif ns_out:
        alerts.append(pl('CAUTION', 6, f"Non-default network namespaces exist ({len(ns_out.splitlines())})", ns_out[:100]))
    else:
        alerts.append(pl('OK', 0, "No extra network namespaces"))

    # 4. mangle/raw tables – TPROXY, packet MARKing for policy routing, and
    # NOTRACK (which hides traffic from conntrack-based monitoring) don't
    # require any nat-table rule at all, so the basic firewall check misses them.
    def strip_known_benign_chains(text):
        """Drop rule blocks belonging to known-benign stock Android/OEM
        chains before keyword matching. Confirmed on real devices: per-UID
        data-usage MARKing (bw_mangle_*, routectrl_mangle_*), tethering
        MSS clamp (tetherctrl_mangle_*), idle-timer notifications
        (idletimer_mangle_*), and empty OEM/vendor security-agent
        placeholder chains (oem_mangle_*, wakeupctrl_mangle_*, and
        OEM-branded chains like thinkshield_*) all legitimately use
        MARK/CONNMARK and are not transparent proxying.
        """
        benign_chain = re.compile(
            r'^Chain (bw_mangle_\w+|routectrl_mangle_\w+|tetherctrl_mangle_\w+|'
            r'idletimer_mangle_\w+|oem_mangle_\w+|wakeupctrl_mangle_\w+|\w*shield_\w+)\b',
            re.M
        )
        blocks = re.split(r'(?=^Chain )', text, flags=re.M)
        return '\n'.join(b for b in blocks if not benign_chain.match(b))

    out,_,rc = run(["iptables", "-t", "mangle", "-L", "-n", "-v"])
    if rc != 0:
        alerts.append(unavailable("mangle table listing (needs CAP_NET_ADMIN)", out))
    else:
        flagged_mangle = strip_known_benign_chains(out)
        if re.search(r'\b(TPROXY|MARK|CONNMARK)\b', flagged_mangle):
            alerts.append(pl('CAUTION', 5, "mangle table has TPROXY/MARK/CONNMARK rules outside known-good stock chains (possible transparent proxy)", flagged_mangle[:120]))
    out,_,rc = run(["iptables", "-t", "raw", "-L", "-n", "-v"])
    if rc != 0:
        alerts.append(unavailable("raw table listing (needs CAP_NET_ADMIN)", out))
    elif "NOTRACK" in out or re.search(r'\bCT\b', out):
        alerts.append(pl('CAUTION', 5, "raw table has NOTRACK/CT rules (traffic evading conntrack)", out[:120]))
    out6,_,rc6 = run(["ip6tables", "-t", "mangle", "-L", "-n", "-v"])
    if rc6 != 0:
        alerts.append(unavailable("IPv6 mangle table listing (needs CAP_NET_ADMIN)", out6))
    else:
        flagged_mangle6 = strip_known_benign_chains(out6)
        if re.search(r'\b(TPROXY|MARK|CONNMARK)\b', flagged_mangle6):
            alerts.append(pl('CAUTION', 5, "IPv6 mangle table has TPROXY/MARK/CONNMARK rules outside known-good stock chains", flagged_mangle6[:120]))
    # nftables can implement the exact same tricks (tproxy, mark, ct) without
    # any iptables ruleset existing at all on a modern nft-only kernel.
    nft_out,_,_ = run(["nft", "list", "ruleset"])
    if nft_out:
        if any(kw in nft_out.lower() for kw in ("tproxy", "meta mark", "ct mark")):
            alerts.append(pl('CAUTION', 5, "nftables ruleset has tproxy/mark/ct-mark rules (possible transparent proxy)", nft_out[:120]))
        if "notrack" in nft_out.lower():
            alerts.append(pl('CAUTION', 5, "nftables ruleset has notrack rules (traffic evading conntrack)", nft_out[:120]))

    # 5. Hidden sockets – compare raw /proc/net/tcp[6] entries against ss output.
    # A hooked ss/netstat binary (or LD_PRELOAD'd libc) can filter its own output
    # while the kernel's own tables still show the true socket.
    def parse_proc_net_tcp(path):
        ports = set()
        try:
            with open(path) as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) > 3 and parts[3] == '0A':  # LISTEN state
                        local = parts[1]
                        port = int(local.split(':')[-1], 16)
                        ports.add(port)
        except Exception:
            pass
        return ports
    kernel_ports = parse_proc_net_tcp('/proc/net/tcp') | parse_proc_net_tcp('/proc/net/tcp6')
    out,_,ss_rc = run(["ss", "-tlnH"])
    tool_used = "ss"
    if ss_rc != 0 or not out:
        # ss missing/unusable on some minimal Android builds — fall back to
        # netstat rather than treating every kernel port as "hidden".
        out,_,ns_rc2 = run(["netstat", "-tln"])
        tool_used = "netstat"
        if ns_rc2 != 0 or not out:
            alerts.append(pl('CAUTION', 2, "Could not verify listening sockets — both ss and netstat unavailable/failed", ""))
            tool_used = None
    listed_ports = set()
    if tool_used:
        for line in out.splitlines():
            m = re.search(r':(\d+)\s+\d', line)
            if m:
                listed_ports.add(int(m.group(1)))
        missing = kernel_ports - listed_ports
        if missing:
            alerts.append(pl('CRITICAL', 8, f"Listening ports visible in /proc/net/tcp but hidden from {tool_used} (possible tool hooking)", f"ports: {sorted(missing)[:10]}"))
        else:
            alerts.append(pl('OK', 0, f"No discrepancy between kernel socket table and {tool_used} output"))

    # 6. DNS config mismatch – Android's reported resolver (net.dns1/2 props)
    # vs what's actually configured in-effect for the shell environment.
    dns1,_,_ = run(["getprop", "net.dns1"])
    dns2,_,_ = run(["getprop", "net.dns2"])
    try:
        with open('/etc/resolv.conf') as f:
            resolv = f.read()
    except Exception:
        resolv = ""
    reported = {x for x in (dns1, dns2) if x}
    configured = set(re.findall(r'nameserver\s+([\d.:a-fA-F]+)', resolv))
    if reported and configured and not reported.intersection(configured) and configured - reported:
        alerts.append(pl('CAUTION', 5, "DNS resolver mismatch: system property vs resolv.conf disagree", f"props: {reported} vs resolv.conf: {configured}"))
    elif reported or configured:
        alerts.append(pl('OK', 0, "DNS configuration consistent"))

    # 7. ARP table – duplicate MACs for the default gateway IP, or multiple IPs
    # claiming the gateway's MAC, are classic signs of ARP-spoofing MITM.
    out,_,_ = run(["ip", "route", "show", "default"])
    gw_match = re.search(r'default via (\S+)', out)
    if gw_match:
        gw_ip = gw_match.group(1)
        arp_out,_,_ = run(["ip", "neigh", "show"])
        gw_macs = set(re.findall(rf'{re.escape(gw_ip)}\s+.*?lladdr\s+([0-9a-fA-F:]+)', arp_out))
        all_entries_for_mac = defaultdict(set)
        for ip, mac in re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+.*?lladdr\s+([0-9a-fA-F:]+)', arp_out):
            all_entries_for_mac[mac].add(ip)
        suspicious_macs = {mac: ips for mac, ips in all_entries_for_mac.items() if len(ips) > 3}
        if len(gw_macs) > 1:
            alerts.append(pl('CAUTION', 5, f"Gateway {gw_ip} has multiple MAC addresses in ARP table — possible ARP spoofing, but router failover/bonding can also cause this; verify manually before acting", f"MACs: {gw_macs}"))
        elif suspicious_macs:
            alerts.append(pl('CAUTION', 3, "Single MAC claims an unusually large number of IPs on the LAN — can indicate MITM, but is also normal behind a NAT/proxy device; verify manually", str(list(suspicious_macs.items())[:1])))
        else:
            alerts.append(pl('OK', 0, "ARP table looks normal"))

    return alerts

def check_firewall():
    alerts = []
    ps("🧱 Firewall (iptables + nftables)")
    progress()
    out,_,rc = run(["iptables", "-t", "nat", "-L", "-n", "-v"])
    if rc != 0:
        alerts.append(unavailable("NAT table listing (needs CAP_NET_ADMIN)", out))
    elif "REDIRECT" in out or "DNAT" in out or "TPROXY" in out:
        alerts.append(pl('CAUTION', 5, "NAT redirects found", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No iptables redirects"))
    out,_,_ = run(["nft", "list", "ruleset"])
    if "redirect" in out.lower() or "dnat" in out.lower() or "tproxy" in out.lower():
        alerts.append(pl('CAUTION', 5, "nftables redirects found", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No nftables redirects"))
    return alerts

def check_proxy_vpn():
    alerts = []
    ps("📡 Proxy & VPN Settings")
    progress()
    out,err,rc = run(["settings", "get", "global", "http_proxy"])
    # A failed Binder transaction (e.g. "cmd: Failure calling service
    # settings: Failed transaction (...)") still prints non-empty,
    # non-"null" text to stdout on some ROMs/execution contexts. That error
    # text was being treated as if it were the actual proxy value. Require
    # the command to have actually succeeded before trusting its output.
    looks_like_failure = out.lower().startswith(('cmd:', 'exception', 'error', 'failure'))
    if rc == 0 and out and out != "null" and not looks_like_failure:
        alerts.append(pl('CAUTION', 4, f"Global proxy: {out}", out))
    elif rc != 0 or looks_like_failure:
        alerts.append(pl('CAUTION', 1, "Could not query global proxy setting (command failed)", out or err))
    else:
        alerts.append(pl('OK', 0, "No global proxy"))

    out,_,dumpsys_rc = run(["dumpsys", "connectivity"])
    # "vpn" as a bare substring is present in dumpsys connectivity's
    # structural/header text (mVpns maps, legacy VPN state fields, etc.) on
    # most devices even with zero VPNs active — that made this fire a
    # near-universal false "Unknown VPN service" CAUTION. TRANSPORT_VPN is
    # the actual NetworkCapabilities marker Android sets only on a live,
    # connected VPN network.
    if dumpsys_rc != 0 or not out:
        alerts.append(unavailable("VPN status via dumpsys connectivity (needs the DUMP permission, generally shell/root-only)", out))
    elif "TRANSPORT_VPN" in out:
        if any(pkg in out for pkg in WL["vpn_apps"]):
            alerts.append(pl('OK', 0, "VPN service from known app"))
        else:
            alerts.append(pl('CAUTION', 3, f"Unknown VPN service", out[:80]))
    else:
        alerts.append(pl('OK', 0, "No active VPN"))
    return alerts

def check_hosts_dns():
    alerts = []
    ps("🌍 DNS & Hosts")
    progress()
    try:
        with open("/etc/hosts", "r") as f:
            out = f.read()
    except:
        out = ""
    suspicious = []
    for line in out.splitlines():
        if line and not line.startswith('#'):
            parts = line.split()
            if len(parts)>=2:
                ip = parts[0]
                try:
                    # ipaddress correctly covers the full 172.16.0.0/12 block
                    # (172.16.x through 172.31.x) plus loopback/link-local —
                    # the old string-prefix tuple only matched "172.16."
                    # literally, so e.g. 172.17.x.x (Docker's default bridge)
                    # or 172.31.x.x (common VPC/VPN range) were false-flagged.
                    addr = ipaddress.ip_address(ip)
                    is_local = addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
                except ValueError:
                    is_local = False  # not a valid IP at all — worth flagging
                if not is_local:
                    suspicious.append(line)
    if suspicious:
        alerts.append(pl('CAUTION', 3, f"Suspicious /etc/hosts entries: {len(suspicious)}", suspicious[0]))
    else:
        alerts.append(pl('OK', 0, "/etc/hosts clean"))
    return alerts

def check_processes():
    alerts = []
    ps("🔪 Processes & Listeners")
    progress()
    out,_,rc = run(["ss", "-tulpn"])
    success = (rc == 0)
    if not out and success:
        out2,_,rc2 = run(["netstat", "-tulpn"])
        if out2:
            out, success = out2, (rc2 == 0)
    if not success:
        alerts.append(unavailable("Listener check (ss/netstat both failed/denied)", out))
    else:
        suspicious = []
        for line in out.splitlines():
            if '127.0.0.1' in line or '::1' in line:
                continue
            if 'LISTEN' in line:
                if any(s in line for s in WL["safe_processes"]):
                    continue
                suspicious.append(line.strip())
        if suspicious:
            alerts.append(pl('CAUTION', 4, f"Non-local listeners: {len(suspicious)}", suspicious[0][:80]))
        else:
            alerts.append(pl('OK', 0, "No suspicious listeners"))

    # LD_PRELOAD – optimised: iterate /proc/*/environ in Python
    preload_found = []       # (pid, preload_value)
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            env_path = f'/proc/{pid}/environ'
            try:
                with open(env_path, 'rb') as f:
                    env_data = f.read()
                for entry in env_data.split(b'\x00'):
                    if entry.startswith(b'LD_PRELOAD='):
                        preload_found.append((pid, entry.split(b'=', 1)[1].decode('utf-8', 'replace')))
                        break
            except (IOError, PermissionError):
                continue
    except Exception:
        pass
    # Termux's own exec wrapper (libtermux-exec-ld-preload.so) works around
    # Android's W^X restrictions and is a well-known, benign, expected
    # LD_PRELOAD on any Termux install — not process hooking. Excluding it
    # avoids flagging the tool's own primary deployment environment as
    # CRITICAL on every single scan.
    known_good_preload = re.compile(r'libtermux-exec-ld-preload\.so')
    unexplained = [(pid, val) for pid, val in preload_found if not known_good_preload.search(val)]
    termux_only = [(pid, val) for pid, val in preload_found if known_good_preload.search(val)]
    if unexplained:
        zygote_detected = False
        for pid, _ in unexplained:
            try:
                with open(f'/proc/{pid}/cmdline', 'r') as f:
                    cmd = f.read()
                    if 'zygote' in cmd:
                        zygote_detected = True
                        break
            except:
                continue
        pids_str = ', '.join(f"{p}:{v}" for p, v in unexplained[:3])
        if zygote_detected:
            alerts.append(pl('CAUTION', 2, "LD_PRELOAD in zygote (likely Magisk)", pids_str))
        else:
            alerts.append(pl('CRITICAL', 7, "LD_PRELOAD detected (possible hooking)", pids_str))
    elif termux_only:
        alerts.append(pl('OK', 0, f"LD_PRELOAD present but matches known-good Termux exec shim ({len(termux_only)} process(es))"))
    else:
        alerts.append(pl('OK', 0, "No LD_PRELOAD"))

    # Hidden processes – compare /proc with ps. These two views are read at
    # slightly different instants, so a PID that simply exited in that race
    # window (extremely common on a busy Android kernel with constant
    # short-lived kworker/binder threads) will always show up as a
    # spurious "hidden" PID. Re-check each candidate against /proc right
    # now — if it's genuinely gone, it just exited normally, not hidden.
    try:
        proc_pids = set([d for d in os.listdir('/proc') if d.isdigit()])
    except:
        proc_pids = set()
    # "ps -A -o pid" (custom column format) was confirmed on a real device
    # to silently drop certain SELinux-restricted vendor/HAL daemon rows
    # (vndservicemanager, media.drm, gnss-service, fdrcontrol, etc.) that
    # the default "ps -A" listing format lists correctly — a toybox/ps
    # quirk with -o formatting, not anything actually hidden. Parse PIDs
    # from the default listing instead (PID is the 2nd whitespace-
    # separated column on this ps build, confirmed from real output).
    out,_,_ = run(["ps", "-A"])
    ps_pids = set()
    for line in out.splitlines()[1:]:  # skip header row
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            ps_pids.add(parts[1])
    candidates = proc_pids - ps_pids
    still_present = [pid for pid in candidates if os.path.exists(f'/proc/{pid}')]
    known_termux_pids = {pid for pid, _ in termux_only}
    still_present = [pid for pid in still_present if pid not in known_termux_pids]
    # Real-device testing showed this wasn't primarily a race condition —
    # the same small set of low-numbered PIDs recurred across separate
    # scans, meaning this ps build simply doesn't enumerate certain
    # kernel worker threads consistently, not that anything is hidden.
    # Kernel threads always have an empty /proc/<pid>/cmdline (no argv —
    # they're kernel-space, no executable is mapped); a hidden userspace
    # backdoor process, which is what this check actually cares about,
    # always has a non-empty one. Filter to that.
    hidden = []
    for pid in still_present:
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                if f.read().strip(b'\x00'):
                    hidden.append(pid)
        except (IOError, PermissionError):
            continue  # unreadable cmdline — can't confirm either way, skip rather than false-alarm
    if hidden:
        alerts.append(pl('CAUTION', 6, f"PIDs in /proc but not in ps output, with a non-empty cmdline (possible kernel hiding of a userspace process; verify manually)", f"PIDs: {', '.join(hidden[:5])}"))
    else:
        alerts.append(pl('OK', 0, "No hidden processes detected"))

    out,_,_ = run(["ps", "-A", "-o", "args"])
    if re.search(r'(nmap|netcat|socat|tcpdump|ettercap|arpspoof|mitmproxy)', out, re.I):
        alerts.append(pl('CAUTION', 4, f"Pentesting tools running (may be legitimate)", out[:100]))
    return alerts

def check_adb():
    alerts = []
    ps("📱 ADB over Network")
    progress()
    # Check properties
    for prop in ["service.adb.tcp.port", "persist.adb.tcp.port"]:
        out,_,_ = run(["getprop", prop])
        if out and out != "0" and out != "-1":
            alerts.append(pl('CRITICAL', 8, f"ADB over TCP enabled via {prop}: {out}", "Possible persistent backdoor"))
    # Check for adbd process
    out,_,_ = run(["ps", "-A"])
    adbd_lines = [l for l in out.splitlines() if re.search(r'adbd', l, re.I)]
    if adbd_lines:
        is_shell_rish = MODE == 'rish' and RISH_IDENTITY and 'uid=2000(shell)' in RISH_IDENTITY
        if is_shell_rish:
            alerts.append(pl('CAUTION', 2, "adbd process running — expected, since this scan itself is running via shell-level Shizuku (which requires ADB/wireless debugging to be active)", adbd_lines[0][:120]))
        else:
            alerts.append(pl('CRITICAL', 7, "adbd process running", adbd_lines[0][:120]))
    # Check listening ports for adb
    out,_,rc = run(["netstat", "-tulpn"])
    if rc != 0 or not out:
        alerts.append(unavailable("ADB network-listener check (netstat failed/denied)", out))
    else:
        for line in out.splitlines():
            if re.search(r'\badbd?\b', line) and "LISTEN" in line:
                alerts.append(pl('CRITICAL', 7, f"ADB listener: {line}", line))
                break
        else:
            alerts.append(pl('OK', 0, "ADB over network not active"))
    return alerts

def check_kernel():
    alerts = []
    ps("🐧 Kernel & eBPF")
    progress()
    out,_,rc = run(["lsmod"])
    if rc != 0:
        alerts.append(unavailable("Kernel module listing", out))
    else:
        mods = [line.split()[0] for line in out.splitlines() if line.split()]
        gki_vendor_hook = re.compile(r'_vendor_hooks$')
        suspicious = [m for m in mods if any(kw in m for kw in ['vpn','tunnel','proxy','hook']) and m not in WL["safe_kernel_modules"] and not gki_vendor_hook.search(m)]
        if suspicious:
            matched_lines = [l for l in out.splitlines() if l.split() and l.split()[0] in suspicious]
            alerts.append(pl('CAUTION', 4, f"Suspicious kernel modules: {', '.join(suspicious[:3])}", '\n'.join(matched_lines[:3])[:120]))
        else:
            alerts.append(pl('OK', 0, "No unusual modules"))

    # eBPF – flag genuine network-hook program types, but first strip out
    # Android's own stock per-UID traffic-accounting BPF programs (netd
    # creates these — e.g. "prog_netd_skfilter_egress_xtbpf" — on every
    # modern Android device). A bare substring match for "sk"/"tc" would
    # otherwise false-positive CRITICAL on that name alone (it contains
    # "sk" from "skfilter"), flagging every stock phone.
    known_good_bpf = re.compile(r'netd_skfilter|netd_shared|cgroup_bpf|xt_bpf|gpu_mem|gpu_work|mali|kgsl|thermal', re.I)
    out,_,_ = run(["bpftool", "prog", "show"])
    if out:
        flagged_lines = [l for l in out.splitlines() if not known_good_bpf.search(l)]
        flagged_text = '\n'.join(flagged_lines)
        if re.search(r'\b(xdp|sched_cls|sched_act|sk_skb|sk_msg|sk_reuseport|cgroup_skb)\b', flagged_text, re.I):
            alerts.append(pl('CRITICAL', 8, "eBPF programs with network hooks (excluding known-good netd traffic-stats programs)", flagged_text[:200]))
        elif flagged_lines:
            alerts.append(pl('OK', 0, "eBPF programs present but not network-specific"))
        else:
            alerts.append(pl('OK', 0, "Only known-good netd traffic-accounting BPF programs present"))
    else:
        out,_,_ = run(["ls", "/sys/fs/bpf/"])
        unexpected_bpf = [l for l in out.splitlines() if l.strip() and not known_good_bpf.search(l)]
        unexpected_text = '\n'.join(unexpected_bpf)
        if unexpected_bpf and re.search(r'\b(xdp|tproxy|hook)\b', unexpected_text, re.I):
            alerts.append(pl('CAUTION', 5, f"Unrecognised eBPF network programs in /sys/fs/bpf", unexpected_text[:100]))
        out,_,_ = run(["tc", "filter", "show"])
        if out:
            alerts.append(pl('CAUTION', 5, "TC filters present (possible eBPF)", out[:100]))
    return alerts

def check_frida():
    alerts = []
    ps("🔬 Frida & Debugger Detection")
    progress()
    out,_,rc = run(["ps", "-A"])
    if rc != 0 or not out:
        alerts.append(unavailable("Frida process search ('ps -A' failed/denied)", out))
    elif re.search(r'frida|frida-server|frida-helper', out, re.I):
        alerts.append(pl('CRITICAL', 8, "Frida server detected", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No Frida server found"))
    
    # TracerPid check – "/proc/*/status" is a shell glob, but run() execs
    # without a shell (by design, to avoid shell=True), so grep was being
    # handed a literal filename ("/proc/*/status") that never exists.
    # grep always failed silently and this check has been a permanent
    # no-op. Iterate /proc directly instead, same pattern already used by
    # the LD_PRELOAD and hidden-process checks.
    traced = []
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                with open(f'/proc/{pid}/status') as f:
                    for line in f:
                        if line.startswith('TracerPid:'):
                            tracer = line.split(':', 1)[1].strip()
                            if tracer not in ('0', ''):
                                traced.append(f"{pid}:{tracer}")
                            break
            except (IOError, PermissionError):
                continue
    except Exception:
        pass
    if traced:
        alerts.append(pl('CRITICAL', 7, "Processes with non-zero TracerPid (debugger/ptrace attached)", f"pid:tracer {traced[:5]}"))
    else:
        alerts.append(pl('OK', 0, "No debuggers attached"))
    return alerts

def check_threat_intel():
    alerts = []
    ps("🛡️ Threat Intelligence")
    progress()
    threat_file = f"{OUTPUT_DIR}/threats.txt"
    cache_file = f"{OUTPUT_DIR}/threats_resolved.json"
    if os.path.exists(threat_file):
        try:
            with open(threat_file) as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            # Cache domain->IP resolutions across runs so a large threats.txt
            # doesn't re-resolve every entry (and re-fail on dead domains)
            # on every single scan.
            cache = {}
            if os.path.exists(cache_file):
                try:
                    with open(cache_file) as f:
                        cache = json.load(f)
                except Exception:
                    cache = {}
            threat_ips = set()
            cache_dirty = False
            for entry in lines:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', entry):
                    threat_ips.add(entry)
                elif entry in cache:
                    threat_ips.update(cache[entry])
                else:
                    try:
                        resolved = list({info[4][0] for info in socket.getaddrinfo(entry, 443, socket.AF_INET)})
                        cache[entry] = resolved
                        cache_dirty = True
                        threat_ips.update(resolved)
                    except Exception:
                        cache[entry] = []
                        cache_dirty = True
                        if VERBOSE:
                            print(f"{C['yellow']}[WARN] Could not resolve threat: {entry}{C['reset']}")
            if cache_dirty:
                try:
                    with open(cache_file, "w") as f:
                        json.dump(cache, f, indent=2)
                except Exception:
                    pass
            if not threat_ips:
                alerts.append(pl('OK', 0, "Threat file contained no valid entries", "Add valid IPs or domain names"))
            else:
                out,_,rc = run(["netstat", "-tan"])
                if rc != 0 or not out:
                    alerts.append(unavailable(f"Active-connection matching against {len(threat_ips)} known threat IP(s)", "netstat unavailable or denied at this privilege level"))
                else:
                    for line in out.splitlines():
                        if "ESTABLISHED" not in line:
                            continue
                        parts = line.split()
                        if len(parts) < 5:
                            continue
                        foreign = parts[4]
                        # "if ip in line" was a raw substring match — threat IP
                        # "1.1.1.1" would false-match a line containing
                        # "31.1.1.1" or "1.1.1.10:443" anywhere on it. Parse the
                        # actual foreign-address field and compare the exact IP.
                        if foreign.startswith('['):
                            foreign_ip = foreign.split(']')[0].lstrip('[')
                        else:
                            foreign_ip = foreign.rsplit(':', 1)[0]
                        if foreign_ip in threat_ips:
                            alerts.append(pl('CRITICAL', 8, f"Active connection to known threat: {foreign_ip}", line))
                    if not alerts:
                        alerts.append(pl('OK', 0, "No connections to known threats"))
        except Exception as e:
            alerts.append(pl('CAUTION', 2, f"Error reading threat file: {e}"))
    else:
        sample = (
            "# Add IPs or domain names, one per line.\n"
            "# For a maintained starting list, pull a current feed yourself, e.g.\n"
            "# abuse.ch's feeds (https://abuse.ch) — do not hardcode indicators here\n"
            "# blindly, they go stale. Example format:\n"
            "# 192.168.1.100\n"
            "# malicious-domain.com\n"
        )
        try:
            with open(threat_file, "w") as f:
                f.write(sample)
            alerts.append(pl('OK', 0, "Threat intelligence file created (empty)", f"Add entries to {threat_file}"))
        except:
            alerts.append(pl('OK', 0, "Threat intelligence file not found (skipping)"))
    return alerts

def check_persistence():
    alerts = []
    ps("🕵️ Persistence Mechanisms")
    progress()

    baseline_file = f"{OUTPUT_DIR}/baseline.json"
    baseline = {}
    if os.path.exists(baseline_file):
        try:
            with open(baseline_file) as f:
                baseline = json.load(f)
        except Exception:
            baseline = {}
    have_baseline = "init_dir_listings" in baseline or "rc_files_with_service" in baseline

    baseline_listings = baseline.get("init_dir_listings", {})
    for location in ["/etc/init.d", "/system/etc/init", "/vendor/etc/init"]:
        out, _, _ = run(["ls", "-1", location])
        if not out:
            continue
        current = set(out.splitlines())
        if location in baseline_listings:
            new_files = current - set(baseline_listings[location])
            if new_files:
                alerts.append(pl('CAUTION', 4, f"New file(s) in {location} since baseline ({len(new_files)})", ', '.join(sorted(new_files)[:5])))
        elif not have_baseline:
            alerts.append(pl('CAUTION', 1, f"{location} has {len(current)} file(s) — expected on every Android device; run --create-baseline to detect future changes here instead of re-flagging this every scan", ""))

    out,_,_ = run(["find", "/system", "/vendor", "/data", "-xdev", "-name", "*.rc", "-type", "f",
                   "-exec", "grep", "-l", "service", "{}", "+"], timeout=30)
    if out:
        current_rc = set(out.splitlines())
        if "rc_files_with_service" in baseline:
            new_rc = current_rc - set(baseline["rc_files_with_service"])
            if new_rc:
                alerts.append(pl('CAUTION', 5, f"New .rc file(s) defining services since baseline ({len(new_rc)})", ', '.join(sorted(new_rc)[:5])))
        elif not have_baseline:
            alerts.append(pl('CAUTION', 1, f"{len(current_rc)} .rc file(s) define services — this matches virtually every stock init.rc on any Android device; run --create-baseline to detect future changes here instead of re-flagging this every scan", ""))
    return alerts

# ----------------------------------------------------------------------
#  DNS Cross-Check with TCP Fallback
# ----------------------------------------------------------------------
def dns_query_tcp(domain, server, qtype='A'):
    """Query over TCP for truncated responses."""
    rtype = 1 if qtype == 'A' else 28
    txid = random.randint(1, 65535)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    qname = b''
    for part in domain.encode('idna').split(b'.'):
        qname += bytes([len(part)]) + part
    qname += b'\x00'
    question = qname + struct.pack('!HH', rtype, 1)
    query = header + question
    # Prepend length for TCP
    tcp_query = struct.pack('!H', len(query)) + query
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, 53))
        sock.send(tcp_query)
        # Read the 2-byte length prefix first, then loop until the full
        # payload is received – a single recv() can return a short read
        # for large responses (many records / EDNS0).
        length_buf = b''
        while len(length_buf) < 2:
            chunk = sock.recv(2 - len(length_buf))
            if not chunk:
                sock.close()
                return None
            length_buf += chunk
        resp_len = struct.unpack('!H', length_buf)[0]
        payload = b''
        while len(payload) < resp_len:
            chunk = sock.recv(resp_len - len(payload))
            if not chunk:
                break
            payload += chunk
        sock.close()
        if len(payload) < resp_len:
            if VERBOSE:
                print(f"{C['red']}[DEBUG] TCP DNS: short read ({len(payload)}/{resp_len} bytes){C['reset']}")
            return None
        return parse_dns_response(payload, expected_txid=txid)
    except Exception as e:
        if VERBOSE:
            print(f"{C['red']}[DEBUG] TCP DNS failed: {e}{C['reset']}")
        return None

def parse_dns_response(data, expected_txid=None):
    """Parse DNS response with full compression pointer handling. If
    expected_txid is given, a mismatched transaction ID means this
    packet isn't a genuine reply to our query — could be a stale/
    unrelated response, or an injected/spoofed one — and gets rejected
    outright rather than parsed."""
    if len(data) < 12:
        return []
    if expected_txid is not None:
        resp_txid = struct.unpack('!H', data[0:2])[0]
        if resp_txid != expected_txid:
            return None
    qdcount = struct.unpack('!H', data[4:6])[0]
    ancount = struct.unpack('!H', data[6:8])[0]
    offset = 12
    # Skip question
    for _ in range(qdcount):
        while True:
            if data[offset] == 0:
                offset += 1
                break
            elif data[offset] & 0xC0:
                offset += 2
                break
            else:
                offset += data[offset] + 1
        offset += 4
    answers = []
    for _ in range(ancount):
        if data[offset] & 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
        offset += 10
        if rtype == 1:  # A
            ip = socket.inet_ntop(socket.AF_INET, data[offset:offset+rdlength])
            answers.append(ip)
        elif rtype == 28:  # AAAA
            ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+rdlength])
            answers.append(ip)
        offset += rdlength
    return answers

def dns_query(domain, server, qtype='A'):
    """Full DNS query with UDP, TCP fallback if truncated."""
    rtype = 1 if qtype == 'A' else 28
    txid = random.randint(1, 65535)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    qname = b''
    for part in domain.encode('idna').split(b'.'):
        qname += bytes([len(part)]) + part
    qname += b'\x00'
    question = qname + struct.pack('!HH', rtype, 1)
    query = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        # connect() restricts this socket to only accept datagrams from
        # (server, 53) — without it, recvfrom() would accept a UDP
        # packet from ANY source claiming to answer our query, which is
        # exactly the kind of injection this tool exists to catch.
        sock.connect((server, 53))
        sock.send(query)
        data = sock.recv(4096)
        # Check TC bit (truncation)
        if len(data) >= 2 and (data[2] & 0x02):
            # Retry over TCP
            sock.close()
            return dns_query_tcp(domain, server, qtype)
        return parse_dns_response(data, expected_txid=txid)
    except socket.timeout:
        return None
    except Exception as e:
        if VERBOSE:
            print(f"{C['red']}[DEBUG] UDP DNS failed: {e}{C['reset']}")
        return None
    finally:
        sock.close()

DNS_CROSS_IPS = {}  # populated by check_dns_cross(); domain -> set of all IPs seen

def _tls_handshake_valid(ip, domain, timeout=3):
    """True if a real TLS handshake to ip:443 with SNI=domain succeeds
    using the system's default trust store (full certificate chain +
    hostname validation, not our own trusted_ca_orgs list). A DNS
    hijacker would need a certificate that's both issued by a CA the
    device already trusts AND valid for this exact hostname — something
    they don't have — so success here is cryptographic proof this IP is
    a legitimate server for the domain, regardless of which IP range
    it's in."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False

def check_dns_cross():
    global DNS_CROSS_IPS
    alerts = []
    ps("🔐 DNS Cross‑Check")
    progress()
    
    resolvers = {
        'Google': '8.8.8.8',
        'Cloudflare': '1.1.1.1',
        'Quad9': '9.9.9.9',
        'OpenDNS': '208.67.222.222',
        'Yandex': '77.88.8.8',
        'Comodo': '8.26.56.26',
        'Verisign': '64.6.64.6',
        'CleanBrowsing': '185.228.168.9',
    }
    # Note: Freenom (80.80.80.80), FDN (80.67.169.40), JPRS (202.12.30.2),
    # and Telstra (203.0.178.191) were dropped after a real scan showed all
    # four failing on every single domain queried — a domain-independent
    # failure pattern means the resolvers themselves are unreachable/dead
    # rather than anything being hijacked, and it was contributing 15+
    # points of guaranteed "resolver failed" noise per scan. Re-review this
    # list periodically; public resolver uptime changes over time.
    
    domains = ['fbi.gov', 'google.com', 'microsoft.com', 'chase.com', 'github.com']
    
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {}
        for domain in domains:
            for name, dns in resolvers.items():
                futures[ex.submit(dns_query, domain, dns, 'A')] = (domain, name, 'A')
                futures[ex.submit(dns_query, domain, dns, 'AAAA')] = (domain, name, 'AAAA')
        
        results = defaultdict(lambda: defaultdict(dict))
        for future in as_completed(futures):
            domain, name, qtype = futures[future]
            ips = future.result()
            if ips is None:
                continue
            results[domain][name][qtype] = ips
    
    # Analyse — iterate over the full domain list, not just results.items().
    # A domain where every resolver timed out never gets a key written into
    # `results` (defaultdict only materializes on a successful reply), so
    # iterating results.items() silently dropped it and its "all resolvers
    # failed" signal entirely instead of reporting it.
    for domain in domains:
        resolver_results = results.get(domain, {})
        resolver_ips = {}
        for name, qtypes in resolver_results.items():
            ips = set()
            if 'A' in qtypes:
                ips.update(qtypes['A'])
            if 'AAAA' in qtypes:
                ips.update(qtypes['AAAA'])
            resolver_ips[name] = ips
        
        # Resolvers with an empty-but-present reply (e.g. NXDOMAIN) AND
        # resolvers that never made it into resolver_results at all (both
        # A and AAAA timed out) both count as "failed" for this domain.
        empty_replies = [name for name, ips in resolver_ips.items() if not ips]
        no_reply_at_all = [name for name in resolvers if name not in resolver_results]
        failed = empty_replies + no_reply_at_all
        if failed:
            alerts.append(pl('CAUTION', 3, f"Domain {domain}: {len(failed)}/{len(resolvers)} resolvers failed", ', '.join(failed)))
        
        DNS_CROSS_IPS[domain] = set().union(*resolver_ips.values()) if resolver_ips else set()

        if resolver_ips:
            first_name = list(resolver_ips.keys())[0]
            baseline = resolver_ips[first_name]
            for name, ips in resolver_ips.items():
                if ips != baseline:
                    all_ips = baseline.union(ips)
                    diff_ips = ips - baseline
                    v4_all = [ip for ip in all_ips if '.' in ip]
                    v6_all = [ip for ip in all_ips if ':' in ip]
                    # Fast path: cheap prefix check for the handful of
                    # ranges we do maintain, avoids extra handshakes for
                    # the common/fast case.
                    is_cdn_v4 = bool(v4_all) and all(any(ip.startswith(pre) for pre in WL["cdn_prefixes"]) for ip in v4_all)
                    v6_prefixes = {':'.join(ip.split(':')[:2]) for ip in v6_all}
                    is_cdn_v6 = bool(v6_all) and len(v6_prefixes) <= 3
                    is_cdn = (is_cdn_v4 or not v4_all) and (is_cdn_v6 or not v6_all) and (v4_all or v6_all)
                    if is_cdn:
                        continue
                    if v4_all and not v6_all:
                        prefixes = [ip.rsplit('.', 1)[0] for ip in v4_all]
                        if len(set(prefixes)) == 1:
                            continue
                    # Slow path: no static IP list can keep up with a
                    # hyperscale anycast provider's actual range diversity
                    # (this exact scan's differing Google IPs aren't in
                    # cdn_prefixes at all). Instead, cryptographically
                    # verify the differing IPs directly: a full-chain +
                    # hostname-validated TLS handshake succeeding proves
                    # the server holds a certificate the device's own
                    # trust store accepts for this exact domain — a DNS
                    # hijacker doesn't have that. Success here is strictly
                    # stronger evidence of legitimacy than any IP range
                    # check, and needs no maintained list at all.
                    sample = list(diff_ips)[:3] or list(ips)[:3]
                    if sample and all(_tls_handshake_valid(ip, domain) for ip in sample):
                        continue
                    alerts.append(pl('CAUTION', 5, f"DNS mismatch for {domain}: {name} differs", f"{name}: {ips} vs {baseline}"))
    
    return alerts

def _get_cert_full_info(ip, domain, timeout=3):
    """Connect to ip:443 with SNI=domain and pull full certificate
    identity: SHA256 + MD5 fingerprint of the raw DER bytes (the actual
    cryptographic identity of the cert — if two certs' SHA256 match,
    they are byte-for-byte identical, which necessarily means their
    serial number, signature, and every other field match too, since
    they're all just different views of the same bytes), serial number,
    issuer/subject, validity window, and — if the 'cryptography' package
    is installed — the actual signature algorithm and signature bytes.
    Returns a dict, or {'error': ...} on any failure (unreachable,
    handshake failure, cert/hostname invalid, etc.)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                parsed = ssock.getpeercert() or {}
                info = {
                    'sha256': hashlib.sha256(der).hexdigest(),
                    'md5': hashlib.md5(der).hexdigest(),
                    'serial': parsed.get('serialNumber', ''),
                    'issuer': dict(x[0] for x in parsed.get('issuer', ())),
                    'subject': dict(x[0] for x in parsed.get('subject', ())),
                    'not_before': parsed.get('notBefore', ''),
                    'not_after': parsed.get('notAfter', ''),
                    'signature_algorithm': None,
                    'signature_hex': None,
                }
                if HAVE_CRYPTOGRAPHY:
                    try:
                        cert_obj = _x509.load_der_x509_certificate(der)
                        info['signature_algorithm'] = getattr(cert_obj.signature_algorithm_oid, '_name', None) or cert_obj.signature_algorithm_oid.dotted_string
                        info['signature_hex'] = cert_obj.signature.hex()
                        info['serial'] = str(cert_obj.serial_number)
                    except Exception:
                        pass
                return info
    except OSError as e:
        # errno 97 (EAFNOSUPPORT) / 101 (ENETUNREACH) mean this network
        # simply has no route to that address family (e.g. no IPv6
        # connectivity) — environmental, not a cert/security signal.
        # Distinguish from a genuine handshake/cert failure.
        network_unavailable = getattr(e, 'errno', None) in (97, 101)
        return {'error': str(e), 'network_unavailable': network_unavailable}
    except Exception as e:
        return {'error': str(e), 'network_unavailable': False}

def check_certificates(resolver_ip_map=None):
    """Full cross-IP certificate fingerprint comparison. For each domain,
    pulls a certificate from every IP seen across all DNS resolvers (plus
    the system resolver, v4 and v6) and groups them by SHA256 fingerprint
    — the one comparison that's cryptographically absolute rather than
    heuristic. All IPs sharing one fingerprint are, by definition, being
    served the exact same certificate. If every IP for a domain lands in
    a single fingerprint group, that's the strongest possible "not
    currently MITM'd, from this vantage point" signal. If a minority of
    IPs present a DIFFERENT fingerprint AND that cert's issuer isn't
    trusted, that's flagged CRITICAL as a likely active interception —
    the specific pattern a MITM produces: most of the world sees the
    real cert, one vantage point (this one, or one poisoned resolver's
    IP) sees a substituted one."""
    alerts = []
    ps("🔐 Certificate Validation & Cross-IP Fingerprint Comparison")
    progress()
    if not HAVE_CRYPTOGRAPHY:
        alerts.append(pl('CAUTION', 1, "'cryptography' package not installed — signature/signature-algorithm fields unavailable (SHA256/MD5 fingerprint comparison still runs at full strength)", "pip install cryptography --break-system-packages"))
    domains = ['fbi.gov', 'google.com', 'microsoft.com', 'chase.com', 'github.com']
    for domain in domains:
        target_ips = set()
        if resolver_ip_map and domain in resolver_ip_map:
            target_ips.update(resolver_ip_map[domain])  # both v4 and v6 — DNS_CROSS_IPS already has both
        try:
            for info in socket.getaddrinfo(domain, 443, socket.AF_UNSPEC):
                target_ips.add(info[4][0])
        except Exception:
            pass
        if not target_ips:
            alerts.append(pl('CAUTION', 3, f"{domain}: could not resolve any IP to check", ""))
            continue

        # Raised well past the old cap of 5 — exhaustive cross-IP
        # comparison across every resolver's view is the entire point
        # here. Still bounded so one domain with an unusually large
        # anycast footprint can't blow up scan time.
        ips_to_check = list(target_ips)[:25]
        cert_results = {ip: _get_cert_full_info(ip, domain) for ip in ips_to_check}

        failed = {ip: info for ip, info in cert_results.items() if 'error' in info}
        network_unavailable_count = sum(1 for info in failed.values() if info.get('network_unavailable'))
        genuine_failures = {ip: info for ip, info in failed.items() if not info.get('network_unavailable')}
        for ip, info in genuine_failures.items():
            alerts.append(pl('CAUTION', 3, f"{domain} @ {ip}: cert check failed", info['error']))
        if network_unavailable_count:
            alerts.append(pl('OK', 0, f"{domain}: {network_unavailable_count} IP(s) skipped (no route from this network — likely no IPv6 connectivity here, not a security signal)", ""))

        groups = defaultdict(list)  # sha256 -> [ip, ...]
        for ip, info in cert_results.items():
            if 'error' not in info:
                groups[info['sha256']].append(ip)

        def issuer_trusted(info):
            issuer_text = ' '.join(str(v) for v in info['issuer'].values())
            return any(t in issuer_text for t in WL["trusted_ca_orgs"])

        trusted_groups = {fp: ips for fp, ips in groups.items() if issuer_trusted(cert_results[ips[0]])}
        untrusted_groups = {fp: ips for fp, ips in groups.items() if fp not in trusted_groups}

        if len(groups) == 1 and not untrusted_groups:
            fp, ips = next(iter(groups.items()))
            rep = cert_results[ips[0]]
            sig_note = f" sig_alg:{rep['signature_algorithm']}" if rep['signature_algorithm'] else ""
            alerts.append(pl('OK', 0,
                f"{domain}: IDENTICAL certificate confirmed across all {len(ips)} checked IP(s) — sha256:{fp[:24]}...",
                f"issuer={rep['issuer'].get('organizationName','?')} serial={rep['serial']}{sig_note} md5:{rep['md5'][:24]}..."))
        elif untrusted_groups and trusted_groups:
            # The MITM pattern: a verified-consistent majority, plus an
            # outlier presenting different, untrusted bytes.
            trusted_ip_count = sum(len(ips) for ips in trusted_groups.values())
            for fp, ips in untrusted_groups.items():
                rep = cert_results[ips[0]]
                alerts.append(pl('CRITICAL', 8,
                    f"{domain}: {len(ips)} IP(s) present a DIFFERENT, untrusted-issuer certificate than the {trusted_ip_count} verified IP(s) elsewhere — possible active MITM",
                    f"IPs: {ips}; sha256:{fp}; issuer={rep['issuer']}"))
            for fp, ips in trusted_groups.items():
                rep = cert_results[ips[0]]
                alerts.append(pl('OK', 0, f"{domain}: {len(ips)} IP(s) share a verified, trusted certificate", f"sha256:{fp[:24]}... issuer={rep['issuer'].get('organizationName','?')}"))
        else:
            # Multiple fingerprints but no trusted/untrusted split — either
            # a legitimate multi-cert CDN deployment (all trusted) or
            # every group is untrusted. Report each group plainly.
            for fp, ips in groups.items():
                rep = cert_results[ips[0]]
                trusted = fp in trusted_groups
                alerts.append(pl('OK' if trusted else 'CAUTION', 0 if trusted else 4,
                    f"{domain}: {len(ips)} IP(s) share certificate sha256:{fp[:24]}... issuer={rep['issuer'].get('organizationName','?')}" + ("" if trusted else " (untrusted issuer)"),
                    f"IPs: {ips[:8]}"))
    return alerts

# ----------------------------------------------------------------------
#  HTML report generator
# ----------------------------------------------------------------------
def generate_html(all_alerts, score, risk_level):
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Apocalypse Detector Report</title>
<style>
body {{ font-family: sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 20px; }}
h1 {{ color: #f5c2e7; }}
.summary {{ background: #313244; padding: 10px; border-radius: 8px; margin-bottom: 20px; }}
.alert {{ margin: 5px 0; padding: 8px; border-radius: 4px; }}
.OK {{ background: #2e5a3b; }}
.CAUTION {{ background: #5a4a2e; }}
.CRITICAL {{ background: #5a2e2e; }}
.SKIP {{ background: #3a3a3a; }}
.evidence {{ color: #a6adc8; font-size: 0.9em; margin-left: 20px; }}
</style></head><body>
<h1>🔥 Apocalypse Detector (Unified) v6.0 – Scan Report</h1>
<div class="summary">
<p><b>Timestamp:</b> {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
<p><b>Mode:</b> {MODE}</p>
<p><b>Risk Score:</b> {score} → <b>{risk_level}</b></p>
<p><b>Critical:</b> {len([a for a in all_alerts if a['level']=='CRITICAL'])} |
   <b>Caution:</b> {len([a for a in all_alerts if a['level']=='CAUTION'])} |
   <b>OK:</b> {len([a for a in all_alerts if a['level']=='OK'])} |
   <b>Unavailable:</b> {len([a for a in all_alerts if a['level']=='SKIP'])}</p>
</div>
<h2>Alerts</h2>
"""
    for alert in all_alerts:
        html += f'<div class="alert {alert["level"]}">'
        html += f'<b>[{alert["level"]}]</b> (w:{alert["weight"]}) {alert["message"]}'
        if alert.get("evidence"):
            html += f'<div class="evidence">→ {alert["evidence"]}</div>'
        html += '</div>'
    html += '</body></html>'
    with open(f"{OUTPUT_DIR}/report.html", "w") as f:
        f.write(html)
    print(f"{C['green']}[+] HTML report saved to {OUTPUT_DIR}/report.html{C['reset']}")

# ----------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------
def main():
    global VERBOSE
    if '--verbose' in sys.argv or '-v' in sys.argv:
        VERBOSE = True

    print("\n" + "="*70)
    print("🔥 APOCALYPSE DETECTOR (Unified) v6.0 – The Professional's Choice")
    print("="*70)
    bootstrap()  # detects MODE (root/rish/lite), resolves OUTPUT_DIR/WHITELIST_PATH/WL

    if '--create-baseline' in sys.argv:
        create_baseline()

    quick = '--quick' in sys.argv

    checks = [
        check_capabilities, check_root_presence,
        check_system, check_network, check_hidden_network, check_firewall, check_proxy_vpn,
        check_hosts_dns, check_processes, check_adb, check_kernel,
        check_frida, check_self_integrity, check_common_inspection_ports, check_threat_intel,
    ]
    if not quick:
        checks.append(check_persistence)
    checks.append(check_dns_cross)  # must run before check_certificates to populate DNS_CROSS_IPS
    set_total_checks(len(checks) + 1)  # +1 for check_certificates

    all_alerts = []
    for check_func in checks:
        all_alerts.extend(check_func())

    all_alerts.extend(check_certificates(DNS_CROSS_IPS))
    
    print("\n")  # Clear progress line
    
    score = sum(alert['weight'] for alert in all_alerts)
    low_threshold = WL.get("score_thresholds", {}).get("low", 30)
    medium_threshold = WL.get("score_thresholds", {}).get("medium", 60)
    if score > medium_threshold:
        risk_level = "HIGH"
    elif score > low_threshold:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    ps("📊 SUMMARY")
    print(f"  Mode:         {MODE}" + (f" ({RISH_IDENTITY})" if MODE == 'rish' and RISH_IDENTITY else ""))
    print(f"  Total alerts: {len(all_alerts)}")
    print(f"  Risk score:   {score} -> {risk_level}")
    print(f"  Critical:     {len([a for a in all_alerts if a['level'] == 'CRITICAL'])}")
    print(f"  Caution:      {len([a for a in all_alerts if a['level'] == 'CAUTION'])}")
    print(f"  OK:           {len([a for a in all_alerts if a['level'] == 'OK'])}")
    print(f"  Unavailable:  {len([a for a in all_alerts if a['level'] == 'SKIP'])}" + ("" if MODE == 'root' else " (needed more privilege than this session has)"))
    
    if risk_level != "LOW":
        print("\n⚠️  Review the alerts above. Many may be benign, but check critical ones first.")
    else:
        print("\n✅ System appears clean (low risk).")
    
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": MODE,
        "rish_identity": RISH_IDENTITY,
        "score": score,
        "risk_level": risk_level,
        "alerts": all_alerts
    }
    with open(f"{OUTPUT_DIR}/report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n📁 JSON report saved to {OUTPUT_DIR}/report.json")
    
    if '--html' in sys.argv:
        generate_html(all_alerts, score, risk_level)
    
    print("="*70)

if __name__ == "__main__":
    main()
