#!/data/data/com.termux/files/usr/bin/python3
"""
Apocalypse Detector v5.4 – The Professional's Choice
- Full DNS with TCP fallback (proper length-looped TCP read)
- Optimised /proc scanning
- Robust threat intel validation
- Enhanced ADB detection
- Granular SELinux context checks (vs known-good policy, not just "unconfined")
- Deep hidden-network analysis: sysfs-vs-netlink interface hiding, policy
  routing, hidden network namespaces, mangle/raw table TPROXY/MARK/NOTRACK,
  hidden listening sockets, DNS config mismatch, ARP spoofing
- Certificate validation across all DNS-cross-checked IPs, not just the first
- Scoped (not filesystem-wide) persistence scan
- --quick mode to skip expensive checks
- HTML report
- Verbose mode
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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ----------------------------------------------------------------------
# Colours & helpers
# ----------------------------------------------------------------------
C = {'red':'\033[91m','green':'\033[92m','yellow':'\033[93m','cyan':'\033[96m','magenta':'\033[95m','bold':'\033[1m','reset':'\033[0m','grey':'\033[90m'}
def p(t, c=''): print(f"{c}{t}{C['reset']}")
def ps(t): p(f"\n{C['cyan']}{C['bold']}{t}{C['reset']}")
def pl(l, w, msg, evidence=''): 
    icons = {'OK':'✓','CAUTION':'⚠','CRITICAL':'✗'}
    colours = {'OK':C['green'],'CAUTION':C['yellow'],'CRITICAL':C['red']}
    print(f"  {colours[l]}{icons[l]}{C['reset']} [{l}] (w:{w}) {msg}")
    if evidence: print(f"    {C['grey']}  → {evidence[:120]}{C['reset']}")
    return {'level': l, 'weight': w, 'message': msg, 'evidence': evidence}

VERBOSE = False
def run(cmd, timeout=12):
    """Run command with list arguments – no shell=True. If VERBOSE, print stderr."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if VERBOSE and r.stderr:
            print(f"{C['grey']}[DEBUG] stderr: {r.stderr[:200]}{C['reset']}")
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        if VERBOSE:
            print(f"{C['red']}[DEBUG] Exception: {e}{C['reset']}")
        return "", str(e), -1

# ----------------------------------------------------------------------
#  Config & whitelist
# ----------------------------------------------------------------------
WHITELIST_PATH = "/data/local/apocalypse/whitelist.json"
DEFAULT_WHITELIST = {
    "vpn_apps": ["com.android.vpndialogs", "org.openvpn", "com.wireguard"],
    "vpn_interfaces": ["tun0", "wg0", "ppp0"],
    "safe_kernel_modules": ["nf_nat", "nf_conntrack", "iptable_filter", "bridge", "ip_tunnel", "xfrm", "tun"],
    "safe_processes": ["netd", "dnsmasq", "sshd", "keystore", "servicemanager", "logd", "vold", "healthd", "adb"],
    "trusted_ca_orgs": ["DigiCert", "Let's Encrypt", "GlobalSign", "Amazon", "Cloudflare", "Google Trust Services"],
    "cdn_prefixes": ["104.16.", "172.64.", "162.159.", "151.101.", "142.250.", "172.217.", "142.251.", "34.120.", "35.186.", "34.64."],
    "system_binaries": ["/system/bin/sh", "/system/bin/netd", "/system/bin/su", "/system/bin/init", "/system/bin/app_process64"],
    "trusted_dns_resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9", "80.80.80.80", "77.88.8.8"],
    "risk_weights": {"default": 3, "critical": 8, "high": 5, "medium": 3, "low": 1},
    "score_thresholds": {"low": 30, "medium": 60}
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

WL = load_whitelist()

# ----------------------------------------------------------------------
#  Baseline creation
# ----------------------------------------------------------------------
def create_baseline():
    print(f"{C['yellow']}[*] Creating baseline...{C['reset']}")
    baseline = {}
    for path in WL["system_binaries"]:
        if os.path.exists(path):
            with open(path, 'rb') as f:
                baseline[path] = hashlib.sha256(f.read()).hexdigest()
            print(f"  {path} -> {baseline[path][:8]}...")
        else:
            baseline[path] = None
    os.makedirs("/data/local/apocalypse", exist_ok=True)
    with open("/data/local/apocalypse/baseline.json", "w") as f:
        json.dump(baseline, f, indent=2)
    os.chmod("/data/local/apocalypse", 0o750)
    print(f"{C['green']}[+] Baseline saved to /data/local/apocalypse/baseline.json{C['reset']}")
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

def check_system():
    alerts = []
    ps("🔍 System Integrity")
    progress()
    out,_,_ = run(["getenforce"])
    if out == "Enforcing":
        alerts.append(pl('OK', 0, f"SELinux: {out}"))
    elif out == "Permissive":
        alerts.append(pl('CAUTION', 3, f"SELinux permissive (common on custom ROMs)", out))
    else:
        alerts.append(pl('CAUTION', 2, "SELinux unknown", out))

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

    baseline_file = "/data/local/apocalypse/baseline.json"
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
    if out:
        alerts.append(pl('OK', 0, "SU binaries present"))
    else:
        alerts.append(pl('CAUTION', 2, "SU binaries missing (unusual)", out))
    return alerts

def check_network():
    alerts = []
    ps("🌐 Network Interfaces & Routes")
    progress()
    out,_,_ = run(["ip", "link", "show"])
    ifaces = re.findall(r': (tun|tap|ppp|wg|vpn|br)[0-9]+:', out, re.I)
    suspicious = [i for i in ifaces if i not in WL["vpn_interfaces"]]
    if suspicious:
        alerts.append(pl('CAUTION', 4, f"Non-standard interfaces: {', '.join(suspicious)}", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No unexpected VPN interfaces"))

    out,_,_ = run(["ip", "route", "show", "default"])
    if any(x in out for x in WL["vpn_interfaces"]):
        alerts.append(pl('CAUTION', 3, f"Default route via VPN: {out}", out))
    else:
        alerts.append(pl('OK', 0, "Default route normal"))

    out,_,_ = run(["ip", "-6", "route", "show", "default"])
    if out and "fe80" in out:
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
    out,_,_ = run(["ip", "-o", "link", "show"])
    netlink_ifaces = set(re.findall(r'^\d+:\s+([^:@]+)[:@]', out, re.M))
    only_sysfs = sysfs_ifaces - netlink_ifaces
    only_netlink = netlink_ifaces - sysfs_ifaces
    if only_sysfs:
        alerts.append(pl('CRITICAL', 8, f"Interfaces in /sys/class/net but hidden from 'ip link' (possible netlink hooking)", f"{', '.join(only_sysfs)}"))
    if only_netlink:
        alerts.append(pl('CAUTION', 4, f"Interfaces reported by 'ip link' but missing from sysfs", f"{', '.join(only_netlink)}"))
    if not only_sysfs and not only_netlink:
        alerts.append(pl('OK', 0, "sysfs and netlink interface lists agree"))

    # 2. Policy routing – traffic can be silently rerouted via `ip rule` without
    # ever creating an obvious tun/wg interface.
    out,_,_ = run(["ip", "rule", "show"])
    default_rules = {"0:\tfrom all lookup local", "32766:\tfrom all lookup main", "32767:\tfrom all lookup default"}
    extra_rules = [l for l in out.splitlines() if l.strip() and l.strip() not in default_rules]
    if extra_rules:
        alerts.append(pl('CAUTION', 5, f"Non-default policy routing rules present ({len(extra_rules)})", extra_rules[0][:100]))
    else:
        alerts.append(pl('OK', 0, "No unexpected policy routing rules"))

    # 3. Network namespaces – a full second network stack (own interfaces,
    # own routes) can be hidden entirely from the default namespace's `ip`/`ss` view.
    out,_,_ = run(["ip", "netns", "list"])
    if out:
        alerts.append(pl('CAUTION', 6, f"Non-default network namespaces exist ({len(out.splitlines())})", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No extra network namespaces"))

    # 4. mangle/raw tables – TPROXY, packet MARKing for policy routing, and
    # NOTRACK (which hides traffic from conntrack-based monitoring) don't
    # require any nat-table rule at all, so the basic firewall check misses them.
    out,_,_ = run(["iptables", "-t", "mangle", "-L", "-n", "-v"])
    if re.search(r'\b(TPROXY|MARK|CONNMARK)\b', out):
        alerts.append(pl('CAUTION', 5, "mangle table has TPROXY/MARK/CONNMARK rules (possible transparent proxy)", out[:120]))
    out,_,_ = run(["iptables", "-t", "raw", "-L", "-n", "-v"])
    if "NOTRACK" in out or "CT" in out:
        alerts.append(pl('CAUTION', 5, "raw table has NOTRACK/CT rules (traffic evading conntrack)", out[:120]))
    out6,_,_ = run(["ip6tables", "-t", "mangle", "-L", "-n", "-v"])
    if re.search(r'\b(TPROXY|MARK|CONNMARK)\b', out6):
        alerts.append(pl('CAUTION', 5, "IPv6 mangle table has TPROXY/MARK/CONNMARK rules", out6[:120]))

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
    out,_,_ = run(["ss", "-tlnH"])
    ss_ports = set()
    for line in out.splitlines():
        m = re.search(r':(\d+)\s+\d', line)
        if m:
            ss_ports.add(int(m.group(1)))
    missing_from_ss = kernel_ports - ss_ports
    if missing_from_ss:
        alerts.append(pl('CRITICAL', 8, f"Listening ports visible in /proc/net/tcp but hidden from ss (possible tool hooking)", f"ports: {sorted(missing_from_ss)[:10]}"))
    else:
        alerts.append(pl('OK', 0, "No discrepancy between kernel socket table and ss output"))

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
            alerts.append(pl('CRITICAL', 7, f"Gateway {gw_ip} has multiple MAC addresses in ARP table (possible ARP spoofing)", f"MACs: {gw_macs}"))
        elif suspicious_macs:
            alerts.append(pl('CAUTION', 4, "Single MAC claims an unusually large number of IPs on the LAN", str(list(suspicious_macs.items())[:1])))
        else:
            alerts.append(pl('OK', 0, "ARP table looks normal"))

    return alerts

def check_firewall():
    alerts = []
    ps("🧱 Firewall (iptables + nftables)")
    progress()
    out,_,_ = run(["iptables", "-t", "nat", "-L", "-n", "-v"])
    if "REDIRECT" in out or "DNAT" in out or "TPROXY" in out:
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
    out,_,_ = run(["settings", "get", "global", "http_proxy"])
    if out and out != "null":
        alerts.append(pl('CAUTION', 4, f"Global proxy: {out}", out))
    else:
        alerts.append(pl('OK', 0, "No global proxy"))

    out,_,_ = run(["dumpsys", "connectivity"])
    if "vpn" in out.lower():
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
                if not ip.startswith(('127.','::1','192.168.','10.','172.16.','0.0.0.0')):
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
    out,_,_ = run(["ss", "-tulpn"])
    if not out:
        out,_,_ = run(["netstat", "-tulpn"])
    suspicious = []
    for line in out.splitlines():
        if '127.0.0.1' in line:
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
    preload_found = []
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            env_path = f'/proc/{pid}/environ'
            try:
                with open(env_path, 'rb') as f:
                    env_data = f.read()
                    if b'LD_PRELOAD' in env_data:
                        preload_found.append(pid)
            except (IOError, PermissionError):
                continue
    except Exception:
        pass
    if preload_found:
        zygote_detected = False
        for pid in preload_found:
            try:
                with open(f'/proc/{pid}/cmdline', 'r') as f:
                    cmd = f.read()
                    if 'zygote' in cmd:
                        zygote_detected = True
                        break
            except:
                continue
        if zygote_detected:
            alerts.append(pl('CAUTION', 2, "LD_PRELOAD in zygote (likely Magisk)", f"PIDs: {', '.join(preload_found[:3])}"))
        else:
            alerts.append(pl('CRITICAL', 7, "LD_PRELOAD detected (possible hooking)", f"PIDs: {', '.join(preload_found[:3])}"))
    else:
        alerts.append(pl('OK', 0, "No LD_PRELOAD"))

    # Hidden processes – compare /proc with ps
    try:
        proc_pids = set([d for d in os.listdir('/proc') if d.isdigit()])
    except:
        proc_pids = set()
    out,_,_ = run(["ps", "-A", "-o", "pid"])
    ps_pids = set(out.splitlines())
    hidden = proc_pids - ps_pids
    if hidden:
        alerts.append(pl('CAUTION', 6, f"PIDs in /proc but not in ps output (possible kernel hiding — can also be kernel threads or processes that exited mid-scan; verify manually)", f"PIDs: {', '.join(list(hidden)[:5])}"))
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
    if re.search(r'adbd', out, re.I):
        alerts.append(pl('CRITICAL', 7, "adbd process running", out[:100]))
    # Check listening ports for adb
    out,_,_ = run(["netstat", "-tulpn"])
    for line in out.splitlines():
        if "adb" in line and "LISTEN" in line:
            alerts.append(pl('CRITICAL', 7, f"ADB listener: {line}", line))
            break
    else:
        alerts.append(pl('OK', 0, "ADB over network not active"))
    return alerts

def check_kernel():
    alerts = []
    ps("🐧 Kernel & eBPF")
    progress()
    out,_,_ = run(["lsmod"])
    mods = [line.split()[0] for line in out.splitlines()]
    suspicious = [m for m in mods if any(kw in m for kw in ['vpn','tunnel','proxy','hook']) and m not in WL["safe_kernel_modules"]]
    if suspicious:
        alerts.append(pl('CAUTION', 4, f"Suspicious kernel modules: {', '.join(suspicious[:3])}", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No unusual modules"))

    out,_,_ = run(["bpftool", "prog", "show"])
    if out:
        if 'xdp' in out.lower() or 'tc' in out.lower() or 'sk' in out.lower():
            alerts.append(pl('CRITICAL', 8, "eBPF programs with network hooks", out[:200]))
        else:
            alerts.append(pl('OK', 0, "eBPF programs present but not network-specific"))
    else:
        out,_,_ = run(["ls", "/sys/fs/bpf/"])
        if re.search(r'(xdp|tc|sk|hook)', out, re.I):
            alerts.append(pl('CAUTION', 5, f"eBPF network programs in /sys/fs/bpf", out[:100]))
        out,_,_ = run(["tc", "filter", "show"])
        if out:
            alerts.append(pl('CAUTION', 5, "TC filters present (possible eBPF)", out[:100]))
    return alerts

def check_frida():
    alerts = []
    ps("🔬 Frida & Debugger Detection")
    progress()
    out,_,_ = run(["ps", "-A"])
    if re.search(r'frida|frida-server|frida-helper', out, re.I):
        alerts.append(pl('CRITICAL', 8, "Frida server detected", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No Frida server found"))
    
    out,_,_ = run(["grep", "-r", "TracerPid:", "/proc/*/status"])
    if out and "TracerPid:\t0" not in out:
        alerts.append(pl('CRITICAL', 7, "Processes with non-zero TracerPid (debugger attached)", out[:100]))
    else:
        alerts.append(pl('OK', 0, "No debuggers attached"))
    return alerts

def check_threat_intel():
    alerts = []
    ps("🛡️ Threat Intelligence")
    progress()
    threat_file = "/data/local/apocalypse/threats.txt"
    if os.path.exists(threat_file):
        try:
            with open(threat_file) as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            threat_ips = set()
            for entry in lines:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', entry):
                    threat_ips.add(entry)
                else:
                    try:
                        for info in socket.getaddrinfo(entry, 443, socket.AF_INET):
                            ip = info[4][0]
                            threat_ips.add(ip)
                    except:
                        if VERBOSE:
                            print(f"{C['yellow']}[WARN] Could not resolve threat: {entry}{C['reset']}")
            if not threat_ips:
                alerts.append(pl('OK', 0, "Threat file contained no valid entries", "Add valid IPs or domain names"))
            else:
                out,_,_ = run(["netstat", "-tan"])
                for line in out.splitlines():
                    if "ESTABLISHED" in line:
                        for ip in threat_ips:
                            if ip in line:
                                alerts.append(pl('CRITICAL', 8, f"Active connection to known threat: {ip}", line))
                                break
                if not alerts:
                    alerts.append(pl('OK', 0, "No connections to known threats"))
        except Exception as e:
            alerts.append(pl('CAUTION', 2, f"Error reading threat file: {e}"))
    else:
        sample = "# Add IPs or domain names, one per line\n# 192.168.1.100\n# malicious-domain.com\n"
        try:
            with open(threat_file, "w") as f:
                f.write(sample)
            alerts.append(pl('OK', 0, "Threat intelligence file created (empty)", "Add entries to /data/local/apocalypse/threats.txt"))
        except:
            alerts.append(pl('OK', 0, "Threat intelligence file not found (skipping)"))
    return alerts

def check_persistence():
    alerts = []
    ps("🕵️ Persistence Mechanisms")
    progress()
    for location in ["/etc/init.d", "/system/etc/init", "/vendor/etc/init"]:
        out,_,_ = run(["ls", "-l", location])
        if out and 'No such file' not in out:
            alerts.append(pl('CAUTION', 3, f"Scripts in {location}", out[:100]))
    # Scoped to /system /vendor /data — scanning "/" also walks /proc, /sys,
    # /dev unnecessarily, costing minutes of CPU/battery for no extra signal.
    out,_,_ = run(["find", "/system", "/vendor", "/data", "-xdev", "-name", "*.rc", "-type", "f",
                   "-exec", "grep", "-l", "service", "{}", ";"], timeout=30)
    if out:
        alerts.append(pl('CAUTION', 3, "init.rc files with service definitions", out[:100]))
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
        return parse_dns_response(payload)
    except Exception as e:
        if VERBOSE:
            print(f"{C['red']}[DEBUG] TCP DNS failed: {e}{C['reset']}")
        return None

def parse_dns_response(data):
    """Parse DNS response with full compression pointer handling."""
    if len(data) < 12:
        return []
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
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(4096)
        # Check TC bit (truncation)
        if len(data) >= 2 and (data[2] & 0x02):
            # Retry over TCP
            sock.close()
            return dns_query_tcp(domain, server, qtype)
        return parse_dns_response(data)
    except socket.timeout:
        return None
    except Exception as e:
        if VERBOSE:
            print(f"{C['red']}[DEBUG] UDP DNS failed: {e}{C['reset']}")
        return None
    finally:
        sock.close()

DNS_CROSS_IPS = {}  # populated by check_dns_cross(); domain -> set of all IPs seen

def check_dns_cross():
    global DNS_CROSS_IPS
    alerts = []
    ps("🔐 DNS Cross‑Check")
    progress()
    
    resolvers = {
        'Google': '8.8.8.8',
        'Cloudflare': '1.1.1.1',
        'Quad9': '9.9.9.9',
        'Freenom': '80.80.80.80',
        'Yandex': '77.88.8.8',
        'FDN (FR)': '80.67.169.40',
        'JPRS (JP)': '202.12.30.2',
        'Telstra (AU)': '203.0.178.191',
    }
    
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
    
    # Analyse
    for domain, resolver_results in results.items():
        resolver_ips = {}
        for name, qtypes in resolver_results.items():
            ips = set()
            if 'A' in qtypes:
                ips.update(qtypes['A'])
            if 'AAAA' in qtypes:
                ips.update(qtypes['AAAA'])
            resolver_ips[name] = ips
        
        empties = [name for name, ips in resolver_ips.items() if not ips]
        if empties:
            alerts.append(pl('CAUTION', 3, f"Domain {domain}: {len(empties)} resolvers failed", ', '.join(empties)))
        
        DNS_CROSS_IPS[domain] = set().union(*resolver_ips.values()) if resolver_ips else set()

        if resolver_ips:
            first_name = list(resolver_ips.keys())[0]
            baseline = resolver_ips[first_name]
            for name, ips in resolver_ips.items():
                if ips != baseline:
                    all_ips = baseline.union(ips)
                    is_cdn = all(any(ip.startswith(pre) for pre in WL["cdn_prefixes"]) for ip in all_ips)
                    if not is_cdn:
                        v4_ips = [ip for ip in all_ips if '.' in ip]
                        if v4_ips and len(v4_ips) == len(all_ips):
                            prefixes = [ip.rsplit('.', 1)[0] for ip in v4_ips]
                            if len(set(prefixes)) == 1:
                                continue
                        alerts.append(pl('CAUTION', 5, f"DNS mismatch for {domain}: {name} differs", f"{name}: {ips} vs {baseline}"))
    
    return alerts

def check_certificates(resolver_ip_map=None):
    """Validate certs. If resolver_ip_map is supplied (domain -> set of IPs
    seen across multiple DNS resolvers, from check_dns_cross), each of those
    IPs is checked individually so a cert served only from one hijacked
    resolver's IP doesn't hide behind a clean system-resolver result."""
    alerts = []
    ps("🔐 Certificate Validation")
    progress()
    domains = ['fbi.gov', 'google.com', 'microsoft.com', 'chase.com', 'github.com']
    for domain in domains:
        target_ips = set()
        if resolver_ip_map and domain in resolver_ip_map:
            target_ips.update(ip for ip in resolver_ip_map[domain] if '.' in ip)  # IPv4 only for now
        try:
            for info in socket.getaddrinfo(domain, 443, socket.AF_INET):
                target_ips.add(info[4][0])
        except Exception:
            pass
        if not target_ips:
            alerts.append(pl('CAUTION', 3, f"{domain}: could not resolve any IP to check", ""))
            continue
        seen_issuers = {}
        for ip in list(target_ips)[:5]:  # cap to avoid excessive handshakes
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((ip, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        issuer = dict(x[0] for x in cert['issuer'])
                        seen_issuers[ip] = issuer
            except Exception as e:
                alerts.append(pl('CAUTION', 3, f"{domain} @ {ip}: cert check failed", str(e)))
        for ip, issuer in seen_issuers.items():
            if any(t in issuer for t in WL["trusted_ca_orgs"]):
                alerts.append(pl('OK', 0, f"{domain} @ {ip}: trusted issuer {issuer}"))
            else:
                alerts.append(pl('CAUTION', 4, f"{domain} @ {ip}: untrusted issuer {issuer}", str(issuer)))
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
.evidence {{ color: #a6adc8; font-size: 0.9em; margin-left: 20px; }}
</style></head><body>
<h1>🔥 Apocalypse Detector v5.4 – Scan Report</h1>
<div class="summary">
<p><b>Timestamp:</b> {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
<p><b>Risk Score:</b> {score} → <b>{risk_level}</b></p>
<p><b>Critical:</b> {len([a for a in all_alerts if a['level']=='CRITICAL'])} |
   <b>Caution:</b> {len([a for a in all_alerts if a['level']=='CAUTION'])} |
   <b>OK:</b> {len([a for a in all_alerts if a['level']=='OK'])}</p>
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
    with open("/data/local/apocalypse/report.html", "w") as f:
        f.write(html)
    print(f"{C['green']}[+] HTML report saved to /data/local/apocalypse/report.html{C['reset']}")

# ----------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------
def main():
    global VERBOSE
    if '--create-baseline' in sys.argv:
        create_baseline()
    if '--verbose' in sys.argv or '-v' in sys.argv:
        VERBOSE = True
    
    if os.geteuid() != 0:
        print(f"{C['red']}[!] Run as root")
        sys.exit(1)
    
    os.makedirs("/data/local/apocalypse", exist_ok=True)
    os.chmod("/data/local/apocalypse", 0o750)
    
    print("\n" + "="*70)
    print("🔥 APOCALYPSE DETECTOR v5.4 – The Professional's Choice")
    print("="*70)
    print(f"{C['grey']}Running with root privileges...{C['reset']}\n")
    
    quick = '--quick' in sys.argv

    checks = [
        check_system, check_network, check_hidden_network, check_firewall, check_proxy_vpn,
        check_hosts_dns, check_processes, check_adb, check_kernel,
        check_frida, check_threat_intel,
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
    print(f"  Total alerts: {len(all_alerts)}")
    print(f"  Risk score:   {score} -> {risk_level}")
    print(f"  Critical:     {len([a for a in all_alerts if a['level'] == 'CRITICAL'])}")
    print(f"  Caution:      {len([a for a in all_alerts if a['level'] == 'CAUTION'])}")
    print(f"  OK:           {len([a for a in all_alerts if a['level'] == 'OK'])}")
    
    if risk_level != "LOW":
        print("\n⚠️  Review the alerts above. Many may be benign, but check critical ones first.")
    else:
        print("\n✅ System appears clean (low risk).")
    
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "score": score,
        "risk_level": risk_level,
        "alerts": all_alerts
    }
    with open("/data/local/apocalypse/report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\n📁 JSON report saved to /data/local/apocalypse/report.json")
    
    if '--html' in sys.argv:
        generate_html(all_alerts, score, risk_level)
    
    print("="*70)

if __name__ == "__main__":
    main()
