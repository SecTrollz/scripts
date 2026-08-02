#!/usr/bin/env python3
"""
SIGINT v3 — Local Network & RF Asset Locator
Single file. Works in Termux (full) and Pydroid3 (LAN only). No root.

Capabilities are probed functionally, not assumed. If a termux-* command
hangs or returns API_ERROR, the UI tells you exactly what to fix.

WHAT IT DOES:
  • LAN inventory via ICMP+TCP liveness, ARP (MAC harvest), and deep TCP
    fingerprinting, fused with SSDP M-SEARCH and full mDNS (including TXT).
    Chromecast, Apple TV, Roku, Sonos, printers – exact model strings.
  • WiFi RSSI survey (if Termux:API is functional) – proximity buckets and
    warmer/colder trend for access points.
  • Bluetooth scan (unofficial fork only – probed, not assumed).
  • Map with your GPS location and proximity rings (no fake device pins).

WHAT IT DOES NOT DO:
  • Count phones (MAC randomisation kills that).
  • Give a precise indoor position (RSSI error is house-sized).
  • Guess MACs for Bluetooth (not available in official API).

SETUP (Termux):
  pkg install python termux-api iproute2 inetutils
  pip install flask
  Install "Termux:API" app from F-Droid.
  Android Settings → Apps → Termux → Permissions → Location → Allow.
  python sigint.py
  termux-open http://localhost:8747
"""

import argparse
import atexit
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing, contextmanager

from flask import Flask, jsonify, render_template_string, request

# ----- configuration --------------------------------------------------
PORT = 8747
DB_PATH = os.path.join(os.path.expanduser("~"), "sigint.db")
SCHEMA_VERSION = 3
SIGHTINGS_PER_ASSET = 120
BIND_HOST = "127.0.0.1"          # change to "0.0.0.0" only on trusted networks

# ----- preflight and capability tracking -------------------------------
CAPS = {}
PREFLIGHT = {}

def _run(cmd, timeout=12):
    """Run a command. Returns (rc, stdout, stderr, timed_out)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip(), False
    except FileNotFoundError:
        return -1, "", "not found", False
    except subprocess.TimeoutExpired:
        return -1, "", "timeout", True
    except Exception as e:
        return -1, "", str(e), False

def classify_termux_result(name, rc, out, err, timed_out):
    if err == "not found":
        return {"status": "no_binary",
                "detail": f"{name} not installed",
                "remedy": "pkg install termux-api   (and Termux:API app from F-Droid)"}
    if timed_out:
        return {"status": "no_apk",
                "detail": f"{name} timed out",
                "remedy": "Install Termux:API app from F-Droid and open it once."}
    if not out:
        return {"status": "no_apk",
                "detail": f"{name} returned nothing",
                "remedy": "Install Termux:API app, then grant location permission."}
    low = out.lower()
    if "api_error" in low or "permission" in low or "denied" in low:
        if "location" in low:
            return {"status": "location_off",
                    "detail": out[:150],
                    "remedy": "Enable Settings → Location, then grant Termux location."}
        return {"status": "no_permission",
                "detail": out[:150],
                "remedy": "Android Settings → Apps → Termux → Permissions → Location → Allow."}
    return {"status": "ok", "detail": "responded with data", "remedy": ""}

def preflight(deep=True):
    """Probe all capabilities, using live invocations when deep=True."""
    checks = {}
    # LAN is pure sockets
    checks["lan"] = {"status": "ok", "detail": "pure sockets", "remedy": ""}
    # helper binaries
    for binname, label in (("ping", "icmp"), ("ip", "arp")):
        checks[label] = ({"status": "ok", "detail": binname+" present", "remedy": ""}
                         if shutil.which(binname)
                         else {"status": "no_binary",
                               "detail": binname+" missing",
                               "remedy": f"pkg install {'inetutils' if binname=='ping' else 'iproute2'} (optional)"})
    # termux bridge
    for key, cmd, tmo in (("wifi_scan", "termux-wifi-scaninfo", 22),
                          ("wifi_conn", "termux-wifi-connectioninfo", 12),
                          ("gps", "termux-location", 4),
                          ("bluetooth", "termux-bluetooth-scaninfo", 8)):
        if not shutil.which(cmd):
            checks[key] = {"status": "no_binary", "detail": cmd+" not installed",
                           "remedy": "pkg install termux-api (plus Termux:API app)" if key!="bluetooth" else "official termux-api has no BT"}
            continue
        if not deep:
            checks[key] = {"status": "unverified", "detail": "binary present, not exercised",
                           "remedy": "Run Preflight to verify"}
        else:
            args = [cmd]
            if key == "gps":
                args += ["-p", "network"]
            rc, out, err, to = _run(args, timeout=tmo)
            if key == "gps" and to:
                checks[key] = {"status": "unverified", "detail": "no fix within 4s",
                               "remedy": "Use Fix GPS button; allow up to 30s"}
            else:
                checks[key] = classify_termux_result(cmd, rc, out, err, to)
    checks["wake_lock"] = ({"status": "ok", "detail": "termux-wake-lock present", "remedy": ""}
                           if shutil.which("termux-wake-lock")
                           else {"status": "no_binary", "detail": "termux-wake-lock missing",
                                 "remedy": "pkg install termux-tools"})
    caps = {k: (v["status"] == "ok") for k, v in checks.items()}
    caps["lan"] = True
    return caps, checks

# ----- wake lock -------------------------------------------------------
_wake_held = False

def wake_lock(on):
    global _wake_held
    if not shutil.which("termux-wake-lock"):
        return False
    try:
        if on and not _wake_held:
            subprocess.run(["termux-wake-lock"], capture_output=True, timeout=8)
            _wake_held = True
        elif not on and _wake_held:
            subprocess.run(["termux-wake-unlock"], capture_output=True, timeout=8)
            _wake_held = False
        return True
    except Exception:
        return False

# ----- interface enumeration -------------------------------------------
VPN_IFACE_RE = re.compile(r"^(tun|tap|ppp|wg|ipsec|utun|nordlynx|proton)", re.I)

def enumerate_interfaces():
    results = []
    if shutil.which("ip"):
        rc, out, _, _ = _run(["ip", "-4", "-o", "addr", "show"], timeout=6)
        for line in out.splitlines():
            m = re.search(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if not m:
                continue
            iface, ip, plen = m.group(1), m.group(2), int(m.group(3))
            if iface == "lo" or ip.startswith("127."):
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
            except ValueError:
                continue
            results.append({"iface": iface, "ip": ip, "cidr": str(net),
                            "is_vpn": bool(VPN_IFACE_RE.match(iface)),
                            "hosts": net.num_addresses - 2 if net.num_addresses > 2 else 1})
    if not results:
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
                s.settimeout(1)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            results.append({"iface": "route-inferred", "ip": ip,
                            "cidr": str(net), "is_vpn": False,
                            "hosts": 254, "assumed_prefix": True})
        except Exception:
            pass
    return results

def choose_scan_target(prefer_iface=None):
    ifaces = enumerate_interfaces()
    if not ifaces:
        return None, {"error": "No usable IPv4 interface. Is WiFi connected?",
                      "interfaces": []}
    if prefer_iface:
        cand = [i for i in ifaces if i["iface"] == prefer_iface] or ifaces
    else:
        physical = [i for i in ifaces if not i["is_vpn"]]
        cand = physical or ifaces
    def rank(i):
        named = 0 if re.match(r"^(wlan|eth|rmnet|ap|swlan)", i["iface"], re.I) else 1
        return (named, i["hosts"])
    chosen = sorted(cand, key=rank)[0]
    net = ipaddress.ip_network(chosen["cidr"], strict=False)
    clamped = False
    if net.num_addresses > 1024:
        net = ipaddress.ip_network(f"{chosen['ip']}/24", strict=False)
        clamped = True
    meta = {"interfaces": ifaces, "chosen_iface": chosen["iface"],
            "self_ip": chosen["ip"], "subnet": str(net),
            "clamped_from": chosen["cidr"] if clamped else None,
            "vpn_present": any(i["is_vpn"] for i in ifaces),
            "vpn_skipped": [i["iface"] for i in ifaces if i["is_vpn"] and i["iface"] != chosen["iface"]],
            "assumed_prefix": chosen.get("assumed_prefix", False)}
    return net, meta

# ----- mDNS (full parser with compression, TXT, SRV) --------------------
MDNS_SERVICES = [
    "_googlecast._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
    "_spotify-connect._tcp.local", "_printer._tcp.local", "_ipp._tcp.local",
    "_hap._tcp.local", "_sonos._tcp.local", "_androidtvremote2._tcp.local",
    "_workstation._tcp.local", "_smb._tcp.local", "_device-info._tcp.local",
]

TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_SRV = 1, 12, 16, 33

def _encode_dns_name(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"

def _parse_dns_name(data, offset, depth=0):
    labels = []
    n = len(data)
    jumped = False
    after = offset
    hops = 0
    while hops < 24:
        if offset >= n:
            break
        ln = data[offset]
        if ln == 0:
            offset += 1
            if not jumped:
                after = offset
            break
        if (ln & 0xC0) == 0xC0:
            if offset + 1 >= n:
                break
            ptr = ((ln & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                after = offset + 2
                jumped = True
            if ptr >= n:
                break
            offset = ptr
            hops += 1
            continue
        if ln > 63 or offset + 1 + ln > n:
            break
        labels.append(data[offset + 1: offset + 1 + ln])
        offset += 1 + ln
        if not jumped:
            after = offset
    name = b".".join(labels).decode("utf-8", "replace")
    return name, after

def _parse_txt(rdata):
    kv = {}
    i = 0
    while i < len(rdata):
        ln = rdata[i]
        i += 1
        if ln == 0 or i + ln > len(rdata):
            break
        item = rdata[i:i + ln].decode("utf-8", "replace")
        i += ln
        if "=" in item:
            k, v = item.split("=", 1)
            kv[k.strip().lower()] = v.strip()
    return kv

def parse_mdns_message(data):
    out = {"ptr": [], "txt": {}, "srv": {}, "a": {}, "instances": set()}
    if len(data) < 12:
        return out
    try:
        _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return out
    off = 12
    for _ in range(qd):
        _, off = _parse_dns_name(data, off)
        off += 4
        if off > len(data):
            return out
    for _ in range(an + ns + ar):
        if off >= len(data):
            break
        rname, off = _parse_dns_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        rd_start = off
        off += rdlen
        if rtype == TYPE_PTR:
            target, _ = _parse_dns_name(data, rd_start)
            if target:
                out["ptr"].append((rname, target))
                out["instances"].add(target)
        elif rtype == TYPE_TXT:
            kv = _parse_txt(rdata)
            if kv:
                out["txt"][rname] = kv
                out["instances"].add(rname)
        elif rtype == TYPE_SRV:
            if rdlen >= 7:
                target, _ = _parse_dns_name(data, rd_start + 6)
                out["srv"][rname] = target
                out["instances"].add(rname)
        elif rtype == TYPE_A:
            if rdlen == 4:
                out["a"][rname] = ".".join(str(b) for b in rdata)
    return out

def mdns_discover(timeout=4, ipv6=False):
    results = {}
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        mcast = "ff02::fb" if ipv6 else "224.0.0.251"
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if not ipv6:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        else:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
        s.settimeout(timeout)
        for svc in MDNS_SERVICES:
            pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
            pkt += _encode_dns_name(svc) + struct.pack(">HH", TYPE_PTR, 1)
            s.sendto(pkt, (mcast, 5353))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                break
            ip = addr[0] if not ipv6 else addr[0]
            parsed = parse_mdns_message(data)
            e = results.setdefault(ip, {"services": set(), "instances": set(),
                                        "txt": {}, "srv": {}})
            for owner, target in parsed["ptr"]:
                for svc in MDNS_SERVICES:
                    base = svc.replace(".local", "")
                    if base in owner or base in target:
                        e["services"].add(base)
            e["instances"] |= parsed["instances"]
            e["txt"].update(parsed["txt"])
            e["srv"].update(parsed["srv"])
        s.close()
    except Exception:
        pass
    return results

# ----- SSDP (IPv4 and IPv6) --------------------------------------------
def ssdp_discover(timeout=4, ipv6=False):
    msg = (b"M-SEARCH * HTTP/1.1\r\n"
           b"HOST: 239.255.255.250:1900\r\n"
           b'MAN: "ssdp:discover"\r\n'
           b"MX: 2\r\n"
           b"ST: upnp:rootdevice\r\n\r\n")
    results = {}
    try:
        family = socket.AF_INET6 if ipv6 else socket.AF_INET
        mcast = "ff02::c" if ipv6 else "239.255.255.250"
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if ipv6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
        else:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        s.sendto(msg, (mcast, 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                break
            ip = addr[0] if not ipv6 else addr[0]
            text = data.decode("utf-8", "ignore")
            e = results.setdefault(ip, {"server": "", "location": "", "st": ""})
            for line in text.split("\r\n"):
                low = line.lower()
                if low.startswith("server:") and not e["server"]:
                    e["server"] = line.split(":", 1)[1].strip()
                elif low.startswith("location:") and not e["location"]:
                    e["location"] = line.split(":", 1)[1].strip()
                elif low.startswith("st:") and not e["st"]:
                    e["st"] = line.split(":", 1)[1].strip()
        s.close()
    except Exception:
        pass
    return results

# ----- liveness detection ----------------------------------------------
FINGERPRINT_PORTS = {
    8008: "chromecast", 8009: "chromecast", 8060: "roku", 7000: "airplay",
    1400: "sonos", 9197: "samsung_tv", 8001: "samsung_tv", 3000: "lg_webos",
    3001: "lg_webos", 631: "printer", 9100: "printer", 445: "smb_host",
    22: "ssh_host", 80: "web_host", 443: "web_host", 32400: "plex",
    1883: "mqtt_iot", 8123: "home_assistant", 5000: "upnp_host",
    62078: "ios_device", 5555: "adb_host",
}
# all ports used both for liveness and for fingerprint
LIVENESS_PORTS = list(FINGERPRINT_PORTS.keys())

def tcp_probe(ip, port, timeout=0.35):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except Exception:
        return False

def icmp_alive(ip, timeout=1):
    if not shutil.which("ping"):
        return False
    try:
        p = subprocess.run(["ping", "-c", "1", "-W", str(int(timeout)), str(ip)],
                           capture_output=True, timeout=timeout+1.5)
        return p.returncode == 0
    except Exception:
        return False

def read_arp_table():
    mapping = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    mapping[parts[0]] = parts[3].lower()
    except Exception:
        pass
    if shutil.which("ip"):
        rc, out, _, _ = _run(["ip", "neigh"], timeout=6)
        for line in out.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
            if m:
                mapping.setdefault(m.group(1), m.group(2).lower())
    return mapping

def find_live_hosts(net, extra_ips=()):
    hosts = list(net.hosts())
    live = set(str(i) for i in extra_ips)
    lock = threading.Lock()
    def ping_stage(ip):
        if icmp_alive(ip):
            with lock:
                live.add(str(ip))
    def tcp_stage(ip):
        s = str(ip)
        if s in live:
            return
        # probe all liveness ports now
        for p in LIVENESS_PORTS:
            if tcp_probe(ip, p, timeout=0.3):
                with lock:
                    live.add(s)
                return
    if shutil.which("ping"):
        with ThreadPoolExecutor(max_workers=48) as ex:
            list(ex.map(ping_stage, hosts))
    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(tcp_stage, hosts))
    return live

def fingerprint_hosts(live_ips):
    found = {}
    lock = threading.Lock()
    def deep(ip):
        hits = []
        for p in FINGERPRINT_PORTS:
            if tcp_probe(ip, p, timeout=0.3):
                hits.append(p)
        classes = {FINGERPRINT_PORTS[p] for p in hits}
        with lock:
            found[ip] = {"classes": classes, "ports": sorted(hits)}
    with ThreadPoolExecutor(max_workers=48) as ex:
        list(ex.map(deep, live_ips))
    return found

# ----- reverse DNS with timeout ----------------------------------------
def reverse_dns(ip, timeout=1.5):
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)

# ----- classification --------------------------------------------------
CLASS_TO_TYPE = {
    "chromecast": ("tv", "Chromecast / Google TV"),
    "roku": ("tv", "Roku"), "airplay": ("tv", "Apple TV / AirPlay"),
    "samsung_tv": ("tv", "Samsung TV"), "lg_webos": ("tv", "LG webOS TV"),
    "sonos": ("speaker", "Sonos"), "printer": ("printer", "Printer"),
    "plex": ("server", "Plex"), "home_assistant": ("server", "Home Assistant"),
    "mqtt_iot": ("iot", "MQTT broker"), "smb_host": ("computer", "File share host"),
    "ssh_host": ("computer", "SSH host"), "ios_device": ("phone", "iOS device"),
    "adb_host": ("computer", "ADB-enabled device"),
    "web_host": ("unknown", "HTTP service"), "upnp_host": ("unknown", "UPnP host"),
}

SERVER_MODEL_HINTS = [
    (r"Roku", "tv", "Roku"), (r"webOS", "tv", "LG webOS TV"),
    (r"Samsung", "tv", "Samsung"), (r"BRAVIA|Sony", "tv", "Sony BRAVIA"),
    (r"Chromecast|Eureka", "tv", "Chromecast / Google TV"),
    (r"Sonos", "speaker", "Sonos"),
    (r"AirTunes|AirReceiver|AppleTV", "tv", "Apple TV / AirPlay"),
    (r"Hisense", "tv", "Hisense"), (r"TCL", "tv", "TCL"),
    (r"Philips", "tv", "Philips"), (r"Vizio", "tv", "Vizio"),
    (r"HP |HP-|Officejet|LaserJet", "printer", "HP printer"),
    (r"EPSON|Epson", "printer", "Epson printer"),
    (r"Brother", "printer", "Brother printer"),
    (r"Canon", "printer", "Canon printer"),
    (r"Xbox", "console", "Xbox"), (r"PlayStation|PS4|PS5", "console", "PlayStation"),
    (r"Plex", "server", "Plex"),
    (r"Synology|DiskStation", "server", "Synology NAS"),
    (r"OpenWrt|RouterOS|dnsmasq|MiniUPnP|AsusWRT|Tomato|Ubiquiti|UniFi",
     "router", "Router / gateway"),
]

MDNS_SERVICE_HINTS = {
    "_googlecast": ("tv", "Chromecast / Google TV"),
    "_airplay": ("tv", "AirPlay device"), "_raop": ("speaker", "AirPlay audio"),
    "_spotify-connect": ("speaker", "Spotify Connect"),
    "_printer": ("printer", "Printer"), "_ipp": ("printer", "Printer"),
    "_hap": ("iot", "HomeKit accessory"), "_sonos": ("speaker", "Sonos"),
    "_androidtvremote2": ("tv", "Android TV"),
    "_workstation": ("computer", "Computer"),
    "_smb": ("computer", "File share host"),
}

TXT_MODEL_KEYS = ["md", "model", "am", "ty", "product", "usb_mdl", "mdl"]
TXT_NAME_KEYS = ["fn", "n", "name", "friendlyname", "note"]

def txt_extract(txt_map):
    model, fname = "", ""
    for _, kv in (txt_map or {}).items():
        for k in TXT_MODEL_KEYS:
            if not model and kv.get(k):
                model = kv[k][:48]
        for k in TXT_NAME_KEYS:
            if not fname and kv.get(k):
                fname = kv[k][:48]
    return model, fname

def _name_score(n):
    score = 0
    if " " in n:
        score += 10
    for tok in re.split(r"[-_ .]", n):
        if len(tok) >= 6 and re.fullmatch(r"[0-9a-fA-F]+", tok):
            score -= 8
        if len(tok) >= 8 and re.search(r"\d", tok) and re.search(r"[a-zA-Z]", tok):
            score -= 4
    if re.fullmatch(r"[0-9a-fA-F:.\-]+", n):
        score -= 12
    score += min(len(n), 24) * 0.1
    return score

def _clean_instance(name):
    n = re.sub(r"\._(tcp|udp)\.local\.?$", "", name)
    n = re.sub(r"\._[a-z0-9\-]+$", "", n)
    n = n.replace("\\032", " ").replace("\\ ", " ")
    return n.strip(". ")

def stable_asset_id(ip, mac):
    if mac:
        return f"lan:mac:{mac}"
    return f"lan:ip:{ip}"

def classify_lan_host(ip, sweep_entry, ssdp_entry, mdns_entry, arp_mac, do_rdns=True):
    dtype, model, name = "unknown", "", ""
    evidence = []
    # mDNS TXT
    if mdns_entry:
        txt_model, txt_name = txt_extract(mdns_entry.get("txt"))
        if txt_model:
            model = txt_model
            evidence.append("txt-model:" + txt_model[:32])
        if txt_name:
            name = txt_name
            evidence.append("txt-name:" + txt_name[:32])
        for svc in mdns_entry.get("services", set()):
            for key, (t, label) in MDNS_SERVICE_HINTS.items():
                if svc.startswith(key):
                    if dtype == "unknown":
                        dtype = t
                    if not model and label:
                        model = label
                    evidence.append("mdns:" + key)
        if not name:
            cands = [_clean_instance(i) for i in mdns_entry.get("instances", set())]
            cands = [c for c in cands if c and not c.startswith("_") and len(c) > 2]
            if cands:
                name = sorted(cands, key=_name_score, reverse=True)[0][:48]
    # SSDP
    if ssdp_entry and ssdp_entry.get("server"):
        server = ssdp_entry["server"]
        evidence.append("ssdp:" + server[:48])
        for pattern, t, label in SERVER_MODEL_HINTS:
            if re.search(pattern, server, re.IGNORECASE):
                if dtype == "unknown":
                    dtype = t
                if not model:
                    model = label
                break
        if not model:
            model = server.split()[0][:40]
    # port fingerprints
    if sweep_entry:
        for cls in sweep_entry.get("classes", set()):
            t, label = CLASS_TO_TYPE.get(cls, ("unknown", cls))
            if dtype == "unknown" and t != "unknown":
                dtype = t
            if not model and label:
                model = label
        if sweep_entry.get("ports"):
            evidence.append("ports:" + ",".join(str(p) for p in sweep_entry["ports"][:8]))
    if arp_mac:
        evidence.append("mac:" + arp_mac)
    if ip.endswith(".1") or ip.endswith(".254"):
        if dtype == "unknown":
            dtype, model = "router", model or "Gateway (inferred)"
    if not name and do_rdns:
        rd = reverse_dns(ip)
        if rd:
            name = rd[:48]
            evidence.append("rdns")
    if not name:
        name = model or f"host-{ip.split('.')[-1]}"
    return {
        "id": stable_asset_id(ip, arp_mac),
        "channel": "lan", "name": name, "model": model,
        "device_type": dtype, "addr": ip, "mac": arp_mac or "",
        "rssi": None, "proximity": "on-network", "evidence": evidence[:7],
    }

def scan_lan(prefer_iface=None):
    net, meta = choose_scan_target(prefer_iface)
    if net is None:
        return [], meta
    # dual‑stack discovery
    ssdp_v4 = ssdp_discover(timeout=4, ipv6=False)
    mdns_v4 = mdns_discover(timeout=4, ipv6=False)
    # IPv6 mDNS/SSDP are optional; we'll try them but don't fail if not supported
    ssdp_v6 = {}
    mdns_v6 = {}
    try:
        ssdp_v6 = ssdp_discover(timeout=3, ipv6=True)
    except Exception:
        pass
    try:
        mdns_v6 = mdns_discover(timeout=3, ipv6=True)
    except Exception:
        pass
    # merge (IPv6 addresses are separate)
    ssdp = {**ssdp_v4, **ssdp_v6}
    mdns = {**mdns_v4, **mdns_v6}
    speakers = set(ssdp) | set(mdns)
    live = find_live_hosts(net, extra_ips=speakers)
    self_ip = meta.get("self_ip")
    if self_ip in live:
        live.remove(self_ip)
    arp = read_arp_table()
    sweep = fingerprint_hosts(sorted(live))
    assets = []
    for ip in sorted(live, key=lambda x: tuple(int(p) for p in x.split(".")) if re.fullmatch(r"[\d.]+", x) else (0,)):
        assets.append(classify_lan_host(ip, sweep.get(ip), ssdp.get(ip),
                                        mdns.get(ip), arp.get(ip)))
    meta.update({
        "ssdp_responders": len(ssdp), "mdns_responders": len(mdns),
        "live_hosts": len(live), "arp_entries": len(arp),
        "txt_records": sum(len(v.get("txt", {})) for v in mdns.values()),
    })
    return assets, meta

# ----- Tier 2 & 3 ------------------------------------------------------
def proximity_bucket(rssi):
    if rssi is None:
        return "unknown"
    if rssi >= -45:
        return "very close"
    if rssi >= -60:
        return "same room"
    if rssi >= -72:
        return "nearby"
    if rssi >= -82:
        return "far"
    return "fringe"

def scan_wifi():
    chk = PREFLIGHT.get("wifi_scan", {})
    if chk.get("status") not in ("ok", "unverified"):
        return [], chk.get("detail", "wifi scan unavailable")
    rc, out, err, to = _run(["termux-wifi-scaninfo"], timeout=25)
    if to:
        return [], "termux-wifi-scaninfo timed out (Termux:API app missing?)"
    if not out:
        return [], "empty scan — is Android location ON?"
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return [], "unparseable scan output"
    if isinstance(data, dict):
        if "API_ERROR" in data:
            return [], "Android: " + str(data["API_ERROR"])
        data = [data]
    assets = []
    for net in data:
        if not isinstance(net, dict):
            continue
        rssi = net.get("rssi", net.get("level"))
        bssid = (net.get("bssid") or "").lower()
        ssid = net.get("ssid") or "(hidden)"
        freq = net.get("frequency_mhz", net.get("frequency"))
        band = ("5GHz" if freq > 3000 else "2.4GHz") if isinstance(freq, int) else ""
        assets.append({
            "id": "wifi:" + bssid, "channel": "wifi", "name": ssid,
            "model": band, "device_type": "router", "addr": bssid,
            "mac": bssid, "rssi": rssi, "proximity": proximity_bucket(rssi),
            "evidence": ["rf:" + str(rssi) + "dBm", "band:" + band],
        })
    return assets, None

def scan_bluetooth():
    chk = PREFLIGHT.get("bluetooth", {})
    if chk.get("status") not in ("ok", "unverified"):
        return [], chk.get("detail", "no bluetooth scan available")
    _run(["termux-bluetooth-scaninfo"], timeout=15)
    time.sleep(6)
    rc, out, err, to = _run(["termux-bluetooth-scaninfo"], timeout=15)
    if to or not out:
        return [], "bluetooth scan returned nothing"
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        data = [{"name": l.strip()} for l in out.splitlines() if l.strip()]
    if isinstance(data, dict):
        if "API_ERROR" in data:
            return [], "Android: " + str(data["API_ERROR"])
        data = [data]
    assets = []
    for d in data:
        if not isinstance(d, dict):
            continue
        nm = d.get("name") or "(unnamed)"
        addr = str(d.get("address", d.get("mac", nm))).lower()
        low = nm.lower()
        dt = "unknown"
        if any(k in low for k in ("bud", "pod", "headphone", "wf-", "wh-", "beats")):
            dt = "earbuds"
        elif any(k in low for k in ("watch", "band", "fit")):
            dt = "wearable"
        elif any(k in low for k in ("tv", "soundbar", "speaker")):
            dt = "speaker"
        assets.append({
            "id": "bt:" + addr, "channel": "bluetooth", "name": nm,
            "model": "", "device_type": dt, "addr": addr, "mac": addr,
            "rssi": d.get("rssi"), "proximity": proximity_bucket(d.get("rssi")),
            "evidence": ["bt-scan"],
        })
    return assets, None

def get_location():
    chk = PREFLIGHT.get("gps", {})
    if chk.get("status") == "no_binary":
        return None, chk.get("remedy", "termux-location unavailable")
    rc, out, err, to = _run(["termux-location", "-p", "network"], timeout=35)
    if to:
        return None, "No fix in 35s. Enable Settings → Location, go near a window."
    if not out:
        return None, "termux-location returned nothing (Termux:API app missing?)"
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return None, "unparseable location output"
    if "API_ERROR" in d:
        return None, "Android: " + str(d["API_ERROR"])
    if "latitude" in d:
        return {"lat": d["latitude"], "lon": d["longitude"],
                "accuracy_m": d.get("accuracy")}, None
    return None, "no latitude in response"

# ----- database -------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS sightings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, asset_id TEXT NOT NULL, channel TEXT, name TEXT,
    model TEXT, device_type TEXT, addr TEXT, mac TEXT, rssi INTEGER,
    proximity TEXT
);
CREATE TABLE IF NOT EXISTS baseline (
    asset_id TEXT PRIMARY KEY, first_seen REAL, name TEXT, channel TEXT
);
CREATE INDEX IF NOT EXISTS idx_s_ts ON sightings(ts DESC);
CREATE INDEX IF NOT EXISTS idx_s_asset ON sightings(asset_id, ts DESC);
"""

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript(SCHEMA)
        row = c.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()
        ver = int(row["v"]) if row else 0
        if ver != SCHEMA_VERSION:
            # version 2 introduced MAC-based identity; version 3 keeps that.
            # We'll keep baselines but re-key them? For simplicity, we drop them
            # on upgrade because old IP-based IDs are meaningless.
            if ver < 2:
                c.execute("DELETE FROM baseline")
            c.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version',?)",
                      (str(SCHEMA_VERSION),))

def save_sightings(assets):
    now = time.time()
    with db() as c:
        for a in assets:
            c.execute(
                """INSERT INTO sightings (ts, asset_id, channel, name, model,
                   device_type, addr, mac, rssi, proximity)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (now, a["id"], a["channel"], a["name"], a["model"],
                 a["device_type"], a["addr"], a["mac"], a["rssi"],
                 a["proximity"]))

def prune_db(keep_per_asset=SIGHTINGS_PER_ASSET):
    with db() as c:
        c.execute(
            """DELETE FROM sightings WHERE id NOT IN (
                 SELECT id FROM (
                   SELECT id, ROW_NUMBER() OVER
                     (PARTITION BY asset_id ORDER BY ts DESC) rn
                   FROM sightings
                 ) WHERE rn <= ?
               )""", (keep_per_asset,))
        return c.total_changes

def commit_baseline(assets):
    now = time.time()
    with db() as c:
        for a in assets:
            c.execute(
                "INSERT OR REPLACE INTO baseline VALUES (?,?,?,?)",
                (a["id"], now, a["name"], a["channel"]))

def get_baseline_ids():
    with db() as c:
        return {r["asset_id"] for r in c.execute("SELECT asset_id FROM baseline")}

def clear_baseline():
    with db() as c:
        c.execute("DELETE FROM baseline")

def rssi_trend(asset_id, samples=6):
    with db() as c:
        rows = c.execute(
            "SELECT rssi FROM sightings WHERE asset_id=? AND rssi IS NOT NULL "
            "ORDER BY ts DESC LIMIT ?", (asset_id, samples)).fetchall()
    vals = [r["rssi"] for r in rows]
    if len(vals) < 3:
        return {"trend": "insufficient", "delta": 0, "samples": len(vals)}
    h = len(vals) // 2
    recent = sum(vals[:h]) / max(1, h)
    older = sum(vals[h:]) / max(1, len(vals) - h)
    delta = round(recent - older, 1)
    trend = "warmer" if delta >= 3 else ("colder" if delta <= -3 else "steady")
    return {"trend": trend, "delta": delta, "samples": len(vals)}

# ----- orchestration --------------------------------------------------
STATE = {
    "running": False, "phase": "idle", "last_scan": None, "last_error": None,
    "assets": [], "lan_meta": {}, "channel_errors": {}, "location": None,
    "location_error": None, "interval": 120, "scan_count": 0,
    "wake_lock": False, "pruned": 0, "prefer_iface": None,
    "scan_version": 0,
}
_lock = threading.Lock()

def do_full_scan():
    with _lock:
        STATE["phase"] = "wifi"
        iface = STATE["prefer_iface"]
    wifi, wifi_err = scan_wifi()
    with _lock:
        STATE["phase"] = "bluetooth"
    bt, bt_err = scan_bluetooth()
    with _lock:
        STATE["phase"] = "lan"
    lan, lan_meta = scan_lan(prefer_iface=iface)
    assets = lan + wifi + bt
    save_sightings(assets)
    pruned = prune_db()
    baseline = get_baseline_ids()
    for a in assets:
        a["is_new"] = bool(baseline) and a["id"] not in baseline
        a["trend"] = rssi_trend(a["id"]) if a["rssi"] is not None else None
    with _lock:
        STATE["assets"] = assets
        STATE["lan_meta"] = lan_meta
        STATE["channel_errors"] = {"wifi": wifi_err, "bluetooth": bt_err,
                                   "lan": lan_meta.get("error")}
        STATE["last_scan"] = time.time()
        STATE["phase"] = "idle"
        STATE["pruned"] = pruned
        STATE["scan_count"] += 1
        STATE["scan_version"] += 1
    return assets

def scan_loop():
    while True:
        with _lock:
            if not STATE["running"]:
                STATE["phase"] = "idle"
                return
            interval = STATE["interval"]
        try:
            do_full_scan()
        except Exception as e:
            with _lock:
                STATE["last_error"] = str(e)[:200]
                STATE["phase"] = "idle"
        for _ in range(interval):
            with _lock:
                if not STATE["running"]:
                    return
            time.sleep(1)

# ----- Flask app ------------------------------------------------------
app = Flask(__name__)

@app.get("/")
def index():
    return render_template_string(UI)

@app.get("/api/preflight")
def api_preflight():
    return jsonify({"caps": CAPS, "checks": PREFLIGHT,
                    "interfaces": enumerate_interfaces()})

@app.post("/api/preflight/run")
def api_preflight_run():
    global CAPS, PREFLIGHT
    CAPS, PREFLIGHT = preflight(deep=True)
    return jsonify({"caps": CAPS, "checks": PREFLIGHT,
                    "interfaces": enumerate_interfaces()})

@app.get("/api/state")
def api_state():
    with _lock:
        return jsonify({
            "running": STATE["running"], "phase": STATE["phase"],
            "last_scan": STATE["last_scan"], "last_error": STATE["last_error"],
            "channel_errors": STATE["channel_errors"],
            "lan_meta": STATE["lan_meta"], "location": STATE["location"],
            "location_error": STATE["location_error"],
            "interval": STATE["interval"], "scan_count": STATE["scan_count"],
            "asset_count": len(STATE["assets"]),
            "baseline_size": len(get_baseline_ids()),
            "wake_lock": _wake_held, "pruned": STATE["pruned"],
            "prefer_iface": STATE["prefer_iface"],
            "scan_version": STATE["scan_version"],
        })

@app.get("/api/assets")
def api_assets():
    with _lock:
        assets = list(STATE["assets"])
    order = {"very close": 0, "same room": 1, "nearby": 2, "on-network": 3,
             "far": 4, "fringe": 5, "unknown": 6}
    assets.sort(key=lambda a: (order.get(a["proximity"], 9), -(a["rssi"] or -999)))
    return jsonify({"assets": assets})

@app.post("/api/scan/once")
def api_once():
    try:
        return jsonify({"ok": True, "count": len(do_full_scan())})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)[:200]}), 500

@app.post("/api/scan/start")
def api_start():
    body = request.get_json(silent=True) or {}
    with _lock:
        if STATE["running"]:
            return jsonify({"error": "already running"}), 400
        STATE["running"] = True
        STATE["interval"] = max(45, int(body.get("interval", 120)))
        if body.get("iface"):
            STATE["prefer_iface"] = body["iface"]
        threading.Thread(target=scan_loop, daemon=True).start()
    wake_lock(True)
    return jsonify({"ok": True, "wake_lock": _wake_held})

@app.post("/api/scan/stop")
def api_stop():
    with _lock:
        STATE["running"] = False
    wake_lock(False)
    return jsonify({"ok": True})

@app.post("/api/iface")
def api_iface():
    body = request.get_json(silent=True) or {}
    with _lock:
        STATE["prefer_iface"] = body.get("iface") or None
    return jsonify({"ok": True, "prefer_iface": STATE["prefer_iface"]})

@app.post("/api/baseline/set")
def api_baseline_set():
    with _lock:
        assets = list(STATE["assets"])
    clear_baseline()
    commit_baseline(assets)
    return jsonify({"ok": True, "size": len(assets)})

@app.post("/api/baseline/clear")
def api_baseline_clear():
    clear_baseline()
    return jsonify({"ok": True})

@app.get("/api/track/<path:asset_id>")
def api_track(asset_id):
    with db() as c:
        rows = c.execute(
            "SELECT ts, rssi, proximity, addr FROM sightings WHERE asset_id=? "
            "ORDER BY ts DESC LIMIT 60", (asset_id,)).fetchall()
    return jsonify({"history": [dict(r) for r in reversed(rows)],
                    "trend": rssi_trend(asset_id)})

@app.post("/api/location")
def api_location():
    loc, err = get_location()
    with _lock:
        STATE["location"] = loc
        STATE["location_error"] = err
    return jsonify({"location": loc, "error": err})

# ----- UI ------------------------------------------------------------
UI = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIGINT v3</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<link href="https://fonts.googleapis.com/css2?family=Chivo+Mono:wght@400;600;800&family=Archivo:wght@500;700;900&display=swap" rel="stylesheet">
<style>
:root{--void:#07090c;--slate:#101419;--edge:#1e242c;--ink:#dfe4ea;--mute:#6f7b89;
 --sig:#7de3c3;--warn:#ffb63d;--hot:#ff6b5e;--cool:#5b9dff}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--void);color:var(--ink);
 font-family:'Chivo Mono',ui-monospace,monospace;font-size:13px}
#wrap{display:flex;flex-direction:column;height:100%}
header{padding:12px 16px;border-bottom:1px solid var(--edge);display:flex;
 justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.brand{font-family:'Archivo',sans-serif;font-weight:900;font-size:15px;
 letter-spacing:.18em;display:flex;align-items:center;gap:9px}
.pip{width:7px;height:7px;border-radius:50%;background:var(--mute)}
.pip.on{background:var(--sig);box-shadow:0 0 9px var(--sig)}
.phase{color:var(--mute);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase}
.lock{font-size:9px;color:var(--warn);border:1px solid var(--warn);
 padding:1px 4px;border-radius:2px;display:none}
.lock.on{display:inline-block}
.bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
button{background:transparent;border:1px solid var(--edge);color:var(--ink);
 padding:7px 11px;font-family:inherit;font-size:11px;border-radius:3px;
 cursor:pointer;letter-spacing:.06em;text-transform:uppercase}
button:hover:not(:disabled){border-color:var(--sig);color:var(--sig)}
button:disabled{opacity:.32;cursor:not-allowed}
button.primary{border-color:var(--sig);color:var(--sig)}
button.danger:hover{border-color:var(--hot);color:var(--hot)}
input[type=number],select{width:auto;background:var(--void);border:1px solid var(--edge);
 color:var(--ink);padding:6px;font-family:inherit;font-size:11px;border-radius:3px}
input[type=number]{width:56px}
#caps{padding:9px 16px;border-bottom:1px solid var(--edge);display:flex;gap:12px;
 flex-wrap:wrap;font-size:10.5px;background:var(--slate)}
.cap{display:flex;align-items:center;gap:5px;letter-spacing:.05em;cursor:help}
.cap b{width:6px;height:6px;border-radius:50%;display:inline-block;flex:none}
.cap.ok b{background:var(--sig)}.cap.ok{color:var(--ink)}
.cap.warn b{background:var(--warn)}.cap.warn{color:var(--warn)}
.cap.bad b{background:#3a4149}.cap.bad{color:var(--mute)}
#body{flex:1;display:flex;min-height:0}
#left{flex:1;min-width:0;display:flex;flex-direction:column;border-right:1px solid var(--edge)}
#right{width:352px;display:flex;flex-direction:column;min-height:0;overflow-y:auto}
@media(max-width:880px){#body{flex-direction:column}#right{width:auto;
 border-top:1px solid var(--edge)}#map{height:210px!important}}
#map{height:270px;background:#05070a;border-bottom:1px solid var(--edge)}
.leaflet-container{background:#05070a}
.leaflet-tile{filter:invert(1) hue-rotate(185deg) brightness(.62) contrast(1.15) saturate(.5)}
.leaflet-control-attribution{background:rgba(7,9,12,.82)!important;
 color:var(--mute)!important;font-size:9px!important}
.leaflet-control-attribution a{color:var(--mute)!important}
.sec{padding:10px 16px;border-bottom:1px solid var(--edge);font-size:10px;
 letter-spacing:.14em;text-transform:uppercase;color:var(--mute);display:flex;
 justify-content:space-between;align-items:center;background:var(--void)}
.sec span.n{color:var(--sig);font-weight:800}
#assets{flex:1;overflow-y:auto;min-height:0}
.row{padding:11px 16px;border-bottom:1px solid #14181e;cursor:pointer}
.row:hover{background:#0d1116}
.row.new{border-left:2px solid var(--warn);padding-left:14px}
.r1{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.px{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;white-space:nowrap}
.px.vc{color:var(--hot)}.px.sr{color:var(--warn)}.px.nb{color:var(--sig)}
.px.on{color:var(--cool)}.px.fr,.px.un{color:var(--mute)}
.r2{margin-top:3px;color:var(--mute);font-size:10.5px;overflow:hidden;
 text-overflow:ellipsis;white-space:nowrap}
.r3{margin-top:5px;display:flex;gap:5px;flex-wrap:wrap}
.tag{font-size:9px;padding:1.5px 5px;border:1px solid var(--edge);
 border-radius:2px;color:var(--mute)}
.tag.t{border-color:var(--sig);color:var(--sig)}
.tag.newt{border-color:var(--warn);color:var(--warn)}
.tag.txt{border-color:var(--cool);color:var(--cool)}
.trend{font-size:9.5px}
.trend.warmer{color:var(--hot)}.trend.colder{color:var(--cool)}
.trend.steady{color:var(--mute)}
.note{padding:11px 16px;color:var(--mute);font-size:10.5px;line-height:1.65;
 border-bottom:1px solid var(--edge)}
.note b{color:var(--warn);font-weight:600}
.fix{border-left:2px solid var(--warn);padding:8px 10px;margin:7px 0;
 background:rgba(255,182,61,.05);color:var(--ink);font-size:10px;line-height:1.55}
.fix .k{color:var(--warn);font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.fix code{color:var(--sig);background:#0b0e12;padding:1px 4px;border-radius:2px}
.err{color:var(--hot)}
.empty{padding:32px 16px;text-align:center;color:var(--mute);font-size:11.5px;line-height:1.7}
#detail{padding:12px 16px;border-top:1px solid var(--edge);display:none;background:var(--slate)}
#detail.show{display:block}
#spark{width:100%;height:42px;display:block;margin-top:8px}
.dh{font-family:'Archivo',sans-serif;font-weight:700;font-size:12.5px;
 margin-bottom:2px;word-break:break-all}
.dm{color:var(--mute);font-size:10.5px;line-height:1.55}
</style>
</head>
<body>
<div id="wrap">
<header>
  <div class="brand"><span class="pip" id="pip"></span>SIGINT
    <span class="phase" id="phase">idle</span>
    <span class="lock" id="lock">wake-lock</span></div>
  <div class="bar">
    <button class="primary" id="once">Scan once</button>
    <button id="start">Auto</button>
    <button id="stop" disabled>Stop</button>
    <input type="number" id="iv" value="120" min="45" title="seconds between scans">
    <select id="iface" title="interface to inventory"></select>
    <button id="pf">Preflight</button>
    <button id="base">Baseline</button>
    <button class="danger" id="baseclr">Clear</button>
    <button id="gps">Fix GPS</button>
  </div>
</header>
<div id="caps"></div>
<div id="body">
  <div id="left">
    <div id="map"></div>
    <div class="sec">Detected assets <span class="n" id="ac">0</span></div>
    <div id="assets"><div class="empty">No scan yet.<br>
      Run <b>Preflight</b> first, then <b>Scan once</b> (~25s).</div></div>
    <div id="detail"><div class="dh" id="dh"></div><div class="dm" id="dm"></div>
      <svg id="spark" viewBox="0 0 300 42" preserveAspectRatio="none"></svg></div>
  </div>
  <div id="right">
    <div class="sec">Preflight remedies</div>
    <div class="note" id="fixes">Run Preflight to verify the termux bridge.</div>
    <div class="sec">Network</div>
    <div class="note" id="net">—</div>
    <div class="sec">Reality check</div>
    <div class="note" id="limits"></div>
  </div>
</div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<script>
var map = L.map('map',{zoomControl:false,attributionControl:true}).setView([20,0],2);
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',
  {maxZoom:19,attribution:'OpenStreetMap'}).addTo(map);
var meMarker=null, rings=[];

function drawRings(lat,lon,acc){
  rings.forEach(function(r){map.removeLayer(r);}); rings=[];
  [[8,'#ff6b5e'],[20,'#ffb63d'],[45,'#7de3c3']].forEach(function(s){
    rings.push(L.circle([lat,lon],{radius:s[0],color:s[1],weight:1,fill:false,
      dashArray:'3,5',opacity:.55}).addTo(map));
  });
  if(acc) rings.push(L.circle([lat,lon],{radius:acc,color:'#5b9dff',weight:1,
    fill:true,fillOpacity:.05,opacity:.3}).addTo(map));
}
function setMe(loc){
  if(!loc) return;
  if(meMarker) map.removeLayer(meMarker);
  meMarker=L.circleMarker([loc.lat,loc.lon],{radius:5,color:'#7de3c3',
    fillColor:'#7de3c3',fillOpacity:1,weight:2}).addTo(map);
  meMarker.bindPopup('You. GPS accuracy '+(loc.accuracy_m||'?')+'m');
  drawRings(loc.lat,loc.lon,loc.accuracy_m);
  map.setView([loc.lat,loc.lon],18);
}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}

var CAP_ORDER=[['lan','LAN'],['icmp','ICMP'],['arp','ARP'],
  ['wifi_scan','WiFi RSSI'],['gps','GPS'],['bluetooth','BT'],['wake_lock','Wake']];
var STATUS_CLASS={ok:'ok',unverified:'warn',no_binary:'bad',no_apk:'warn',
  no_permission:'warn',location_off:'warn',error:'bad'};

function renderCaps(d){
  var ch=d.checks||{};
  document.getElementById('caps').innerHTML=CAP_ORDER.map(function(p){
    var c=ch[p[0]]||{status:'bad'};
    return '<div class="cap '+(STATUS_CLASS[c.status]||'bad')+'" title="'+
      esc(c.detail||'')+'"><b></b>'+p[1]+'</div>';
  }).join('');

  var fixes=[];
  Object.keys(ch).forEach(function(k){
    var c=ch[k];
    if(c.status!=='ok' && c.remedy){
      fixes.push('<div class="fix"><div class="k">'+esc(k)+' — '+
        esc(c.status)+'</div>'+esc(c.detail||'')+'<br><code>'+
        esc(c.remedy)+'</code></div>');
    }
  });
  document.getElementById('fixes').innerHTML = fixes.length ? fixes.join('') :
    'All probed capabilities responded. Nothing to fix.';

  var sel=document.getElementById('iface');
  var cur=sel.value;
  var ifs=d.interfaces||[];
  sel.innerHTML='<option value="">auto</option>'+ifs.map(function(i){
    return '<option value="'+esc(i.iface)+'">'+esc(i.iface)+' '+esc(i.cidr)+
      (i.is_vpn?' (vpn)':'')+'</option>';
  }).join('');
  if(cur) sel.value=cur;
}

function renderLimits(){
  var h='';
  h+='<b>Cannot count phones.</b> MAC randomization gives unpaired phones a ';
  h+='new random address every few minutes. No honest count exists.<br><br>';
  h+='<b>No position fixes.</b> Indoor RSSI error exceeds a house. You get ';
  h+='proximity buckets and warmer/colder trend, never a pin.<br><br>';
  h+='<b>Rings are indicative.</b> Drawn at your GPS point to scale the ';
  h+='buckets — they do not place any device.<br><br>';
  h+='<b>Needs a cooperative network.</b> Firewalls blocking mDNS/SSDP, or ';
  h+='client isolation on guest WiFi, will hide devices.<br><br>';
  h+='<b>TVs and speakers are the strong case.</b> mDNS TXT records carry ';
  h+='exact model and friendly-name strings.';
  document.getElementById('limits').innerHTML=h;
}

var PXC={'very close':'vc','same room':'sr','nearby':'nb','on-network':'on',
  'far':'fr','fringe':'fr','unknown':'un'};

function renderAssets(a){
  document.getElementById('ac').textContent=a.length;
  var box=document.getElementById('assets');
  if(!a.length){
    box.innerHTML='<div class="empty">Nothing detected.<br>Check the '+
      'preflight remedies panel — an empty WiFi scan almost always means '+
      'Android location services are off.</div>';
    return;
  }
  box.innerHTML=a.map(function(x){
    var px=PXC[x.proximity]||'un';
    var l2=[x.model,x.addr,x.mac].filter(Boolean).join('  ·  ');
    var t='<span class="tag t">'+esc(x.channel)+'</span>';
    t+='<span class="tag">'+esc(x.device_type)+'</span>';
    if(x.is_new) t+='<span class="tag newt">new</span>';
    if(x.rssi!=null) t+='<span class="tag">'+x.rssi+' dBm</span>';
    var hasTxt=(x.evidence||[]).some(function(e){return e.indexOf('txt-')===0;});
    if(hasTxt) t+='<span class="tag txt">txt</span>';
    if(x.trend&&x.trend.trend&&x.trend.trend!=='insufficient'){
      t+='<span class="trend '+x.trend.trend+'">'+x.trend.trend+' '+
        (x.trend.delta>0?'+':'')+x.trend.delta+'</span>';
    }
    return '<div class="row'+(x.is_new?' new':'')+'" data-id="'+esc(x.id)+'">'+
      '<div class="r1"><div class="nm">'+esc(x.name)+'</div>'+
      '<div class="px '+px+'">'+esc(x.proximity)+'</div></div>'+
      (l2?'<div class="r2">'+esc(l2)+'</div>':'')+
      '<div class="r3">'+t+'</div></div>';
  }).join('');
  Array.prototype.forEach.call(box.querySelectorAll('.row'),function(r){
    r.addEventListener('click',function(){showDetail(r.getAttribute('data-id'));});
  });
}

function showDetail(id){
  fetch('/api/track/'+encodeURIComponent(id)).then(function(r){return r.json();})
  .then(function(d){
    document.getElementById('detail').classList.add('show');
    document.getElementById('dh').textContent=id;
    var t=d.trend||{};
    document.getElementById('dm').textContent = t.trend==='insufficient'
      ? 'Not enough RSSI samples yet. Run more scans; LAN assets have no RSSI at all.'
      : 'Signal '+t.trend+' ('+(t.delta>0?'+':'')+t.delta+' dBm over '+
        t.samples+' samples). Walk and rescan — warmer means closer.';
    var pts=(d.history||[]).filter(function(h){return h.rssi!=null;});
    var svg=document.getElementById('spark');
    if(pts.length<2){svg.innerHTML='';return;}
    var v=pts.map(function(p){return p.rssi;});
    var lo=Math.min.apply(null,v),hi=Math.max.apply(null,v),sp=(hi-lo)||1;
    svg.innerHTML='<path d="'+v.map(function(y,i){
      return (i?'L':'M')+((i/(v.length-1))*300).toFixed(1)+' '+
        (38-((y-lo)/sp)*32).toFixed(1);}).join(' ')+
      '" fill="none" stroke="#7de3c3" stroke-width="1.5"/>';
  });
}

function renderNet(s){
  var m=s.lan_meta||{},o=[];
  if(m.error) o.push('<span class="err">'+esc(m.error)+'</span>');
  if(m.chosen_iface) o.push('iface <b>'+esc(m.chosen_iface)+'</b> — '+esc(m.subnet));
  if(m.clamped_from) o.push('<span class="err">prefix '+esc(m.clamped_from)+
    ' too large — clamped to /24</span>');
  if(m.assumed_prefix) o.push('prefix assumed /24 (no iproute2)');
  if(m.vpn_skipped&&m.vpn_skipped.length) o.push('vpn skipped: '+
    esc(m.vpn_skipped.join(', ')));
  if(m.live_hosts!=null) o.push('live '+m.live_hosts+' · arp '+m.arp_entries+
    ' · ssdp '+m.ssdp_responders+' · mdns '+m.mdns_responders+
    ' · txt '+m.txt_records);
  var ce=s.channel_errors||{};
  ['wifi','bluetooth'].forEach(function(k){
    if(ce[k]) o.push('<span class="err">'+k+': '+esc(ce[k])+'</span>');
  });
  if(s.location_error) o.push('<span class="err">gps: '+esc(s.location_error)+'</span>');
  if(s.baseline_size) o.push('baseline '+s.baseline_size+' known');
  if(s.last_error) o.push('<span class="err">'+esc(s.last_error)+'</span>');
  document.getElementById('net').innerHTML=o.join('<br>')||'—';
}

var lastVersion = -1;
function poll(){
  fetch('/api/state').then(function(r){return r.json();}).then(function(s){
    document.getElementById('pip').className='pip'+(s.phase!=='idle'?' on':'');
    document.getElementById('phase').textContent=
      s.phase!=='idle'?('scanning '+s.phase):(s.running?'armed':'idle');
    document.getElementById('lock').className='lock'+(s.wake_lock?' on':'');
    document.getElementById('start').disabled=s.running;
    document.getElementById('stop').disabled=!s.running;
    if(s.location) setMe(s.location);
    renderNet(s);
    if(s.scan_version !== lastVersion){
      lastVersion = s.scan_version;
      fetch('/api/assets').then(function(r){return r.json();})
        .then(function(d){renderAssets(d.assets||[]);});
    }
    schedule(s);
  });
}
var timer=null;
function schedule(s){
  if(timer) clearTimeout(timer);
  var ms = (s && s.phase!=='idle') ? 1500 : ((s && s.running) ? 5000 : 15000);
  timer=setTimeout(poll,ms);
}
function post(u,b){return fetch(u,{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});}

document.getElementById('once').addEventListener('click',function(){
  var b=this;b.disabled=true;b.textContent='Scanning…';
  post('/api/scan/once').then(function(){lastVersion=-1;poll();})
    .finally(function(){b.disabled=false;b.textContent='Scan once';});});
document.getElementById('start').addEventListener('click',function(){
  post('/api/scan/start',{interval:parseInt(document.getElementById('iv').value,10),
    iface:document.getElementById('iface').value}).then(poll);});
document.getElementById('stop').addEventListener('click',function(){
  post('/api/scan/stop').then(poll);});
document.getElementById('iface').addEventListener('change',function(){
  post('/api/iface',{iface:this.value});});
document.getElementById('base').addEventListener('click',function(){
  post('/api/baseline/set').then(function(){lastVersion=-1;poll();});});
document.getElementById('baseclr').addEventListener('click',function(){
  post('/api/baseline/clear').then(function(){lastVersion=-1;poll();});});
document.getElementById('pf').addEventListener('click',function(){
  var b=this;b.disabled=true;b.textContent='Probing…';
  post('/api/preflight/run').then(function(r){return r.json();})
    .then(renderCaps).finally(function(){b.disabled=false;b.textContent='Preflight';});});
document.getElementById('gps').addEventListener('click',function(){
  var b=this;b.disabled=true;b.textContent='Locating…';
  post('/api/location').then(function(r){return r.json();})
    .then(function(d){if(d.location)setMe(d.location);poll();})
    .finally(function(){b.disabled=false;b.textContent='Fix GPS';});});

fetch('/api/preflight').then(function(r){return r.json();}).then(renderCaps);
renderLimits();
poll();
</script>
</body>
</html>
"""

# ----- main -----------------------------------------------------------
def _shutdown(*_):
    wake_lock(False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default=BIND_HOST,
                        help="bind address (default 127.0.0.1; use 0.0.0.0 for remote access)")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    # detect Pydroid3
    if "pydroid" in sys.executable.lower():
        print("\n*** Pydroid3 detected: WiFi RSSI, GPS, Bluetooth will be unavailable.")
        print("*** Only the LAN sweep (pure sockets) will work. This is expected.\n")

    CAPS, PREFLIGHT = preflight(deep=True)   # full preflight at startup
    init_db()

    print("")
    print("  SIGINT v3 — local network & RF asset locator")
    print("  " + "-" * 56)
    for k, label in (("lan", "LAN tier"), ("icmp", "ICMP prefilter"),
                     ("arp", "ARP/iproute"), ("wifi_scan", "WiFi RSSI"),
                     ("gps", "GPS"), ("bluetooth", "Bluetooth"),
                     ("wake_lock", "Wake lock")):
        c = PREFLIGHT.get(k, {})
        print(f"   {label:15} {c.get('status','?'):11} {c.get('detail','')[:44]}")
    ifs = enumerate_interfaces()
    for i in ifs:
        print(f"   iface          {i['iface']:11} {i['cidr']}{'  (vpn)' if i['is_vpn'] else ''}")
    if not ifs:
        print("   iface          none        no IPv4 interface found")
    print("  " + "-" * 56)
    print("   db      " + DB_PATH)
    print(f"   listen  {args.bind}:{args.port}")
    print("   open    termux-open http://localhost:%d" % args.port)
    print("  " + "-" * 56)

    atexit.register(_shutdown)
    app.run(host=args.bind, port=args.port, debug=False,
            use_reloader=False, threaded=True)
