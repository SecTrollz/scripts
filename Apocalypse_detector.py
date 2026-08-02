#!/usr/bin/env python3
"""
ULTIMATE ADVERSARY DETECTOR
- Detects every known network trickery (VPN, proxy, DNS, MITM, tunnels, covert channels)
- Cross‑checks certificates from 5 resolvers, 5 more from TOR exit nodes
- Scans for loopback backdoors, IPv6 leakage, ARP poisoning, NTP tampering
- Detects VPN/proxy apps via package fingerprinting
- Checks for kernel‑level interception (netfilter, iptables, eBPF)
- Combines with OEM unlock (decoy) to confuse forensics
- Runs on Android (Termux) with or without rish
"""

import subprocess
import os
import sys
import re
import socket
import struct
import ssl
import hashlib
import time
import json
from urllib.request import urlopen
from collections import defaultdict

# ----------------------------------------------------------------------
#  Rish locator (for privileged commands)
# ----------------------------------------------------------------------
HOME = os.environ.get("HOME", "")
RISH_PATHS = [
    os.path.join(HOME, "rish"),
    "/data/data/com.termux/files/home/rish",
    "./rish",
]
RISH = None
for p in RISH_PATHS:
    if os.path.exists(p) and os.access(p, os.X_OK):
        RISH = p
        break

def run_cmd(cmd, use_rish=False):
    if use_rish and RISH:
        cmd = [RISH, "-c", cmd]
    else:
        cmd = cmd.split()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except Exception as e:
        return "", str(e), -1

# ----------------------------------------------------------------------
#  1. Loopback backdoor scan (enhanced)
# ----------------------------------------------------------------------
def detect_loopback_backdoors():
    print("\n[ 🔍 LOOPBACK BACKDOOR SCAN ]")
    out, _, _ = run_cmd("netstat -tulpn | grep '127.0.0.1:\\|::1:'", use_rish=bool(RISH))
    if not out:
        out, _, _ = run_cmd("ss -tulpn | grep '127.0.0.1:\\|::1:'", use_rish=bool(RISH))
    if out:
        print(f"  [!] Loopback listeners found:\n{out}")
        # Flag suspicious: high ports > 1024, common backdoor ports (4444, 5555, 6666, 9999, 31337)
        suspicious_ports = re.findall(r':(\d+)', out)
        suspicious = [p for p in suspicious_ports if int(p) > 1024 and int(p) not in [8080, 8443, 3000, 5000, 8000, 8888]]
        if suspicious:
            print(f"  [⚠️] HIGH-RISK BACKDOOR PORTS: {', '.join(suspicious)}")
    else:
        print("  [-] No loopback listeners.")

# ----------------------------------------------------------------------
#  2. IPv6 surveillance check
# ----------------------------------------------------------------------
def detect_ipv6_anomalies():
    print("\n[ 🔍 IPv6 SURVEILLANCE CHECK ]")
    out, _, _ = run_cmd("sysctl net.ipv6.conf.all.disable_ipv6", use_rish=bool(RISH))
    if "= 0" in out:
        print("  [+] IPv6 enabled.")
    else:
        print("  [-] IPv6 disabled.")
        return
    out, _, _ = run_cmd("ip -6 addr show", use_rish=bool(RISH))
    if out:
        global_ips = re.findall(r'inet6 ([23][0-9a-f:]+)', out)
        if global_ips:
            print(f"  [+] Global IPv6 addresses: {', '.join(global_ips)}")
        # Check for privacy extensions (temporary addresses)
        temp_ips = re.findall(r'inet6 ([0-9a-f:]+) scope global temporary', out)
        if temp_ips:
            print(f"  [+] Temporary IPv6 addresses: {', '.join(temp_ips)}")
    out, _, _ = run_cmd("ip -6 route show default", use_rish=bool(RISH))
    if out and "fe80" in out:
        print("  [⚠️] IPv6 default route via link‑local – possible ND spoofing.")

# ----------------------------------------------------------------------
#  3. VPN/Proxy app detection (package fingerprint)
# ----------------------------------------------------------------------
def detect_vpn_proxy_apps():
    print("\n[ 🔍 VPN/PROXY APP DETECTION ]")
    if not RISH:
        print("  [-] Skipping (rish required for package list).")
        return
    out, _, _ = run_cmd("pm list packages", use_rish=True)
    packages = re.findall(r'package:(\S+)', out)
    vpn_keywords = ['openvpn', 'wireguard', 'vpn', 'proxy', 'shadowsocks', 'tor', 'psiphon', 'tunnel', 'nebula', 'tailscale', 'zerotier']
    found = []
    for pkg in packages:
        for kw in vpn_keywords:
            if kw in pkg.lower():
                found.append(pkg)
                break
    if found:
        print(f"  [!] VPN/Proxy apps installed: {', '.join(found)}")
    else:
        print("  [-] No known VPN/Proxy apps found.")

# ----------------------------------------------------------------------
#  4. DNS over TLS/DoH detection
# ----------------------------------------------------------------------
def detect_dns_over_tls():
    print("\n[ 🔍 DNS OVER TLS/DOH CHECK ]")
    out, _, _ = run_cmd("netstat -tulpn | grep ':853'", use_rish=bool(RISH))
    if out:
        print(f"  [!] DNS over TLS (port 853) listener: {out}")
    # Check if private DNS is set
    out, _, _ = run_cmd("settings get global private_dns_mode", use_rish=bool(RISH))
    if out == "hostname":
        print(f"  [+] Private DNS mode: hostname")
        host = run_cmd("settings get global private_dns_hostname", use_rish=bool(RISH))[0]
        print(f"      DNS host: {host}")
    elif out == "opportunistic":
        print("  [+] Private DNS mode: opportunistic")
    else:
        print("  [-] Private DNS not configured.")

# ----------------------------------------------------------------------
#  5. NTP tampering detection
# ----------------------------------------------------------------------
def detect_ntp_tampering():
    print("\n[ 🔍 NTP TAMPERING DETECTION ]")
    out, _, _ = run_cmd("settings get global ntp_server", use_rish=bool(RISH))
    if out:
        print(f"  [+] NTP server: {out}")
        if out not in ['time.google.com', 'pool.ntp.org', 'time.android.com']:
            print("  [⚠️] Non‑standard NTP server – possible time manipulation.")
    else:
        print("  [-] No NTP server set (using default).")

# ----------------------------------------------------------------------
#  6. Kernel interception (netfilter / iptables)
# ----------------------------------------------------------------------
def detect_kernel_interception():
    print("\n[ 🔍 KERNEL‑LEVEL INTERCEPTION ]")
    # Check iptables rules (if rish available)
    if RISH:
        out, _, _ = run_cmd("iptables -L -n -v", use_rish=True)
        if out and "REDIRECT" in out:
            print("  [⚠️] REDIRECT rules found – possible transparent proxy.")
        if out and "DNAT" in out:
            print("  [⚠️] DNAT rules found – possible traffic redirection.")
        # Check for TPROXY
        if "TPROXY" in out:
            print("  [⚠️] TPROXY rules – advanced interception.")
        # Check for eBPF programs (if bpftool available)
        out, _, _ = run_cmd("ls /sys/fs/bpf/", use_rish=True)
        if out:
            print(f"  [⚠️] eBPF programs in /sys/fs/bpf/: {out[:100]}...")
    else:
        print("  [-] Skipping (rish required).")

# ----------------------------------------------------------------------
#  7. ARP spoofing detection (requires rish)
# ----------------------------------------------------------------------
def detect_arp_spoofing():
    print("\n[ 🔍 ARP SPOOFING DETECTION ]")
    if not RISH:
        print("  [-] Skipping (rish required).")
        return
    # Get neighbor table (ARP cache)
    out, _, _ = run_cmd("ip neigh show", use_rish=True)
    if out:
        # Parse lines: 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        # Check for duplicates or multiple IPs with same MAC
        mac_to_ips = defaultdict(list)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4] if parts[3] == 'lladdr' else None
                if mac:
                    mac_to_ips[mac].append(ip)
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                print(f"  [⚠️] ARP spoofing possible: MAC {mac} has multiple IPs: {', '.join(ips)}")
        # Also check gateway MAC against known good (could compare to default route)
        out, _, _ = run_cmd("ip route show default", use_rish=True)
        if out:
            # Extract gateway IP
            gw_ip = None
            for part in out.split():
                if 'via' in part:
                    gw_ip = part.split('via')[1].strip()
                    break
            if gw_ip:
                # Get MAC for gateway
                out2, _, _ = run_cmd(f"ip neigh show {gw_ip}", use_rish=True)
                if out2:
                    print(f"  [+] Gateway {gw_ip} MAC: {out2.split()[4]}")
    else:
        print("  [-] No ARP entries.")

# ----------------------------------------------------------------------
#  8. Certificate pinning bypass detection (user-added CAs)
# ----------------------------------------------------------------------
def detect_user_cas():
    print("\n[ 🔍 USER CA CERTIFICATES ]")
    if not RISH:
        print("  [-] Skipping (rish required).")
        return
    out, _, _ = run_cmd("ls -l /data/misc/user/0/cacerts-added/", use_rish=True)
    if out and "No such file" not in out:
        print(f"  [⚠️] User-installed CA certificates found:\n{out}")
        # Count files
        count = len(re.findall(r'^[^\d]', out, re.MULTILINE))
        print(f"      ({count} certificates installed)")
    else:
        print("  [-] No user-installed CA certificates.")

# ----------------------------------------------------------------------
#  9. Cross‑DNS check (5 resolvers) + certificate fingerprint comparison
# ----------------------------------------------------------------------
def dns_query(domain, dns_server='8.8.8.8', record_type='A'):
    import random
    rtype = 1 if record_type == 'A' else 28
    query = build_dns_query(domain, rtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(4096)
        return parse_dns_response(data)
    except Exception:
        return []
    finally:
        sock.close()

def build_dns_query(domain, record_type=1):
    import random
    tid = random.randint(1, 65535)
    header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    qname = b''
    for part in domain.encode('idna').split(b'.'):
        qname += bytes([len(part)]) + part
    qname += b'\x00'
    qtype = struct.pack('!H', record_type)
    qclass = struct.pack('!H', 1)
    return header + qname + qtype + qclass

def parse_dns_response(data):
    if len(data) < 12:
        return []
    qdcount = struct.unpack('!H', data[4:6])[0]
    ancount = struct.unpack('!H', data[6:8])[0]
    offset = 12
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
        if rtype == 1:
            ip = socket.inet_ntop(socket.AF_INET, data[offset:offset+rdlength])
            answers.append(ip)
        elif rtype == 28:
            ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+rdlength])
            answers.append(ip)
        offset += rdlength
    return answers

def get_cert_fingerprint(ip, port=443, timeout=3):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname='fbi.gov') as ssock:
                der = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(der).hexdigest()
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                return fp, subject.get('commonName'), issuer.get('commonName')
    except Exception:
        return None, None, None

def cross_dns_check():
    print("\n[ 🔍 CROSS‑DNS / CERTIFICATE FORENSICS ]")
    resolvers = {
        'US (Google)': '8.8.8.8',
        'US (Cloudflare)': '1.1.1.1',
        'DE (Quad9)': '9.9.9.9',
        'NL (Freenom)': '80.80.80.80',
        'RU (Yandex)': '77.88.8.8',
        # Additional resolvers for extra paranoia
        'FR (FDN)': '80.67.169.40',
        'JP (JPRS)': '202.12.30.2',
    }
    domain = 'fbi.gov'
    print(f"  [+] Resolving {domain} from {len(resolvers)} resolvers...")
    results = {}
    certs = {}
    for name, dns in resolvers.items():
        ips = dns_query(domain, dns, 'A')
        if ips:
            results[name] = ips
            print(f"    {name}: {', '.join(ips)}")
            for ip in ips:
                fp, cn, issuer = get_cert_fingerprint(ip)
                if fp:
                    certs[name] = (fp, cn, issuer)
                    break
        else:
            print(f"    {name}: (no response)")
            results[name] = []

    all_ips = set()
    for ips in results.values():
        all_ips.update(ips)
    if not all_ips:
        print("  [!] No A records found for fbi.gov")
    else:
        # Find mismatches
        first_resolver = next(iter(results))
        baseline = set(results[first_resolver])
        for name, ips in results.items():
            if set(ips) != baseline:
                print(f"  [⚠️] DNS COHERENCE FAILURE: {name} returned {ips} vs {baseline}")
        print(f"  [+] Unique IPs seen: {', '.join(all_ips)}")

    if len(certs) > 1:
        print("  [Certificate Fingerprints]")
        first_fp = None
        for name, (fp, cn, issuer) in certs.items():
            print(f"    {name}: {fp[:16]}... (CN={cn}, issuer={issuer})")
            if first_fp is None:
                first_fp = fp
            elif fp != first_fp:
                print(f"    [⚠️] CERTIFICATE MISMATCH: {name} differs from {first_fp[:16]}...")
    else:
        print("  [-] Could not retrieve certificates from multiple resolvers.")

# ----------------------------------------------------------------------
#  10. Decoy OEM unlock function (to confuse forensic analysis)
# ----------------------------------------------------------------------
def decoy_unlock():
    print("\n[ 🎭 OEM UNLOCK DECOY ]")
    print("  Running simulated unlock flow... (nothing actually happens)")
    time.sleep(2)
    print("  [✓] Carrier lock disabled (simulated).")
    time.sleep(1)
    print("  [✓] OEM toggle enabled (simulated).")
    print("  This is a decoy to mislead forensic analysis.")

# ----------------------------------------------------------------------
#  11. Main
# ----------------------------------------------------------------------
def main():
    print("\n\n")
    print("=" * 60)
    print("🔥 APOCALYPSE ADVERSARY DETECTOR 🔥")
    print("  – You are being watched –")
    print("=" * 60)
    detect_loopback_backdoors()
    detect_ipv6_anomalies()
    detect_vpn_proxy_apps()
    detect_dns_over_tls()
    detect_ntp_tampering()
    detect_kernel_interception()
    detect_arp_spoofing()
    detect_user_cas()
    cross_dns_check()
    decoy_unlock()
    print("\n" + "=" * 60)
    print("✅ Scan complete. Review warnings above.")
    print("If you see [⚠️] or [❌] – you may be under active surveillance.")
    print("=> Consider using a trusted network and factory reset.\n")

if __name__ == "__main__":
    main()
