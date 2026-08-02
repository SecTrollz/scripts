#!/usr/bin/env python3
"""
APOCALYPSE DETECTOR 2026 – ROOT EDITION
- Runs as root (no rish needed) for full system access.
- Scans for backdoors, IPv6 leaks, VPN/proxy apps, DNS tampering, kernel hooks, ARP spoofing, and user CAs.
- Cross‑checks DNS & TLS certificates for 20+ high‑value domains (banking, gov, tech, social).
- Detects suspicious kernel modules and processes.
- Includes a decoy OEM unlock routine.
- Pure Python, no external libs.
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
from collections import defaultdict

# ----------------------------------------------------------------------
#  We assume we are running as root. Check UID.
# ----------------------------------------------------------------------
if os.geteuid() != 0:
    print("[!] This script must be run as root. Use: su -c 'python apocalypse_detector_root_2026.py'")
    sys.exit(1)

def run_cmd(cmd):
    """Run a shell command and return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except Exception as e:
        return "", str(e), -1

# ----------------------------------------------------------------------
#  1. Loopback backdoor scan (root can see processes)
# ----------------------------------------------------------------------
def detect_loopback_backdoors():
    print("\n[ 🔍 LOOPBACK BACKDOOR SCAN ]")
    # Use netstat/ss to list all listeners on 127.0.0.1 and ::1
    out, _, _ = run_cmd("netstat -tulpn 2>/dev/null | grep '127.0.0.1:\\|::1:'")
    if not out:
        out, _, _ = run_cmd("ss -tulpn 2>/dev/null | grep '127.0.0.1:\\|::1:'")
    if out:
        print(f"  [!] Loopback listeners found:\n{out}")
        # Extract ports and PIDs to spot suspicious ones
        suspicious_ports = re.findall(r':(\d+)\s+.*LISTEN\s+(\d+)/', out)
        for port, pid in suspicious_ports:
            if int(port) > 1024 and int(port) not in [8080, 8443, 3000, 5000, 8000, 8888]:
                # Check process name
                proc_name = run_cmd(f"ps -p {pid} -o comm=")[0].strip()
                print(f"  [⚠️] Suspicious listener: port {port} (PID {pid}, {proc_name})")
    else:
        print("  [-] No loopback listeners.")

# ----------------------------------------------------------------------
#  2. IPv6 surveillance check (enhanced)
# ----------------------------------------------------------------------
def detect_ipv6_anomalies():
    print("\n[ 🔍 IPv6 SURVEILLANCE CHECK ]")
    out, _, _ = run_cmd("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    if "= 0" in out:
        print("  [+] IPv6 enabled.")
    else:
        print("  [-] IPv6 disabled.")
        return
    # List IPv6 addresses
    out, _, _ = run_cmd("ip -6 addr show")
    if out:
        global_ips = re.findall(r'inet6 ([23][0-9a-f:]+)', out)
        if global_ips:
            print(f"  [+] Global IPv6 addresses: {', '.join(global_ips)}")
        temp_ips = re.findall(r'inet6 ([0-9a-f:]+) scope global temporary', out)
        if temp_ips:
            print(f"  [+] Temporary IPv6 addresses: {', '.join(temp_ips)}")
    out, _, _ = run_cmd("ip -6 route show default")
    if out and "fe80" in out:
        print("  [⚠️] IPv6 default route via link‑local – potential ND spoofing.")

# ----------------------------------------------------------------------
#  3. VPN/Proxy app detection (root can see all packages)
# ----------------------------------------------------------------------
def detect_vpn_proxy_apps():
    print("\n[ 🔍 VPN/PROXY APP DETECTION ]")
    out, _, _ = run_cmd("pm list packages")
    packages = re.findall(r'package:(\S+)', out)
    vpn_keywords = [
        'openvpn', 'wireguard', 'vpn', 'proxy', 'shadowsocks', 'tor', 'psiphon',
        'tunnel', 'nebula', 'tailscale', 'zerotier', 'mullvad', 'protonvpn',
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'vyprvpn',
        'privateinternetaccess', 'ivpn', 'airvpn', 'windscribe', 'torguard',
        '1.1.1.1', 'warp', 'cloudflare', 'secure', 'privacy', 'anonym',
        'obfuscated', 'bridge', 'socks', 'http', 'tls', 'dns', 'adguard'
    ]
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
#  4. DNS over TLS/DoH/DoQ detection (root sees all listeners)
# ----------------------------------------------------------------------
def detect_dns_over_tls():
    print("\n[ 🔍 DNS OVER TLS/DOH/DOQ CHECK ]")
    out, _, _ = run_cmd("netstat -tulpn 2>/dev/null | grep ':853'")
    if out:
        print(f"  [!] DNS over TLS (port 853) listener: {out}")
    out, _, _ = run_cmd("netstat -tulpn 2>/dev/null | grep ':443' | grep -v LISTEN")
    if out:
        # Could be DoH/DoQ – we can't be sure, but flag it.
        print(f"  [!] Potential DoH/DoQ traffic on port 443:\n{out[:200]}")
    # Private DNS mode
    out, _, _ = run_cmd("settings get global private_dns_mode")
    if out == "hostname":
        host = run_cmd("settings get global private_dns_hostname")[0]
        print(f"  [+] Private DNS host: {host}")
    elif out == "opportunistic":
        print("  [+] Private DNS mode: opportunistic")
    else:
        print("  [-] Private DNS not configured.")

# ----------------------------------------------------------------------
#  5. NTP tampering detection
# ----------------------------------------------------------------------
def detect_ntp_tampering():
    print("\n[ 🔍 NTP TAMPERING DETECTION ]")
    out, _, _ = run_cmd("settings get global ntp_server")
    if out:
        print(f"  [+] NTP server: {out}")
        if out not in ['time.google.com', 'pool.ntp.org', 'time.android.com']:
            print("  [⚠️] Non‑standard NTP server – possible time manipulation.")
    else:
        print("  [-] No NTP server set (using default).")

# ----------------------------------------------------------------------
#  6. Kernel‑level interception (root can read iptables, eBPF, modules)
# ----------------------------------------------------------------------
def detect_kernel_interception():
    print("\n[ 🔍 KERNEL‑LEVEL INTERCEPTION ]")
    # iptables rules
    out, _, _ = run_cmd("iptables -L -n -v")
    if "REDIRECT" in out:
        print("  [⚠️] REDIRECT rules – transparent proxy.")
    if "DNAT" in out:
        print("  [⚠️] DNAT rules – traffic redirection.")
    if "TPROXY" in out:
        print("  [⚠️] TPROXY rules – advanced interception.")
    # eBPF programs
    out, _, _ = run_cmd("ls /sys/fs/bpf/ 2>/dev/null")
    if out:
        print(f"  [⚠️] eBPF programs in /sys/fs/bpf/: {out[:100]}...")
    out, _, _ = run_cmd("ls /sys/fs/bpf/xdp/ 2>/dev/null")
    if out:
        print(f"  [⚠️] XDP programs detected: {out}")
    # Suspicious kernel modules
    out, _, _ = run_cmd("lsmod | grep -E 'hid|vpn|tunnel|proxy|hook'")
    if out:
        print(f"  [⚠️] Suspicious kernel modules loaded:\n{out}")

# ----------------------------------------------------------------------
#  7. ARP spoofing detection (root sees all neighbours)
# ----------------------------------------------------------------------
def detect_arp_spoofing():
    print("\n[ 🔍 ARP SPOOFING DETECTION ]")
    out, _, _ = run_cmd("ip neigh show")
    if out:
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
                print(f"  [⚠️] ARP spoofing: MAC {mac} has multiple IPs: {', '.join(ips)}")
        # Gateway MAC check
        out2, _, _ = run_cmd("ip route show default")
        if out2:
            gw_ip = None
            for part in out2.split():
                if 'via' in part:
                    gw_ip = part.split('via')[1].strip()
                    break
            if gw_ip:
                out3, _, _ = run_cmd(f"ip neigh show {gw_ip}")
                if out3:
                    print(f"  [+] Gateway {gw_ip} MAC: {out3.split()[4]}")
    else:
        print("  [-] No ARP entries.")

# ----------------------------------------------------------------------
#  8. User CA certificates (MITM detection)
# ----------------------------------------------------------------------
def detect_user_cas():
    print("\n[ 🔍 USER CA CERTIFICATES ]")
    out, _, _ = run_cmd("ls -l /data/misc/user/0/cacerts-added/ 2>/dev/null")
    if out and "No such file" not in out:
        print(f"  [⚠️] User-installed CA certificates found:\n{out}")
        count = len(re.findall(r'^[^\d]', out, re.MULTILINE))
        print(f"      ({count} certificates installed)")
    else:
        print("  [-] No user-installed CA certificates.")

# ----------------------------------------------------------------------
#  9. Suspicious processes (rootkit-like)
# ----------------------------------------------------------------------
def detect_suspicious_processes():
    print("\n[ 🔍 SUSPICIOUS PROCESSES ]")
    out, _, _ = run_cmd("ps -A -o pid,comm,args | grep -E 'nc|netcat|socat|nmap|tcpdump|tcpflow|ettercap|arpspoof|dsniff|sslstrip|mitmproxy|burp|zap|frida|xposed|magisk' | grep -v grep")
    if out:
        print(f"  [⚠️] Suspicious processes found:\n{out}")

# ----------------------------------------------------------------------
#  10. Cross‑DNS + TLS certificate validation (20+ high‑value domains)
# ----------------------------------------------------------------------
def dns_query(domain, dns_server='8.8.8.8', record_type='A'):
    import random
    rtype = 1 if record_type == 'A' else 28
    tid = random.randint(1, 65535)
    header = struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    qname = b''
    for part in domain.encode('idna').split(b'.'):
        qname += bytes([len(part)]) + part
    qname += b'\x00'
    qtype = struct.pack('!H', rtype)
    qclass = struct.pack('!H', 1)
    query = header + qname + qtype + qclass
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

def get_cert_fingerprint(ip, port=443, hostname='fbi.gov', timeout=3):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
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
        'FR (FDN)': '80.67.169.40',
        'JP (JPRS)': '202.12.30.2',
        'AU (Telstra)': '203.0.178.191',
    }
    # High‑value domains: banks, gov, tech, social, cloud, etc.
    domains = [
        'fbi.gov', 'usa.gov', 'whitehouse.gov', 'state.gov', 'nsa.gov',
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'github.com', 'gitlab.com', 'cloudflare.com',
        'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
        'paypal.com', 'venmo.com', 'square.com',
        'googlevideo.com', 'youtube.com', 'netflix.com',
        'spotify.com', 'whatsapp.net',
    ]
    for domain in domains:
        print(f"\n  [*] Domain: {domain}")
        results = {}
        certs = {}
        for name, dns in resolvers.items():
            ips = dns_query(domain, dns, 'A')
            if ips:
                results[name] = ips
                print(f"    {name}: {', '.join(ips)}")
                # Get cert from first IP
                for ip in ips:
                    fp, cn, issuer = get_cert_fingerprint(ip, hostname=domain)
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
            print("    [!] No A records for this domain.")
            continue
        # Check for DNS incoherence
        first_resolver = next(iter(results))
        baseline = set(results[first_resolver])
        for name, ips in results.items():
            if set(ips) != baseline:
                print(f"    [⚠️] DNS INCOHERENCE: {name} returned {ips} vs {baseline}")

        # Certificate fingerprint comparison
        if len(certs) > 1:
            first_fp = None
            for name, (fp, cn, issuer) in certs.items():
                if first_fp is None:
                    first_fp = fp
                elif fp != first_fp:
                    print(f"    [⚠️] CERT MISMATCH: {name} differs from {first_fp[:16]}...")
        else:
            print("    [-] Certificate retrieval limited.")

# ----------------------------------------------------------------------
#  11. Decoy OEM unlock routine
# ----------------------------------------------------------------------
def decoy_unlock():
    print("\n[ 🎭 OEM UNLOCK DECOY ]")
    print("  Simulating OEM unlock flow (advanced deception)...")
    time.sleep(2)
    print("  [✓] Carrier lock bypassed (simulated).")
    time.sleep(1)
    print("  [✓] OEM toggle enabled (simulated).")
    time.sleep(1)
    print("  [✓] Bootloader ready for unlock (simulated).")
    print("  This decoy misdirects forensic analysis.")

# ----------------------------------------------------------------------
#  12. Main
# ----------------------------------------------------------------------
def main():
    print("\n\n")
    print("=" * 70)
    print("🔥 APOCALYPSE DETECTOR 2026 – ROOT EDITION 🔥")
    print("  – For the modern threat landscape –")
    print("=" * 70)
    detect_loopback_backdoors()
    detect_ipv6_anomalies()
    detect_vpn_proxy_apps()
    detect_dns_over_tls()
    detect_ntp_tampering()
    detect_kernel_interception()
    detect_arp_spoofing()
    detect_user_cas()
    detect_suspicious_processes()
    cross_dns_check()
    decoy_unlock()
    print("\n" + "=" * 70)
    print("✅ Scan complete. Review warnings above.")
    print("If you see [⚠️], you may be under active surveillance.")
    print("=> Consider using a trusted network and factory reset.\n")

if __name__ == "__main__":
    main()
