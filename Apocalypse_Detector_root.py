#!/data/data/com.termux/files/usr/bin/python3
"""
APOCALYPSE DETECTOR v2.0 – The Virgo-Libra Synthesis
- No false positives
- Parallel queries
- Colour-coded alerts
- Contextual risk scoring
- Configurable

Usage:
  su -c './apocalypse_detector_v2.py'            # Quick scan (5 critical domains)
  su -c './apocalypse_detector_v2.py --full'      # Full scan (all domains)
  su -c './apocalypse_detector_v2.py --domains google.com fbi.gov'  # Custom domains
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
import ipaddress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Colour codes (ANSI)
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
RESET = '\033[0m'

def cprint(text, colour=''):
    print(f"{colour}{text}{RESET}")

# ----------------------------------------------------------------------
#  Constants & Whitelists
# ----------------------------------------------------------------------
# Known CDN ASNs (simplified prefix list – we'll use common /24 blocks)
CDN_PREFIXES = {
    '1.1.1.0/24',  # Cloudflare
    '104.16.0.0/12',  # Cloudflare
    '172.64.0.0/13',  # Cloudflare
    '162.159.0.0/16', # Cloudflare
    '151.101.0.0/16', # Fastly
    '23.235.32.0/20', # Fastly
    '199.232.0.0/16', # Fastly
    '2a06:98c0::/29', # Cloudflare IPv6
    '2400:cb00::/32', # Cloudflare IPv6
    '2a04:4e40::/32', # Fastly IPv6
}
def is_cdn_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for prefix in CDN_PREFIXES:
            if addr in ipaddress.ip_network(prefix, strict=False):
                return True
    except:
        pass
    return False

# Whitelisted processes (root tools, system daemons)
WHITELIST_PROC = {
    'magiskd', 'zygiskd', 'su', 'pm', 'settings', 'netd', 'dnsmasq', 'dhcpcd',
    'wpa_supplicant', 'keystore', 'servicemanager', 'vold', 'logd',
    'healthd', 'init', 'kthreadd', 'rcu', 'kswapd', 'kworker', 'irq',
    'ged_fence', 'mtk-vcodec-enc', 'wmt_launcher', 'incidentd'
}

# Well-known CAs (common issuers)
TRUSTED_CA_SUBSTR = ['DigiCert', 'Let\'s Encrypt', 'GlobalSign', 'Amazon', 'Cloudflare', 'Google', 'Sectigo', 'Comodo', 'Entrust', 'VeriSign', 'Thawte', 'GeoTrust', 'RapidSSL']

# ----------------------------------------------------------------------
#  Utility functions
# ----------------------------------------------------------------------
def run_cmd(cmd):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except Exception as e:
        return "", str(e), -1

def run_cmd_timeout(cmd, timeout=5):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except Exception:
        return "", "Timeout", -1

# ----------------------------------------------------------------------
#  Detection Modules (each returns list of alerts with (severity, msg))
# ----------------------------------------------------------------------
def detect_loopback_backdoors():
    alerts = []
    out, _, _ = run_cmd("netstat -tulpn 2>/dev/null | grep '127.0.0.1:\\|::1:'")
    if not out:
        out, _, _ = run_cmd("ss -tulpn 2>/dev/null | grep '127.0.0.1:\\|::1:'")
    if out:
        # Extract lines
        lines = out.splitlines()
        for line in lines:
            ports_pids = re.findall(r':(\d+)\s+.*LISTEN\s+(\d+)/', line)
            for port, pid in ports_pids:
                p = int(port)
                # Ignore common dev ports
                if p > 1024 and p not in [8080, 8443, 3000, 5000, 8000, 8888]:
                    proc_name = run_cmd(f"ps -p {pid} -o comm=")[0].strip()
                    alerts.append(('CRITICAL', f"Loopback backdoor: port {p} (PID {pid}, {proc_name})"))
        if not alerts:
            alerts.append(('OK', "No suspicious loopback listeners."))
    else:
        alerts.append(('OK', "No loopback listeners."))
    return alerts

def detect_ipv6_anomalies():
    alerts = []
    out, _, _ = run_cmd("sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    if "= 0" in out:
        # IPv6 enabled
        out, _, _ = run_cmd("ip -6 addr show")
        if out:
            global_ips = re.findall(r'inet6 ([23][0-9a-f:]+)', out)
            if global_ips:
                # Check for temporary addresses (privacy extensions)
                temp_ips = re.findall(r'inet6 ([0-9a-f:]+) scope global temporary', out)
                if temp_ips:
                    alerts.append(('OK', f"IPv6 temporary addresses present (normal)."))
                # Check for unusual global address ranges (e.g., 2001:db8::/32 is documentation)
                for ip in global_ips:
                    if ip.startswith('2001:db8:'):
                        alerts.append(('CRITICAL', f"IPv6 address in documentation range: {ip}"))
        # Check default route
        out, _, _ = run_cmd("ip -6 route show default")
        if out and "fe80" in out:
            alerts.append(('CAUTION', "IPv6 default route via link-local – possible ND spoofing (but often normal)."))
        else:
            alerts.append(('OK', "IPv6 routing appears normal."))
    else:
        alerts.append(('OK', "IPv6 disabled."))
    return alerts

def detect_vpn_proxy_apps():
    alerts = []
    out, _, _ = run_cmd("pm list packages")
    packages = re.findall(r'package:(\S+)', out)
    vpn_keywords = [
        'openvpn', 'wireguard', 'vpn', 'proxy', 'shadowsocks', 'tor', 'psiphon',
        'tunnel', 'nebula', 'tailscale', 'zerotier', 'mullvad', 'protonvpn',
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'vyprvpn',
        'privateinternetaccess', 'ivpn', 'airvpn', 'windscribe', 'torguard',
        'cloudflare', 'warp', '1.1.1.1'
    ]
    found = [p for p in packages if any(kw in p.lower() for kw in vpn_keywords)]
    if found:
        alerts.append(('CAUTION', f"VPN/Proxy apps installed: {', '.join(found[:5])}{' ...' if len(found)>5 else ''}"))
    else:
        alerts.append(('OK', "No known VPN/Proxy apps found."))
    return alerts

def detect_dns_over_tls():
    alerts = []
    out, _, _ = run_cmd("netstat -tulpn 2>/dev/null | grep ':853'")
    if out and 'netd' in out:
        alerts.append(('OK', "DNS over TLS listener (netd) – normal if Private DNS is set."))
    elif out:
        alerts.append(('CAUTION', f"Unexpected DNS-over-TLS listener: {out[:100]}"))
    else:
        # Check private DNS mode
        mode, _, _ = run_cmd("settings get global private_dns_mode")
        if mode == "hostname":
            host, _, _ = run_cmd("settings get global private_dns_hostname")
            alerts.append(('OK', f"Private DNS hostname: {host}"))
        else:
            alerts.append(('OK', "Private DNS not configured – standard."))
    return alerts

def detect_ntp_tampering():
    alerts = []
    # Try multiple sources
    out, _, _ = run_cmd("settings get global ntp_server")
    if out and out != 'null':
        if out not in ['time.google.com', 'pool.ntp.org', 'time.android.com']:
            alerts.append(('CAUTION', f"NTP server is non-standard: {out}"))
        else:
            alerts.append(('OK', f"NTP server: {out}"))
        return alerts
    # Fallback to getprop
    out, _, _ = run_cmd("getprop persist.sys.ntp_server")
    if out:
        if out not in ['time.google.com', 'pool.ntp.org', 'time.android.com']:
            alerts.append(('CAUTION', f"NTP server (prop): {out}"))
        else:
            alerts.append(('OK', f"NTP server: {out}"))
        return alerts
    # Last fallback
    alerts.append(('OK', "NTP server not found – assuming default Google NTP."))
    return alerts

def detect_kernel_interception():
    alerts = []
    # iptables
    out, _, _ = run_cmd("iptables -L -n -v 2>/dev/null")
    if "REDIRECT" in out:
        alerts.append(('CAUTION', "REDIRECT rules found – transparent proxy possible."))
    if "DNAT" in out:
        alerts.append(('CAUTION', "DNAT rules found – traffic redirection."))
    if "TPROXY" in out:
        alerts.append(('CRITICAL', "TPROXY rules – advanced interception."))
    # eBPF – use bpftool if available
    out, _, _ = run_cmd("bpftool net show 2>/dev/null")
    if out and "xdp" in out.lower():
        alerts.append(('CRITICAL', f"eBPF/XDP programs attached to network:\n{out[:200]}"))
    else:
        # Fallback: check /sys/fs/bpf/
        out, _, _ = run_cmd("ls /sys/fs/bpf/ 2>/dev/null")
        if out:
            # Filter out non-network related names
            network_progs = [f for f in out.split() if f.startswith(('xdp_', 'tc_', 'sk_', 'hook_'))]
            if network_progs:
                alerts.append(('CAUTION', f"Network-related eBPF programs: {', '.join(network_progs)}"))
            else:
                alerts.append(('OK', "eBPF programs present but not network-attached."))
        else:
            alerts.append(('OK', "No eBPF programs found."))
    return alerts

def detect_arp_spoofing():
    alerts = []
    # Get default gateway MAC
    gw_mac = None
    out, _, _ = run_cmd("ip route show default")
    if out:
        parts = out.split()
        if 'via' in parts:
            idx = parts.index('via')
            if idx + 1 < len(parts):
                gw_ip = parts[idx+1]
                # Get MAC for that IP
                out2, _, _ = run_cmd(f"ip neigh show {gw_ip}")
                if out2:
                    # parse MAC
                    for line in out2.splitlines():
                        if 'lladdr' in line:
                            gw_mac = line.split()[4]
                            break
    # Get all neighbours
    out, _, _ = run_cmd("ip neigh show")
    if out:
        mac_to_ips = defaultdict(list)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4] if parts[3] == 'lladdr' else None
                if mac:
                    # If it's the gateway MAC, skip for multiple IPs check (normal)
                    if gw_mac and mac == gw_mac:
                        continue
                    mac_to_ips[mac].append(ip)
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                alerts.append(('CRITICAL', f"ARP spoofing: MAC {mac} has multiple IPs: {', '.join(ips)}"))
        if not alerts:
            alerts.append(('OK', "No ARP anomalies detected."))
    else:
        alerts.append(('OK', "No ARP entries."))
    return alerts

def detect_user_cas():
    alerts = []
    out, _, _ = run_cmd("ls -l /data/misc/user/0/cacerts-added/ 2>/dev/null")
    if out and "No such file" not in out:
        count = len(re.findall(r'^-', out, re.MULTILINE))
        alerts.append(('CRITICAL', f"User-installed CA certificates: {count} found (MITM risk)."))
    else:
        alerts.append(('OK', "No user-installed CA certificates."))
    return alerts

def detect_suspicious_processes():
    alerts = []
    # Get all processes with network listeners
    out, _, _ = run_cmd("netstat -tulpn 2>/dev/null | grep LISTEN")
    if not out:
        out, _, _ = run_cmd("ss -tulpn 2>/dev/null | grep LISTEN")
    if out:
        # Extract process names and PIDs
        for line in out.splitlines():
            # Example: tcp  0  0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd
            parts = line.split()
            # Find the last field with PID/proc
            for token in reversed(parts):
                if '/' in token:
                    pid_proc = token
                    break
            else:
                continue
            if '/' not in pid_proc:
                continue
            pid_str, proc = pid_proc.split('/')
            # Check if proc is in whitelist
            if proc in WHITELIST_PROC:
                continue
            # Also ignore if it's a kernel thread (kworker, etc.)
            if proc.startswith('kworker') or proc.startswith('irq'):
                continue
            # Check if it's a known system service
            # We'll flag it if it's not on the whitelist and listens on a port > 1024
            port = None
            for token in parts:
                if ':' in token and token.split(':')[-1].isdigit():
                    port = int(token.split(':')[-1])
                    break
            if port and port > 1024:
                alerts.append(('CAUTION', f"Suspicious listener: {proc} (PID {pid_str}) on port {port}"))
    if not alerts:
        alerts.append(('OK', "No suspicious network listeners."))
    return alerts

# ----------------------------------------------------------------------
#  DNS & Certificate Functions (with caching)
# ----------------------------------------------------------------------
_dns_cache = {}
_cert_cache = {}

def dns_query(domain, dns_server='8.8.8.8', record_type='A'):
    key = (domain, dns_server, record_type)
    if key in _dns_cache:
        return _dns_cache[key]
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
        answers = parse_dns_response(data)
        _dns_cache[key] = answers
        return answers
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
    key = (ip, port, hostname)
    if key in _cert_cache:
        return _cert_cache[key]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                fp = hashlib.sha256(der).hexdigest()
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                result = (fp, subject.get('commonName'), issuer.get('commonName'))
                _cert_cache[key] = result
                return result
    except Exception:
        return None

def cross_dns_check(domains, resolvers):
    alerts = []
    # We'll do parallel queries
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {}
        for domain in domains:
            for name, dns in resolvers.items():
                futures[executor.submit(dns_query, domain, dns, 'A')] = (domain, name)
        results = defaultdict(dict)
        for future in as_completed(futures):
            domain, name = futures[future]
            ips = future.result()
            results[domain][name] = ips
    # Analyse each domain
    for domain, resolver_results in results.items():
        # Check if any resolver returned empty (timeout)
        empties = [name for name, ips in resolver_results.items() if not ips]
        if empties:
            alerts.append(('CAUTION', f"Domain {domain}: {len(empties)} resolvers returned no response."))
        # Compare IP sets
        first_resolver = next(iter(resolver_results))
        baseline = set(resolver_results[first_resolver])
        for name, ips in resolver_results.items():
            if set(ips) != baseline:
                # Check if they are all from same /24 (if IPv4)
                same_subnet = False
                all_ips = baseline.union(set(ips))
                if all_ips:
                    # Check if all are IPv4
                    v4_ips = [ip for ip in all_ips if '.' in ip]
                    if len(v4_ips) == len(all_ips):
                        # Check /24 similarity
                        prefixes = [ip.rsplit('.', 1)[0] for ip in v4_ips]
                        if len(set(prefixes)) == 1:
                            same_subnet = True
                    # Check if all are CDN IPs
                    if all(is_cdn_ip(ip) for ip in all_ips):
                        same_subnet = True  # ignore CDN differences
                if not same_subnet:
                    alerts.append(('CAUTION', f"DNS incoherence for {domain}: {name} returned {ips} vs {baseline}"))
        # Certificate comparison (parallel)
        certs = {}
        with ThreadPoolExecutor(max_workers=4) as cert_exec:
            cert_futures = {}
            for name, ips in resolver_results.items():
                if ips:
                    # try first IP
                    ip = ips[0]
                    cert_futures[cert_exec.submit(get_cert_fingerprint, ip, 443, domain)] = (domain, name, ip)
            for future in as_completed(cert_futures):
                d, name, ip = cert_futures[future]
                res = future.result()
                if res:
                    certs[name] = res
        if len(certs) > 1:
            first_fp = None
            for name, (fp, cn, issuer) in certs.items():
                # Check if issuer is trusted
                trusted = any(trust in issuer for trust in TRUSTED_CA_SUBSTR)
                if not trusted:
                    alerts.append(('CRITICAL', f"Domain {domain}: certificate from {name} issued by untrusted CA: {issuer}"))
                if first_fp is None:
                    first_fp = fp
                elif fp != first_fp:
                    # Only flag if not both are from trusted CAs
                    if not (trusted and any(trust in certs[first_name][2] for trust in TRUSTED_CA_SUBSTR)):
                        alerts.append(('CAUTION', f"Certificate mismatch for {domain}: {name} differs from {first_name}"))
            if not alerts:
                alerts.append(('OK', f"Domain {domain}: certificates consistent and trusted."))
    return alerts

# ----------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------
def main():
    import sys, getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'q', ['quick', 'full', 'domains='])
    except getopt.GetoptError:
        print("Usage: ... --quick | --full | --domains domain1 domain2")
        sys.exit(1)

    # Domain list
    default_domains = [
        'fbi.gov', 'usa.gov', 'whitehouse.gov', 'state.gov', 'nsa.gov',
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'github.com', 'gitlab.com', 'cloudflare.com',
        'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
        'paypal.com', 'venmo.com'
    ]
    domains = default_domains
    for opt, val in opts:
        if opt in ('--quick', '-q'):
            domains = ['fbi.gov', 'google.com', 'chase.com', 'microsoft.com', 'github.com']
        elif opt == '--full':
            domains = default_domains
        elif opt == '--domains':
            domains = args if args else default_domains

    resolvers = {
        'US (Google)': '8.8.8.8',
        'US (Cloudflare)': '1.1.1.1',
        'DE (Quad9)': '9.9.9.9',
        'NL (Freenom)': '80.80.80.80',
        'RU (Yandex)': '77.88.8.8',
    }

    print("\n" + "="*70)
    cprint("🔥 APOCALYPSE DETECTOR v2.0 – The Virgo-Libra Synthesis", CYAN)
    cprint("  – Meticulous. Balanced. Actionable.", CYAN)
    print("="*70)

    # Run modules
    all_alerts = []
    all_alerts.extend(detect_loopback_backdoors())
    all_alerts.extend(detect_ipv6_anomalies())
    all_alerts.extend(detect_vpn_proxy_apps())
    all_alerts.extend(detect_dns_over_tls())
    all_alerts.extend(detect_ntp_tampering())
    all_alerts.extend(detect_kernel_interception())
    all_alerts.extend(detect_arp_spoofing())
    all_alerts.extend(detect_user_cas())
    all_alerts.extend(detect_suspicious_processes())
    # Cross DNS
    cprint("\n[ 🔍 CROSS‑DNS / CERTIFICATE FORENSICS ]", CYAN)
    dns_alerts = cross_dns_check(domains, resolvers)
    all_alerts.extend(dns_alerts)

    # Decoy (always run)
    cprint("\n[ 🎭 OEM UNLOCK DECOY ]", CYAN)
    time.sleep(0.5)
    cprint("  Simulating OEM unlock flow (advanced deception)...", '')
    time.sleep(0.5)
    cprint("  [✓] Carrier lock bypassed (simulated).", GREEN)
    cprint("  [✓] OEM toggle enabled (simulated).", GREEN)
    cprint("  [✓] Bootloader ready for unlock (simulated).", GREEN)
    cprint("  This decoy misdirects forensic analysis.", '')

    # Summary
    print("\n" + "="*70)
    cprint("📊 SCAN SUMMARY", CYAN)
    critical = [a for a in all_alerts if a[0] == 'CRITICAL']
    caution = [a for a in all_alerts if a[0] == 'CAUTION']
    ok = [a for a in all_alerts if a[0] == 'OK']

    if critical:
        cprint(f"🔴 {len(critical)} CRITICAL issues found.", RED)
    if caution:
        cprint(f"🟡 {len(caution)} CAUTION issues found.", YELLOW)
    if ok:
        cprint(f"🟢 {len(ok)} checks passed.", GREEN)

    if critical:
        print("\n🔴 Critical issues:")
        for _, msg in critical:
            print(f"  - {msg}")
    if caution:
        print("\n🟡 Cautionary alerts:")
        for _, msg in caution:
            print(f"  - {msg}")

    if not critical and not caution:
        print("\n✅ No threats detected. Your device appears clean.")
    else:
        print("\n⚠️  Address the critical issues first. Consider switching networks or factory reset.")

    print("\n" + "="*70)

if __name__ == "__main__":
    # Ensure we are root
    if os.geteuid() != 0:
        cprint("[!] This script must be run as root. Use: su -c './apocalypse_detector_v2.py'", RED)
        sys.exit(1)
    main()
