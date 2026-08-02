#!/usr/bin/env python3
"""
Paranoid Hacker’s VPN/Proxy/DNS Trickery Detection Script
Runs on Android (Termux) – uses rish if available for system-level checks.
"""

import subprocess
import os
import sys
import re
import socket
import json
from urllib.request import urlopen

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
    """Run a shell command, optionally via rish. Return (stdout, stderr, rc)."""
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
#  Detect VPN interfaces and routes
# ----------------------------------------------------------------------
def detect_vpn():
    print("\n[ VPN Detection ]")
    # Check for tun/tap interfaces
    out, _, _ = run_cmd("ip link show")
    vpn_ifaces = re.findall(r'(tun|tap|ppp|wgp)\d+', out)
    if vpn_ifaces:
        print(f"  [+] VPN interfaces found: {', '.join(vpn_ifaces)}")
    else:
        print("  [-] No obvious VPN interfaces.")

    # Check routing for non-typical default gateways
    out, _, _ = run_cmd("ip route show default")
    if "tun" in out or "ppp" in out or "wgp" in out:
        print(f"  [+] Default route via VPN: {out}")
    else:
        print(f"  [-] Default route appears normal: {out}")

    # Check for VPN apps via dumpsys (requires rish)
    if RISH:
        out, _, _ = run_cmd("dumpsys connectivity | grep -i vpn", use_rish=True)
        if out:
            print(f"  [+] VPN service detected: {out[:100]}...")
        else:
            print("  [-] No VPN service in connectivity dump.")
    else:
        print("  [!] Skipping dumpsys VPN check (rish not available).")

# ----------------------------------------------------------------------
#  Detect system proxy settings
# ----------------------------------------------------------------------
def detect_proxy():
    print("\n[ Proxy Detection ]")
    # Environment variables
    env_vars = ['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy']
    found = False
    for var in env_vars:
        val = os.environ.get(var) or os.environ.get(var.upper())
        if val:
            print(f"  [+] {var} = {val}")
            found = True
    if not found:
        print("  [-] No proxy environment variables.")

    # Android global proxy settings (via settings command)
    out, _, _ = run_cmd("settings get global http_proxy", use_rish=bool(RISH))
    if out and out != "null":
        print(f"  [+] Global HTTP proxy: {out}")
        found = True

    # Proxy auto-config (PAC) if any
    out, _, _ = run_cmd("settings get global global_http_proxy_host", use_rish=bool(RISH))
    if out and out != "null":
        print(f"  [+] Global proxy host: {out}")
        found = True

    if not found:
        print("  [-] No system proxy detected.")

# ----------------------------------------------------------------------
#  Detect DNS tampering
# ----------------------------------------------------------------------
def detect_dns():
    print("\n[ DNS Trickery Detection ]")
    # Get DNS servers from system properties
    dns_servers = []
    for i in range(1, 5):
        prop = f"net.dns{i}"
        out, _, _ = run_cmd(f"getprop {prop}", use_rish=bool(RISH))
        if out:
            dns_servers.append(out)
    if dns_servers:
        print(f"  [+] DNS servers: {', '.join(dns_servers)}")
    else:
        print("  [-] Could not retrieve DNS servers.")

    # Compare against known public DNS
    public_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']
    suspicious = [d for d in dns_servers if d not in public_dns and not d.startswith('192.168.') and not d.startswith('10.')]
    if suspicious:
        print(f"  [!] Suspicious DNS servers: {', '.join(suspicious)}")
    else:
        print("  [-] DNS servers appear normal.")

    # Check DNS resolution for a known domain
    try:
        ip = socket.gethostbyname('google.com')
        print(f"  [+] google.com resolves to {ip}")
        if ip not in ['142.250.0.0/16', '172.217.0.0/16']:
            print("  [!] google.com resolution may be hijacked.")
    except Exception as e:
        print(f"  [!] DNS resolution failed: {e}")

    # Check if DNS over TLS is enforced (via netstat)
    out, _, _ = run_cmd("netstat -tulpn | grep 53")
    if "tcp" in out:
        print("  [+] TCP port 53 listener found – possible DoT or hijack.")
    else:
        print("  [-] No TCP 53 listener (typical).")

# ----------------------------------------------------------------------
#  Detect root CA certificates (possible MITM)
# ----------------------------------------------------------------------
def detect_ca():
    print("\n[ Certificate Authority Check ]")
    # List user-installed CAs (if rish available)
    if RISH:
        out, _, _ = run_cmd("ls -la /data/misc/user/0/cacerts-added/", use_rish=True)
        if out and "No such file" not in out:
            print(f"  [+] User-installed CAs found:\n{out}")
        else:
            print("  [-] No user-installed CAs.")
    else:
        print("  [!] Skipping CA check (rish not available).")

# ----------------------------------------------------------------------
#  Detect if the device is behind a VPN/proxy via geo-ip check
# ----------------------------------------------------------------------
def detect_geo_anomaly():
    print("\n[ Geo-IP / Network Location Check ]")
    try:
        # Use ipinfo.io for location
        with urlopen('https://ipinfo.io/json', timeout=5) as response:
            data = json.loads(response.read().decode())
            ip = data.get('ip', 'unknown')
            country = data.get('country', 'unknown')
            city = data.get('city', 'unknown')
            print(f"  [+] Public IP: {ip} ({country}, {city})")
            # Compare with expected country (if set)
            # (We'll just flag if it's not your home country - you can set manually)
    except Exception as e:
        print(f"  [!] Geo-IP check failed: {e}")

# ----------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------
def main():
    print("=== Paranoid Hacker’s VPN/Proxy/DNS Trickery Detection ===\n")
    detect_vpn()
    detect_proxy()
    detect_dns()
    detect_ca()
    detect_geo_anomaly()
    print("\n[+] Detection complete.")
    print("    If anything suspicious is found, verify manually.")
    print("    Remember: some VPNs are legitimate privacy tools.")

if __name__ == "__main__":
    main()
