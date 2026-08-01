#!/usr/bin/env python3
"""
NetBoost Proxy - Lightweight HTTP/HTTPS forwarding proxy with a live
network-metrics dashboard.

Run:   python3 netboost_proxy.py
Open:  http://localhost:8080
Requires: pip install requests --break-system-packages
"""

import http.server
import socketserver
import gzip
import io
import ipaddress
import logging
import re
import secrets
import signal
import sys
import threading
import time
from collections import deque
from http.cookies import SimpleCookie
from typing import Dict, Optional
from urllib.parse import urlparse, urljoin, quote, parse_qs

try:
    import requests
except ImportError:
    print("Missing 'requests'. Install with: pip install requests --break-system-packages")
    sys.exit(1)

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
PORT = 8080
SESSION_IDLE_TIMEOUT = 1800
CLEANUP_INTERVAL = 300
METRICS_HISTORY = 60  # how many samples to keep per session

BLOCKED_SUBNETS = [
    ipaddress.IPv4Network("10.0.0.0/8"), ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"), ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"), ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NetBoost")

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ----------------------------------------------------------------------
# Aurora dashboard - real metrics only (latency, bytes, compression, count)
# ----------------------------------------------------------------------
def build_dashboard(token: str) -> str:
    return f"""
<style>
#nb-aurora {{
  position:fixed; bottom:18px; right:18px; width:320px;
  background:rgba(15,17,26,0.7); backdrop-filter:blur(18px);
  -webkit-backdrop-filter:blur(18px); color:#f1f5f9;
  border-radius:22px; border:1px solid rgba(255,255,255,0.1);
  font-family:'Inter',system-ui,sans-serif; font-size:13px;
  z-index:2147483647; box-shadow:0 20px 60px rgba(0,0,0,0.6);
  overflow:hidden; transition:all 0.35s cubic-bezier(.16,1,.3,1);
}}
#nb-aurora::before {{
  content:''; position:absolute; inset:-40% -40% auto -40%; height:160%;
  background:conic-gradient(from 0deg, #22d3ee, #a855f7, #f472b6, #22d3ee);
  filter:blur(50px); opacity:0.22; animation:nb-spin 14s linear infinite; z-index:-1;
}}
@keyframes nb-spin {{ to {{ transform:rotate(360deg); }} }}
#nb-aurora.collapsed {{ width:54px; height:54px; border-radius:50%; }}
#nb-aurora.collapsed .nb-body, #nb-aurora.collapsed .nb-head-text {{ display:none; }}
#nb-head {{ display:flex; justify-content:space-between; align-items:center;
  padding:14px 18px; cursor:pointer; }}
#nb-head h3 {{ margin:0; font-size:15px; font-weight:600;
  background:linear-gradient(135deg,#22d3ee,#a855f7); -webkit-background-clip:text;
  -webkit-text-fill-color:transparent; }}
.nb-body {{ padding:4px 18px 16px; }}
.nb-row {{ display:flex; justify-content:space-between; margin:7px 0; }}
.nb-label {{ opacity:0.65; }}
.nb-value {{ font-weight:600; font-variant-numeric:tabular-nums; }}
.nb-spark {{ display:flex; gap:2px; align-items:flex-end; height:26px; margin:6px 0 10px; }}
.nb-spark span {{ flex:1; background:linear-gradient(180deg,#22d3ee,#a855f7); border-radius:2px; min-height:2px; }}
</style>
<div id="nb-aurora">
  <div id="nb-head">
    <span class="nb-head-text"><h3>NetBoost</h3></span>
    <span id="nb-orb">📡</span>
  </div>
  <div class="nb-body">
    <div class="nb-row"><span class="nb-label">Latency</span><span class="nb-value" id="nb-latency">- ms</span></div>
    <div class="nb-spark" id="nb-spark"></div>
    <div class="nb-row"><span class="nb-label">Transferred</span><span class="nb-value" id="nb-bytes">0 KB</span></div>
    <div class="nb-row"><span class="nb-label">Compression</span><span class="nb-value" id="nb-compress">0%</span></div>
    <div class="nb-row"><span class="nb-label">Requests</span><span class="nb-value" id="nb-count">0</span></div>
    <div class="nb-row"><span class="nb-label">Session Uptime</span><span class="nb-value" id="nb-uptime">0s</span></div>
  </div>
</div>
<script>
(function() {{
  const token = "{token}";
  const el = document.getElementById('nb-aurora');
  let collapsed = false;
  document.getElementById('nb-head').addEventListener('click', () => {{
    collapsed = !collapsed;
    el.classList.toggle('collapsed', collapsed);
  }});

  const history = [];
  function fmtBytes(n) {{
    if (n < 1024) return n + ' B';
    if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
    return (n/1024/1024).toFixed(2) + ' MB';
  }}
  function renderSpark() {{
    const max = Math.max(...history, 1);
    document.getElementById('nb-spark').innerHTML = history.map(v =>
      `<span style="height:${{Math.max(6,(v/max)*100)}}%"></span>`).join('');
  }}

  async function poll() {{
    try {{
      const res = await fetch('/metrics/' + token);
      if (!res.ok) return;
      const m = await res.json();
      document.getElementById('nb-latency').textContent = m.last_latency_ms.toFixed(0) + ' ms';
      document.getElementById('nb-bytes').textContent = fmtBytes(m.total_bytes);
      document.getElementById('nb-compress').textContent = m.compression_pct.toFixed(0) + '%';
      document.getElementById('nb-count').textContent = m.request_count;
      document.getElementById('nb-uptime').textContent = m.uptime_s.toFixed(0) + 's';
      history.push(m.last_latency_ms);
      if (history.length > 20) history.shift();
      renderSpark();
    }} catch (e) {{ /* silent - proxied page may block fetch to other origins */ }}
  }}
  setInterval(poll, 1500);
  poll();
}})();
</script>
"""

# ----------------------------------------------------------------------
# Session
# ----------------------------------------------------------------------
class ClientSession:
    def __init__(self, target_base: str):
        self.target_base = target_base
        self.token = secrets.token_hex(16)
        self.created = time.time()
        self.last_activity = time.time()
        self.request_count = 0
        self.total_bytes_raw = 0
        self.total_bytes_sent = 0
        self.latencies = deque(maxlen=METRICS_HISTORY)
        self.lock = threading.Lock()

    def record(self, latency_ms: float, raw_len: int, sent_len: int):
        with self.lock:
            self.request_count += 1
            self.total_bytes_raw += raw_len
            self.total_bytes_sent += sent_len
            self.latencies.append(latency_ms)
            self.last_activity = time.time()

    def metrics(self) -> dict:
        with self.lock:
            comp_pct = 0.0
            if self.total_bytes_raw > 0:
                comp_pct = max(0.0, (1 - self.total_bytes_sent / self.total_bytes_raw) * 100)
            return {
                "last_latency_ms": self.latencies[-1] if self.latencies else 0.0,
                "avg_latency_ms": sum(self.latencies) / len(self.latencies) if self.latencies else 0.0,
                "total_bytes": self.total_bytes_sent,
                "compression_pct": comp_pct,
                "request_count": self.request_count,
                "uptime_s": time.time() - self.created,
                "target": self.target_base,
            }


class SessionStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: Dict[str, ClientSession] = {}
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def create(self, target_base: str) -> ClientSession:
        s = ClientSession(target_base)
        with self._lock:
            self._sessions[s.token] = s
        return s

    def get(self, token: str) -> Optional[ClientSession]:
        with self._lock:
            s = self._sessions.get(token)
            if s and (time.time() - s.last_activity) < SESSION_IDLE_TIMEOUT:
                return s
            if s:
                del self._sessions[token]
        return None

    def list_sessions(self):
        with self._lock:
            return list(self._sessions.values())

    def _cleanup_loop(self):
        while True:
            time.sleep(CLEANUP_INTERVAL)
            with self._lock:
                now = time.time()
                expired = [t for t, s in self._sessions.items()
                           if (now - s.last_activity) >= SESSION_IDLE_TIMEOUT]
                for t in expired:
                    del self._sessions[t]
                if expired:
                    logger.info(f"Cleaned up {len(expired)} expired sessions")


session_store = SessionStore()

# ----------------------------------------------------------------------
# URL validation - block internal/private targets (SSRF guard)
# ----------------------------------------------------------------------
def is_private_ip(hostname: str) -> bool:
    import socket
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        except (socket.gaierror, TypeError):
            return False
    return any(ip in net for net in BLOCKED_SUBNETS)


def validate_target_url(raw_url: str) -> str:
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if not parsed.hostname:
        raise ValueError("Invalid URL - no hostname")
    if is_private_ip(parsed.hostname):
        raise ValueError("Private/internal addresses are not allowed")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS allowed")
    return f"{parsed.scheme}://{parsed.netloc}"

# ----------------------------------------------------------------------
# Rewriting
# ----------------------------------------------------------------------
def proxify_asset_url(token: str, url: str) -> str:
    return f"/proxy/asset/{token}?url={quote(url, safe='')}"


def rewrite_html(token: str, html: str, base: str) -> str:
    def attr_repl(m):
        attr, val = m.group(1), m.group(2)
        if val.startswith(('data:', '#')) or not val.startswith('http'):
            return f'{attr}="{val}"'
        if urlparse(val).netloc == urlparse(base).netloc:
            return f'{attr}="{proxify_asset_url(token, val)}"'
        return f'{attr}="{val}"'
    return re.sub(r'(src|href|action|poster)="([^"]*)"', attr_repl, html, flags=re.IGNORECASE)


def rewrite_css(token: str, css: str, base: str) -> str:
    def repl(m):
        url = m.group(1).strip("'\"")
        if url.startswith(('data:', '#')):
            return m.group(0)
        abs_url = url if urlparse(url).netloc else urljoin(base + '/', url)
        if urlparse(abs_url).netloc == urlparse(base).netloc:
            return f"url({proxify_asset_url(token, abs_url)})"
        return f"url({abs_url})"
    return re.sub(r'url\(([^)]*)\)', repl, css)

# ----------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------
LANDING_PAGE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetBoost Proxy</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0c10; color:#e5e7eb; font-family:'Inter',system-ui,sans-serif;
    display:flex; justify-content:center; align-items:center; min-height:100vh; padding:20px; }
  .container { background:#1a1d29; border-radius:20px; padding:28px 22px; width:100%; max-width:420px;
    border:1px solid #2d3348; box-shadow:0 10px 40px rgba(0,0,0,0.6); }
  h1 { text-align:center; margin-bottom:22px; font-size:1.6rem;
    background:linear-gradient(135deg,#22d3ee,#a855f7); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
  label { display:block; margin:14px 0 5px; color:#9ca3af; font-size:0.9rem; }
  input { width:100%; padding:13px 12px; background:#111420; border:1px solid #374151;
    border-radius:10px; color:#fff; font-size:1rem; outline:none; }
  input:focus { border-color:#22d3ee; }
  .btn { width:100%; margin-top:22px; padding:15px; background:linear-gradient(135deg,#22d3ee,#a855f7);
    color:#0a0c10; border:none; border-radius:12px; font-size:1.05rem; font-weight:700; cursor:pointer; }
  .note { text-align:center; margin-top:16px; font-size:0.82rem; color:#6b7280; }
</style></head>
<body>
  <div class="container">
    <h1>NetBoost Proxy</h1>
    <form action="/launch" method="get">
      <label for="url">Target URL</label>
      <input type="url" id="url" name="url" placeholder="https://example.com" required>
      <button type="submit" class="btn">Launch</button>
    </form>
    <div class="note">Forwards requests and shows live latency, transfer, and compression stats.</div>
  </div>
</body></html>"""

ERROR_PAGE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>NetBoost - Error</title>
<style>body{{background:#0a0c10;color:#e5e7eb;font-family:sans-serif;display:flex;
justify-content:center;align-items:center;min-height:100vh;padding:20px;}}
.box{{background:#1a1d29;padding:24px;border-radius:16px;max-width:420px;text-align:center;}}
.detail{{background:#111420;padding:12px;border-radius:8px;color:#f87171;font-family:monospace;margin:14px 0;word-break:break-word;}}
a{{color:#22d3ee;}}</style></head>
<body><div class="box"><h2>Connection Error</h2><p>{error}</p>
<div class="detail">{detail}</div><a href="/">Back</a></div></body></html>"""

# ----------------------------------------------------------------------
# Handler
# ----------------------------------------------------------------------
class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.client_address[0], fmt % args)

    def _serve_html(self, html, code=200, headers=None):
        data = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _serve_json(self, obj):
        import json
        data = json.dumps(obj).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(data)

    def _serve_binary(self, code, content_type, data):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _cookie_token(self) -> Optional[str]:
        c = SimpleCookie(self.headers.get('Cookie', ''))
        m = c.get('nb_session')
        return m.value if m else None

    def _set_cookie(self, token: str) -> str:
        c = SimpleCookie()
        c['nb_session'] = token
        c['nb_session']['path'] = '/'
        c['nb_session']['httponly'] = True
        return c.output(header='').strip()

    def do_GET(self):
        try:
            if self.path in ('/', ''):
                self._serve_html(LANDING_PAGE)
            elif self.path.startswith('/launch'):
                self._handle_launch()
            elif self.path.startswith('/metrics/'):
                self._handle_metrics()
            elif self.path == '/sessions':
                self._handle_sessions()
            else:
                self._proxy_request('GET')
        except Exception:
            logger.exception("Unhandled error in GET %s", self.path)
            self.send_error(500)

    def do_POST(self):
        try:
            self._proxy_request('POST')
        except Exception:
            logger.exception("Unhandled error in POST %s", self.path)
            self.send_error(500)

    def _handle_metrics(self):
        token = self.path.split('/metrics/')[1].split('?')[0]
        session = session_store.get(token)
        if not session:
            self._serve_json({"error": "unknown session"})
            return
        self._serve_json(session.metrics())

    def _handle_sessions(self):
        sessions = session_store.list_sessions()
        self._serve_json([{
            "token": s.token[:8] + "...",
            "target": s.target_base,
            "uptime_s": round(time.time() - s.created),
            "requests": s.request_count,
        } for s in sessions])

    def _handle_launch(self):
        params = parse_qs(urlparse(self.path).query)
        raw_url = params.get('url', [''])[0].strip()
        try:
            base = validate_target_url(raw_url)
        except ValueError as e:
            self._serve_html(ERROR_PAGE.format(error=str(e), detail=""), code=400)
            return

        session = session_store.create(base)
        token = session.token

        t0 = time.time()
        try:
            resp = requests.get(base, headers=DEFAULT_HEADERS, timeout=15, allow_redirects=True)
        except requests.RequestException as e:
            self._serve_html(ERROR_PAGE.format(error="Could not reach target", detail=str(e)), code=502)
            return
        latency_ms = (time.time() - t0) * 1000

        ct = resp.headers.get('Content-Type', 'text/html')
        raw_bytes = resp.content
        if 'text/html' not in ct:
            session.record(latency_ms, len(raw_bytes), len(raw_bytes))
            self._send_asset_redirect(token, base)
            return

        html = resp.text
        html = rewrite_html(token, html, base)
        dashboard = build_dashboard(token)
        base_tag = f'<base href="{base}">'
        if '<head>' in html:
            html = html.replace('<head>', f'<head>\n{base_tag}\n', 1)
            html = html.replace('</body>', f'{dashboard}\n</body>') if '</body>' in html else html + dashboard
        else:
            html = base_tag + html + dashboard

        sent_bytes = html.encode('utf-8')
        session.record(latency_ms, len(raw_bytes), len(sent_bytes))
        self._serve_html(html, headers={'Set-Cookie': self._set_cookie(token)})

    def _send_asset_redirect(self, token, url):
        self.send_response(302)
        self.send_header('Location', proxify_asset_url(token, url))
        self.end_headers()

    def _proxy_request(self, method):
        token = self._cookie_token()
        session = session_store.get(token) if token else None
        if not session:
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return

        base = session.target_base

        if self.path.startswith('/proxy/asset/'):
            params = parse_qs(urlparse(self.path).query)
            target_url = params.get('url', [None])[0]
            if not target_url:
                self.send_error(400)
                return
        else:
            path_only = self.path.split('?')[0]
            target_url = urljoin(base, path_only)
            q = urlparse(self.path).query
            if q:
                target_url += '?' + q

        t0 = time.time()
        try:
            req_headers = {k: v for k, v in self.headers.items() if k.lower() != 'host'}
            if method == 'GET':
                resp = requests.get(target_url, headers=req_headers, timeout=15, allow_redirects=False)
                body = b''
            else:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                resp = requests.post(target_url, data=body, headers=req_headers, timeout=15, allow_redirects=False)
        except requests.RequestException as e:
            logger.warning("Proxy fetch failed for %s: %s", target_url, e)
            self._serve_binary(502, 'text/plain', b'Upstream fetch failed')
            return
        latency_ms = (time.time() - t0) * 1000

        if resp.status_code in (301, 302, 303, 307, 308) and 'Location' in resp.headers:
            abs_loc = urljoin(target_url, resp.headers['Location'])
            self.send_response(resp.status_code)
            self.send_header('Location', f"/proxy/asset/{session.token}?url={quote(abs_loc, safe='')}")
            self.end_headers()
            return

        ct = resp.headers.get('Content-Type', 'application/octet-stream')
        content = resp.content
        raw_len = len(content)

        if 'text/html' in ct and method == 'GET':
            html = content.decode('utf-8', errors='ignore')
            html = rewrite_html(session.token, html, base)
            content = html.encode('utf-8')
            ct = 'text/html; charset=utf-8'
        elif 'text/css' in ct:
            css = content.decode('utf-8', errors='ignore')
            css = rewrite_css(session.token, css, base)
            content = css.encode('utf-8')

        session.record(latency_ms, raw_len, len(content))
        self._serve_binary(resp.status_code, ct, content)


def shutdown(server, *_):
    logger.info("Shutting down...")
    server.shutdown()
    sys.exit(0)


def main():
    logger.info(f"NetBoost Proxy running - http://localhost:{PORT}")
    server = socketserver.ThreadingTCPServer(("0.0.0.0", PORT), ProxyHandler)
    signal.signal(signal.SIGINT, lambda s, f: shutdown(server))
    signal.signal(signal.SIGTERM, lambda s, f: shutdown(server))
    server.serve_forever()


if __name__ == "__main__":
    main()
