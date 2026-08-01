#!/data/data/com.termux/files/usr/bin/bash
#
# mitm_diagnose.sh — pinpoint exactly where MITM interception is failing
#
# Usage: ./mitm_diagnose.sh <target-host> [proxy-port]
#   e.g. ./mitm_diagnose.sh blackjackapp.example.com 8080
#
# Checks, in order:
#   1. mitmproxy CA cert exists and hash
#   2. Cert present in Android system trust store (not just user store)
#   3. mitmdump/mitmproxy process actually running and listening
#   4. Device-level proxy settings actually point at it
#   5. Raw TCP reachability to the proxy port
#   6. TLS handshake through the proxy — whose cert do we actually get back?
#   7. TLS handshake direct (no proxy) — compare against the real site cert
#   8. Verdict: routing / trust / pinning / other
#
set -uo pipefail

TARGET="${1:-}"
PORT="${2:-8080}"
CA_CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}== $1 ==${NC}"; }

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target-host> [proxy-port]"
  exit 1
fi

ISSUES=()

# ---------------------------------------------------------------------------
section "1. mitmproxy CA cert"
if [ -f "$CA_CERT" ]; then
  pass "CA cert found at $CA_CERT"
  CA_HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CA_CERT" 2>/dev/null | head -1)
  CA_SUBJECT=$(openssl x509 -inform PEM -noout -subject -in "$CA_CERT" 2>/dev/null)
  CA_EXPIRY=$(openssl x509 -inform PEM -noout -enddate -in "$CA_CERT" 2>/dev/null)
  info "Hash (subject_hash_old): $CA_HASH"
  info "Subject: $CA_SUBJECT"
  info "$CA_EXPIRY"
else
  fail "CA cert not found at $CA_CERT — mitmproxy was likely never run to generate one"
  ISSUES+=("no_ca_cert")
  CA_HASH=""
fi

# ---------------------------------------------------------------------------
section "2. System trust store (requires root)"
if [ -n "$CA_HASH" ]; then
  SYS_CERT_PATH="/system/etc/security/cacerts/${CA_HASH}.0"
  if command -v su >/dev/null 2>&1; then
    if su -c "test -f $SYS_CERT_PATH" 2>/dev/null; then
      pass "Cert present in system trust store: $SYS_CERT_PATH"
    else
      fail "Cert NOT in system trust store at expected path: $SYS_CERT_PATH"
      warn "Apps ignore user-added certs by default since Android 7 (API 24+)."
      ISSUES+=("not_in_system_store")
    fi
    USER_CERT_COUNT=$(su -c "ls /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l" 2>/dev/null)
    if [ -n "$USER_CERT_COUNT" ] && [ "$USER_CERT_COUNT" -gt 0 ]; then
      warn "Found $USER_CERT_COUNT cert(s) in USER store — this alone won't be trusted by most apps"
    fi
  else
    warn "No root access ('su' not found) — cannot verify system trust store directly"
    ISSUES+=("no_root_check")
  fi
else
  warn "Skipping — no CA hash available"
fi

# ---------------------------------------------------------------------------
section "3. mitmproxy process"
MITM_PID=$(pgrep -f "mitmdump|mitmproxy|mitmweb" | head -1)
if [ -n "$MITM_PID" ]; then
  pass "mitmproxy process running (PID $MITM_PID)"
else
  fail "No mitmproxy/mitmdump/mitmweb process found running"
  ISSUES+=("not_running")
fi

LISTEN_CHECK=$(command -v netstat >/dev/null 2>&1 && netstat -tlnp 2>/dev/null | grep ":$PORT " )
if [ -z "$LISTEN_CHECK" ] && command -v ss >/dev/null 2>&1; then
  LISTEN_CHECK=$(ss -tlnp 2>/dev/null | grep ":$PORT ")
fi
if [ -n "$LISTEN_CHECK" ]; then
  pass "Something is listening on port $PORT"
  info "$LISTEN_CHECK"
else
  fail "Nothing appears to be listening on port $PORT"
  ISSUES+=("port_not_listening")
fi

# ---------------------------------------------------------------------------
section "4. Device proxy settings"
if command -v su >/dev/null 2>&1; then
  HTTP_PROXY_SETTING=$(su -c "settings get global http_proxy" 2>/dev/null)
  if [ -n "$HTTP_PROXY_SETTING" ] && [ "$HTTP_PROXY_SETTING" != "null" ]; then
    pass "Device global HTTP proxy is set: $HTTP_PROXY_SETTING"
  else
    warn "No global HTTP proxy set at OS level."
    warn "If you configured proxy only in Wi-Fi settings for one network, confirm the phone is actually on that Wi-Fi now."
    ISSUES+=("no_global_proxy")
  fi
else
  warn "No root — cannot check device-level proxy setting from here"
fi

# ---------------------------------------------------------------------------
section "5. Raw TCP reachability to proxy port"
if command -v nc >/dev/null 2>&1; then
  if timeout 3 nc -zv 127.0.0.1 "$PORT" 2>&1 | grep -qi "open\|succeeded"; then
    pass "Proxy port $PORT reachable from this shell"
  else
    fail "Cannot reach proxy port $PORT from this shell (localhost)"
    ISSUES+=("port_unreachable")
  fi
else
  warn "'nc' not installed — skipping (pkg install netcat-openbsd for this check)"
fi

# ---------------------------------------------------------------------------
section "6. TLS handshake THROUGH the proxy for $TARGET"
THROUGH_PROXY_CERT=$(echo | timeout 8 openssl s_client -connect 127.0.0.1:"$PORT" -servername "$TARGET" -proxy 127.0.0.1:"$PORT" 2>/dev/null | openssl x509 -noout -issuer -subject 2>/dev/null)
if [ -n "$THROUGH_PROXY_CERT" ]; then
  info "$THROUGH_PROXY_CERT"
  if echo "$THROUGH_PROXY_CERT" | grep -qi "mitmproxy"; then
    pass "Proxy IS intercepting — cert issued by mitmproxy CA"
  else
    fail "Proxy responded but cert is NOT the mitmproxy CA — traffic may be bypassing proxy (VPN app, direct socket, or app-pinned connection)"
    ISSUES+=("not_intercepted")
  fi
else
  fail "Could not complete TLS handshake through proxy to $TARGET"
  ISSUES+=("handshake_through_proxy_failed")
fi

# ---------------------------------------------------------------------------
section "7. TLS handshake DIRECT (no proxy) for $TARGET — baseline"
DIRECT_CERT=$(echo | timeout 8 openssl s_client -connect "${TARGET}:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -issuer -subject 2>/dev/null)
if [ -n "$DIRECT_CERT" ]; then
  info "$DIRECT_CERT"
  pass "Direct connection to real site succeeds (site itself is reachable)"
else
  warn "Direct connection to $TARGET:443 failed too — may just be a network/DNS issue unrelated to MITM setup"
  ISSUES+=("direct_conn_failed")
fi

# ---------------------------------------------------------------------------
section "VERDICT"
if [ ${#ISSUES[@]} -eq 0 ]; then
  pass "No obvious infrastructure problems detected."
  echo
  echo "If the app STILL won't load with all of the above green, this is almost"
  echo "certainly certificate pinning inside the app itself — no new CA cert will"
  echo "fix that. Next step: Frida + an SSL-unpinning script, or patch the APK's"
  echo "network_security_config.xml / pinning logic directly."
else
  echo "Issues found, in likely priority order to fix:"
  for issue in "${ISSUES[@]}"; do
    case "$issue" in
      no_ca_cert)              echo "  - Run mitmdump once to generate ~/.mitmproxy/mitmproxy-ca-cert.pem" ;;
      not_in_system_store)     echo "  - Install cert into /system/etc/security/cacerts/ (user store isn't trusted by apps on API 24+)" ;;
      no_root_check)           echo "  - Re-run as root or grant su to Termux to verify trust store placement" ;;
      not_running)             echo "  - Start mitmproxy/mitmdump before testing" ;;
      port_not_listening)      echo "  - mitmproxy isn't bound to port $PORT — check its startup logs/config" ;;
      no_global_proxy)         echo "  - Set device Wi-Fi proxy (or confirm you're on the network where it's set)" ;;
      port_unreachable)        echo "  - Proxy port not reachable — firewall, wrong interface bind, or wrong IP" ;;
      not_intercepted)         echo "  - Traffic is bypassing the proxy entirely (app-level VPN, direct IP, or custom network stack) — check if the target app uses its own DNS/VPN/Cronet stack that ignores system proxy settings" ;;
      handshake_through_proxy_failed) echo "  - Proxy isn't completing TLS at all for this host — check mitmproxy logs for the exact rejection reason" ;;
      direct_conn_failed)      echo "  - Target unreachable even without proxy — rule out DNS/network before blaming MITM setup" ;;
    esac
  done
  echo
  echo "Only once ALL of the above are green and the app STILL fails is it worth"
  echo "assuming certificate pinning and moving to Frida/APK patching."
fi
