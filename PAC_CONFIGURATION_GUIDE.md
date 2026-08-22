# PAC Configuration Guide - Phase 2.2

**Proxy Auto-Config (PAC) Setup for GodHand HTTPS Interception**

This guide covers configuring PAC (Proxy Auto-Config) on target devices to route all traffic through the GodHand MITM proxy on port 8888.

---

## Overview

**What is PAC?**
- PAC is JavaScript that runs on the device to determine which traffic goes through a proxy
- Browser/OS automatically fetches the PAC file from a URL
- PAC script runs locally to decide: proxy or direct connection?

**GodHand PAC Setup:**
- PAC URL: `http://pac.installCA.lan/pac`
- Routes all HTTP/HTTPS traffic through `127.0.0.1:8888` (or your GodHand device IP)
- Excludes localhost and private IP ranges to avoid loops

**Prerequisites for All Platforms:**
1. GodHand running on rooted device (e.g., Pixel 9a)
2. Target device on same network as GodHand
3. DNS resolution of `.lan` domains (configured on GodHand)
4. CA certificate installed on target device (Phase 2.1)

---

## Platform-Specific PAC Configuration

### Android (Rooted Device)

**Option 1: Using PAC URL**

```
Settings → Network & Internet → WiFi
├─ Long-press connected network
├─ Select "Modify"
├─ Toggle "Show advanced options" → ON
├─ Proxy section
│  ├─ Select "Automatic"
│  └─ Enter PAC hostname: pac.installCA.lan
└─ Save
```

**Option 2: Manual PAC Entry**

```
Settings → Network & Internet → WiFi
├─ Long-press connected network
├─ Select "Modify"
├─ Advanced options → ON
├─ Proxy → Manual
├─ Proxy hostname: 192.168.1.X (GodHand device IP)
├─ Proxy port: 8888
└─ Save
```

**Verification (Rooted Android):**
```bash
# Via ADB
adb shell settings get global http_proxy
# Should show: 192.168.1.X:8888 or similar

# Check iptables rules (if using transparent proxy)
adb shell iptables -L -n | grep 8888

# Monitor proxy traffic
adb logcat | grep "proxy\|PAC"
```

**Testing:**
1. Open Chrome
2. Navigate to `http://example.com` (should see in GodHand logs)
3. Navigate to `https://example.com` (should show CA warning initially, then work)
4. Check GodHand web UI → Attacks → HTTPS Interception → Live Traffic

---

### Android (Unrooted Device)

**Limitation:** Unrooted Android devices cannot use system-wide proxy settings easily. Instead:

**Option 1: Chrome Proxy Settings**
```
Chrome → Settings → System → Proxy settings
├─ Automatic proxy configuration → ON
├─ Proxy hostname: pac.installCA.lan
└─ Apply
```

**Option 2: Manual Proxy per WiFi Network**
```
Settings → Network & Internet → WiFi
├─ Long-press connected network
├─ Modify
├─ Proxy → Manual
├─ Proxy hostname: 192.168.1.X
├─ Proxy port: 8888
└─ Save (may require separate app)
```

**Note:** System-wide proxy on unrooted Android requires:
- Device owner (MDM) privileges, OR
- Custom ROM with full proxy support, OR
- App-specific proxy (limited to that app)

**Recommended:** Use Chrome proxy settings or install a third-party proxy app.

---

### iOS

**Prerequisites:**
- iOS 14+ (earlier versions have limited PAC support)
- CA certificate installed (Phase 2.1)
- Device on same WiFi as GodHand

**Configuration:**

```
Settings → WiFi
├─ Long-press connected network
├─ "i" (info icon)
├─ Scroll to "Proxy"
├─ Select "Automatic"
├─ URL: http://pac.installCA.lan/pac
└─ Save
```

**Alternative (if iOS doesn't support PAC):**
```
Settings → WiFi
├─ Network info icon
├─ Proxy → Manual
├─ Server: 192.168.1.X (GodHand IP)
├─ Port: 8888
└─ Save
```

**Limitations (iOS):**
- Safari and system apps only (apps must use system proxy)
- Many apps use certificate pinning (won't trust custom CA)
- Requires user to accept proxy configuration

**Testing:**
1. Open Safari
2. Navigate to `https://www.example.com`
3. Check GodHand logs: `curl http://192.168.1.X:5000/api/https_traffic?limit=5`

---

### macOS

**Prerequisites:**
- CA certificate installed in Keychain (Phase 2.1)
- Device on same network as GodHand

**Configuration (System-Wide):**

```
System Preferences → Network
├─ Select WiFi
├─ Click "Advanced"
├─ Go to "Proxies" tab
├─ Check "Automatic Proxy Configuration"
├─ Proxy configuration URL: http://pac.installCA.lan/pac
└─ Click "OK" → "Apply"
```

**Or (Manual Proxy):**
```
System Preferences → Network
├─ Advanced → Proxies
├─ Check "Web Proxy (HTTP)"
│  ├─ Proxy Server: 192.168.1.X
│  └─ Port: 8888
├─ Check "Secure Web Proxy (HTTPS)"
│  ├─ Proxy Server: 192.168.1.X
│  └─ Port: 8888
└─ Apply
```

**Verification (macOS):**
```bash
# Check system proxy settings
networksetup -getautoproxyurl "Wi-Fi"

# Check manual proxy
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"

# Monitor traffic (requires tcpdump)
sudo tcpdump -i en0 port 8888
```

**Testing:**
1. Open Safari or Chrome
2. Navigate to `https://www.example.com`
3. Monitor GodHand: `curl http://192.168.1.X:5000/api/https_traffic`

---

### Windows

**Prerequisites:**
- CA certificate installed in Trusted Root CA store (Phase 2.1)
- Device on same network as GodHand

**Configuration (System-Wide PAC):**

```
Settings → Network & Internet → Proxy
├─ Scroll to "Automatic proxy setup"
├─ Toggle "Use a proxy server" → OFF (disable manual first)
├─ Scroll to "Automatic proxy configuration"
├─ Toggle → ON
├─ Proxy configuration URL: http://pac.installCA.lan/pac
└─ Close (settings auto-save)
```

**Or (Manual Proxy):**
```
Settings → Network & Internet → Proxy
├─ Toggle "Use a proxy server" → ON
├─ Proxy address: 192.168.1.X
├─ Port: 8888
├─ Toggle "Don't use the proxy server for local (intranet) addresses" → ON
└─ Save
```

**Or (Legacy - netsh command):**
```powershell
# Set automatic PAC
netsh winhttp set proxy-server "pac.installCA.lan:80"

# Set manual proxy
netsh winhttp set proxy 192.168.1.X:8888

# View current settings
netsh winhttp show proxy

# Reset
netsh winhttp reset proxy
```

**Verification (Windows):**
```powershell
# Check proxy settings
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer

# Monitor network traffic (requires netsh trace)
netsh trace start capture=yes tracefile=C:\temp\network.etl
netsh trace stop
```

**Testing:**
1. Open Edge or Chrome
2. Navigate to `https://www.example.com`
3. Monitor GodHand from another machine: `curl http://192.168.1.X:5000/api/https_traffic`

---

## Testing PAC Delivery

### Verify PAC File Downloads Correctly

**From any device on the network:**

```bash
# Test PAC download
curl -v http://pac.installCA.lan/pac

# Should return:
# 1. HTTP 200 OK
# 2. Content-Type: application/x-ns-proxy-autoconfig
# 3. JavaScript code for proxy rules
```

**Expected PAC Output:**
```javascript
function FindProxyForURL(url, host) {
    if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";
    if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
    if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";
    return "PROXY 127.0.0.1:8888";
}
```

### Verify CA Certificate Downloads

```bash
# Download CA certificate
curl -v http://pac.installCA.lan/ca-cert

# Should return:
# 1. HTTP 200 OK
# 2. Content-Type: application/x-pem-file
# 3. PEM-formatted certificate

# Verify certificate contents
curl http://pac.installCA.lan/ca-cert | openssl x509 -text -noout
```

### Verify Device Routes Through Proxy

**Method 1: Check GodHand Traffic Logs**

```bash
# Start monitoring
curl -H "Authorization: Bearer TOKEN" http://192.168.1.X:5000/api/https_traffic/stream

# On target device, open browser and navigate to any HTTPS site
# You should see traffic appear in the stream within 1-2 seconds
```

**Method 2: Packet Capture**

```bash
# On GodHand device, capture traffic on port 8888
sudo tcpdump -i eth0 port 8888 -A

# On target device, make HTTPS request
# You should see incoming connections on port 8888
```

**Method 3: Check GodHand Web UI**

```
1. Open http://192.168.1.X:5000
2. Navigate to Attacks tab
3. Scroll to "HTTPS Interception" card
4. Click "🔒 Start Interception"
5. Watch live traffic table
6. On target device, navigate to any HTTPS site
7. Traffic should appear in table within seconds
```

---

## Troubleshooting PAC Configuration

### Issue: PAC File Not Downloading

**Symptoms:**
```
- Device cannot access pac.installCA.lan
- "DNS resolution failed" or "Cannot connect" error
- Proxy not activating
```

**Solutions:**

1. **Check DNS resolution:**
   ```bash
   # On target device (via SSH or ADB)
   nslookup pac.installCA.lan
   dig pac.installCA.lan
   
   # Should resolve to GodHand device IP (192.168.1.X)
   ```

2. **Configure DNS for .lan domain:**
   ```bash
   # On GodHand device
   # Edit /etc/dnsmasq.conf or equivalent
   address=/installCA.lan/192.168.1.X
   
   # Restart DNS service
   systemctl restart dnsmasq
   ```

3. **Use IP instead of hostname:**
   ```
   Proxy URL: http://192.168.1.X/pac (instead of pac.installCA.lan)
   ```

### Issue: Proxy Not Activating After PAC Download

**Symptoms:**
```
- PAC file downloads but proxy doesn't work
- Traffic doesn't appear in GodHand logs
- "No internet" or "Cannot access websites"
```

**Solutions:**

1. **Verify proxy settings applied:**
   ```bash
   # Android: adb shell settings get global http_proxy
   # macOS: networksetup -getautoproxyurl "Wi-Fi"
   # Windows: netsh winhttp show proxy
   ```

2. **Check GodHand is running:**
   ```bash
   curl http://192.168.1.X:5000/api/state
   # Should return status and port information
   ```

3. **Verify port 8888 is open:**
   ```bash
   # From target device
   nc -zv 192.168.1.X 8888
   # Should show: Connection successful
   ```

### Issue: Traffic Appears in Logs But Device Shows Error

**Symptoms:**
```
- GodHand logs show traffic
- Device browser shows "Certificate Error" or "Not Secure"
- HTTPS sites don't load
```

**Solutions:**

1. **Verify CA certificate is installed:**
   - Go to device Settings → Security → Trusted Certificates
   - Look for "GodHand CA"
   - If missing, reinstall from Phase 2.1

2. **Clear browser cache:**
   ```bash
   # Chrome: Settings → Privacy → Clear browsing data
   # Safari: Settings → Safari → Clear History and Website Data
   ```

3. **Check certificate chain:**
   ```bash
   # Download and inspect CA
   curl http://pac.installCA.lan/ca-cert | openssl x509 -text
   
   # Verify: Issuer and Subject should both show "GodHand CA"
   ```

### Issue: Only Some Traffic Captured (Not All HTTPS)

**Symptoms:**
```
- Some apps show traffic, others don't
- System apps not proxied
- Certificate pinning apps reject proxy
```

**Causes:**
- App uses certificate pinning (hardcoded cert validation)
- App doesn't respect system proxy settings
- App is system service with special permissions

**Solutions:**
- This is expected behavior (certificate pinning is a security feature)
- Test with system browser (Chrome, Safari, Firefox)
- Use different apps to verify proxy is working

---

## Phase 2.2 Verification Checklist

- [ ] PAC file accessible: `curl http://pac.installCA.lan/pac` returns JavaScript
- [ ] CA certificate accessible: `curl http://pac.installCA.lan/ca-cert` returns PEM
- [ ] Device resolves .lan domain: `nslookup pac.installCA.lan` returns correct IP
- [ ] Device downloads PAC: Browser/OS shows proxy settings applied
- [ ] Device routes traffic: GodHand logs show connections from device IP
- [ ] CA installed on device: Settings → Security shows "GodHand CA" in trusted
- [ ] HTTPS traffic intercepted: GodHand web UI shows live traffic table updates
- [ ] Multiple devices tested: Android, iOS, macOS, Windows all configured

---

## Next Steps

**Phase 2.3**: End-to-end validation on real devices
- Capture 24+ hours of traffic from Pixel 9a
- Verify all types intercepted (HTTP, HTTPS, DNS)
- Document any gaps or limitations

**Phase 3**: Response injection capability
- Implement traffic modification in proxy
- Add request/response body inspection to UI
- Test on real devices

---

For issues, check the [HTTPS_SETUP_GUIDE.md](HTTPS_SETUP_GUIDE.md) troubleshooting section and GodHand logs:

```bash
curl -H "Authorization: Bearer TOKEN" http://192.168.1.X:5000/api/logs
```
