# GodHand HTTPS Interception Setup Guide

**Phase 2: Device Configuration & CA Installation**

This guide covers installing the GodHand Certificate Authority (CA) on your rooted Android device and configuring test devices to route HTTPS traffic through the MITM proxy for inspection.

---

## Overview

GodHand intercepts HTTPS traffic by acting as a transparent MITM proxy. To make this work:

1. **GodHand generates a custom CA certificate** on startup (stored in `/var/godhand/certs/`)
2. **You install this CA certificate** on rooted devices so they trust the proxy's fake certs
3. **You configure devices' proxy settings** to route all traffic through GodHand (port 8888)
4. **GodHand intercepts, logs, and (optionally) modifies** the HTTPS traffic

**Security Notes:**
- ✅ CA installation is **explicit** (user action), not covert
- ✅ The hostname `pac.installCA.lan` signals that a CA is being installed
- ✅ All work is **reversible** — remove the CA certificate to stop interception
- ✅ Project Tegu authorization: Personal de-MDM research on own devices only

---

## Phase 2.1: CA Installation on Rooted Pixel 9a

### Prerequisites
- Rooted Pixel 9a (or other rooted Android device)
- GodHand running on same network
- `adb` (Android Debug Bridge) installed on development machine
- USB debugging enabled on Pixel 9a

### Step 1: Start GodHand on Pixel 9a

```bash
# On Pixel 9a (SSH or Termux)
python3 GodHand.py
```

Expected output:
```
GodHand listening on 0.0.0.0:5000
HTTPS MITM proxy infrastructure initialized
HTTPS MITM proxy started on port 8888
```

### Step 2: Download CA Certificate

```bash
# On development machine
adb shell curl -s http://192.168.1.X:5000/api/https_ca_install > godhand-ca-cert.pem
# Replace 192.168.1.X with Pixel 9a's IP
```

Verify certificate downloaded:
```bash
openssl x509 -in godhand-ca-cert.pem -text -noout
```

### Step 3: Enable System Partition R/W

```bash
adb shell su -c "mount -o rw,remount /system"
```

Verify:
```bash
adb shell mount | grep system
# Should show /system as rw (read-write)
```

### Step 4: Push CA Certificate to System Store

```bash
adb push godhand-ca-cert.pem /system/etc/security/cacerts/
```

### Step 5: Set Proper Permissions

```bash
adb shell su -c "chmod 644 /system/etc/security/cacerts/godhand-ca-cert.pem"
adb shell su -c "chown root:root /system/etc/security/cacerts/godhand-ca-cert.pem"
```

### Step 6: Reboot Device

```bash
adb reboot
```

Wait for device to come back online.

### Step 7: Verify CA Installation

```bash
adb shell openssl x509 -in /system/etc/security/cacerts/godhand-ca-cert.pem -text -noout
```

Or in Settings → Security → Trusted credentials → System → Look for "GodHand CA"

### Step 8: Configure Pixel 9a Proxy Settings

On the Pixel 9a:

1. **Settings** → **Network & Internet** → **WiFi**
2. Long-press connected network → **Modify** → **Show advanced options**
3. **Proxy** → Select **Automatic**
4. **Proxy hostname**: `pac.installCA.lan`
5. Save

Or manually enter the PAC URL:
- **Proxy** → **Manual**
- **Proxy hostname**: `192.168.1.X` (GodHand IP)
- **Proxy port**: `8888`

### Step 9: Verify Interception

On Pixel 9a, open Chrome and navigate to:
```
https://www.example.com
```

On development machine, check GodHand logs:
```bash
curl -s http://192.168.1.X:5000/api/https_traffic?limit=10 | jq .
```

You should see traffic entries with:
- `hostname`: "example.com"
- `type`: "request" and "response"
- `client_ip`: Pixel 9a's IP
- `method`: GET, POST, etc.

---

## Phase 2.2: Configure Secondary Test Devices

### Android (Unrooted)

1. **Settings** → **Security** → **Install certificate from storage**
2. Download CA certificate from `http://pac.installCA.lan/ca-cert`
3. Select downloaded file → Install as "User certificate"
4. **Settings** → **Network & Internet** → **WiFi**
5. Long-press network → **Modify** → **Proxy** → **Automatic**
6. **PAC hostname**: `pac.installCA.lan`

**Note**: Unrooted devices can only intercept app traffic if apps use the system certificate store. Many apps use certificate pinning.

### iOS

1. Navigate to `http://pac.installCA.lan` on the device
2. Tap **Download CA Certificate** → **Allow**
3. **Settings** → **VPN & Device Management** → Find "GodHand CA" → **Trust Certificate**
4. **Settings** → **WiFi**
5. Tap info icon next to network → **Configure Proxy** → **Automatic**
6. **URL**: `http://pac.installCA.lan/pac`
7. Join network

**Limitations**:
- Requires iOS 14+
- Only Safari and some system apps respect user-installed CA
- Apps with certificate pinning will bypass proxy

### macOS

1. Download CA from `http://pac.installCA.lan/ca-cert`
2. Double-click → **Keychain Access** → Open
3. Search for "GodHand" → Right-click → **Trust**
4. Select **Always Trust**
5. **System Preferences** → **Network** → **WiFi** → **Advanced**
6. **Proxies** tab → Check **Automatic Proxy Configuration**
7. **PAC URL**: `http://pac.installCA.lan/pac`
8. Apply

### Windows

1. Download CA from `http://pac.installCA.lan/ca-cert`
2. Right-click → **Install Certificate**
3. Select **Current User** → **Browse**
4. Choose **Trusted Root Certification Authorities** → **OK** → **Finish**
5. **Settings** → **Network & Internet** → **Proxy**
6. **Automatic proxy configuration** → Enable
7. **PAC URL**: `http://pac.installCA.lan/pac`
8. Save

---

## Monitoring Traffic

### Web UI Dashboard

1. Open browser → `http://192.168.1.X:5000` (GodHand IP)
2. Navigate to **Attacks** tab
3. Scroll to **HTTPS Interception** card
4. Click **🔒 Start Interception**
5. Watch live traffic table update in real-time

### REST API

Get recent traffic:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=50
```

Filter by hostname:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://192.168.1.X:5000/api/https_traffic?hostname_filter=google.com&limit=20"
```

---

## Troubleshooting

### Traffic Not Appearing

**Check list:**
1. Is GodHand proxy running? `curl http://192.168.1.X:5000/api/https_traffic/start`
2. Is CA certificate installed on device? (Settings → Security → Trusted CAs)
3. Is PAC URL correct? Should be `http://pac.installCA.lan/pac`
4. Is device on same network as GodHand? Both on same WiFi?
5. Can device reach GodHand? `adb shell ping 192.168.1.X`

### Certificate Warnings

**Browser shows "Certificate Error" or "Not Secure":**
1. CA not installed on device
2. CA not trusted in device settings
3. Device using old cached cert (clear browser cache)

**Solution:**
```bash
# On device, verify CA is installed
adb shell openssl x509 -in /system/etc/security/cacerts/godhand-ca-cert.pem -text

# Clear Chrome cache
adb shell am start -a android.intent.action.VIEW https://example.com
# (Close Chrome after error, clear cache, reopen)
```

### DNS Not Resolving `.lan` Domains

**Issue**: `pac.installCA.lan` not resolving on device

**Solution**:
1. Ensure DNS is pointing to GodHand device
2. Configure `/etc/dnsmasq.conf` or DNS server for `.lan` domain:
   ```
   address=/installCA.lan/192.168.1.X
   ```
3. Restart dnsmasq: `systemctl restart dnsmasq`
4. On device, flush DNS cache: `adb shell am broadcast -a android.intent.action.BOOT_COMPLETED`

### Connection Timeout (ERR_CONNECTION_TIMED_OUT)

**Issue**: Device can't connect to proxy on port 8888

**Solution:**
1. Check firewall: `sudo iptables -L | grep 8888`
2. Allow port 8888: `sudo iptables -A INPUT -p tcp --dport 8888 -j ACCEPT`
3. Verify listening: `lsof -i :8888`

### App Still Encrypted (Certificate Pinning)

**Issue**: App shows HTTPS error or ignores proxy

**Cause**: App uses certificate pinning (hardcoded expected cert)

**Solution:**
- Use system browser (Chrome, Firefox, Safari) instead
- Try different apps
- Apps with pinning cannot be intercepted (by design)

---

## Uninstalling / Reversing Changes

### Rooted Android

```bash
# Remove CA certificate
adb shell su -c "rm /system/etc/security/cacerts/godhand-ca-cert.pem"

# Reset proxy to none
adb shell settings delete secure http_proxy
adb shell settings delete secure https_proxy
adb shell settings delete secure all_proxy

# Reboot to reload certificate store
adb reboot
```

### Unrooted Android

**Settings** → **Apps & notifications** → **See all apps** → **Google Play Services** (or target app) → **Storage** → **Clear cache & Clear storage**

Or:
**Settings** → **Security** → **Remove installed certificates** → Select "GodHand CA"

### iOS

**Settings** → **General** → **VPN & Device Management** → Select cert → **Delete**

### macOS

**Keychain Access** → Search "GodHand" → Right-click → **Delete**

### Windows

**Settings** → **Manage certificates** → Find "GodHand CA" → Delete from Trusted Root CAs

---

## Project Tegu Scope & Authorization

This infrastructure is authorized for:
- ✅ Personal de-MDM research on own rooted Pixel 9a
- ✅ Testing on your own devices and network
- ✅ Inspection of traffic from test devices you own/control

**Not authorized for:**
- ❌ Intercepting traffic on devices you don't own
- ❌ Intercepting other users' traffic on shared networks
- ❌ Conducting MITM attacks on unauthorized systems

All CA installation is **explicit** (requires user action) and **reversible** (can be removed anytime).

---

## Next Steps

1. **Monitor Traffic** → Use web UI dashboard or REST API to inspect HTTPS traffic
2. **Phase 2 Testing** → Verify CA installation works on multiple devices
3. **Phase 3** → End-to-end validation on real Pixel 9a
4. **Phase 2** → Response injection capability (modify traffic before forwarding)

---

For questions, check GodHand logs:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://192.168.1.X:5000/api/logs
```
