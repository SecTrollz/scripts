# Phase 3: HTTPS Interception Validation & End-to-End Testing

**Complete testing procedures and validation checklists for real-world HTTPS interception on Android, iOS, macOS, and Windows devices.**

---

## Overview

Phase 3 validates that HTTPS interception works end-to-end on real devices:
1. **Setup validation**: Verify infrastructure is correctly configured
2. **Single device testing**: Pixel 9a (rooted) as primary test device
3. **Multi-device testing**: Secondary devices (iOS, macOS, Windows)
4. **Stress testing**: Multiple concurrent connections and high-volume traffic
5. **Edge case testing**: Certificate pinning, app-specific proxies, etc.

---

## Phase 3.1: End-to-End Test on Pixel 9a (Rooted)

### Prerequisites
- Rooted Pixel 9a with adb access
- GodHand running on rooted device or accessible via network
- CA certificate installed (Phase 2.1)
- PAC proxy configured (Phase 2.2)
- Chrome or Firefox browser installed

### 3.1.1 Infrastructure Startup Validation

**Checklist:**
```
□ GodHand service running:
  adb shell ps | grep -i godhand
  Expected: Python process listening on port 5000

□ CA certificate present:
  adb shell ls -la /system/etc/security/cacerts/ | grep godhand
  Expected: godhand-ca-cert.pem with -rw-r--r-- permissions

□ MITM proxy service started:
  adb shell curl -s http://localhost:5000/api/state | jq '.status'
  Expected: "Ready" or similar

□ PAC server accessible:
  adb shell curl -s http://localhost/pac | head -1
  Expected: "function FindProxyForURL(url, host) {"

□ Network connectivity:
  adb shell ping -c 3 8.8.8.8
  Expected: 3 packets transmitted, 3 received, 0% packet loss
```

### 3.1.2 Basic HTTPS Interception Test

**Test Case 1: Single HTTP Request**

**Setup:**
```bash
# On development machine
adb shell
# On Pixel 9a shell:
curl http://example.com -v
```

**Expected Output:**
```
* Connected to example.com (192.0.2.1) port 80 (#0)
> GET / HTTP/1.1
> Host: example.com
< HTTP/1.1 200 OK
< Content-Type: text/html
```

**Validation in GodHand:**
```bash
# On development machine
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=5 | jq '.entries[] | select(.hostname=="example.com")'

# Expected:
# {
#   "timestamp": "2026-08-22T...",
#   "type": "request",
#   "client_ip": "192.168.1.PIXEL",
#   "hostname": "example.com",
#   "method": "GET",
#   "path": "/",
#   ...
# }
```

**Test Case 2: Single HTTPS Request**

**Setup:**
```bash
# On Pixel 9a:
chrome --args https://example.com &
# Or via adb from dev machine:
adb shell am start -a android.intent.action.VIEW https://example.com
```

**Expected Behavior:**
1. Chrome opens and navigates to https://example.com
2. No certificate warning (CA is trusted)
3. Page loads normally
4. Address bar shows green lock icon

**Validation in GodHand:**
```bash
# Check traffic log
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?hostname_filter=example.com | jq '.'

# Expected to see both:
# 1. Request: method=GET, hostname=example.com, path=/
# 2. Response: status=200, bytes=12345 (approx)
```

**Validation in Web UI:**
```
1. Open http://192.168.1.X:5000 (GodHand web UI)
2. Navigate to Attacks tab
3. Scroll to "HTTPS Interception" card
4. Verify "🔒 Start Interception" is running (green status)
5. Watch live traffic table
6. Should see rows:
   Timestamp | → request | example.com | GET | 192.168.1.PIXEL
   Timestamp | ← response | example.com | 200 | 192.168.1.PIXEL
```

### 3.1.3 Multi-Request Test

**Test Case 3: Multiple Concurrent HTTPS Requests**

**Setup:**
```bash
# Open multiple Chrome tabs on Pixel 9a, navigate to:
# 1. https://www.google.com
# 2. https://www.github.com
# 3. https://www.wikipedia.org
# 4. https://www.youtube.com
# 5. https://www.amazon.com
```

**Expected Results:**
- All sites load without certificate errors
- All pages render correctly
- No hangs or timeouts

**Validation:**
```bash
# Check GodHand traffic log
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=50 | jq '.entries | length'

# Expected: Minimum 10+ entries (2 per site: request + response)
# Should see hostnames: google.com, github.com, wikipedia.org, youtube.com, amazon.com
```

### 3.1.4 Traffic Inspection Validation

**Test Case 4: Verify Logged Fields**

**Setup:**
Navigate to https://example.com on Pixel 9a

**Validation - Check all required fields:**
```bash
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=1 | jq '.entries[0]'

# Expected output includes:
{
  "timestamp": "2026-08-22T03:30:45Z",      # ✓ ISO 8601 format
  "type": "request",                         # ✓ "request" or "response"
  "client_ip": "192.168.1.PIXEL",           # ✓ Device IP
  "hostname": "example.com",                 # ✓ SNI hostname
  "method": "GET",                           # ✓ HTTP method (requests only)
  "path": "/",                               # ✓ Request path (requests only)
  "status": null,                            # ✓ null for requests, 200/301/etc for responses
  "bytes": 1234                              # ✓ Response body size
}
```

### 3.1.5 High-Volume Traffic Test

**Test Case 5: Sustained Traffic (5+ Minutes)**

**Setup:**
```bash
# On Pixel 9a, run continuous traffic generation:
while true; do
  curl -s https://example.com > /dev/null
  curl -s https://google.com > /dev/null
  curl -s https://github.com > /dev/null
  sleep 1
done
```

**Expected Results:**
- All requests succeed
- No proxy crashes or hangs
- No memory leaks (memory usage stays stable)
- No dropped packets

**Validation:**
```bash
# Check entry count after 5 minutes (should be ~30+ entries)
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=100 | jq '.entries | length'

# Monitor GodHand memory usage
adb shell "top -n 1 | grep godhand"
# Expected: Stable memory usage (not growing over time)

# Check for errors in logs
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/logs | jq '.[] | select(.level=="error")'
# Expected: No entries (or only unrelated errors)
```

### 3.1.6 Certificate Validation Test

**Test Case 6: HTTPS Site Certificate Chain**

**Setup:**
Navigate to multiple HTTPS sites with different certificate types:
1. Let's Encrypt (common free cert)
2. DigiCert (major CA)
3. Self-signed (some IoT devices)

**Expected Behavior:**
- All sites load with green lock icon
- No certificate warnings
- Address bar shows "Secure"

**Technical Validation:**
```bash
# Extract certificate from traffic and verify chain
curl -s https://example.com 2>&1 | openssl s_client -connect example.com:443 | \
  openssl x509 -noout -text | grep -A5 "Issuer:"

# Expected: Issuer should show "GodHand CA" (our intercepting certificate)
```

---

## Phase 3.2: Multi-Device Testing

### Secondary Device Testing Plan

**Devices to Test (if available):**
- [ ] iPhone (iOS 14+)
- [ ] iPad (iPadOS 14+)
- [ ] MacBook (macOS 10.15+)
- [ ] Windows 10/11 PC
- [ ] Android tablet (unrooted)
- [ ] Pixel 8 (different Android version)

### 3.2.1 iOS Testing (iPhone)

**Prerequisites:**
- CA certificate installed (Phase 2.1)
- PAC proxy configured (Phase 2.2)
- Safari or other app with system proxy support

**Test Procedure:**
```
1. Open Safari
2. Navigate to https://www.example.com
3. Verify page loads with green lock icon
4. Navigate to 5+ HTTPS sites
5. Check GodHand traffic log for traffic from iPhone IP
```

**Expected Output:**
```bash
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=20 | jq '.entries[] | select(.client_ip=="192.168.1.IPHONE")'

# Should show multiple entries from iPhone
```

**iOS-Specific Issues to Watch For:**
- App certificate pinning (some apps won't work)
- Limited to Safari and system apps
- May require repeated cert installation

### 3.2.2 macOS Testing (MacBook)

**Prerequisites:**
- CA certificate in Keychain (Phase 2.1)
- PAC or manual proxy configured (Phase 2.2)

**Test Procedure:**
```bash
# Open Safari and test
open -a Safari https://www.example.com

# Or use curl with proxy
curl -x 192.168.1.X:8888 https://www.example.com -v
```

**Expected Results:**
- Full OS-wide HTTPS interception
- All apps should route through proxy
- Safari, Chrome, Firefox all work

### 3.2.3 Windows Testing

**Prerequisites:**
- CA certificate installed in Trusted Root CA (Phase 2.1)
- PAC or manual proxy configured (Phase 2.2)

**Test Procedure:**
```powershell
# PowerShell test
Invoke-WebRequest https://www.example.com -Proxy "http://192.168.1.X:8888"

# Or via browser
# Open Edge/Chrome and navigate to HTTPS sites
```

**Expected Results:**
- All requests succeed
- No certificate errors
- Can see traffic in GodHand logs

### 3.2.4 Concurrent Multi-Device Test

**Test Case: 3+ Devices Simultaneously**

**Setup:**
Start traffic from 3 different devices at same time:
```
Device 1 (Pixel 9a):  curl loop for 10 requests
Device 2 (iPhone):    Navigate to 5 HTTPS sites in Safari
Device 3 (Mac):       Open browser and click random links
```

**Validation:**
```bash
# Count traffic entries by device IP
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=200 | jq '.entries | group_by(.client_ip) | map({ip: .[0].client_ip, count: length})'

# Expected: See entries from 3 different device IPs
```

---

## Phase 3.3: Edge Case & Stress Testing

### 3.3.1 Certificate Pinning Test

**Setup:** Navigate to apps/sites with certificate pinning:
- Twitter app (pins certificates)
- Gmail app (may pin)
- Banking apps (usually pin)

**Expected Behavior:**
- Apps with pinning will reject proxy (expected)
- System browser (Safari, Chrome) should work fine
- This is normal and expected behavior

**Validation:**
```bash
# Try accessing Twitter via system browser (should work)
# Try Twitter app (will likely fail with "Cannot connect")
# This is correct - certificate pinning prevents MITM

# Browser should work:
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?hostname_filter=twitter.com
# Should show traffic
```

### 3.3.2 High Bandwidth Test

**Setup:**
Download large file (100MB+) from Pixel 9a:
```bash
adb shell wget https://speed.cloudflare.com/__down -O /tmp/download.bin
```

**Expected:**
- File downloads without errors
- No proxy timeouts or hangs
- Traffic logged successfully

**Validation:**
```bash
# Check file downloaded
adb shell ls -lh /tmp/download.bin
# Expected: 100MB+ file present

# Check proxy logs don't show errors
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/logs | jq '.[] | select(.level=="error")'
# Expected: Minimal errors (proxy should handle large transfers)
```

### 3.3.3 Rapid Connection Test

**Setup:**
Open 50 HTTPS sites rapidly on Pixel 9a:
```bash
for i in {1..50}; do
  curl -s "https://example.com/$i" > /dev/null &
done
wait
```

**Expected:**
- All requests succeed
- Proxy doesn't crash
- No connection refused errors

**Validation:**
```bash
# Check entry count (should be 100+ for 50 requests)
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/https_traffic?limit=150 | jq '.entries | length'
# Expected: 100+
```

---

## Phase 3 Validation Checklist

### Infrastructure
- [ ] GodHand service running and responsive
- [ ] CA certificate present and readable
- [ ] PAC file accessible via pac.installCA.lan
- [ ] Port 8888 listening and accepting connections
- [ ] Traffic logging working (entries appear in logs)

### Single Device (Pixel 9a)
- [ ] HTTP requests logged (http://example.com)
- [ ] HTTPS requests logged (https://example.com)
- [ ] Certificate chain shows "GodHand CA" as issuer
- [ ] No certificate warnings on HTTPS sites
- [ ] All requested fields present in logs (timestamp, method, hostname, etc.)
- [ ] 5+ concurrent requests handled correctly
- [ ] 5+ minute sustained traffic test passes
- [ ] No memory leaks or service crashes

### Multi-Device
- [ ] iOS device routes through proxy and logs traffic
- [ ] macOS device routes through proxy and logs traffic
- [ ] Windows device routes through proxy and logs traffic
- [ ] Concurrent multi-device test shows traffic from 3+ device IPs
- [ ] Web UI live traffic table updates in real-time for all devices

### Edge Cases
- [ ] Certificate pinning apps reject proxy (expected)
- [ ] High bandwidth transfer (100MB+) succeeds
- [ ] Rapid connection test (50+ concurrent) succeeds
- [ ] No significant errors in logs during stress testing
- [ ] Memory usage remains stable under sustained load

### Documentation
- [ ] All test results documented
- [ ] Any failures documented with root cause
- [ ] Performance metrics recorded
- [ ] Known limitations documented

---

## Troubleshooting During Validation

### Issue: Traffic Not Appearing in Logs

**Diagnostics:**
```bash
# 1. Verify proxy is running
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/state

# 2. Test device connectivity to proxy
adb shell nc -zv 192.168.1.X 8888
# Expected: Connection successful

# 3. Check if device reached proxy
# Look for connection attempts in logs
curl -H "Authorization: Bearer TOKEN" \
  http://192.168.1.X:5000/api/logs | grep -i "accept\|connect"
```

### Issue: Certificate Warnings on Device

**Diagnostics:**
```bash
# 1. Verify CA is installed
adb shell ls /system/etc/security/cacerts/godhand*

# 2. Check CA cert hash
adb shell openssl x509 -in /system/etc/security/cacerts/godhand-ca-cert.pem \
  -noout -subject_hash_old
```

### Issue: Proxy Crashes Under Load

**Diagnostics:**
```bash
# 1. Check if proxy is still running
adb shell ps | grep godhand

# 2. Check system resource usage
adb shell free -h
adb shell df -h

# 3. Look for error messages in logs
adb shell tail -f /var/log/godhand-https-traffic.log
```

---

## Performance Metrics to Track

| Metric | Acceptable Range | Warning Threshold |
|--------|------------------|-------------------|
| Request latency | <500ms | >1000ms |
| Proxy memory usage | <100MB | >300MB |
| Traffic log size | <50MB (per hour) | >100MB/hour |
| Concurrent connections | >50 | <20 |
| Packet loss | 0% | >1% |
| CPU usage | <50% | >80% |

---

## Next Steps

After Phase 3 validation passes:

1. **Document Findings:** Record all test results, metrics, and issues found
2. **Fix Issues:** Address any bugs or limitations discovered
3. **Phase 4:** Documentation cleanup and UI enhancements
4. **Phase 5:** Response injection capability (modify traffic in-flight)

---

For detailed setup instructions, see:
- [HTTPS_SETUP_GUIDE.md](HTTPS_SETUP_GUIDE.md) - CA installation
- [PAC_CONFIGURATION_GUIDE.md](PAC_CONFIGURATION_GUIDE.md) - Proxy configuration
