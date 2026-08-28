# Orchestrate: Phone as Remote Access Hub (Pure Open-Source)

## The Vision

Your phone becomes a **self-configuring remote access gateway** with zero proprietary dependencies:

1. **At home**: Run one command, phone scans LAN, deploys clients to devices
2. **Phone leaves**: Relay keeps running, accessible via Dynamic DNS hostname
3. **Anywhere**: Access all home devices via WireGuard VPN or relay URLs

```
┌─────────────────────────────────────────────┐
│  Home Network (192.168.1.0/24)              │
│                                             │
│  NAS          Gaming Rig      Media Server  │
│  ├─ Movies   ├─ SSH (22)      ├─ Plex      │
│  └─ Photos   └─ HTTP (8080)   └─ Web (80)  │
│       ↓             ↓              ↓        │
│  ┌─────────────────────────────────────┐   │
│  │    Phone (Relay)                    │   │
│  │  Hostname: myphone.duckdns.org      │   │
│  │  Token: abc123...                   │   │
│  │  Port 9000: control                 │   │
│  │  Port 8080: HTTP proxy              │   │
│  └─────────────────────────────────────┘   │
│       ↓ (can roam to any network)          │
└───────┼─────────────────────────────────────┘
        │
    Dynamic DNS (myphone.duckdns.org)
    (always resolves to current IP)
        │
   ┌────┴─────┐
   ↓          ↓
[Laptop]   [Phone on Mobile Data]
(VPN)      (new IP, same hostname)
Access via WireGuard VPN
```

## Key Concept: Dynamic DNS

**Problem**: Phone's IP changes when it leaves home (192.168.1.50 → 118.123.45.67)
- Targets deployed with home IP lose connection
- Clients can't reach relay at new IP

**Solution**: Dynamic DNS provides a stable **hostname** that updates automatically
- Phone's IP changes constantly (doesn't matter!)
- `myphone.duckdns.org` always points to current IP
- All targets reconnect automatically via hostname lookup
- DNS updates every 5 minutes via auto-update script

## Dynamic DNS Options (All Open-Source Friendly)

### Option 1: DuckDNS (Recommended - Fastest to Setup)

Free, no credit card required, simple API:

```bash
# 1. Sign up (5 seconds)
# Go to https://www.duckdns.org
# Click login with GitHub/Google
# Create domain: myphone

# 2. Get your token from dashboard
TOKEN="xxxxxxxxxxxxxxxx"

# 3. Test DDNS update
curl "https://www.duckdns.org/update?domains=myphone&token=$TOKEN&ip="

# 4. Keep updated automatically (run on phone)
# See "Auto-Update Script" section below
```

### Option 2: Self-Hosted (Complete Control)

If you want everything on your own servers:

```bash
# Use any home server with a static IP
# Set up bind9 DNS or dnsmasq
# Point A record to relay device

# Simple dnsmasq setup on router:
# address=/relay.local.example.com/192.168.1.50
# address=/relay.example.com/203.0.113.10  # Public IP
```

### Option 3: Other DDNS Services (All Open-Source Compatible)

- **Cloudflare**: Dynamic DNS via API token
- **No-IP**: Free DDNS hostname + update client
- **freedns.afraid.org**: Hosted on community servers
- **homeDNS**: Self-hosted, open-source
- **AdGuard Home**: Self-hosted with DDNS support

## Quick Start

### Step 1: Install DDNS Auto-Update on Phone

```bash
# Create update script on your phone
cat > /home/user/ddns-update.sh << 'EOF'
#!/bin/bash
# Auto-update Dynamic DNS when IP changes
# Run this every 5 minutes via cron

DOMAIN="myphone"
TOKEN="your-duckdns-token"
CACHE_FILE="/tmp/duckdns-last-ip"

# Get current public IP
CURRENT_IP=$(curl -s ifconfig.me 2>/dev/null)

# Read last IP from cache
LAST_IP=$(cat "$CACHE_FILE" 2>/dev/null || echo "")

# Only update if IP changed
if [ "$CURRENT_IP" != "$LAST_IP" ]; then
    echo "[$(date)] IP changed: $LAST_IP → $CURRENT_IP"
    
    # Update DuckDNS
    curl -s "https://www.duckdns.org/update?domains=$DOMAIN&token=$TOKEN&ip=$CURRENT_IP"
    
    # Cache new IP
    echo "$CURRENT_IP" > "$CACHE_FILE"
else
    echo "[$(date)] IP unchanged: $CURRENT_IP"
fi
EOF

chmod +x /home/user/ddns-update.sh

# Test it
./ddns-update.sh
# Output should show successful update
```

### Step 2: Schedule Auto-Updates with Cron

```bash
# Edit crontab
crontab -e

# Add this line to run every 5 minutes
*/5 * * * * /home/user/ddns-update.sh >> /tmp/ddns-update.log 2>&1
```

### Step 3: Run Orchestrate Command

```bash
python3 ngrok_tunnel.py orchestrate
```

This interactive wizard will:

1. **Setup DDNS Configuration**
   ```
   Options:
   1. Configure new DuckDNS domain
   2. Use existing DDNS hostname
   3. Manual IP/hostname entry
   
   Choose: 1
   ✓ DuckDNS domain: myphone
   ✓ Token configured
   ✓ Auto-update script installed
   ```

2. **Generate relay credentials**
   ```
   Token: xyz789...
   Control Port: 9000
   HTTP Port: 8080
   ```

3. **Scan LAN for devices**
   ```
   Found 4 devices:
   [1] 192.168.1.10 (NAS) - ports: 445, 8080
   [2] 192.168.1.20 (Gaming PC) - ports: 22, 3389
   [3] 192.168.1.30 (Media Server) - ports: 32400, 80
   [4] 192.168.1.40 (Printer) - ports: 9100
   ```

4. **Select targets to expose**
   ```
   Device numbers (e.g. 1,2,3): 1,2,3
   ✓ Selected 3 devices
   ```

5. **Review orchestration plan**
   ```
   Phone (Relay):
     • Hostname: myphone.duckdns.org
     • Control: myphone.duckdns.org:9000
     • Token: xyz789...
     • Auto-update: enabled (every 5 min)
   
   Targets:
     1. NAS (192.168.1.10) → tunnel
     2. Gaming PC (192.168.1.20) → tunnel
     3. Media Server (192.168.1.30) → tunnel
   ```

6. **Relay starts running**
   ```
   Starting relay server...
   ✓ Relay running on 0.0.0.0:9000
   ✓ Script server on http://192.168.1.XXX:8765
   ✓ DDNS auto-update enabled
   ```

### Step 4: Deploy Clients (Manual SSH to each target)

**SSH into each target and run:**

```bash
# On NAS
ssh user@192.168.1.10

# Download ngrok_tunnel.py
curl -fsSL http://192.168.1.XXX:8765/ngrok_tunnel.py -o ngrok_tunnel.py

# Create tunnel (HTTP example)
nohup python3 ngrok_tunnel.py http 8080 \
    --server myphone.duckdns.org:9000 \
    --token 'xyz789...' \
    --subdomain nas > tunnel.log 2>&1 &

# Verify
tail tunnel.log
```

Repeat for each target device, adjusting the port and subdomain.

### Step 5: Setup WireGuard VPN (on phone, requires sudo)

```bash
# While relay is still running at home:
sudo python3 ngrok_tunnel.py vpn-server \
    --wg-interface wg0 \
    --wg-subnet 10.0.0.0/24 \
    --listen-port 51820

# Save the output! You need the server public key.
```

### Step 6: Generate VPN Client Config

```bash
# On phone:
python3 ngrok_tunnel.py vpn-client \
    --server myphone.duckdns.org \
    --output mobile-vpn.conf

chmod 600 mobile-vpn.conf
```

### Step 7: Connect VPN from Remote

**On your laptop:**

```bash
# Linux/macOS
sudo wg-quick up ./mobile-vpn.conf

# Verify VPN IP (should be 10.0.0.x)
ip addr show wg0

# Access tunneled services
curl http://nas.myphone.duckdns.org:8080
ssh -p 2222 user@myphone.duckdns.org
```

### Step 8: Leave Home

Phone disconnects from home WiFi, switches to mobile data or coffee shop WiFi.

- Old IP: `192.168.1.50` (irrelevant)
- New IP: `118.123.45.67` (constantly changing)
- DDNS Hostname: `myphone.duckdns.org` (always same)

Auto-update script keeps DNS pointing to new IP. All tunnels reconnect automatically.

### Step 9: Access from Anywhere

**From coffee shop with Tailscale on laptop:**

```bash
# Connect VPN (uses DDNS hostname)
sudo wg-quick up ./mobile-vpn.conf

# Access home services from anywhere
curl http://nas.myphone.duckdns.org:8080  # NAS web UI
ssh -p 2222 user@myphone.duckdns.org      # Gaming PC SSH
open http://myphone.duckdns.org:8080/plex # Media Server

# Monitor relay
curl myphone.duckdns.org:8080/metrics | jq
```

## Architecture Deep Dive

### Why Dynamic DNS?

**Advantages:**
- Stable **hostname** (not IP)
- Works on any network (home WiFi, mobile hotspot, coffee shop)
- Open-source auto-update script
- Free (DuckDNS) or self-hosted (dnsmasq, bind9)
- Targets reconnect automatically via DNS lookup
- No proprietary mesh network required

**How it works:**
1. Phone runs auto-update script every 5 minutes
2. Script detects IP change (via `curl ifconfig.me`)
3. Posts new IP to DDNS service (DuckDNS API)
4. DNS records update globally
5. All clients automatically resolve new IP
6. Connections re-establish without manual intervention

### Data Flow

```
Target Device (192.168.1.10) sends data to relay:
  ↓
  [Tunnel Client] → "myphone.duckdns.org:9000"
  ↓
  [DNS Lookup] → resolves to current relay IP
  ↓
  [Network] → routes to current relay location
  ↓
  [Relay Server] on phone receives data
  ↓
  [Phone] forwards to target service
  ↓
  [WireGuard VPN] encrypts response
  ↓
  [Remote Client] receives data via VPN
```

### Why Not Tailscale/Zerotier/Other Mesh VPNs?

- **Proprietary**: Requires vendor infrastructure
- **Opaque**: Can't audit network behavior
- **Dependency**: If vendor service down, network down
- **Lock-in**: Switching providers painful

**Our approach:**
- **100% Open-Source**: WireGuard (kernel module) + DDNS script
- **Transparent**: You understand every byte flowing
- **Self-Hosted**: No vendor lock-in
- **Resilient**: Works with any DNS provider or self-hosted DNS

## Complete Orchestrate Workflow

### Timeline

**T=0min (At home, on WiFi)**
```
$ python3 ngrok_tunnel.py orchestrate
✓ DDNS domain: myphone.duckdns.org
✓ Token generated
✓ Auto-update script installed (cron enabled)
✓ Scanned LAN (found 4 devices)
✓ User selected 3 targets
✓ Relay running on :9000
✓ Waiting for manual client deployment
```

**T=5min (Deploy clients)**
```
$ ssh user@192.168.1.10  # NAS
$ curl ... ngrok_tunnel.py
$ python3 ngrok_tunnel.py http 8080 --server myphone.duckdns.org:9000 --token ...
✓ Tunnel created: NAS → Relay

(Repeat for other targets...)
```

**T=15min (Setup WireGuard)**
```
$ sudo python3 ngrok_tunnel.py vpn-server ...
✓ WireGuard up on port 51820

$ python3 ngrok_tunnel.py vpn-client --server myphone.duckdns.org --output vpn.conf
✓ Client config generated
```

**T=30min (Phone leaves home)**
```
Phone disconnects from home WiFi
Switches to mobile data
Old IP: 192.168.1.50 (irrelevant)
New IP: 118.123.45.67 (just got assigned)
Auto-update script runs, updates DuckDNS:
  myphone.duckdns.org → 118.123.45.67

All targets automatically reconnect!
```

**T=30min+1sec (From anywhere)**
```
Laptop with VPN connected
$ curl http://nas.myphone.duckdns.org:8080  ✓
$ ssh user@myphone.duckdns.org -p 2222     ✓
$ open http://myphone.duckdns.org:8080/plex ✓

All services accessible!
```

## Security Checklist

- [x] Strong token generated (use `gen-token`)
- [x] DDNS hostname is stable but DNS is public (anyone can resolve)
- [x] Token must match on relay & clients (authentication)
- [x] Tunnel traffic encrypted by WireGuard (if VPN enabled)
- [x] Session timeout prevents stale connections
- [x] Each service protected by individual tunnel + token
- [x] Auto-update script runs as unprivileged user
- [x] DDNS token stored securely (not in repo)
- [x] Never expose token publicly (share only with targets)

## Troubleshooting

**Q: DDNS not updating**
```bash
# Check auto-update script
cat /tmp/ddns-update.log

# Manually test
./ddns-update.sh

# Verify cron is running
crontab -l

# Check public IP changed
curl ifconfig.me
```

**Q: Clients can't connect after phone leaves home**
```bash
# Verify DDNS resolves to new IP
nslookup myphone.duckdns.org

# Check relay is still running
curl myphone.duckdns.org:8080/health

# Restart tunnel client with hostname instead of IP
python3 ngrok_tunnel.py http 8080 \
    --server myphone.duckdns.org:9000 \
    --token 'xyz789...'
```

**Q: VPN won't connect after relay moves**
```bash
# VPN config has hostname, should auto-resolve
# If stuck, regenerate config with new IP:
python3 ngrok_tunnel.py vpn-client \
    --server myphone.duckdns.org \
    --output vpn-updated.conf

# Reconnect
sudo wg-quick down ./mobile-vpn.conf
sudo wg-quick up ./vpn-updated.conf
```

## Advanced: Multiple Phones (Failover)

Deploy relay on two phones for redundancy:

```bash
# Phone 1 (primary)
python3 ngrok_tunnel.py orchestrate
# Generates: phone1.duckdns.org

# Phone 2 (backup)
python3 ngrok_tunnel.py orchestrate
# Generates: phone2.duckdns.org
```

Deploy some clients to Phone 1, others to Phone 2:

```bash
# NAS → Phone 1
python3 ngrok_tunnel.py http 8080 \
    --server phone1.duckdns.org:9000 \
    --token 'token1'

# Gaming PC → Phone 2
python3 ngrok_tunnel.py tcp 22 \
    --server phone2.duckdns.org:9000 \
    --token 'token2'
```

Now if Phone 1 dies, Phone 2 still has gaming PC access.

## The "Set It and Forget It" Promise

After running orchestrate once:

1. ✓ Relay keeps running 24/7 on phone (leave it at home)
2. ✓ Clients auto-connect and reconnect if dropped
3. ✓ DDNS keeps hostname updated (auto-update script runs every 5 min)
4. ✓ You access everything from anywhere
5. ✓ No manual reconfiguration needed
6. ✓ Works on any network (WiFi, mobile, wired, VPN)

The only moving part is the phone's network - DDNS handles that transparently.

## Next Steps

- [x] Install DDNS auto-update script
- [x] Run orchestrate command
- [x] SSH deploy clients manually
- [ ] Leave home and test access
- [ ] Verify DDNS updates correctly
- [ ] Setup WireGuard VPN
- [ ] Connect VPN from remote
- [ ] Add rescue mode for admin access
- [ ] Monitor relay with /metrics endpoint

This is the ultimate "phone as gateway" setup. Everything is self-contained, open-source, encrypted, and just works. 🚀
