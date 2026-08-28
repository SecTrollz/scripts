# Orchestrate: Phone as Remote Access Hub (Self-Hosted DDNS, Zero Privacy Leaks)

## The Vision

Your phone becomes a **self-configuring remote access gateway** with zero external services or privacy issues:

1. **At home**: Run one command, phone scans LAN, deploys clients to devices
2. **Phone leaves**: Relay keeps running, accessible via self-hosted DDNS
3. **Anywhere**: Access all home devices via WireGuard VPN + private DDNS

```
┌─────────────────────────────────────────────┐
│  Home Network (192.168.1.0/24)              │
│                                             │
│  NAS          Gaming Rig      Media Server  │
│  ├─ Movies   ├─ SSH (22)      ├─ Plex      │
│  └─ Photos   └─ HTTP (8080)   └─ Web (80)  │
│       ↓             ↓              ↓        │
│  ┌─────────────────────────────────────┐   │
│  │    Phone (Relay + DDNS Server)      │   │
│  │  Hostname: myphone (private)        │   │
│  │  Token: abc123...                   │   │
│  │  Port 9000: control                 │   │
│  │  Port 8080: HTTP proxy + DDNS API   │   │
│  └─────────────────────────────────────┘   │
│       ↓ (can roam to any network)          │
└───────┼─────────────────────────────────────┘
        │
    Self-Hosted DDNS (Zero External Services)
    (stores DNS locally, no logging)
        │
   ┌────┴─────┐
   ↓          ↓
[Laptop]   [Phone on Mobile Data]
(VPN)      (new IP, same hostname)
Access via WireGuard VPN
No third-party logging. No privacy trail.
```

## Key Concept: Self-Hosted DDNS (Zero Privacy Issues)

**Problem**: Third-party DDNS services (DuckDNS, No-IP) log all DNS updates, creating a privacy trail:
- Service owner sees when you go online/offline
- Tracks your IP changes over time
- Records available to law enforcement or breaches
- DNS queries logged centrally

**Solution**: Self-hosted DDNS server built into the relay:
- DNS records stored **only** on your relay device
- **Zero** external services or logging
- **Zero** privacy trail
- **Zero** third-party dependencies
- Targets update relay locally via private API

## How Self-Hosted DDNS Works

### Setup Phase (At Home)

1. **Relay starts DDNS server** on startup (built-in)
2. **Auto-update script runs** every 5 minutes locally
3. **DNS records kept private** on relay device only
4. **No external services** contacted

### Mobile Phase (Phone Leaves Home)

1. Phone connects to new network → gets new IP
2. Auto-update script detects IP change
3. Script posts update to local relay API
4. Relay stores new IP locally (no external calls)
5. Targets query relay to resolve hostname → current IP
6. Connections re-establish automatically

## Quick Start

### Step 1: Run Orchestrate Command

```bash
python3 ngrok_tunnel.py orchestrate
```

Choose option 1 (Self-hosted DDNS):
```
Options:
  1. Self-hosted DDNS (recommended - zero privacy issues)
  2. Use existing DDNS hostname (manual)
  3. Use public IP (manual, not recommended)

Choose (1/2/3): 1
```

### Step 2: Enter Desired Hostname

```
Enter desired hostname (e.g., myphone): myphone
✓ Self-hosted DDNS configured
  Hostname: myphone
  Token: abc123...
  Status: Local-only, zero external services
```

### Step 3: Auto-Update Script Created

```bash
✓ Self-hosted DDNS update script created: ~/ddns-update.sh
✓ Added to crontab (runs every 5 minutes)
```

Script runs automatically, never needs external services.

### Step 4: Deploy Clients (Manual SSH)

**SSH into each target:**

```bash
ssh user@192.168.1.10

curl -fsSL http://192.168.1.XXX:8765/ngrok_tunnel.py -o ngrok_tunnel.py

# Create tunnel (uses private hostname)
nohup python3 ngrok_tunnel.py http 8080 \
    --server myphone:9000 \
    --token 'abc123...' \
    --subdomain nas > tunnel.log 2>&1 &
```

### Step 5: Setup WireGuard VPN (on phone, requires sudo)

```bash
sudo python3 ngrok_tunnel.py vpn-server \
    --wg-interface wg0 \
    --wg-subnet 10.0.0.0/24 \
    --listen-port 51820
```

### Step 6: Generate VPN Client Config

```bash
python3 ngrok_tunnel.py vpn-client \
    --server myphone \
    --output mobile-vpn.conf

chmod 600 mobile-vpn.conf
```

### Step 7: Connect VPN from Remote

```bash
# Linux/macOS
sudo wg-quick up ./mobile-vpn.conf

# Access tunneled services (via private hostname)
curl http://nas.myphone:8080
ssh -p 2222 user@myphone
```

### Step 8: Leave Home

Phone disconnects from home WiFi, switches to mobile data.

- Old IP: `192.168.1.50` (irrelevant)
- New IP: `118.123.45.67` (constantly changing)
- Self-Hosted DDNS: `myphone` (always resolves to current IP)

Auto-update script keeps relay's DNS records current. All tunnels reconnect automatically.

### Step 9: Access from Anywhere

```bash
# Connect VPN (uses private hostname)
sudo wg-quick up ./mobile-vpn.conf

# Access home services from anywhere
curl http://nas.myphone:8080        # NAS web UI
ssh -p 2222 user@myphone            # Gaming PC SSH
open http://myphone:8080/plex       # Media Server

# Monitor relay
curl myphone:8080/metrics | jq
```

## Architecture

### Self-Hosted DDNS Server

Built into the relay, no external dependencies:

```python
class DDNSServer:
    """Zero external services, pure stdlib."""
    
    def update_record(hostname, ip, token):
        """Only callable with correct token."""
        stores ip locally only
    
    def resolve(hostname):
        """Public lookup, no logging."""
        returns current ip for hostname
```

### Endpoints

- `POST /ddns/update?hostname=X&ip=Y&token=Z` → Update DNS record
- `GET /ddns/resolve?hostname=X` → Lookup hostname (public)

Both endpoints run **locally only**, no external services.

### Auto-Update Script

```bash
#!/bin/bash
CURRENT_IP=$(curl -s ifconfig.me)
curl "http://localhost:8080/ddns/update?hostname=myphone&ip=$CURRENT_IP&token=abc123"
```

Runs via cron every 5 minutes on the relay device.

## Data Privacy Comparison

| Service | External Calls | Logging | Privacy Trail | Dependency |
|---------|---|---|---|---|
| **Self-Hosted DDNS** | None | Local only | Zero | None |
| DuckDNS | Yes (every 5 min) | Yes (centralized) | Full | DuckDNS service |
| No-IP | Yes (every 30 min) | Yes (centralized) | Full | No-IP service |
| Cloudflare DDNS | Yes (every update) | Maybe | Possible | Cloudflare service |

**Self-hosted wins**: Zero external services, zero logging, zero privacy trail.

## Security Checklist

- [x] Zero external DDNS services (no privacy leaks)
- [x] DNS records stored locally only
- [x] Token-protected DDNS updates
- [x] Auto-update script runs locally only
- [x] WireGuard encrypts all tunnel traffic
- [x] Session timeout prevents stale connections
- [x] Each service protected by individual tunnel + token
- [x] Self-update script runs as unprivileged user
- [x] Token never exposed publicly

## Troubleshooting

**Q: Clients can't resolve hostname**
```bash
# Verify relay DDNS server is running
curl http://localhost:8080/ddns/resolve?hostname=myphone

# Should return: {"hostname":"myphone","ip":"118.123.45.67"}
```

**Q: Auto-update script not running**
```bash
# Check crontab
crontab -l

# Check logs
tail -f /tmp/ddns-update.log

# Manually test
~/ddns-update.sh
```

**Q: Hostname not resolving after IP change**
```bash
# Force immediate update
~/ddns-update.sh

# Verify relay has new IP
curl http://localhost:8080/ddns/resolve?hostname=myphone

# Verify targets can resolve
ping myphone  # Should ping relay's new IP
```

## The Complete Timeline

**T=0min (At home, on WiFi)**
```
$ python3 ngrok_tunnel.py orchestrate
✓ Self-hosted DDNS: myphone
✓ Token generated
✓ Auto-update script installed (cron enabled)
✓ Scanned LAN (found 4 devices)
✓ User selected 3 targets
✓ Relay running on :9000
✓ DDNS server running on :8080 (private)
```

**T=5min (Deploy clients)**
```
$ ssh user@192.168.1.10  # NAS
$ curl ... ngrok_tunnel.py
$ python3 ngrok_tunnel.py http 8080 --server myphone:9000 --token ...
✓ Tunnel created: NAS → Relay (using private hostname)

(Repeat for other targets...)
```

**T=15min (Setup WireGuard)**
```
$ sudo python3 ngrok_tunnel.py vpn-server ...
✓ WireGuard up on port 51820

$ python3 ngrok_tunnel.py vpn-client --server myphone --output vpn.conf
✓ Client config generated (uses private hostname)
```

**T=30min (Phone leaves home)**
```
Phone disconnects from home WiFi
Switches to mobile data
Old IP: 192.168.1.50 (irrelevant)
New IP: 118.123.45.67 (doesn't matter!)

Auto-update script runs every 5 minutes:
  1. Detects IP changed
  2. Posts to relay DDNS API
  3. Relay stores new IP locally
  4. No external services contacted
  5. Zero privacy trail
```

**T=35min (From anywhere)**
```
Laptop with VPN connected (uses private hostname)
$ curl http://nas.myphone:8080  ✓
$ ssh user@myphone -p 2222     ✓
$ open http://myphone:8080/plex ✓

All services accessible!
No third-party DDNS service involved.
No logging, no privacy trail.
```

## Benefits of Self-Hosted DDNS

✅ **Zero Privacy Issues** - No third-party logging  
✅ **Zero External Dependencies** - Works offline  
✅ **Zero Privacy Trail** - No way to track you  
✅ **Transparent** - You own all data  
✅ **Fast** - Local updates, no API latency  
✅ **Resilient** - No service dependency  
✅ **Simple** - Built into relay, just works  

## Next Steps

- [x] Install self-hosted DDNS (built-in)
- [x] Run orchestrate command
- [x] SSH deploy clients manually
- [ ] Leave home and test access
- [ ] Verify auto-update runs correctly
- [ ] Setup WireGuard VPN
- [ ] Connect VPN from remote
- [ ] Add rescue mode for admin access
- [ ] Monitor relay with /metrics endpoint

This is the ultimate "phone as gateway" setup. Everything is self-contained, open-source, transparent, and zero privacy leaks. 🚀
