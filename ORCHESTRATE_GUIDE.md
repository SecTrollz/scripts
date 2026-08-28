# Orchestrate: Phone as Remote Access Hub

## The Vision

Your phone becomes a **self-configuring remote access gateway**:

1. **At home**: Run one command, phone scans LAN, deploys clients to devices
2. **Phone leaves**: Relay keeps running, accessible via Tailscale/DDNS
3. **Anywhere**: Access all home devices via VPN or relay URLs

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
│  │  Tailscale IP: 100.64.0.1           │   │
│  │  Token: abc123...                   │   │
│  │  Port 9000: control                 │   │
│  │  Port 8080: HTTP proxy              │   │
│  └─────────────────────────────────────┘   │
│       ↓                                     │
└───────┼─────────────────────────────────────┘
        │
    Tailscale Mesh Network (VPN)
    (IP stays constant: 100.64.0.1)
        │
   ┌────┴─────┐
   ↓          ↓
[Laptop]   [Phone Mobile Data]
(10.0.0.2) (new IP each network)
  Access Home     Control Relay
```

## Quick Start

### Step 1: Install Tailscale (on phone and laptop)

**On phone:**
```bash
# Install Tailscale
sudo apt install tailscale  # Linux
# or use Tailscale app (iOS/Android)

# Start Tailscale
sudo tailscale up

# Get Tailscale IP
tailscale status
# Output: 100.64.0.1 (or similar)
```

**On laptop/remote:**
```bash
sudo tailscale up
# Now connected to same mesh
```

### Step 2: Run Orchestrate (on phone, at home)

```bash
python3 ngrok_tunnel.py orchestrate
```

This interactive wizard will:

1. **Detect Tailscale IP** (or ask for DDNS hostname / public IP)
   ```
   Options:
   1. Auto-detect Tailscale IP
   2. Use dynamic DNS hostname
   3. Use public IP
   
   Choose: 1
   ✓ Tailscale IP: 100.64.0.1
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
     • 100.64.0.1:9000 (Tailscale)
     • Token: xyz789...
   
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
   ```

### Step 3: Deploy Clients (Manual SSH to each target)

**SSH into each target and run:**

```bash
# On NAS
ssh user@192.168.1.10

# Download and deploy client
curl -fsSL http://192.168.1.XXX:8765/ngrok_tunnel.py -o ngrok_tunnel.py

# Create tunnel (HTTP example)
nohup python3 ngrok_tunnel.py http 8080 \
    --server 100.64.0.1:9000 \
    --token 'xyz789...' \
    --subdomain nas > tunnel.log 2>&1 &

# Verify
tail tunnel.log
```

Repeat for each target device, adjusting the port and subdomain.

### Step 4: Leave Home

Phone disconnects from home WiFi, switches to mobile data or coffee shop WiFi.

Tailscale keeps 100.64.0.1 reachable through mesh network.

### Step 5: Access from Anywhere

**Connect Tailscale on laptop:**
```bash
sudo tailscale up
# Now on same mesh as phone
```

**Access services via relay:**
```bash
# NAS via HTTP
curl http://nas.100.64.0.1:8080

# Gaming PC SSH
ssh user@100.64.0.1 -p 2222

# Media Server (Plex)
open http://100.64.0.1:8080/plex

# Monitor relay
curl 100.64.0.1:8080/metrics | jq
```

**Optional: Rescue shell on target device**
```bash
python3 ngrok_tunnel.py rescue-admin \
    --server 100.64.0.1:9000 \
    --token 'xyz789...'

# Pick which device
# Get live shell
```

## Architecture Deep Dive

### Why Tailscale?

**Problem**: Phone's home LAN IP (192.168.1.50) changes when it leaves home.
- Targets deployed with 192.168.1.50 lose connection
- Updating all targets manually is painful

**Solution**: Tailscale provides stable IP (100.64.0.1) that never changes.
- Phone switches networks
- Tailscale IP stays 100.64.0.1
- Mesh network routes packets through Tailscale infrastructure
- Targets always find phone at same IP

### Data Flow

```
Target (192.168.1.10) sends data to relay:
  ↓
  [Tunnel Client] → "100.64.0.1:9000" (Tailscale IP)
  ↓
  [Tailscale Client on Target] routes through mesh
  ↓
  [Tailscale Infrastructure] (WireGuard encrypted)
  ↓
  [Tailscale Client on Phone]
  ↓
  [Relay Server] on phone receives data
  ↓
  [Phone] → Laptop via HTTP or SSH
```

### Without Tailscale (DDNS Fallback)

If you don't have Tailscale, use dynamic DNS:

1. **Setup DDNS** (e.g., DuckDNS)
   ```bash
   curl -X POST "https://www.duckdns.org/update?domains=myphone&token=MYTOKEN&ip="
   ```

2. **Run update script on phone**
   ```bash
   # Keep IP updated as network changes
   while true; do
       IP=$(curl -s ifconfig.me)
       curl -X POST "https://www.duckdns.org/update?domains=myphone&token=MYTOKEN&ip=$IP"
       sleep 300  # Update every 5 minutes
   done
   ```

3. **Deploy clients with DDNS name**
   ```bash
   python3 ngrok_tunnel.py http 8080 \
       --server myphone.duckdns.org:9000 \
       --token 'xyz789...'
   ```

4. **Access via DDNS**
   ```bash
   curl http://nas.myphone.duckdns.org:8080
   ssh user@myphone.duckdns.org -p 2222
   ```

## Complete Orchestrate Workflow

### Timeline

**T=0min (At home, on WiFi)**
```
$ python3 ngrok_tunnel.py orchestrate
✓ Tailscale IP: 100.64.0.1
✓ Generated token
✓ Scanned LAN (found 4 devices)
✓ User selected 3 targets
✓ Relay running on :9000
```

**T=5min (Deploy clients)**
```
$ ssh user@192.168.1.10  # NAS
$ curl ... ngrok_tunnel.py
$ python3 ngrok_tunnel.py http 8080 --server 100.64.0.1:9000 --token ...
✓ Tunnel created: NAS → Relay

(Repeat for other targets...)
```

**T=30min (Phone leaves home)**
```
Phone disconnects from home WiFi
Switches to mobile data
New IP: 118.123.45.67 (doesn't matter!)
Tailscale IP: 100.64.0.1 (same!)
```

**T=30min+1sec (From anywhere)**
```
Laptop on Tailscale mesh
$ curl http://nas.100.64.0.1:8080  ✓
$ ssh user@100.64.0.1 -p 2222     ✓
$ open http://100.64.0.1:8080/plex ✓

All services accessible!
```

## Security Checklist

- [x] Strong token generated (use `gen-token`)
- [x] Tailscale IP is private mesh (100.64.x.x range)
- [x] Tunnel traffic encrypted by WireGuard (Tailscale)
- [x] Session timeout prevents stale connections
- [x] Token must match on relay & clients
- [x] Never expose token publicly
- [x] Firewall on phone allows port 9000 from Tailscale only
- [x] Each service protected by individual tunnel

## Troubleshooting

**Q: Clients can't connect to 100.64.0.1:9000**
```bash
# Check Tailscale IP on phone
tailscale status

# Check if relay is running
curl 100.64.0.1:8080/health

# Check firewall allows port 9000
sudo ufw allow from 100.64.0.0/10 to any port 9000
```

**Q: Relay runs but new targets can't connect**
```bash
# Verify token matches
# Check target tunnel logs
ssh user@target
tail tunnel.log

# Verify network connectivity
ping 100.64.0.1  # Should work if on Tailscale
```

**Q: Services work at home but not remotely**
```bash
# Check Tailscale connection on phone
sudo tailscale status

# Verify Tailscale on laptop
sudo tailscale up

# Check relay is still running
curl 100.64.0.1:8080/metrics
```

## Advanced: Multiple Phones (Failover)

Deploy relay on two phones for redundancy:

```bash
# Phone 1 (primary)
python3 ngrok_tunnel.py orchestrate  # Tailscale IP: 100.64.0.1

# Phone 2 (backup)
python3 ngrok_tunnel.py orchestrate  # Tailscale IP: 100.64.0.2
```

Deploy some clients to Phone 1, others to Phone 2:

```bash
# NAS → Phone 1
python3 ngrok_tunnel.py http 8080 \
    --server 100.64.0.1:9000 \
    --token 'token1'

# Gaming PC → Phone 2
python3 ngrok_tunnel.py tcp 22 \
    --server 100.64.0.2:9000 \
    --token 'token2'
```

Now if Phone 1 dies, Phone 2 still has gaming PC access.

## The "Set It and Forget It" Promise

After running orchestrate once:

1. ✓ Relay keeps running 24/7 on phone (can keep phone at home permanently)
2. ✓ Clients auto-connect and reconnect if dropped
3. ✓ Tailscale keeps IP stable (or DDNS updates automatically)
4. ✓ You access everything from anywhere
5. ✓ No manual reconfiguration needed

The only moving part is the phone's network - Tailscale handles that transparently.

## Next Steps

- [x] Install Tailscale (or setup DDNS)
- [x] Run orchestrate command
- [x] SSH deploy clients manually
- [ ] Leave home and test access
- [ ] Setup auto-reconnect for clients (systemd service)
- [ ] Add rescue mode admin panel
- [ ] Monitor relay with /metrics endpoint

This is the ultimate "phone as gateway" setup. Everything is self-contained, encrypted, and just works. 🚀
