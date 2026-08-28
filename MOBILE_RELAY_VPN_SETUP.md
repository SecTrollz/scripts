# Mobile Relay + WireGuard VPN Architecture

## Overview

The relay device is **completely mobile**. After initial LAN setup, it can leave and move to any network (coffee shop, office, mobile hotspot, etc.). All tunnels remain active and VPN clients can still access everything.

### The Power of This Architecture

```
┌──────────────────────────────────────────┐
│    Initial Setup (LAN only)              │
│                                          │
│  Device A :5000  Device B :3000          │
│     ↓               ↓                    │
│  ┌────────────────────────────┐          │
│  │  Relay Server (Mobile)      │          │
│  │  192.168.1.50:9000         │          │
│  └────────────┬───────────────┘          │
│               │                          │
│         Setup Phase                      │
│         (LAN only)                       │
└───────────────┼──────────────────────────┘
                │
           Tunnels created
           Relay registered
                │
    ┌───────────┴──────────────┐
    │ Relay can NOW move away! │
    └───────────┬──────────────┘
                │
       ┌────────┴────────┐
       ↓                 ↓
   [Relay Device]   [Relay Device]
   Coffee Shop      Office Network
   (any network)    (any network)
       ↓                 ↓
   [VPN Clients still access all tunnels]
```

## Key Principle

**Once tunnels are established, the relay device can roam to ANY network and tunnels remain active.**

Device A and Device B stay on home LAN. Relay leaves. Everyone can still access everything through VPN.

---

## Setup Phase (Relay on LAN)

### Step 1: Relay Device Joins LAN & Starts Server

```bash
RELAY_IP=$(hostname -I | awk '{print $1}')  # 192.168.1.50
TOKEN=$(python3 ngrok_tunnel.py gen-token)

python3 ngrok_tunnel.py server \
    --bind 0.0.0.0 \
    --control-port 9000 \
    --http-port 8080 \
    --token "$TOKEN" \
    --session-timeout 3600
```

### Step 2: Start WireGuard VPN (on relay, requires sudo)

```bash
sudo python3 ngrok_tunnel.py vpn-server \
    --wg-interface wg0 \
    --wg-subnet 10.0.0.0/24 \
    --listen-port 51820
```

### Step 3: Other Devices Create Tunnels (while relay is on LAN)

**Device A (stays on LAN):**
```bash
python3 ngrok_tunnel.py http 5000 \
    --server 192.168.1.50:9000 \
    --token "$TOKEN" \
    --subdomain device-a
```

**Device B (stays on LAN):**
```bash
python3 ngrok_tunnel.py http 3000 \
    --server 192.168.1.50:9000 \
    --token "$TOKEN" \
    --subdomain device-b
```

**Device C (stays on LAN):**
```bash
python3 ngrok_tunnel.py tcp 22 \
    --server 192.168.1.50:9000 \
    --token "$TOKEN" \
    --remote-port 2222
```

### Step 4: Generate VPN Configs (while relay on LAN)

```bash
# On relay device
python3 ngrok_tunnel.py vpn-client \
    --server 192.168.1.50 \
    --output mobile-vpn.conf

# For external access (after relay leaves LAN), need external IP/DNS
# Get relay's public IP or use a stable hostname
PUBLIC_IP=$(curl -s ifconfig.me)  # or use dynamic DNS hostname
python3 ngrok_tunnel.py vpn-client \
    --server "$PUBLIC_IP" \
    --output external-vpn.conf
```

**Important**: Save both configs:
- `mobile-vpn.conf` - uses LAN IP (local access)
- `external-vpn.conf` - uses public IP (remote access after relay leaves)

---

## Mobile Phase (Relay Leaves LAN)

### Before Relay Leaves

```bash
# Stop accepting new clients (gracefully shutdown)
# Let existing tunnels keep working
Ctrl+C

# Restart in nomadic mode (can be anywhere)
python3 ngrok_tunnel.py server \
    --bind 0.0.0.0 \
    --control-port 9000 \
    --http-port 8080 \
    --token "$TOKEN" \
    --session-timeout 3600 \
    --max-connections-per-ip 50 \
    --max-requests-per-second 500
```

VPN should stay running:
```bash
# Keep WireGuard VPN up
sudo wg show wg0
# Should still see connected peers
```

### Relay Goes Mobile

Relay device can now:
- 🚗 Leave home (switch to mobile hotspot)
- ☕ Go to coffee shop (switch to WiFi)
- 🏢 Go to office (switch to office network)
- 🌍 Travel anywhere with internet

**Tunnels don't care where relay is!**

### Device A & B Stay on LAN

Device A and B can keep their tunnels open to relay:

```bash
# Device A (can reconnect if needed)
python3 ngrok_tunnel.py http 5000 \
    --server <relay-ip-or-dns>:9000 \
    --token "$TOKEN" \
    --subdomain device-a
```

For this to work from different networks, use DNS or update IP dynamically.

---

## Remote Access Phase (VPN Clients Connect)

### Scenario 1: Direct IP (if relay has public IP)

```bash
# Connect using relay's public IP
sudo wg-quick up ./external-vpn.conf

# Access tunnels
curl http://device-a.relay-public-ip:8080
```

### Scenario 2: DNS (Recommended)

Use dynamic DNS for relay (e.g., Cloudflare DDNS, Route53, etc.):

```bash
# Configure relay to update DNS
# Then use DNS name in VPN config
python3 ngrok_tunnel.py vpn-client \
    --server relay.example.com \
    --output dynamic-vpn.conf

sudo wg-quick up ./dynamic-vpn.conf
```

### Scenario 3: Relay Stays LAN-Local (no external access)

If relay never leaves LAN network boundaries:
- Use LAN IP for all configs
- Works within LAN only
- VPN clients must be on same LAN

---

## Best Practice: Relay Roaming Setup

### On Relay Device

```bash
# 1. Start server (accessible from anywhere)
python3 ngrok_tunnel.py server \
    --bind 0.0.0.0 \
    --control-port 9000 \
    --http-port 8080 \
    --token "$TOKEN" \
    --session-timeout 3600

# 2. Keep WireGuard VPN running in background
# (use systemd or screen/tmux)
sudo wg-quick up /etc/wireguard/wg0.conf &

# 3. (Optional) Update dynamic DNS on network change
# Script to detect network change and update DNS
watch-network-change.sh  # pseudocode
```

### On Device A & B (Tunnel Clients)

Keep tunnels alive with reconnection logic:

```bash
#!/bin/bash
RELAY_SERVER="${RELAY_IP:-192.168.1.50}:9000"
TOKEN="your-token"
LOCAL_PORT=5000
SUBDOMAIN="device-a"

while true; do
    echo "Connecting to relay at $RELAY_SERVER..."
    python3 ngrok_tunnel.py http $LOCAL_PORT \
        --server "$RELAY_SERVER" \
        --token "$TOKEN" \
        --subdomain "$SUBDOMAIN"
    
    # If connection dies, wait and retry
    echo "Connection lost, retrying in 5 seconds..."
    sleep 5
done
```

Save as `keep-tunnel-alive.sh`, run with:
```bash
nohup ./keep-tunnel-alive.sh > tunnel.log 2>&1 &
```

### On Remote VPN Clients

```bash
# Connect to relay (wherever it is)
sudo wg-quick up ./vpn-config.conf

# Access tunnels through relay
curl http://device-a.relay-address:8080
curl http://device-b.relay-address:8080
ssh -p 2222 user@relay-address  # Device C SSH
```

---

## Relay Network Transitions

### When Relay Changes Networks

**Scenario**: Relay was on home WiFi, now on mobile hotspot

1. **Device A & B**: Tunnels may drop temporarily
   - Reconnect logic tries to reach relay at new IP/network
   - Once relay is reachable, tunnels re-establish

2. **VPN Clients**: If using static IP, lose connection
   - **Solution 1**: Use dynamic DNS (recommended)
   - **Solution 2**: Manually update VPN config with new relay IP
   - **Solution 3**: Use relay discovery service (advanced)

### Recommended: Dynamic DNS Solution

**Set up on relay device:**

```bash
#!/bin/bash
# Update dynamic DNS when network changes
# Run this script periodically or on network change

DDNS_PROVIDER="cloudflare"
DOMAIN="relay.example.com"
ZONE_ID="your-zone-id"
API_TOKEN="your-api-token"

get_public_ip() {
    curl -s ifconfig.me
}

update_dns() {
    local ip=$1
    curl -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/..." \
        -H "Authorization: Bearer $API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"content\":\"$ip\"}"
}

# Run every 5 minutes
while true; do
    IP=$(get_public_ip)
    update_dns "$IP"
    sleep 300
done
```

Then VPN configs always work:
```bash
python3 ngrok_tunnel.py vpn-client \
    --server relay.example.com \
    --output vpn.conf
```

---

## Architecture Comparison

### Before (Static Relay)
```
Relay stuck on LAN
↓
Devices A, B: Can tunnel
↓
External users: Can't access (no internet path to relay)
```

### After (Mobile Relay)
```
Relay can be anywhere
↓
Devices A, B: Can tunnel from anywhere (if using DNS)
↓
External VPN users: Can access all tunnels via VPN
```

---

## Security Implications

### Advantages
- Relay doesn't expose home network (relay leaves!)
- Tunnel connections only when relay is running
- VPN clients can't reach home network directly
- Clean separation of concerns

### Security Checklist
- [ ] Strong token on relay
- [ ] VPN configs kept private (`chmod 600`)
- [ ] Relay only accepts connections from known devices
- [ ] Firewall blocks direct access to relay control port
- [ ] Dynamic DNS service is protected (API key stored safely)
- [ ] Session timeout prevents stale connections

---

## Advanced: Relay Discovery

For auto-discovery without manual IP/DNS updates:

```python
# Relay announces itself to a discovery service
import requests

def register_relay():
    relay_ip = get_public_ip()
    requests.post(
        "https://relay-discovery.example.com/register",
        json={
            "name": "my-relay",
            "ip": relay_ip,
            "port": 9000,
            "vpn_port": 51820
        }
    )

# Run periodically on relay device
while True:
    register_relay()
    sleep(60)
```

Then clients query discovery:
```bash
RELAY_IP=$(curl https://relay-discovery.example.com/find/my-relay | jq .ip)
python3 ngrok_tunnel.py vpn-client --server "$RELAY_IP" --output vpn.conf
```

---

## Summary

**The relay is a nomadic gateway:**
1. Setup phase: Relay on LAN, devices create tunnels
2. Mobile phase: Relay leaves, all tunnels persist
3. Access: VPN clients reach relay & tunnels regardless of relay location
4. Recovery: Tunnels re-establish if connection breaks

This is perfect for:
- **Travel**: Take relay on laptop, tunnels follow you
- **Redundancy**: Relay can failover to backup network
- **Privacy**: Tunnels don't expose home infrastructure
- **Flexibility**: Relay isn't locked to one location

The only requirement after setup: **Relay must be reachable** (via IP or DNS).
