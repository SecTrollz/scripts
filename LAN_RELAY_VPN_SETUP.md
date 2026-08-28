# Local LAN Relay + WireGuard VPN Setup Guide

## Overview

This guide covers setting up a **local relay server on your LAN** that tunnels local services, with access provided via **WireGuard VPN** (no public VPS needed).

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Local Network (192.168.1.0/24)                         │
│                                                          │
│  [Device A]              [Device B]                     │
│   :5000 app              :3000 web                      │
│      ↓                      ↓                            │
│   Tunnel to relay ←→ Local Relay Server (192.168.1.50)  │
│      (port 9000)            ↓                            │
│                        WireGuard VPN                     │
│                        (10.0.0.0/24)                    │
│                                                          │
└─────────────────────────────────────────────────────────┘
                            ↓
                   [Remote VPN Clients]
                   (10.0.0.2, 10.0.0.3)
                   Access all tunnels
```

## Quick Start

### Step 1: Start the Relay Server (on a LAN device)

```bash
# Generate auth token
TOKEN=$(python3 ngrok_tunnel.py gen-token)

# Start relay on local LAN IP (192.168.1.50 example)
python3 ngrok_tunnel.py server \
    --bind 192.168.1.50 \
    --control-port 9000 \
    --http-port 8080 \
    --token "$TOKEN" \
    --session-timeout 3600
```

**Notes:**
- Use your relay device's actual LAN IP (find with `hostname -I` or `ifconfig`)
- Token should be shared with all clients securely
- No public IP/domain needed
- HTTP port (8080) only for local access

### Step 2: Create Tunnels (on other LAN devices)

**Device A - expose web app on :5000**
```bash
python3 ngrok_tunnel.py http 5000 \
    --server 192.168.1.50:9000 \
    --token "$TOKEN" \
    --subdomain devicea-app
```

**Device B - expose another app on :3000**
```bash
python3 ngrok_tunnel.py http 3000 \
    --server 192.168.1.50:9000 \
    --token "$TOKEN" \
    --subdomain deviceb-web
```

### Step 3: Set Up WireGuard VPN (on relay device, requires root)

```bash
# Generate server keys and config
python3 ngrok_tunnel.py vpn-server \
    --wg-interface wg0 \
    --wg-subnet 10.0.0.0/24 \
    --listen-port 51820

# This outputs:
# - Server public key
# - Example client config
# - Installation instructions
```

**Expected output:**
```
╔═══════════════════════════════════════════════════════╗
║              WireGuard VPN Server Setup               ║
╚═══════════════════════════════════════════════════════╝

Server Interface: wg0
Server IP: 10.0.0.1/24
Server Public Key: [base64_key]
Listen Port: 51820

To start: sudo wg-quick up /etc/wireguard/wg0.conf
```

### Step 4: Generate Client VPN Config

```bash
python3 ngrok_tunnel.py vpn-client \
    --server 192.168.1.50 \
    --output my-vpn.conf

# Copy my-vpn.conf to your laptop/phone
```

### Step 5: Connect VPN Client

**On Linux/macOS:**
```bash
sudo wg-quick up ./my-vpn.conf
```

**On Windows/iPhone/Android:**
- Use WireGuard GUI app
- Import the `.conf` file
- Connect

**Verify connection:**
```bash
# Should see 10.0.0.x IP
ip addr show wg0

# Test access to tunneled services
curl http://devicea-app.192.168.1.50:8080
curl http://deviceb-web.192.168.1.50:8080
```

## Complete Configuration Example

### Relay Server Config (`/etc/ngrok-tunnel/lan-relay.env`)

```bash
# Network
bind=192.168.1.50
control_port=9000
http_port=8080

# Security
token=your-secret-token-from-gen-token
session_timeout=3600

# Logging
access_log=/var/log/tunnel/access.log
structured_logs=true

# Rate limiting (adjust for your needs)
max_connections_per_ip=20
max_requests_per_second=200

# IP filtering (restrict to LAN only)
allow_ips=192.168.1.0/24
deny_ips=
```

**Run with config:**
```bash
python3 ngrok_tunnel.py server --config lan-relay.env
```

### Client Config (Device A)

```bash
# Create local config
cat > devicea-tunnel.conf << 'EOF'
[tunnel]
server=192.168.1.50:9000
token=your-secret-token
local_port=5000
type=http
subdomain=devicea-app
EOF

# Run with config
python3 ngrok_tunnel.py http 5000 \
    --server 192.168.1.50:9000 \
    --token <token> \
    --subdomain devicea-app
```

## Deployment Options

### Option A: Systemd Service (Linux)

**Server service** (`/etc/systemd/system/ngrok-relay.service`):
```ini
[Unit]
Description=Local LAN Relay Server
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/ngrok-tunnel
ExecStart=/usr/bin/python3 ngrok_tunnel.py server \
    --config /etc/ngrok-tunnel/lan-relay.env
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**VPN service** (`/etc/systemd/system/ngrok-vpn.service`):
```ini
[Unit]
Description=WireGuard VPN for Tunnel Access
After=ngrok-relay.service
Requires=ngrok-relay.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 ngrok_tunnel.py vpn-server \
    --wg-interface wg0 --wg-subnet 10.0.0.0/24
RemainAfterExit=yes
StandardOutput=journal

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl enable ngrok-relay ngrok-vpn
sudo systemctl start ngrok-relay ngrok-vpn
```

### Option B: Manual Start (Development)

**Terminal 1 - Start relay:**
```bash
python3 ngrok_tunnel.py server \
    --bind 192.168.1.50 \
    --control-port 9000 \
    --http-port 8080 \
    --token $(python3 ngrok_tunnel.py gen-token) \
    --access-log relay.log
```

**Terminal 2 - Start VPN:**
```bash
sudo python3 ngrok_tunnel.py vpn-server \
    --wg-interface wg0 \
    --wg-subnet 10.0.0.0/24
```

**Terminal 3+ - Create tunnels:**
```bash
python3 ngrok_tunnel.py http 5000 \
    --server 192.168.1.50:9000 \
    --token <token> \
    --subdomain myapp
```

## Security Considerations

### 1. LAN-Only Access (Recommended)

Since relay is on private LAN, restrict to LAN IPs only:

```bash
python3 ngrok_tunnel.py server \
    --allow-ips "192.168.1.0/24" \
    --token <strong-token>
```

### 2. VPN Access Control

Only trusted devices should have VPN configs:
```bash
# Keep VPN client configs private
chmod 600 my-vpn.conf
```

### 3. Token Management

Strong token (from `gen-token`):
```bash
TOKEN=$(python3 ngrok_tunnel.py gen-token)
# Distribute securely (encrypted email, secure message, etc.)
# Never commit to git
```

### 4. Session Timeout

Aggressive timeout for untrusted networks:
```bash
--session-timeout 300  # 5 minutes idle disconnect
```

### 5. Firewall Rules

**Allow relay control port (9000) only from LAN:**
```bash
sudo ufw allow from 192.168.1.0/24 to any port 9000
sudo ufw allow from 192.168.1.0/24 to any port 8080
```

**Allow VPN port (51820) from anywhere (needed for remote clients):**
```bash
sudo ufw allow 51820/udp
```

## Monitoring & Troubleshooting

### Check Relay Status

```bash
# Logs
tail -f relay.log

# Connected clients
curl http://localhost:8080/metrics | jq

# VPN peers
sudo wg show wg0
```

### Debug VPN Connection

```bash
# Test ping through VPN
sudo wg-quick up ./my-vpn.conf
ping 10.0.0.1  # Should reach relay VPN IP

# Check routing
ip route | grep 10.0.0
```

### Common Issues

**Problem**: "Connection refused" on relay port
- **Check**: Is relay listening? `netstat -tlnp | grep 9000`
- **Check**: Is firewall blocking? `sudo ufw status`
- **Fix**: Start relay with correct LAN IP

**Problem**: VPN connects but can't access tunnels
- **Check**: Is relay accessible from VPN network? Test with `ping 192.168.1.50` from VPN
- **Check**: Are tunnels registered? Look at relay logs
- **Fix**: Verify tunnel client still connected to relay

**Problem**: Slow access through VPN
- **Check**: Network congestion on LAN
- **Check**: CPU on relay device
- **Tune**: Increase `--max-requests-per-second` if rate-limited

## Advanced: Multiple Relay Servers

For redundancy, run multiple relays:

**Relay 1** (primary):
```bash
python3 ngrok_tunnel.py server --bind 192.168.1.50 --control-port 9000 --token $TOKEN
```

**Relay 2** (backup):
```bash
python3 ngrok_tunnel.py server --bind 192.168.1.51 --control-port 9000 --token $TOKEN
```

Clients can connect to either:
```bash
python3 ngrok_tunnel.py http 5000 --server 192.168.1.50:9000 --token $TOKEN
python3 ngrok_tunnel.py http 5000 --server 192.168.1.51:9000 --token $TOKEN
```

## Performance Tuning

### For Many Concurrent Tunnels

```bash
python3 ngrok_tunnel.py server \
    --max-connections-per-ip 50 \
    --max-requests-per-second 500 \
    --session-timeout 3600
```

### For Limited Hardware (Raspberry Pi, etc.)

```bash
python3 ngrok_tunnel.py server \
    --max-connections-per-ip 5 \
    --max-requests-per-second 50 \
    --session-timeout 600
```

## Backup & Recovery

### Backup VPN Keys

```bash
# Never lose your VPN server keys!
sudo cp /etc/wireguard/wg0.conf ~/backup-wg0.conf
chmod 600 ~/backup-wg0.conf
```

### Restore from Backup

```bash
sudo cp ~/backup-wg0.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

## Summary Checklist

- [ ] Relay device identified (static LAN IP)
- [ ] Relay server started with strong token
- [ ] Tunnel clients connecting to relay
- [ ] WireGuard VPN server initialized
- [ ] Client VPN config generated
- [ ] VPN client connected and tested
- [ ] Firewall rules configured
- [ ] Access logging enabled
- [ ] Backup of VPN keys taken
- [ ] Remote devices can access tunneled services via VPN

## Next Steps

- **Scaling**: Add more tunnel clients as needed
- **Monitoring**: Set up log aggregation for all access
- **Automation**: Write scripts to auto-start relay + VPN on boot
- **Security**: Rotate VPN client configs periodically
- **Documentation**: Document which device runs which tunnel

This setup is perfect for:
- Home labs with multiple devices
- Small team internal networks
- Development environments
- Emergency access to headless devices (via VPN)
- No public IP exposure required!
