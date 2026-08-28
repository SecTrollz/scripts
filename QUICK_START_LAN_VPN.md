# Quick Start: LAN Relay + WireGuard VPN (5 Minutes)

## The Goal
Access local services from anywhere via WireGuard VPN. No public VPS. No internet-facing relay.

## Architecture
```
Device A (Port 5000)  ─┐
Device B (Port 3000)  ─┬─→ [Local Relay] ←─ WireGuard VPN ←─ [Remote Clients]
Device C (Port 8080)  ─┘
```

---

## Steps

### 1️⃣ Pick Your Relay Device (1 min)

Find your LAN IP:
```bash
hostname -I
# Output example: 192.168.1.50 192.168.1.51

# Use the first one as RELAY_IP
RELAY_IP=192.168.1.50
TOKEN=$(python3 ngrok_tunnel.py gen-token)
echo "Relay IP: $RELAY_IP"
echo "Token: $TOKEN"  # Save this!
```

### 2️⃣ Start the Relay Server (30 seconds)

**On your relay device:**
```bash
python3 ngrok_tunnel.py server \
    --bind $RELAY_IP \
    --control-port 9000 \
    --http-port 8080 \
    --token $TOKEN \
    --allow-ips "192.168.1.0/24"
```

✓ Done! Relay is running on `$RELAY_IP:9000`

### 3️⃣ Create Tunnels (30 seconds per device)

**On Device A (expose port 5000):**
```bash
python3 ngrok_tunnel.py http 5000 \
    --server $RELAY_IP:9000 \
    --token $TOKEN \
    --subdomain device-a
```

**On Device B (expose port 3000):**
```bash
python3 ngrok_tunnel.py http 3000 \
    --server $RELAY_IP:9000 \
    --token $TOKEN \
    --subdomain device-b
```

**On Device C (expose port 8080):**
```bash
python3 ngrok_tunnel.py tcp 8080 \
    --server $RELAY_IP:9000 \
    --token $TOKEN \
    --remote-port 8080
```

✓ Done! Services are now tunneled through relay

### 4️⃣ Set Up WireGuard VPN (1 min, requires sudo)

**On relay device:**
```bash
sudo python3 ngrok_tunnel.py vpn-server \
    --wg-interface wg0 \
    --wg-subnet 10.0.0.0/24 \
    --listen-port 51820
```

Save the output! You need:
- Server public key
- Server IP (`10.0.0.1`)

### 5️⃣ Generate VPN Client Config (30 seconds)

**On relay device:**
```bash
python3 ngrok_tunnel.py vpn-client \
    --server $RELAY_IP \
    --output my-lan-vpn.conf

# Make it secret!
chmod 600 my-lan-vpn.conf
```

### 6️⃣ Connect VPN Client (30 seconds)

**On your laptop/phone:**

Linux/macOS:
```bash
sudo wg-quick up ./my-lan-vpn.conf
```

Windows/Phone:
- Install WireGuard app
- Import `my-lan-vpn.conf`
- Click Connect

### 7️⃣ Test It Works! (30 seconds)

```bash
# Check VPN IP (should be 10.0.0.2+)
ip addr show wg0

# Access tunneled services through relay LAN IP
curl http://device-a.$RELAY_IP:8080     # Device A's web app
curl http://device-b.$RELAY_IP:8080     # Device B's web app
nc $RELAY_IP 8080 < /dev/null          # Device C's TCP service
```

✅ **Done! You have remote access via VPN to all tunneled services!**

---

## What You Get

| Device | Service | Access Point |
|--------|---------|--------------|
| A | :5000 (web) | `http://device-a.192.168.1.50:8080` (via VPN) |
| B | :3000 (web) | `http://device-b.192.168.1.50:8080` (via VPN) |
| C | :8080 (tcp) | `192.168.1.50:8080` (via VPN) |

---

## Troubleshooting

**Relay won't start**
```bash
# Check IP is correct
hostname -I
# Try: --bind 0.0.0.0 instead
```

**Tunnel client can't connect**
```bash
# Verify relay is running
netstat -tlnp | grep 9000
# Check token matches
echo $TOKEN
```

**VPN won't connect**
```bash
# Check VPN is up on relay
sudo wg show wg0
# Port 51820 open?
sudo ufw allow 51820/udp
```

**Can't reach tunneled services**
```bash
# Test relay access
curl http://$RELAY_IP:8080/health
# Check tunnel client logs
```

---

## Advanced: Make It Persistent

### Auto-start with Systemd

**Create service** (`/etc/systemd/system/ngrok-relay.service`):
```ini
[Unit]
Description=LAN Relay
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /path/to/ngrok_tunnel.py server \
    --bind 192.168.1.50 --control-port 9000 --http-port 8080 \
    --token YOUR_TOKEN --allow-ips 192.168.1.0/24
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable ngrok-relay
sudo systemctl start ngrok-relay
sudo systemctl status ngrok-relay
```

### Auto-start VPN

**Create service** (`/etc/systemd/system/ngrok-vpn.service`):
```ini
[Unit]
Description=LAN Relay VPN
After=ngrok-relay.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /path/to/ngrok_tunnel.py vpn-server \
    --wg-interface wg0 --wg-subnet 10.0.0.0/24
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl enable ngrok-vpn
sudo systemctl start ngrok-vpn
```

---

## Security Checklist

- [ ] Strong token (use `gen-token`)
- [ ] LAN IP filtering enabled (`--allow-ips 192.168.1.0/24`)
- [ ] VPN config file private (`chmod 600 my-lan-vpn.conf`)
- [ ] Firewall allows VPN port 51820 only
- [ ] Relay firewall blocks non-LAN (using `--allow-ips`)
- [ ] Session timeout set reasonably (`--session-timeout 3600`)

---

## One-Liner Setup (if you remember the steps!)

```bash
# On relay device
RELAY_IP=192.168.1.50
TOKEN=$(python3 ngrok_tunnel.py gen-token)

# Terminal 1: Start relay
python3 ngrok_tunnel.py server --bind $RELAY_IP --control-port 9000 \
    --http-port 8080 --token $TOKEN --allow-ips "192.168.1.0/24"

# Terminal 2: Start VPN (requires sudo)
sudo python3 ngrok_tunnel.py vpn-server --wg-interface wg0 \
    --wg-subnet 10.0.0.0/24 --listen-port 51820

# On other devices: Create tunnels
python3 ngrok_tunnel.py http 5000 --server $RELAY_IP:9000 \
    --token $TOKEN --subdomain myapp

# On remote device: Connect VPN
python3 ngrok_tunnel.py vpn-client --server $RELAY_IP --output my.conf
sudo wg-quick up my.conf
curl http://myapp.$RELAY_IP:8080
```

---

That's it! You now have a complete, private tunnel infrastructure! 🎉
