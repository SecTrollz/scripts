# ngrok_tunnel.py - Deployment & Operations Guide

This guide covers production deployment, security hardening, and operational best practices for the self-hosted reverse tunnel server.

## Quick Start Deployment

### 1. Generate authentication token

```bash
python3 ngrok_tunnel.py gen-token
# Output: AbCd1234_example_token_1234abCd5678
```

### 2. Start the server with basic config

```bash
python3 ngrok_tunnel.py server \
    --token AbCd1234_example_token_1234abCd5678 \
    --control-port 9000 \
    --http-port 8080 \
    --public-host your-server-ip.com
```

### 3. Connect a client

```bash
# On your laptop, expose local port 5000
python3 ngrok_tunnel.py http 5000 \
    --server your-server-ip.com:9000 \
    --token AbCd1234_example_token_1234abCd5678 \
    --subdomain myapp
# Your app is now live at: http://myapp.your-server-ip.com:8080
```

## Configuration

### Using Config Files

Config files streamline deployment and can be version-controlled (with tokens removed).

#### JSON Format

```bash
python3 ngrok_tunnel.py server --config production.json
```

See `example-server-config.json` for a complete example with all available options.

#### KEY=VALUE Format

```bash
python3 ngrok_tunnel.py server --config production.env
```

See `example-server-config.env` for a complete example.

**Note:** Command-line arguments override config file values, allowing safe defaults with per-deployment overrides.

### Core Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--bind` | `0.0.0.0` | Listen address (use `127.0.0.1` for localhost-only) |
| `--control-port` | 9000 | Port clients dial to create tunnels |
| `--http-port` | 8080 | Port for HTTP tunnels |
| `--https-port` | - | Port for HTTPS tunnels (requires `--cert` and `--key`) |
| `--domain` | - | Base domain for subdomain routing (e.g., `tunnel.example.com`) |
| `--token` | - | **Strongly recommended**: shared auth token clients must present |
| `--tcp-port-range` | 20000-20100 | Allowed ports for TCP tunnels |

## Security Hardening

### 1. Enable Authentication

Always set `--token` in production. Generate a strong random token:

```bash
python3 ngrok_tunnel.py gen-token
```

Then use it on both server and all clients.

### 2. IP Filtering

Restrict tunnel access to specific networks:

```bash
# Only allow connections from internal networks
python3 ngrok_tunnel.py server \
    --token <token> \
    --allow-ips "10.0.0.0/8,192.168.0.0/16"
```

Block specific IPs:

```bash
# Allow all except compromised network
python3 ngrok_tunnel.py server \
    --token <token> \
    --deny-ips "192.168.1.100/32"
```

**Note:** Deny takes precedence over allow.

### 3. Enable HTTPS

For production, always use TLS:

```bash
python3 ngrok_tunnel.py server \
    --token <token> \
    --https-port 8443 \
    --cert /path/to/cert.pem \
    --key /path/to/key.pem
```

### 4. Rate Limiting

Protect against abuse with per-IP limits:

```bash
python3 ngrok_tunnel.py server \
    --token <token> \
    --max-connections-per-ip 5 \
    --max-requests-per-second 50
```

### 5. Session Timeout

Automatically disconnect idle clients (default 30 minutes):

```bash
# Disconnect clients idle for 10 minutes
python3 ngrok_tunnel.py server \
    --token <token> \
    --session-timeout 600
```

### 6. Cryptographic Identity (Zero-Trust Auth)

For high-security deployments, enable device-based authentication:

```bash
# On device: generate device seed
python3 ngrok_tunnel.py identity generate --show-seed

# On server: configure with seed hash
python3 ngrok_tunnel.py server \
    --token <token> \
    --identity-seed-hash <seed_hash_from_device>

# On device: connect with identity
python3 ngrok_tunnel.py http 5000 \
    --server your-server.com:9000 \
    --token <token> \
    --identity-seed-file ~/.tunnel_seed
```

## Operational Monitoring

### Access Logging

Enable detailed audit logs:

```bash
python3 ngrok_tunnel.py server \
    --token <token> \
    --access-log /var/log/tunnel/access.log
```

### Structured Logging

For centralized logging (e.g., ELK, Splunk):

```bash
python3 ngrok_tunnel.py server \
    --token <token> \
    --access-log /var/log/tunnel/access.log \
    --structured-logs
```

Logs will be output as JSON:

```json
{
  "timestamp": 1693286400.123,
  "timestamp_iso": "2023-08-28T17:00:00Z",
  "client_ip": "192.168.1.100",
  "tunnel_type": "http",
  "tunnel_id": "abc12345",
  "status": "connected",
  "details": ""
}
```

### Health Check Endpoint

Health and metrics are available via HTTP:

```bash
# Check server health
curl http://your-server.com:8080/health

# View metrics (JSON)
curl http://your-server.com:8080/metrics | jq
```

Expected metrics response:

```json
{
  "uptime_seconds": 3600,
  "connections_total": 42,
  "connections_active": 3,
  "bytes_in": 1000000,
  "bytes_out": 5000000,
  "errors": 2,
  "throughput_mbps": 1.33
}
```

### Verbose Logging

Enable debug output:

```bash
python3 ngrok_tunnel.py server -vv --token <token>
```

- `-v`: INFO level (connection events)
- `-vv`: DEBUG level (detailed stream activity)

## Systemd Service

For production deployments, run as a systemd service:

### /etc/systemd/system/ngrok-tunnel.service

```ini
[Unit]
Description=Self-hosted reverse tunnel server
After=network.target

[Service]
Type=simple
User=tunnel
WorkingDirectory=/opt/ngrok-tunnel
ExecStart=/usr/bin/python3 /opt/ngrok-tunnel/ngrok_tunnel.py server \
    --config /etc/ngrok-tunnel/config.env \
    --bind 0.0.0.0 \
    --control-port 9000 \
    --http-port 8080
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable ngrok-tunnel
sudo systemctl start ngrok-tunnel
sudo systemctl status ngrok-tunnel
```

View logs:

```bash
sudo journalctl -u ngrok-tunnel -f
```

## Supervisor Configuration

Alternative to systemd (especially for BSD, older Linux):

### /etc/supervisor/conf.d/ngrok-tunnel.conf

```ini
[program:ngrok-tunnel]
command=/usr/bin/python3 /opt/ngrok-tunnel/ngrok_tunnel.py server --config /etc/ngrok-tunnel/config.env
autorestart=true
startsecs=10
stderr_logfile=/var/log/tunnel/stderr.log
stdout_logfile=/var/log/tunnel/stdout.log
user=tunnel
directory=/opt/ngrok-tunnel
```

## Performance Tuning

### For High-Throughput Deployments

Increase resource limits:

```bash
# Adjust max connections per IP
python3 ngrok_tunnel.py server \
    --token <token> \
    --max-connections-per-ip 50

# Increase requests per second per IP
python3 ngrok_tunnel.py server \
    --token <token> \
    --max-requests-per-second 500
```

### Session Timeout Tuning

Balance between resource usage and disconnection latency:

```bash
# Short timeout: aggressive cleanup (5 minutes)
--session-timeout 300

# Long timeout: minimize reconnects (60 minutes)
--session-timeout 3600
```

## Troubleshooting

### Client connection rejected

Check:
1. Token matches between client and server: `--token`
2. IP filtering allows the client: `--allow-ips`, `--deny-ips`
3. Rate limit not exceeded: `--max-connections-per-ip`
4. Session not idle-disconnected: `--session-timeout`

### Access denied with identity auth

Ensure:
1. Device seed generated: `python3 ngrok_tunnel.py identity generate`
2. Server has correct seed hash: `--identity-seed-hash`
3. Device uses seed file: `--identity-seed-file`

### Slow throughput

Check:
1. Network latency to server
2. Rate limiting: `--max-requests-per-second`
3. TCP port range not exhausted: `--tcp-port-range`
4. Server disk I/O for access logging

### Memory growth over time

Possible causes:
1. Idle sessions not timing out: lower `--session-timeout`
2. Access log unbounded: rotate `/var/log/tunnel/access.log`
3. Metrics accumulation: restart server daily or implement metrics reset

## Production Checklist

- [ ] Token configured and rotated periodically
- [ ] HTTPS enabled with valid certificate
- [ ] Access logging enabled
- [ ] IP filtering configured for your network
- [ ] Session timeout set appropriately
- [ ] Rate limiting tuned for your workload
- [ ] Systemd/supervisor service configured
- [ ] Log rotation configured (logrotate)
- [ ] Monitoring and alerts set up
- [ ] Backup/restore procedure documented
- [ ] Incident response plan in place

## Advanced: Load Balancing

For multiple servers, use a simple round-robin DNS or HAProxy:

### HAProxy Configuration

```
listen tunnel-control
    bind 0.0.0.0:9000
    mode tcp
    balance roundrobin
    server relay1 10.0.0.1:9000
    server relay2 10.0.0.2:9000
    server relay3 10.0.0.3:9000
```

Each relay server runs independently with shared token and config.

## Next Steps

- **Security:** Enable cryptographic identity for zero-trust auth
- **Scaling:** Deploy multiple relay servers with load balancing
- **Integration:** Use health check endpoint for monitoring
- **Automation:** Package in Docker for cloud deployments
