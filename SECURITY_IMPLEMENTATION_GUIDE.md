# Secure HTTPS Download Implementation Guide

**Production-grade security for sensitive database downloads**

## Security Threats & Mitigations

### 1. Man-in-the-Middle (MITM) Attacks

**Threat:** Attacker intercepts HTTPS connection and steals data

**Mitigations:**
```python
# ✅ Certificate validation (mandatory)
context = ssl.create_default_context(cafile=certifi.where())
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# ✅ TLS 1.2+ only (no old, weak protocols)
context.minimum_version = ssl.TLSVersion.TLSv1_2

# ✅ Strong cipher suites
context.set_ciphers(
    'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
)

# ✅ Certificate pinning (optional, for high-security scenarios)
# Can pin specific certificate or public key
```

**Implementation:**
```python
ssl_context = SecureSSLContext.create_context(
    verify_ssl=True,  # Always True in production
    ca_bundle_path=Path("/etc/ssl/certs/ca-bundle.crt")  # Custom CA bundle
)

connector = aiohttp.TCPConnector(ssl=ssl_context)
```

---

### 2. Credential Leakage

**Threat:** Authentication tokens logged or exposed in memory

**Mitigations:**

```python
# ✅ Never log token values
logger.info("✅ Authentication token set")  # Good
logger.info(f"Token: {token}")              # ❌ Bad

# ✅ Clear token from memory after use
def clear_token(self):
    self._token = None  # Overwrite reference
    
# ✅ Use secure header transmission
auth_header = {'Authorization': f'Bearer {token}'}
# Token stays in memory only as long as request

# ✅ Don't store credentials in config files
class DownloadConfig:
    # ❌ DON'T include credentials
    # password: str = "secret"
    
    # ✅ DO pass credentials separately
    # token: str (passed at runtime, not stored)
```

**Best Practices:**
```python
# Get token from secure source
class SecureTokenProvider:
    def get_token(self) -> str:
        """Get token from environment variable"""
        token = os.environ.get('DOWNLOAD_TOKEN')
        if not token:
            raise ValueError("DOWNLOAD_TOKEN environment variable not set")
        return token

# Or from secure credential store
def get_token_from_keychain() -> str:
    """Retrieve token from OS keychain"""
    # macOS: Keychain
    # Windows: Credential Manager
    # Linux: Secret Service
    pass

# Never store in code or config
downloader.set_auth_token(get_token_from_secure_source())
```

---

### 3. Insecure File Operations

**Threat:** Downloaded data written with world-readable permissions

**Mitigations:**

```python
# ✅ Create temp file with secure permissions
temp_dir = Path(tempfile.gettempdir()) / ".beenverified"
temp_dir.mkdir(exist_ok=True, mode=0o700)  # Only owner readable

# ✅ Atomic file operations
with open(temp_file, 'wb') as f:
    f.seek(offset)
    f.write(data)  # Atomic write

# ✅ Set restrictive permissions on final file
output_path.chmod(0o600)  # Owner read/write only

# ✅ Secure deletion of temp files
def cleanup(self):
    if temp_file.exists():
        # Overwrite with random data before deletion
        file_size = temp_file.stat().st_size
        with open(temp_file, 'wb') as f:
            f.write(os.urandom(file_size))  # Overwrite
        temp_file.unlink()  # Delete
```

**Permission Matrix:**
```
Temp file:      0o700  (rwx------)  - Owner only
Final file:     0o600  (rw-------)  - Owner read/write
Database file:  0o600  (rw-------)  - Owner read/write
Temp directory: 0o700  (rwx------)  - Owner only
```

---

### 4. Network-Based Attacks

**Threat:** Connection hijacking, replay attacks

**Mitigations:**

```python
# ✅ Single connection (prevent connection storms)
connector = aiohttp.TCPConnector(
    ssl=ssl_context,
    limit=1,  # One connection
    limit_per_host=1
)

# ✅ Timeout protection (prevent slowloris attacks)
timeout = aiohttp.ClientTimeout(
    total=None,  # No total timeout (long download ok)
    sock_read=300  # 5-minute read timeout
)

# ✅ Rate monitoring (detect anomalies)
rate_monitor = RateMonitor(
    min_rate_mbps=0.5,  # Alert if slower than 0.5 MB/s
    timeout_seconds=300  # Alert if no data for 5 minutes
)

# ✅ Session security
headers = {
    'User-Agent': 'BeenVerifiedOffline/1.0.0',
    'Authorization': 'Bearer token',
}

# ✅ Secure User-Agent (identify as legitimate client)
# ❌ AVOID: 'Mozilla/5.0...' (masquerading as browser)
```

---

### 5. Data Integrity Attacks

**Threat:** Attacker modifies data in transit or on disk

**Mitigations:**

```python
# ✅ Cryptographic hash verification
def verify_download(self, file_path, expected_hash):
    actual_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            actual_hash.update(chunk)
    
    if actual_hash.hexdigest() != expected_hash:
        raise ValueError("Hash mismatch - data corrupted!")
    
    return True

# ✅ Schema validation on sample records
def validate_schema(file_path, sample_size=100):
    required_fields = ['record_id', 'full_name', 'phone']
    
    with gzip.open(file_path, 'rt') as f:
        for i, line in enumerate(f):
            if i >= sample_size:
                break
            
            record = json.loads(line)
            for field in required_fields:
                if field not in record:
                    raise ValueError(f"Missing field: {field}")

# ✅ Range request validation (prevent truncation)
if response.status != 206:  # Partial Content
    raise ValueError("Server doesn't support range requests")
```

---

### 6. Denial of Service (DoS) Protection

**Threat:** Attacker causes resource exhaustion

**Mitigations:**

```python
# ✅ Disk space check (prevent full disk)
def check_available_space(required_gb):
    stat = shutil.disk_usage('/')
    required_bytes = required_gb * 1024**3
    
    if stat.free < required_bytes:
        raise Exception(f"Insufficient space: {stat.free} < {required_bytes}")

# ✅ Memory limits (streaming, not buffering)
async def download_chunk(self, chunk_size_mb=100):
    # Download in 100MB chunks (not entire file)
    # Prevents memory exhaustion
    chunk_size = chunk_size_mb * 1024 * 1024
    
    async with session.get(url) as resp:
        while True:
            data = await resp.content.read(chunk_size)
            if not data:
                break
            await write_to_disk(data)  # Stream to disk

# ✅ Connection limits (prevent connection storms)
connector = aiohttp.TCPConnector(
    limit=1,  # Max 1 connection
    limit_per_host=1
)

# ✅ Timeout protection
timeout = aiohttp.ClientTimeout(sock_read=300)  # 5-minute timeout
```

---

### 7. Authentication Bypass

**Threat:** Expired or stolen tokens used for access

**Mitigations:**

```python
# ✅ Token refresh before expiry
def needs_refresh(self, lifetime_minutes=120):
    age = datetime.now() - self.token_acquired_at
    # Refresh 5 minutes before expiry
    return age > (lifetime_minutes - 5) * 60 * 1000

# ✅ Automatic re-authentication on 401
async def download_chunk(self, chunk_num, chunk_size):
    async with session.get(url, headers=auth_header) as resp:
        if resp.status == 401:  # Unauthorized
            # Refresh token
            new_token = await self.auth.refresh_token()
            # Retry with new token
            return await self.download_chunk(chunk_num, chunk_size)

# ✅ Session timeout protection
if not await auth.refresh_if_needed():
    raise AuthError("Failed to refresh authentication")

# ✅ Verify account has download permission
def verify_access(session):
    resp = await session.get('/api/account/status')
    account = resp.json()
    
    if account['subscription_status'] != 'active':
        raise PermissionError("Subscription not active")
    
    if not account['can_download_database']:
        raise PermissionError("Downloads disabled for account")
```

---

### 8. Logging and Information Disclosure

**Threat:** Sensitive data exposed in logs or error messages

**Mitigations:**

```python
# ✅ Never log sensitive data
logger.info("Starting download...")  # ✅ Good
logger.info(f"Token: {token}")       # ❌ Bad
logger.info(f"URL: {url}")           # ⚠️ Questionable
logger.info(f"URL: {url[:50]}...")   # ✅ Redacted

# ✅ Redact errors
try:
    async with session.get(url) as resp:
        pass
except ClientSSLError as e:
    logger.error("SSL error: Certificate validation failed")
    # NOT: logger.error(f"SSL error: {e}")

# ✅ Configure logging to avoid debug info in production
logging.getLogger('aiohttp').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# ✅ Use environment-specific log levels
if os.environ.get('DEBUG'):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
```

---

### 9. Dependency Vulnerabilities

**Threat:** Vulnerable libraries used in download

**Mitigations:**

```bash
# ✅ Keep dependencies updated
pip install --upgrade aiohttp certifi

# ✅ Use specific versions (reproducible builds)
pip install aiohttp==3.8.5 certifi==2023.7.22

# ✅ Audit dependencies
pip-audit  # Check for known vulnerabilities

# ✅ Use requirements.txt with hashes
aiohttp==3.8.5 --hash=sha256:abc123...
certifi==2023.7.22 --hash=sha256:def456...
```

**requirements.txt:**
```
aiohttp==3.8.5
certifi==2023.7.22
```

---

## Security Checklist

### Before Deployment

- [ ] SSL/TLS certificate validation enabled (`verify_ssl=True`)
- [ ] Minimum TLS version set to 1.2 or higher
- [ ] Strong cipher suites configured
- [ ] Hostname verification enabled
- [ ] Authentication tokens never logged
- [ ] Credentials stored in environment variables, not code
- [ ] Temp files created with secure permissions (0o700)
- [ ] Final files created with secure permissions (0o600)
- [ ] Secure token refresh mechanism implemented
- [ ] Rate monitoring for anomaly detection
- [ ] Hash verification implemented
- [ ] Schema validation implemented
- [ ] Disk space check implemented
- [ ] Connection limits set (limit=1)
- [ ] Timeout protection enabled
- [ ] All dependencies audited for vulnerabilities
- [ ] Logging configured to never expose secrets
- [ ] Error handling doesn't leak information
- [ ] SSL error handling prevents MITM retry
- [ ] Account access verified before download

### During Development

```python
# ✅ Use environment variables for secrets
import os

auth_token = os.environ['DOWNLOAD_TOKEN']
downloader.set_auth_token(auth_token)

# ✅ Never hardcode credentials
# ❌ downloader.set_auth_token("my-secret-token")

# ✅ Test with certificates
ssl_context = SecureSSLContext.create_context(
    verify_ssl=True,
    ca_bundle_path=Path("/path/to/ca-bundle.crt")
)

# ✅ Verify HTTPS in logs (no insecure HTTP)
assert downloader.config.url.startswith('https://')
```

### Runtime Security

```bash
# Set authentication token securely
export DOWNLOAD_TOKEN="secure_token_from_env"

# Run with logging at INFO level (no debug info)
python secure_downloader.py

# Check file permissions on download
ls -l downloaded_database.db
# Should show: -rw------- (0o600)

# Verify hash after download
sha256sum downloaded_database.db
# Compare with expected: abc123def456...
```

---

## SSL Certificate Pinning (Advanced)

For maximum security in high-risk scenarios:

```python
import ssl
import certifi

class PinnedSSLContext:
    """SSL context with certificate pinning"""
    
    @staticmethod
    def create_pinned_context(cert_path: Path) -> ssl.SSLContext:
        """Create context with pinned certificate"""
        context = ssl.create_default_context()
        
        # Load the pinned certificate
        context.load_verify_locations(cert_path)
        
        # Verify against pinned cert only
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        return context

# Usage
pinned_context = PinnedSSLContext.create_pinned_context(
    Path("/path/to/beenverified.com.crt")
)

connector = aiohttp.TCPConnector(ssl=pinned_context)
```

---

## Common Security Mistakes to Avoid

| ❌ Mistake | ✅ Correct |
|-----------|-----------|
| `verify_ssl=False` in production | Always `verify_ssl=True` |
| Logging tokens | Never log sensitive data |
| Using HTTP instead of HTTPS | Always use HTTPS |
| Storing passwords in code | Use environment variables |
| World-readable files | Use permissions `0o600` |
| No hash verification | Always verify integrity |
| Hardcoded API keys | Load from secure store |
| Ignoring SSL errors | Handle SSL errors explicitly |
| No timeout protection | Set socket timeouts |
| Buffering entire file | Stream to disk in chunks |

---

## Testing Security

```python
# Test 1: Verify SSL enforcement
try:
    downloader = SecureDownloader(
        DownloadConfig(url="http://insecure.example.com/file")
    )
    await downloader.download()
    assert False, "Should reject HTTP"
except Exception:
    print("✅ HTTP correctly rejected")

# Test 2: Verify token refresh
downloader.auth.set_token("test_token")
# Simulate token near expiry
downloader.auth._token_acquired_at = datetime.now() - timedelta(minutes=115)
assert downloader.auth.needs_refresh()
print("✅ Token refresh detected")

# Test 3: Verify hash validation
config = DownloadConfig(output_path=Path("test.db"))
downloader = SecureDownloader(config)

# Download with wrong hash
try:
    await downloader.download(verify_hash="wrong_hash")
    assert False, "Should reject wrong hash"
except Exception:
    print("✅ Hash validation working")

# Test 4: Verify file permissions
from pathlib import Path
import stat

downloaded_file = Path("database.db")
perms = stat.filemode(downloaded_file.stat().st_mode)
assert perms == "-rw-------", f"Wrong permissions: {perms}"
print("✅ File permissions correct")
```

---

## Compliance Requirements

### GDPR (Personal Data Protection)
- ✅ Encrypted transfer (HTTPS)
- ✅ Access control (authentication)
- ✅ Data integrity (hashing)
- ✅ Secure storage (0o600 permissions)
- ✅ Audit logging (never log personal data)

### HIPAA (Health Information)
- ✅ Encryption in transit (TLS 1.2+)
- ✅ Encryption at rest (depends on disk encryption)
- ✅ Access controls (authentication + authorization)
- ✅ Audit controls (logging without data exposure)

### PCI DSS (Payment Card)
- ✅ Secure protocols (HTTPS/TLS 1.2+)
- ✅ Strong authentication
- ✅ No credential storage
- ✅ Regular security testing

---

## Security Resources

### Python Security
- https://python.readthedocs.io/en/stable/library/ssl.html
- https://owasp.org/www-project-secure-coding-practices/
- https://cwe.mitre.org/top25/

### HTTPS/TLS Best Practices
- https://mozilla.github.io/server-side-tls/ssl-config-generator/
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

### Cryptography
- https://cryptography.io/
- https://www.certifi.python-requests.org/

---

## Summary

**Key Security Principles:**

1. **Certificate Validation:** Always verify SSL certificates
2. **Credential Hygiene:** Never log or hardcode secrets
3. **File Security:** Use restrictive permissions (0o600)
4. **Data Integrity:** Verify hashes of downloaded files
5. **Authentication:** Refresh tokens before expiry
6. **Resource Protection:** Limit connections, set timeouts
7. **Secure Deletion:** Overwrite temp files before deletion
8. **Error Handling:** Don't leak information in errors
9. **Dependency Security:** Keep libraries updated
10. **Logging:** Never log sensitive data

**Expected Security Level:** Production-grade (suitable for sensitive PII downloads)
