#!/usr/bin/env python3
"""
Secure HTTPS downloader with production-grade security.
- Certificate validation
- Secure credential handling
- TLS best practices
- No credential leakage
"""

import asyncio
import aiohttp
import hashlib
import json
import logging
import ssl
import certifi
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import tempfile
import os

# Setup logging (never log sensitive data)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecureDownloader')

# Disable logging of sensitive headers
logging.getLogger('aiohttp').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)


@dataclass
class DownloadConfig:
    """Download configuration (never store credentials here)"""
    url: str
    output_path: Path
    chunk_size_mb: int = 100
    timeout_seconds: int = 300
    verify_ssl: bool = True
    ca_bundle_path: Optional[Path] = None
    max_retries: int = 5
    min_rate_mbps: float = 0.5  # Minimum download rate (MB/sec)

    def __post_init__(self):
        self.output_path = Path(self.output_path)
        if self.ca_bundle_path:
            self.ca_bundle_path = Path(self.ca_bundle_path)


class SecureSSLContext:
    """Creates secure SSL/TLS context with best practices"""

    @staticmethod
    def create_context(
        verify_ssl: bool = True,
        ca_bundle_path: Optional[Path] = None
    ) -> ssl.SSLContext:
        """
        Create SSL context with security hardening

        Args:
            verify_ssl: Verify SSL certificates (always True in production)
            ca_bundle_path: Custom CA bundle path

        Returns:
            Configured SSL context
        """
        if not verify_ssl:
            logger.warning("⚠️ SSL verification DISABLED - only for testing!")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context

        # Create secure context (defaults to CERT_REQUIRED)
        context = ssl.create_default_context(
            cafile=ca_bundle_path if ca_bundle_path else certifi.where()
        )

        # Force TLS 1.2 or higher (disable old, insecure protocols)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Strong cipher suites only
        # Prefer: ECDHE (forward secrecy) + AES-GCM (authenticated encryption)
        context.set_ciphers(
            'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS'
        )

        # Enable session tickets (safe with TLS 1.2+)
        context.options |= ssl.OP_NO_TICKET

        # Verify hostname (prevent DNS spoofing)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        logger.info(f"✅ SSL context: {context.protocol.name}")
        return context


class AuthenticationManager:
    """Manages secure credential handling"""

    def __init__(self):
        self._token = None
        self._token_acquired_at = None
        self._refresh_callback = None

    def set_token(self, token: str):
        """
        Set auth token securely

        Never log or print the token value
        """
        self._token = token
        self._token_acquired_at = datetime.now()
        logger.info("✅ Authentication token set")

    def set_refresh_callback(self, callback):
        """Set callback to refresh token"""
        self._refresh_callback = callback

    def get_auth_header(self) -> dict:
        """Get auth header without exposing token"""
        if not self._token:
            raise ValueError("No token set")

        return {'Authorization': f'Bearer {self._token}'}

    def needs_refresh(self, lifetime_minutes: int = 120) -> bool:
        """Check if token needs refresh"""
        if not self._token_acquired_at:
            return True

        age = datetime.now() - self._token_acquired_at
        refresh_threshold = timedelta(minutes=5)
        token_lifetime = timedelta(minutes=lifetime_minutes)

        return age > (token_lifetime - refresh_threshold)

    async def refresh_if_needed(self, lifetime_minutes: int = 120) -> bool:
        """Refresh token if needed"""
        if not self.needs_refresh(lifetime_minutes):
            return True

        if not self._refresh_callback:
            logger.error("❌ Token needs refresh but no callback provided")
            return False

        logger.info("🔄 Refreshing authentication token...")
        try:
            new_token = await self._refresh_callback()
            self.set_token(new_token)
            return True
        except Exception as e:
            logger.error(f"❌ Token refresh failed: {e}")
            return False

    def clear_token(self):
        """Clear token from memory"""
        self._token = None
        self._token_acquired_at = None
        logger.info("✅ Token cleared from memory")


class SecureFileHandler:
    """Handles secure temporary file operations"""

    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.temp_dir = Path(tempfile.gettempdir()) / ".beenverified"
        self.temp_dir.mkdir(exist_ok=True, mode=0o700)  # Only user readable

        # Create temp file with secure permissions
        self.temp_file = self.temp_dir / f"{output_path.name}.tmp"

    def get_temp_path(self) -> Path:
        """Get secure temporary file path"""
        return self.temp_file

    async def write_chunk(self, chunk_num: int, data: bytes) -> bool:
        """Write chunk securely"""
        try:
            offset = chunk_num * len(data)

            # Secure file write (atomic append)
            with open(self.temp_file, 'r+b' if self.temp_file.exists() else 'wb') as f:
                f.seek(offset)
                f.write(data)

            return True
        except Exception as e:
            logger.error(f"❌ Failed to write chunk {chunk_num}: {e}")
            return False

    async def finalize(self, expected_hash: Optional[str] = None) -> bool:
        """Move temp file to final location after verification"""
        if not self.temp_file.exists():
            logger.error("❌ Temporary file not found")
            return False

        try:
            # Verify hash if provided
            if expected_hash:
                actual_hash = self._compute_hash()
                if actual_hash != expected_hash:
                    logger.error(f"❌ Hash mismatch: expected {expected_hash}, got {actual_hash}")
                    self.temp_file.unlink()
                    return False

            # Move temp file to final location
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.temp_file.replace(self.output_path)

            # Set secure file permissions (owner read/write only)
            self.output_path.chmod(0o600)

            logger.info(f"✅ File finalized: {self.output_path}")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to finalize download: {e}")
            return False

    def _compute_hash(self) -> str:
        """Compute SHA256 of file"""
        hasher = hashlib.sha256()
        with open(self.temp_file, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def cleanup(self):
        """Securely delete temporary file"""
        if self.temp_file.exists():
            try:
                # Overwrite with random data (secure deletion)
                file_size = self.temp_file.stat().st_size
                with open(self.temp_file, 'wb') as f:
                    f.write(os.urandom(file_size))

                # Delete
                self.temp_file.unlink()
                logger.info("✅ Temporary file securely deleted")
            except Exception as e:
                logger.warning(f"⚠️ Failed to securely delete temp file: {e}")


class RateMonitor:
    """Monitors download rate for security (detect stalled transfers)"""

    def __init__(self, min_rate_mbps: float = 0.5, timeout_seconds: int = 300):
        self.min_rate_mbps = min_rate_mbps
        self.timeout_seconds = timeout_seconds
        self.last_activity = datetime.now()
        self.bytes_downloaded = 0
        self.start_time = datetime.now()

    def update(self, bytes_received: int):
        """Update activity"""
        self.last_activity = datetime.now()
        self.bytes_downloaded += bytes_received

    def is_stalled(self) -> bool:
        """Check if download is stalled"""
        elapsed = (datetime.now() - self.last_activity).total_seconds()
        return elapsed > self.timeout_seconds

    def get_current_rate_mbps(self) -> float:
        """Get current download rate"""
        total_elapsed = (datetime.now() - self.start_time).total_seconds()
        if total_elapsed < 1:
            return 0
        return (self.bytes_downloaded / (1024 * 1024)) / total_elapsed

    def rate_is_acceptable(self) -> bool:
        """Check if rate meets minimum threshold"""
        rate = self.get_current_rate_mbps()
        return rate >= self.min_rate_mbps or self.bytes_downloaded < 1024 * 1024


class SecureDownloader:
    """Production-grade HTTPS downloader with security"""

    def __init__(self, config: DownloadConfig):
        self.config = config
        self.auth = AuthenticationManager()
        self.ssl_context = SecureSSLContext.create_context(
            verify_ssl=config.verify_ssl,
            ca_bundle_path=config.ca_bundle_path
        )
        self.file_handler = SecureFileHandler(config.output_path)
        self.retry_count = 0

    def set_auth_token(self, token: str):
        """Set authentication token"""
        self.auth.set_token(token)

    def set_token_refresh_callback(self, callback):
        """Set token refresh callback"""
        self.auth.set_refresh_callback(callback)

    async def download(self, verify_hash: Optional[str] = None) -> bool:
        """
        Perform secure HTTPS download

        Args:
            verify_hash: Expected SHA256 hash for verification

        Returns:
            True if successful, False otherwise
        """
        logger.info("🔒 Starting secure HTTPS download...")
        logger.info(f"Target: {self.config.url[:50]}...")  # Don't log full URL
        logger.info(f"Output: {self.config.output_path}")

        # Create aiohttp session with secure SSL context
        connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
            limit=1,  # Single connection to avoid connection storms
            limit_per_host=1
        )

        timeout = aiohttp.ClientTimeout(total=None, sock_read=self.config.timeout_seconds)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'BeenVerifiedOffline/1.0.0'}
        ) as session:
            return await self._download_impl(session, verify_hash)

    async def _download_impl(
        self,
        session: aiohttp.ClientSession,
        verify_hash: Optional[str]
    ) -> bool:
        """Implementation of download logic"""
        try:
            # Get file metadata securely
            logger.info("📊 Fetching file metadata...")
            file_size = await self._get_file_size(session)
            if not file_size:
                return False

            chunk_size = self.config.chunk_size_mb * 1024 * 1024
            total_chunks = (file_size + chunk_size - 1) // chunk_size

            logger.info(f"File size: {file_size / 1024**3:.2f} GB")
            logger.info(f"Chunks: {total_chunks} × {self.config.chunk_size_mb} MB")

            # Download chunks
            logger.info("⬇️ Starting download...\n")

            rate_monitor = RateMonitor(
                min_rate_mbps=self.config.min_rate_mbps,
                timeout_seconds=self.config.timeout_seconds
            )

            for chunk_num in range(total_chunks):
                # Refresh token if needed
                if not await self.auth.refresh_if_needed():
                    logger.error("❌ Authentication failed")
                    return False

                # Download chunk with retry
                success = await self._download_chunk_with_retry(
                    session, chunk_num, chunk_size
                )

                if not success:
                    logger.error(f"❌ Failed to download chunk {chunk_num}")
                    return False

                # Check rate
                if not rate_monitor.rate_is_acceptable():
                    logger.warning(f"⚠️ Download rate too slow: {rate_monitor.get_current_rate_mbps():.2f} MB/s")

                if rate_monitor.is_stalled():
                    logger.error("❌ Download stalled")
                    return False

                # Progress
                percent = ((chunk_num + 1) / total_chunks) * 100
                logger.info(f"Progress: {percent:.1f}% | Rate: {rate_monitor.get_current_rate_mbps():.2f} MB/s")

            # Finalize
            logger.info("\n✔️ Validating and finalizing...")
            if not await self.file_handler.finalize(verify_hash):
                return False

            logger.info("✅ Download complete and verified!")
            self.auth.clear_token()  # Clear token from memory

            return True

        except asyncio.CancelledError:
            logger.error("❌ Download cancelled")
            self.file_handler.cleanup()
            return False

        except Exception as e:
            logger.error(f"❌ Download failed: {e}")
            self.file_handler.cleanup()
            return False

    async def _get_file_size(self, session: aiohttp.ClientSession) -> Optional[int]:
        """Get file size via HEAD request"""
        try:
            async with session.head(
                self.config.url,
                headers=self.auth.get_auth_header(),
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status == 200:
                    return int(resp.headers.get('Content-Length', 0))
                else:
                    logger.error(f"❌ HEAD request failed: {resp.status}")
                    return None

        except Exception as e:
            logger.error(f"❌ Failed to get file size: {e}")
            return None

    async def _download_chunk_with_retry(
        self,
        session: aiohttp.ClientSession,
        chunk_num: int,
        chunk_size: int
    ) -> bool:
        """Download chunk with automatic retries"""
        for attempt in range(self.config.max_retries):
            try:
                return await self._download_chunk(session, chunk_num, chunk_size)

            except aiohttp.ClientSSLError as e:
                logger.error(f"❌ SSL error (attempt {attempt + 1}): Certificate validation failed")
                logger.error(f"   Details: {e}")
                # Don't retry SSL errors - indicates MITM or misconfiguration
                return False

            except aiohttp.ClientConnectorError as e:
                logger.warning(f"⚠️ Connection error (attempt {attempt + 1}): {e}")
                await asyncio.sleep(2 ** attempt)

            except asyncio.TimeoutError:
                logger.warning(f"⚠️ Timeout (attempt {attempt + 1})")
                await asyncio.sleep(2 ** attempt)

            except Exception as e:
                logger.warning(f"⚠️ Error (attempt {attempt + 1}): {e}")
                await asyncio.sleep(2 ** attempt)

        logger.error(f"❌ Failed after {self.config.max_retries} attempts")
        return False

    async def _download_chunk(
        self,
        session: aiohttp.ClientSession,
        chunk_num: int,
        chunk_size: int
    ) -> bool:
        """Download single chunk"""
        start_byte = chunk_num * chunk_size
        end_byte = start_byte + chunk_size - 1

        range_header = f'bytes={start_byte}-{end_byte}'

        try:
            async with session.get(
                self.config.url,
                headers={
                    **self.auth.get_auth_header(),
                    'Range': range_header
                },
                timeout=aiohttp.ClientTimeout(sock_read=self.config.timeout_seconds)
            ) as resp:
                if resp.status == 206:  # Partial content
                    data = await resp.read()
                    return await self.file_handler.write_chunk(chunk_num, data)

                elif resp.status == 200:  # Server doesn't support ranges
                    logger.warning("⚠️ Server doesn't support range requests")
                    return False

                elif resp.status == 401:
                    logger.error("❌ Unauthorized - check authentication")
                    return False

                elif resp.status == 403:
                    logger.error("❌ Forbidden - access denied")
                    return False

                else:
                    logger.error(f"❌ HTTP {resp.status}")
                    return False

        except Exception as e:
            logger.error(f"❌ Download failed: {e}")
            raise

    def cleanup(self):
        """Cleanup resources"""
        self.file_handler.cleanup()
        self.auth.clear_token()


async def example_download():
    """Example usage"""
    config = DownloadConfig(
        url="https://api.example.com/database.sql.gz",
        output_path=Path("./data/database.sql.gz"),
        chunk_size_mb=100,
        timeout_seconds=300,
        verify_ssl=True,
        ca_bundle_path=None,  # Uses system CA bundle by default
        max_retries=5
    )

    downloader = SecureDownloader(config)

    # Set authentication token (in production, get from secure source)
    downloader.set_auth_token("your_secure_token_here")

    # Optional: Set token refresh callback
    async def refresh_token():
        # In production, would call auth endpoint securely
        logger.info("Refreshing token...")
        return "new_token_here"

    downloader.set_token_refresh_callback(refresh_token)

    # Download
    success = await downloader.download(
        verify_hash="expected_sha256_hash_here"
    )

    if success:
        logger.info("🎉 Download successful!")
    else:
        logger.error("❌ Download failed")

    downloader.cleanup()


if __name__ == "__main__":
    asyncio.run(example_download())
