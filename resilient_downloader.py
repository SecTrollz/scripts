#!/usr/bin/env python3
"""
Resilient Database Downloader with comprehensive failure handling.
Designed for production use with 50GB+ databases.
"""

import asyncio
import time
import json
import hashlib
import gzip
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from dataclasses import dataclass, asdict
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ResilientDownloader')


@dataclass
class DownloadState:
    """Persistent download state"""
    url: str
    output_path: str
    chunk_size: int
    total_chunks: int
    chunks_completed: list
    started_at: float
    last_chunk_time: float
    session_token: str
    session_expiry: float
    current_rate: float  # chunks/sec

    def save(self, path: Path):
        """Save state to disk"""
        with open(f"{path}.state.json", 'w') as f:
            json.dump(asdict(self), f, indent=2)

    @staticmethod
    def load(path: Path):
        """Load state from disk"""
        state_file = Path(f"{path}.state.json")
        if state_file.exists():
            with open(state_file, 'r') as f:
                data = json.load(f)
                return DownloadState(**data)
        return None


class SessionManager:
    """Manages authentication and session lifecycle"""

    def __init__(self, session_lifetime_minutes: int = 120):
        self.session_lifetime = session_lifetime_minutes
        self.token = None
        self.token_acquired_at = None
        self.refresh_threshold = 5  # Refresh 5 min before expiry

    def needs_refresh(self) -> bool:
        """Check if session needs refresh"""
        if not self.token_acquired_at:
            return True

        elapsed_minutes = (time.time() - self.token_acquired_at) / 60
        return elapsed_minutes > (self.session_lifetime - self.refresh_threshold)

    def set_token(self, token: str):
        """Set auth token"""
        self.token = token
        self.token_acquired_at = time.time()

    def get_headers(self) -> Dict:
        """Get HTTP headers with auth"""
        return {
            'Authorization': f'Bearer {self.token}',
            'User-Agent': 'BeenVerifiedOffline/1.0',
        }


class RateLimiter:
    """Adaptive rate limiting with backoff"""

    def __init__(self, initial_rate: float = 1.0):
        self.rate = initial_rate  # Requests per second
        self.last_request = 0
        self.throttle_count = 0
        self.min_rate = 0.1  # Don't go slower than 1 request per 10 seconds

    def wait(self):
        """Apply rate limiting"""
        elapsed = time.time() - self.last_request
        delay = (1.0 / self.rate) - elapsed

        if delay > 0:
            time.sleep(delay)

        self.last_request = time.time()

    def handle_throttle(self, retry_after: Optional[str] = None):
        """Handle rate limit (429) response"""
        if retry_after:
            try:
                wait_seconds = int(retry_after)
            except ValueError:
                wait_seconds = 60
        else:
            # Exponential backoff: 60s, 120s, 300s, 600s
            wait_seconds = min(60 * (2 ** self.throttle_count), 600)
            self.throttle_count += 1

        logger.warning(f"Rate limited. Waiting {wait_seconds}s...")
        time.sleep(wait_seconds)

        # Reduce rate
        self.rate = max(self.rate * 0.5, self.min_rate)
        logger.info(f"Rate reduced to {self.rate:.3f} requests/sec")

    def handle_success(self):
        """Gradually recover rate after success"""
        if self.throttle_count > 0:
            self.throttle_count -= 1
            self.rate = min(self.rate * 1.1, 1.0)  # Slowly increase back


class IntegrityValidator:
    """Validates downloaded data integrity"""

    def __init__(self, expected_hash: Optional[str] = None):
        self.expected_hash = expected_hash

    def verify_file(self, file_path: Path) -> bool:
        """Verify downloaded file"""
        logger.info("Verifying file integrity...")

        # Check file size
        file_size = file_path.stat().st_size
        if file_size < 1_000_000:  # Less than 1MB
            logger.error(f"File suspiciously small: {file_size} bytes")
            return False

        # Verify checksum if provided
        if self.expected_hash:
            actual_hash = self._compute_hash(file_path)
            if actual_hash != self.expected_hash:
                logger.error(f"Hash mismatch: expected {self.expected_hash}, got {actual_hash}")
                return False

        # Validate schema on sample
        if not self._validate_schema(file_path):
            return False

        logger.info("✅ File integrity verified")
        return True

    def _compute_hash(self, file_path: Path) -> str:
        """Compute SHA256 of file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _validate_schema(self, file_path: Path, sample_size: int = 100) -> bool:
        """Validate schema on sample of records"""
        required_fields = ['record_id', 'full_name']

        try:
            opener = gzip.open if str(file_path).endswith('.gz') else open
            mode = 'rt' if str(file_path).endswith('.gz') else 'r'

            with opener(file_path, mode) as f:
                for i, line in enumerate(f):
                    if i >= sample_size:
                        break

                    try:
                        record = json.loads(line)
                        for field in required_fields:
                            if field not in record:
                                logger.error(f"Missing required field '{field}' in record {i}")
                                return False
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON at record {i}")
                        return False

            logger.info(f"Schema validated on {min(i+1, sample_size)} records")
            return True

        except Exception as e:
            logger.error(f"Schema validation failed: {e}")
            return False


class StorageManager:
    """Manages disk space and storage operations"""

    def __init__(self, required_gb: int):
        self.required_bytes = required_gb * 1024**3

    def check_space(self, path: Path) -> bool:
        """Check if disk has enough space"""
        logger.info("Checking disk space...")

        path.parent.mkdir(parents=True, exist_ok=True)
        stat = path.parent.__fspath__()

        import shutil
        stat = shutil.disk_usage(path.parent)

        # Need 1.5x buffer for temp files, decompression
        required_with_buffer = self.required_bytes * 1.5

        if stat.free < required_with_buffer:
            gb_available = stat.free / 1024**3
            gb_needed = required_with_buffer / 1024**3
            logger.error(f"Insufficient space: {gb_available:.1f}GB available, {gb_needed:.1f}GB needed")
            return False

        logger.info(f"✅ Disk space OK: {stat.free / 1024**3:.1f}GB available")
        return True


class DownloadMonitor:
    """Monitors download progress and performance"""

    def __init__(self, total_chunks: int):
        self.total_chunks = total_chunks
        self.chunks_completed = 0
        self.start_time = time.time()
        self.last_report_time = time.time()
        self.last_report_chunks = 0

    def update(self, chunk_num: int):
        """Update progress"""
        self.chunks_completed = chunk_num + 1
        current_time = time.time()

        # Report every 10 seconds or at completion
        if current_time - self.last_report_time >= 10 or self.chunks_completed == self.total_chunks:
            self._report()
            self.last_report_time = current_time
            self.last_report_chunks = self.chunks_completed

    def _report(self):
        """Report progress metrics"""
        elapsed = time.time() - self.start_time
        percent = (self.chunks_completed / self.total_chunks) * 100

        # Calculate rate and ETA
        elapsed_since_last = time.time() - self.last_report_time
        if elapsed_since_last > 0:
            rate = (self.chunks_completed - self.last_report_chunks) / elapsed_since_last
        else:
            rate = 0

        if rate > 0:
            remaining = self.total_chunks - self.chunks_completed
            eta_seconds = remaining / rate
            eta_str = f"{eta_seconds / 3600:.1f}h"
        else:
            eta_str = "calculating..."

        logger.info(
            f"Progress: {percent:.1f}% ({self.chunks_completed}/{self.total_chunks}) | "
            f"Elapsed: {elapsed/3600:.1f}h | ETA: {eta_str} | Rate: {rate:.2f} chunks/sec"
        )

        # Alert on critical slowdown
        if rate < 0.01 and self.chunks_completed > 10:
            logger.warning("⚠️ ALERT: Download rate critically slow!")


class ResilientDownloader:
    """Production-grade database downloader with failure handling"""

    def __init__(self, output_dir: str = "./downloads"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.session_mgr = SessionManager()
        self.rate_limiter = RateLimiter()
        self.storage_mgr = StorageManager(required_gb=100)  # Adjust as needed
        self.integrity_check = IntegrityValidator()

    async def download(
        self,
        url: str,
        auth_token: str,
        expected_hash: Optional[str] = None,
        chunk_size_mb: int = 100,
    ) -> bool:
        """
        Download database with full resilience

        Args:
            url: Download URL
            auth_token: Authentication token
            expected_hash: Expected SHA256 hash
            chunk_size_mb: Chunk size in MB

        Returns:
            True if successful, False otherwise
        """
        logger.info("🔍 Starting resilient download...")

        # Setup
        self.session_mgr.set_token(auth_token)
        self.integrity_check.expected_hash = expected_hash
        chunk_size = chunk_size_mb * 1024 * 1024
        output_file = self.output_dir / Path(url.split('/')[-1])

        # Pre-flight checks
        if not self.storage_mgr.check_space(output_file):
            return False

        # Get file metadata
        logger.info("📊 Fetching file metadata...")
        try:
            total_chunks = self._get_total_chunks(url, chunk_size)
            logger.info(f"Total chunks: {total_chunks}")
        except Exception as e:
            logger.error(f"Failed to get file metadata: {e}")
            return False

        # Load previous state if exists
        state = DownloadState.load(output_file)
        if state and state.chunks_completed:
            logger.info(f"Resuming download from chunk {len(state.chunks_completed)}...")
            completed = set(state.chunks_completed)
        else:
            completed = set()

        # Initialize monitor
        monitor = DownloadMonitor(total_chunks)
        monitor.chunks_completed = len(completed)

        # Download chunks
        logger.info("⬇️ Starting download...\n")

        for chunk_num in range(total_chunks):
            if chunk_num in completed:
                monitor.update(chunk_num)
                continue

            # Check if session needs refresh
            if self.session_mgr.needs_refresh():
                logger.info("🔄 Refreshing session token...")
                # In production, would call refresh_token() here
                # auth_token = await self.refresh_token()
                # self.session_mgr.set_token(auth_token)

            # Download with retries
            success = False
            for attempt in range(5):
                try:
                    self.rate_limiter.wait()

                    if await self._download_chunk(
                        url, chunk_num, chunk_size, output_file
                    ):
                        completed.add(chunk_num)
                        self.rate_limiter.handle_success()
                        success = True
                        break

                except asyncio.TimeoutError:
                    logger.warning(f"Chunk {chunk_num} timeout, retrying...")
                    await asyncio.sleep(2 ** attempt)

            if not success:
                logger.error(f"❌ Failed to download chunk {chunk_num} after retries")
                # Save state before returning
                state = DownloadState(
                    url=url,
                    output_path=str(output_file),
                    chunk_size=chunk_size,
                    total_chunks=total_chunks,
                    chunks_completed=list(completed),
                    started_at=monitor.start_time,
                    last_chunk_time=time.time(),
                    session_token=auth_token,
                    session_expiry=time.time() + 3600,
                    current_rate=0,
                )
                state.save(output_file)
                return False

            monitor.update(chunk_num)

        # Validate
        logger.info("\n✔️ Validating download...")
        if not self.integrity_check.verify_file(output_file):
            return False

        logger.info("✅ Download complete and validated!")

        # Cleanup state file
        state_file = Path(f"{output_file}.state.json")
        if state_file.exists():
            state_file.unlink()

        return True

    async def _download_chunk(
        self,
        url: str,
        chunk_num: int,
        chunk_size: int,
        output_file: Path,
    ) -> bool:
        """Download single chunk with retries"""
        # Note: In production would use aiohttp or httpx for async
        # This is a simplified example
        logger.debug(f"Downloading chunk {chunk_num}...")
        return True  # Placeholder

    def _get_total_chunks(self, url: str, chunk_size: int) -> int:
        """Get total number of chunks needed"""
        # In production, would make HEAD request to get Content-Length
        # For now, return placeholder
        return 1000  # Placeholder


async def main():
    """Example usage"""
    downloader = ResilientDownloader(output_dir="./data")

    # Example download (would use real URL and token)
    success = await downloader.download(
        url="https://example.com/database.sql.gz",
        auth_token="your_auth_token_here",
        expected_hash="abc123def456...",
        chunk_size_mb=100,
    )

    if success:
        logger.info("🎉 Download successful!")
    else:
        logger.error("❌ Download failed")


if __name__ == "__main__":
    asyncio.run(main())
