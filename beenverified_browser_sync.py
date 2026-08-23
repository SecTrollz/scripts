#!/usr/bin/env python3
"""
BeenVerified Browser-Based Offline Database Access
Uses Firefox browser for authentication and provides an overlay status monitor
"""

import os
import sys
import json
import sqlite3
import asyncio
import argparse
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import time

try:
    from playwright.async_api import async_playwright, Page, Browser
except ImportError:
    print("Error: Playwright is required. Install with: pip install playwright")
    sys.exit(1)


class BrowserAuthenticator:
    """Handle BeenVerified authentication via Firefox browser"""

    LOGIN_URL = "https://www.beenverified.com/login"
    DASHBOARD_URL = "https://www.beenverified.com/dashboard"

    def __init__(self, headless: bool = False):
        self.headless = headless
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        self.auth_token = None
        self.cookies = {}

    async def launch(self):
        """Launch Firefox browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.firefox.launch(
            headless=self.headless,
            args=['--width=1400', '--height=900']
        )
        self.page = await self.browser.new_page()
        print("🌐 Firefox launched")

    async def login(self) -> bool:
        """Navigate to login and wait for authentication"""
        try:
            print("📱 Opening BeenVerified login page...")
            await self.page.goto(self.LOGIN_URL, wait_until='networkidle')

            # Inject overlay
            await self._inject_status_overlay(
                "Waiting for login...\n\nPlease enter your credentials"
            )

            # Wait for successful login (redirect to dashboard or records page)
            try:
                await self.page.wait_for_url(
                    lambda url: 'dashboard' in str(url) or 'records' in str(url),
                    timeout=300000  # 5 minutes
                )
            except Exception:
                print("❌ Login timeout or failed")
                return False

            # Extract auth information from localStorage/sessionStorage
            auth_data = await self.page.evaluate("""
                () => {
                    return {
                        localStorage: JSON.stringify(localStorage),
                        sessionStorage: JSON.stringify(sessionStorage),
                        cookies: document.cookie
                    };
                }
            """)

            self.auth_token = auth_data.get('localStorage', '{}')
            print("✅ Successfully authenticated")
            return True

        except Exception as e:
            print(f"❌ Login error: {e}")
            return False

    async def _inject_status_overlay(self, message: str, progress: float = 0):
        """Inject a status overlay on the page"""
        overlay_html = f"""
        <div id="bv-sync-overlay" style="
            position: fixed;
            top: 0;
            right: 0;
            width: 400px;
            height: 100vh;
            background: linear-gradient(135deg, #1e3a8a 0%, #2d5a96 100%);
            color: white;
            padding: 20px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            z-index: 10000;
            box-shadow: -2px 0 10px rgba(0,0,0,0.3);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            border-left: 4px solid #3b82f6;
        ">
            <div>
                <h2 style="margin: 0 0 20px 0; font-size: 18px; display: flex; align-items: center;">
                    <span style="display: inline-block; width: 24px; height: 24px; margin-right: 10px; border: 2px solid #3b82f6; border-radius: 50%; border-top-color: transparent; animation: spin 1s linear infinite;"></span>
                    Database Sync
                </h2>
                <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <p style="margin: 0; white-space: pre-wrap; font-size: 14px; line-height: 1.5;">{message}</p>
                </div>
            </div>

            <div>
                <div style="background: rgba(255,255,255,0.1); border-radius: 8px; height: 8px; margin-bottom: 10px; overflow: hidden;">
                    <div style="background: #3b82f6; height: 100%; width: {progress}%; transition: width 0.3s ease;"></div>
                </div>
                <p style="margin: 0; font-size: 12px; opacity: 0.8;">{progress:.1f}% Complete</p>
            </div>

            <style>
                @keyframes spin {{
                    to {{ transform: rotate(360deg); }}
                }}
            </style>
        </div>
        """

        await self.page.evaluate(f"""
            () => {{
                let overlay = document.getElementById('bv-sync-overlay');
                if (overlay) {{
                    overlay.remove();
                }}
                document.body.insertAdjacentHTML('beforeend', `{overlay_html}`);
            }}
        """)

    async def close(self):
        """Close browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()


class ChunkedDatabaseDownloader:
    """Download and index database in chunks"""

    CHUNK_SIZE = 1000  # Records per chunk
    API_BASE = "https://www.beenverified.com/api"

    def __init__(self, db_path: str, page: Page):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True, mode=0o700)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.page = page
        self.total_downloaded = 0
        self.total_records = 0
        self._init_schema()

    def _init_schema(self):
        """Initialize database schema"""
        cursor = self.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                record_id TEXT UNIQUE NOT NULL,
                person_name TEXT NOT NULL,
                search_type TEXT,
                data JSONB,
                indexed_at TEXT,
                chunk_number INTEGER
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_person_name ON records(person_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_record_id ON records(record_id)
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        self.conn.commit()

    async def download_chunks(self, max_chunks: Optional[int] = None) -> bool:
        """Download records in chunks with indexing"""
        try:
            chunk_num = 0
            total_chunks_estimate = max_chunks or 100

            while True:
                if max_chunks and chunk_num >= max_chunks:
                    break

                progress = (chunk_num / total_chunks_estimate) * 100

                # Update overlay
                await self._update_overlay(
                    f"Downloading chunk {chunk_num + 1}...\n"
                    f"Records indexed: {self.total_downloaded}\n"
                    f"Time: {datetime.now().strftime('%H:%M:%S')}",
                    progress
                )

                # Fetch chunk from API
                records = await self._fetch_chunk(chunk_num)

                if not records:
                    break

                # Index chunk
                self._index_chunk(records, chunk_num)
                self.total_downloaded += len(records)

                chunk_num += 1
                time.sleep(0.5)  # Rate limiting

            # Final update
            await self._update_overlay(
                f"✅ Sync complete!\n"
                f"Total records: {self.total_downloaded}\n"
                f"Completed: {datetime.now().strftime('%H:%M:%S')}",
                100
            )

            print(f"✅ Downloaded {self.total_downloaded} records in {chunk_num} chunks")
            return True

        except Exception as e:
            print(f"❌ Download error: {e}")
            return False

    async def _fetch_chunk(self, chunk_num: int) -> List[Dict]:
        """Fetch a chunk from the API"""
        try:
            url = f'{self.API_BASE}/v2/records?page={chunk_num + 1}&limit={self.CHUNK_SIZE}'
            response = await self.page.evaluate(f"""
                async () => {{
                    try {{
                        const response = await fetch(
                            '{url}',
                            {{
                                method: 'GET',
                                headers: {{
                                    'Accept': 'application/json',
                                    'X-Requested-With': 'XMLHttpRequest'
                                }}
                            }}
                        );
                        return await response.json();
                    }} catch (e) {{
                        return {{ records: [] }};
                    }}
                }}
            """)

            return response.get('records', []) if response else []

        except Exception as e:
            print(f"Warning: Chunk fetch failed: {e}")
            return []

    def _index_chunk(self, records: List[Dict], chunk_num: int):
        """Index a chunk of records in SQLite"""
        cursor = self.conn.cursor()

        for record in records:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO records
                    (record_id, person_name, search_type, data, indexed_at, chunk_number)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    record.get('id'),
                    record.get('name', ''),
                    record.get('type'),
                    json.dumps(record),
                    datetime.now().isoformat(),
                    chunk_num
                ))
            except Exception as e:
                print(f"Warning: Failed to index record: {e}")
                continue

        self.conn.commit()

    async def _update_overlay(self, message: str, progress: float):
        """Update status overlay"""
        overlay_html = f"""<div id="bv-sync-overlay" style="position:fixed;top:0;right:0;width:420px;height:100vh;background:linear-gradient(135deg,#1e3a8a 0%,#2d5a96 100%);color:white;padding:25px;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;z-index:10000;box-shadow:-4px 0 20px rgba(0,0,0,0.4);display:flex;flex-direction:column;justify-content:space-between;border-left:5px solid #3b82f6"><div><h2 style="margin:0 0 25px 0;font-size:20px;font-weight:600;display:flex;align-items:center"><span style="display:inline-block;width:28px;height:28px;margin-right:12px;border:3px solid #3b82f6;border-radius:50%;border-top-color:transparent;animation:spin 1s linear infinite"></span>Database Sync</h2><div style="background:rgba(255,255,255,0.1);padding:18px;border-radius:10px;margin-bottom:25px;border:1px solid rgba(255,255,255,0.2)"><p style="margin:0;white-space:pre-wrap;font-size:14px;line-height:1.6;font-family:'Monaco',monospace">{message}</p></div><div style="background:rgba(255,255,255,0.05);padding:12px;border-radius:8px;font-size:12px;opacity:0.9;border-left:3px solid #3b82f6"><p style="margin:0;margin-bottom:8px"><strong>Status:</strong> Indexing data...</p><p style="margin:0"><strong>Process:</strong> Chunk-based download with local indexing</p></div></div><div><div style="background:rgba(255,255,255,0.15);border-radius:10px;height:10px;margin-bottom:12px;overflow:hidden;border:1px solid rgba(255,255,255,0.2)"><div style="background:linear-gradient(90deg,#3b82f6,#60a5fa);height:100%;width:{progress}%;transition:width 0.4s cubic-bezier(0.4,0,0.2,1);box-shadow:0 0 10px rgba(59,130,246,0.5)"></div></div><p style="margin:0;font-size:13px;opacity:0.85;font-weight:500">{progress:.1f}% Complete</p></div><style>@keyframes spin {{from {{transform:rotate(0deg)}} to {{transform:rotate(360deg)}}}}</style></div>"""

        try:
            escaped_html = overlay_html.replace('`', '\\`').replace("'", "\\'")
            await self.page.evaluate(f"""
                () => {{
                    let overlay = document.getElementById('bv-sync-overlay');
                    if (overlay) {{
                        overlay.remove();
                    }}
                    document.body.insertAdjacentHTML('beforeend', `{escaped_html}`);
                }}
            """)
        except Exception as e:
            print(f"Warning: Could not update overlay: {e}")

    def search(self, query: str) -> List[Dict]:
        """Search indexed database"""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT * FROM records
            WHERE person_name LIKE ?
            LIMIT 100
        """, (f"%{query}%",))

        results = []
        for row in cursor.fetchall():
            try:
                record_data = json.loads(row['data'])
                results.append({
                    'id': row['record_id'],
                    'name': row['person_name'],
                    'type': row['search_type'],
                    'indexed_at': row['indexed_at'],
                    'chunk': row['chunk_number'],
                    'data': record_data
                })
            except json.JSONDecodeError:
                pass

        return results

    def get_stats(self) -> Dict:
        """Get sync statistics"""
        cursor = self.conn.cursor()

        cursor.execute("SELECT COUNT(*) as total FROM records")
        total = cursor.fetchone()['total']

        cursor.execute("SELECT COUNT(DISTINCT chunk_number) as chunks FROM records")
        chunks = cursor.fetchone()['chunks']

        return {
            'total_records': total,
            'total_chunks': chunks,
            'last_sync': datetime.now().isoformat()
        }

    def close(self):
        """Close database"""
        self.conn.close()


async def main():
    parser = argparse.ArgumentParser(
        description="BeenVerified Browser-Based Offline Sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive browser sync
  %(prog)s sync --headless false

  # Headless mode (background)
  %(prog)s sync

  # Search indexed database
  %(prog)s search --query "John Doe"
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Sync command
    sync_parser = subparsers.add_parser('sync', help='Sync database via browser')
    sync_parser.add_argument('--headless', default='true', help='Run headless (true/false)')
    sync_parser.add_argument('--max-chunks', type=int, help='Max chunks to download')
    sync_parser.add_argument('--db', default='~/.beenverified/browser_data.db', help='Database path')

    # Search command
    search_parser = subparsers.add_parser('search', help='Search indexed database')
    search_parser.add_argument('--query', required=True, help='Search query')
    search_parser.add_argument('--db', default='~/.beenverified/browser_data.db', help='Database path')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show sync statistics')
    stats_parser.add_argument('--db', default='~/.beenverified/browser_data.db', help='Database path')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    db_path = os.path.expanduser(args.db)

    if args.command == 'sync':
        headless = args.headless.lower() == 'true'

        print("🚀 Starting browser-based sync...")
        print(f"📁 Database: {db_path}")
        print(f"🎯 Mode: {'Headless' if headless else 'Interactive (Firefox will open)'}")
        print()

        authenticator = BrowserAuthenticator(headless=headless)

        try:
            await authenticator.launch()

            # Login via browser
            if not await authenticator.login():
                return 1

            # Download and index
            downloader = ChunkedDatabaseDownloader(db_path, authenticator.page)
            await downloader.download_chunks(args.max_chunks)

            stats = downloader.get_stats()
            print(f"\n📊 Sync Complete!")
            print(f"   Total Records: {stats['total_records']}")
            print(f"   Chunks: {stats['total_chunks']}")
            downloader.close()

        finally:
            await authenticator.close()

        return 0

    elif args.command == 'search':
        downloader = ChunkedDatabaseDownloader(db_path, None)
        results = downloader.search(args.query)

        if not results:
            print(f"❌ No records found for '{args.query}'")
            downloader.close()
            return 1

        print(f"\n📊 Found {len(results)} record(s):\n")
        for result in results:
            print(f"Name: {result['name']}")
            print(f"ID: {result['id']}")
            print(f"Type: {result['type']}")
            print(f"Indexed: {result['indexed_at']}")
            print(f"Chunk: {result['chunk']}")
            print("-" * 60)

        downloader.close()
        return 0

    elif args.command == 'stats':
        downloader = ChunkedDatabaseDownloader(db_path, None)
        stats = downloader.get_stats()

        print("\n📈 Database Statistics:")
        print(f"  Total Records: {stats['total_records']}")
        print(f"  Chunks: {stats['total_chunks']}")
        print(f"  Last Sync: {stats['last_sync']}")
        print()

        downloader.close()
        return 0


if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
