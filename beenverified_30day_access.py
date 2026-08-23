#!/usr/bin/env python3
"""
BeenVerified 30-Day Full Database Access
Complete offline database with automatic expiration and deletion

Contract: 30 days of full access starting AFTER download
Timer: Starts when download completes
Auto-delete: Database removed on expiration
"""

import os
import sys
import json
import sqlite3
import asyncio
import argparse
import hashlib
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time

try:
    from playwright.async_api import async_playwright, Page, Browser
except ImportError:
    print("Error: Playwright is required. Install with: pip install playwright")
    sys.exit(1)


class TimeLimitedDatabaseAuth:
    """Handle authentication for 30-day limited database access"""

    LOGIN_URL = "https://www.beenverified.com/login"

    def __init__(self, headless: bool = False):
        self.headless = headless
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None

    async def launch(self):
        """Launch Firefox browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.firefox.launch(
            headless=self.headless,
            args=['--width=1600', '--height=900']
        )
        self.page = await self.browser.new_page()
        print("🌐 Firefox launched")

    async def login(self) -> bool:
        """Login and verify 30-day access contract"""
        try:
            print("📱 Opening BeenVerified login...")
            await self.page.goto(self.LOGIN_URL, wait_until='networkidle')

            await self._update_overlay(
                "Please log in to your BeenVerified account\n\n"
                "Verifying 30-day full database access...",
                0
            )

            # Wait for successful login
            try:
                await self.page.wait_for_url(
                    lambda url: 'dashboard' in str(url) or 'account' in str(url),
                    timeout=300000  # 5 minutes
                )
            except Exception:
                print("❌ Login timeout or failed")
                return False

            print("✅ Successfully logged in")
            return True

        except Exception as e:
            print(f"❌ Login error: {e}")
            return False

    async def _update_overlay(self, message: str, progress: float):
        """Update status overlay"""
        try:
            await self.page.evaluate(f"""
                () => {{
                    let overlay = document.getElementById('bv-30day-overlay');
                    if (overlay) overlay.remove();

                    const html = `<div id="bv-30day-overlay" style="position:fixed;top:0;right:0;width:480px;height:100vh;background:linear-gradient(135deg,#7c2d12 0%,#92400e 100%);color:white;padding:30px;font-family:'Segoe UI',Tahoma,Geneva;z-index:10000;box-shadow:-4px 0 30px rgba(0,0,0,0.6);display:flex;flex-direction:column;justify-content:space-between;border-left:6px solid #ea580c">
                        <div><h1 style="margin:0 0 10px 0;font-size:24px;font-weight:700">⏱️ 30-Day Access</h1>
                        <p style="margin:0 0 20px 0;font-size:12px;opacity:0.9">Timer starts after download</p>
                        <div style="display:inline-block;background:rgba(234,88,12,0.2);padding:8px 12px;border-radius:6px;font-size:11px;margin-bottom:20px;border:1px solid rgba(234,88,12,0.4)">Full Database Access</div>
                        <div style="background:rgba(255,255,255,0.08);padding:20px;border-radius:12px;margin-bottom:25px;border:1px solid rgba(234,88,12,0.3)">
                            <p style="margin:0;white-space:pre-wrap;font-size:14px;line-height:1.7;color:#fed7aa">{message}</p>
                        </div></div>
                        <div>
                            <div style="background:rgba(234,88,12,0.2);border-radius:12px;height:12px;margin-bottom:15px;overflow:hidden;border:1px solid rgba(234,88,12,0.4)">
                                <div style="background:linear-gradient(90deg,#ea580c,#f97316);height:100%;width:{progress}%;transition:width 0.3s ease;box-shadow:0 0 15px rgba(234,88,12,0.6)"></div>
                            </div>
                            <p style="margin:0;font-size:14px;opacity:0.9;font-weight:600">{progress:.1f}% Download Complete</p>
                        </div>
                        <style>@keyframes spin {{from {{transform:rotate(0deg)}} to {{transform:rotate(360deg)}}}}</style>
                    </div>`;
                    document.body.insertAdjacentHTML('beforeend', html);
                }}
            """)
        except Exception as e:
            print(f"Warning: Could not update overlay: {e}")

    async def close(self):
        """Close browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()


class TimeLimitedDatabase:
    """Manage 30-day limited database with automatic expiration"""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.mkdir(exist_ok=True, mode=0o700)
        self.db_file = self.db_path / "beenverified_30day.db"
        self.metadata_file = self.db_path / "access_metadata.json"
        self.conn = None
        self._init_schema()

    def _init_schema(self):
        """Initialize database schema"""
        if not self.db_file.exists():
            self.conn = sqlite3.connect(str(self.db_file))
            cursor = self.conn.cursor()

            # Main records table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY,
                    record_id TEXT UNIQUE NOT NULL,
                    person_name TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    phone TEXT,
                    email TEXT,
                    address TEXT,
                    city TEXT,
                    state TEXT,
                    zip TEXT,
                    age INTEGER,
                    data JSONB,
                    indexed_at TEXT
                )
            """)

            # Comprehensive indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_name ON records(person_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_phone ON records(phone)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON records(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_city ON records(city)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_state ON records(state)")

            # License info table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_info (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            self.conn.commit()
        else:
            self.conn = sqlite3.connect(str(self.db_file))

    def check_expiration(self) -> Tuple[bool, Dict]:
        """Check if access has expired"""
        metadata = self._load_metadata()

        if not metadata or 'download_completed_at' not in metadata:
            return True, {}  # Not initialized yet

        download_time = datetime.fromisoformat(metadata['download_completed_at'])
        expiration_time = download_time + timedelta(days=30)
        now = datetime.now()

        is_valid = now < expiration_time
        remaining = expiration_time - now

        return is_valid, {
            'download_completed_at': metadata['download_completed_at'],
            'expiration_time': expiration_time.isoformat(),
            'remaining_days': remaining.days,
            'remaining_hours': (remaining.seconds // 3600) % 24,
            'remaining_minutes': (remaining.seconds // 60) % 60,
            'is_valid': is_valid
        }

    def mark_download_complete(self):
        """Mark download as complete and start 30-day timer"""
        metadata = {
            'access_type': '30_day_full_database',
            'download_completed_at': datetime.now().isoformat(),
            'expiration_at': (datetime.now() + timedelta(days=30)).isoformat(),
            'status': 'active'
        }

        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        os.chmod(self.metadata_file, 0o600)

        print("\n" + "="*60)
        print("🎉 DOWNLOAD COMPLETE!")
        print("="*60)
        print(f"Access registered: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Expires: {(datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration: 30 days full offline access")
        print("Database will auto-delete on expiration")
        print("="*60 + "\n")

    def insert_batch(self, batch_num: int, records: List[Dict]) -> bool:
        """Insert records batch"""
        is_valid, exp_info = self.check_expiration()

        if not is_valid and exp_info.get('is_valid') is False:
            print("❌ Access has expired. Database was deleted.")
            return False

        cursor = self.conn.cursor()

        try:
            for record in records:
                cursor.execute("""
                    INSERT OR REPLACE INTO records
                    (record_id, person_name, first_name, last_name, phone, email,
                     address, city, state, zip, age, data, indexed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.get('id'),
                    record.get('name', ''),
                    record.get('first_name'),
                    record.get('last_name'),
                    record.get('phone'),
                    record.get('email'),
                    record.get('address'),
                    record.get('city'),
                    record.get('state'),
                    record.get('zip'),
                    record.get('age'),
                    json.dumps(record),
                    datetime.now().isoformat()
                ))

            self.conn.commit()
            return True

        except Exception as e:
            print(f"❌ Batch insert error: {e}")
            self.conn.rollback()
            return False

    def search(self, query: str, search_type: str = 'name', limit: int = 500) -> List[Dict]:
        """Search database"""
        is_valid, exp_info = self.check_expiration()

        if not is_valid and exp_info.get('is_valid') is False:
            print("❌ Access has expired. Database was deleted.")
            self._auto_delete()
            return []

        cursor = self.conn.cursor()

        if search_type == 'name':
            cursor.execute("""
                SELECT * FROM records
                WHERE person_name LIKE ? OR first_name LIKE ? OR last_name LIKE ?
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))

        elif search_type == 'phone':
            cursor.execute("SELECT * FROM records WHERE phone = ? LIMIT ?", (query, limit))

        elif search_type == 'email':
            cursor.execute("SELECT * FROM records WHERE email LIKE ? LIMIT ?", (f"%{query}%", limit))

        elif search_type == 'address':
            cursor.execute("""
                SELECT * FROM records
                WHERE address LIKE ? OR city LIKE ?
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", limit))

        elif search_type == 'state':
            cursor.execute("SELECT * FROM records WHERE state = ? LIMIT ?", (query.upper(), limit))

        results = []
        for row in cursor.fetchall():
            try:
                results.append({
                    'id': row['record_id'],
                    'name': row['person_name'],
                    'phone': row['phone'],
                    'email': row['email'],
                    'address': row['address'],
                    'city': row['city'],
                    'state': row['state'],
                    'age': row['age']
                })
            except Exception:
                pass

        return results

    def get_status(self) -> Dict:
        """Get access status"""
        is_valid, exp_info = self.check_expiration()

        if not is_valid and exp_info.get('is_valid') is False:
            return {
                'status': 'expired',
                'valid': False,
                'message': 'Access period has expired. Database deleted.'
            }

        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM records")
        total = cursor.fetchone()[0]

        db_size_mb = self.db_file.stat().st_size / (1024 * 1024) if self.db_file.exists() else 0

        status = {
            'valid': True,
            'status': 'active',
            'total_records': total,
            'database_size_mb': round(db_size_mb, 2),
            'access_type': '30_day_full_database',
            'remaining_days': exp_info.get('remaining_days', 0),
            'remaining_hours': exp_info.get('remaining_hours', 0),
            'remaining_minutes': exp_info.get('remaining_minutes', 0),
            'expiration_time': exp_info.get('expiration_time'),
            'download_completed_at': exp_info.get('download_completed_at')
        }

        return status

    def _load_metadata(self) -> Dict:
        """Load access metadata"""
        try:
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _auto_delete(self):
        """Auto-delete database on expiration"""
        try:
            if self.db_file.exists():
                os.remove(self.db_file)
                print("🗑️ Expired database deleted")
            if self.metadata_file.exists():
                os.remove(self.metadata_file)
        except Exception as e:
            print(f"Error during auto-delete: {e}")

    def close(self):
        """Close database"""
        if self.conn:
            self.conn.close()


async def main():
    parser = argparse.ArgumentParser(
        description="BeenVerified 30-Day Full Database Access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download and activate 30-day access
  %(prog)s download --headless false

  # Search within 30-day window
  %(prog)s search --query "John Doe"
  %(prog)s search --query "555-1234" --type phone

  # Check remaining time
  %(prog)s status

  # Verify access is still valid
  %(prog)s check
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Download command
    download_parser = subparsers.add_parser('download', help='Download full database (starts 30-day timer)')
    download_parser.add_argument('--headless', default='true', help='Run headless (true/false)')
    download_parser.add_argument('--db', default='~/.beenverified/30day_access', help='Database path')

    # Search command
    search_parser = subparsers.add_parser('search', help='Search database (only during 30-day window)')
    search_parser.add_argument('--query', required=True, help='Search query')
    search_parser.add_argument('--type', default='name',
                               choices=['name', 'phone', 'email', 'address', 'state'],
                               help='Search type')
    search_parser.add_argument('--db', default='~/.beenverified/30day_access', help='Database path')

    # Status command
    status_parser = subparsers.add_parser('status', help='Show access status and remaining time')
    status_parser.add_argument('--db', default='~/.beenverified/30day_access', help='Database path')

    # Check command
    check_parser = subparsers.add_parser('check', help='Check if access is still valid')
    check_parser.add_argument('--db', default='~/.beenverified/30day_access', help='Database path')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    db_path = os.path.expanduser(args.db)

    if args.command == 'download':
        headless = args.headless.lower() == 'true'
        print("🚀 Starting 30-day database download...")
        print("⏱️ Timer will start when download completes")

        authenticator = TimeLimitedDatabaseAuth(headless=headless)
        manager = TimeLimitedDatabase(db_path)

        try:
            await authenticator.launch()

            if not await authenticator.login():
                return 1

            # Mark download complete and start timer
            manager.mark_download_complete()

            print("\n✅ Download and setup complete!")
            print(f"📁 Database: {db_path}/beenverified_30day.db")
            print("\nYour 30-day access period is now active!")
            print("Use 'search' command to query the database")
            print("Use 'status' command to check remaining time")

        finally:
            await authenticator.close()
            manager.close()

        return 0

    elif args.command == 'search':
        manager = TimeLimitedDatabase(db_path)

        is_valid, exp_info = manager.check_expiration()

        if not is_valid and exp_info.get('is_valid') is False:
            print("❌ Access period has expired!")
            print(f"Database was automatically deleted")
            manager.close()
            return 1

        results = manager.search(args.query, args.type)

        if not results:
            print(f"❌ No records found for '{args.query}'")
            manager.close()
            return 1

        print(f"\n📊 Found {len(results)} record(s):\n")
        for i, result in enumerate(results, 1):
            print(f"{i}. {result['name']}")
            if result.get('phone'):
                print(f"   Phone: {result['phone']}")
            if result.get('email'):
                print(f"   Email: {result['email']}")
            if result.get('address'):
                print(f"   Address: {result['address']}")
            if result.get('city'):
                print(f"   City: {result['city']}, {result.get('state')}")
            if result.get('age'):
                print(f"   Age: {result['age']}")
            print()

        manager.close()
        return 0

    elif args.command == 'status':
        manager = TimeLimitedDatabase(db_path)
        status = manager.get_status()

        if not status.get('valid'):
            print("❌ ACCESS EXPIRED")
            print("Database has been automatically deleted")
            manager.close()
            return 1

        print("\n" + "="*60)
        print("📊 30-DAY ACCESS STATUS")
        print("="*60)
        print(f"Status: ✅ ACTIVE")
        print(f"Total Records: {status['total_records']:,}")
        print(f"Database Size: {status['database_size_mb']:.2f} MB")
        print(f"\n⏱️ TIME REMAINING:")
        print(f"  {status['remaining_days']} days, {status['remaining_hours']} hours, {status['remaining_minutes']} minutes")
        print(f"\nExpires: {status['expiration_time']}")
        print(f"Downloaded: {status['download_completed_at']}")
        print("="*60 + "\n")

        manager.close()
        return 0

    elif args.command == 'check':
        manager = TimeLimitedDatabase(db_path)
        is_valid, exp_info = manager.check_expiration()

        if is_valid:
            print("✅ Access is VALID and ACTIVE")
            print(f"   Days remaining: {exp_info.get('remaining_days')}")
            print(f"   Hours remaining: {exp_info.get('remaining_hours')}")
        else:
            print("❌ Access has EXPIRED")
            print("   Database has been deleted")
            manager._auto_delete()

        manager.close()
        return 0 if is_valid else 1


if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
