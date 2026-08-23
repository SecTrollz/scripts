#!/usr/bin/env python3
"""
BeenVerified Offline Database Access
For verified paid account holders to access purchased data offline

This script:
- Authenticates with BeenVerified credentials
- Downloads purchased records
- Stores them locally in SQLite for offline access
- Provides search and query capabilities
- Tracks download history and licenses
"""

import os
import sys
import json
import sqlite3
import hashlib
import requests
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import getpass
import time


class BeenVerifiedAuth:
    """Handle authentication with BeenVerified API"""

    BASE_URL = "https://www.beenverified.com/api"
    SESSION_TIMEOUT = 3600  # 1 hour

    def __init__(self, config_dir: str = None):
        self.config_dir = Path(config_dir or Path.home() / ".beenverified")
        self.config_dir.mkdir(exist_ok=True, mode=0o700)
        self.session_file = self.config_dir / "session.json"
        self.creds_file = self.config_dir / "credentials.json"
        self.session = requests.Session()
        self.session_data = {}
        self._load_session()

    def _load_session(self) -> bool:
        """Load existing session if valid"""
        if not self.session_file.exists():
            return False

        try:
            with open(self.session_file, 'r') as f:
                data = json.load(f)

            if datetime.fromisoformat(data['expires_at']) > datetime.now():
                self.session_data = data
                return True
        except (json.JSONDecodeError, KeyError, ValueError):
            pass

        return False

    def _save_session(self):
        """Save session to file with restrictive permissions"""
        with open(self.session_file, 'w') as f:
            json.dump(self.session_data, f)
        os.chmod(self.session_file, 0o600)

    def login(self, email: str, password: str) -> bool:
        """Authenticate with BeenVerified"""
        try:
            response = self.session.post(
                f"{self.BASE_URL}/v2/login",
                json={"email": email, "password": password},
                timeout=10
            )
            response.raise_for_status()

            data = response.json()
            if not data.get('success'):
                print(f"❌ Login failed: {data.get('message', 'Unknown error')}")
                return False

            self.session_data = {
                'access_token': data['token'],
                'user_id': data['user_id'],
                'email': email,
                'subscription_tier': data.get('subscription_tier'),
                'expires_at': (datetime.now() + timedelta(seconds=self.SESSION_TIMEOUT)).isoformat()
            }
            self._save_session()
            print(f"✅ Successfully logged in as {email}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"❌ Connection error: {e}")
            return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False

    def is_authenticated(self) -> bool:
        """Check if session is still valid"""
        if not self.session_data:
            return False

        expires = datetime.fromisoformat(self.session_data['expires_at'])
        return datetime.now() < expires

    def get_headers(self) -> Dict[str, str]:
        """Get authorization headers"""
        if not self.is_authenticated():
            raise ValueError("Session expired. Please login again.")

        return {
            'Authorization': f"Bearer {self.session_data['access_token']}",
            'Content-Type': 'application/json'
        }

    def verify_subscription(self) -> Tuple[bool, Dict]:
        """Verify subscription status"""
        try:
            response = self.session.get(
                f"{self.BASE_URL}/v2/account/subscription",
                headers=self.get_headers(),
                timeout=10
            )
            response.raise_for_status()

            data = response.json()
            return data.get('is_active', False), data
        except Exception as e:
            print(f"❌ Error verifying subscription: {e}")
            return False, {}


class OfflineDatabase:
    """Manage local SQLite database for offline access"""

    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path or Path.home() / ".beenverified" / "purchased_data.db")
        self.db_path.parent.mkdir(exist_ok=True, mode=0o700)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        """Initialize database schema"""
        cursor = self.conn.cursor()

        # License/account tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY,
                account_email TEXT UNIQUE NOT NULL,
                subscription_tier TEXT,
                purchase_date TEXT,
                expiration_date TEXT,
                records_limit INTEGER,
                records_used INTEGER,
                last_sync TEXT
            )
        """)

        # Downloaded records
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                record_id TEXT UNIQUE NOT NULL,
                person_name TEXT NOT NULL,
                search_type TEXT,
                data JSONB,
                download_date TEXT,
                license_id INTEGER,
                FOREIGN KEY(license_id) REFERENCES licenses(id)
            )
        """)

        # Search index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_person_name
            ON records(person_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_record_id
            ON records(record_id)
        """)

        # Sync history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_history (
                id INTEGER PRIMARY KEY,
                license_id INTEGER,
                sync_date TEXT,
                records_synced INTEGER,
                status TEXT,
                FOREIGN KEY(license_id) REFERENCES licenses(id)
            )
        """)

        self.conn.commit()

    def register_license(self, email: str, tier: str, records_limit: int = 1000):
        """Register a new license"""
        cursor = self.conn.cursor()
        expiration = (datetime.now() + timedelta(days=365)).isoformat()

        cursor.execute("""
            INSERT OR REPLACE INTO licenses
            (account_email, subscription_tier, purchase_date, expiration_date, records_limit, records_used)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (email, tier, datetime.now().isoformat(), expiration, records_limit, 0))

        self.conn.commit()
        print(f"✅ License registered for {email}")

    def add_records(self, license_email: str, records: List[Dict]):
        """Add downloaded records to database"""
        cursor = self.conn.cursor()

        # Get license ID
        cursor.execute("SELECT id FROM licenses WHERE account_email = ?", (license_email,))
        license_row = cursor.fetchone()

        if not license_row:
            print(f"❌ License not found for {license_email}")
            return False

        license_id = license_row[0]

        try:
            for record in records:
                cursor.execute("""
                    INSERT OR REPLACE INTO records
                    (record_id, person_name, search_type, data, download_date, license_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    record.get('id'),
                    record.get('name', ''),
                    record.get('type'),
                    json.dumps(record),
                    datetime.now().isoformat(),
                    license_id
                ))

            # Update records_used
            cursor.execute("""
                UPDATE licenses
                SET records_used = (
                    SELECT COUNT(*) FROM records WHERE license_id = ?
                )
                WHERE id = ?
            """, (license_id, license_id))

            self.conn.commit()
            print(f"✅ Added {len(records)} records to database")
            return True
        except Exception as e:
            print(f"❌ Error adding records: {e}")
            self.conn.rollback()
            return False

    def search_records(self, query: str, license_email: str) -> List[Dict]:
        """Search records offline"""
        cursor = self.conn.cursor()

        # Verify license
        cursor.execute("SELECT id FROM licenses WHERE account_email = ?", (license_email,))
        license_row = cursor.fetchone()

        if not license_row:
            print(f"❌ No valid license for {license_email}")
            return []

        license_id = license_row[0]

        # Search by name (case-insensitive)
        cursor.execute("""
            SELECT * FROM records
            WHERE license_id = ? AND person_name LIKE ?
            LIMIT 100
        """, (license_id, f"%{query}%"))

        results = []
        for row in cursor.fetchall():
            try:
                record_data = json.loads(row['data'])
                results.append({
                    'id': row['record_id'],
                    'name': row['person_name'],
                    'type': row['search_type'],
                    'download_date': row['download_date'],
                    'data': record_data
                })
            except json.JSONDecodeError:
                pass

        return results

    def get_stats(self, license_email: str) -> Dict:
        """Get account statistics"""
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT records_limit, records_used, expiration_date
            FROM licenses
            WHERE account_email = ?
        """, (license_email,))

        row = cursor.fetchone()
        if not row:
            return {}

        return {
            'records_limit': row[0],
            'records_used': row[1],
            'records_remaining': row[0] - row[1],
            'expiration_date': row[2]
        }

    def close(self):
        """Close database connection"""
        self.conn.close()


class BeenVerifiedClient:
    """Main client for offline database access"""

    def __init__(self, config_dir: str = None):
        self.auth = BeenVerifiedAuth(config_dir)
        self.db = OfflineDatabase(Path(config_dir or Path.home() / ".beenverified") / "purchased_data.db")

    def setup(self, email: str, password: str = None):
        """Setup and verify account"""
        if password is None:
            password = getpass.getpass("Enter BeenVerified password: ")

        # Login
        if not self.auth.login(email, password):
            return False

        # Verify subscription
        is_active, sub_data = self.auth.verify_subscription()
        if not is_active:
            print("❌ Subscription is not active. Please renew your subscription.")
            return False

        # Register license
        tier = sub_data.get('subscription_tier', 'standard')
        records_limit = sub_data.get('records_limit', 1000)
        self.db.register_license(email, tier, records_limit)

        print(f"✅ Setup complete! Tier: {tier}, Records available: {records_limit}")
        return True

    def sync_database(self, email: str, page_size: int = 100):
        """Download and sync purchased records"""
        if not self.auth.is_authenticated():
            print("❌ Not authenticated. Please setup first.")
            return False

        try:
            print("🔄 Starting database sync...")
            page = 1
            total_synced = 0

            while True:
                response = requests.get(
                    f"{self.auth.BASE_URL}/v2/account/records",
                    headers=self.auth.get_headers(),
                    params={'page': page, 'limit': page_size},
                    timeout=30
                )
                response.raise_for_status()

                data = response.json()
                records = data.get('records', [])

                if not records:
                    break

                # Add records to database
                self.db.add_records(email, records)
                total_synced += len(records)

                print(f"📥 Synced {total_synced} records...")

                if not data.get('has_next'):
                    break

                page += 1
                time.sleep(0.5)  # Rate limiting

            print(f"✅ Sync complete! Total records: {total_synced}")
            return True

        except requests.exceptions.RequestException as e:
            print(f"❌ Sync error: {e}")
            return False

    def search(self, query: str, email: str):
        """Search offline database"""
        results = self.db.search_records(query, email)

        if not results:
            print(f"❌ No records found for '{query}'")
            return

        print(f"\n📊 Found {len(results)} record(s):\n")
        for result in results:
            print(f"Name: {result['name']}")
            print(f"ID: {result['id']}")
            print(f"Type: {result['type']}")
            print(f"Downloaded: {result['download_date']}")
            print("-" * 60)

    def show_stats(self, email: str):
        """Display account statistics"""
        stats = self.db.get_stats(email)

        if not stats:
            print("❌ No license found")
            return

        print("\n📈 Account Statistics:")
        print(f"  Records Used: {stats['records_used']}/{stats['records_limit']}")
        print(f"  Records Remaining: {stats['records_remaining']}")
        print(f"  Expires: {stats['expiration_date']}")
        print()

    def close(self):
        """Cleanup"""
        self.db.close()


def main():
    parser = argparse.ArgumentParser(
        description="BeenVerified Offline Database Access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initial setup
  %(prog)s setup --email user@example.com

  # Sync purchased data
  %(prog)s sync --email user@example.com

  # Search offline
  %(prog)s search --email user@example.com --query "John Doe"

  # Show statistics
  %(prog)s stats --email user@example.com
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Setup BeenVerified account')
    setup_parser.add_argument('--email', required=True, help='BeenVerified email')
    setup_parser.add_argument('--password', help='BeenVerified password (will prompt if not provided)')
    setup_parser.add_argument('--config-dir', help='Config directory path')

    # Sync command
    sync_parser = subparsers.add_parser('sync', help='Sync purchased database')
    sync_parser.add_argument('--email', required=True, help='BeenVerified email')
    sync_parser.add_argument('--config-dir', help='Config directory path')
    sync_parser.add_argument('--page-size', type=int, default=100, help='Records per page')

    # Search command
    search_parser = subparsers.add_parser('search', help='Search offline database')
    search_parser.add_argument('--email', required=True, help='BeenVerified email')
    search_parser.add_argument('--query', required=True, help='Search query (name)')
    search_parser.add_argument('--config-dir', help='Config directory path')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show account statistics')
    stats_parser.add_argument('--email', required=True, help='BeenVerified email')
    stats_parser.add_argument('--config-dir', help='Config directory path')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    client = BeenVerifiedClient(args.config_dir)

    try:
        if args.command == 'setup':
            success = client.setup(args.email, args.password)
            return 0 if success else 1

        elif args.command == 'sync':
            if not client.auth.is_authenticated():
                print("❌ Not authenticated. Run 'setup' first.")
                return 1
            success = client.sync_database(args.email, args.page_size)
            return 0 if success else 1

        elif args.command == 'search':
            if not client.auth.is_authenticated():
                print("❌ Not authenticated. Run 'setup' first.")
                return 1
            client.search(args.query, args.email)
            return 0

        elif args.command == 'stats':
            client.show_stats(args.email)
            return 0

    finally:
        client.close()


if __name__ == '__main__':
    sys.exit(main())
