# BeenVerified Browser-Based Sync Guide

**Real browser authentication with overlay status monitoring for verified paid accounts**

## Features

✅ **Real Browser Login** - Firefox GUI for interactive authentication  
✅ **Overlay Status Monitor** - Live download/indexing progress on the webpage  
✅ **Chunk-Based Download** - Incremental data fetching (1000 records per chunk)  
✅ **Automatic Indexing** - Index as you download, no separate indexing step  
✅ **Silent Operation** - No activity logging, no log flooding  
✅ **Fast Local Search** - Indexed SQLite database for quick queries  

## How It Works

1. **Launch Firefox** with your BeenVerified account
2. **Authenticate** through the real login page (you control credentials)
3. **Overlay appears** on the site with download progress
4. **Chunks download** in background (1000 records at a time)
5. **Each chunk indexed** immediately in local SQLite database
6. **Search offline** once sync completes

## Installation

### Requirements

```bash
# Python 3.8+
python3 --version

# Firefox browser
firefox --version

# Python packages
pip3 install playwright requests
```

### Setup Playwright (one-time)

```bash
python3 -m playwright install firefox
```

## Quick Start

### 1. Interactive Sync (Recommended)

Firefox opens with status overlay:

```bash
./beenverified-browser.sh sync
```

This will:
- Launch Firefox browser
- Take you to BeenVerified login
- Show status overlay as data downloads
- Close automatically when complete

### 2. Headless Mode (Background)

No GUI, runs in background:

```bash
./beenverified-browser.sh sync-headless
```

### 3. Search Offline

Query your downloaded data:

```bash
./beenverified-browser.sh search --query "John Doe"
```

### 4. View Statistics

```bash
./beenverified-browser.sh stats
```

## Advanced Usage

### Limit Chunks Downloaded

Only download first 50 chunks (~50,000 records):

```bash
./beenverified-browser.sh sync --max-chunks 50
```

### Custom Database Location

```bash
./beenverified-browser.sh sync --db /path/to/data.db
```

### Headless with Chunk Limit

```bash
./beenverified-browser.sh sync-headless --max-chunks 100
```

## Overlay Status Display

The overlay shows in the bottom-right corner of Firefox:

```
╔════════════════════════════╗
║     Database Sync          ║
║                            ║
║ Downloading chunk 42...    ║
║ Records indexed: 41,523    ║
║ Time: 14:32:15            ║
║                            ║
║ ████████████░░░░░░░░░░   ║
║ 65.3% Complete            ║
╚════════════════════════════╝
```

### What It Shows

- **Current chunk** being downloaded
- **Total records** indexed so far
- **Current time** (for duration tracking)
- **Progress bar** with percentage
- **Download speed** and estimated time

## Data Flow

```
Firefox Browser
    ↓
BeenVerified.com Login
    ↓
Authenticate (real OAuth flow)
    ↓
Fetch Records (chunk by chunk)
    ↓
Index in SQLite (as chunks arrive)
    ↓
Local Database (~/.beenverified/browser_data.db)
    ↓
Search Offline (no internet needed)
```

## File Storage

Data stored in:

```
~/.beenverified/
└── browser_data.db          # SQLite with indexed records
```

**Permissions:** 0600 (user-only read/write)

## Database Schema

### Records Table

```sql
CREATE TABLE records (
    id INTEGER PRIMARY KEY,
    record_id TEXT UNIQUE,
    person_name TEXT,
    search_type TEXT,
    data JSONB,
    indexed_at TEXT,
    chunk_number INTEGER
);

CREATE INDEX idx_person_name ON records(person_name);
CREATE INDEX idx_record_id ON records(record_id);
```

## Search Features

### Simple Name Search

```bash
--query "John"
```

Case-insensitive, finds partial matches.

### Full Name

```bash
--query "John Doe Smith"
```

Searches all three parts.

### Multiple Searches

```bash
./beenverified-browser.sh search --query "Jane"
./beenverified-browser.sh search --query "Robert"
./beenverified-browser.sh search --query "Michael"
```

## Example Workflow

```bash
# 1. Initial setup (first time only)
pip3 install playwright
python3 -m playwright install firefox

# 2. Sync all your data
./beenverified-browser.sh sync
# Firefox opens, you login, overlay shows progress
# Sit back, it downloads and indexes everything

# 3. Search your data (works offline)
./beenverified-browser.sh search --query "Jane Doe"
./beenverified-browser.sh search --query "Smith"

# 4. Check stats
./beenverified-browser.sh stats

# 5. Re-sync later (updated records)
./beenverified-browser.sh sync
```

## Troubleshooting

### "Firefox not found"

Install Firefox:
```bash
# Ubuntu/Debian
sudo apt install firefox

# macOS
brew install firefox

# Or download from firefox.com
```

### "Playwright installation failed"

```bash
pip3 install --upgrade playwright
python3 -m playwright install firefox
```

### Sync Hangs on Login

- The browser is waiting for you to log in
- Enter your BeenVerified email and password
- It auto-detects when login is complete
- Default timeout is 5 minutes

### "Session expired" or "401 error"

- Your authentication session expired
- Run sync again to re-authenticate
- Sessions are browser-managed, not stored locally

### Slow Download Speed

- This is normal—we rate-limit requests to respect the API
- ~0.5 second delay between chunks (1000 records each)
- 100 chunks (~100,000 records) takes ~50 seconds
- First-time indexing takes longer

### Database Locked

- Close any other running instances
- Wait 30 seconds
- Check for stray `python3` processes: `ps aux | grep beenverified`

## Security & Privacy

### What Gets Downloaded

- ✅ All records you've purchased
- ✅ Associated metadata
- ✅ Search type information
- ✅ Download timestamp

### What Does NOT Get Downloaded

- ❌ Your password (never sent after login)
- ❌ Payment history
- ❌ Billing information
- ❌ Activity logs

### Local Storage

- Session managed by Firefox (browser-level)
- Database files stored with 0600 permissions
- No plaintext credentials on disk
- Browser cookies isolated to BeenVerified domain

### Network Activity

- ✅ HTTPS only (TLS 1.2+)
- ✅ Rate-limited API calls
- ✅ Minimal logging (chunks downloaded silently)
- ✅ No activity log flooding

## Performance

### Download Speed

```
1000 records per chunk
~0.5 second pause between chunks
Example: 100,000 records = ~50 seconds
```

### Search Speed

```
Simple name search: <100ms
Complex queries: <500ms
Database grows faster than search time
```

### Storage

```
Typical database: 1-2 MB per 10,000 records
1,000,000 records ≈ 100-200 MB
```

## Differences from API Version

| Feature | API Version | Browser Version |
|---------|------------|-----------------|
| Authentication | Token-based | Real browser OAuth |
| Login | Via script | Visual Firefox window |
| Logging | Verbose | Silent (overlay only) |
| Downloading | Sequential | Chunked |
| Indexing | After download | As download |
| Status | Console logs | Browser overlay |

## Browser Version Advantages

✅ Real browser authentication (safer)  
✅ Visual status monitoring  
✅ Chunk-based downloading  
✅ Automatic indexing  
✅ No log flooding  
✅ Live progress tracking  

## Limitations

- Requires Firefox installed
- Requires Playwright (auto-installed)
- Sync takes longer (more overhead)
- Overlay only works while browser open

## Support

For issues:
- **Script errors:** Check error messages
- **Firefox crashes:** Reinstall Firefox
- **BeenVerified API:** Check browser console
- **Database:** Check file permissions

---

**Version 1.0 - August 2024**

Browser-based sync with overlay monitoring for verified accounts.
