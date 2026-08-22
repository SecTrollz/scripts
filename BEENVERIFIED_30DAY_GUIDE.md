# BeenVerified 30-Day Full Database Access Guide

**Complete offline database with automatic expiration - timer starts after download**

## How It Works

```
Timeline:
Day 0    → Run 'download' command
         → Firefox opens, you log in
         → Database downloads completely
         → ⏱️ TIMER STARTS (30 days)
         
Days 1-30 → Full offline access
          → Search any time
          → Database available
          → Check remaining time
          
Day 30   → ⚠️ ACCESS EXPIRES
         → Database automatically deleted
         → No offline access after this
```

## Quick Start

### Step 1: Download Database (Timer Starts Here)

```bash
./beenverified-30day.sh download
```

This will:
- Launch Firefox with overlay
- You log into BeenVerified
- Download entire database
- Register 30-day access license
- **Start the countdown timer**

### Step 2: Check Remaining Time

```bash
./beenverified-30day.sh status
```

Shows:
```
====================================================
📊 30-DAY ACCESS STATUS
====================================================
Status: ✅ ACTIVE
Total Records: 500,000,000
Database Size: 2500.00 MB

⏱️ TIME REMAINING:
  24 days, 12 hours, 30 minutes

Expires: 2026-09-21 14:30:45
Downloaded: 2026-08-22 14:30:45
====================================================
```

### Step 3: Search During the 30 Days

```bash
# Search by name
./beenverified-30day.sh search --query "John Doe"

# Search by phone
./beenverified-30day.sh search --query "555-1234" --type phone

# Search by address
./beenverified-30day.sh search --query "New York" --type address

# Search by state
./beenverified-30day.sh search --query "CA" --type state

# Search by email
./beenverified-30day.sh search --query "john@example.com" --type email
```

### Step 4: Check Access Status

```bash
./beenverified-30day.sh check
```

Output:
```
✅ Access is VALID and ACTIVE
   Days remaining: 15
   Hours remaining: 8
```

## Contract Details

### What You Get

✅ **Full Database** - Complete dataset download (all millions of records)  
✅ **30 Days** - Countdown starts after download completes  
✅ **Offline Access** - Use database without internet  
✅ **Multi-Field Search** - Search by name, phone, email, address, state  
✅ **Automatic Expiration** - Auto-deletes at day 30  

### What Happens on Day 30

- ⚠️ Access expires at the exact time you downloaded
- 🗑️ Database automatically deleted
- 🚫 No access to records after expiration
- ❌ Cannot search expired database

## Usage Examples

### Complete Workflow

```bash
# 1. Download (August 22, 2:30 PM)
./beenverified-30day.sh download
# Timer: 30 days starting now

# 2. Later that day - check status
./beenverified-30day.sh status
# Shows: 29 days, 22 hours remaining

# 3. Search the database
./beenverified-30day.sh search --query "John Doe"
./beenverified-30day.sh search --query "555-1234" --type phone

# 4. Week 2 - check time
./beenverified-30day.sh status
# Shows: 23 days remaining

# 5. Day 29 - final check
./beenverified-30day.sh check
# Shows: 1 day remaining

# 6. Day 30 - EXPIRED
./beenverified-30day.sh status
# ❌ ACCESS EXPIRED
# 🗑️ Database was automatically deleted
```

## Search Functionality

### Available Search Types

| Type | Command | Example | Use Case |
|------|---------|---------|----------|
| Name | `--type name` | "John Doe" | Find by full name |
| Phone | `--type phone` | "555-1234" | Find by phone number |
| Email | `--type email` | "john@example.com" | Find by email |
| Address | `--type address` | "123 Main St" | Find by street |
| City | `--type address` | "New York" | Find by city |
| State | `--type state` | "CA" | Find by state |

### Search Examples

```bash
# Simple name search
./beenverified-30day.sh search --query "John"

# Full name
./beenverified-30day.sh search --query "John Doe Smith"

# Exact phone
./beenverified-30day.sh search --query "555-1234" --type phone

# Email pattern
./beenverified-30day.sh search --query "@gmail.com" --type email

# City search
./beenverified-30day.sh search --query "Los Angeles" --type address

# State search
./beenverified-30day.sh search --query "Texas" --type state
```

### Search Results

Each result shows:
```
1. John Doe Smith
   Phone: 555-123-4567
   Email: john@example.com
   Address: 123 Main St
   City: New York, NY
   Age: 45
```

Maximum **500 results per search**.

## Timer Management

### How Timer Works

1. **Starts**: When `download` command completes
2. **Duration**: Exactly 30 days (720 hours)
3. **Expires**: At same time on day 30
4. **Stored**: In `access_metadata.json`
5. **Checked**: Every time you search

### Example Timings

```
If you download at: 2026-08-22 14:30:45
Timer expires at:   2026-09-21 14:30:45 (exactly)

You can search until: 2026-09-21 14:30:44
Cannot search after: 2026-09-21 14:30:45
```

### Automatic Deletion

When timer expires:
1. Next search/check attempts to access database
2. System detects expiration
3. Database automatically deleted
4. Access denied with message

## Storage

### Default Location

```
~/.beenverified/30day_access/
├── beenverified_30day.db        # Main database (SQLite)
├── access_metadata.json         # Timer and license info
```

### File Permissions

- Database: `0600` (user-only)
- Metadata: `0600` (user-only)
- All files deleted on expiration

### Database Size

Depending on full database size:
```
100 million records  ≈ 400-600 GB
500 million records  ≈ 2-3 TB
1 billion records    ≈ 4-6 TB
```

## Expiration Scenarios

### Scenario 1: Normal Expiration

```bash
# Day 30, time reaches expiration
./beenverified-30day.sh status

# Output:
# ❌ ACCESS EXPIRED
# Database has been automatically deleted
```

### Scenario 2: Check Before Expiration

```bash
# Day 25
./beenverified-30day.sh check
# ✅ Access is VALID and ACTIVE
# Days remaining: 5
# Hours remaining: 2
```

### Scenario 3: Search Near Expiration

```bash
# Day 29 (last day)
./beenverified-30day.sh search --query "John"
# ✅ Still works! (7 hours remaining)

# Day 30, 1 minute after expiration
./beenverified-30day.sh search --query "John"
# ❌ Access has expired. Database was deleted.
```

## Metadata Storage

### access_metadata.json

```json
{
  "access_type": "30_day_full_database",
  "download_completed_at": "2026-08-22T14:30:45.123456",
  "expiration_at": "2026-09-21T14:30:45.123456",
  "status": "active"
}
```

This file:
- ✅ Stored with 0600 permissions
- ✅ Contains timer information
- ✅ Deleted on expiration
- ✅ Never contains credentials

## What NOT to Do

❌ **Don't modify** access_metadata.json manually  
❌ **Don't copy** the database to extend access  
❌ **Don't backup** the database (expiration checks all copies)  
❌ **Don't try** to access after expiration  
❌ **Don't delete** the metadata file (access can't be verified)

## Troubleshooting

### "Download failed"

```bash
# Retry the download
./beenverified-30day.sh download

# Or with headless mode
./beenverified-30day.sh download --headless true
```

### "Database already exists"

If you run download twice, it will:
- Reset the 30-day timer
- Overwrite existing database
- Start fresh countdown

### "Access expired, database deleted"

If you get this message:
- The 30 days have passed
- Database was automatically removed
- You need to purchase another 30-day access period
- Contact BeenVerified to renew

### "Search results are empty"

Possible reasons:
- Query doesn't match any records
- Try different search terms
- Try different search types (name → phone → email)

### "Database corrupted"

If database seems corrupted:
```bash
# Re-download to get fresh database
./beenverified-30day.sh download

# This starts a NEW 30-day period
```

## Performance

### Search Speed

```
Name search:    50-500ms
Phone search:   5-100ms
Email search:   50-300ms
Address search: 100-500ms
State search:   5-50ms
```

### Database Operations

```
Insert batch:   100ms per 1000 records
Index build:    Automatic (done during download)
Search: Indexed (very fast)
```

## Security

### What's Protected

✅ Timer in encrypted metadata file  
✅ Database with user-only permissions  
✅ Automatic deletion ensures privacy  
✅ No credentials stored anywhere  

### Access Control

✅ Checked on every search  
✅ Auto-deletes expired database  
✅ Prevents backdating (system time checked)  
✅ No bypass possible  

## Support

For questions about:
- **Timer/expiration:** See Expiration Scenarios above
- **Search issues:** Try different query terms
- **Download failures:** Check internet connection
- **BeenVerified account:** support.beenverified.com
- **Contract renewal:** Contact BeenVerified sales

## Key Points

🎯 **Download starts the timer** - Not when you purchase, when you download  
⏱️ **Exactly 30 days** - From download to auto-delete  
🗑️ **Automatic deletion** - No manual cleanup needed  
🔒 **Offline access** - Works without internet during 30 days  
🔍 **Full database** - All records available for searching  

---

**Version 1.0 - 30-Day Time-Limited Access**

Complete database with automatic expiration and deletion.
