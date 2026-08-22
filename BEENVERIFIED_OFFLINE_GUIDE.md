# BeenVerified Offline Database Access Guide

**For verified paid account holders only.** This script enables offline access to BeenVerified records you've already purchased.

## Features

✅ **Account Verification** - Validates paid subscription status  
✅ **Secure Authentication** - OAuth-style token-based auth  
✅ **Offline Database** - SQLite storage for purchased records  
✅ **Fast Search** - Indexed searches without internet  
✅ **License Tracking** - Monitor records usage and expiration  
✅ **Sync Management** - Incremental record downloads  

## Requirements

- Python 3.8+
- Valid BeenVerified.com paid account
- ~5 GB free disk space (for purchased data)

## Installation

```bash
# Make the script executable
chmod +x beenverified_offline_access.py

# Or run directly
python3 beenverified_offline_access.py --help
```

## Quick Start

### 1. Initial Setup (One-time)

Authenticate and verify your subscription:

```bash
python3 beenverified_offline_access.py setup --email your@email.com
```

This will:
- Prompt for your BeenVerified password (not stored plainly)
- Verify your subscription is active
- Register your license locally
- Store encrypted session token

**Security note:** Password is only used for authentication request; it's never stored. Session tokens auto-expire after 1 hour.

### 2. Sync Your Purchased Data

Download all records from your account:

```bash
python3 beenverified_offline_access.py sync --email your@email.com
```

This will:
- Connect to BeenVerified API
- Download all purchased records in batches
- Store locally in encrypted SQLite database
- Show progress

**Tip:** Depending on volume, this may take several minutes. You'll see progress updates.

### 3. Search Offline

Find records without internet:

```bash
python3 beenverified_offline_access.py search --email your@email.com --query "John Doe"
```

Returns all matching records with:
- Full name
- Record ID
- Record type
- Download date
- Complete data

### 4. Check Account Status

View your license and usage:

```bash
python3 beenverified_offline_access.py stats --email your@email.com
```

Shows:
- Records used vs. available
- License expiration date
- Remaining searches

## Advanced Usage

### Custom Config Directory

Store data in a specific location:

```bash
python3 beenverified_offline_access.py setup \
  --email your@email.com \
  --config-dir /path/to/storage
```

### Batch Sync with Larger Pages

Faster but uses more bandwidth:

```bash
python3 beenverified_offline_access.py sync \
  --email your@email.com \
  --page-size 500
```

### Full Example Workflow

```bash
# First time
python3 beenverified_offline_access.py setup --email john@example.com

# Sync all your purchased records
python3 beenverified_offline_access.py sync --email john@example.com

# Search locally (no internet needed)
python3 beenverified_offline_access.py search --email john@example.com --query "Jane Smith"
python3 beenverified_offline_access.py search --email john@example.com --query "Robert Johnson"

# Check license status
python3 beenverified_offline_access.py stats --email john@example.com

# Re-sync weekly to get new purchases
python3 beenverified_offline_access.py sync --email john@example.com
```

## Data Storage

Your data is stored in:

```
~/.beenverified/
├── session.json              # Encrypted session token
├── credentials.json          # Account info (read-only)
└── purchased_data.db        # SQLite database with records
```

**Permissions:** Files are stored with `0600` (user-only read/write)

## What Gets Downloaded?

The sync command downloads:
- All records you've purchased
- Associated metadata and details
- Search type information
- Download timestamps

**Does NOT include:**
- Your password (never stored)
- Full payment history
- Billing information

## Search Features

### Simple Name Search
```bash
--query "John"
```
Finds all records with "John" in the name (case-insensitive)

### Multiple Words
```bash
--query "John Doe"
```
Searches for both first and last name

## Troubleshooting

### "Login failed: Invalid credentials"
- Check your email and password
- Reset password at beenverified.com if needed
- Verify account isn't locked after multiple attempts

### "Subscription is not active"
- Your account needs an active paid subscription
- Log in at beenverified.com to renew
- Try setup again after renewal

### "Session expired"
- Sessions auto-expire after 1 hour of inactivity
- Run `setup` again to re-authenticate
- This is a security feature

### Database Locked
- Close any other instances of the script
- Wait 30 seconds and try again
- Check for stray `python3` processes: `ps aux | grep beenverified`

### Slow Search
- First-time search builds the index (only happens once)
- Subsequent searches are much faster
- For very large datasets (100k+ records), searches may take 5-10 seconds

## Privacy & Security

### Local Encryption
- Session tokens stored with restricted permissions (0600)
- SQLite database is local and not transmitted
- Passwords never stored on disk

### Network Calls
- Only communicates with official BeenVerified.com API
- Uses HTTPS (TLS 1.2+)
- Session tokens auto-expire after 1 hour
- Requests rate-limited to respect API

### Subscription Verification
- License status verified on each setup
- Prevents unauthorized offline access
- Respects your subscription tier limits

## Offline Capabilities

Once synced, the following work **without internet:**
- ✅ Search by name
- ✅ View record details
- ✅ Check account stats
- ✅ Export search results

These require **internet:**
- ❌ Login/authentication
- ❌ Sync/download new records
- ❌ Update subscription status

## License and Usage

This tool respects your BeenVerified subscription terms:
- Records downloaded are for your personal use
- Offline access doesn't bypass any subscription limits
- Record limits are enforced locally
- Usage tracked per your account

## Support

For issues with:
- **Script errors:** Check error messages above
- **BeenVerified account:** Visit support.beenverified.com
- **API access:** Verify subscription is active

## Example Output

```
✅ Successfully logged in as john@example.com
✅ License registered for john@example.com

🔄 Starting database sync...
📥 Synced 100 records...
📥 Synced 200 records...
✅ Sync complete! Total records: 847

📊 Found 5 record(s):

Name: John Doe Smith
ID: rec_12345
Type: person
Downloaded: 2024-08-22T10:30:45.123456
------------------------------------------------------------

📈 Account Statistics:
  Records Used: 847/1000
  Records Remaining: 153
  Expires: 2025-08-22
```

## Updates

Check for updates periodically as the BeenVerified API may change.

**Version 1.0** - August 2024
