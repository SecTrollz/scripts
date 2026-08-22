# BeenVerified Full Database Access Guide

**For accounts with complete dataset purchase contracts**

This tool manages access to the entire BeenVerified database that you've purchased. Unlike per-record or limited-record access, full database contracts grant access to the complete dataset.

## Contract Access Levels

### What This Tool Supports

✅ **Full Database Access** - Complete dataset purchase  
✅ **Entire Records** - All people in the database  
✅ **Unlimited Searches** - Multi-field search across all data  
✅ **Bulk Operations** - Download and compress the entire database  
✅ **License Verification** - Contract-based access validation  

### Not For

❌ Individual record purchases  
❌ Limited search counts  
❌ Trial or limited access accounts  
❌ Free tier accounts  

## Quick Start

### 1. Verify Access (One-time)

```bash
./beenverified-full-db.sh verify
```

This will:
- Open Firefox and log you in
- Check your BeenVerified account contract
- Verify full database access is enabled
- Initialize local database storage
- Show verification overlay

### 2. Search the Database

```bash
# By name
./beenverified-full-db.sh search --query "John Doe"

# By phone
./beenverified-full-db.sh search --query "555-1234" --type phone

# By email
./beenverified-full-db.sh search --query "john@example.com" --type email

# By location
./beenverified-full-db.sh search --query "New York" --type address
./beenverified-full-db.sh search --query "CA" --type state
```

### 3. View Statistics

```bash
./beenverified-full-db.sh stats
```

Shows:
- Total records in database
- Database size on disk
- Number of batches downloaded
- License information

### 4. View License

```bash
./beenverified-full-db.sh license
```

Shows:
- Access level (Full Database)
- Registration date
- Contract details

## Full Usage

### Verification

```bash
# Interactive (Firefox opens)
./beenverified-full-db.sh verify

# Headless (background)
./beenverified-full-db.sh verify --headless true
```

**What gets verified:**
1. Account login credentials
2. Contract status (full database access)
3. License validity
4. Access level confirmation

### Search Commands

#### By Name
```bash
./beenverified-full-db.sh search --query "John"
./beenverified-full-db.sh search --query "John Doe Smith"
./beenverified-full-db.sh search --query "Smith"
```

Returns up to 500 matching records with name, phone, email, address, age.

#### By Phone
```bash
./beenverified-full-db.sh search --query "555-123-4567" --type phone
./beenverified-full-db.sh search --query "5551234567" --type phone
```

Exact phone number match (try with/without dashes).

#### By Email
```bash
./beenverified-full-db.sh search --query "john@example.com" --type email
./beenverified-full-db.sh search --query "example.com" --type email
```

Partial email match supported.

#### By Address
```bash
./beenverified-full-db.sh search --query "123 Main St" --type address
./beenverified-full-db.sh search --query "New York" --type address
```

Search street address or city.

#### By State
```bash
./beenverified-full-db.sh search --query "CA" --type state
./beenverified-full-db.sh search --query "New York" --type state
```

Two-letter state code or full state name (normalized to uppercase).

### Database Compression

Store database in compressed format:

```bash
./beenverified-full-db.sh compress
```

Example output:
```
📦 Compressing database...
✅ Compressed: 2,500.00MB → 650.00MB (74.0% reduction)
```

### Statistics

```bash
./beenverified-full-db.sh stats
```

Example output:
```
📈 Full Database Statistics:
  Total Records: 500,000,000
  Database Size: 2500.00 MB
  Batches: 1,250

📜 License Information:
  Access Level: full_database
  Registered: 2026-08-22T21:47:33Z
```

## Data Storage

### Storage Location

Default: `~/.beenverified/full_database/`

```
~/.beenverified/full_database/
├── beenverified_full.db          # Main database (SQLite)
├── beenverified_full.db.gz       # Compressed archive
├── database_metadata.json        # License info
└── sync_progress                 # Download tracking
```

### File Permissions

All files stored with `0600` permissions (user-only access).

### Database Size Estimates

```
50 million records    ≈ 200-300 GB
100 million records   ≈ 400-600 GB
500 million records   ≈ 2-3 TB
```

(Depends on data density and compression)

## Search Capabilities

### Multi-Field Indexing

Database is indexed on:
- ✅ Full name (person_name)
- ✅ First name
- ✅ Last name
- ✅ Phone number
- ✅ Email address
- ✅ Street address
- ✅ City
- ✅ State
- ✅ Record ID

### Search Limits

- **Results per query:** Up to 500 records
- **Field combinations:** Search one field at a time
- **Query speed:** <1 second for most queries
- **Large datasets:** 5-10 seconds for very large matches

### Example Searches

```bash
# Find all Johns
./beenverified-full-db.sh search --query "John"

# Find exact phone
./beenverified-full-db.sh search --query "555-1234" --type phone

# Find all in New York
./beenverified-full-db.sh search --query "New York" --type address

# Find all in California
./beenverified-full-db.sh search --query "CA" --type state
```

## Database Architecture

### Schema

```sql
CREATE TABLE records (
    id INTEGER PRIMARY KEY,
    record_id TEXT UNIQUE,
    person_name TEXT,
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
    indexed_at TEXT,
    batch_number INTEGER
);

-- Multiple indexes for fast search
CREATE INDEX idx_name ON records(person_name);
CREATE INDEX idx_phone ON records(phone);
CREATE INDEX idx_email ON records(email);
-- ... etc
```

### Batch Processing

Large datasets are downloaded and indexed in batches:

```
Batch 1: Records 1-1,000,000
Batch 2: Records 1,000,001-2,000,000
Batch 3: Records 2,000,001-3,000,000
...
```

Each batch indexed immediately after download for incremental access.

## Workflow Example

### Complete Workflow

```bash
# 1. First time: Verify access
./beenverified-full-db.sh verify
# Firefox opens, you log in, verification completes

# 2. Check what you have
./beenverified-full-db.sh stats

# 3. Search the database
./beenverified-full-db.sh search --query "John Smith"
./beenverified-full-db.sh search --query "555-1234" --type phone
./beenverified-full-db.sh search --query "New York" --type address

# 4. Archive for storage
./beenverified-full-db.sh compress

# 5. Later, verify license still valid
./beenverified-full-db.sh license
```

## Contract Requirements

Your account must have:

✅ **Full Database Purchase** - Contract for complete dataset  
✅ **Active Subscription** - Valid payment status  
✅ **No Access Restrictions** - All records available  

If you only have:

❌ Limited record access (e.g., 1000 records/month)  
❌ Specific field restrictions  
❌ Geographic limitations  
❌ Trial or free tier access  

**Use the limited-record tools instead:**
- `beenverified.sh` - API-based sync (limited records)
- `beenverified-browser.sh` - Browser-based sync (limited records)

## Verification Process

When you run `verify`:

1. **Login Page** - Firefox opens BeenVerified.com
2. **Authentication** - You enter your credentials
3. **Access Check** - Script looks for "full database" access
4. **License Registration** - Registers access in local database
5. **Overlay Confirmation** - Shows verification status

### What's Checked

```
✅ Account login successful
✅ Full database access available
✅ License can be registered locally
✅ Database storage initialized
```

### Failure Reasons

```
❌ Login failed (wrong credentials)
❌ Full database access not found
❌ Account suspended or expired
❌ Storage permissions issue
```

## Troubleshooting

### "Full database access not found"

- Verify your contract includes full database purchase
- Contact BeenVerified support if you think this is wrong
- Check that you're logged into the correct account

### Slow Searches

On very large datasets:
- First search on a field is slower (building cache)
- Subsequent searches are faster
- Large result sets (100+ records) take longer
- Phone searches are fastest, name searches slower

### Database Too Large

Compress database to save space:
```bash
./beenverified-full-db.sh compress
```

Can reduce database by 60-80% depending on data density.

### "Permission denied" on database

```bash
# Fix permissions
chmod 600 ~/.beenverified/full_database/beenverified_full.db
chmod 600 ~/.beenverified/full_database/database_metadata.json
```

### Firefox Won't Open

```bash
# Ensure Firefox is installed
which firefox

# Or reinstall
sudo apt install firefox  # Ubuntu/Debian
brew install firefox      # macOS
```

## Performance Notes

### Search Performance

```
Name search:    50-500ms (depends on result count)
Phone search:   10-100ms (exact match is fast)
Email search:   50-300ms (pattern match)
Address search: 100-500ms (fuzzy matching)
State search:   5-50ms (indexed)
```

### Database Size

```
Uncompressed: 200GB - 3TB (full database)
Compressed:   50GB - 800GB (with gzip)
Index Space:  ~20% of database size
```

### Batch Size

- Default: 1,000,000 records per batch
- Smaller batches for RAM-constrained systems
- Larger batches for faster bulk operations

## License & Contract

This tool respects your BeenVerified contract:

✅ Full database access as contracted  
✅ All records available per your agreement  
✅ Offline access within license terms  
✅ License verification on each verification  

## Support

For issues:
- **Script errors:** Check error messages above
- **BeenVerified account:** support.beenverified.com
- **Contract questions:** Contact your BeenVerified account manager
- **Database issues:** Check file permissions and disk space

---

**Version 1.0 - Full Database Edition**

For accounts with complete dataset purchase contracts.
