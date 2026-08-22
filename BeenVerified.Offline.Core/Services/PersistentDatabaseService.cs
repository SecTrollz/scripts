namespace BeenVerified.Services;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BeenVerified.Domain;
using Microsoft.Data.Sqlite;

/// <summary>
/// Manages SQLite database for permanent offline access.
/// No expiration checking. No auto-deletion. No timers.
/// Download once, access forever.
/// </summary>
public sealed class PersistentDatabaseService : IAsyncDisposable
{
    private readonly string _connectionString;
    private readonly Lazy<SqliteConnection> _connection;
    private PersistentDatabase? _database;

    public PersistentDatabaseService(string databasePath)
    {
        var dbPath = Path.Combine(databasePath, "beenverified_offline.db");
        Directory.CreateDirectory(databasePath);
        _connectionString = $"Data Source={dbPath};Cache=Shared";
        _connection = new Lazy<SqliteConnection>(() => new SqliteConnection(_connectionString));
    }

    public async Task InitializeAsync()
    {
        var connection = _connection.Value;
        await connection.OpenAsync();

        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                record_id TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                phone TEXT,
                email TEXT,
                street_address TEXT,
                city TEXT,
                state TEXT,
                zip TEXT,
                age INTEGER,
                raw_data TEXT,
                indexed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_name ON records(full_name);
            CREATE INDEX IF NOT EXISTS idx_first_name ON records(first_name);
            CREATE INDEX IF NOT EXISTS idx_phone ON records(phone);
            CREATE INDEX IF NOT EXISTS idx_email ON records(email);
            CREATE INDEX IF NOT EXISTS idx_city ON records(city);
            CREATE INDEX IF NOT EXISTS idx_state ON records(state);

            CREATE TABLE IF NOT EXISTS database_info (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        ";

        await cmd.ExecuteNonQueryAsync();
    }

    public async Task RegisterDatabaseAsync(PersistentDatabase database)
    {
        _database = database;

        using var cmd = _connection.Value.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO database_info (key, value) VALUES
            (@key1, @value1), (@key2, @value2)
        ";

        cmd.Parameters.AddWithValue("@key1", "registered_at");
        cmd.Parameters.AddWithValue("@value1", database.RegisteredAt.ToString("O"));
        cmd.Parameters.AddWithValue("@key2", "access_type");
        cmd.Parameters.AddWithValue("@value2", "permanent_offline");

        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<PersistentDatabase?> LoadDatabaseInfoAsync()
    {
        if (_database is not null) return _database;

        using var cmd = _connection.Value.CreateCommand();
        cmd.CommandText = "SELECT value FROM database_info WHERE key = 'registered_at'";

        var result = await cmd.ExecuteScalarAsync() as string;
        if (result is null) return null;

        if (DateTime.TryParse(result, out var registerTime))
        {
            _database = new PersistentDatabase(registerTime);

            // Load stats
            var count = await GetRecordCountAsync();
            _database.TotalRecords = count;

            var dbSize = new FileInfo(_connection.Value.DataSource).Length;
            _database.DatabaseSizeBytes = dbSize;

            return _database;
        }

        return null;
    }

    public async Task InsertBatchAsync(IEnumerable<PersonRecord> records)
    {
        using var transaction = _connection.Value.BeginTransaction();
        using var cmd = _connection.Value.CreateCommand();
        cmd.Transaction = transaction;

        cmd.CommandText = @"
            INSERT OR REPLACE INTO records
            (record_id, full_name, first_name, last_name, phone, email,
             street_address, city, state, zip, age, raw_data, indexed_at)
            VALUES
            (@recordId, @fullName, @firstName, @lastName, @phone, @email,
             @address, @city, @state, @zip, @age, @rawData, @indexedAt)
        ";

        foreach (var record in records)
        {
            cmd.Parameters.Clear();
            cmd.Parameters.AddWithValue("@recordId", record.RecordId);
            cmd.Parameters.AddWithValue("@fullName", record.FullName);
            cmd.Parameters.AddWithValue("@firstName", record.FirstName ?? "");
            cmd.Parameters.AddWithValue("@lastName", record.LastName ?? "");
            cmd.Parameters.AddWithValue("@phone", (object?)record.PhoneNumber ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@email", (object?)record.Email ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@address", (object?)record.StreetAddress ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@city", (object?)record.City ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@state", (object?)record.State ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@zip", (object?)record.ZipCode ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@age", (object?)record.Age ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@rawData", System.Text.Json.JsonSerializer.Serialize(record.RawData));
            cmd.Parameters.AddWithValue("@indexedAt", record.IndexedAt.ToString("O"));

            await cmd.ExecuteNonQueryAsync();
        }

        await transaction.CommitAsync();
    }

    public async Task<List<PersonRecord>> SearchAsync(string query, SearchFieldType fieldType, int limit = 500)
    {
        using var cmd = _connection.Value.CreateCommand();

        cmd.CommandText = fieldType switch
        {
            SearchFieldType.Name => @"
                SELECT * FROM records
                WHERE full_name LIKE @query
                   OR first_name LIKE @query
                   OR last_name LIKE @query
                LIMIT @limit",

            SearchFieldType.Phone => @"
                SELECT * FROM records
                WHERE phone = @query
                LIMIT @limit",

            SearchFieldType.Email => @"
                SELECT * FROM records
                WHERE email LIKE @query
                LIMIT @limit",

            SearchFieldType.Address => @"
                SELECT * FROM records
                WHERE street_address LIKE @query
                   OR city LIKE @query
                LIMIT @limit",

            SearchFieldType.State => @"
                SELECT * FROM records
                WHERE state = @query COLLATE NOCASE
                LIMIT @limit",

            _ => throw new ArgumentException($"Unknown search type: {fieldType}")
        };

        cmd.Parameters.AddWithValue("@query", $"%{query}%");
        cmd.Parameters.AddWithValue("@limit", limit);

        var records = new List<PersonRecord>();
        using var reader = await cmd.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            records.Add(new PersonRecord
            {
                RecordId = reader.GetString(1),
                FullName = reader.GetString(2),
                FirstName = reader.IsDBNull(3) ? "" : reader.GetString(3),
                LastName = reader.IsDBNull(4) ? "" : reader.GetString(4),
                PhoneNumber = reader.IsDBNull(5) ? null : reader.GetString(5),
                Email = reader.IsDBNull(6) ? null : reader.GetString(6),
                StreetAddress = reader.IsDBNull(7) ? null : reader.GetString(7),
                City = reader.IsDBNull(8) ? null : reader.GetString(8),
                State = reader.IsDBNull(9) ? null : reader.GetString(9),
                ZipCode = reader.IsDBNull(10) ? null : reader.GetString(10),
                Age = reader.IsDBNull(11) ? null : reader.GetInt32(11),
                IndexedAt = DateTime.Parse(reader.GetString(13))
            });
        }

        return records;
    }

    public async Task<int> GetRecordCountAsync()
    {
        using var cmd = _connection.Value.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM records";

        var result = await cmd.ExecuteScalarAsync();
        return Convert.ToInt32(result);
    }

    public async Task<DatabaseStats> GetStatsAsync()
    {
        var count = await GetRecordCountAsync();
        var dbSize = new FileInfo(_connection.Value.DataSource).Length;

        using var cmd = _connection.Value.CreateCommand();
        cmd.CommandText = "SELECT COUNT(DISTINCT city) as city_count FROM records WHERE city IS NOT NULL";
        var cityCount = Convert.ToInt32(await cmd.ExecuteScalarAsync());

        return new DatabaseStats
        {
            TotalRecords = count,
            DatabaseSizeBytes = dbSize,
            UniqueCities = cityCount,
            LastUpdated = DateTime.UtcNow
        };
    }

    public async ValueTask DisposeAsync()
    {
        if (_connection.IsValueCreated)
        {
            var conn = _connection.Value;
            if (conn.State == System.Data.ConnectionState.Open)
                await conn.CloseAsync();
            await conn.DisposeAsync();
        }
    }
}

public record DatabaseStats
{
    public int TotalRecords { get; init; }
    public long DatabaseSizeBytes { get; init; }
    public int UniqueCities { get; init; }
    public DateTime LastUpdated { get; init; }

    public string FormattedSize => DatabaseSizeBytes switch
    {
        > 1_000_000_000 => $"{DatabaseSizeBytes / 1_000_000_000.0:F2} GB",
        > 1_000_000 => $"{DatabaseSizeBytes / 1_000_000.0:F2} MB",
        _ => $"{DatabaseSizeBytes / 1_000.0:F2} KB"
    };
}
