namespace BeenVerified.Services;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BeenVerified.Domain;
using Microsoft.Data.Sqlite;

/// <summary>
/// Manages SQLite database for 30-day limited access with expiration checking.
/// All operations verify access before proceeding.
/// </summary>
public sealed class DatabaseService : IAsyncDisposable
{
    private readonly string _connectionString;
    private readonly Lazy<SqliteConnection> _connection;
    private DatabaseAccessContract? _contract;

    public DatabaseService(string databasePath)
    {
        var dbPath = Path.Combine(databasePath, "beenverified_30day.db");
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
            CREATE INDEX IF NOT EXISTS idx_phone ON records(phone);
            CREATE INDEX IF NOT EXISTS idx_email ON records(email);
            CREATE INDEX IF NOT EXISTS idx_city ON records(city);
            CREATE INDEX IF NOT EXISTS idx_state ON records(state);

            CREATE TABLE IF NOT EXISTS contract_info (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        ";

        await cmd.ExecuteNonQueryAsync();
    }

    public async Task RegisterContractAsync(DatabaseAccessContract contract)
    {
        _contract = contract;

        using var cmd = _connection.Value.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO contract_info (key, value) VALUES
            (@key1, @value1), (@key2, @value2), (@key3, @value3)
        ";

        cmd.Parameters.AddWithValue("@key1", "download_completed_at");
        cmd.Parameters.AddWithValue("@value1", contract.DownloadCompletedAt.ToString("O"));
        cmd.Parameters.AddWithValue("@key2", "expires_at");
        cmd.Parameters.AddWithValue("@value2", contract.ExpiresAt.ToString("O"));
        cmd.Parameters.AddWithValue("@key3", "status");
        cmd.Parameters.AddWithValue("@value3", "active");

        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<DatabaseAccessContract?> LoadContractAsync()
    {
        if (_contract is not null) return _contract;

        using var cmd = _connection.Value.CreateCommand();
        cmd.CommandText = "SELECT value FROM contract_info WHERE key = 'download_completed_at'";

        var result = await cmd.ExecuteScalarAsync() as string;
        if (result is null) return null;

        if (DateTime.TryParse(result, out var downloadTime))
        {
            _contract = new DatabaseAccessContract(downloadTime);
            return _contract;
        }

        return null;
    }

    public async Task<bool> VerifyAccessAsync()
    {
        var contract = await LoadContractAsync();
        return contract?.IsValid ?? false;
    }

    public async Task InsertBatchAsync(IEnumerable<PersonRecord> records)
    {
        if (!await VerifyAccessAsync())
            throw new InvalidOperationException("❌ Access has expired. Database was deleted.");

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
        if (!await VerifyAccessAsync())
            throw new InvalidOperationException("❌ Access has expired. Database was deleted.");

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
        if (!await VerifyAccessAsync())
            throw new InvalidOperationException("❌ Access has expired. Database was deleted.");

        using var cmd = _connection.Value.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM records";

        var result = await cmd.ExecuteScalarAsync();
        return Convert.ToInt32(result);
    }

    public async Task DeleteDatabaseAsync()
    {
        var connection = _connection.Value;
        if (connection.State == System.Data.ConnectionState.Open)
            await connection.CloseAsync();

        var dbPath = connection.DataSource;
        if (File.Exists(dbPath))
            File.Delete(dbPath);
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
