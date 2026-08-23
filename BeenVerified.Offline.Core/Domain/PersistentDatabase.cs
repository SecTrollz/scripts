namespace BeenVerified.Domain;

using System;

/// <summary>
/// Represents persistent offline database access with no time limits.
/// Once downloaded, database remains accessible indefinitely.
/// No expiration, no auto-deletion, no timers.
/// </summary>
public sealed class PersistentDatabase
{
    public Guid Id { get; } = Guid.NewGuid();
    public string AccessType { get; } = "persistent_offline_database";
    public DateTime RegisteredAt { get; }
    public bool IsValid => true;  // Always valid, no expiration

    public int TotalRecords { get; set; }
    public long DatabaseSizeBytes { get; set; }
    public DateTime LastAccessedAt { get; set; } = DateTime.UtcNow;

    public PersistentDatabase(DateTime registeredAt = default)
    {
        RegisteredAt = registeredAt == default ? DateTime.UtcNow : registeredAt;
    }

    public string GetStatusSummary() =>
        $"✅ PERMANENT ACCESS - {TotalRecords:N0} records available indefinitely";

    public TimeSpan GetUptime() => DateTime.UtcNow - RegisteredAt;

    public string FormatDatabaseSize() =>
        DatabaseSizeBytes switch
        {
            > 1_000_000_000 => $"{DatabaseSizeBytes / 1_000_000_000.0:F2} GB",
            > 1_000_000 => $"{DatabaseSizeBytes / 1_000_000.0:F2} MB",
            > 1_000 => $"{DatabaseSizeBytes / 1_000.0:F2} KB",
            _ => $"{DatabaseSizeBytes} bytes"
        };

    public static PersistentDatabase CreateNew() => new();
}
