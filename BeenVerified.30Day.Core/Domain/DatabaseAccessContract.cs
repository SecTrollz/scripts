namespace BeenVerified.Domain;

using System;

/// <summary>
/// Represents a 30-day full database access contract with automatic expiration.
/// Timer starts on download completion, not on purchase.
/// </summary>
public sealed class DatabaseAccessContract
{
    private readonly DateTime _downloadCompletedAt;
    private readonly TimeSpan _accessDuration = TimeSpan.FromDays(30);

    public Guid Id { get; } = Guid.NewGuid();
    public string AccessType { get; } = "30_day_full_database";
    public DateTime DownloadCompletedAt => _downloadCompletedAt;
    public DateTime ExpiresAt => _downloadCompletedAt.Add(_accessDuration);
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsValid => !IsExpired;
    public TimeSpan RemainingTime => IsExpired ? TimeSpan.Zero : ExpiresAt - DateTime.UtcNow;

    public int RemainingDays => (int)RemainingTime.TotalDays;
    public int RemainingHours => RemainingTime.Hours;
    public int RemainingMinutes => RemainingTime.Minutes;

    public DatabaseAccessContract(DateTime downloadCompletedAt)
    {
        _downloadCompletedAt = downloadCompletedAt;
    }

    public string GetStatusSummary() => IsExpired
        ? $"❌ EXPIRED - Deleted on {ExpiresAt:yyyy-MM-dd HH:mm:ss}"
        : $"✅ ACTIVE - {RemainingDays}d {RemainingHours}h {RemainingMinutes}m remaining";

    public static DatabaseAccessContract CreateFromNow() => new(DateTime.UtcNow);
}
