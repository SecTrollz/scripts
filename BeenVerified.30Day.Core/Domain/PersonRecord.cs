namespace BeenVerified.Domain;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents a complete person record from the BeenVerified database.
/// Designed for efficient searching across multiple fields.
/// </summary>
public sealed record PersonRecord
{
    public string RecordId { get; init; } = string.Empty;
    public string FullName { get; init; } = string.Empty;
    public string FirstName { get; init; } = string.Empty;
    public string LastName { get; init; } = string.Empty;
    public string? PhoneNumber { get; init; }
    public string? Email { get; init; }
    public string? StreetAddress { get; init; }
    public string? City { get; init; }
    public string? State { get; init; }
    public string? ZipCode { get; init; }
    public int? Age { get; init; }
    public DateTime IndexedAt { get; init; } = DateTime.UtcNow;
    public Dictionary<string, object> RawData { get; init; } = new();

    public bool Matches(string query, SearchFieldType fieldType) => fieldType switch
    {
        SearchFieldType.Name => MatchesName(query),
        SearchFieldType.Phone => MatchesPhone(query),
        SearchFieldType.Email => MatchesEmail(query),
        SearchFieldType.Address => MatchesAddress(query),
        SearchFieldType.State => MatchesState(query),
        _ => false
    };

    private bool MatchesName(string query) =>
        query.AsSpan().IsContainedInSpan(FullName.AsSpan(), StringComparison.OrdinalIgnoreCase) ||
        query.AsSpan().IsContainedInSpan(FirstName.AsSpan(), StringComparison.OrdinalIgnoreCase) ||
        query.AsSpan().IsContainedInSpan(LastName.AsSpan(), StringComparison.OrdinalIgnoreCase);

    private bool MatchesPhone(string query) =>
        PhoneNumber?.Equals(query, StringComparison.Ordinal) ?? false;

    private bool MatchesEmail(string query) =>
        Email?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false;

    private bool MatchesAddress(string query) =>
        (StreetAddress?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
        (City?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false);

    private bool MatchesState(string query) =>
        State?.Equals(query, StringComparison.OrdinalIgnoreCase) ?? false;

    public string FormatForDisplay() =>
        $"""
         {FullName}
         Phone: {PhoneNumber ?? "N/A"}
         Email: {Email ?? "N/A"}
         Address: {StreetAddress ?? "N/A"}
         City: {City}, {State} {ZipCode}
         Age: {Age ?? 0}
         """;
}

public enum SearchFieldType
{
    Name,
    Phone,
    Email,
    Address,
    State
}

/// <summary>
/// Extension method for efficient substring search using Span<T>
/// </summary>
internal static class SpanExtensions
{
    public static bool IsContainedInSpan(this ReadOnlySpan<char> needle, ReadOnlySpan<char> haystack, StringComparison comparison) =>
        comparison switch
        {
            StringComparison.OrdinalIgnoreCase => haystack.ToString().Contains(needle.ToString(), StringComparison.OrdinalIgnoreCase),
            _ => haystack.ToString().Contains(needle.ToString(), StringComparison.Ordinal)
        };
}
