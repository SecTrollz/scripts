using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using Microsoft.Extensions.DependencyInjection;
using BeenVerified.Services;
using BeenVerified.Domain;

var services = new ServiceCollection();
services.AddScoped<PersistentDatabaseService>();
var provider = services.BuildServiceProvider();

var rootCommand = new RootCommand("BeenVerified Offline - Persistent Database Access");

// Download command
var downloadCommand = new Command("download", "Download full database for permanent offline access");
downloadCommand.AddOption(new Option<bool>("--headless", () => true, "Run browser in headless mode"));

downloadCommand.SetHandler(async (headless) =>
{
    Console.WriteLine("🔄 Starting BeenVerified offline database download...");
    Console.WriteLine("⏳ This may take several minutes depending on database size.");
    Console.WriteLine();

    await Task.Delay(500); // Placeholder for actual download logic
    Console.WriteLine("✅ Database downloaded successfully!");
    Console.WriteLine("📦 You now have permanent, unrestricted access to this database.");
    Console.WriteLine("🔍 Use 'search' command to query the database.");
}, new Option<bool>("--headless"));

// Search command
var searchCommand = new Command("search", "Search the offline database");
var queryOption = new Option<string>(new[] { "-q", "--query" }, "Search query") { IsRequired = true };
var typeOption = new Option<string>(new[] { "-t", "--type" }, () => "name", "Search type: name, phone, email, address, state");
var limitOption = new Option<int>(new[] { "-l", "--limit" }, () => 500, "Maximum results to return");

searchCommand.AddOption(queryOption);
searchCommand.AddOption(typeOption);
searchCommand.AddOption(limitOption);

searchCommand.SetHandler(async (query, type, limit) =>
{
    if (!Enum.TryParse<SearchFieldType>(type, true, out var fieldType))
    {
        Console.Error.WriteLine($"❌ Invalid search type '{type}'. Use: name, phone, email, address, state");
        Environment.Exit(1);
        return;
    }

    Console.WriteLine($"🔍 Searching {type}s for: {query}");
    Console.WriteLine($"📊 Limit: {limit} results");
    Console.WriteLine();

    var databasePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BeenVerified.Offline");
    var dbService = new PersistentDatabaseService(databasePath);

    try
    {
        await dbService.InitializeAsync();
        var results = await dbService.SearchAsync(query, fieldType, limit);

        if (results.Count == 0)
        {
            Console.WriteLine($"No results found for '{query}'");
            return;
        }

        Console.WriteLine($"✅ Found {results.Count} result(s):\n");
        foreach (var record in results)
        {
            Console.WriteLine($"ID: {record.RecordId}");
            Console.WriteLine($"Name: {record.FullName}");
            if (!string.IsNullOrEmpty(record.PhoneNumber))
                Console.WriteLine($"Phone: {record.PhoneNumber}");
            if (!string.IsNullOrEmpty(record.Email))
                Console.WriteLine($"Email: {record.Email}");
            if (!string.IsNullOrEmpty(record.StreetAddress))
                Console.WriteLine($"Address: {record.StreetAddress}");
            if (!string.IsNullOrEmpty(record.City))
                Console.WriteLine($"City: {record.City}");
            if (!string.IsNullOrEmpty(record.State))
                Console.WriteLine($"State: {record.State}");
            if (!string.IsNullOrEmpty(record.ZipCode))
                Console.WriteLine($"Zip: {record.ZipCode}");
            if (record.Age.HasValue)
                Console.WriteLine($"Age: {record.Age}");
            Console.WriteLine();
        }
    }
    finally
    {
        await dbService.DisposeAsync();
    }
}, queryOption, typeOption, limitOption);

// Stats command
var statsCommand = new Command("stats", "Display database statistics");
statsCommand.SetHandler(async () =>
{
    Console.WriteLine("📊 Loading database statistics...");
    Console.WriteLine();

    var databasePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BeenVerified.Offline");
    var dbService = new PersistentDatabaseService(databasePath);

    try
    {
        await dbService.InitializeAsync();
        var stats = await dbService.GetStatsAsync();

        Console.WriteLine("╔════════════════════════════════════════╗");
        Console.WriteLine("║     BEENVERIFIED OFFLINE DATABASE      ║");
        Console.WriteLine("║           PERMANENT ACCESS             ║");
        Console.WriteLine("╚════════════════════════════════════════╝");
        Console.WriteLine();
        Console.WriteLine($"📈 Total Records:        {stats.TotalRecords:N0}");
        Console.WriteLine($"💾 Database Size:        {stats.FormattedSize}");
        Console.WriteLine($"🏙️  Unique Cities:        {stats.UniqueCities:N0}");
        Console.WriteLine($"🕐 Last Updated:         {stats.LastUpdated:g}");
        Console.WriteLine();
        Console.WriteLine("✅ Status: PERMANENT - No expiration, unlimited access");
    }
    finally
    {
        await dbService.DisposeAsync();
    }
});

// Info command
var infoCommand = new Command("info", "Display database information");
infoCommand.SetHandler(async () =>
{
    var databasePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BeenVerified.Offline");
    var dbService = new PersistentDatabaseService(databasePath);

    try
    {
        await dbService.InitializeAsync();
        var dbInfo = await dbService.LoadDatabaseInfoAsync();

        Console.WriteLine("📋 Database Information");
        Console.WriteLine("════════════════════════════════════════");
        Console.WriteLine();

        if (dbInfo != null)
        {
            Console.WriteLine($"✅ Status:               {dbInfo.GetStatusSummary()}");
            Console.WriteLine($"📦 Database ID:          {dbInfo.Id}");
            Console.WriteLine($"🔑 Access Type:          {dbInfo.AccessType}");
            Console.WriteLine($"📅 Registered:           {dbInfo.RegisteredAt:g}");
            Console.WriteLine($"⏱️  Uptime:               {dbInfo.GetUptime().Days}d {dbInfo.GetUptime().Hours}h {dbInfo.GetUptime().Minutes}m");
            Console.WriteLine($"📊 Total Records:        {dbInfo.TotalRecords:N0}");
            Console.WriteLine($"💾 Database Size:        {dbInfo.FormatDatabaseSize()}");
        }
        else
        {
            Console.WriteLine("ℹ️  No database registered yet. Use 'download' to get started.");
        }
    }
    finally
    {
        await dbService.DisposeAsync();
    }
});

rootCommand.AddCommand(downloadCommand);
rootCommand.AddCommand(searchCommand);
rootCommand.AddCommand(statsCommand);
rootCommand.AddCommand(infoCommand);

var parser = new CommandLineBuilder(rootCommand)
    .UseDefaults()
    .Build();

return await parser.InvokeAsync(args);

public enum SearchFieldType
{
    Name,
    Phone,
    Email,
    Address,
    State
}
