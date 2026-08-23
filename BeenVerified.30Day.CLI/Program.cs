using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Parsing;
using BeenVerified.Domain;
using BeenVerified.Services;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddScoped<DatabaseService>();
services.AddScoped<BrowserService>();

var provider = services.BuildServiceProvider();

var rootCommand = new RootCommand("BeenVerified 30-Day Full Database Access");

// Download command
var downloadCommand = new Command("download", "Download full database and start 30-day timer");
downloadCommand.AddOption(new Option<bool>("--headless", () => true, "Run in headless mode"));

downloadCommand.SetHandler(async (headless) =>
{
    await ExecuteDownloadAsync(provider, headless);
}, downloadCommand.Options.OfType<Option<bool>>().First());

// Search command
var searchCommand = new Command("search", "Search database during 30-day window");
searchCommand.AddOption(new Option<string>(new[] { "-q", "--query" }, "Search query") { IsRequired = true });
searchCommand.AddOption(new Option<SearchFieldType>(new[] { "-t", "--type" }, () => SearchFieldType.Name, "Search type"));

searchCommand.SetHandler(async (query, type) =>
{
    await ExecuteSearchAsync(provider, query, type);
}, searchCommand.Options.OfType<Option<string>>().First(),
   searchCommand.Options.OfType<Option<SearchFieldType>>().First());

// Status command
var statusCommand = new Command("status", "Show access status and countdown");
statusCommand.SetHandler(async () =>
{
    await ExecuteStatusAsync(provider);
});

// Check command
var checkCommand = new Command("check", "Quick validity check");
checkCommand.SetHandler(async () =>
{
    await ExecuteCheckAsync(provider);
});

rootCommand.Add(downloadCommand);
rootCommand.Add(searchCommand);
rootCommand.Add(statusCommand);
rootCommand.Add(checkCommand);

var parser = new CommandLineBuilder(rootCommand)
    .UseDefaults()
    .Build();

return await parser.InvokeAsync(args);

async Task ExecuteDownloadAsync(IServiceProvider sp, bool headless)
{
    Console.WriteLine("🚀 Starting 30-day database download...");
    Console.WriteLine("⏱️ Timer will start when download completes");

    using var browser = sp.GetRequiredService<BrowserService>();
    using var db = sp.GetRequiredService<DatabaseService>();

    try
    {
        await db.InitializeAsync();
        await browser.LaunchAsync(headless);

        if (!await browser.LoginAsync())
            Environment.Exit(1);

        var contract = DatabaseAccessContract.CreateFromNow();
        await db.RegisterContractAsync(contract);

        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("🎉 DOWNLOAD COMPLETE!");
        Console.WriteLine(new string('=', 60));
        Console.WriteLine($"Access registered: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"Expires: {contract.ExpiresAt:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine("Duration: 30 days full offline access");
        Console.WriteLine("Database will auto-delete on expiration");
        Console.WriteLine(new string('=', 60) + "\n");
    }
    finally
    {
        await browser.DisposeAsync();
        await db.DisposeAsync();
    }
}

async Task ExecuteSearchAsync(IServiceProvider sp, string query, SearchFieldType type)
{
    using var db = sp.GetRequiredService<DatabaseService>();
    await db.InitializeAsync();

    if (!await db.VerifyAccessAsync())
    {
        Console.WriteLine("❌ Access has expired. Database was deleted.");
        Environment.Exit(1);
    }

    var results = await db.SearchAsync(query, type);

    if (results.Count == 0)
    {
        Console.WriteLine($"❌ No records found for '{query}'");
        Environment.Exit(1);
    }

    Console.WriteLine($"\n📊 Found {results.Count} record(s):\n");

    foreach (var (i, result) in results.Select((r, idx) => (idx + 1, r)))
    {
        Console.WriteLine($"{i}. {result.FullName}");
        if (!string.IsNullOrEmpty(result.PhoneNumber))
            Console.WriteLine($"   Phone: {result.PhoneNumber}");
        if (!string.IsNullOrEmpty(result.Email))
            Console.WriteLine($"   Email: {result.Email}");
        if (!string.IsNullOrEmpty(result.StreetAddress))
            Console.WriteLine($"   Address: {result.StreetAddress}");
        if (!string.IsNullOrEmpty(result.City))
            Console.WriteLine($"   City: {result.City}, {result.State}");
        if (result.Age.HasValue)
            Console.WriteLine($"   Age: {result.Age}");
        Console.WriteLine();
    }

    await db.DisposeAsync();
}

async Task ExecuteStatusAsync(IServiceProvider sp)
{
    using var db = sp.GetRequiredService<DatabaseService>();
    await db.InitializeAsync();

    var contract = await db.LoadContractAsync();

    if (contract?.IsExpired ?? true)
    {
        Console.WriteLine("❌ ACCESS EXPIRED");
        Console.WriteLine("Database has been automatically deleted");
        Environment.Exit(1);
    }

    var count = await db.GetRecordCountAsync();
    var dbSize = new FileInfo("~/.beenverified/30day_access/beenverified_30day.db".ExpandPath())
        .Length / (1024.0 * 1024.0);

    Console.WriteLine("\n" + new string('=', 60));
    Console.WriteLine("📊 30-DAY ACCESS STATUS");
    Console.WriteLine(new string('=', 60));
    Console.WriteLine($"Status: ✅ ACTIVE");
    Console.WriteLine($"Total Records: {count:N0}");
    Console.WriteLine($"Database Size: {dbSize:F2} MB");
    Console.WriteLine($"\n⏱️ TIME REMAINING:");
    Console.WriteLine($"  {contract.RemainingDays} days, {contract.RemainingHours} hours, {contract.RemainingMinutes} minutes");
    Console.WriteLine($"\nExpires: {contract.ExpiresAt:yyyy-MM-dd HH:mm:ss}");
    Console.WriteLine($"Downloaded: {contract.DownloadCompletedAt:yyyy-MM-dd HH:mm:ss}");
    Console.WriteLine(new string('=', 60) + "\n");

    await db.DisposeAsync();
}

async Task ExecuteCheckAsync(IServiceProvider sp)
{
    using var db = sp.GetRequiredService<DatabaseService>();
    await db.InitializeAsync();

    var contract = await db.LoadContractAsync();

    if (contract?.IsValid ?? false)
    {
        Console.WriteLine("✅ Access is VALID and ACTIVE");
        Console.WriteLine($"   Days remaining: {contract.RemainingDays}");
        Console.WriteLine($"   Hours remaining: {contract.RemainingHours}");
    }
    else
    {
        Console.WriteLine("❌ Access has EXPIRED");
        Console.WriteLine("   Database has been deleted");
    }

    await db.DisposeAsync();
}
