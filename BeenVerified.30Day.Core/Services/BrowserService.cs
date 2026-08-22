namespace BeenVerified.Services;

using System;
using System.Threading.Tasks;
using Microsoft.Playwright;

/// <summary>
/// Handles Firefox automation for BeenVerified authentication.
/// Uses Playwright for cross-platform reliability.
/// </summary>
public sealed class BrowserService : IAsyncDisposable
{
    private const string LoginUrl = "https://www.beenverified.com/login";
    private const string DashboardUrl = "https://www.beenverified.com/dashboard";

    private IPlaywright? _playwright;
    private IBrowser? _browser;
    private IPage? _page;

    public async Task LaunchAsync(bool headless = true)
    {
        _playwright = await Playwright.CreateAsync();
        _browser = await _playwright.Firefox.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = headless,
            Args = new[] { "--width=1600", "--height=900" }
        });

        _page = await _browser.NewPageAsync();
        Console.WriteLine("🌐 Firefox launched");
    }

    public async Task<bool> LoginAsync()
    {
        if (_page is null) throw new InvalidOperationException("Browser not launched");

        Console.WriteLine("📱 Opening BeenVerified login...");
        await _page.GotoAsync(LoginUrl, new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle });

        await UpdateOverlayAsync("Please log in to your account\nVerifying 30-day access...", 0);

        try
        {
            await _page.WaitForURLAsync(new System.Text.RegularExpressions.Regex("(dashboard|account)"),
                new PageWaitForURLOptions { Timeout = 300000 });

            Console.WriteLine("✅ Successfully logged in");
            return true;
        }
        catch
        {
            Console.WriteLine("❌ Login timeout or failed");
            return false;
        }
    }

    public async Task UpdateOverlayAsync(string message, double progress)
    {
        if (_page is null) return;

        var escapedMessage = System.Text.Json.JsonSerializer.Serialize(message);
        var script = $@"
            let overlay = document.getElementById('bv-30day-overlay');
            if (overlay) overlay.remove();

            const html = `<div id='bv-30day-overlay' style='position:fixed;top:0;right:0;width:480px;height:100vh;background:linear-gradient(135deg,#7c2d12 0%,#92400e 100%);color:white;padding:30px;font-family:Segoe UI,Tahoma,Geneva;z-index:10000;box-shadow:-4px 0 30px rgba(0,0,0,0.6);display:flex;flex-direction:column;justify-content:space-between;border-left:6px solid #ea580c'>
                <div>
                    <h1 style='margin:0 0 10px 0;font-size:24px;font-weight:700'>⏱️ 30-Day Access</h1>
                    <p style='margin:0 0 20px 0;font-size:12px;opacity:0.9'>Timer starts after download</p>
                    <div style='background:rgba(234,88,12,0.2);padding:20px;border-radius:12px;margin-bottom:25px;border:1px solid rgba(234,88,12,0.3)'>
                        <p style='margin:0;white-space:pre-wrap;font-size:14px;color:#fed7aa'>{escapedMessage}</p>
                    </div>
                </div>
                <div>
                    <div style='background:rgba(234,88,12,0.2);border-radius:12px;height:12px;margin-bottom:15px;overflow:hidden'>
                        <div style='background:linear-gradient(90deg,#ea580c,#f97316);height:100%;width:{progress}%;transition:width 0.3s'></div>
                    </div>
                    <p style='margin:0;font-size:14px;opacity:0.9'>{progress:F1}% Complete</p>
                </div>
            </div>`;
            document.body.insertAdjacentHTML('beforeend', html);
        ";

        try
        {
            await _page.EvaluateAsync(script);
        }
        catch
        {
            // Overlay update failures are non-critical
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_page is not null)
            await _page.CloseAsync();

        if (_browser is not null)
            await _browser.CloseAsync();

        _playwright?.Dispose();
    }
}
