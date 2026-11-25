using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// Every admin page fits the screen: on a phone (390 px) and on a desktop (1280 px), in English and in German (the
/// longest words), with the example configuration (long names, IP lists, host names). A page may scroll its tables
/// inside their own box, never the whole page sideways. Needs a Chromium for Playwright; where none is installed the
/// test uses an installed Chrome or Edge, and is skipped when there is none (GitHub's runners have Chrome).
/// </summary>
public sealed class LayoutTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// Development: static files (the stylesheet, the scripts) are served from the source folders. Otherwise a test
    /// run serves them empty, as they are only copied with a publish, and the pages would be checked without styles.
    /// </summary>
    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs => ["--environment=Development"];
    }

    /// <summary>
    /// Playwright's own Chromium when it is installed, else the Chrome or Edge installed on the machine (GitHub's
    /// runners have Chrome); null when there is none.
    /// </summary>
    private static async Task<IBrowser?> LaunchAsync(IPlaywright playwright)
    {
        foreach (var channel in new string?[] { null, "chrome", "msedge" })
        {
            try
            {
                return await playwright.Chromium.LaunchAsync(new() { Headless = true, Channel = channel });
            }
            catch (PlaywrightException)
            {
                // Not installed: try the next one.
            }
        }

        return null;
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    [Fact]
    public async Task Every_admin_page_fits_a_phone_and_a_desktop_screen()
    {
        var playwright = await Playwright.CreateAsync();
        var browser = await LaunchAsync(playwright);
        if (browser is null)
        {
            playwright.Dispose();
            Assert.Skip("No browser for Playwright on this machine: neither its own Chromium nor an installed Chrome or Edge. Install one, e.g. pwsh bin/<configuration>/net11.0/playwright.ps1 install chromium");
            return;
        }

        using var _ = playwright;
        await using var __ = browser;
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        // The example configuration: realistic names, host lists, IP lists and conditions.
        var example = await File.ReadAllTextAsync(Path.Combine(RepositoryRoot(), "schemas", "gateway-config.example.json"), Ct);
        var configuration = GatewayConfigurationJson.Parse(example).Configuration!;
        var activated = await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct);
        Assert.True(activated.Succeeded, string.Join("; ", activated.Errors));
        using (var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}/wp-login.php")))
        {
            request.Headers.Host = "www.example.com";
            using var response = await gateway.Public.SendAsync(request, Ct); // a request log entry
        }

        var active = configuration;
        var version = activated.Version!.Version;
        string[] pages =
        [
            "/", "/performance", "/performance?period=1h", "/performance/settings",
            "/logs", "/logs/settings", "/logs/1",
            "/routes", "/routes/new", $"/routes/{active.Routes[0].Name}/edit", $"/routes/{active.Routes[0].Name}/delete",
            "/targets", "/targets/new", $"/targets/{active.Targets[0].Name}/edit",
            "/rules", "/rules/new", $"/rules/{active.Rules[0].Name}/edit", $"/rules/{active.Rules[0].Name}/delete",
            "/rate-limits", "/rate-limits/new", $"/rate-limits/{active.RateLimits[0].Name}/edit",
            "/detection/exclusions/new", "/certificates", "/certificates/upload", "/library", "/test-request",
            "/history", $"/history/{version}", "/audit", "/backup", "/import", "/remote-access",
            "/ai", "/ai/settings", "/account", "/account/history", "/account/two-factor",
        ];

        var cookies = gateway.AdminCookies.GetAllCookies()
            .Select(c => new Microsoft.Playwright.Cookie { Name = c.Name, Value = c.Value, Domain = "127.0.0.1", Path = "/", HttpOnly = c.HttpOnly })
            .ToList();
        var problems = new List<string>();
        foreach (var (width, height, mobile) in new[] { (360, 780, true), (390, 844, true), (1280, 720, false) })
        {
            foreach (var locale in new[] { "en-US", "de-DE" })
            {
                await using var context = await browser.NewContextAsync(new() { ViewportSize = new() { Width = width, Height = height }, IsMobile = mobile, Locale = locale });
                await context.AddCookiesAsync(cookies);
                var page = await context.NewPageAsync();
                foreach (var path in pages)
                {
                    var response = await page.GotoAsync($"http://127.0.0.1:{gateway.AdminPort}{path}", new() { WaitUntil = WaitUntilState.Load });
                    if (response is null || response.Status != (int)HttpStatusCode.OK)
                    {
                        problems.Add($"{path}: status {response?.Status}");
                        continue;
                    }

                    await page.WaitForTimeoutAsync(150); // the page's scripts (charts) draw
                    Assert.True(
                        await page.EvaluateAsync<bool>("getComputedStyle(document.documentElement).getPropertyValue('--surface').trim() !== ''"),
                        $"{path}: the stylesheet did not load");
                    var overflow = await page.EvaluateAsync<int>("document.documentElement.scrollWidth - document.documentElement.clientWidth");
                    if (overflow > 1)
                    {
                        // Which element sticks out furthest, to know what to fix.
                        var culprit = await page.EvaluateAsync<string>("""
                            () => {
                                // The outermost element that sticks out (the first in document order): that is what to fix.
                                const limit = document.documentElement.clientWidth;
                                const name = (e) => `${e.tagName.toLowerCase()}${e.id ? '#' + e.id : ''}${e.className && typeof e.className === 'string' ? '.' + e.className.trim().split(/\s+/).join('.') : ''}`;
                                for (const e of document.querySelectorAll('body *')) {
                                    const r = e.getBoundingClientRect();
                                    if (r.width > 0 && r.right > limit + 1) {
                                        return `${name(e)} in ${e.parentElement ? name(e.parentElement) : '-'} (to ${Math.round(r.right)} px)`;
                                    }
                                }
                                return '?';
                            }
                            """);
                        problems.Add($"{width} px, {locale}, {path}: {overflow} px wider than the screen; widest: {culprit}");
                    }
                }
            }
        }

        Assert.True(problems.Count == 0, string.Join(Environment.NewLine, problems));
    }
}
