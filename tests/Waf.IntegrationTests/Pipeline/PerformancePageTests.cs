using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>The Performance page and its CSV export, against running gateways.</summary>
public sealed class PerformancePageTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway(params string[] extra) : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            [.. new RouteArgs().Add("website", [("http", A.Port)], hosts: ["www.example.com"]).ToArray(), .. extra];
    }

    private static async Task SendAsync(AdminGateway gateway, string host, string path = "/")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"));
        request.Headers.Host = host;
        using var _ = await gateway.Public.SendAsync(request, Ct);
    }

    /// <summary>Traffic of the last seconds, stored: 6 forwarded, 2 blocked by a rule, 1 without a route; and in the request log.</summary>
    private static async Task WithTrafficAsync(Gateway gateway)
    {
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Rules.Add(new WafRule
        {
            Name = "no-secret",
            Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/secret" } } },
        });
        Assert.True((await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

        for (var i = 0; i < 6; i++)
        {
            await SendAsync(gateway, "www.example.com");
        }

        await SendAsync(gateway, "www.example.com", "/secret/a");
        await SendAsync(gateway, "www.example.com", "/secret/b");
        await SendAsync(gateway, "unknown.example.com");
        await gateway.App.Services.GetRequiredService<RequestMetricsWriter>().FlushAsync(all: true, Ct);

        var log = gateway.App.Services.GetRequiredService<FASoft.Waf.Engine.IRequestLogMonitor>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (log.Statistics!.Written < 9 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50, Ct);
        }
    }

    [Fact]
    public async Task The_page_shows_good_bad_and_failed_traffic_with_links_to_the_request_log()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await WithTrafficAsync(gateway);

        var html = WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h"));

        Assert.Contains("href=\"performance\"", html, StringComparison.Ordinal); // in the navigation
        Assert.Contains("id=\"perf-chart\"", html, StringComparison.Ordinal);
        Assert.Contains(">9<", html, StringComparison.Ordinal); // requests in total
        Assert.Contains("Blocked by a rule: no-secret", html, StringComparison.Ordinal);
        Assert.Contains("No route", html, StringComparison.Ordinal);
        Assert.Contains("<code>127.0.0.1</code>", html, StringComparison.Ordinal);
        Assert.Contains("show=Blocked&rule=no-secret", html, StringComparison.Ordinal); // to the request log
        Assert.Contains("type=RuleBlocked%3Ano-secret", html, StringComparison.Ordinal); // "only this"
        Assert.Contains("performance/export.csv?period=1h", html, StringComparison.Ordinal);
        Assert.Contains("\"buckets\":[[", html, StringComparison.Ordinal); // the chart's data
        Assert.Equal(3, System.Text.RegularExpressions.Regex.Count(html, "<table [^>]*data-pie")); // kinds, sources, destinations: also as pie charts
        Assert.Contains("data-count=\"2\"", html, StringComparison.Ordinal);

        // A request log link opens the same requests.
        var link = System.Text.RegularExpressions.Regex.Match(html, "href=\"(?<url>logs\\?[^\"]*rule=no-secret[^\"]*)\"").Groups["url"].Value;
        var log = await gateway.GetPageAsync("/" + link);
        Assert.Contains("/secret/a", log, StringComparison.Ordinal);
        Assert.Contains("/secret/b", log, StringComparison.Ordinal);
        Assert.DoesNotContain("unknown.example.com", log, StringComparison.Ordinal);
        Assert.Contains("from the Performance page", log, StringComparison.Ordinal);

        // Requested destinations of the bad requests: host and path, each with "only this" and a log link.
        Assert.Contains("<code>www.example.com/secret/a</code>", html, StringComparison.Ordinal);
        Assert.Contains("<code>unknown.example.com/</code>", html, StringComparison.Ordinal);
        Assert.Contains("destination=www.example.com%2Fsecret%2Fb", html, StringComparison.Ordinal);
        var destinationLink = System.Text.RegularExpressions.Regex.Match(html, "href=\"(?<url>logs\\?[^\"]*host=www.example.com[^\"]*)\"").Groups["url"].Value;
        var destinationLog = await gateway.GetPageAsync("/" + destinationLink);
        Assert.Contains("/secret/", destinationLog, StringComparison.Ordinal);
        Assert.DoesNotContain("unknown.example.com", destinationLog, StringComparison.Ordinal);

        var onlyOne = WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h&destination=www.example.com/secret/b"));
        Assert.Contains("Only bad requests to www.example.com/secret/b.", onlyOne, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Filters_narrow_every_table_and_the_export()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await WithTrafficAsync(gateway);

        var html = WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h&type=NoRoute"));
        Assert.Contains("value=\"NoRoute\" checked", html, StringComparison.Ordinal);
        Assert.Contains(">1<", html, StringComparison.Ordinal);

        using var csv = await gateway.Admin.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/performance/export.csv?period=1h"), Ct);
        Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
        Assert.Equal("text/csv", csv.Content.Headers.ContentType!.MediaType);
        Assert.StartsWith("attachment", csv.Content.Headers.ContentDisposition!.ToString(), StringComparison.Ordinal);
        var lines = (await csv.Content.ReadAsStringAsync(Ct)).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("start_utc,seconds,good,bad,failed,total,per_second,peak_per_second", lines[0]);
        Assert.Equal(9, lines.Skip(1).Sum(l => long.Parse(l.Split(',')[5], System.Globalization.CultureInfo.InvariantCulture)));

        using var filtered = await gateway.Admin.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/performance/export.csv?period=1h&type=RuleBlocked"), Ct);
        var bad = (await filtered.Content.ReadAsStringAsync(Ct)).Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Skip(1);
        Assert.Equal(2, bad.Sum(l => long.Parse(l.Split(',')[3], System.Globalization.CultureInfo.InvariantCulture)));

        // History periods and the live view render too.
        foreach (var period in new[] { "", "?period=24h&compare=1", "?period=7d", "?period=30d", "?period=3m", "?period=1y", "?period=3y", "?period=1h&source=127.0.0.1&route=website" })
        {
            Assert.Contains("id=\"perf-chart\"", await gateway.GetPageAsync("/performance" + period), StringComparison.Ordinal);
        }
    }

    /// <summary>A website on backend A and a route whose backend is down (nothing listens on its port).</summary>
    private sealed class TwoRoutes : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs()
                .Add("website", [("http", A.Port)], hosts: ["www.example.com"])
                .Add("dead", [("http", ClosedPort())], hosts: ["dead.example.com"])
                .ToArray();

        private static int ClosedPort()
        {
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }

    [Fact]
    public async Task Response_time_percentiles_match_the_request_log()
    {
        await using var gateway = new TwoRoutes();
        await gateway.InitializeAsync();
        for (var i = 0; i < 40; i++)
        {
            await SendAsync(gateway, "www.example.com", $"/slow?ms={i % 10 * 8}"); // 0 to 72 ms
        }

        await gateway.App.Services.GetRequiredService<RequestMetricsWriter>().FlushAsync(all: true, Ct);
        var log = gateway.App.Services.GetRequiredService<FASoft.Waf.Engine.IRequestLogMonitor>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (log.Statistics!.Written < 40 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50, Ct);
        }

        var options = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<EventDbContext>()
            .UseSqlite(SqliteRequestLogStore.ConnectionString(new StoragePaths(gateway.DataDirectory, gateway.DataDirectory)))
            .Options;
        await using var db = new EventDbContext(options);
        var latencies = db.RequestEvents.Select(e => e.LatencyMs).AsEnumerable().Order().ToList();
        Assert.Equal(40, latencies.Count);

        var store = gateway.App.Services.GetRequiredService<SqliteMetricsStore>();
        var now = DateTimeOffset.UtcNow;
        var (_, summary) = await store.ReadLatencyAsync(new TrafficQuery(now.AddHours(-1), now.AddMinutes(1), MetricsTier.Minute), Ct);
        Assert.Equal(40, summary.Requests);
        foreach (var (p, value) in new[] { (0.5, summary.P50), (0.95, summary.P95), (0.99, summary.P99) })
        {
            var exact = latencies[(int)Math.Ceiling(p * latencies.Count) - 1];
            Assert.InRange(value!.Value / exact, 1 / 1.12, 1.12);
        }

        // The backend's time is most of it; the gateway adds little.
        Assert.True(summary.GatewayP50 < summary.BackendP50, $"gateway {summary.GatewayP50} ms, backend {summary.BackendP50} ms");

        var html = WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h&route=website"));
        Assert.Contains("id=\"perf-latency\"", html, StringComparison.Ordinal);
        Assert.Contains("95th percentile", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_backend_that_is_down_shows_its_errors_and_the_failover_period()
    {
        await using var gateway = new TwoRoutes();
        await gateway.InitializeAsync();
        await SendAsync(gateway, "www.example.com");
        for (var i = 0; i < 3; i++)
        {
            await SendAsync(gateway, "dead.example.com");
        }

        // A failover period that has ended: the gateway's own flush (every few seconds) records the real failover
        // state, which would end a period that is still open at any moment, so the test does not rely on one.
        await gateway.App.Services.GetRequiredService<RequestMetricsWriter>().FlushAsync(all: true, Ct);
        var store = gateway.App.Services.GetRequiredService<SqliteMetricsStore>();
        var since = DateTimeOffset.UtcNow.AddMinutes(-2);
        await store.RecordFailoversAsync([new FASoft.Waf.Core.Routing.RouteFailoverStatus("dead", 1, "http://10.0.0.99:8080/", since)], since.AddSeconds(5), Ct);
        await store.RecordFailoversAsync([], since.AddMinutes(1), Ct);

        var html = WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h"));
        Assert.Contains("Failovers in this period", html, StringComparison.Ordinal);
        Assert.Contains("failover 1: http://10.0.0.99:8080/", html, StringComparison.Ordinal);
        Assert.Contains("\"failovers\":[[", html, StringComparison.Ordinal); // drawn as a band on the charts

        // The dead route's backend: three 502s, marked.
        var row = System.Text.RegularExpressions.Regex.Match(html, "<tr class=\"row-warning\">\\s*<td>dead</td>(?<cells>.*?)</tr>", System.Text.RegularExpressions.RegexOptions.Singleline);
        Assert.True(row.Success, "the dead route's backend row");
        var cells = System.Text.RegularExpressions.Regex.Matches(row.Groups["cells"].Value, "<td>(?<v>[^<]*)</td>").Select(m => m.Groups["v"].Value).ToList();
        Assert.Equal(["3", "0", "0", "0", "0", "3", "0", "0"], cells); // requests, 2xx..5xx, 502, 503, 504
    }

    [Fact]
    public async Task A_network_can_be_blocked_from_the_page_as_a_new_configuration_version()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        await WithTrafficAsync(gateway);
        var before = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Version;

        var html = WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h&sources=network"));
        Assert.Contains("<code>127.0.0.0/24</code>", html, StringComparison.Ordinal);
        Assert.Contains("network=127.0.0.0%2F24", html, StringComparison.Ordinal); // "only this"
        Assert.Contains("q=127.0.0.", html, StringComparison.Ordinal);               // the request log, by prefix
        Assert.Contains("rate-limits/new?source=127.0.0.0%2F24", html, StringComparison.Ordinal);
        var block = System.Text.RegularExpressions.Regex.Match(html, "href=\"(?<url>rules/new\\?source=127.0.0.0%2F24[^\"]*)\"").Groups["url"].Value;
        Assert.NotEmpty(block);

        // The rule editor opens pre-filled; saving it is an ordinary change: a new version, which can be rolled back.
        var form = await gateway.GetPageAsync("/" + block);
        Assert.Contains("127.0.0.0/24", form, StringComparison.Ordinal);
        await gateway.PostAsync("/" + block, "rule-edit", AdminGateway.ScrapeForm(form, "rule-edit"));
        var after = (await gateway.Store.GetLastKnownGoodAsync(Ct))!;
        Assert.Equal(before + 1, after.Version);
        Assert.Contains(after.Configuration.Rules, r => r.Conditions.Any(c => c.Values.Contains("127.0.0.0/24")));
        using (var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}/")))
        {
            request.Headers.Host = "www.example.com";
            using var response = await gateway.Public.SendAsync(request, Ct);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        Assert.True((await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().RollbackAsync(before, after.Version, AuditActor.System("test"), Ct)).Succeeded);
        Assert.DoesNotContain((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Rules, r => r.Conditions.Any(c => c.Values.Contains("127.0.0.0/24")));

        // The rate limit editor opens pre-filled too.
        var limit = WebUtility.HtmlDecode(await gateway.GetPageAsync("/rate-limits/new?source=127.0.0.0%2F24"));
        Assert.Contains("limit-127-0-0-0-24", limit, StringComparison.Ordinal);
        Assert.Contains("127.0.0.0/24", limit, StringComparison.Ordinal);
    }

    [Fact]
    public async Task With_a_country_file_the_sources_can_be_listed_by_country()
    {
        var file = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"), "countries.csv");
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        await File.WriteAllTextAsync(file, "127.0.0.0,127.255.255.255,NL\n", Ct);
        try
        {
            await using var gateway = new Gateway($"--Gateway:Metrics:GeoIpFile={file}");
            await gateway.InitializeAsync();
            var history = gateway.App.Services.GetRequiredService<IMetricsHistory>();
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (history.CountrySource is null && DateTime.UtcNow < deadline)
            {
                await Task.Delay(50, Ct); // read in the background at start
            }

            Assert.Equal("countries.csv", history.CountrySource);
            await WithTrafficAsync(gateway);

            var html = WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h&sources=country"));
            Assert.Contains("(NL)</th>", html, StringComparison.Ordinal);
            Assert.Contains("country=NL", html, StringComparison.Ordinal);
            Assert.Contains("Countries from countries.csv", html, StringComparison.Ordinal);
            Assert.Contains(">3<", WebUtility.HtmlDecode(await gateway.GetPageAsync("/performance?period=1h&country=NL")), StringComparison.Ordinal);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            File.Delete(file);
        }
    }

    [Fact]
    public async Task Without_a_country_file_countries_are_not_offered()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var html = await gateway.GetPageAsync("/performance?period=1h");
        Assert.Contains("sources=network", html, StringComparison.Ordinal);
        Assert.DoesNotContain("sources=country", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_page_and_the_export_need_a_session()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using var anonymous = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });

        using var pageRequest = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.AdminPort}/performance"));
        pageRequest.Headers.Accept.ParseAdd("text/html");
        using var page = await anonymous.SendAsync(pageRequest, Ct);
        Assert.Equal(HttpStatusCode.Redirect, page.StatusCode);
        using var csv = await anonymous.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/performance/export.csv"), Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, csv.StatusCode);
    }

    [Fact]
    public async Task Without_traffic_counts_the_page_says_so()
    {
        await using var gateway = new Gateway("--Gateway:Metrics:Enabled=false");
        await gateway.InitializeAsync();

        Assert.Contains("Gateway:Metrics:Enabled", await gateway.GetPageAsync("/performance"), StringComparison.Ordinal);
        using var csv = await gateway.Admin.GetAsync(new Uri($"http://127.0.0.1:{gateway.AdminPort}/performance/export.csv"), Ct);
        Assert.Equal(HttpStatusCode.NotFound, csv.StatusCode);
    }
}
