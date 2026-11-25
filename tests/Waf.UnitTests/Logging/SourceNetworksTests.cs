using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Logging;

public sealed class SourceNetworksTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 11, 25, 10, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Theory]
    [InlineData("203.0.113.77", "203.0.113.0/24")]
    [InlineData("::ffff:203.0.113.77", "203.0.113.0/24")]
    [InlineData("2001:db8:1:2:3:4:5:6", "2001:db8:1::/48")]
    [InlineData("2001:db8::1", "2001:db8::/48")]
    [InlineData("not an address", null)]
    [InlineData(null, null)]
    public void The_network_of_an_address_is_its_24_or_48(string? address, string? expected)
    {
        Assert.Equal(expected, TrafficClassifier.Network(address));
    }

    private string Write(string name, string content)
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Country_files_with_addresses_are_read_as_db_ip_publishes_them()
    {
        var lookup = CountryLookup.Load(Write("dbip-country-lite.csv", """
            start,end,country
            1.0.0.0,1.0.0.255,AU
            198.51.100.0,198.51.100.255,nl
            203.0.113.0,203.0.113.127,ZZ
            2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE
            """));

        Assert.Equal(3, lookup.Count);
        Assert.Equal("dbip-country-lite.csv", lookup.Source);
        Assert.Equal("AU", lookup.Find("1.0.0.0"));
        Assert.Equal("AU", lookup.Find("1.0.0.255"));
        Assert.Null(lookup.Find("1.0.1.0"));
        Assert.Equal("NL", lookup.Find("198.51.100.7"));
        Assert.Null(lookup.Find("203.0.113.5")); // ZZ: unknown
        Assert.Equal("DE", lookup.Find("2001:db8:1::5"));
        Assert.Equal("NL", lookup.Find("::ffff:198.51.100.7"));
        Assert.Null(lookup.Find("0.0.0.1"));
        Assert.Null(lookup.Find("nonsense"));
    }

    [Fact]
    public void Country_files_with_numbers_are_read_as_ip2location_publishes_them()
    {
        var lookup = CountryLookup.Load(Write("IP2LOCATION-LITE-DB1.CSV", """
            "0","16777215","-","-"
            "16777216","16777471","AU","Australia"
            "3325256704","3325256959","NL","Netherlands"
            """));

        Assert.Equal(2, lookup.Count);
        Assert.Equal("AU", lookup.Find("1.0.0.1"));
        Assert.Equal("NL", lookup.Find("198.51.100.1")); // 3325256704 = 198.51.100.0
        Assert.Null(lookup.Find("0.0.0.5"));
    }

    [Fact]
    public void An_attack_from_many_addresses_in_one_network_is_one_network_at_the_top()
    {
        // 500 addresses of one /24, each once, plus a single noisy address elsewhere: by address, the network's
        // requests are spread over many rows (beyond the memory limit, "other"); by network, it is one row on top.
        var counter = new TrafficCounter(maxCells: 10_000, maxSourceCells: 200);
        for (var i = 0; i < 500; i++)
        {
            counter.Add(Start, TrafficKind.RuleBlocked, "r", "website", $"198.51.{100 + (i / 250)}.{i % 250}", null, "NL");
        }

        for (var i = 0; i < 30; i++)
        {
            counter.Add(Start, TrafficKind.NoRoute, "", null, "203.0.113.9", null, "US");
        }

        var take = counter.TakeCompleted(Start.AddMinutes(5), TimeSpan.Zero);

        // By address: at most the top 100, each with 1 request; the rest, the noisy one too, is "other".
        Assert.True(take.Sources.Where(s => s.Source == TrafficCounter.OtherSource).Sum(s => s.Count) > 300);
        Assert.All(take.Sources.Where(s => s.Source != TrafficCounter.OtherSource), s => Assert.Equal(1, s.Count));
        var networks = take.Networks.GroupBy(n => n.Source).Select(g => (Network: g.Key, Count: g.Sum(n => n.Count))).OrderByDescending(n => n.Count).ToList();
        Assert.Equal([("198.51.100.0/24", 250L), ("198.51.101.0/24", 250L), ("203.0.113.0/24", 30L)], networks);
        Assert.Equal(500, take.Countries.Single(c => c.Source == "NL").Count);
        Assert.Equal(530, take.Networks.Sum(n => n.Count));
    }

    [Fact]
    public async Task Networks_and_countries_are_stored_rolled_up_and_filtered_and_client_ips_follow_the_log_retention()
    {
        var store = new SqliteMetricsStore(Path.Combine(_directory, "metrics.db"));
        await store.InitializeAsync(Ct);
        var counter = new TrafficCounter();
        counter.Add(Start, TrafficKind.Forwarded, "", "website", "198.51.100.1", "www.example.com/", "NL");
        for (var i = 0; i < 5; i++)
        {
            counter.Add(Start, TrafficKind.RuleBlocked, "r", "website", $"198.51.100.{i}", "www.example.com/admin", "NL");
        }

        counter.Add(Start, TrafficKind.NoRoute, "", null, "203.0.113.9", "probe.example.net/", null);
        await store.WriteAsync(counter.TakeCompleted(Start.AddHours(1), TimeSpan.Zero, all: true), Ct);
        var period = new TrafficQuery(Start, Start.AddHours(1), MetricsTier.Second);

        Assert.Equal([new LiveSourceCount("198.51.100.0/24", 5), new LiveSourceCount("203.0.113.0/24", 1)], await store.ReadTopNetworksAsync(period, 10, Ct));
        Assert.Equal([new LiveSourceCount("NL", 5)], await store.ReadTopCountriesAsync(period, 10, Ct));
        Assert.Equal((6L, 5L), (await store.ReadNetworkTotalAsync(period, Ct), await store.ReadCountryTotalAsync(period, Ct)));
        Assert.Equal(5, (await store.ReadSeriesAsync(period with { Networks = ["198.51.100.0/24"] }, Ct)).Sum(b => b.Bad));
        Assert.Equal(1, (await store.ReadSeriesAsync(period with { Networks = ["203.0.113.0/24"], Countries = ["NL"] }, Ct)).Sum(b => b.Bad)); // networks win
        Assert.Equal(5, (await store.ReadSeriesAsync(period with { Countries = ["NL"] }, Ct)).Sum(b => b.Bad));

        // Ten days later with a request log kept 7 days: client IPs are gone, networks and countries stay (as hours).
        await store.MaintainAsync(new MetricsRetention(), Start.AddDays(10), Ct, clientIpRetention: TimeSpan.FromDays(7));
        var later = new TrafficQuery(Start.AddHours(-1), Start.AddHours(2), MetricsTier.Hour);
        Assert.Empty(await store.ReadTopSourcesAsync(later, 10, Ct));
        Assert.Equal(6, (await store.ReadTopNetworksAsync(later, 10, Ct)).Sum(n => n.Count));
        Assert.Equal(5, (await store.ReadTopCountriesAsync(later, 10, Ct)).Sum(c => c.Count));
        Assert.Equal(6, (await store.ReadTopDestinationsAsync(later, 10, Ct)).Sum(d => d.Count));
    }

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7")]
    [InlineData("203.0.113.0/24", "203.0.113.0/24")]
    [InlineData("2001:db8:1::/48", "2001:db8:1::/48")]
    [InlineData("203.0.113.7/24", null)] // not a network address: refused, like everywhere else
    [InlineData("nonsense", null)]
    [InlineData("", null)]
    public void A_source_from_the_dashboard_is_an_address_or_a_network(string text, string? expected)
    {
        Assert.Equal(expected, LogActions.ParseSource(text));
    }

    [Fact]
    public void A_network_is_added_to_a_block_list_unless_it_is_covered()
    {
        var configuration = new GatewayConfiguration();
        var model = LogActions.NewBlockList("198.51.100.0/24", configuration, 3);
        Assert.Equal("198.51.100.0/24", model.Conditions[0].Values);
        Assert.False(LogActions.AddToBlockList(model, "198.51.100.7")); // inside the network
        Assert.False(LogActions.AddToBlockList(model, "198.51.100.0/24"));
        Assert.True(LogActions.AddToBlockList(model, "203.0.113.0/24"));
        Assert.Equal(["198.51.100.0/24", "203.0.113.0/24"], model.Conditions[0].ValueList);
    }

    [Fact]
    public void A_rate_limit_for_a_source_limits_it_per_client()
    {
        var limit = LogActions.NewRateLimit("198.51.100.0/24", new GatewayConfiguration(), 3).ToLimit();

        Assert.Equal("limit-198-51-100-0-24", limit.Name);
        Assert.Equal(RateLimitKey.ClientIp, limit.Key);
        Assert.Equal((60, 60), (limit.PermitLimit, limit.WindowSeconds));
        var condition = Assert.Single(limit.Conditions);
        Assert.Equal((ConditionField.ClientIp, ConditionOperator.InCidr, "198.51.100.0/24"), (condition.Field, condition.Operator, condition.Values.Single()));
    }

    [Fact]
    public void The_address_keeps_network_and_country_filters_and_the_source_level()
    {
        var query = PerformanceQuery.Parse(new QueryCollection(QueryHelpers.ParseQuery("period=1h&network=198.51.100.0/24&network=bad&country=nl&country=XYZ&sources=network")));

        Assert.Equal(["198.51.100.0/24"], query.Networks);
        Assert.Equal(["NL"], query.Countries);
        Assert.Equal(SourceLevel.Network, query.SourcesBy);
        Assert.True(query.HasSourceFilter);
        var url = query.Url();
        Assert.Contains("network=198.51.100.0%2F24", url, StringComparison.Ordinal);
        Assert.Contains("country=NL", url, StringComparison.Ordinal);
        Assert.Contains("sources=network", url, StringComparison.Ordinal);
        Assert.Equal(["203.0.113.0/24"], query.WithNetwork("203.0.113.0/24").Networks);
        Assert.Empty(query.WithNetwork("203.0.113.0/24").Countries);
        Assert.Equal("198.51.100.", PerformanceText.NetworkPrefix("198.51.100.0/24"));
        Assert.Null(PerformanceText.NetworkPrefix("2001:db8:1::/48"));
    }
}
