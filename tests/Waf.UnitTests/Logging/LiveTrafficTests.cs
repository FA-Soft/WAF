using FASoft.Waf.Engine;
using FASoft.Waf.UnitTests.Engine;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Logging;

public class LiveTrafficTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static RequestLogEntry Entry(RequestAction action, string? route = "website", string ip = "203.0.113.7", int status = 200, string? rule = null) =>
        new(Start, ip, "GET", "www.example.com", "/", route, action, action == RequestAction.Blocked ? WafEventKind.RuleBlocked : null, rule, null, null, status, 1.0);

    [Fact]
    public void Nothing_is_counted_while_nobody_watches()
    {
        var time = new ManualTimeProvider { Now = Start };
        var live = new LiveTraffic(time);
        live.Record(Entry(RequestAction.Forwarded), failed: false);

        Assert.False(live.IsWatched);
        Assert.Empty(live.TakeCompleted(long.MaxValue).Counts);
    }

    [Fact]
    public void Requests_are_counted_in_the_second_they_complete_while_watched()
    {
        var time = new ManualTimeProvider { Now = Start };
        var live = new LiveTraffic(time);
        live.AddWatcher();
        live.Record(Entry(RequestAction.Forwarded), failed: false);
        live.Record(Entry(RequestAction.Forwarded), failed: false);
        time.Advance(TimeSpan.FromSeconds(1));
        live.Record(Entry(RequestAction.NoRoute, route: null, status: 404), failed: false);

        var (counts, sources) = live.TakeCompleted(Start.ToUnixTimeSeconds() + 1);
        Assert.Equal([new TrafficCount(Start.ToUnixTimeSeconds(), TrafficKind.Forwarded, "", "website", 2)], counts);
        Assert.Empty(sources);

        (counts, sources) = live.TakeCompleted(Start.ToUnixTimeSeconds() + 2);
        Assert.Equal(TrafficKind.NoRoute, Assert.Single(counts).Kind);
        Assert.Equal(new LiveSourceHit(Start.ToUnixTimeSeconds() + 1, "203.0.113.7", "", 1), Assert.Single(sources));
    }

    [Fact]
    public void When_the_last_viewer_leaves_the_counts_are_forgotten()
    {
        var time = new ManualTimeProvider { Now = Start };
        var live = new LiveTraffic(time);
        live.AddWatcher();
        live.AddWatcher();
        live.Record(Entry(RequestAction.Forwarded), failed: false);
        live.RemoveWatcher();
        Assert.True(live.IsWatched);
        live.RemoveWatcher();
        live.RemoveWatcher(); // one too many: stays at zero
        Assert.False(live.IsWatched);
        Assert.Empty(live.TakeCompleted(long.MaxValue).Counts);
        live.AddWatcher();
        Assert.True(live.IsWatched);
    }

    [Fact]
    public void A_snapshot_adds_up_one_second_and_ranks_the_sources_of_the_last_minute()
    {
        var second = Start.ToUnixTimeSeconds();
        TrafficCount[] counts =
        [
            new(second, TrafficKind.Forwarded, "", "website", 40),
            new(second, TrafficKind.Forwarded, "", "api", 10),
            new(second, TrafficKind.RuleBlocked, "no-admin", "website", 3),
            new(second, TrafficKind.AttackBlocked, "SqlInjection", "api", 5),
            new(second, TrafficKind.BackendTimeout, "", "api", 1),
            new(second - 1, TrafficKind.Forwarded, "", "website", 99), // another second
        ];
        LiveSourceHit[] sources =
        [
            new(second, "10.0.0.1", "website", 3),
            new(second - 30, "10.0.0.2", "api", 5),
            new(second - 30, "10.0.0.1", "api", 1),
            new(second - 60, "10.0.0.9", "api", 50), // more than a minute ago
            new(second, TrafficCounter.OtherSource, "api", 7),
        ];

        var all = LiveTraffic.Build(second, null, counts, sources);
        Assert.Equal((59L, 50L, 8L, 1L), (all.Total, all.Good, all.Bad, all.Failed));
        Assert.Equal(new LiveKindCount(TrafficKind.Forwarded, TrafficOutcome.Good, "", 50), all.Kinds[0]);
        Assert.Contains(new LiveKindCount(TrafficKind.AttackBlocked, TrafficOutcome.Bad, "SqlInjection", 5), all.Kinds);
        Assert.Equal([new LiveSourceCount("10.0.0.1", 4), new LiveSourceCount("10.0.0.2", 5)], all.TopSources.OrderBy(s => s.Source));
        Assert.Equal("10.0.0.2", all.TopSources[0].Source);

        var api = LiveTraffic.Build(second, "api", counts, sources);
        Assert.Equal(("api", 16L, 10L, 5L, 1L), (api.Route, api.Total, api.Good, api.Bad, api.Failed));
        Assert.Equal([new LiveSourceCount("10.0.0.2", 5), new LiveSourceCount("10.0.0.1", 1)], api.TopSources);

        var quiet = LiveTraffic.Build(second + 1, null, counts, sources);
        Assert.Equal(0, quiet.Total);
        Assert.Empty(quiet.Kinds);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("http://127.0.0.1:9000", true)]
    [InlineData("HTTP://127.0.0.1:9000", true)]
    [InlineData("http://127.0.0.1:9001", false)]
    [InlineData("https://127.0.0.1:9000", false)]
    [InlineData("http://evil.example", false)]
    [InlineData("null", false)]
    public void Only_the_admin_address_itself_may_open_the_hub_from_a_browser(string? origin, bool allowed)
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new Microsoft.AspNetCore.Http.HostString("127.0.0.1:9000");
        if (origin is not null)
        {
            context.Request.Headers.Origin = origin;
        }

        Assert.Equal(allowed, TrafficHub.IsSameOrigin(context.Request));
    }
}
