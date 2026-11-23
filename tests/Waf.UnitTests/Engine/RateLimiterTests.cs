using System.Net;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Engine.RateLimiting;
using static FASoft.Waf.UnitTests.Engine.RuleBuilder;

namespace FASoft.Waf.UnitTests.Engine;

/// <summary>A clock tests can move by hand.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    // Midnight UTC: aligned with every window length that divides a day.
    public DateTimeOffset Now { get; set; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}

public class RateLimiterTests
{
    private readonly ManualTimeProvider _time = new();

    private static RateLimitRule Limit(string name, int permits, int windowSeconds = 60, RateLimitKey key = RateLimitKey.ClientIp, params RuleCondition[] conditions)
    {
        var limit = new RateLimitRule { Name = name, PermitLimit = permits, WindowSeconds = windowSeconds, Key = key };
        foreach (var condition in conditions)
        {
            limit.Conditions.Add(condition);
        }

        return limit;
    }

    private RateLimiter Limiter(params RateLimitRule[] limits) => Limiter(capacity: GatewaySettingsDefaults, limits);

    private const int GatewaySettingsDefaults = GatewaySettings.DefaultRateLimitMaxTrackedClients;

    private RateLimiter Limiter(int capacity, params RateLimitRule[] limits)
    {
        var configuration = Config();
        configuration.Settings.RateLimitMaxTrackedClients = capacity;
        foreach (var limit in limits)
        {
            configuration.RateLimits.Add(limit);
        }

        return new RateLimiter(configuration, _time);
    }

    private static FakeRequest From(string ip, string path = "/", string method = "GET", string? route = "website") =>
        new() { ClientIp = IPAddress.Parse(ip), Path = path, Method = method, RouteName = route };

    private static int CountAllowed(RateLimiter limiter, FakeRequest request, int attempts) =>
        Enumerable.Range(0, attempts).Count(_ => !limiter.Check(request).IsLimited);

    [Fact]
    public void Without_limits_everything_is_allowed()
    {
        var limiter = Limiter();

        Assert.False(limiter.HasLimits);
        Assert.Same(RateLimitDecision.Allowed, limiter.Check(From("198.51.100.1")));
        Assert.Equal(0, limiter.TrackedCount);
    }

    [Fact]
    public void Requests_up_to_the_limit_pass_and_the_next_is_limited()
    {
        var limiter = Limiter(Limit("per-ip", permits: 3));
        var client = From("198.51.100.1");

        Assert.Equal(3, CountAllowed(limiter, client, 3));

        var decision = limiter.Check(client);
        Assert.Equal(RateLimitOutcome.Limited, decision.Outcome);
        Assert.Equal("per-ip", decision.RuleName);
        Assert.Equal(TimeSpan.FromSeconds(60), decision.RetryAfter);
    }

    [Fact]
    public void Retry_after_counts_down_to_the_end_of_the_window()
    {
        var limiter = Limiter(Limit("per-ip", permits: 1));
        var client = From("198.51.100.1");
        _time.Advance(TimeSpan.FromSeconds(45.5));

        limiter.Check(client);

        Assert.Equal(TimeSpan.FromSeconds(15), limiter.Check(client).RetryAfter);
    }

    [Fact]
    public void Each_client_has_its_own_counter()
    {
        var limiter = Limiter(Limit("per-ip", permits: 2));

        Assert.Equal(2, CountAllowed(limiter, From("198.51.100.1"), 5));
        Assert.Equal(2, CountAllowed(limiter, From("198.51.100.2"), 5));
    }

    [Fact]
    public void Window_slides_instead_of_resetting_all_at_once()
    {
        var limiter = Limiter(Limit("per-ip", permits: 10));
        var client = From("198.51.100.1");
        Assert.Equal(10, CountAllowed(limiter, client, 10));

        // Halfway through the next window, half of the previous window still counts: 10 * 0.5 = 5.
        _time.Advance(TimeSpan.FromSeconds(90));

        Assert.Equal(5, CountAllowed(limiter, client, 20));
    }

    [Fact]
    public void Limit_lifts_once_the_client_slows_down()
    {
        var limiter = Limiter(Limit("per-ip", permits: 3));
        var client = From("198.51.100.1");
        CountAllowed(limiter, client, 3);
        Assert.True(limiter.Check(client).IsLimited);

        _time.Advance(TimeSpan.FromSeconds(120));

        Assert.False(limiter.Check(client).IsLimited);
    }

    [Fact]
    public void Rejected_requests_count_so_hammering_keeps_the_client_limited()
    {
        var limiter = Limiter(Limit("per-ip", permits: 2));
        var client = From("198.51.100.1");
        CountAllowed(limiter, client, 10); // 2 allowed, 8 rejected, all counted

        // 75% into the next window: 10 * 0.25 = 2.5 >= 2, still limited.
        _time.Advance(TimeSpan.FromSeconds(105));

        Assert.True(limiter.Check(client).IsLimited);
    }

    [Fact]
    public void Client_ip_and_route_key_counts_routes_separately()
    {
        var limiter = Limiter(Limit("per-ip-route", permits: 1, key: RateLimitKey.ClientIpAndRoute));

        Assert.False(limiter.Check(From("198.51.100.1", route: "website")).IsLimited);
        Assert.False(limiter.Check(From("198.51.100.1", route: "api")).IsLimited);
        Assert.True(limiter.Check(From("198.51.100.1", route: "api")).IsLimited);
    }

    [Fact]
    public void Route_key_counts_all_clients_together()
    {
        var limiter = Limiter(Limit("protect-api", permits: 2, key: RateLimitKey.Route));

        Assert.False(limiter.Check(From("198.51.100.1", route: "api")).IsLimited);
        Assert.False(limiter.Check(From("198.51.100.2", route: "api")).IsLimited);
        Assert.True(limiter.Check(From("198.51.100.3", route: "api")).IsLimited);
        Assert.False(limiter.Check(From("198.51.100.3", route: "website")).IsLimited);
    }

    [Fact]
    public void Route_scope_and_conditions_select_the_requests_that_count()
    {
        var login = Limit("login", permits: 2, conditions:
        [
            When(ConditionField.Path, ConditionOperator.Equals, "/login"),
            When(ConditionField.Method, ConditionOperator.Equals, "POST"),
        ]);
        login.Routes.Add("website");
        var limiter = Limiter(login);

        Assert.Equal(2, CountAllowed(limiter, From("198.51.100.1", "/login", "POST"), 5));
        Assert.Equal(5, CountAllowed(limiter, From("198.51.100.1", "/login", "GET"), 5));
        Assert.Equal(5, CountAllowed(limiter, From("198.51.100.1", "/products", "POST"), 5));
        Assert.Equal(5, CountAllowed(limiter, From("198.51.100.1", "/login", "POST", route: "api"), 5));
    }

    [Fact]
    public void Detection_only_limit_reports_but_does_not_limit()
    {
        var tryOut = Limit("try-out", permits: 1);
        tryOut.DetectionOnly = true;
        var limiter = Limiter(tryOut);
        var client = From("198.51.100.1");

        limiter.Check(client);
        var decision = limiter.Check(client);

        Assert.Equal(RateLimitOutcome.WouldLimit, decision.Outcome);
        Assert.False(decision.IsLimited);
        Assert.Equal("try-out", decision.RuleName);
    }

    [Fact]
    public void Global_detection_only_applies_to_rate_limits()
    {
        var configuration = Config();
        configuration.Settings.DetectionOnly = true;
        configuration.RateLimits.Add(Limit("per-ip", permits: 1));
        var limiter = new RateLimiter(configuration, _time);

        limiter.Check(From("198.51.100.1"));

        Assert.Equal(RateLimitOutcome.WouldLimit, limiter.Check(From("198.51.100.1")).Outcome);
    }

    [Fact]
    public void Enforced_limit_wins_over_a_detection_only_limit()
    {
        var tryOut = Limit("a-try-out", permits: 1);
        tryOut.DetectionOnly = true;
        var limiter = Limiter(tryOut, Limit("b-enforced", permits: 1));
        var client = From("198.51.100.1");

        limiter.Check(client);
        var decision = limiter.Check(client);

        Assert.Equal((RateLimitOutcome.Limited, "b-enforced"), (decision.Outcome, decision.RuleName));
    }

    [Fact]
    public void Disabled_limits_are_ignored()
    {
        var disabled = Limit("off", permits: 1);
        disabled.Enabled = false;
        var limiter = Limiter(disabled);

        Assert.False(limiter.HasLimits);
        Assert.Equal(5, CountAllowed(limiter, From("198.51.100.1"), 5));
    }

    [Theory]
    [InlineData("2001:db8::1", "2001:db8::ffff:2", true)]       // same /64
    [InlineData("2001:db8::1", "2001:db8:0:1::1", false)]       // different /64
    [InlineData("198.51.100.1", "::ffff:198.51.100.1", true)]   // IPv4 and its IPv4-mapped form
    [InlineData("198.51.100.1", "198.51.100.2", false)]
    public void Ipv6_clients_are_counted_per_64_network(string first, string second, bool shared)
    {
        var limiter = Limiter(Limit("per-ip", permits: 1));

        limiter.Check(From(first));

        Assert.Equal(shared, limiter.Check(From(second)).IsLimited);
    }

    [Fact]
    public void Counter_table_never_exceeds_its_capacity()
    {
        var limiter = Limiter(capacity: 1_000, Limit("per-ip", permits: 100));

        for (var i = 0; i < 20_000; i++)
        {
            limiter.Check(From(new IPAddress(0x0A000000u + (uint)i).ToString()));
            Assert.True(limiter.TrackedCount <= limiter.Capacity, $"{limiter.TrackedCount} counters after {i + 1} clients");
        }
    }

    [Fact]
    public void Flood_of_new_addresses_does_not_reset_a_limited_client()
    {
        var limiter = Limiter(capacity: 1_000, Limit("per-ip", permits: 5));
        var attacker = From("198.51.100.66");
        CountAllowed(limiter, attacker, 5);
        Assert.True(limiter.Check(attacker).IsLimited);

        // 5000 one-off requests from new addresses force several evictions.
        for (var i = 0; i < 5_000; i++)
        {
            limiter.Check(From(new IPAddress(0x0A000000u + (uint)i).ToString()));
        }

        Assert.True(limiter.Check(attacker).IsLimited);
    }

    [Fact]
    public void Expired_counters_are_dropped_first()
    {
        var limiter = Limiter(capacity: 1_000, Limit("per-ip", permits: 100));
        for (var i = 0; i < 1_000; i++)
        {
            limiter.Check(From(new IPAddress(0x0A000000u + (uint)i).ToString()));
        }

        Assert.Equal(1_000, limiter.TrackedCount);

        _time.Advance(TimeSpan.FromMinutes(5)); // all windows expired
        limiter.Check(From("198.51.100.1"));

        Assert.Equal(1, limiter.TrackedCount);
    }

    [Fact]
    public async Task Concurrent_requests_never_exceed_the_limit()
    {
        var limiter = Limiter(Limit("per-ip", permits: 100));
        var client = From("198.51.100.1");
        var allowed = 0;

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 1_000; i++)
            {
                if (!limiter.Check(client).IsLimited)
                {
                    Interlocked.Increment(ref allowed);
                }
            }
        }, TestContext.Current.CancellationToken)));

        Assert.Equal(100, allowed);
    }
}
