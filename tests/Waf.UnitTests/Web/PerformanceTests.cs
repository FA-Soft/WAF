using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

public class PerformanceTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    private static PerformanceQuery Parse(string query) => PerformanceQuery.Parse(new QueryCollection(QueryHelpers.ParseQuery(query)));

    [Fact]
    public void The_default_is_the_live_view_of_the_last_five_minutes()
    {
        var query = Parse("");

        Assert.True(query.IsLive);
        Assert.False(query.IsFiltered);
        Assert.Equal((Now.AddMinutes(-5), Now), query.Range(Now));
        Assert.Equal("performance", query.Url());
    }

    [Fact]
    public void Periods_and_filters_round_trip_through_the_address()
    {
        var query = Parse("period=7d&route=api&type=RuleBlocked:no-admin&type=NoRoute&source=203.0.113.7,%202001:db8::1&compare=1");

        Assert.Equal("7d", query.Period);
        Assert.Equal("api", query.Route);
        Assert.Equal([new TrafficType(TrafficKind.RuleBlocked, "no-admin"), new TrafficType(TrafficKind.NoRoute)], query.Types);
        Assert.Equal(["203.0.113.7", "2001:db8::1"], query.Sources);
        Assert.True(query.Compare);
        Assert.Equal((Now.AddDays(-7), Now), query.Range(Now));
        Assert.Equal(query.Url(), Parse(query.Url()[(query.Url().IndexOf('?', StringComparison.Ordinal) + 1)..]).Url());
    }

    [Fact]
    public void A_custom_period_takes_unix_seconds_or_iso_times_and_is_kept_within_bounds()
    {
        var from = Now.AddDays(-2);
        var to = Now.AddDays(-1);
        var query = Parse($"period=custom&from={from.ToUnixTimeSeconds()}&to={to.ToUnixTimeSeconds()}");
        Assert.Equal((from, to), query.Range(Now));

        var iso = Parse("period=custom&from=2026-11-24T10:00:00%2B01:00&to=2026-11-24T12:00");
        Assert.Equal((new DateTimeOffset(2026, 11, 24, 9, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 11, 24, 12, 0, 0, TimeSpan.Zero)), iso.Range(Now));

        // Into the future: up to now.
        Assert.Equal(Now, Parse($"period=custom&from={from.ToUnixTimeSeconds()}&to={Now.AddDays(5).ToUnixTimeSeconds()}").Range(Now).To);

        // Incomplete or reversed: the live view.
        Assert.True(Parse($"period=custom&from={to.ToUnixTimeSeconds()}&to={from.ToUnixTimeSeconds()}").IsLive);
        Assert.True(Parse("period=custom&from=1").IsLive);
    }

    [Theory]
    [InlineData("period=forever")]
    [InlineData("route=%00x")]
    [InlineData("type=Nonsense&type=12")]
    [InlineData("source=not-an-ip&source=<script>")]
    public void Unknown_values_are_ignored(string text)
    {
        var query = Parse(text);
        Assert.True(query.IsLive);
        Assert.False(query.IsFiltered);
    }

    [Fact]
    public void At_most_twenty_types_and_sources_are_kept()
    {
        var sources = string.Join('&', Enumerable.Range(1, 30).Select(i => $"source=10.0.0.{i}"));
        Assert.Equal(PerformanceQuery.MaxFilterValues, Parse("period=1h&" + sources).Sources.Count);
    }

    [Theory]
    [InlineData(TrafficKind.RuleBlocked, "no-admin", "show=Blocked&rule=no-admin")]
    [InlineData(TrafficKind.RateLimited, "per-ip", "show=Blocked&rule=per-ip")]
    [InlineData(TrafficKind.AttackBlocked, "SqlInjection", "show=Blocked&q=SqlInjection")]
    [InlineData(TrafficKind.WouldBeBlocked, "SqlInjection", "show=WouldBlock&q=SqlInjection")]
    [InlineData(TrafficKind.WouldBeBlocked, "watch-old-clients", "show=WouldBlock&rule=watch-old-clients")]
    [InlineData(TrafficKind.NoRoute, null, "show=NoRoute")]
    [InlineData(TrafficKind.FailClosed, null, "show=Blocked&status=503")]
    [InlineData(TrafficKind.BackendTimeout, null, "status=504")]
    public void Numbers_link_to_the_same_requests_in_the_request_log(TrafficKind kind, string? name, string expected)
    {
        var url = PerformanceText.LogUrl(Now.AddHours(-1), Now, Now.AddDays(-30), "api", new TrafficType(kind, name))!;
        var query = QueryHelpers.ParseQuery(url[(url.IndexOf('?', StringComparison.Ordinal) + 1)..]);

        Assert.StartsWith("logs?", url, StringComparison.Ordinal);
        Assert.Equal(Now.AddHours(-1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), query["from"]);
        Assert.Equal(Now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), query["to"]);
        Assert.Equal("api", query["route"]);
        foreach (var pair in QueryHelpers.ParseQuery(expected))
        {
            Assert.Equal(pair.Value, query[pair.Key]);
        }

        // The log page understands the link: the same period and filters.
        var log = LogQuery.Parse(new QueryCollection(query));
        Assert.Equal((Now.AddHours(-1), Now), (log.From!.Value, log.To!.Value));
        Assert.Equal((Now.AddHours(-1), Now), (log.ToFilter(Now).From!.Value, log.ToFilter(Now).To!.Value));
    }

    [Fact]
    public void A_destination_filter_is_read_from_the_address_and_replaces_the_source_filter()
    {
        var query = Parse("period=1h&source=203.0.113.7&destination=www.example.com/wp-login.php&destination=no-slash&destination=%00x/");

        Assert.Equal(["www.example.com/wp-login.php"], query.Destinations);
        Assert.True(query.IsFiltered);
        Assert.Contains("destination=www.example.com%2Fwp-login.php", query.Url(), StringComparison.Ordinal);

        var only = query.WithDestination("probe.example.net/.env");
        Assert.Equal(["probe.example.net/.env"], only.Destinations);
        Assert.Empty(only.Sources);
        Assert.Empty(only.WithSource("203.0.113.9").Destinations);
    }

    [Fact]
    public void A_destination_links_to_its_host_and_path_in_the_request_log()
    {
        var url = PerformanceText.LogUrl(Now.AddHours(-1), Now, Now.AddDays(-1), null, null, null, "www.example.com/wp-login.php")!;
        var query = QueryHelpers.ParseQuery(url[(url.IndexOf('?', StringComparison.Ordinal) + 1)..]);

        Assert.Equal("www.example.com", query["host"]);
        Assert.Equal("/wp-login.php", query["q"]);
    }

    [Fact]
    public void There_is_no_link_when_the_request_log_no_longer_has_the_period()
    {
        Assert.Null(PerformanceText.LogUrl(Now.AddDays(-60), Now.AddDays(-40), Now.AddDays(-30), null));
        Assert.Null(PerformanceText.LogUrl(Now.AddHours(-1), Now, null, null));
        Assert.Contains("ip=203.0.113.7", PerformanceText.LogUrl(Now.AddHours(-1), Now, Now.AddDays(-1), null, null, "203.0.113.7"), StringComparison.Ordinal);
    }

    [Fact]
    public void The_csv_has_one_line_per_bucket_in_utc()
    {
        var report = new PerformanceReport(
            Now.AddMinutes(-2), Now, MetricsTier.Minute,
            [new TrafficBucket(Now.AddMinutes(-2).ToUnixTimeSeconds(), 60, 120, 6, 0, 9), new TrafficBucket(Now.AddMinutes(-1).ToUnixTimeSeconds(), 60, 0, 0, 0, null)],
            null, [], []);

        Assert.Equal(
            "start_utc,seconds,good,bad,failed,total,per_second,peak_per_second\r\n" +
            "2026-11-25T11:58:00Z,60,120,6,0,126,2.1,9\r\n" +
            "2026-11-25T11:59:00Z,60,0,0,0,0,0,\r\n",
            report.ToCsv());
        Assert.Equal(126, report.Total);
        Assert.Equal(9, report.Peak);
        Assert.Equal(126.0 / 120, report.PerSecond);
    }

    [Fact]
    public void The_log_page_keeps_a_fixed_period_in_its_address()
    {
        var log = LogQuery.Parse(new QueryCollection(QueryHelpers.ParseQuery("from=1764064800&to=1764068400&show=blocked")));

        Assert.True(log.HasPeriod);
        Assert.Contains("from=1764064800", log.Url("logs"), StringComparison.Ordinal);
        Assert.Contains("to=1764068400", log.Url("logs"), StringComparison.Ordinal);
        Assert.Null(LogQuery.Parse(new QueryCollection(QueryHelpers.ParseQuery("from=abc"))).From);
    }
}
