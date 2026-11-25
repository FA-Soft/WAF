using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.UnitTests.Engine;

namespace FASoft.Waf.UnitTests.Logging;

public sealed class ResponseTimesTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 11, 25, 10, 0, 0, TimeSpan.Zero);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly SqliteMetricsStore _store;

    public ResponseTimesTests()
    {
        _store = new SqliteMetricsStore(Path.Combine(_directory, "metrics.db"));
    }

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
    [InlineData(0.1)]
    [InlineData(0.5)]
    [InlineData(0.7)]
    [InlineData(3)]
    [InlineData(42)]
    [InlineData(250)]
    [InlineData(1_234)]
    [InlineData(29_000)]
    public void Every_time_falls_in_a_bin_whose_estimate_is_within_12_percent(double milliseconds)
    {
        var bin = LatencyHistogram.Bin(milliseconds);
        Assert.InRange(milliseconds, bin == 0 ? 0 : LatencyHistogram.UpperEdge(bin - 1), LatencyHistogram.UpperEdge(bin));
        if (bin > 0)
        {
            Assert.InRange(LatencyHistogram.Estimate(bin) / milliseconds, 1 / 1.12, 1.12);
        }
    }

    [Fact]
    public void Very_slow_requests_share_the_last_bin()
    {
        Assert.Equal(LatencyHistogram.Bins - 1, LatencyHistogram.Bin(10 * 60 * 1000));
        Assert.True(LatencyHistogram.UpperEdge(LatencyHistogram.Bins - 1) > 100_000);
        Assert.Equal(0, LatencyHistogram.Bin(double.NaN));
    }

    [Fact]
    public void Percentiles_from_the_histogram_match_the_exact_ones_within_its_precision()
    {
        var random = new Random(49);
        var times = Enumerable.Range(0, 5000).Select(_ => Math.Exp(random.NextDouble() * 8)).ToList(); // 1 ms to 3 s
        var counts = new long[LatencyHistogram.Bins];
        foreach (var time in times)
        {
            counts[LatencyHistogram.Bin(time)]++;
        }

        var sorted = times.Order().ToList();
        foreach (var p in new[] { 0.5, 0.95, 0.99 })
        {
            var exact = sorted[(int)Math.Ceiling(p * sorted.Count) - 1];
            Assert.InRange(LatencyHistogram.Percentile(counts, p)!.Value / exact, 1 / 1.12, 1.12);
        }

        Assert.Null(LatencyHistogram.Percentile(new long[LatencyHistogram.Bins], 0.5));
    }

    [Theory]
    [InlineData(200, BackendMetric.Status2xx)]
    [InlineData(204, BackendMetric.Status2xx)]
    [InlineData(301, BackendMetric.Status3xx)]
    [InlineData(404, BackendMetric.Status4xx)]
    [InlineData(500, BackendMetric.Status5xx)]
    [InlineData(503, BackendMetric.Status5xx)]
    public void Status_codes_are_grouped_in_classes(int status, BackendMetric expected)
    {
        Assert.Equal(expected, LatencyHistogram.StatusClass(status));
    }

    private static RequestLogEntry Entry(RequestAction action, int status, double latency, double? backend, string? destination = "http://10.0.0.5:8080/", DateTimeOffset? at = null) =>
        new(at ?? Start, "203.0.113.7", "GET", "www.example.com", "/", "website", action, null, null, null, destination, status, latency, backend);

    private sealed class Failovers : IRouteFailoverMonitor
    {
        public IReadOnlyList<RouteFailoverStatus> Statuses { get; set; } = [];
    }

    [Fact]
    public async Task The_writer_counts_response_times_and_backend_results_per_minute()
    {
        await _store.InitializeAsync(Ct);
        var time = new ManualTimeProvider { Now = Start };
        var failovers = new Failovers();
        using var writer = new RequestMetricsWriter(_store, new MetricsOptions(), time, NullLogger<RequestMetricsWriter>.Instance, failovers);

        writer.Record(Entry(RequestAction.Forwarded, 200, 12.0, 10.0), failed: false);
        writer.Record(Entry(RequestAction.Forwarded, 200, 120.0, 118.0), failed: false);
        writer.Record(Entry(RequestAction.Forwarded, 404, 5.0, 4.5), failed: false);
        writer.Record(Entry(RequestAction.Forwarded, 500, 30.0, 29.0), failed: false);
        writer.Record(Entry(RequestAction.BackendUnavailable, 502, 3.0, 2.5), failed: false);
        writer.Record(Entry(RequestAction.BackendUnavailable, 503, 1.0, null, destination: null), failed: false);
        writer.Record(Entry(RequestAction.NoRoute, 404, 0.4, null, destination: null), failed: false); // no route: neither
        failovers.Statuses = [new RouteFailoverStatus("website", 1, "http://10.0.0.6:8080/", Start)];

        time.Now = Start.AddMinutes(2);
        await writer.FlushAsync(all: false, Ct);

        var (series, summary) = await _store.ReadLatencyAsync(new TrafficQuery(Start, Start.AddMinutes(1), MetricsTier.Minute), Ct);
        Assert.Equal(4, summary.Requests); // only the forwarded ones
        Assert.Equal(4, Assert.Single(series).Requests);
        Assert.InRange(summary.P50!.Value, 10, 15);  // 12 ms (5, 12, 30, 120: the 2nd)
        Assert.InRange(summary.P99!.Value, 105, 135); // 120 ms
        Assert.InRange(summary.GatewayP50!.Value, 0.9, 1.3); // about 1 ms added: 2, 2, 0.5, 1

        var backend = Assert.Single(await _store.ReadBackendsAsync(new TrafficQuery(Start, Start.AddMinutes(1), MetricsTier.Minute), Ct), b => b.Destination.Length > 0);
        Assert.Equal(
            (2L, 1L, 1L, 1L, 5L),
            (backend.Get(BackendMetric.Status2xx), backend.Get(BackendMetric.Status4xx), backend.Get(BackendMetric.Status5xx), backend.Get(BackendMetric.BackendError), backend.Total));
        var none = Assert.Single(await _store.ReadBackendsAsync(new TrafficQuery(Start, Start.AddMinutes(1), MetricsTier.Minute), Ct), b => b.Destination.Length == 0);
        Assert.Equal(1, none.Get(BackendMetric.NoBackend));

        var period = Assert.Single(await _store.ReadFailoversAsync(Start, Start.AddHours(1), null, Ct));
        Assert.Equal(("website", 1, Start, (DateTimeOffset?)null), (period.Route, period.Failover, period.Start, period.End));
    }

    [Fact]
    public async Task Failover_periods_start_switch_and_end()
    {
        await _store.InitializeAsync(Ct);
        var first = new RouteFailoverStatus("api", 1, "http://10.0.0.6/", Start);
        await _store.RecordFailoversAsync([first], Start.AddMinutes(1), Ct);
        await _store.RecordFailoversAsync([first], Start.AddMinutes(2), Ct); // unchanged: nothing written

        var second = new RouteFailoverStatus("api", 2, "http://10.0.0.7/", Start.AddMinutes(5));
        await _store.RecordFailoversAsync([second], Start.AddMinutes(6), Ct);
        await _store.RecordFailoversAsync([], Start.AddMinutes(10), Ct); // back on its primaries

        var periods = await _store.ReadFailoversAsync(Start, Start.AddHours(1), "api", Ct);
        Assert.Equal(
            [
                new FailoverPeriod("api", 1, "http://10.0.0.6/", Start, Start.AddMinutes(5)),
                new FailoverPeriod("api", 2, "http://10.0.0.7/", Start.AddMinutes(5), Start.AddMinutes(10)),
            ],
            periods);
        Assert.Empty(await _store.ReadFailoversAsync(Start.AddMinutes(11), Start.AddHours(1), null, Ct));
        Assert.Empty(await _store.ReadFailoversAsync(Start, Start.AddHours(1), "website", Ct));

        // Kept as long as the month tier.
        await _store.MaintainAsync(new MetricsRetention(), Start.AddDays(1200), Ct);
        Assert.Empty(await _store.ReadFailoversAsync(Start, Start.AddHours(1), null, Ct));
    }

    [Fact]
    public async Task Response_times_and_backends_are_rolled_up_by_summing()
    {
        await _store.InitializeAsync(Ct);
        var counter = new TrafficCounter();
        for (var minute = 0; minute < 3; minute++)
        {
            for (var i = 0; i < 10; i++)
            {
                counter.AddResponse(Start.AddMinutes(minute), "website", 10 * (minute + 1), 8 * (minute + 1));
                counter.AddBackend(Start.AddMinutes(minute), "website", "http://10.0.0.5/", BackendMetric.Status2xx);
            }
        }

        await _store.WriteAsync(counter.TakeCompleted(Start.AddHours(1), TimeSpan.Zero, all: true), Ct);
        await _store.MaintainAsync(new MetricsRetention(), Start.AddDays(10), Ct); // minutes gone, hours and days kept

        foreach (var tier in new[] { MetricsTier.Hour, MetricsTier.Day })
        {
            var query = new TrafficQuery(Start.AddDays(-1), Start.AddDays(1), tier);
            var (_, summary) = await _store.ReadLatencyAsync(query, Ct);
            Assert.Equal(30, summary.Requests);
            Assert.InRange(summary.P50!.Value, 18, 22.5); // 20 ms
            Assert.Equal(30, Assert.Single(await _store.ReadBackendsAsync(query, Ct)).Get(BackendMetric.Status2xx));
        }

        var minutes = await _store.ReadLatencyAsync(new TrafficQuery(Start, Start.AddMinutes(3), MetricsTier.Minute), Ct);
        Assert.Equal(0, minutes.Summary.Requests);
    }

    [Fact]
    public async Task The_route_filter_applies_to_response_times_and_backends()
    {
        await _store.InitializeAsync(Ct);
        var counter = new TrafficCounter();
        counter.AddResponse(Start, "website", 10, 9);
        counter.AddResponse(Start, "api", 1000, 990);
        counter.AddBackend(Start, "website", "http://10.0.0.5/", BackendMetric.Status2xx);
        counter.AddBackend(Start, "api", "http://10.0.0.9/", BackendMetric.BackendTimeout);
        await _store.WriteAsync(counter.TakeCompleted(Start.AddHours(1), TimeSpan.Zero, all: true), Ct);
        var query = new TrafficQuery(Start, Start.AddMinutes(1), MetricsTier.Second, "api"); // seconds: read per minute

        var (series, summary) = await _store.ReadLatencyAsync(query, Ct);
        Assert.Equal(1, summary.Requests);
        Assert.InRange(summary.P50!.Value, 900, 1120);
        Assert.Equal(60, Assert.Single(series).Seconds);
        Assert.Equal("http://10.0.0.9/", Assert.Single(await _store.ReadBackendsAsync(query, Ct)).Destination);
    }
}
