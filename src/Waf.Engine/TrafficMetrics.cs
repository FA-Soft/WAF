using System.Collections.Concurrent;
using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Engine;

/// <summary>The three groups of traffic on the performance dashboard.</summary>
public enum TrafficOutcome
{
    /// <summary>Handled as intended: forwarded, redirected to HTTPS, or answered by the gateway.</summary>
    Good = 0,

    /// <summary>Refused because of the visitor's request: blocked, rate limited, fail-closed or no route.</summary>
    Bad = 1,

    /// <summary>Not answered because of the gateway or a backend, not the visitor: no backend, backend error or timeout.</summary>
    Failed = 2,
}

/// <summary>
/// What a request is counted as. The numbers are stored in <c>metrics.db</c>: never change them, only add new ones.
/// The tens digit is the <see cref="TrafficOutcome"/>.
/// </summary>
public enum TrafficKind
{
    /// <summary>Forwarded to a backend.</summary>
    Forwarded = 1,

    /// <summary>Redirected from HTTP to HTTPS.</summary>
    Redirected = 2,

    /// <summary>Answered by the gateway itself (a Let's Encrypt challenge).</summary>
    Answered = 3,

    /// <summary>Forwarded, but a rule, attack check or rate limit in detection-only mode would have blocked it.</summary>
    WouldBeBlocked = 4,

    /// <summary>Blocked by a rule (403). Name: the rule.</summary>
    RuleBlocked = 10,

    /// <summary>Blocked by attack detection (403). Name: the attack category.</summary>
    AttackBlocked = 11,

    /// <summary>Rejected by a rate limit (429). Name: the limit.</summary>
    RateLimited = 12,

    /// <summary>Refused because the firewall was unavailable (503, fail-closed).</summary>
    FailClosed = 13,

    /// <summary>No route matched (404).</summary>
    NoRoute = 14,

    /// <summary>A route matched, but it had no available backend (503).</summary>
    NoBackend = 20,

    /// <summary>The backend refused the connection or sent an invalid answer (502).</summary>
    BackendError = 21,

    /// <summary>The backend did not answer in time (504).</summary>
    BackendTimeout = 22,

    /// <summary>The gateway failed while handling the request (500).</summary>
    GatewayError = 23,
}

/// <summary>Resolution of stored traffic counts. The numbers are stored in <c>metrics.db</c>.</summary>
public enum MetricsTier
{
    Second = 0,
    Minute = 1,
    Hour = 2,
    Day = 3,
    Week = 4,
    Month = 5,
}

/// <summary>Bucket boundaries of the tiers, in Unix seconds (UTC). Weeks start on Monday; months are calendar months.</summary>
public static class MetricsBuckets
{
    /// <summary>The tiers from fine to coarse.</summary>
    public static IReadOnlyList<MetricsTier> Tiers { get; } =
        [MetricsTier.Second, MetricsTier.Minute, MetricsTier.Hour, MetricsTier.Day, MetricsTier.Week, MetricsTier.Month];

    /// <summary>
    /// The tier a tier is made from. Weeks and months are both made from days (a month does not consist of whole
    /// weeks); seconds are not made from anything.
    /// </summary>
    public static MetricsTier? FinerOf(MetricsTier tier) => tier switch
    {
        MetricsTier.Minute => MetricsTier.Second,
        MetricsTier.Hour => MetricsTier.Minute,
        MetricsTier.Day => MetricsTier.Hour,
        MetricsTier.Week or MetricsTier.Month => MetricsTier.Day,
        _ => null,
    };

    /// <summary>The tiers made from <paramref name="tier"/>.</summary>
    public static IEnumerable<MetricsTier> CoarserOf(MetricsTier tier) => Tiers.Where(t => FinerOf(t) == tier);

    /// <summary>Start of the bucket of <paramref name="tier"/> that holds <paramref name="unixSeconds"/>.</summary>
    public static long Start(MetricsTier tier, long unixSeconds) => tier switch
    {
        MetricsTier.Second => unixSeconds,
        MetricsTier.Minute => Floor(unixSeconds, 60),
        MetricsTier.Hour => Floor(unixSeconds, 3600),
        MetricsTier.Day => Floor(unixSeconds, 86400),
        // 1 January 1970 was a Thursday: 3 days after a Monday.
        MetricsTier.Week => Floor(unixSeconds + (3 * 86400), 7 * 86400) - (3 * 86400),
        MetricsTier.Month => MonthStart(DateTimeOffset.FromUnixTimeSeconds(unixSeconds)),
        _ => throw new ArgumentOutOfRangeException(nameof(tier)),
    };

    /// <summary>Start of the bucket after the one that starts at <paramref name="bucketStart"/>.</summary>
    public static long Next(MetricsTier tier, long bucketStart) => tier switch
    {
        MetricsTier.Second => bucketStart + 1,
        MetricsTier.Minute => bucketStart + 60,
        MetricsTier.Hour => bucketStart + 3600,
        MetricsTier.Day => bucketStart + 86400,
        MetricsTier.Week => bucketStart + (7 * 86400),
        MetricsTier.Month => DateTimeOffset.FromUnixTimeSeconds(bucketStart).AddMonths(1).ToUnixTimeSeconds(),
        _ => throw new ArgumentOutOfRangeException(nameof(tier)),
    };

    /// <summary>The first bucket start of <paramref name="tier"/> at or after <paramref name="unixSeconds"/>.</summary>
    public static long Ceiling(MetricsTier tier, long unixSeconds)
    {
        var start = Start(tier, unixSeconds);
        return start == unixSeconds ? start : Next(tier, start);
    }

    private static long Floor(long value, long size) => value - (((value % size) + size) % size);

    private static long MonthStart(DateTimeOffset time) => new DateTimeOffset(time.Year, time.Month, 1, 0, 0, 0, TimeSpan.Zero).ToUnixTimeSeconds();
}

/// <summary>Requests of one kind, route and name within one bucket.</summary>
/// <param name="BucketStart">Start of the bucket, in Unix seconds (UTC).</param>
/// <param name="Kind">What the requests were counted as.</param>
/// <param name="Name">Rule, attack category or rate limit; empty for the other kinds.</param>
/// <param name="Route">Route; empty when no route matched.</param>
/// <param name="Count">Number of requests.</param>
public sealed record TrafficCount(long BucketStart, TrafficKind Kind, string Name, string Route, long Count)
{
    public TrafficOutcome Outcome => TrafficClassifier.OutcomeOf(Kind);
}

/// <summary>Bad requests from one source (client IP), or to one destination (host and path), of one kind within one bucket.</summary>
/// <param name="BucketStart">Start of the bucket, in Unix seconds (UTC).</param>
/// <param name="Source">Client IP, or <see cref="TrafficCounter.OtherSource"/> for all sources outside the top.</param>
/// <param name="Kind">What the requests were counted as (always a bad kind).</param>
/// <param name="Count">Number of requests.</param>
public sealed record SourceCount(long BucketStart, string Source, TrafficKind Kind, long Count);

/// <summary>Sorts a request into a <see cref="TrafficKind"/>.</summary>
public static class TrafficClassifier
{
    /// <summary>Longest name or route kept; longer ones are cut (names come from the configuration, so this is rare).</summary>
    public const int MaxNameLength = 100;

    public static TrafficOutcome OutcomeOf(TrafficKind kind) => (TrafficOutcome)((int)kind / 10);

    /// <summary>
    /// What <paramref name="entry"/> counts as, and its name (rule, attack category or rate limit).
    /// <paramref name="failed"/>: the pipeline threw an exception.
    /// </summary>
    public static (TrafficKind Kind, string Name) Classify(RequestLogEntry entry, bool failed)
    {
        ArgumentNullException.ThrowIfNull(entry);

        return entry.Action switch
        {
            RequestAction.Blocked when entry.Event == WafEventKind.AttackBlocked => (TrafficKind.AttackBlocked, AttackCategoryOf(entry.Detail)),
            RequestAction.Blocked => (TrafficKind.RuleBlocked, Name(entry.RuleName)),
            RequestAction.RateLimited => (TrafficKind.RateLimited, Name(entry.RuleName)),
            RequestAction.FailClosed => (TrafficKind.FailClosed, string.Empty),
            RequestAction.NoRoute => (TrafficKind.NoRoute, string.Empty),
            RequestAction.BackendUnavailable => (entry.StatusCode switch
            {
                502 => TrafficKind.BackendError,
                504 => TrafficKind.BackendTimeout,
                _ => TrafficKind.NoBackend,
            }, string.Empty),
            _ when failed => (TrafficKind.GatewayError, string.Empty),
            RequestAction.Redirected => (TrafficKind.Redirected, string.Empty),
            RequestAction.Answered => (TrafficKind.Answered, string.Empty),
            _ => entry.Event switch
            {
                WafEventKind.RuleDetected or WafEventKind.RateLimitDetected => (TrafficKind.WouldBeBlocked, Name(entry.RuleName)),
                WafEventKind.AttackDetected => (TrafficKind.WouldBeBlocked, AttackCategoryOf(entry.Detail)),
                _ => (TrafficKind.Forwarded, string.Empty),
            },
        };
    }

    /// <summary>The attack category at the start of an attack event's detail ("SqlInjection in QueryString …").</summary>
    private static string AttackCategoryOf(string? detail)
    {
        var first = detail?.Split(' ', 2)[0];
        return Enum.TryParse<AttackCategory>(first, out var category) && Enum.IsDefined(category) ? category.ToString() : string.Empty;
    }

    /// <summary>Longest destination kept: the host name and the start of the path.</summary>
    public const int MaxDestinationLength = 300;

    /// <summary>
    /// The requested destination of a request: its host name (lower case) and path, without the query string, e.g.
    /// "www.example.com/wp-login.php"; cut at <see cref="MaxDestinationLength"/> characters.
    /// </summary>
    public static string Destination(RequestLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var host = entry.Host.ToLowerInvariant();
        var destination = host.Length > 100 ? host[..100] : host;
        destination += string.IsNullOrEmpty(entry.Path) ? "/" : entry.Path;
        return destination.Length <= MaxDestinationLength ? destination : destination[..MaxDestinationLength];
    }

    /// <summary>
    /// The network of a client IP: the /24 of an IPv4 address ("203.0.113.0/24"), the /48 of an IPv6 address
    /// ("2001:db8:1::/48"); null when it is not an IP address.
    /// </summary>
    public static string? Network(string? clientIp)
    {
        if (!System.Net.IPAddress.TryParse(clientIp, out var address))
        {
            return null;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();
        var (keep, prefix) = bytes.Length == 4 ? (3, 24) : (6, 48);
        for (var i = keep; i < bytes.Length; i++)
        {
            bytes[i] = 0;
        }

        return $"{new System.Net.IPAddress(bytes)}/{prefix}";
    }

    /// <summary>A rule, limit or route name as stored: empty for none, cut at <see cref="MaxNameLength"/>.</summary>
    public static string Name(string? name) =>
        string.IsNullOrEmpty(name) ? string.Empty : name.Length <= MaxNameLength ? name : name[..MaxNameLength];
}

/// <summary>
/// Counts requests in memory: per second by kind, name and route, and bad requests per minute by source and by
/// requested destination (host and path). Adding is
/// lock-free and never waits; a background writer takes the completed buckets (<see cref="TakeCompleted"/>).
/// </summary>
/// <remarks>
/// Each count is a cell in a concurrent dictionary, incremented with <see cref="Interlocked"/>. Taking a bucket
/// removes its cell and swaps its value for a "taken" mark; a request that still held the cell sees the mark and
/// counts again in a new cell, so no request is lost or counted twice. A request that arrives late (counted by its
/// start time, after its bucket was taken) lands in a new cell of that bucket; the store adds it to the stored count.
/// </remarks>
public sealed class TrafficCounter
{
    /// <summary>The source that stands for all sources outside the top of a bucket.</summary>
    public const string OtherSource = "other";

    /// <summary>Sources kept per minute; the rest are added up as <see cref="OtherSource"/>.</summary>
    public const int TopSources = 100;

    private const long Taken = long.MinValue / 2;

    private readonly ConcurrentDictionary<CountKey, Cell> _counts = new();
    private readonly ConcurrentDictionary<SourceKey, Cell> _sources = new();
    private readonly ConcurrentDictionary<SourceKey, Cell> _destinations = new();
    private readonly ConcurrentDictionary<SourceKey, Cell> _networks = new();
    private readonly ConcurrentDictionary<SourceKey, Cell> _countries = new();
    private readonly ConcurrentDictionary<LatencyKey, Cell> _latencies = new();
    private readonly ConcurrentDictionary<BackendKey, Cell> _backends = new();
    private readonly int _maxCells;
    private readonly int _maxSourceCells;
    private int _countCells;
    private int _sourceCells;
    private int _destinationCells;
    private int _networkCells;
    private int _countryCells;
    private int _latencyCells;
    private int _backendCells;

    /// <param name="maxCells">Most counts waiting in memory; beyond that, requests are not counted (see <see cref="Add"/>).</param>
    /// <param name="maxSourceCells">Most source counts waiting in memory; beyond that, new sources count as <see cref="OtherSource"/>.</param>
    public TrafficCounter(int maxCells = 100_000, int maxSourceCells = 20_000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxCells, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxSourceCells, 1);
        _maxCells = maxCells;
        _maxSourceCells = maxSourceCells;
    }

    /// <summary>Counts waiting in memory.</summary>
    public int Pending =>
        Volatile.Read(ref _countCells) + Volatile.Read(ref _sourceCells) + Volatile.Read(ref _destinationCells)
        + Volatile.Read(ref _networkCells) + Volatile.Read(ref _countryCells)
        + Volatile.Read(ref _latencyCells) + Volatile.Read(ref _backendCells);

    /// <summary>
    /// Counts the response times of a forwarded request, per minute: the total, and when known the backend's time and
    /// what the gateway added. Beyond the memory limit they are left out (the request itself is counted by <see cref="Add"/>).
    /// </summary>
    public void AddResponse(DateTimeOffset timestamp, string? route, double totalMs, double? backendMs)
    {
        var second = timestamp.ToUnixTimeSeconds();
        var minute = second - (second % 60);
        var name = TrafficClassifier.Name(route);
        Increment(_latencies, new LatencyKey(minute, name, LatencySeries.Total, LatencyHistogram.Bin(totalMs)), ref _latencyCells, _maxSourceCells);
        if (backendMs is { } backend)
        {
            Increment(_latencies, new LatencyKey(minute, name, LatencySeries.Backend, LatencyHistogram.Bin(backend)), ref _latencyCells, _maxSourceCells);
            Increment(_latencies, new LatencyKey(minute, name, LatencySeries.Gateway, LatencyHistogram.Bin(Math.Max(0, totalMs - backend))), ref _latencyCells, _maxSourceCells);
        }
    }

    /// <summary>Counts what a backend did with a request (its status class, or the error when it did not answer), per minute.</summary>
    public void AddBackend(DateTimeOffset timestamp, string? route, string? destination, BackendMetric metric)
    {
        var second = timestamp.ToUnixTimeSeconds();
        var key = new BackendKey(second - (second % 60), TrafficClassifier.Name(route), destination ?? string.Empty, metric);
        Increment(_backends, key, ref _backendCells, _maxSourceCells);
    }

    /// <summary>
    /// Counts one request. Returns false when it could not be counted because too many counts are waiting (the
    /// store is not keeping up).
    /// </summary>
    /// <param name="destination">The requested host and path (<see cref="TrafficClassifier.Destination"/>), kept for bad requests like the source.</param>
    /// <param name="country">The source's country (ISO code), when a country database is configured.</param>
    public bool Add(DateTimeOffset timestamp, TrafficKind kind, string name, string? route, string? source, string? destination = null, string? country = null)
    {
        ArgumentNullException.ThrowIfNull(name);

        var second = timestamp.ToUnixTimeSeconds();
        if (!Increment(_counts, new CountKey(second, kind, name, TrafficClassifier.Name(route)), ref _countCells, _maxCells))
        {
            return false;
        }

        if (source is not null && TrafficClassifier.OutcomeOf(kind) == TrafficOutcome.Bad)
        {
            var minute = second - (second % 60);
            if (!Increment(_sources, new SourceKey(minute, source, kind), ref _sourceCells, _maxSourceCells))
            {
                // Many addresses at once (a distributed attack): the request is still counted, as "other".
                Increment(_sources, new SourceKey(minute, OtherSource, kind), ref _sourceCells, int.MaxValue);
            }
        }

        if (TrafficClassifier.OutcomeOf(kind) == TrafficOutcome.Bad)
        {
            var minute = second - (second % 60);
            if (TrafficClassifier.Network(source) is { } network)
            {
                AddTop(_networks, new SourceKey(minute, network, kind), ref _networkCells);
            }

            if (country is not null)
            {
                AddTop(_countries, new SourceKey(minute, country, kind), ref _countryCells);
            }
        }

        if (destination is not null && TrafficClassifier.OutcomeOf(kind) == TrafficOutcome.Bad)
        {
            var minute = second - (second % 60);
            if (!Increment(_destinations, new SourceKey(minute, destination, kind), ref _destinationCells, _maxSourceCells))
            {
                // A scan of many paths at once: the request is still counted, as "other".
                Increment(_destinations, new SourceKey(minute, OtherSource, kind), ref _destinationCells, int.MaxValue);
            }
        }

        return true;
    }

    /// <summary>
    /// Takes the counts of completed buckets: seconds before <paramref name="now"/>'s second, and minutes of sources
    /// that ended at least <paramref name="sourceGrace"/> ago (so slow requests that started in them are included).
    /// Everything when <paramref name="all"/> (shutdown). Sources are limited to the top <see cref="TopSources"/>
    /// per minute.
    /// </summary>
    public TrafficTake TakeCompleted(DateTimeOffset now, TimeSpan sourceGrace, bool all = false)
    {
        var second = now.ToUnixTimeSeconds();
        var counts = new List<TrafficCount>();
        foreach (var key in _counts.Keys)
        {
            if ((all || key.Second < second) && Take(_counts, key, ref _countCells) is { } value)
            {
                counts.Add(new TrafficCount(key.Second, key.Kind, key.Name, key.Route, value));
            }
        }

        var sourceCutoff = (now - sourceGrace).ToUnixTimeSeconds();
        var sources = new List<SourceCount>();
        foreach (var key in _sources.Keys)
        {
            if ((all || key.Minute + 60 <= sourceCutoff) && Take(_sources, key, ref _sourceCells) is { } value)
            {
                sources.Add(new SourceCount(key.Minute, key.Source, key.Kind, value));
            }
        }

        var destinations = new List<SourceCount>();
        foreach (var key in _destinations.Keys)
        {
            if ((all || key.Minute + 60 <= sourceCutoff) && Take(_destinations, key, ref _destinationCells) is { } value)
            {
                destinations.Add(new SourceCount(key.Minute, key.Source, key.Kind, value));
            }
        }

        var latencies = new List<LatencyCount>();
        foreach (var key in _latencies.Keys)
        {
            if ((all || key.Minute + 60 <= sourceCutoff) && Take(_latencies, key, ref _latencyCells) is { } value)
            {
                latencies.Add(new LatencyCount(key.Minute, key.Route, key.Series, key.Bin, value));
            }
        }

        var backends = new List<BackendCount>();
        foreach (var key in _backends.Keys)
        {
            if ((all || key.Minute + 60 <= sourceCutoff) && Take(_backends, key, ref _backendCells) is { } value)
            {
                backends.Add(new BackendCount(key.Minute, key.Route, key.Destination, key.Metric, value));
            }
        }

        return new TrafficTake(counts, LimitSources(sources, TopSources), LimitSources(destinations, TopSources), latencies, backends)
        {
            Networks = LimitSources(TakeTop(_networks, ref _networkCells, all, sourceCutoff), TopSources),
            Countries = LimitSources(TakeTop(_countries, ref _countryCells, all, sourceCutoff), TopSources),
        };
    }

    /// <summary>Counts a bad request in a per-minute top table; beyond the memory limit as "other".</summary>
    private void AddTop(ConcurrentDictionary<SourceKey, Cell> cells, SourceKey key, ref int size)
    {
        if (!Increment(cells, key, ref size, _maxSourceCells))
        {
            Increment(cells, key with { Source = OtherSource }, ref size, int.MaxValue);
        }
    }

    private static List<SourceCount> TakeTop(ConcurrentDictionary<SourceKey, Cell> cells, ref int size, bool all, long cutoff)
    {
        var taken = new List<SourceCount>();
        foreach (var key in cells.Keys)
        {
            if ((all || key.Minute + 60 <= cutoff) && Take(cells, key, ref size) is { } value)
            {
                taken.Add(new SourceCount(key.Minute, key.Source, key.Kind, value));
            }
        }

        return taken;
    }

    /// <summary>
    /// Keeps the <paramref name="top"/> sources with the most requests per bucket and adds up the rest as
    /// <see cref="OtherSource"/> (per kind).
    /// </summary>
    public static List<SourceCount> LimitSources(IReadOnlyCollection<SourceCount> sources, int top)
    {
        ArgumentNullException.ThrowIfNull(sources);

        var result = new List<SourceCount>();
        foreach (var bucket in sources.GroupBy(s => s.BucketStart).OrderBy(b => b.Key))
        {
            var kept = bucket
                .Where(s => s.Source != OtherSource)
                .GroupBy(s => s.Source, StringComparer.Ordinal)
                .Select(g => (Source: g.Key, Total: g.Sum(s => s.Count)))
                .OrderByDescending(s => s.Total)
                .ThenBy(s => s.Source, StringComparer.Ordinal)
                .Take(top)
                .Select(s => s.Source)
                .ToHashSet(StringComparer.Ordinal);

            result.AddRange(bucket.Where(s => kept.Contains(s.Source)).OrderBy(s => s.Source, StringComparer.Ordinal).ThenBy(s => s.Kind));
            result.AddRange(bucket
                .Where(s => !kept.Contains(s.Source))
                .GroupBy(s => s.Kind)
                .OrderBy(g => g.Key)
                .Select(g => new SourceCount(bucket.Key, OtherSource, g.Key, g.Sum(s => s.Count))));
        }

        return result;
    }

    internal static bool Increment<TKey>(ConcurrentDictionary<TKey, Cell> cells, TKey key, ref int size, int max)
        where TKey : notnull
    {
        while (true)
        {
            if (!cells.TryGetValue(key, out var cell))
            {
                if (Volatile.Read(ref size) >= max)
                {
                    return false;
                }

                cell = new Cell();
                if (!cells.TryAdd(key, cell))
                {
                    continue; // another request added it first: use that one
                }

                Interlocked.Increment(ref size);
            }

            if (Interlocked.Increment(ref cell.Value) > 0)
            {
                return true;
            }

            // Taken by the writer after we found it: count again in a new cell.
        }
    }

    internal static long? Take<TKey>(ConcurrentDictionary<TKey, Cell> cells, TKey key, ref int size)
        where TKey : notnull
    {
        if (!cells.TryRemove(key, out var cell))
        {
            return null;
        }

        Interlocked.Decrement(ref size);
        var value = Interlocked.Exchange(ref cell.Value, Taken);
        return value > 0 ? value : null;
    }

    internal sealed class Cell
    {
        public long Value;
    }

    private readonly record struct CountKey(long Second, TrafficKind Kind, string Name, string Route);

    private readonly record struct SourceKey(long Minute, string Source, TrafficKind Kind);

    private readonly record struct LatencyKey(long Minute, string Route, LatencySeries Series, int Bin);

    private readonly record struct BackendKey(long Minute, string Route, string Destination, BackendMetric Metric);
}

/// <summary>
/// Receives every public request when its response is complete, for the traffic counts. <see cref="Record"/> must
/// never block or throw: it is called on the request path.
/// </summary>
public interface IRequestMetrics
{
    /// <param name="entry">The request, as the request log sees it.</param>
    /// <param name="failed">The pipeline threw an exception.</param>
    void Record(RequestLogEntry entry, bool failed);
}

/// <summary>Current state of the traffic counts.</summary>
public interface IRequestMetricsMonitor
{
    /// <summary>The counters; null when the traffic counts are switched off.</summary>
    RequestMetricsStatistics? Statistics { get; }
}

/// <summary>Traffic counts that count nothing (switched off).</summary>
public sealed class NullRequestMetrics : IRequestMetrics, IRequestMetricsMonitor
{
    public RequestMetricsStatistics? Statistics => null;

    public void Record(RequestLogEntry entry, bool failed)
    {
    }
}

/// <summary>Counters of the traffic counts themselves, for the dashboard.</summary>
/// <param name="Counted">Requests counted since start.</param>
/// <param name="Dropped">Requests whose count was lost: too many counts waiting, or storing failed.</param>
/// <param name="Pending">Counts waiting in memory to be stored.</param>
/// <param name="LastWrite">When counts were last stored; null when not yet.</param>
/// <param name="LastError">The last storage error, if storing currently fails.</param>
public sealed record RequestMetricsStatistics(long Counted, long Dropped, int Pending, DateTimeOffset? LastWrite, string? LastError);
