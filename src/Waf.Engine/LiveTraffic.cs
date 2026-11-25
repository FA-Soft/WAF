using System.Collections.Concurrent;

namespace FASoft.Waf.Engine;

/// <summary>One second of live traffic, as sent to the dashboards.</summary>
/// <param name="Second">The second, in Unix seconds (UTC); requests are counted in the second they completed.</param>
/// <param name="Route">The route the snapshot is narrowed to; null for all traffic.</param>
/// <param name="Total">Requests completed in that second.</param>
/// <param name="Good">Of which good.</param>
/// <param name="Bad">Of which bad.</param>
/// <param name="Failed">Of which failed.</param>
/// <param name="Kinds">Requests per kind and name (rule, attack category, rate limit), most first.</param>
/// <param name="TopSources">The sources with the most bad requests in the last minute, most first.</param>
public sealed record LiveTrafficSnapshot(
    long Second, string? Route, long Total, long Good, long Bad, long Failed, IReadOnlyList<LiveKindCount> Kinds, IReadOnlyList<LiveSourceCount> TopSources);

/// <summary>Requests of one kind and name in a live snapshot.</summary>
public sealed record LiveKindCount(TrafficKind Kind, TrafficOutcome Outcome, string Name, long Count);

/// <summary>Bad requests from one source in the last minute.</summary>
public sealed record LiveSourceCount(string Source, long Count);

/// <summary>Bad requests from one source on one route within one second.</summary>
public sealed record LiveSourceHit(long Second, string Source, string Route, long Count);

/// <summary>
/// Counts requests per second for the live dashboards, but only while someone watches
/// (<see cref="AddWatcher"/>): with no dashboard open, <see cref="Record"/> returns at once and nothing is kept.
/// Adding is lock-free, like <see cref="TrafficCounter"/>.
/// </summary>
public sealed class LiveTraffic(TimeProvider time)
{
    /// <summary>Sources shown in a snapshot.</summary>
    public const int TopSources = 10;

    /// <summary>The period the top sources are counted over.</summary>
    public static readonly TimeSpan SourceWindow = TimeSpan.FromMinutes(1);

    private const int MaxCells = 20_000;
    private const int MaxSourceCells = 20_000;

    private readonly ConcurrentDictionary<CountKey, TrafficCounter.Cell> _counts = new();
    private readonly ConcurrentDictionary<SourceKey, TrafficCounter.Cell> _sources = new();
    private int _watchers;
    private int _countCells;
    private int _sourceCells;

    /// <summary>True while at least one dashboard watches.</summary>
    public bool IsWatched => Volatile.Read(ref _watchers) > 0;

    public void AddWatcher() => Interlocked.Increment(ref _watchers);

    public void RemoveWatcher()
    {
        if (Interlocked.Decrement(ref _watchers) <= 0)
        {
            Interlocked.Exchange(ref _watchers, 0);
            Clear(); // nobody watches: forget what was counted
        }
    }

    /// <summary>Counts a completed request, if someone watches. Never blocks or throws.</summary>
    public void Record(RequestLogEntry entry, bool failed)
    {
        if (!IsWatched || entry is null)
        {
            return;
        }

        var second = time.GetUtcNow().ToUnixTimeSeconds();
        var (kind, name) = TrafficClassifier.Classify(entry, failed);
        var route = TrafficClassifier.Name(entry.RouteName);
        TrafficCounter.Increment(_counts, new CountKey(second, kind, name, route), ref _countCells, MaxCells);
        if (TrafficClassifier.OutcomeOf(kind) == TrafficOutcome.Bad
            && !TrafficCounter.Increment(_sources, new SourceKey(second, entry.ClientIp, route), ref _sourceCells, MaxSourceCells))
        {
            TrafficCounter.Increment(_sources, new SourceKey(second, TrafficCounter.OtherSource, route), ref _sourceCells, int.MaxValue);
        }
    }

    /// <summary>Takes the counts of the seconds before <paramref name="beforeSecond"/>.</summary>
    public (List<TrafficCount> Counts, List<LiveSourceHit> Sources) TakeCompleted(long beforeSecond)
    {
        var counts = new List<TrafficCount>();
        foreach (var key in _counts.Keys)
        {
            if (key.Second < beforeSecond && TrafficCounter.Take(_counts, key, ref _countCells) is { } value)
            {
                counts.Add(new TrafficCount(key.Second, key.Kind, key.Name, key.Route, value));
            }
        }

        var sources = new List<LiveSourceHit>();
        foreach (var key in _sources.Keys)
        {
            if (key.Second < beforeSecond && TrafficCounter.Take(_sources, key, ref _sourceCells) is { } value)
            {
                sources.Add(new LiveSourceHit(key.Second, key.Source, key.Route, value));
            }
        }

        return (counts, sources);
    }

    /// <summary>
    /// The snapshot of <paramref name="second"/>, from that second's <paramref name="counts"/> and the
    /// <paramref name="sources"/> of the last minute; narrowed to <paramref name="route"/> unless it is null.
    /// </summary>
    public static LiveTrafficSnapshot Build(long second, string? route, IEnumerable<TrafficCount> counts, IEnumerable<LiveSourceHit> sources)
    {
        ArgumentNullException.ThrowIfNull(counts);
        ArgumentNullException.ThrowIfNull(sources);

        var mine = counts.Where(c => c.BucketStart == second && (route is null || c.Route == route)).ToList();
        long Sum(TrafficOutcome outcome) => mine.Where(c => c.Outcome == outcome).Sum(c => c.Count);

        var kinds = mine
            .GroupBy(c => (c.Kind, c.Name))
            .Select(g => new LiveKindCount(g.Key.Kind, TrafficClassifier.OutcomeOf(g.Key.Kind), g.Key.Name, g.Sum(c => c.Count)))
            .OrderByDescending(k => k.Count)
            .ThenBy(k => k.Kind)
            .ThenBy(k => k.Name, StringComparer.Ordinal)
            .ToList();

        var top = sources
            .Where(s => s.Second > second - (long)SourceWindow.TotalSeconds && s.Second <= second && (route is null || s.Route == route))
            .GroupBy(s => s.Source, StringComparer.Ordinal)
            .Select(g => new LiveSourceCount(g.Key, g.Sum(s => s.Count)))
            .Where(s => s.Source != TrafficCounter.OtherSource)
            .OrderByDescending(s => s.Count)
            .ThenBy(s => s.Source, StringComparer.Ordinal)
            .Take(TopSources)
            .ToList();

        return new LiveTrafficSnapshot(second, route, mine.Sum(c => c.Count), Sum(TrafficOutcome.Good), Sum(TrafficOutcome.Bad), Sum(TrafficOutcome.Failed), kinds, top);
    }

    private void Clear()
    {
        foreach (var key in _counts.Keys)
        {
            TrafficCounter.Take(_counts, key, ref _countCells);
        }

        foreach (var key in _sources.Keys)
        {
            TrafficCounter.Take(_sources, key, ref _sourceCells);
        }
    }

    private readonly record struct CountKey(long Second, TrafficKind Kind, string Name, string Route);

    private readonly record struct SourceKey(long Second, string Source, string Route);
}
