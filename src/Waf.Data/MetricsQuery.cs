using System.Text;
using Microsoft.Data.Sqlite;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Data;

/// <summary>A kind of traffic to filter on, optionally one rule, attack category or rate limit of it.</summary>
/// <param name="Kind">The kind.</param>
/// <param name="Name">The rule, category or limit; null for every one of the kind.</param>
public sealed record TrafficType(TrafficKind Kind, string? Name = null)
{
    /// <summary>Text form, for addresses: "RuleBlocked" or "RuleBlocked:no-admin".</summary>
    public override string ToString() => Name is null ? Kind.ToString() : $"{Kind}:{Name}";

    /// <summary>Parses <see cref="ToString"/>; null when it is not a known kind.</summary>
    public static TrafficType? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var parts = text.Trim().Split(':', 2);
        if (!Enum.TryParse<TrafficKind>(parts[0], ignoreCase: false, out var kind) || !Enum.IsDefined(kind) || int.TryParse(parts[0], out _))
        {
            return null;
        }

        var name = parts.Length == 2 && parts[1].Length > 0 ? parts[1] : null;
        return name is { Length: > TrafficClassifier.MaxNameLength } ? null : new TrafficType(kind, name);
    }
}

/// <summary>What to read from the traffic history.</summary>
/// <param name="From">Start of the period (inclusive).</param>
/// <param name="To">End of the period (exclusive).</param>
/// <param name="Tier">Resolution to read (see <see cref="SqliteMetricsStore.ChooseTier"/>).</param>
/// <param name="Route">Only this route; null for all. Not available together with <paramref name="Sources"/>.</param>
/// <param name="Types">Only these kinds of traffic; empty for all.</param>
/// <param name="Sources">Only bad traffic from these client IPs; empty for all traffic. Sources are kept per minute and
/// coarser, without the route and the rule name, so this reads the source counts instead.</param>
/// <param name="Destinations">Only bad traffic to these destinations (host and path), like <paramref name="Sources"/>.</param>
/// <param name="Networks">Only bad traffic from these networks ("203.0.113.0/24").</param>
/// <param name="Countries">Only bad traffic from these countries (ISO codes).</param>
/// <remarks>Sources, networks, countries and destinations are separate tables: only one of them filters, in that order.</remarks>
public sealed record TrafficQuery(
    DateTimeOffset From,
    DateTimeOffset To,
    MetricsTier Tier,
    string? Route = null,
    IReadOnlyList<TrafficType>? Types = null,
    IReadOnlyList<string>? Sources = null,
    IReadOnlyList<string>? Destinations = null,
    IReadOnlyList<string>? Networks = null,
    IReadOnlyList<string>? Countries = null)
{
    public IReadOnlyList<TrafficType> TypeFilter => Types ?? [];

    public IReadOnlyList<string> SourceFilter => Sources ?? [];

    public IReadOnlyList<string> DestinationFilter => TopFilter is { Index: 1 } filter ? filter.Values : [];

    /// <summary>
    /// The per-minute table of bad traffic that filters, as its index in the top tables (0 sources, 1 destinations,
    /// 2 networks, 3 countries) and the values; null when none does.
    /// </summary>
    public (int Index, IReadOnlyList<string> Values)? TopFilter =>
        SourceFilter.Count > 0 ? (0, SourceFilter)
        : Networks is { Count: > 0 } networks ? (2, networks)
        : Countries is { Count: > 0 } countries ? (3, countries)
        : Destinations is { Count: > 0 } destinations ? (1, destinations)
        : null;

    /// <summary>Reads a per-minute table of bad traffic (sources, destinations, networks, countries) instead of the counts.</summary>
    public bool ByTop => TopFilter is not null;
}

/// <summary>One bucket of a traffic series.</summary>
/// <param name="Start">Start of the bucket, Unix seconds (UTC).</param>
/// <param name="Seconds">Length of the bucket in seconds (months differ).</param>
/// <param name="Good">Good requests in the bucket.</param>
/// <param name="Bad">Bad requests.</param>
/// <param name="Failed">Failed requests.</param>
/// <param name="Peak">Highest requests per second inside the bucket; null when unknown (with filters, or not rolled up yet).</param>
public sealed record TrafficBucket(long Start, long Seconds, long Good, long Bad, long Failed, long? Peak)
{
    public long Total => Good + Bad + Failed;

    /// <summary>Average requests per second over the bucket.</summary>
    public double PerSecond => Seconds > 0 ? (double)Total / Seconds : 0;
}

/// <summary>Requests of one kind and name over a period.</summary>
public sealed record TrafficKindTotal(TrafficKind Kind, string Name, long Count)
{
    public TrafficOutcome Outcome => TrafficClassifier.OutcomeOf(Kind);
}

/// <summary>Reading the traffic history for the Performance page.</summary>
public sealed partial class SqliteMetricsStore
{
    /// <summary>Most buckets in one chart: one hour per second, a day per minute, a week per hour.</summary>
    public const int MaxPoints = 3600;

    /// <summary>
    /// The finest tier that shows [<paramref name="from"/>, <paramref name="to"/>) in at most <see cref="MaxPoints"/>
    /// buckets and is still kept for <paramref name="from"/>; the month tier when none is.
    /// </summary>
    public static MetricsTier ChooseTier(DateTimeOffset from, DateTimeOffset to, DateTimeOffset now, MetricsRetention retention)
    {
        ArgumentNullException.ThrowIfNull(retention);

        foreach (var tier in MetricsBuckets.Tiers)
        {
            if (Buckets(tier, from, to) <= MaxPoints && now - retention.For(tier) <= from)
            {
                return tier;
            }
        }

        return MetricsTier.Month;
    }

    /// <summary>Number of buckets of <paramref name="tier"/> in the period (an estimate for months).</summary>
    public static long Buckets(MetricsTier tier, DateTimeOffset from, DateTimeOffset to)
    {
        var seconds = Math.Max(0, (to - from).TotalSeconds);
        var size = tier switch
        {
            MetricsTier.Second => 1,
            MetricsTier.Minute => 60,
            MetricsTier.Hour => 3600,
            MetricsTier.Day => 86400,
            MetricsTier.Week => 7 * 86400,
            _ => 28 * 86400,
        };
        return (long)Math.Ceiling(seconds / size);
    }

    /// <summary>
    /// The series of the query: one bucket for every bucket start in the period (empty ones too), with the peaks when
    /// no filter is set.
    /// </summary>
    public async Task<List<TrafficBucket>> ReadSeriesAsync(TrafficQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var tier = EffectiveTier(query);
        var from = MetricsBuckets.Start(tier, query.From.ToUnixTimeSeconds());
        var to = EndSeconds(query.To);
        var sums = new Dictionary<long, long[]>();
        var peaks = new Dictionary<long, long>();

        if (File.Exists(DatabasePath))
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using (var command = connection.CreateCommand())
            {
                var (table, where) = Filter(command, query, tier, from, to);
                command.CommandText = $"SELECT BucketStart, Outcome, SUM(Count) FROM {table} WHERE {where} GROUP BY BucketStart, Outcome";
                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    var outcome = reader.GetInt32(1);
                    if (outcome is >= 0 and <= 2)
                    {
                        if (!sums.TryGetValue(reader.GetInt64(0), out var row))
                        {
                            sums[reader.GetInt64(0)] = row = new long[3];
                        }

                        row[outcome] += reader.GetInt64(2);
                    }
                }
            }

            if (IsUnfiltered(query) && tier != MetricsTier.Second)
            {
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT BucketStart, Total FROM TrafficPeaks WHERE Tier = $tier AND BucketStart >= $from AND BucketStart < $to";
                command.Parameters.AddWithValue("$tier", (int)tier);
                command.Parameters.AddWithValue("$from", from);
                command.Parameters.AddWithValue("$to", to);
                await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    peaks[reader.GetInt64(0)] = reader.GetInt64(1);
                }
            }
        }

        var series = new List<TrafficBucket>();
        for (var start = from; start < to && series.Count <= MaxPoints * 2; start = MetricsBuckets.Next(tier, start))
        {
            var row = sums.GetValueOrDefault(start) ?? new long[3];
            long? peak = tier == MetricsTier.Second && IsUnfiltered(query) ? row.Sum() : peaks.TryGetValue(start, out var p) ? p : null;
            series.Add(new TrafficBucket(start, MetricsBuckets.Next(tier, start) - start, row[0], row[1], row[2], peak));
        }

        return series;
    }

    /// <summary>Requests per kind and name over the period (the type filter is not applied: this is what it chooses from).</summary>
    public async Task<List<TrafficKindTotal>> ReadKindsAsync(TrafficQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var result = new List<TrafficKindTotal>();
        if (!File.Exists(DatabasePath))
        {
            return result;
        }

        var unfiltered = query with { Types = [] };
        var tier = EffectiveTier(unfiltered);
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        var (table, where) = Filter(command, unfiltered, tier, MetricsBuckets.Start(tier, query.From.ToUnixTimeSeconds()), EndSeconds(query.To));
        var name = table == "TrafficCounts" ? "Name" : "''";
        command.CommandText = $"SELECT Kind, {name}, SUM(Count) FROM {table} WHERE {where} GROUP BY Kind, {name} ORDER BY 3 DESC";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new TrafficKindTotal((TrafficKind)reader.GetInt32(0), reader.GetString(1), reader.GetInt64(2)));
        }

        return result;
    }

    /// <summary>
    /// The sources with the most bad requests over the period, most first, with "other" left out; with the type
    /// filter (by kind) applied. Sources are kept per minute and coarser.
    /// </summary>
    public Task<List<LiveSourceCount>> ReadTopSourcesAsync(TrafficQuery query, int limit, CancellationToken cancellationToken) =>
        ReadTopAsync(query, TopTables[0], limit, cancellationToken);

    /// <summary>The requested destinations (host and path) with the most bad requests over the period, like <see cref="ReadTopSourcesAsync"/>.</summary>
    public Task<List<LiveSourceCount>> ReadTopDestinationsAsync(TrafficQuery query, int limit, CancellationToken cancellationToken) =>
        ReadTopAsync(query, TopTables[1], limit, cancellationToken);

    /// <summary>
    /// All bad requests counted in the sources (with "other") over the period, with the kind filter: what each source's
    /// share is of. Sources are stored a little after each minute, so this can be lower than the counts of the period.
    /// </summary>
    public Task<long> ReadSourceTotalAsync(TrafficQuery query, CancellationToken cancellationToken) =>
        ReadTopTotalAsync(query, TopTables[0], cancellationToken);

    /// <summary>The networks (/24, /48) with the most bad requests, like <see cref="ReadTopSourcesAsync"/>.</summary>
    public Task<List<LiveSourceCount>> ReadTopNetworksAsync(TrafficQuery query, int limit, CancellationToken cancellationToken) =>
        ReadTopAsync(query, TopTables[2], limit, cancellationToken);

    /// <summary>The countries with the most bad requests, like <see cref="ReadTopSourcesAsync"/>.</summary>
    public Task<List<LiveSourceCount>> ReadTopCountriesAsync(TrafficQuery query, int limit, CancellationToken cancellationToken) =>
        ReadTopAsync(query, TopTables[3], limit, cancellationToken);

    /// <summary>All bad requests counted in the networks (with "other").</summary>
    public Task<long> ReadNetworkTotalAsync(TrafficQuery query, CancellationToken cancellationToken) =>
        ReadTopTotalAsync(query, TopTables[2], cancellationToken);

    /// <summary>All bad requests counted in the countries (with "other"; requests whose country is unknown are not in it).</summary>
    public Task<long> ReadCountryTotalAsync(TrafficQuery query, CancellationToken cancellationToken) =>
        ReadTopTotalAsync(query, TopTables[3], cancellationToken);

    /// <summary>All bad requests counted in the destinations (with "other"), like <see cref="ReadSourceTotalAsync"/>.</summary>
    public Task<long> ReadDestinationTotalAsync(TrafficQuery query, CancellationToken cancellationToken) =>
        ReadTopTotalAsync(query, TopTables[1], cancellationToken);

    private async Task<long> ReadTopTotalAsync(TrafficQuery query, (string Table, string Column) top, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!File.Exists(DatabasePath))
        {
            return 0;
        }

        var tier = query.Tier == MetricsTier.Second ? MetricsTier.Minute : query.Tier;
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        var where = new StringBuilder("Tier = $tier AND BucketStart >= $from AND BucketStart < $to");
        command.Parameters.AddWithValue("$tier", (int)tier);
        command.Parameters.AddWithValue("$from", MetricsBuckets.Start(tier, query.From.ToUnixTimeSeconds()));
        command.Parameters.AddWithValue("$to", EndSeconds(query.To));
        AddKinds(command, where, query.TypeFilter);
        command.CommandText = $"SELECT COALESCE(SUM(Count), 0) FROM {top.Table} WHERE {where}";
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<List<LiveSourceCount>> ReadTopAsync(TrafficQuery query, (string Table, string Column) top, int limit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var result = new List<LiveSourceCount>();
        if (!File.Exists(DatabasePath))
        {
            return result;
        }

        var tier = query.Tier == MetricsTier.Second ? MetricsTier.Minute : query.Tier;
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        var where = new StringBuilder($"Tier = $tier AND BucketStart >= $from AND BucketStart < $to AND {top.Column} <> $other");
        command.Parameters.AddWithValue("$tier", (int)tier);
        command.Parameters.AddWithValue("$from", MetricsBuckets.Start(tier, query.From.ToUnixTimeSeconds()));
        command.Parameters.AddWithValue("$to", EndSeconds(query.To));
        command.Parameters.AddWithValue("$other", TrafficCounter.OtherSource);
        command.Parameters.AddWithValue("$limit", limit);
        AddKinds(command, where, query.TypeFilter);
        command.CommandText = $"SELECT {top.Column}, SUM(Count) AS Total FROM {top.Table} WHERE {where} GROUP BY {top.Column} ORDER BY Total DESC, {top.Column} LIMIT $limit";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new LiveSourceCount(reader.GetString(0), reader.GetInt64(1)));
        }

        return result;
    }

    /// <summary>The exclusive end in Unix seconds, rounded up: "until now" includes the second that is still running.</summary>
    private static long EndSeconds(DateTimeOffset to) => (to.ToUnixTimeMilliseconds() + 999) / 1000;

    private static bool IsUnfiltered(TrafficQuery query) =>
        query.Route is null && query.TypeFilter.Count == 0 && !query.ByTop;

    /// <summary>Sources and destinations are kept per minute and coarser: their filters read at least the minute tier.</summary>
    private static MetricsTier EffectiveTier(TrafficQuery query) =>
        query.ByTop && query.Tier == MetricsTier.Second ? MetricsTier.Minute : query.Tier;

    /// <summary>The table and WHERE clause of the query's filters (parameters added to <paramref name="command"/>).</summary>
    private static (string Table, string Where) Filter(SqliteCommand command, TrafficQuery query, MetricsTier tier, long from, long to)
    {
        var where = new StringBuilder("Tier = $tier AND BucketStart >= $from AND BucketStart < $to");
        command.Parameters.AddWithValue("$tier", (int)tier);
        command.Parameters.AddWithValue("$from", from);
        command.Parameters.AddWithValue("$to", to);

        if (query.ByTop)
        {
            var (index, values) = query.TopFilter!.Value;
            var (table, column) = TopTables[index];
            where.Append(" AND ").Append(column).Append(" IN (");
            for (var i = 0; i < values.Count; i++)
            {
                where.Append(i == 0 ? "$s" : ", $s").Append(i);
                command.Parameters.AddWithValue("$s" + i, values[i]);
            }

            where.Append(')');
            AddKinds(command, where, query.TypeFilter);
            return (table, where.ToString());
        }

        if (query.Route is not null)
        {
            where.Append(" AND Route = $route");
            command.Parameters.AddWithValue("$route", query.Route);
        }

        if (query.TypeFilter.Count > 0)
        {
            where.Append(" AND (");
            for (var i = 0; i < query.TypeFilter.Count; i++)
            {
                var type = query.TypeFilter[i];
                where.Append(i == 0 ? "(" : " OR (").Append("Kind = $k").Append(i);
                command.Parameters.AddWithValue("$k" + i, (int)type.Kind);
                if (type.Name is not null)
                {
                    where.Append(" AND Name = $n").Append(i);
                    command.Parameters.AddWithValue("$n" + i, type.Name);
                }

                where.Append(')');
            }

            where.Append(')');
        }

        return ("TrafficCounts", where.ToString());
    }

    /// <summary>The kinds of the type filter (sources have no names).</summary>
    private static void AddKinds(SqliteCommand command, StringBuilder where, IReadOnlyList<TrafficType> types)
    {
        var kinds = types.Select(t => (int)t.Kind).Distinct().ToList();
        if (kinds.Count == 0)
        {
            return;
        }

        where.Append(" AND Kind IN (");
        for (var i = 0; i < kinds.Count; i++)
        {
            where.Append(i == 0 ? "$kind" : ", $kind").Append(i);
            command.Parameters.AddWithValue("$kind" + i, kinds[i]);
        }

        where.Append(')');
    }
}
