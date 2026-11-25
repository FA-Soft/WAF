using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Data;

/// <summary>Response time percentiles of one bucket, in milliseconds; null when no request was forwarded in it.</summary>
/// <param name="Start">Start of the bucket, Unix seconds (UTC).</param>
/// <param name="Seconds">Length of the bucket.</param>
/// <param name="Requests">Forwarded requests in the bucket.</param>
/// <param name="P50">Median response time.</param>
/// <param name="P95">95th percentile.</param>
/// <param name="P99">99th percentile.</param>
/// <param name="GatewayP50">Median of what the gateway itself added (null when the backend's time is not known).</param>
/// <param name="GatewayP95">95th percentile of what the gateway added.</param>
public sealed record LatencyPoint(long Start, long Seconds, long Requests, double? P50, double? P95, double? P99, double? GatewayP50, double? GatewayP95);

/// <summary>Response times over a whole period, in milliseconds.</summary>
public sealed record LatencySummary(long Requests, double? P50, double? P95, double? P99, double? BackendP50, double? GatewayP50, double? GatewayP95);

/// <summary>What one backend of one route did over a period.</summary>
/// <param name="Route">The route.</param>
/// <param name="Destination">The backend as the request log shows it; empty for requests that found no backend.</param>
/// <param name="Counts">Requests per result.</param>
public sealed record BackendSummary(string Route, string Destination, IReadOnlyDictionary<BackendMetric, long> Counts)
{
    public long Get(BackendMetric metric) => Counts.GetValueOrDefault(metric);

    /// <summary>Requests the backend answered.</summary>
    public long Answered => Get(BackendMetric.Status2xx) + Get(BackendMetric.Status3xx) + Get(BackendMetric.Status4xx) + Get(BackendMetric.Status5xx);

    /// <summary>Requests that got 502, 503 or 504 from the gateway because the backend did not answer.</summary>
    public long Errors => Get(BackendMetric.BackendError) + Get(BackendMetric.NoBackend) + Get(BackendMetric.BackendTimeout);

    public long Total => Answered + Errors;
}

/// <summary>A period in which a route ran on a failover destination.</summary>
/// <param name="End">When the route was back on its primaries; null while it still runs on the failover.</param>
public sealed record FailoverPeriod(string Route, int Failover, string Destinations, DateTimeOffset Start, DateTimeOffset? End);

/// <summary>Response times, backends and failover periods in <c>metrics.db</c>.</summary>
/// <remarks>
/// <c>LatencyCounts(Tier, BucketStart, Route, Series, Bin, Count)</c>: a response time histogram per bucket
/// (<see cref="LatencyHistogram"/>), per minute and coarser. <c>BackendCounts(Tier, BucketStart, Route, Destination,
/// Metric, Count)</c>: what each backend did, per minute and coarser. Both are rolled up by summing.
/// <c>FailoverPeriods(Route, Start, Failover, Destinations, End)</c>: kept as long as the month tier.
/// </remarks>
public sealed partial class SqliteMetricsStore
{
    private static async Task WriteResponsesAsync(
        SqliteConnection connection, SqliteTransaction transaction, List<LatencyCount> latencies, List<BackendCount> backends, CancellationToken cancellationToken)
    {
        if (latencies.Count > 0)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO LatencyCounts (Tier, BucketStart, Route, Series, Bin, Count) VALUES ($tier, $bucket, $route, $series, $bin, $count)
                ON CONFLICT (Tier, BucketStart, Route, Series, Bin) DO UPDATE SET Count = Count + excluded.Count
                """;
            var bucket = command.Parameters.Add("$bucket", SqliteType.Integer);
            var route = command.Parameters.Add("$route", SqliteType.Text);
            var series = command.Parameters.Add("$series", SqliteType.Integer);
            var bin = command.Parameters.Add("$bin", SqliteType.Integer);
            var count = command.Parameters.Add("$count", SqliteType.Integer);
            command.Parameters.AddWithValue("$tier", (int)MetricsTier.Minute);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            foreach (var item in latencies)
            {
                bucket.Value = item.BucketStart;
                route.Value = item.Route;
                series.Value = (int)item.Series;
                bin.Value = item.Bin;
                count.Value = item.Count;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        if (backends.Count > 0)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO BackendCounts (Tier, BucketStart, Route, Destination, Metric, Count) VALUES ($tier, $bucket, $route, $destination, $metric, $count)
                ON CONFLICT (Tier, BucketStart, Route, Destination, Metric) DO UPDATE SET Count = Count + excluded.Count
                """;
            var bucket = command.Parameters.Add("$bucket", SqliteType.Integer);
            var route = command.Parameters.Add("$route", SqliteType.Text);
            var destination = command.Parameters.Add("$destination", SqliteType.Text);
            var metric = command.Parameters.Add("$metric", SqliteType.Integer);
            var count = command.Parameters.Add("$count", SqliteType.Integer);
            command.Parameters.AddWithValue("$tier", (int)MetricsTier.Minute);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            foreach (var item in backends)
            {
                bucket.Value = item.BucketStart;
                route.Value = item.Route;
                destination.Value = item.Destination;
                metric.Value = (int)item.Metric;
                count.Value = item.Count;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Rolls up the response times and the backends into a coarser tier (sums; nothing is limited).</summary>
    private static string ResponseRollupSql(string bucket, string range) => $"""
        DELETE FROM LatencyCounts WHERE Tier = $tier AND {range};
        INSERT INTO LatencyCounts (Tier, BucketStart, Route, Series, Bin, Count)
            SELECT $tier, {bucket}, Route, Series, Bin, SUM(Count) FROM LatencyCounts
            WHERE Tier = $finer AND {range}
            GROUP BY {bucket}, Route, Series, Bin;
        DELETE FROM BackendCounts WHERE Tier = $tier AND {range};
        INSERT INTO BackendCounts (Tier, BucketStart, Route, Destination, Metric, Count)
            SELECT $tier, {bucket}, Route, Destination, Metric, SUM(Count) FROM BackendCounts
            WHERE Tier = $finer AND {range}
            GROUP BY {bucket}, Route, Destination, Metric;

        """;

    public async Task RecordFailoversAsync(IReadOnlyList<RouteFailoverStatus> current, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(current);

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var open = new List<(string Route, long Start)>();
        await using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT Route, Start FROM FailoverPeriods WHERE End IS NULL";
            await using var reader = await read.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                open.Add((reader.GetString(0), reader.GetInt64(1)));
            }
        }

        var wanted = current.ToDictionary(s => TrafficClassifier.Name(s.RouteName), StringComparer.Ordinal);
        var toClose = open.Where(o => !wanted.TryGetValue(o.Route, out var status) || status.Since.ToUnixTimeSeconds() != o.Start).ToList();
        var toOpen = wanted.Values.Where(s => !open.Contains((TrafficClassifier.Name(s.RouteName), s.Since.ToUnixTimeSeconds()))).ToList();
        if (toClose.Count == 0 && toOpen.Count == 0)
        {
            return; // nothing changed: no write
        }

        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        foreach (var (route, start) in toClose)
        {
            await using var close = connection.CreateCommand();
            close.Transaction = transaction;
            close.CommandText = "UPDATE FailoverPeriods SET End = $end WHERE Route = $route AND Start = $start";
            // A route that switched to another failover ends one period where the next starts.
            var end = wanted.TryGetValue(route, out var next) && next.Since.ToUnixTimeSeconds() > start ? next.Since.ToUnixTimeSeconds() : now.ToUnixTimeSeconds();
            close.Parameters.AddWithValue("$end", Math.Max(end, start));
            close.Parameters.AddWithValue("$route", route);
            close.Parameters.AddWithValue("$start", start);
            await close.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        foreach (var status in toOpen)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO FailoverPeriods (Route, Start, Failover, Destinations, End) VALUES ($route, $start, $failover, $destinations, NULL)
                ON CONFLICT (Route, Start) DO UPDATE SET End = NULL, Failover = excluded.Failover, Destinations = excluded.Destinations
                """;
            insert.Parameters.AddWithValue("$route", TrafficClassifier.Name(status.RouteName));
            insert.Parameters.AddWithValue("$start", status.Since.ToUnixTimeSeconds());
            insert.Parameters.AddWithValue("$failover", status.Failover);
            insert.Parameters.AddWithValue("$destinations", status.Destinations.Length <= TrafficClassifier.MaxDestinationLength ? status.Destinations : status.Destinations[..TrafficClassifier.MaxDestinationLength]);
            await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Removes failover periods that ended before <paramref name="cutoff"/>.</summary>
    private static async Task<long> DeleteOldFailoversAsync(SqliteConnection connection, DateTimeOffset cutoff, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM FailoverPeriods WHERE End IS NOT NULL AND End < $cutoff";
        command.Parameters.AddWithValue("$cutoff", cutoff.ToUnixTimeSeconds());
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Response times are kept per minute and coarser.</summary>
    private static MetricsTier ResponseTier(MetricsTier tier) => tier == MetricsTier.Second ? MetricsTier.Minute : tier;

    /// <summary>
    /// The response time percentiles per bucket (every bucket of the period, empty ones too) and over the whole
    /// period, of the query's route (other filters do not apply: response times are kept per route only).
    /// </summary>
    public async Task<(List<LatencyPoint> Series, LatencySummary Summary)> ReadLatencyAsync(TrafficQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var tier = ResponseTier(query.Tier);
        var from = MetricsBuckets.Start(tier, query.From.ToUnixTimeSeconds());
        var to = EndSeconds(query.To);
        // [bucket][series][bin]
        var histograms = new Dictionary<long, long[][]>();
        var whole = NewHistograms();

        if (File.Exists(DatabasePath))
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            var where = new StringBuilder("Tier = $tier AND BucketStart >= $from AND BucketStart < $to");
            command.Parameters.AddWithValue("$tier", (int)tier);
            command.Parameters.AddWithValue("$from", from);
            command.Parameters.AddWithValue("$to", to);
            if (query.Route is not null)
            {
                where.Append(" AND Route = $route");
                command.Parameters.AddWithValue("$route", query.Route);
            }

            command.CommandText = $"SELECT BucketStart, Series, Bin, SUM(Count) FROM LatencyCounts WHERE {where} GROUP BY BucketStart, Series, Bin";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var (series, bin, count) = (reader.GetInt32(1), reader.GetInt32(2), reader.GetInt64(3));
                if (series is < 0 or > 2 || bin is < 0 or >= LatencyHistogram.Bins)
                {
                    continue;
                }

                if (!histograms.TryGetValue(reader.GetInt64(0), out var bucket))
                {
                    histograms[reader.GetInt64(0)] = bucket = NewHistograms();
                }

                bucket[series][bin] += count;
                whole[series][bin] += count;
            }
        }

        var points = new List<LatencyPoint>();
        for (var start = from; start < to && points.Count <= MaxPoints * 2; start = MetricsBuckets.Next(tier, start))
        {
            var h = histograms.GetValueOrDefault(start) ?? NewHistograms();
            points.Add(new LatencyPoint(
                start,
                MetricsBuckets.Next(tier, start) - start,
                h[(int)LatencySeries.Total].Sum(),
                LatencyHistogram.Percentile(h[(int)LatencySeries.Total], 0.50),
                LatencyHistogram.Percentile(h[(int)LatencySeries.Total], 0.95),
                LatencyHistogram.Percentile(h[(int)LatencySeries.Total], 0.99),
                LatencyHistogram.Percentile(h[(int)LatencySeries.Gateway], 0.50),
                LatencyHistogram.Percentile(h[(int)LatencySeries.Gateway], 0.95)));
        }

        var summary = new LatencySummary(
            whole[(int)LatencySeries.Total].Sum(),
            LatencyHistogram.Percentile(whole[(int)LatencySeries.Total], 0.50),
            LatencyHistogram.Percentile(whole[(int)LatencySeries.Total], 0.95),
            LatencyHistogram.Percentile(whole[(int)LatencySeries.Total], 0.99),
            LatencyHistogram.Percentile(whole[(int)LatencySeries.Backend], 0.50),
            LatencyHistogram.Percentile(whole[(int)LatencySeries.Gateway], 0.50),
            LatencyHistogram.Percentile(whole[(int)LatencySeries.Gateway], 0.95));
        return (points, summary);

        static long[][] NewHistograms() => [new long[LatencyHistogram.Bins], new long[LatencyHistogram.Bins], new long[LatencyHistogram.Bins]];
    }

    /// <summary>What every backend did over the period, per route (or of the query's route), most requests first.</summary>
    public async Task<List<BackendSummary>> ReadBackendsAsync(TrafficQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var rows = new Dictionary<(string Route, string Destination), Dictionary<BackendMetric, long>>();
        if (File.Exists(DatabasePath))
        {
            var tier = ResponseTier(query.Tier);
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            var where = new StringBuilder("Tier = $tier AND BucketStart >= $from AND BucketStart < $to");
            command.Parameters.AddWithValue("$tier", (int)tier);
            command.Parameters.AddWithValue("$from", MetricsBuckets.Start(tier, query.From.ToUnixTimeSeconds()));
            command.Parameters.AddWithValue("$to", EndSeconds(query.To));
            if (query.Route is not null)
            {
                where.Append(" AND Route = $route");
                command.Parameters.AddWithValue("$route", query.Route);
            }

            command.CommandText = $"SELECT Route, Destination, Metric, SUM(Count) FROM BackendCounts WHERE {where} GROUP BY Route, Destination, Metric";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var key = (reader.GetString(0), reader.GetString(1));
                if (!rows.TryGetValue(key, out var counts))
                {
                    rows[key] = counts = [];
                }

                counts[(BackendMetric)reader.GetInt32(2)] = reader.GetInt64(3);
            }
        }

        return [.. rows
            .Select(r => new BackendSummary(r.Key.Route, r.Key.Destination, r.Value))
            .OrderBy(b => b.Route, StringComparer.OrdinalIgnoreCase)
            .ThenByDescending(b => b.Total)
            .ThenBy(b => b.Destination, StringComparer.Ordinal)];
    }

    /// <summary>The failover periods that overlap [<paramref name="from"/>, <paramref name="to"/>), of one route or all.</summary>
    public async Task<List<FailoverPeriod>> ReadFailoversAsync(DateTimeOffset from, DateTimeOffset to, string? route, CancellationToken cancellationToken)
    {
        var result = new List<FailoverPeriod>();
        if (!File.Exists(DatabasePath))
        {
            return result;
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Route, Failover, Destinations, Start, End FROM FailoverPeriods
            WHERE Start < $to AND (End IS NULL OR End > $from) AND ($route IS NULL OR Route = $route)
            ORDER BY Start, Route
            """;
        command.Parameters.AddWithValue("$from", from.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$to", EndSeconds(to));
        command.Parameters.AddWithValue("$route", (object?)route ?? DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new FailoverPeriod(
                reader.GetString(0),
                reader.GetInt32(1),
                reader.GetString(2),
                DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(3)),
                reader.IsDBNull(4) ? null : DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(4))));
        }

        return result;
    }
}
