using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.Sqlite;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Data;

/// <summary>
/// How long each tier of the traffic counts is kept, bound from <c>Gateway:Metrics:Retention</c> (host settings).
/// Older buckets are removed once the next coarser tier holds them.
/// </summary>
public sealed class MetricsRetention
{
    /// <summary>Longest time any tier may be kept: ten years.</summary>
    public static readonly TimeSpan MaxKeep = TimeSpan.FromDays(3653);

    /// <summary>Shortest time any tier may be kept: one hour.</summary>
    public static readonly TimeSpan MinKeep = TimeSpan.FromHours(1);

    /// <summary>Counts per second: 3 days.</summary>
    public TimeSpan Second { get; set; } = TimeSpan.FromDays(3);

    /// <summary>Counts and sources per minute: 1 week.</summary>
    public TimeSpan Minute { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Per hour: 4 weeks.</summary>
    public TimeSpan Hour { get; set; } = TimeSpan.FromDays(28);

    /// <summary>Per day: 3 months.</summary>
    public TimeSpan Day { get; set; } = TimeSpan.FromDays(92);

    /// <summary>Per week: 1 year.</summary>
    public TimeSpan Week { get; set; } = TimeSpan.FromDays(366);

    /// <summary>Per month: 3 years. Nothing is kept longer.</summary>
    public TimeSpan Month { get; set; } = TimeSpan.FromDays(1096);

    public TimeSpan For(MetricsTier tier) => tier switch
    {
        MetricsTier.Second => Second,
        MetricsTier.Minute => Minute,
        MetricsTier.Hour => Hour,
        MetricsTier.Day => Day,
        MetricsTier.Week => Week,
        MetricsTier.Month => Month,
        _ => throw new ArgumentOutOfRangeException(nameof(tier)),
    };

    /// <param name="sectionName">Settings section, for the messages (e.g. <c>Gateway:Metrics:Retention</c>).</param>
    public IReadOnlyList<string> Validate(string sectionName)
    {
        var errors = new List<string>();
        MetricsTier? previous = null;
        foreach (var tier in MetricsBuckets.Tiers)
        {
            var keep = For(tier);
            if (keep < MinKeep || keep > MaxKeep)
            {
                errors.Add($"{sectionName}:{tier} must be between {MinKeep} and {MaxKeep.TotalDays:0} days (is {keep}).");
            }
            else if (previous is { } finer && keep < For(finer))
            {
                errors.Add($"{sectionName}:{tier} must be at least as long as {sectionName}:{finer} (a coarser tier is kept at least as long as a finer one).");
            }

            previous = tier;
        }

        return errors;
    }
}

/// <summary>Outcome of one rollup and retention run of the traffic counts.</summary>
/// <param name="FinishedAt">When the run finished.</param>
/// <param name="RolledUp">Rows written to coarser tiers.</param>
/// <param name="Deleted">Rows removed because they were older than their tier's retention.</param>
/// <param name="Duration">How long the run took.</param>
/// <param name="Error">Why the run failed; null when it succeeded.</param>
public sealed record MetricsMaintenanceResult(DateTimeOffset FinishedAt, long RolledUp, long Deleted, TimeSpan Duration, string? Error = null);

/// <summary>What one tier of the traffic counts holds.</summary>
/// <param name="Tier">The tier.</param>
/// <param name="KeptFor">How long its buckets are kept.</param>
/// <param name="Oldest">Start of its oldest stored bucket; null when it is empty.</param>
/// <param name="Newest">Start of its newest stored bucket; null when it is empty.</param>
public sealed record MetricsTierStatus(MetricsTier Tier, TimeSpan KeptFor, DateTimeOffset? Oldest, DateTimeOffset? Newest);

/// <summary>Size and contents of <c>metrics.db</c>.</summary>
/// <param name="FileBytes">Size on disk, with the write-ahead log.</param>
/// <param name="Tiers">Each tier, from fine to coarse.</param>
public sealed record MetricsStorageStatus(long FileBytes, IReadOnlyList<MetricsTierStatus> Tiers);

/// <summary>Highest requests per second inside one bucket, in total and per group.</summary>
public sealed record TrafficPeak(long BucketStart, long Total, long Good, long Bad, long Failed);

/// <summary>Rollups and retention of <c>metrics.db</c>.</summary>
/// <remarks>
/// <para>
/// Each tier is made from the next finer one (<see cref="MetricsBuckets.FinerOf"/>) once its buckets are complete:
/// a bucket is rolled up <see cref="SettleDelay"/> after it ended, when the writer has stored everything counted in
/// it. <c>RollupState.DoneUntil</c> is how far a tier is rolled up; a run continues from there, so it is idempotent
/// and catches up after the gateway was off. A rolled-up range is replaced as a whole (delete, then insert the sums),
/// so running it again gives the same result.
/// </para>
/// <para>
/// A slow request is counted in the second it arrived, so it can be stored after its bucket was rolled up. The
/// writer then moves <c>DoneUntil</c> of every coarser tier back to that bucket (<see cref="ReopenRollupsAsync"/>),
/// and the next run rolls it up again. Rows of a tier are removed only when they are older than the tier's retention
/// and every coarser tier made from it has rolled them up; <c>RollupState.DeletedBefore</c> records that, so a tier is
/// never rolled up again from rows that are gone.
/// </para>
/// </remarks>
public sealed partial class SqliteMetricsStore
{
    /// <summary>
    /// How long after a bucket ended it is rolled up: longer than the writer's longest flush interval plus the
    /// sources' grace period, so the bucket is complete.
    /// </summary>
    public static readonly TimeSpan SettleDelay = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Rolls up every completed bucket and removes rows beyond their tier's retention, as of <paramref name="now"/>.
    /// Each tier is rolled up in its own transaction.
    /// </summary>
    public async Task<MetricsMaintenanceResult> MaintainAsync(MetricsRetention retention, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(retention);

        var stopwatch = Stopwatch.StartNew();
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "PRAGMA synchronous=NORMAL;", cancellationToken).ConfigureAwait(false);
        var state = await ReadStateAsync(connection, cancellationToken).ConfigureAwait(false);
        var settled = (now - SettleDelay).ToUnixTimeSeconds();

        long rolledUp = 0;
        foreach (var tier in MetricsBuckets.Tiers)
        {
            if (MetricsBuckets.FinerOf(tier) is not { } finer)
            {
                continue;
            }

            var limit = finer == MetricsTier.Second ? settled : Math.Min(settled, state[finer].DoneUntil);
            var to = MetricsBuckets.Start(tier, limit);
            var from = Math.Max(state[tier].DoneUntil, MetricsBuckets.Ceiling(tier, state[finer].DeletedBefore));
            if (to <= from)
            {
                continue;
            }

            rolledUp += await RollUpAsync(connection, tier, finer, from, to, cancellationToken).ConfigureAwait(false);
            state[tier] = state[tier] with { DoneUntil = to };
        }

        long deleted = 0;
        foreach (var tier in MetricsBuckets.Tiers)
        {
            var cutoff = MetricsBuckets.Start(tier, (now - retention.For(tier)).ToUnixTimeSeconds());
            foreach (var coarser in MetricsBuckets.CoarserOf(tier))
            {
                cutoff = Math.Min(cutoff, state[coarser].DoneUntil);
            }

            deleted += await DeleteBeforeAsync(connection, tier, cutoff, Math.Max(cutoff, state[tier].DeletedBefore), cancellationToken).ConfigureAwait(false);
            state[tier] = state[tier] with { DeletedBefore = Math.Max(cutoff, state[tier].DeletedBefore) };
        }

        deleted += await DeleteOldFailoversAsync(connection, now - retention.Month, cancellationToken).ConfigureAwait(false);

        if (deleted > 0)
        {
            await GiveSpaceBackAsync(connection, cancellationToken).ConfigureAwait(false);
        }

        return new MetricsMaintenanceResult(now, rolledUp, deleted, stopwatch.Elapsed);
    }

    /// <summary>Size of the database and the stored range of each tier.</summary>
    public async Task<MetricsStorageStatus> GetStatusAsync(MetricsRetention retention, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(retention);

        var bytes = FileSize(DatabasePath) + FileSize(DatabasePath + "-wal");
        var tiers = new List<MetricsTierStatus>();
        if (!File.Exists(DatabasePath))
        {
            return new MetricsStorageStatus(0, [.. MetricsBuckets.Tiers.Select(t => new MetricsTierStatus(t, retention.For(t), null, null))]);
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        foreach (var tier in MetricsBuckets.Tiers)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT MIN(BucketStart), MAX(BucketStart) FROM TrafficCounts WHERE Tier = $tier";
            command.Parameters.AddWithValue("$tier", (int)tier);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            tiers.Add(new MetricsTierStatus(
                tier,
                retention.For(tier),
                reader.IsDBNull(0) ? null : DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(0)),
                reader.IsDBNull(1) ? null : DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(1))));
        }

        return new MetricsStorageStatus(bytes, tiers);
    }

    /// <summary>Stored peaks of <paramref name="tier"/> with a bucket start in [<paramref name="from"/>, <paramref name="to"/>).</summary>
    public async Task<List<TrafficPeak>> ReadPeaksAsync(MetricsTier tier, DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT BucketStart, Total, Good, Bad, Failed FROM TrafficPeaks
            WHERE Tier = $tier AND BucketStart >= $from AND BucketStart < $to
            ORDER BY BucketStart
            """;
        command.Parameters.AddWithValue("$tier", (int)tier);
        command.Parameters.AddWithValue("$from", from.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$to", to.ToUnixTimeSeconds());
        var result = new List<TrafficPeak>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new TrafficPeak(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3), reader.GetInt64(4)));
        }

        return result;
    }

    /// <summary>The SQL expression for the start of the <paramref name="tier"/> bucket that holds <paramref name="column"/> (as <see cref="MetricsBuckets.Start"/>).</summary>
    public static string BucketSql(MetricsTier tier, string column) => tier switch
    {
        MetricsTier.Second => column,
        MetricsTier.Minute => $"({column} - {column} % 60)",
        MetricsTier.Hour => $"({column} - {column} % 3600)",
        MetricsTier.Day => $"({column} - {column} % 86400)",
        MetricsTier.Week => $"({column} - ({column} + 259200) % 604800)",
        MetricsTier.Month => $"CAST(strftime('%s', {column}, 'unixepoch', 'start of month') AS INTEGER)",
        _ => throw new ArgumentOutOfRangeException(nameof(tier)),
    };

    private static async Task<long> RollUpAsync(SqliteConnection connection, MetricsTier tier, MetricsTier finer, long from, long to, CancellationToken cancellationToken)
    {
        var bucket = BucketSql(tier, "BucketStart");
        var range = "BucketStart >= $from AND BucketStart < $to";
        var sql = $"""
            DELETE FROM TrafficCounts WHERE Tier = $tier AND {range};
            INSERT INTO TrafficCounts (Tier, BucketStart, Kind, Name, Route, Outcome, Count)
                SELECT $tier, {bucket}, Kind, Name, Route, Outcome, SUM(Count) FROM TrafficCounts
                WHERE Tier = $finer AND {range}
                GROUP BY {bucket}, Kind, Name, Route;
            DELETE FROM TrafficPeaks WHERE Tier = $tier AND {range};
            """;

        sql += finer == MetricsTier.Second
            ? $"""
                INSERT INTO TrafficPeaks (Tier, BucketStart, Total, Good, Bad, Failed)
                    SELECT $tier, {bucket}, MAX(Total), MAX(Good), MAX(Bad), MAX(Failed) FROM (
                        SELECT BucketStart, SUM(Count) AS Total,
                            SUM(CASE WHEN Outcome = 0 THEN Count ELSE 0 END) AS Good,
                            SUM(CASE WHEN Outcome = 1 THEN Count ELSE 0 END) AS Bad,
                            SUM(CASE WHEN Outcome = 2 THEN Count ELSE 0 END) AS Failed
                        FROM TrafficCounts WHERE Tier = $finer AND {range} GROUP BY BucketStart)
                    GROUP BY {bucket};
                """
            : $"""
                INSERT INTO TrafficPeaks (Tier, BucketStart, Total, Good, Bad, Failed)
                    SELECT $tier, {bucket}, MAX(Total), MAX(Good), MAX(Bad), MAX(Failed) FROM TrafficPeaks
                    WHERE Tier = $finer AND {range}
                    GROUP BY {bucket};
                """ + string.Concat(TopTables.Select(t => TopRollupSql(t.Table, t.Column, bucket, range))) + ResponseRollupSql(bucket, range);

        sql += """
            INSERT INTO RollupState (Tier, DoneUntil, DeletedBefore) VALUES ($tier, $to, 0)
                ON CONFLICT (Tier) DO UPDATE SET DoneUntil = excluded.DoneUntil;
            """;

        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$tier", (int)tier);
        command.Parameters.AddWithValue("$finer", (int)finer);
        command.Parameters.AddWithValue("$from", from);
        command.Parameters.AddWithValue("$to", to);
        command.Parameters.AddWithValue("$other", TrafficCounter.OtherSource);
        command.Parameters.AddWithValue("$top", TrafficCounter.TopSources);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

        // Rows written: what the tier holds now in the rolled-up range.
        await using var count = connection.CreateCommand();
        count.CommandText = $"SELECT (SELECT COUNT(*) FROM TrafficCounts WHERE Tier = $tier AND {range}) + (SELECT COUNT(*) FROM SourceCounts WHERE Tier = $tier AND {range})";
        count.Parameters.AddWithValue("$tier", (int)tier);
        count.Parameters.AddWithValue("$from", from);
        count.Parameters.AddWithValue("$to", to);
        return Convert.ToInt64(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Rolls up a per-minute table of bad traffic (sources or destinations) into a coarser tier: the top
    /// <see cref="TrafficCounter.TopSources"/> values per bucket by their total, the rest added up as "other".
    /// </summary>
    private static string TopRollupSql(string table, string column, string bucket, string range) => $"""
        DELETE FROM {table} WHERE Tier = $tier AND {range};
        WITH agg AS (
                SELECT {bucket} AS B, {column} AS V, Kind, Outcome, SUM(Count) AS C FROM {table}
                WHERE Tier = $finer AND {range}
                GROUP BY {bucket}, {column}, Kind),
            totals AS (SELECT B, V, SUM(C) AS T FROM agg WHERE V <> $other GROUP BY B, V),
            ranked AS (SELECT B, V, ROW_NUMBER() OVER (PARTITION BY B ORDER BY T DESC, V) AS R FROM totals)
        INSERT INTO {table} (Tier, BucketStart, {column}, Kind, Outcome, Count)
            SELECT $tier, a.B, CASE WHEN r.R <= $top THEN a.V ELSE $other END, a.Kind, a.Outcome, SUM(a.C)
            FROM agg a LEFT JOIN ranked r ON r.B = a.B AND r.V = a.V
            GROUP BY a.B, CASE WHEN r.R <= $top THEN a.V ELSE $other END, a.Kind;

        """;

    private static async Task<long> DeleteBeforeAsync(SqliteConnection connection, MetricsTier tier, long cutoff, long deletedBefore, CancellationToken cancellationToken)
    {
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        long deleted = 0;
        foreach (var table in new[] { "TrafficCounts", "SourceCounts", "DestinationCounts", "LatencyCounts", "BackendCounts", "TrafficPeaks" })
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"DELETE FROM {table} WHERE Tier = $tier AND BucketStart < $cutoff";
            command.Parameters.AddWithValue("$tier", (int)tier);
            command.Parameters.AddWithValue("$cutoff", cutoff);
            deleted += await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await using (var state = connection.CreateCommand())
        {
            state.Transaction = transaction;
            state.CommandText = """
                INSERT INTO RollupState (Tier, DoneUntil, DeletedBefore) VALUES ($tier, 0, $deleted)
                    ON CONFLICT (Tier) DO UPDATE SET DeletedBefore = excluded.DeletedBefore
                    WHERE DeletedBefore <> excluded.DeletedBefore
                """;
            state.Parameters.AddWithValue("$tier", (int)tier);
            state.Parameters.AddWithValue("$deleted", deletedBefore);
            await state.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return deleted;
    }

    /// <summary>
    /// Moves <c>DoneUntil</c> of every tier back to the bucket of the oldest count or source just written, so a bucket
    /// that was rolled up already is rolled up again with the late count. Normally nothing changes: the writer stores
    /// seconds that ended a moment ago, long after the last rollup's settle delay.
    /// </summary>
    private static async Task ReopenRollupsAsync(
        SqliteConnection connection, SqliteTransaction transaction, List<TrafficCount> counts, IEnumerable<long> minutes, CancellationToken cancellationToken)
    {
        long? oldestCount = counts.Count == 0 ? null : counts.Min(c => c.BucketStart);
        long? oldestSource = minutes.Any() ? minutes.Min() : null;

        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE RollupState SET DoneUntil = $start WHERE Tier = $tier AND DoneUntil > $start";
        var tierParameter = command.Parameters.Add("$tier", SqliteType.Integer);
        var startParameter = command.Parameters.Add("$start", SqliteType.Integer);
        foreach (var tier in MetricsBuckets.Tiers.Where(t => t != MetricsTier.Second))
        {
            long? start = oldestCount is { } second ? MetricsBuckets.Start(tier, second) : null;
            if (tier != MetricsTier.Minute && oldestSource is { } minute)
            {
                var sourceStart = MetricsBuckets.Start(tier, minute);
                start = start is { } s ? Math.Min(s, sourceStart) : sourceStart;
            }

            if (start is { } value)
            {
                tierParameter.Value = (int)tier;
                startParameter.Value = value;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static async Task<Dictionary<MetricsTier, (long DoneUntil, long DeletedBefore)>> ReadStateAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        var state = MetricsBuckets.Tiers.ToDictionary(t => t, _ => (DoneUntil: 0L, DeletedBefore: 0L));
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT Tier, DoneUntil, DeletedBefore FROM RollupState";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            state[(MetricsTier)reader.GetInt32(0)] = (reader.GetInt64(1), reader.GetInt64(2));
        }

        return state;
    }

    /// <summary>When more than a quarter of the file is free pages (for example after shortening a retention), gives them back to the disk.</summary>
    private static async Task GiveSpaceBackAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        var free = Convert.ToInt64(await ScalarAsync(connection, "PRAGMA freelist_count", cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
        var pages = Convert.ToInt64(await ScalarAsync(connection, "PRAGMA page_count", cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
        if (pages > 0 && free * 4 > pages)
        {
            await ExecuteAsync(connection, "PRAGMA incremental_vacuum;", cancellationToken).ConfigureAwait(false);
        }
    }

    private static long FileSize(string path) => File.Exists(path) ? new FileInfo(path).Length : 0;
}
