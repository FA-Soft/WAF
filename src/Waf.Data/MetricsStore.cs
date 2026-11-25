using System.Globalization;
using Microsoft.Data.Sqlite;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Data;

/// <summary>Stores and reads traffic counts.</summary>
public interface IMetricsStore
{
    /// <summary>Creates or upgrades the database.</summary>
    Task InitializeAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Adds <paramref name="counts"/> and <paramref name="sources"/> (per-second and per-minute buckets) in one
    /// transaction. A bucket that is stored already gets the new count added.
    /// </summary>
    Task WriteAsync(IReadOnlyList<TrafficCount> counts, IReadOnlyList<SourceCount> sources, CancellationToken cancellationToken);
}

/// <summary>
/// <c>metrics.db</c>: traffic counts per bucket (SQLite, write-ahead logging). Separate from <c>events.db</c> and
/// <c>config.db</c>: it is written all the time and read by the performance dashboard. The tables are made with
/// plain SQL (not EF Core migrations): the database is only written with upserts and read with aggregate queries.
/// </summary>
/// <remarks>
/// Tables (all without row id; one row per bucket and dimension):
/// <c>TrafficCounts(Tier, BucketStart, Kind, Name, Route, Outcome, Count)</c> and
/// <c>SourceCounts(Tier, BucketStart, Source, Kind, Outcome, Count)</c>, <c>TrafficPeaks(Tier, BucketStart, Total, Good, Bad, Failed)</c>
/// (the highest requests per second inside a bucket of the minute tier and coarser) and <c>RollupState(Tier, DoneUntil,
/// DeletedBefore)</c> (see <c>MetricsRollup.cs</c>). <c>Tier</c> is a <see cref="MetricsTier"/>,
/// <c>BucketStart</c> Unix seconds (UTC), <c>Kind</c> a <see cref="TrafficKind"/> and <c>Outcome</c> a
/// <see cref="TrafficOutcome"/>. The schema version is <c>PRAGMA user_version</c>.
/// </remarks>
public sealed partial class SqliteMetricsStore : IMetricsStore
{
    /// <summary>File name of the metrics database in the data folder.</summary>
    public const string FileName = "metrics.db";

    /// <summary>How long a write waits for a locked database before it fails, in seconds.</summary>
    public const int BusyTimeoutSeconds = 5;

    /// <summary>Schema version written to <c>PRAGMA user_version</c>.</summary>
    /// <remarks>1: counts and sources (step 45). 2: rollup state and peaks (step 46).</remarks>
    public const int SchemaVersion = 2;

    private const string CreateSql = """
        CREATE TABLE IF NOT EXISTS TrafficCounts (
            Tier INTEGER NOT NULL,
            BucketStart INTEGER NOT NULL,
            Kind INTEGER NOT NULL,
            Name TEXT NOT NULL,
            Route TEXT NOT NULL,
            Outcome INTEGER NOT NULL,
            Count INTEGER NOT NULL,
            PRIMARY KEY (Tier, BucketStart, Kind, Name, Route)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS SourceCounts (
            Tier INTEGER NOT NULL,
            BucketStart INTEGER NOT NULL,
            Source TEXT NOT NULL,
            Kind INTEGER NOT NULL,
            Outcome INTEGER NOT NULL,
            Count INTEGER NOT NULL,
            PRIMARY KEY (Tier, BucketStart, Source, Kind)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS TrafficPeaks (
            Tier INTEGER NOT NULL,
            BucketStart INTEGER NOT NULL,
            Total INTEGER NOT NULL,
            Good INTEGER NOT NULL,
            Bad INTEGER NOT NULL,
            Failed INTEGER NOT NULL,
            PRIMARY KEY (Tier, BucketStart)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS RollupState (
            Tier INTEGER NOT NULL PRIMARY KEY,
            DoneUntil INTEGER NOT NULL,
            DeletedBefore INTEGER NOT NULL
        ) WITHOUT ROWID;
        """;

    private const string InsertCountSql = """
        INSERT INTO TrafficCounts (Tier, BucketStart, Kind, Name, Route, Outcome, Count)
        VALUES ($tier, $bucket, $kind, $name, $route, $outcome, $count)
        ON CONFLICT (Tier, BucketStart, Kind, Name, Route) DO UPDATE SET Count = Count + excluded.Count
        """;

    private const string InsertSourceSql = """
        INSERT INTO SourceCounts (Tier, BucketStart, Source, Kind, Outcome, Count)
        VALUES ($tier, $bucket, $source, $kind, $outcome, $count)
        ON CONFLICT (Tier, BucketStart, Source, Kind) DO UPDATE SET Count = Count + excluded.Count
        """;

    private readonly string _connectionString;

    /// <param name="databasePath">Full path of the database file.</param>
    public SqliteMetricsStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        DatabasePath = databasePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            DefaultTimeout = BusyTimeoutSeconds,
        }.ToString();
    }

    /// <summary>Full path of the database file.</summary>
    public string DatabasePath { get; }

    /// <summary>
    /// The database path from the host setting: empty means <c>metrics.db</c> in the data folder; a relative path is
    /// relative to the data folder.
    /// </summary>
    public static string ResolvePath(StoragePaths paths, string? configured)
    {
        ArgumentNullException.ThrowIfNull(paths);
        return string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(paths.DataDirectory, FileName)
            : Path.GetFullPath(configured, paths.DataDirectory);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        var folder = Path.GetDirectoryName(DatabasePath);
        if (!string.IsNullOrEmpty(folder))
        {
            Directory.CreateDirectory(folder);
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var version = Convert.ToInt32(await ScalarAsync(connection, "PRAGMA user_version", cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
        if (version > SchemaVersion)
        {
            throw new InvalidOperationException(
                $"{DatabasePath} was made by a newer version of the gateway (schema {version}; this version knows {SchemaVersion}).");
        }

        // Incremental auto-vacuum (before any table exists, so no VACUUM is needed) lets removed rows give space back.
        if (version == 0)
        {
            await ExecuteAsync(connection, "PRAGMA auto_vacuum=INCREMENTAL;", cancellationToken).ConfigureAwait(false);
        }

        // WAL: the dashboard reads while the writer writes.
        await ExecuteAsync(connection, "PRAGMA journal_mode=WAL;", cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, CreateSql, cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, $"PRAGMA user_version={SchemaVersion};", cancellationToken).ConfigureAwait(false);
    }

    public async Task WriteAsync(IReadOnlyList<TrafficCount> counts, IReadOnlyList<SourceCount> sources, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(counts);
        ArgumentNullException.ThrowIfNull(sources);
        if (counts.Count == 0 && sources.Count == 0)
        {
            return;
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        // synchronous=NORMAL is safe with WAL: at worst the last writes before a power failure are lost.
        await ExecuteAsync(connection, "PRAGMA synchronous=NORMAL;", cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        if (counts.Count > 0)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = InsertCountSql;
            var tier = command.Parameters.Add("$tier", SqliteType.Integer);
            var bucket = command.Parameters.Add("$bucket", SqliteType.Integer);
            var kind = command.Parameters.Add("$kind", SqliteType.Integer);
            var name = command.Parameters.Add("$name", SqliteType.Text);
            var route = command.Parameters.Add("$route", SqliteType.Text);
            var outcome = command.Parameters.Add("$outcome", SqliteType.Integer);
            var count = command.Parameters.Add("$count", SqliteType.Integer);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            tier.Value = (int)MetricsTier.Second;
            foreach (var item in counts)
            {
                bucket.Value = item.BucketStart;
                kind.Value = (int)item.Kind;
                name.Value = item.Name;
                route.Value = item.Route;
                outcome.Value = (int)item.Outcome;
                count.Value = item.Count;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        if (sources.Count > 0)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = InsertSourceSql;
            var tier = command.Parameters.Add("$tier", SqliteType.Integer);
            var bucket = command.Parameters.Add("$bucket", SqliteType.Integer);
            var source = command.Parameters.Add("$source", SqliteType.Text);
            var kind = command.Parameters.Add("$kind", SqliteType.Integer);
            var outcome = command.Parameters.Add("$outcome", SqliteType.Integer);
            var count = command.Parameters.Add("$count", SqliteType.Integer);
            await command.PrepareAsync(cancellationToken).ConfigureAwait(false);
            tier.Value = (int)MetricsTier.Minute;
            foreach (var item in sources)
            {
                bucket.Value = item.BucketStart;
                source.Value = item.Source;
                kind.Value = (int)item.Kind;
                outcome.Value = (int)TrafficClassifier.OutcomeOf(item.Kind);
                count.Value = item.Count;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        // Counts for buckets that were rolled up already (a slow request is counted by its start): roll them up again.
        await ReopenRollupsAsync(connection, transaction, counts, sources, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Stored counts of <paramref name="tier"/> with a bucket start in [<paramref name="from"/>, <paramref name="to"/>).</summary>
    public async Task<List<TrafficCount>> ReadCountsAsync(MetricsTier tier, DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT BucketStart, Kind, Name, Route, Count FROM TrafficCounts
            WHERE Tier = $tier AND BucketStart >= $from AND BucketStart < $to
            ORDER BY BucketStart, Kind, Name, Route
            """;
        command.Parameters.AddWithValue("$tier", (int)tier);
        command.Parameters.AddWithValue("$from", from.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$to", to.ToUnixTimeSeconds());
        var result = new List<TrafficCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new TrafficCount(reader.GetInt64(0), (TrafficKind)reader.GetInt32(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4)));
        }

        return result;
    }

    /// <summary>Stored source counts of <paramref name="tier"/> with a bucket start in [<paramref name="from"/>, <paramref name="to"/>).</summary>
    public async Task<List<SourceCount>> ReadSourcesAsync(MetricsTier tier, DateTimeOffset from, DateTimeOffset to, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT BucketStart, Source, Kind, Count FROM SourceCounts
            WHERE Tier = $tier AND BucketStart >= $from AND BucketStart < $to
            ORDER BY BucketStart, Source, Kind
            """;
        command.Parameters.AddWithValue("$tier", (int)tier);
        command.Parameters.AddWithValue("$from", from.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$to", to.ToUnixTimeSeconds());
        var result = new List<SourceCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new SourceCount(reader.GetInt64(0), reader.GetString(1), (TrafficKind)reader.GetInt32(2), reader.GetInt64(3)));
        }

        return result;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }
}
