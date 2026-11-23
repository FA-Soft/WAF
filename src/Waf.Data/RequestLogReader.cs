using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;

namespace FASoft.Waf.Data;

/// <summary>Which requests the log viewer shows, in plain language.</summary>
public enum LogView
{
    /// <summary>Every request.</summary>
    All,

    /// <summary>Rejected: blocked, rate limited or fail-closed.</summary>
    Blocked,

    /// <summary>Would have been blocked, but detection-only mode let them through.</summary>
    WouldBlock,

    /// <summary>Matched a "log only" rule.</summary>
    Logged,

    /// <summary>Forwarded to a backend.</summary>
    Forwarded,

    /// <summary>No route matched (404).</summary>
    NoRoute,

    /// <summary>Server errors (status 500 and higher), e.g. a backend that is down.</summary>
    Errors,
}

/// <summary>Filter of the log viewer. Every given criterion must match.</summary>
public sealed record RequestLogFilter
{
    /// <summary>Only requests from this moment on.</summary>
    public DateTimeOffset? From { get; init; }

    public LogView Show { get; init; }

    /// <summary>Exact client IP.</summary>
    public string? ClientIp { get; init; }

    /// <summary>Exact host name.</summary>
    public string? Host { get; init; }

    /// <summary>Exact route name.</summary>
    public string? Route { get; init; }

    /// <summary>Exact rule, rate limit or signature name.</summary>
    public string? Rule { get; init; }

    public int? Status { get; init; }

    /// <summary>Free text, found anywhere in the path, host, client IP, route, rule, detail or destination (case-insensitive).</summary>
    public string? Search { get; init; }
}

/// <summary>One page of the log, newest first.</summary>
/// <param name="Items">The entries, newest first.</param>
/// <param name="HasOlder">More matching entries exist before the last item.</param>
/// <param name="HasNewer">More matching entries exist after the first item.</param>
public sealed record RequestLogPage(IReadOnlyList<RequestEvent> Items, bool HasOlder, bool HasNewer);

/// <summary>
/// Reads <c>events.db</c> for the log viewer, fast at any size.
/// </summary>
/// <remarks>
/// <para>
/// Pages are found by key (entries before or after an id), never by offset, so every page costs the same. The
/// time range is first turned into an id range with the timestamp index; the table is then read newest first along
/// its primary key and reading stops as soon as the page is full. That is predictable for every filter, unlike
/// letting SQLite choose an index for an ORDER BY with a range (which can mean sorting millions of rows). Only a
/// client-IP filter, which is very selective, uses its own index.
/// </para>
/// <para>Reads run in their own read-only connection; with write-ahead logging they never wait for the writer.</para>
/// </remarks>
public sealed class RequestLogReader(StoragePaths paths)
{
    /// <summary>Largest page size.</summary>
    public const int MaxPageSize = 500;

    private const string Columns =
        "Id, TimestampMs, ClientIp, Method, Host, Path, RouteName, Action, Event, RuleName, Detail, Destination, StatusCode, LatencyMs";

    private string DatabasePath => Path.Combine(paths.DataDirectory, SqliteRequestLogStore.FileName);

    /// <summary>False until the first entry has been written (or when logging is off).</summary>
    public bool DatabaseExists => File.Exists(DatabasePath);

    /// <summary>A page of entries matching <paramref name="filter"/>: the newest, or those before / after an id.</summary>
    public async Task<RequestLogPage> ReadPageAsync(RequestLogFilter filter, long? before, long? after, int size, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        size = Math.Clamp(size, 1, MaxPageSize);
        if (!DatabaseExists)
        {
            return new RequestLogPage([], false, false);
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var range = await IdRangeAsync(connection, filter, cancellationToken).ConfigureAwait(false);
        if (range is null)
        {
            return new RequestLogPage([], false, false);
        }

        if (after is not null)
        {
            // Newer page: read upwards from 'after', show newest first.
            var rows = await QueryAsync(connection, filter, range.Value, minExclusive: after, maxExclusive: null, ascending: true, size + 1, cancellationToken).ConfigureAwait(false);
            var hasNewer = rows.Count > size;
            var items = rows.Take(size).Reverse().ToList();
            var hasOlder = await AnyAsync(connection, filter, range.Value, minExclusive: null, maxExclusive: after + 1, cancellationToken).ConfigureAwait(false);
            return new RequestLogPage(items, hasOlder, hasNewer);
        }

        var page = await QueryAsync(connection, filter, range.Value, minExclusive: null, maxExclusive: before, ascending: false, size + 1, cancellationToken).ConfigureAwait(false);
        var newer = before is not null
            && await AnyAsync(connection, filter, range.Value, minExclusive: before - 1, maxExclusive: null, cancellationToken).ConfigureAwait(false);
        return new RequestLogPage([.. page.Take(size)], page.Count > size, newer);
    }

    /// <summary>
    /// Entries after <paramref name="after"/> (and up to <paramref name="upTo"/>, if given) matching
    /// <paramref name="filter"/>, oldest first (for the live view).
    /// </summary>
    public async Task<IReadOnlyList<RequestEvent>> ReadNewerAsync(RequestLogFilter filter, long after, int max, CancellationToken cancellationToken, long? upTo = null)
    {
        ArgumentNullException.ThrowIfNull(filter);
        if (!DatabaseExists)
        {
            return [];
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var range = await IdRangeAsync(connection, filter, cancellationToken).ConfigureAwait(false);
        return range is null
            ? []
            : await QueryAsync(connection, filter, range.Value, minExclusive: after, maxExclusive: upTo + 1, ascending: true, Math.Clamp(max, 1, MaxPageSize), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The newest entry id (0 when the log is empty): where the live view continues from.</summary>
    public async Task<long> GetLatestIdAsync(CancellationToken cancellationToken)
    {
        if (!DatabaseExists)
        {
            return 0;
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COALESCE(MAX(Id), 0) FROM RequestEvents";
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    /// <summary>One entry, or null.</summary>
    public async Task<RequestEvent?> GetAsync(long id, CancellationToken cancellationToken)
    {
        if (!DatabaseExists)
        {
            return null;
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {Columns} FROM RequestEvents WHERE Id = $id";
        command.Parameters.AddWithValue("$id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        return await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ? Map(reader) : null;
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            DefaultTimeout = SqliteRequestLogStore.BusyTimeoutSeconds,
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    /// <summary>The id range of the time filter: from the first entry at or after From; null when nothing is that recent.</summary>
    private static async Task<(long Min, long Max)?> IdRangeAsync(SqliteConnection connection, RequestLogFilter filter, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        // Separate subqueries: SQLite answers a lone MIN or MAX of the key with one seek, but MIN and MAX together, or
        // MIN(Id) over a timestamp range, with a scan.
        if (filter.From is { } from)
        {
            // The first entry at or after From by timestamp (one seek in the timestamp index). Ids follow arrival
            // order closely; around the boundary a request that took long can be a few ids off, which is fine for a
            // time filter (the timestamp itself is still checked).
            command.CommandText = """
                SELECT (SELECT Id FROM RequestEvents WHERE TimestampMs >= $from ORDER BY TimestampMs LIMIT 1),
                       (SELECT MAX(Id) FROM RequestEvents)
                """;
            command.Parameters.AddWithValue("$from", from.ToUnixTimeMilliseconds());
        }
        else
        {
            command.CommandText = "SELECT (SELECT MIN(Id) FROM RequestEvents), (SELECT MAX(Id) FROM RequestEvents)";
        }

        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) || reader.IsDBNull(0))
        {
            return null;
        }

        return (reader.GetInt64(0), reader.GetInt64(1));
    }

    private static async Task<List<RequestEvent>> QueryAsync(
        SqliteConnection connection, RequestLogFilter filter, (long Min, long Max) range, long? minExclusive, long? maxExclusive,
        bool ascending, int limit, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        var where = Where(command, filter, range, minExclusive, maxExclusive);
        command.CommandText = $"SELECT {Columns} FROM RequestEvents {IndexHint(filter)} WHERE {where} ORDER BY Id {(ascending ? "ASC" : "DESC")} LIMIT $limit";
        command.Parameters.AddWithValue("$limit", limit);

        var rows = new List<RequestEvent>(Math.Min(limit, 64));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(Map(reader));
        }

        return rows;
    }

    private static async Task<bool> AnyAsync(
        SqliteConnection connection, RequestLogFilter filter, (long Min, long Max) range, long? minExclusive, long? maxExclusive, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        var where = Where(command, filter, range, minExclusive, maxExclusive);
        command.CommandText = $"SELECT EXISTS (SELECT 1 FROM RequestEvents {IndexHint(filter)} WHERE {where})";
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture) == 1;
    }

    /// <summary>Client IP: its own (selective) index. Everything else: read along the primary key, newest first.</summary>
    private static string IndexHint(RequestLogFilter filter) =>
        string.IsNullOrWhiteSpace(filter.ClientIp) ? "NOT INDEXED" : "INDEXED BY IX_RequestEvents_ClientIp";

    private static string Where(SqliteCommand command, RequestLogFilter filter, (long Min, long Max) range, long? minExclusive, long? maxExclusive)
    {
        var where = new StringBuilder("Id >= $minId AND Id <= $maxId");
        command.Parameters.AddWithValue("$minId", Math.Max(range.Min, (minExclusive ?? long.MinValue) + 1));
        command.Parameters.AddWithValue("$maxId", Math.Min(range.Max, (maxExclusive ?? long.MaxValue) - 1));

        if (filter.From is { } from)
        {
            // Unary + keeps SQLite from switching to the timestamp index for this check.
            where.Append(" AND +TimestampMs >= $from");
            command.Parameters.AddWithValue("$from", from.ToUnixTimeMilliseconds());
        }

        switch (filter.Show)
        {
            case LogView.Blocked:
                where.Append(" AND Action IN ('Blocked', 'RateLimited', 'FailClosed')");
                break;
            case LogView.WouldBlock:
                where.Append(" AND Event IN ('RuleDetected', 'AttackDetected', 'RateLimitDetected')");
                break;
            case LogView.Logged:
                where.Append(" AND Event = 'RuleLogged'");
                break;
            case LogView.Forwarded:
                where.Append(" AND Action = 'Forwarded'");
                break;
            case LogView.NoRoute:
                where.Append(" AND Action = 'NoRoute'");
                break;
            case LogView.Errors:
                where.Append(" AND StatusCode >= 500");
                break;
        }

        AddExact(command, where, "ClientIp", "$ip", filter.ClientIp);
        AddExact(command, where, "Host", "$host", filter.Host, ignoreCase: true);
        AddExact(command, where, "RouteName", "$route", filter.Route, ignoreCase: true);
        AddExact(command, where, "RuleName", "$rule", filter.Rule, ignoreCase: true);

        if (filter.Status is { } status)
        {
            where.Append(" AND StatusCode = $status");
            command.Parameters.AddWithValue("$status", status);
        }

        if (!string.IsNullOrWhiteSpace(filter.Search))
        {
            // LIKE is case-insensitive for ASCII; %, _ and \ in the search text are matched literally.
            var pattern = "%" + filter.Search.Trim().Replace(@"\", @"\\", StringComparison.Ordinal)
                .Replace("%", @"\%", StringComparison.Ordinal).Replace("_", @"\_", StringComparison.Ordinal) + "%";
            command.Parameters.AddWithValue("$q", pattern);
            where.Append(" AND (Path LIKE $q ESCAPE '\\' OR Host LIKE $q ESCAPE '\\' OR ClientIp LIKE $q ESCAPE '\\'");
            where.Append(" OR RouteName LIKE $q ESCAPE '\\' OR RuleName LIKE $q ESCAPE '\\' OR Detail LIKE $q ESCAPE '\\' OR Destination LIKE $q ESCAPE '\\')");
        }

        return where.ToString();
    }

    private static void AddExact(SqliteCommand command, StringBuilder where, string column, string parameter, string? value, bool ignoreCase = false)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        where.Append(CultureInfo.InvariantCulture, $" AND {column} = {parameter}{(ignoreCase ? " COLLATE NOCASE" : string.Empty)}");
        command.Parameters.AddWithValue(parameter, value.Trim());
    }

    private static RequestEvent Map(SqliteDataReader reader) => new()
    {
        Id = reader.GetInt64(0),
        TimestampMs = reader.GetInt64(1),
        ClientIp = reader.GetString(2),
        Method = reader.GetString(3),
        Host = reader.GetString(4),
        Path = reader.GetString(5),
        RouteName = reader.IsDBNull(6) ? null : reader.GetString(6),
        Action = reader.GetString(7),
        Event = reader.IsDBNull(8) ? null : reader.GetString(8),
        RuleName = reader.IsDBNull(9) ? null : reader.GetString(9),
        Detail = reader.IsDBNull(10) ? null : reader.GetString(10),
        Destination = reader.IsDBNull(11) ? null : reader.GetString(11),
        StatusCode = reader.GetInt32(12),
        LatencyMs = reader.GetDouble(13),
    };
}
