using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Data;

/// <summary>Stores batches of request log entries.</summary>
public interface IRequestLogStore
{
    /// <summary>Creates or migrates the database.</summary>
    Task InitializeAsync(CancellationToken cancellationToken);

    /// <summary>Stores <paramref name="entries"/> in one transaction: all or none.</summary>
    Task WriteAsync(IReadOnlyList<RequestLogEntry> entries, CancellationToken cancellationToken);
}

/// <summary>
/// <c>events.db</c> in the data folder (SQLite, write-ahead logging). Inserts use one prepared command per batch,
/// in one transaction, which is far faster than inserting through EF Core.
/// </summary>
public sealed class SqliteRequestLogStore(StoragePaths paths) : IRequestLogStore
{
    /// <summary>File name of the event database.</summary>
    public const string FileName = "events.db";

    /// <summary>How long a write waits for a locked database before it fails, in seconds.</summary>
    public const int BusyTimeoutSeconds = 5;

    private const string InsertSql = """
        INSERT INTO RequestEvents
            (TimestampMs, ClientIp, Method, Host, Path, RouteName, Action, Event, RuleName, Detail, Destination, StatusCode, LatencyMs)
        VALUES
            ($timestamp, $clientIp, $method, $host, $path, $route, $action, $event, $rule, $detail, $destination, $status, $latency)
        """;

    /// <summary>Full path of <c>events.db</c>.</summary>
    public string DatabasePath => Path.Combine(paths.DataDirectory, FileName);

    /// <summary>Connection string for <c>events.db</c>.</summary>
    public static string ConnectionString(StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        return new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(paths.DataDirectory, FileName),
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            DefaultTimeout = BusyTimeoutSeconds,
        }.ToString();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        paths.EnsureDataDirectory();
        var options = new DbContextOptionsBuilder<EventDbContext>().UseSqlite(ConnectionString(paths)).Options;
        await using var db = new EventDbContext(options);
        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);

        // WAL: the log viewer reads while the writer writes. synchronous=NORMAL is safe with WAL (no corruption);
        // at worst the last batches before a power failure are lost, which is acceptable for a log.
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken).ConfigureAwait(false);

        // Incremental auto-vacuum lets retention give free space back to the disk when the file is over its size
        // limit. It must be switched on before data is written, or followed by one VACUUM (instant on a new database).
        var connection = db.Database.GetDbConnection();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var check = connection.CreateCommand();
        check.CommandText = "PRAGMA auto_vacuum";
        if (Convert.ToInt64(await check.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture) != IncrementalAutoVacuum)
        {
            await db.Database.ExecuteSqlRawAsync("PRAGMA auto_vacuum=INCREMENTAL;", cancellationToken).ConfigureAwait(false);
            await db.Database.ExecuteSqlRawAsync("VACUUM;", cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Value of <c>PRAGMA auto_vacuum</c> for incremental mode.</summary>
    private const long IncrementalAutoVacuum = 2;

    public async Task WriteAsync(IReadOnlyList<RequestLogEntry> entries, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entries);
        if (entries.Count == 0)
        {
            return;
        }

        await using var connection = new SqliteConnection(ConnectionString(paths));
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA synchronous=NORMAL;";
            await pragma.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = InsertSql;
        var timestamp = command.Parameters.Add("$timestamp", SqliteType.Integer);
        var clientIp = command.Parameters.Add("$clientIp", SqliteType.Text);
        var method = command.Parameters.Add("$method", SqliteType.Text);
        var host = command.Parameters.Add("$host", SqliteType.Text);
        var path = command.Parameters.Add("$path", SqliteType.Text);
        var route = command.Parameters.Add("$route", SqliteType.Text);
        var action = command.Parameters.Add("$action", SqliteType.Text);
        var wafEvent = command.Parameters.Add("$event", SqliteType.Text);
        var rule = command.Parameters.Add("$rule", SqliteType.Text);
        var detail = command.Parameters.Add("$detail", SqliteType.Text);
        var destination = command.Parameters.Add("$destination", SqliteType.Text);
        var status = command.Parameters.Add("$status", SqliteType.Integer);
        var latency = command.Parameters.Add("$latency", SqliteType.Real);
        await command.PrepareAsync(cancellationToken).ConfigureAwait(false);

        foreach (var entry in entries)
        {
            timestamp.Value = entry.Timestamp.ToUnixTimeMilliseconds();
            clientIp.Value = entry.ClientIp;
            method.Value = entry.Method;
            host.Value = entry.Host;
            path.Value = entry.Path;
            route.Value = (object?)entry.RouteName ?? DBNull.Value;
            action.Value = entry.Action.ToString();
            wafEvent.Value = (object?)entry.Event?.ToString() ?? DBNull.Value;
            rule.Value = (object?)entry.RuleName ?? DBNull.Value;
            detail.Value = (object?)entry.Detail ?? DBNull.Value;
            destination.Value = (object?)entry.Destination ?? DBNull.Value;
            status.Value = entry.StatusCode;
            latency.Value = entry.LatencyMs;
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }
}
