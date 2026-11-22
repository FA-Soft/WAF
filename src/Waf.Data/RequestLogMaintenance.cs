using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.Sqlite;
using Waf.Core.Configuration;

namespace Waf.Data;

/// <summary>Size and contents of <c>events.db</c>.</summary>
/// <param name="FileBytes">Size on disk: the database file plus its write-ahead log.</param>
/// <param name="UsedBytes">Space holding data; the rest of the file is free space that new entries reuse.</param>
/// <param name="Entries">Number of log entries.</param>
/// <param name="Oldest">Timestamp of the oldest entry; null when empty.</param>
public sealed record LogDatabaseInfo(long FileBytes, long UsedBytes, long Entries, DateTimeOffset? Oldest);

/// <summary>Outcome of one cleanup run.</summary>
/// <param name="FinishedAt">When the run finished.</param>
/// <param name="DeletedByAge">Entries removed because they were older than the age limit.</param>
/// <param name="DeletedBySize">Oldest entries removed to get below the size limit.</param>
/// <param name="FileBytesBefore">Size on disk before the run.</param>
/// <param name="FileBytesAfter">Size on disk after the run.</param>
/// <param name="Duration">How long the run took.</param>
/// <param name="Error">Why the run failed; null on success.</param>
public sealed record LogCleanupResult(
    DateTimeOffset FinishedAt, long DeletedByAge, long DeletedBySize, long FileBytesBefore, long FileBytesAfter, TimeSpan Duration, string? Error = null)
{
    public long Deleted => DeletedByAge + DeletedBySize;
}

/// <summary>
/// Keeps <c>events.db</c> within its retention limits: removes entries older than the age limit, and the oldest
/// entries when the database gets close to its size limit.
/// </summary>
/// <remarks>
/// <para>
/// Size: when the data reaches <see cref="HighWatermark"/> of the limit, the oldest entries are removed until it is
/// at <see cref="LowWatermark"/>. Removed entries leave free space in the file that new entries reuse, so the file
/// stops growing. If the file itself is larger than the limit (for example after the limit was lowered), the free
/// space is returned to the operating system (incremental vacuum) and the write-ahead log is truncated.
/// </para>
/// <para>
/// Deletes run in chunks of <see cref="ChunkSize"/> entries, each in its own short transaction, so the request log
/// writer never waits long for the database.
/// </para>
/// </remarks>
public sealed class RequestLogMaintenance(StoragePaths paths)
{
    public const double HighWatermark = 0.9;
    public const double LowWatermark = 0.8;
    public const int ChunkSize = 5000;

    private string DatabasePath => Path.Combine(paths.DataDirectory, SqliteRequestLogStore.FileName);

    public bool DatabaseExists => File.Exists(DatabasePath);

    public async Task<LogDatabaseInfo?> GetInfoAsync(CancellationToken cancellationToken)
    {
        if (!DatabaseExists)
        {
            return null;
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var (fileBytes, usedBytes) = await SizeAsync(connection, cancellationToken).ConfigureAwait(false);
        var entries = await ScalarAsync(connection, "SELECT COUNT(*) FROM RequestEvents", cancellationToken).ConfigureAwait(false);
        var oldestMs = await ScalarAsync(connection, "SELECT COALESCE((SELECT TimestampMs FROM RequestEvents ORDER BY Id LIMIT 1), -1)", cancellationToken).ConfigureAwait(false);
        return new LogDatabaseInfo(fileBytes, usedBytes, entries, oldestMs < 0 ? null : DateTimeOffset.FromUnixTimeMilliseconds(oldestMs));
    }

    /// <summary>Applies <paramref name="settings"/> once.</summary>
    public async Task<LogCleanupResult> CleanUpAsync(LogRetentionSettings settings, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var watch = Stopwatch.StartNew();
        if (!DatabaseExists)
        {
            return new LogCleanupResult(now, 0, 0, 0, 0, watch.Elapsed);
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var (before, _) = await SizeAsync(connection, cancellationToken).ConfigureAwait(false);

        // Move the write-ahead log into the database first, so the measured data is not counted twice.
        await ExecuteAsync(connection, "PRAGMA wal_checkpoint(TRUNCATE);", cancellationToken).ConfigureAwait(false);

        // 1. Age.
        long byAge = 0;
        if (settings.MaxAgeDays > 0)
        {
            var cutoff = now.AddDays(-settings.MaxAgeDays).ToUnixTimeMilliseconds();

            // By timestamp (its index), in chunks: correct even when entries are not in time order, e.g. after the
            // system clock was set back.
            while (true)
            {
                await using var command = connection.CreateCommand();
                command.CommandText = "DELETE FROM RequestEvents WHERE Id IN (SELECT Id FROM RequestEvents WHERE TimestampMs < $cutoff LIMIT $chunk)";
                command.Parameters.AddWithValue("$cutoff", cutoff);
                command.Parameters.AddWithValue("$chunk", ChunkSize);
                var rows = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                byAge += rows;
                if (rows == 0)
                {
                    break;
                }
            }
        }

        // 2. Size.
        long bySize = 0;
        var limit = (long)settings.MaxDatabaseSizeMb * 1024 * 1024;
        var (_, used) = await SizeAsync(connection, cancellationToken).ConfigureAwait(false);
        if (used > limit * HighWatermark)
        {
            var target = (long)(limit * LowWatermark);
            for (var round = 0; round < 50 && used > target; round++)
            {
                var entries = await ScalarAsync(connection, "SELECT COUNT(*) FROM RequestEvents", cancellationToken).ConfigureAwait(false);
                if (entries == 0)
                {
                    break;
                }

                // Estimate how many of the oldest entries hold the excess, with a little margin.
                var bytesPerEntry = Math.Max(1.0, (double)used / entries);
                var excess = (long)Math.Ceiling((used - target) / bytesPerEntry * 1.05);
                var firstId = await ScalarAsync(connection, "SELECT COALESCE(MIN(Id), 0) FROM RequestEvents", cancellationToken).ConfigureAwait(false);
                bySize += await DeleteBelowAsync(connection, firstId + Math.Max(1, excess), cancellationToken).ConfigureAwait(false);
                (_, used) = await SizeAsync(connection, cancellationToken).ConfigureAwait(false);
            }
        }

        // 3. Give space back when the file itself is over the limit, and keep the write-ahead log small.
        await ExecuteAsync(connection, "PRAGMA wal_checkpoint(TRUNCATE);", cancellationToken).ConfigureAwait(false);
        var (file, _) = await SizeAsync(connection, cancellationToken).ConfigureAwait(false);
        if (file > limit)
        {
            await ExecuteAsync(connection, "PRAGMA incremental_vacuum;", cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, "PRAGMA wal_checkpoint(TRUNCATE);", cancellationToken).ConfigureAwait(false);
            (file, _) = await SizeAsync(connection, cancellationToken).ConfigureAwait(false);
        }

        return new LogCleanupResult(now, byAge, bySize, before, file, watch.Elapsed);
    }

    /// <summary>Deletes all entries with an id below <paramref name="keepFrom"/>, oldest first, in short transactions.</summary>
    private static async Task<long> DeleteBelowAsync(SqliteConnection connection, long keepFrom, CancellationToken cancellationToken)
    {
        long deleted = 0;
        while (true)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM RequestEvents WHERE Id < MIN($keepFrom, (SELECT COALESCE(MIN(Id), 0) FROM RequestEvents) + $chunk)";
            command.Parameters.AddWithValue("$keepFrom", keepFrom);
            command.Parameters.AddWithValue("$chunk", ChunkSize);
            var rows = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            deleted += rows;
            if (rows == 0)
            {
                return deleted;
            }
        }
    }

    /// <summary>
    /// (database file + write-ahead log, pages holding data) in bytes. With write-ahead logging page_count already
    /// includes pages that are still in the log, so the log file only counts towards the size on disk.
    /// </summary>
    private async Task<(long File, long Used)> SizeAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        var pageSize = await ScalarAsync(connection, "PRAGMA page_size", cancellationToken).ConfigureAwait(false);
        var pages = await ScalarAsync(connection, "PRAGMA page_count", cancellationToken).ConfigureAwait(false);
        var free = await ScalarAsync(connection, "PRAGMA freelist_count", cancellationToken).ConfigureAwait(false);
        var wal = new FileInfo(DatabasePath + "-wal");
        var walBytes = wal.Exists ? wal.Length : 0;
        return ((pages * pageSize) + walBytes, (pages - free) * pageSize);
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        // Short busy timeout: a checkpoint holds up the request log writer while it waits, so give up quickly
        // instead; the next run (a minute later) tries again.
        var builder = new SqliteConnectionStringBuilder(SqliteRequestLogStore.ConnectionString(paths)) { DefaultTimeout = BusyTimeoutSeconds };
        var connection = new SqliteConnection(builder.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, $"PRAGMA busy_timeout={BusyTimeoutSeconds * 1000};", cancellationToken).ConfigureAwait(false);
        return connection;
    }

    /// <summary>How long cleanup waits for the writer, in seconds.</summary>
    public const int BusyTimeoutSeconds = 1;

    private static async Task<long> ScalarAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken, params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
