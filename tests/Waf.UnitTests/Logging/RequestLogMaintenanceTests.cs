using Microsoft.Data.Sqlite;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.UnitTests.Logging;

public sealed class RequestLogMaintenanceTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
    private const long Mb = 1024 * 1024;

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private StoragePaths Paths => new(_directory, _directory);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask InitializeAsync() => ValueTask.CompletedTask;

    public ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    private static RequestLogEntry Entry(DateTimeOffset timestamp, int i) => new(
        timestamp, $"10.0.{i % 250}.{i % 200}", "GET", "www.example.com", $"/products/category-{i % 40}/item-{i}", "website",
        RequestAction.Forwarded, null, null, null, "http://10.0.0.5:8080/", 200, 2.5);

    private async Task<SqliteRequestLogStore> StoreAsync()
    {
        var store = new SqliteRequestLogStore(Paths);
        await store.InitializeAsync(Ct);
        return store;
    }

    private static async Task WriteAsync(SqliteRequestLogStore store, int count, int start, Func<int, DateTimeOffset> timestamp)
    {
        var batch = new List<RequestLogEntry>(10_000);
        for (var i = start; i < start + count; i++)
        {
            batch.Add(Entry(timestamp(i), i));
            if (batch.Count == batch.Capacity)
            {
                await store.WriteAsync(batch, Ct);
                batch.Clear();
            }
        }

        await store.WriteAsync(batch, Ct);
    }

    private static LogRetentionSettings Limits(int maxAgeDays = 0, int maxSizeMb = 1024) => new() { MaxAgeDays = maxAgeDays, MaxDatabaseSizeMb = maxSizeMb };

    [Fact]
    public async Task Entries_older_than_the_age_limit_are_removed()
    {
        var store = await StoreAsync();
        await WriteAsync(store, 1000, 0, i => Now.AddDays(-40).AddMinutes(i)); // 40 days old
        await WriteAsync(store, 500, 1000, i => Now.AddDays(-10).AddMinutes(i)); // 10 days old
        var maintenance = new RequestLogMaintenance(Paths);

        var kept = await maintenance.CleanUpAsync(Limits(maxAgeDays: 0), Now, Ct);
        Assert.Equal(0, kept.Deleted);

        var result = await maintenance.CleanUpAsync(Limits(maxAgeDays: 30), Now, Ct);

        Assert.Equal((1000L, 0L), (result.DeletedByAge, result.DeletedBySize));
        var info = (await maintenance.GetInfoAsync(Ct))!;
        Assert.Equal(500, info.Entries);
        Assert.Equal(Now.AddDays(-10).AddMinutes(1000), info.Oldest); // the first of the 10-day-old entries

        Assert.Equal(500, (await maintenance.CleanUpAsync(Limits(maxAgeDays: 1), Now, Ct)).DeletedByAge);
        Assert.Equal(0, (await maintenance.GetInfoAsync(Ct))!.Entries);
    }

    /// <summary>
    /// Acceptance: the log is filled with about three times its size limit, in rounds, with a cleanup after each round
    /// (as the background job does). On disk it never exceeds the limit, and the newest entries are always kept.
    /// </summary>
    [Fact]
    public async Task Database_size_stays_within_the_configured_limit()
    {
        const int LimitMb = 10;
        var store = await StoreAsync();
        var maintenance = new RequestLogMaintenance(Paths);
        var next = 0;
        long deletedBySize = 0;

        for (var round = 0; round < 12; round++)
        {
            await WriteAsync(store, 10_000, next, i => Now.AddSeconds(i));
            next += 10_000;

            var result = await maintenance.CleanUpAsync(Limits(maxSizeMb: LimitMb), Now.AddDays(1), Ct);
            deletedBySize += result.DeletedBySize;
            var info = (await maintenance.GetInfoAsync(Ct))!;
            var onDisk = new FileInfo(Path.Combine(_directory, "events.db")).Length
                + (File.Exists(Path.Combine(_directory, "events.db-wal")) ? new FileInfo(Path.Combine(_directory, "events.db-wal")).Length : 0);

            TestContext.Current.TestOutputHelper!.WriteLine(
                $"round {round + 1}: {next:N0} written, {info.Entries:N0} kept, {onDisk / (double)Mb:F1} MB on disk, {info.UsedBytes / (double)Mb:F1} MB used, {result.DeletedBySize:N0} removed");
            Assert.True(onDisk <= LimitMb * Mb, $"Round {round + 1}: {onDisk / (double)Mb:F1} MB on disk exceeds the {LimitMb} MB limit.");
            Assert.Equal(next, info.Entries + deletedBySize); // only the oldest are removed...
            Assert.Equal(next - 1, (await new RequestLogReader(Paths).ReadPageAsync(new RequestLogFilter(), null, null, 1, Ct)).Items.Single().Path.Split('-')[^1] is { } last ? int.Parse(last, System.Globalization.CultureInfo.InvariantCulture) : -1); // ...the newest stays
        }

        Assert.True(deletedBySize > 0, "Three times the limit was written; old entries must have been removed.");
    }

    [Fact]
    public async Task A_lowered_limit_gives_space_back_to_the_disk()
    {
        var store = await StoreAsync();
        await WriteAsync(store, 80_000, 0, i => Now.AddSeconds(i));
        var maintenance = new RequestLogMaintenance(Paths);
        var before = (await maintenance.GetInfoAsync(Ct))!;

        // The data alone is over the new limit (the file size also depends on when the write-ahead log was checkpointed).
        Assert.True(before.UsedBytes > 12 * Mb, $"Test data too small: {before.UsedBytes / (double)Mb:F1} MB.");

        var result = await maintenance.CleanUpAsync(Limits(maxSizeMb: 10), Now, Ct);

        var after = (await maintenance.GetInfoAsync(Ct))!;
        Assert.True(result.DeletedBySize > 0);
        Assert.True(after.FileBytes <= 10 * Mb, $"{after.FileBytes / (double)Mb:F1} MB on disk after lowering the limit to 10 MB.");
        Assert.Equal(after.FileBytes, result.FileBytesAfter);
        TestContext.Current.TestOutputHelper!.WriteLine(
            $"{before.Entries:N0} entries in {before.FileBytes / (double)Mb:F1} MB ({before.UsedBytes / (double)before.Entries:F0} bytes each); after: {after.Entries:N0} in {after.FileBytes / (double)Mb:F1} MB");
    }

    [Fact]
    public async Task Incremental_auto_vacuum_is_switched_on_also_for_an_existing_database()
    {
        await StoreAsync();
        Assert.Equal(2, await PragmaAsync("auto_vacuum"));

        // A database from before this setting existed.
        await ExecuteAsync("PRAGMA auto_vacuum=NONE; VACUUM;");
        Assert.Equal(0, await PragmaAsync("auto_vacuum"));

        await StoreAsync();
        Assert.Equal(2, await PragmaAsync("auto_vacuum"));
    }

    [Fact]
    public async Task An_absent_database_needs_no_cleanup()
    {
        var maintenance = new RequestLogMaintenance(Paths);

        Assert.Null(await maintenance.GetInfoAsync(Ct));
        Assert.Equal(0, (await maintenance.CleanUpAsync(Limits(maxAgeDays: 1, maxSizeMb: 10), Now, Ct)).Deleted);
    }

    [Theory]
    [InlineData(-1, 1024, "MaxAgeDays")]
    [InlineData(3651, 1024, "MaxAgeDays")]
    [InlineData(30, 9, "MaxDatabaseSizeMb")]
    public void Limits_are_validated(int days, int sizeMb, string expected)
    {
        var configuration = new GatewayConfiguration();
        configuration.Settings.LogRetention.MaxAgeDays = days;
        configuration.Settings.LogRetention.MaxDatabaseSizeMb = sizeMb;

        Assert.Contains(expected, Assert.Single(GatewayConfigurationValidator.Validate(configuration)), StringComparison.Ordinal);
    }

    private async Task<long> PragmaAsync(string name)
    {
        await using var connection = new SqliteConnection(SqliteRequestLogStore.ConnectionString(Paths));
        await connection.OpenAsync(Ct);
        await using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA {name}";
        return (long)(await command.ExecuteScalarAsync(Ct))!;
    }

    private async Task ExecuteAsync(string sql)
    {
        await using var connection = new SqliteConnection(SqliteRequestLogStore.ConnectionString(Paths));
        await connection.OpenAsync(Ct);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(Ct);
    }
}
