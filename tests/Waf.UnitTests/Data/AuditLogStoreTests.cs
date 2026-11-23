using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.UnitTests.Engine;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Data;

/// <summary>The audit log in <c>config.db</c>, against a real SQLite database file in a temporary folder.</summary>
public sealed class AuditLogStoreTests : IDisposable
{
    private static readonly AuditActor Frank = new("frank", "192.0.2.10", "admin UI");

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly ManualTimeProvider _time = new();
    private readonly ServiceProvider _services;

    public AuditLogStoreTests()
    {
        var paths = new StoragePaths(_directory, _directory);
        paths.EnsureDataDirectory();
        _services = new ServiceCollection()
            .AddSingleton<TimeProvider>(_time)
            .AddWafData(paths)
            .BuildServiceProvider();
        Store = _services.GetRequiredService<ConfigurationStore>();
        Audit = _services.GetRequiredService<AuditLogStore>();
    }

    private ConfigurationStore Store { get; }

    private AuditLogStore Audit { get; }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        _services.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private async Task<ConfigDbContext> ContextAsync() =>
        await _services.GetRequiredService<IDbContextFactory<ConfigDbContext>>().CreateDbContextAsync(Ct);

    private async Task<List<AuditEntry>> AllAsync() =>
        [.. (await Audit.ReadPageAsync(new AuditFilter(), null, null, AuditLogStore.MaxPageSize, Ct)).Items.Reverse()];

    [Fact]
    public async Task Saving_a_version_records_who_saved_it_and_what_changed()
    {
        await Store.InitializeAsync(Ct);

        var first = await Store.SaveAsync(Config(), AuditActor.System("appsettings import"), "Imported.", Ct);
        _time.Advance(TimeSpan.FromMinutes(5));
        var second = await Store.SaveAsync(Config(Rule("block-admin", RuleAction.Block, 10)), Frank, "Rule 'block-admin' added.", Ct);

        var entries = await AllAsync();
        Assert.Equal([first.Version, second.Version], entries.Select(e => e.ConfigurationVersionId!.Value));
        Assert.Equal("First configuration: 2 route(s), 0 rule(s), 0 rate limit(s).", entries[0].Details);
        Assert.Equal(("appsettings import", null, "system"), (entries[0].UserName, entries[0].ClientIp, entries[0].Source));

        var entry = entries[1];
        Assert.Equal((AuditCategory.Configuration, AuditActions.ConfigSaved), (entry.Category, entry.Action));
        Assert.Equal(("frank", "192.0.2.10", "admin UI"), (entry.UserName, entry.ClientIp, entry.Source));
        Assert.Equal($"Version {second.Version}: Rule 'block-admin' added.", entry.Summary);
        Assert.Equal("Rule 'block-admin' added", entry.Details);
        Assert.Equal(_time.Now.UtcDateTime, entry.TimestampUtc);
        Assert.Equal("frank", second.Author);
    }

    [Fact]
    public async Task An_unchanged_configuration_adds_no_version_and_no_entry()
    {
        await Store.InitializeAsync(Ct);

        await Store.SaveIfChangedAsync(Config(), Frank, null, Ct);
        await Store.SaveIfChangedAsync(Config(), Frank, null, Ct);

        Assert.Single(await AllAsync());
    }

    [Fact]
    public async Task An_invalid_configuration_adds_no_entry()
    {
        await Store.InitializeAsync(Ct);

        await Assert.ThrowsAsync<ArgumentException>(() => Store.SaveAsync(Config(new WafRule { Name = "no-conditions" }), Frank, null, Ct));

        Assert.Empty(await AllAsync());
    }

    [Fact]
    public async Task Restoring_versions_keeps_the_log_and_records_versions_that_changed()
    {
        await Store.InitializeAsync(Ct);
        var one = await Store.SaveAsync(Config(), Frank, "one", Ct);
        await Store.SaveAsync(Config(Rule("r", RuleAction.LogOnly, 1)), Frank, "two", Ct);
        var before = await AllAsync();

        // Version 1 stays the same; version 2 gets other content; version 3 is new.
        var restorer = new AuditActor("anna", "192.0.2.20", "admin UI");
        await Store.ReplaceAllAsync(
            [
                new BackupVersion(1, one.CreatedAtUtc, "frank", "one", Config()),
                new BackupVersion(2, one.CreatedAtUtc, "bob", "other two", Config(Rule("x", RuleAction.Block, 1))),
                new BackupVersion(3, one.CreatedAtUtc, "bob", null, Config(Rule("y", RuleAction.Block, 1))),
            ],
            3,
            restorer,
            Ct);

        var after = await AllAsync();
        Assert.Equal(before.Select(e => e.Id), after.Take(before.Count).Select(e => e.Id));
        var added = after.Skip(before.Count).ToList();
        Assert.Equal([2L, 3L], added.Select(e => e.ConfigurationVersionId!.Value));
        Assert.All(added, e => Assert.Equal((AuditActions.ConfigRestored, "anna"), (e.Action, e.UserName)));
        Assert.StartsWith("Originally stored by bob at ", added[0].Details, StringComparison.Ordinal);
        Assert.EndsWith(": other two", added[0].Details, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Other_events_are_recorded_and_filtered()
    {
        await Store.InitializeAsync(Ct);
        await Store.SaveAsync(Config(), Frank, null, Ct);
        await Audit.RecordAsync(AuditCategory.SignIn, AuditActions.SignedIn, new AuditActor("Anna", null, "admin UI"), "Signed in.", cancellationToken: Ct);
        await Audit.RecordAsync(AuditCategory.Security, AuditActions.PasswordChanged, Frank, "Password changed.", cancellationToken: Ct);

        async Task<List<string>> ActionsAsync(AuditFilter filter) =>
            [.. (await Audit.ReadPageAsync(filter, null, null, 50, Ct)).Items.Select(e => e.Action)];

        Assert.Equal([AuditActions.PasswordChanged, AuditActions.SignedIn, AuditActions.ConfigSaved], await ActionsAsync(new AuditFilter()));
        Assert.Equal([AuditActions.SignedIn], await ActionsAsync(new AuditFilter { Category = AuditCategory.SignIn }));
        Assert.Equal([AuditActions.SignedIn], await ActionsAsync(new AuditFilter { UserName = "anna" }));
        Assert.Equal([AuditActions.ConfigSaved], await ActionsAsync(new AuditFilter { Version = 1 }));
        Assert.Equal(["Anna", "frank"], await Audit.GetUserNamesAsync(Ct));
    }

    [Fact]
    public async Task Long_values_are_cut_to_fit()
    {
        await Store.InitializeAsync(Ct);

        var entry = await Audit.RecordAsync(
            AuditCategory.Maintenance, AuditActions.LogsCleaned, Frank, new string('s', 1000), new string('d', 10_000), Ct);

        Assert.Equal(AuditEntry.MaxSummaryLength, entry.Summary.Length);
        Assert.Equal(AuditEntry.MaxDetailsLength, entry.Details!.Length);
        Assert.EndsWith("…", entry.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Pages_go_back_and_forth_by_id()
    {
        await Store.InitializeAsync(Ct);
        for (var i = 1; i <= 7; i++)
        {
            await Audit.RecordAsync(AuditCategory.SignIn, AuditActions.SignedIn, Frank, $"#{i}", cancellationToken: Ct);
        }

        static string Summaries(AuditPage page) => string.Join(",", page.Items.Select(e => e.Summary));

        var newest = await Audit.ReadPageAsync(new AuditFilter(), null, null, 3, Ct);
        Assert.Equal(("#7,#6,#5", true, false), (Summaries(newest), newest.HasOlder, newest.HasNewer));

        var older = await Audit.ReadPageAsync(new AuditFilter(), newest.Items[^1].Id, null, 3, Ct);
        Assert.Equal(("#4,#3,#2", true, true), (Summaries(older), older.HasOlder, older.HasNewer));

        var oldest = await Audit.ReadPageAsync(new AuditFilter(), older.Items[^1].Id, null, 3, Ct);
        Assert.Equal(("#1", false, true), (Summaries(oldest), oldest.HasOlder, oldest.HasNewer));

        var back = await Audit.ReadPageAsync(new AuditFilter(), null, oldest.Items[0].Id, 3, Ct);
        Assert.Equal(("#4,#3,#2", true, true), (Summaries(back), back.HasOlder, back.HasNewer));
    }

    [Fact]
    public async Task Upgrading_an_existing_database_records_its_versions_in_the_audit_log()
    {
        // A database from before the audit log, with two versions.
        await using (var db = await ContextAsync())
        {
            await db.GetService<IMigrator>().MigrateAsync("20261122155302_AddAppSettingsFingerprint", Ct);
            var json = GatewayConfigurationJson.Serialize(Config());
            await db.Database.ExecuteSqlAsync(
                $"INSERT INTO ConfigurationVersions (CreatedAtUtc, Author, Comment, SchemaVersion, Json, Sha256) VALUES ('2026-11-01 08:00:00', 'appsettings import', NULL, 1, {json}, {new string('a', 64)})",
                Ct);
            await db.Database.ExecuteSqlAsync(
                $"INSERT INTO ConfigurationVersions (CreatedAtUtc, Author, Comment, SchemaVersion, Json, Sha256) VALUES ('2026-11-02 09:00:00', 'admin UI', 'Route added.', 1, {json}, {new string('b', 64)})",
                Ct);
        }

        await Store.InitializeAsync(Ct);

        var entries = await AllAsync();
        Assert.Equal([1L, 2L], entries.Select(e => e.ConfigurationVersionId!.Value));
        Assert.Equal(["Version 1: configuration changed.", "Version 2: Route added."], entries.Select(e => e.Summary));
        Assert.Equal(["appsettings import", "admin UI"], entries.Select(e => e.UserName));
        Assert.All(entries, e => Assert.Equal((AuditCategory.Configuration, AuditActions.ConfigBackfilled), (e.Category, e.Action)));
        Assert.Equal(new DateTime(2026, 11, 2, 9, 0, 0), entries[1].TimestampUtc);
    }
}
