using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.UnitTests.Engine;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Data;

/// <summary>Runs against a real SQLite database file in a temporary folder.</summary>
public sealed class ConfigurationStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly ManualTimeProvider _time = new();
    private readonly ServiceProvider _services;

    public ConfigurationStoreTests()
    {
        var paths = new StoragePaths(_directory, _directory);
        paths.EnsureDataDirectory();
        _services = new ServiceCollection()
            .AddSingleton<TimeProvider>(_time)
            .AddWafData(paths)
            .BuildServiceProvider();
        Store = _services.GetRequiredService<ConfigurationStore>();
    }

    private ConfigurationStore Store { get; }

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

    [Fact]
    public async Task Initialize_creates_the_database_with_all_migrations_applied()
    {
        await Store.InitializeAsync(Ct);

        Assert.True(File.Exists(Path.Combine(_directory, StoragePaths.ConfigDatabaseFileName)));
        await using var db = await ContextAsync();
        Assert.Empty(await db.Database.GetPendingMigrationsAsync(Ct));
        Assert.NotEmpty(await db.Database.GetAppliedMigrationsAsync(Ct));
    }

    [Fact]
    public async Task Migrations_match_the_model()
    {
        // Fails when the model was changed without adding a migration (dotnet ef migrations add ...).
        await using var db = await ContextAsync();

        Assert.False(db.Database.HasPendingModelChanges(), "The EF model has changes without a migration.");
    }

    [Fact]
    public async Task Initialize_twice_is_harmless_and_enables_write_ahead_logging()
    {
        await Store.InitializeAsync(Ct);
        await Store.InitializeAsync(Ct);

        await using var db = await ContextAsync();
        await db.Database.OpenConnectionAsync(Ct);
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "PRAGMA journal_mode;";
        Assert.Equal("wal", (string?)await command.ExecuteScalarAsync(Ct));
    }

    [Fact]
    public async Task Empty_database_has_no_latest_version()
    {
        await Store.InitializeAsync(Ct);

        Assert.Null(await Store.GetLatestAsync(Ct));
        Assert.Equal(0, await Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Saved_configuration_round_trips_with_metadata()
    {
        await Store.InitializeAsync(Ct);
        var configuration = Config(Rule("block-admin", RuleAction.Block, 10, When(ConditionField.Path, ConditionOperator.StartsWith, "/admin")));

        var saved = await Store.SaveAsync(configuration, "frank", "first version", Ct);
        var latest = await Store.GetLatestAsync(Ct);

        Assert.NotNull(latest);
        Assert.Equal(saved.Version, latest.Version);
        Assert.Equal(("frank", "first version"), (latest.Author, latest.Comment));
        Assert.Equal(_time.Now.UtcDateTime, latest.CreatedAtUtc);
        Assert.Equal(64, latest.Sha256.Length);
        Assert.Equal(GatewayConfigurationJson.Serialize(configuration), GatewayConfigurationJson.Serialize(latest.Configuration));
        Assert.Equal(latest.Version, (await Store.GetAsync(latest.Version, Ct))!.Version);
        Assert.Null(await Store.GetAsync(999, Ct));
    }

    [Fact]
    public async Task Every_save_adds_a_version()
    {
        await Store.InitializeAsync(Ct);

        var first = await Store.SaveAsync(Config(), "a", null, Ct);
        _time.Advance(TimeSpan.FromMinutes(1));
        var second = await Store.SaveAsync(Config(Rule("r", RuleAction.LogOnly, 1)), "b", null, Ct);

        Assert.True(second.Version > first.Version);
        Assert.Equal(2, await Store.CountAsync(Ct));
        Assert.Equal(second.Version, (await Store.GetLatestAsync(Ct))!.Version);
    }

    [Fact]
    public async Task Invalid_configuration_is_not_stored()
    {
        await Store.InitializeAsync(Ct);
        var invalid = Config(new WafRule { Name = "no-conditions" });

        var ex = await Assert.ThrowsAsync<ArgumentException>(() => Store.SaveAsync(invalid, "a", null, Ct));

        Assert.Contains("at least one condition", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, await Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Unchanged_configuration_is_not_stored_again()
    {
        await Store.InitializeAsync(Ct);

        var (first, created1) = await Store.SaveIfChangedAsync(Config(), "import", null, Ct);
        var (second, created2) = await Store.SaveIfChangedAsync(Config(), "import", null, Ct);
        var (third, created3) = await Store.SaveIfChangedAsync(Config(Rule("r", RuleAction.LogOnly, 1)), "import", null, Ct);

        Assert.Equal((true, false, true), (created1, created2, created3));
        Assert.Equal(first.Version, second.Version);
        Assert.NotEqual(first.Version, third.Version);
        Assert.Equal(2, await Store.CountAsync(Ct));
    }

    [Fact]
    public async Task Editor_schema_hint_does_not_count_as_a_change()
    {
        await Store.InitializeAsync(Ct);
        var withHint = Config();
        withHint.Schema = "./gateway-config.schema.json";

        await Store.SaveIfChangedAsync(Config(), "import", null, Ct);
        var (_, created) = await Store.SaveIfChangedAsync(withHint, "import", null, Ct);

        Assert.False(created);
        Assert.Equal("./gateway-config.schema.json", withHint.Schema); // caller's object is left as it was
    }

    [Fact]
    public async Task Unusable_database_file_is_reported_as_a_storage_error()
    {
        await File.WriteAllTextAsync(Path.Combine(_directory, StoragePaths.ConfigDatabaseFileName), "this is not a SQLite database", Ct);

        await Assert.ThrowsAsync<StorageInitializationException>(() => Store.InitializeAsync(Ct));
    }
}
