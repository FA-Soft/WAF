using FASoft.Waf.Ai;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.UnitTests.Engine;
using FASoft.Waf.Web;
using Microsoft.Data.Sqlite;

namespace FASoft.Waf.UnitTests.Ai;

/// <summary>The AI switch: off without a key, the key encrypted at rest, every change audited.</summary>
public sealed class AiAssistantTests : IDisposable
{
    private const string ApiKey = "sk-ant-api03-unit-test-key-WXYZ";

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly StoragePaths _paths;
    private readonly ManualTimeProvider _time = new();
    private readonly RecordingFactory _factory = new();
    private readonly AuditActor _actor = new("alice", "192.0.2.10", "admin UI");

    public AiAssistantTests()
    {
        _paths = new StoragePaths(_directory, _directory);
        _paths.EnsureDataDirectory();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, recursive: true);
    }

    /// <summary>Stands in for Data Protection: a reversible scramble, so stored bytes differ from the key.</summary>
    private sealed class ScramblingProtector : IApiKeyProtector
    {
        public byte[] Protect(byte[] plaintext) => [0xEE, .. plaintext.Select(b => (byte)(b ^ 0x5A))];

        public byte[] Unprotect(byte[] protectedData) => [.. protectedData.Skip(1).Select(b => (byte)(b ^ 0x5A))];
    }

    /// <summary>Records which providers were created; never calls anything.</summary>
    private sealed class RecordingFactory : IAiProviderFactory
    {
        public List<(string Provider, string ApiKey)> Created { get; } = [];

        public IAiProvider Create(string provider, string apiKey)
        {
            Created.Add((provider, apiKey));
            return new NullProvider();
        }
    }

    private sealed class NullProvider : IAiProvider
    {
        public string Name => "test";

        public string Model => "test-model";

        public Task<AiCompletion> CompleteAsync(AiRequest request, CancellationToken cancellationToken) =>
            Task.FromResult(new AiCompletion(string.Empty, Model, 0, 0));

        public Task CheckAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public void Dispose()
        {
        }
    }

    /// <summary>Only <see cref="GetActiveAsync"/> is used by the assistant.</summary>
    private sealed class ActiveConfiguration(GatewayConfiguration configuration) : IGatewayConfigurationService
    {
        public Task<StoredConfiguration?> GetActiveAsync(CancellationToken cancellationToken) =>
            Task.FromResult<StoredConfiguration?>(new StoredConfiguration(1, DateTime.UtcNow, "test", null, "sha", configuration));

        public Task<ActivationResult> ActivateAsync(GatewayConfiguration candidate, AuditActor actor, string? comment, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ActivationResult> ActivateIfCurrentAsync(long baseVersion, GatewayConfiguration candidate, AuditActor actor, string? comment, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ActivationResult> RollbackAsync(long version, long baseVersion, AuditActor actor, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<RestoreResult> RestoreBackupAsync(GatewayBackup backup, AuditActor actor, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<ActivationResult> ImportAppSettingsAsync(AuditActor actor, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task DismissAppSettingsAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private async Task<(AiAssistant Assistant, AuditLogStore Audit)> CreateAsync(GatewayConfiguration? configuration = null)
    {
        await ConfigurationStore.Create(_paths, _time).InitializeAsync(Ct);
        var audit = AuditLogStore.Create(_paths, _time);
        var store = AiSettingsStore.Create(_paths, new ScramblingProtector(), _time);
        return (new AiAssistant(store, _factory, new ActiveConfiguration(configuration ?? new GatewayConfiguration()), audit), audit);
    }

    [Fact]
    public async Task Without_a_key_everything_is_off_and_no_provider_is_created()
    {
        var (assistant, _) = await CreateAsync();

        Assert.Null(await assistant.GetStatusAsync(Ct));
        Assert.Null(await assistant.CreateProviderAsync(Ct));
        Assert.Equal("No API key is configured.", await assistant.CheckKeyAsync(Ct));
        Assert.Empty(_factory.Created);
    }

    [Fact]
    public async Task A_saved_key_turns_it_on_and_is_encrypted_at_rest()
    {
        var (assistant, audit) = await CreateAsync();

        Assert.Empty(await assistant.SaveKeyAsync(ApiKey, _actor, Ct));

        var status = await assistant.GetStatusAsync(Ct);
        Assert.Equal((AiAssistant.AnthropicProvider, "WXYZ", "alice"), (status!.Provider, status.KeyHint, status.UpdatedBy));
        using (var provider = await assistant.CreateProviderAsync(Ct))
        {
            Assert.NotNull(provider);
        }

        Assert.Equal((AiAssistant.AnthropicProvider, ApiKey), Assert.Single(_factory.Created));

        // Neither the database file nor its write-ahead log holds the key in clear text.
        SqliteConnection.ClearAllPools();
        foreach (var file in Directory.GetFiles(_directory, "config.db*"))
        {
            var bytes = await File.ReadAllBytesAsync(file, Ct);
            Assert.DoesNotContain(ApiKey, System.Text.Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
        }

        var entry = Assert.Single((await audit.ReadPageAsync(new AuditFilter(), null, null, 10, Ct)).Items);
        Assert.Equal((AuditActions.AiKeySaved, "alice"), (entry.Action, entry.UserName));
        Assert.DoesNotContain(ApiKey, entry.Summary, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null, "Enter the API key.")]
    [InlineData("  ", "Enter the API key.")]
    [InlineData("sk-ant-api03 with spaces", "spaces")]
    [InlineData("not-a-key-0000000000000000", "sk-ant-")]
    [InlineData("sk-ant-short", "sk-ant-")]
    public async Task A_malformed_key_is_refused_and_nothing_is_stored(string? key, string expected)
    {
        var (assistant, audit) = await CreateAsync();

        var problem = Assert.Single(await assistant.SaveKeyAsync(key, _actor, Ct));

        Assert.Contains(expected, problem, StringComparison.Ordinal);
        Assert.Null(await assistant.GetStatusAsync(Ct));
        Assert.Empty((await audit.ReadPageAsync(new AuditFilter(), null, null, 10, Ct)).Items);
    }

    [Fact]
    public async Task Removing_the_key_turns_it_off_again()
    {
        var (assistant, audit) = await CreateAsync();
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);

        await assistant.RemoveKeyAsync(_actor, Ct);
        await assistant.RemoveKeyAsync(_actor, Ct); // nothing left to remove: no second entry

        Assert.Null(await assistant.GetStatusAsync(Ct));
        Assert.Null(await assistant.CreateProviderAsync(Ct));
        var actions = (await audit.ReadPageAsync(new AuditFilter(), null, null, 10, Ct)).Items.Select(e => e.Action).ToList();
        Assert.Equal([AuditActions.AiKeyRemoved, AuditActions.AiKeySaved], actions);
    }

    [Fact]
    public async Task Replacing_the_key_keeps_one_setting()
    {
        var (assistant, _) = await CreateAsync();
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);

        await assistant.SaveKeyAsync("sk-ant-api03-another-key-ABCD", _actor, Ct);

        Assert.Equal("ABCD", (await assistant.GetStatusAsync(Ct))!.KeyHint);
        using var provider = await assistant.CreateProviderAsync(Ct);
        Assert.Equal("sk-ant-api03-another-key-ABCD", _factory.Created.Last().ApiKey);
    }

    [Fact]
    public async Task The_shown_summary_is_the_sanitized_one()
    {
        var configuration = RuleBuilder.Config(new WafRule
        {
            Name = "require-key",
            Conditions = { new RuleCondition { Field = ConditionField.Header, HeaderName = "X-Api-Key", Operator = ConditionOperator.Equals, Values = { "hidden-value-42" } } },
        });
        var (assistant, _) = await CreateAsync(configuration);

        var summary = await assistant.ConfigurationSummaryAsync(Ct);

        Assert.Equal(ConfigurationSummary.Create(configuration), summary);
        Assert.DoesNotContain("hidden-value-42", summary, StringComparison.Ordinal);
    }
}
