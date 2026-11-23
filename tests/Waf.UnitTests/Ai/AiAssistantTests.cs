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

        /// <summary>What the provider answers; an exception to throw instead.</summary>
        public string Answer { get; set; } = string.Empty;

        public AiProviderException? Failure { get; set; }

        public List<AiRequest> Requests { get; } = [];

        public IAiProvider Create(string provider, string apiKey)
        {
            Created.Add((provider, apiKey));
            return new ScriptedProvider(this);
        }
    }

    private sealed class ScriptedProvider(RecordingFactory factory) : IAiProvider
    {
        public string Name => "test";

        public string Model => "test-model";

        public Task<AiCompletion> CompleteAsync(AiRequest request, CancellationToken cancellationToken)
        {
            factory.Requests.Add(request);
            return factory.Failure is { } failure ? Task.FromException<AiCompletion>(failure) : Task.FromResult(new AiCompletion(factory.Answer, Model, 1000, 200));
        }

        public Task CheckAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public void Dispose()
        {
        }
    }

    /// <summary>Only <see cref="GetActiveAsync"/> is used by the assistant.</summary>
    private sealed class ActiveConfiguration(GatewayConfiguration configuration) : IGatewayConfigurationService
    {
        /// <summary>The running version; changing it stands for a change made by someone else.</summary>
        public long Version { get; set; } = 1;

        public Task<StoredConfiguration?> GetActiveAsync(CancellationToken cancellationToken) =>
            Task.FromResult<StoredConfiguration?>(new StoredConfiguration(Version, DateTime.UtcNow, "test", null, "sha", configuration));

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
        _proposals = AiProposalStore.Create(_paths, _time);
        _active = new ActiveConfiguration(configuration ?? new GatewayConfiguration());
        return (new AiAssistant(store, _proposals, _factory, _active, audit), audit);
    }

    private AiProposalStore _proposals = null!;

    private ActiveConfiguration _active = null!;

    private static string Answer(string summary, string configuration) =>
        new System.Text.Json.Nodes.JsonObject { ["summary"] = summary, ["configuration"] = configuration }.ToJsonString();

    [Fact]
    public async Task Asking_without_a_key_sends_nothing()
    {
        var (assistant, audit) = await CreateAsync();

        var result = await assistant.AskAsync("Turn on detection-only mode.", _actor, Ct);

        Assert.Contains("off", Assert.Single(result.Errors), StringComparison.Ordinal);
        Assert.Empty(_factory.Requests);
        Assert.Empty((await audit.ReadPageAsync(new AuditFilter(), null, null, 10, Ct)).Items);
    }

    [Fact]
    public async Task A_valid_answer_becomes_a_proposal_waiting_for_review()
    {
        var (assistant, audit) = await CreateAsync(RuleBuilder.Config());
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);
        _factory.Answer = Answer("Turns on detection-only mode.", """{"Settings":{"DetectionOnly":true}}""");

        var result = await assistant.AskAsync("  Turn on detection-only mode.  ", _actor, Ct);

        Assert.True(result.Succeeded);
        var request = Assert.Single(_factory.Requests);
        Assert.Equal(("Turn on detection-only mode.", ConfigurationProposal.ResponseSchema), (request.Prompt, request.ResponseSchema));
        var proposal = (await assistant.GetProposalAsync(result.ProposalId!.Value, Ct))!;
        Assert.Equal((AiProposalStatus.Ready, 1L, "alice", "Turns on detection-only mode.", 1000L, 200L),
            (proposal.Status, proposal.BaseVersion, proposal.UserName, proposal.Summary, proposal.InputTokens, proposal.OutputTokens));
        Assert.Null(proposal.AppliedVersion); // nothing is applied without approval

        var sent = (await audit.ReadPageAsync(new AuditFilter(), null, null, 10, Ct)).Items[0];
        Assert.Equal((AuditActions.AiProposalRequested, "Turn on detection-only mode."), (sent.Action, sent.Details));
    }

    [Fact]
    public async Task An_answer_that_fails_the_checks_is_kept_as_rejected()
    {
        var (assistant, _) = await CreateAsync(RuleBuilder.Config());
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);
        _factory.Answer = Answer("Adds a certificate.", """{"Certificates":[{"HostName":"x.example.com"}]}""");

        var result = await assistant.AskAsync("Add a certificate.", _actor, Ct);

        var proposal = (await assistant.GetProposalAsync(result.ProposalId!.Value, Ct))!;
        Assert.Equal(AiProposalStatus.Invalid, proposal.Status);
        Assert.Contains("'Certificates'", Assert.Single(proposal.ErrorList), StringComparison.Ordinal);
        Assert.False((await assistant.ApproveAsync(proposal.Id, _actor, Ct)).Succeeded);
    }

    [Theory]
    [InlineData("not json at all", AiProposalStatus.Invalid)]
    [InlineData("""{"summary":"Which route do you mean?","configuration":""}""", AiProposalStatus.NoChange)]
    public async Task Other_answers_are_kept_with_their_status(string answer, AiProposalStatus expected)
    {
        var (assistant, _) = await CreateAsync(RuleBuilder.Config());
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);
        _factory.Answer = answer;

        var result = await assistant.AskAsync("Change the route.", _actor, Ct);

        Assert.Equal(expected, (await assistant.GetProposalAsync(result.ProposalId!.Value, Ct))!.Status);
    }

    [Fact]
    public async Task A_provider_failure_is_explained_and_nothing_is_stored()
    {
        var (assistant, _) = await CreateAsync(RuleBuilder.Config());
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);
        _factory.Failure = new AiProviderException(AiFailure.RateLimited, "Anthropic's rate limit was reached.");

        var result = await assistant.AskAsync("Turn on detection-only mode.", _actor, Ct);

        Assert.Equal(["Anthropic's rate limit was reached."], result.Errors);
        Assert.Empty(await assistant.RecentProposalsAsync(10, Ct));
    }

    [Fact]
    public async Task A_proposal_for_an_older_version_is_not_applied()
    {
        var (assistant, _) = await CreateAsync(RuleBuilder.Config());
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);
        _factory.Answer = Answer("Detection only.", """{"Settings":{"DetectionOnly":true}}""");
        var id = (await assistant.AskAsync("Detection only.", _actor, Ct)).ProposalId!.Value;
        _active.Version = 2; // changed by someone else in between (activation would throw in this fake)

        var result = await assistant.ApproveAsync(id, _actor, Ct);

        Assert.Contains("changed after this proposal was made", Assert.Single(result.Errors), StringComparison.Ordinal);
        Assert.Equal(AiProposalStatus.Ready, (await assistant.GetProposalAsync(id, Ct))!.Status);
        Assert.False((await assistant.UndoAsync(id, _actor, Ct)).Succeeded); // not applied: nothing to undo
    }

    [Fact]
    public async Task A_discarded_proposal_cannot_be_approved()
    {
        var (assistant, _) = await CreateAsync(RuleBuilder.Config());
        await assistant.SaveKeyAsync(ApiKey, _actor, Ct);
        _factory.Answer = Answer("Detection only.", """{"Settings":{"DetectionOnly":true}}""");
        var id = (await assistant.AskAsync("Detection only.", _actor, Ct)).ProposalId!.Value;

        Assert.True((await assistant.DiscardAsync(id, _actor, Ct)).Succeeded);

        Assert.Equal(AiProposalStatus.Discarded, (await assistant.GetProposalAsync(id, Ct))!.Status);
        Assert.Contains("discarded", Assert.Single((await assistant.ApproveAsync(id, _actor, Ct)).Errors), StringComparison.Ordinal);
        Assert.False((await assistant.DiscardAsync(id, _actor, Ct)).Succeeded);
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
