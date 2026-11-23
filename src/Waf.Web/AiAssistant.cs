using FASoft.Waf.Ai;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>Creates the provider for a stored key (replaceable in tests).</summary>
public interface IAiProviderFactory
{
    /// <summary>The provider called <paramref name="provider"/> using <paramref name="apiKey"/>.</summary>
    IAiProvider Create(string provider, string apiKey);
}

/// <summary>The built-in providers: Anthropic Claude.</summary>
/// <param name="anthropicBaseUrl">Another address for Anthropic's API (an API gateway of your own); null for Anthropic's.</param>
public sealed class AiProviderFactory(Uri? anthropicBaseUrl = null) : IAiProviderFactory
{
    /// <summary>The setting with another address for Anthropic's API.</summary>
    public const string AnthropicBaseUrlSetting = "Gateway:Ai:AnthropicBaseUrl";

    public IAiProvider Create(string provider, string apiKey) => provider switch
    {
        AiAssistant.AnthropicProvider => new AnthropicAiProvider(apiKey, baseUrl: anthropicBaseUrl),
        _ => throw new ArgumentException($"Unknown AI provider '{provider}'.", nameof(provider)),
    };
}

/// <summary>
/// The AI features: off until an API key is saved, and then the only place a provider is created.
/// Without a key, <see cref="CreateProviderAsync"/> returns null, so no code path can send anything.
/// A request becomes a stored proposal; only an explicit approval applies it (as a new configuration version), and an
/// applied proposal can be undone by rolling back to the version it was made for.
/// </summary>
public sealed class AiAssistant(
    AiSettingsStore store, AiProposalStore proposals, IAiProviderFactory providers, IGatewayConfigurationService configurations, AuditLogStore audit)
{
    public const string AnthropicProvider = "anthropic";

    /// <summary>The source of configuration changes approved from a proposal, in versions and the audit log.</summary>
    public const string AuditSource = "AI assistant";

    /// <summary>One request at a time: a second click never sends (and pays for) the same request twice.</summary>
    private int _asking;

    /// <summary>The configured provider (never the key); null when the AI features are off.</summary>
    public Task<AiSettingsInfo?> GetStatusAsync(CancellationToken cancellationToken) => store.GetAsync(cancellationToken);

    /// <summary>A provider for the stored key, to be disposed by the caller; null when no key is configured.</summary>
    public async Task<IAiProvider?> CreateProviderAsync(CancellationToken cancellationToken)
    {
        var key = await store.GetKeyAsync(cancellationToken).ConfigureAwait(false);
        return key is { } stored ? providers.Create(stored.Provider, stored.ApiKey) : null;
    }

    /// <summary>Why <paramref name="apiKey"/> cannot be an Anthropic API key; empty when it looks right.</summary>
    public static IReadOnlyList<string> CheckKeyFormat(string? apiKey) =>
        string.IsNullOrWhiteSpace(apiKey) ? ["Enter the API key."]
        : apiKey.Any(char.IsWhiteSpace) ? ["The key contains spaces or line breaks; paste it again."]
        : !apiKey.StartsWith("sk-ant-", StringComparison.Ordinal) || apiKey.Length < 20
            ? ["This does not look like an Anthropic API key (they start with sk-ant-). Create one in the Anthropic Console."]
            : [];

    /// <summary>Saves the key (encrypted) and turns the AI features on; returns why not otherwise.</summary>
    public async Task<IReadOnlyList<string>> SaveKeyAsync(string? apiKey, AuditActor actor, CancellationToken cancellationToken)
    {
        var problems = CheckKeyFormat(apiKey);
        if (problems.Count > 0)
        {
            return problems;
        }

        await store.SaveAsync(AnthropicProvider, apiKey!.Trim(), actor.UserName, cancellationToken).ConfigureAwait(false);
        await audit.RecordAsync(AuditCategory.Security, AuditActions.AiKeySaved, actor,
            $"AI assistant API key saved (Anthropic, ending in {apiKey[^4..]}).", cancellationToken: cancellationToken).ConfigureAwait(false);
        return [];
    }

    /// <summary>Removes the key: the AI features are off again.</summary>
    public async Task RemoveKeyAsync(AuditActor actor, CancellationToken cancellationToken)
    {
        if (await store.RemoveAsync(cancellationToken).ConfigureAwait(false))
        {
            await audit.RecordAsync(AuditCategory.Security, AuditActions.AiKeyRemoved, actor,
                "AI assistant API key removed; the AI features are off.", cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Checks the stored key with the provider (free: no model call). Null when it works; the reason otherwise.</summary>
    public async Task<string?> CheckKeyAsync(CancellationToken cancellationToken)
    {
        using var provider = await CreateProviderAsync(cancellationToken).ConfigureAwait(false);
        if (provider is null)
        {
            return "No API key is configured.";
        }

        try
        {
            await provider.CheckAsync(cancellationToken).ConfigureAwait(false);
            return null;
        }
        catch (AiProviderException ex)
        {
            return ex.Message;
        }
    }

    /// <summary>The newest proposals first.</summary>
    public Task<IReadOnlyList<AiProposal>> RecentProposalsAsync(int count, CancellationToken cancellationToken) =>
        proposals.ListRecentAsync(count, cancellationToken);

    public Task<AiProposal?> GetProposalAsync(long id, CancellationToken cancellationToken) => proposals.GetAsync(id, cancellationToken);

    /// <summary>
    /// Checks <paramref name="proposal"/> (the model's sections) against <paramref name="running"/>: only allowed sections,
    /// then read as strictly as an imported file (unknown properties, wrong types, nulls), secrets kept by placeholder
    /// filled in, and the complete configuration validated. A proposal that changes nothing is refused too.
    /// </summary>
    public static ProposalReview Review(string? proposal, GatewayConfiguration running)
    {
        ArgumentNullException.ThrowIfNull(running);
        var merged = ConfigurationProposal.Merge(proposal, running);
        if (merged.Json is null)
        {
            return new ProposalReview(null, merged.Errors, []);
        }

        var preview = ConfigurationImport.Preview(merged.Json, running);
        if (preview.Candidate is null)
        {
            return new ProposalReview(null, preview.Errors, []);
        }

        return preview.Changes.Count == 0
            ? new ProposalReview(null, ["The proposal does not change anything."], [])
            : new ProposalReview(preview.Candidate, [], preview.Changes);
    }

    /// <summary>
    /// Sends <paramref name="prompt"/> with the configuration summary to the provider, checks the answer and stores it as a
    /// proposal (valid or not). Nothing is applied: approving is a separate step.
    /// </summary>
    public async Task<AiActionResult> AskAsync(string? prompt, AuditActor actor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (ConfigurationProposal.CheckPrompt(prompt) is { Count: > 0 } problems)
        {
            return new AiActionResult(problems);
        }

        if (Interlocked.CompareExchange(ref _asking, 1, 0) != 0)
        {
            return AiActionResult.Failed("The assistant is already working on a request. Wait for it to finish, then try again.");
        }

        try
        {
            using var provider = await CreateProviderAsync(cancellationToken).ConfigureAwait(false);
            if (provider is null)
            {
                return AiActionResult.Failed("The AI assistant is off: save an API key in the AI assistant settings first.");
            }

            var active = await configurations.GetActiveAsync(cancellationToken).ConfigureAwait(false);
            if (active is null)
            {
                return AiActionResult.Failed("No configuration is active yet.");
            }

            prompt = prompt!.Trim();
            await audit.RecordAsync(AuditCategory.Security, AuditActions.AiProposalRequested, actor,
                $"Request and configuration summary (version {active.Version}) sent to {provider.Name} ({provider.Model}).", prompt, cancellationToken).ConfigureAwait(false);

            AiCompletion completion;
            try
            {
                completion = await provider.CompleteAsync(ConfigurationProposal.Request(prompt, active.Configuration), cancellationToken).ConfigureAwait(false);
            }
            catch (AiProviderException ex)
            {
                return AiActionResult.Failed(ex.Message);
            }

            var proposal = new AiProposal
            {
                UserName = actor.UserName,
                Prompt = prompt,
                BaseVersion = active.Version,
                Model = completion.Model,
                InputTokens = completion.InputTokens,
                OutputTokens = completion.OutputTokens,
            };

            var answer = ConfigurationProposal.ReadAnswer(completion.Text);
            if (answer.Answer is null)
            {
                proposal.Status = AiProposalStatus.Invalid;
                proposal.Errors = string.Join('\n', answer.Errors);
                proposal.ProposalJson = completion.Text; // kept to show what came back
            }
            else if (answer.Answer.Configuration is null)
            {
                proposal.Status = AiProposalStatus.NoChange;
                proposal.Summary = answer.Answer.Summary;
            }
            else
            {
                var review = Review(answer.Answer.Configuration, active.Configuration);
                proposal.Status = review.Errors.Count == 0 ? AiProposalStatus.Ready : AiProposalStatus.Invalid;
                proposal.Errors = review.Errors.Count == 0 ? null : string.Join('\n', review.Errors);
                proposal.Summary = answer.Answer.Summary;
                proposal.ProposalJson = answer.Answer.Configuration;
            }

            return new AiActionResult([], await proposals.AddAsync(proposal, cancellationToken).ConfigureAwait(false));
        }
        finally
        {
            Volatile.Write(ref _asking, 0);
        }
    }

    /// <summary>
    /// Applies proposal <paramref name="id"/>: checked again, and activated only if the configuration it was made for is
    /// still the running one. Creates a configuration version (with its audit entry).
    /// </summary>
    public async Task<AiActionResult> ApproveAsync(long id, AuditActor actor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var (proposal, active, problem) = await LoadAsync(id, AiProposalStatus.Ready, cancellationToken).ConfigureAwait(false);
        if (problem is not null)
        {
            return AiActionResult.Failed(problem);
        }

        if (active!.Version != proposal!.BaseVersion)
        {
            return AiActionResult.Failed($"The configuration changed after this proposal was made (it was made for version {proposal.BaseVersion}; version {active.Version} is running now). Ask again.");
        }

        var review = Review(proposal.ProposalJson, active.Configuration);
        if (review.Candidate is null)
        {
            return new AiActionResult(review.Errors);
        }

        var summary = proposal.Summary.Length > 1800 ? proposal.Summary[..1800] + "…" : proposal.Summary;
        var result = await configurations.ActivateIfCurrentAsync(proposal.BaseVersion, review.Candidate, actor, $"AI proposal {proposal.Id}: {summary}", cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return new AiActionResult(result.Errors);
        }

        var version = result.Version!.Version;
        await proposals.DecideAsync(id, AiProposalStatus.Ready, AiProposalStatus.Applied, actor.UserName, version, null, cancellationToken).ConfigureAwait(false);
        return new AiActionResult([], id, version);
    }

    /// <summary>Undoes an applied proposal: a rollback to the version it was made for, if nothing changed since.</summary>
    public async Task<AiActionResult> UndoAsync(long id, AuditActor actor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var (proposal, active, problem) = await LoadAsync(id, AiProposalStatus.Applied, cancellationToken).ConfigureAwait(false);
        if (problem is not null)
        {
            return AiActionResult.Failed(problem);
        }

        if (active!.Version != proposal!.AppliedVersion)
        {
            return AiActionResult.Failed($"The configuration changed after this proposal was applied (version {active.Version} is running now). To undo it anyway, restore version {proposal.BaseVersion} on the history page.");
        }

        var result = await configurations.RollbackAsync(proposal.BaseVersion, active.Version, actor, cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return new AiActionResult(result.Errors);
        }

        var version = result.Version!.Version;
        await proposals.DecideAsync(id, AiProposalStatus.Applied, AiProposalStatus.Undone, actor.UserName, null, version, cancellationToken).ConfigureAwait(false);
        return new AiActionResult([], id, version);
    }

    /// <summary>Marks a proposal that was not applied as discarded.</summary>
    public async Task<AiActionResult> DiscardAsync(long id, AuditActor actor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var proposal = await proposals.GetAsync(id, cancellationToken).ConfigureAwait(false);
        if (proposal is null)
        {
            return AiActionResult.Failed("This proposal does not exist.");
        }

        if (proposal.Status is not (AiProposalStatus.Ready or AiProposalStatus.Invalid)
            || !await proposals.DecideAsync(id, proposal.Status, AiProposalStatus.Discarded, actor.UserName, null, null, cancellationToken).ConfigureAwait(false))
        {
            return AiActionResult.Failed("Only a proposal that was not applied can be discarded.");
        }

        await audit.RecordAsync(AuditCategory.Configuration, AuditActions.AiProposalDiscarded, actor,
            $"AI proposal {id} discarded without applying it.", proposal.Prompt, cancellationToken).ConfigureAwait(false);
        return new AiActionResult([], id);
    }

    /// <summary>Exactly what a provider would receive about the active configuration.</summary>
    public async Task<string> ConfigurationSummaryAsync(CancellationToken cancellationToken)
    {
        var active = await configurations.GetActiveAsync(cancellationToken).ConfigureAwait(false);
        return active is null ? "{}" : ConfigurationSummary.Create(active.Configuration);
    }

    private async Task<(AiProposal? Proposal, StoredConfiguration? Active, string? Problem)> LoadAsync(long id, AiProposalStatus expected, CancellationToken cancellationToken)
    {
        var proposal = await proposals.GetAsync(id, cancellationToken).ConfigureAwait(false);
        if (proposal is null)
        {
            return (null, null, "This proposal does not exist.");
        }

        if (proposal.Status != expected)
        {
            return (proposal, null, $"This proposal is {AiProposalText.Status(proposal.Status).ToLowerInvariant()}, so that cannot be done now.");
        }

        var active = await configurations.GetActiveAsync(cancellationToken).ConfigureAwait(false);
        return active is null ? (proposal, null, "No configuration is active yet.") : (proposal, active, null);
    }
}

/// <summary>Plain-language names of proposal statuses.</summary>
public static class AiProposalText
{
    public static string Status(AiProposalStatus status) => status switch
    {
        AiProposalStatus.Ready => "Waiting for review",
        AiProposalStatus.Invalid => "Rejected by the checks",
        AiProposalStatus.NoChange => "No change proposed",
        AiProposalStatus.Applied => "Applied",
        AiProposalStatus.Undone => "Undone",
        AiProposalStatus.Discarded => "Discarded",
        _ => status.ToString(),
    };

    /// <summary>The badge style of a status.</summary>
    public static string Badge(AiProposalStatus status) => status switch
    {
        AiProposalStatus.Ready => "badge-warning",
        AiProposalStatus.Applied => "badge-ok",
        AiProposalStatus.Invalid => "badge-danger",
        _ => "badge-muted",
    };
}

/// <summary>What a proposal would change in a configuration, after every check.</summary>
/// <param name="Candidate">The complete configuration that would become active; null when the proposal is refused.</param>
/// <param name="Errors">Why it is refused; empty when it can be approved.</param>
/// <param name="Changes">The differences with the running configuration.</param>
public sealed record ProposalReview(GatewayConfiguration? Candidate, IReadOnlyList<string> Errors, IReadOnlyList<ConfigurationChange> Changes);

/// <summary>Outcome of asking, approving, undoing or discarding.</summary>
/// <param name="Errors">Why it did not happen; empty on success.</param>
/// <param name="ProposalId">The proposal (asking).</param>
/// <param name="Version">The configuration version created (approving, undoing).</param>
public sealed record AiActionResult(IReadOnlyList<string> Errors, long? ProposalId = null, long? Version = null)
{
    public bool Succeeded => Errors.Count == 0;

    public static AiActionResult Failed(params string[] errors) => new(errors);
}

/// <summary>The API key form; the key is never sent back to the browser.</summary>
internal sealed class AiKeyFormModel
{
    public string? ApiKey { get; set; }
}

/// <summary>The request form of the assistant page.</summary>
internal sealed class AiPromptFormModel
{
    public string? Prompt { get; set; }
}
