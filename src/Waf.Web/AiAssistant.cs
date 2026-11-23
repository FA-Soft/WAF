using FASoft.Waf.Ai;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>Creates the provider for a stored key (replaceable in tests).</summary>
public interface IAiProviderFactory
{
    /// <summary>The provider called <paramref name="provider"/> using <paramref name="apiKey"/>.</summary>
    IAiProvider Create(string provider, string apiKey);
}

/// <summary>The built-in providers: Anthropic Claude.</summary>
public sealed class AiProviderFactory : IAiProviderFactory
{
    public IAiProvider Create(string provider, string apiKey) => provider switch
    {
        AiAssistant.AnthropicProvider => new AnthropicAiProvider(apiKey),
        _ => throw new ArgumentException($"Unknown AI provider '{provider}'.", nameof(provider)),
    };
}

/// <summary>
/// The AI features' switch and settings: off until an API key is saved, and then the only place a provider is created.
/// Without a key, <see cref="CreateProviderAsync"/> returns null, so no code path can send anything.
/// </summary>
public sealed class AiAssistant(AiSettingsStore store, IAiProviderFactory providers, IGatewayConfigurationService configurations, AuditLogStore audit)
{
    public const string AnthropicProvider = "anthropic";

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

    /// <summary>Exactly what a provider would receive about the active configuration.</summary>
    public async Task<string> ConfigurationSummaryAsync(CancellationToken cancellationToken)
    {
        var active = await configurations.GetActiveAsync(cancellationToken).ConfigureAwait(false);
        return active is null ? "{}" : ConfigurationSummary.Create(active.Configuration);
    }
}

/// <summary>The API key form; the key is never sent back to the browser.</summary>
internal sealed class AiKeyFormModel
{
    public string? ApiKey { get; set; }
}
