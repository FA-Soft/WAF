namespace FASoft.Waf.Ai;

/// <summary>
/// A language model that helps with the gateway configuration. Pluggable: the gateway uses one provider at a time, and
/// none at all until an API key is configured (the AI features are then fully off: no provider exists, nothing is sent).
/// </summary>
/// <remarks>
/// A provider only ever receives what is in <see cref="AiRequest"/>: fixed instructions, the administrator's own prompt
/// and a <see cref="ConfigurationSummary"/> - never request bodies, cookies, secrets or log content.
/// </remarks>
public interface IAiProvider : IDisposable
{
    /// <summary>Display name, e.g. "Anthropic Claude".</summary>
    string Name { get; }

    /// <summary>The model used, e.g. <c>claude-opus-5-5</c>.</summary>
    string Model { get; }

    /// <summary>Sends <paramref name="request"/> and returns the model's answer.</summary>
    /// <exception cref="AiProviderException">The provider refused or failed; the message says why, in plain language.</exception>
    Task<AiCompletion> CompleteAsync(AiRequest request, CancellationToken cancellationToken);

    /// <summary>Checks that the API key works, without using the model (no cost).</summary>
    /// <exception cref="AiProviderException">The key is not accepted or the provider cannot be reached.</exception>
    Task CheckAsync(CancellationToken cancellationToken);
}

/// <summary>Everything a provider receives for one question.</summary>
/// <param name="Instructions">Fixed instructions of the gateway (the system prompt).</param>
/// <param name="Prompt">What the administrator typed.</param>
/// <param name="Configuration">The sanitized configuration summary (<see cref="ConfigurationSummary.Create"/>).</param>
/// <param name="ResponseSchema">
/// A JSON schema the answer must follow (structured output), as JSON; null for free text. The answer is still checked
/// by the caller: a schema only shapes it.
/// </param>
public sealed record AiRequest(string Instructions, string Prompt, string Configuration, string? ResponseSchema = null);

/// <summary>The model's answer.</summary>
public sealed record AiCompletion(string Text, string Model, long InputTokens, long OutputTokens);

/// <summary>Why a provider call failed.</summary>
public enum AiFailure
{
    /// <summary>The API key is wrong, revoked or lacks access.</summary>
    InvalidKey,

    /// <summary>Too many requests or tokens: try again later.</summary>
    RateLimited,

    /// <summary>The provider cannot be reached or is overloaded.</summary>
    Unavailable,

    /// <summary>The model declined to answer.</summary>
    Refused,

    /// <summary>The answer was cut off (too long).</summary>
    Incomplete,

    /// <summary>Any other error.</summary>
    Failed,
}

/// <summary>A provider call that failed, with a message for the administrator.</summary>
public sealed class AiProviderException : Exception
{
    public AiProviderException()
    {
    }

    public AiProviderException(string message)
        : base(message)
    {
    }

    public AiProviderException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public AiProviderException(AiFailure failure, string message, Exception? innerException = null)
        : base(message, innerException) => Failure = failure;

    public AiFailure Failure { get; } = AiFailure.Failed;
}
