using System.Text;
using Anthropic;
using Anthropic.Exceptions;
using Anthropic.Models.Beta;
using Anthropic.Models.Beta.Messages;

namespace FASoft.Waf.Ai;

/// <summary>
/// Anthropic Claude through the official Anthropic SDK. One request per question: the fixed instructions as the system
/// prompt, and the sanitized configuration summary plus the administrator's prompt as the user message.
/// </summary>
/// <remarks>
/// Uses Claude Opus 5.5 with adaptive thinking (always on for this model) at high effort: configuration changes are
/// worth thinking about. Server-side refusal fallback is enabled, so a request a safety classifier declines is answered
/// by a fallback model within the same call instead of failing.
/// </remarks>
public sealed class AnthropicAiProvider : IAiProvider, IDisposable
{
    /// <summary>The model used unless another is given.</summary>
    public const string DefaultModel = "claude-opus-5-5";

    private const int MaxOutputTokens = 16_000;

    private readonly AnthropicClient _client;

    /// <param name="apiKey">The Anthropic API key (from the gateway's encrypted settings).</param>
    /// <param name="httpClient">HTTP client to use (tests, proxies); a default one when null.</param>
    /// <param name="model">Model ID.</param>
    public AnthropicAiProvider(string apiKey, HttpClient? httpClient = null, string model = DefaultModel)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(model);

        Model = model;
        _client = httpClient is null
            ? new AnthropicClient { ApiKey = apiKey }
            : new AnthropicClient { ApiKey = apiKey, HttpClient = httpClient };
    }

    public string Name => "Anthropic Claude";

    public string Model { get; }

    public async Task<AiCompletion> CompleteAsync(AiRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var parameters = new MessageCreateParams
        {
            Model = Model,
            MaxTokens = MaxOutputTokens,
            Betas = [AnthropicBeta.ServerSideFallback2026_07_01],
            Fallbacks = new Default(),
            OutputConfig = new BetaOutputConfig { Effort = Effort.High },
            System = request.Instructions,
            Messages =
            [
                new BetaUserMessageParam { Content = UserMessage(request) },
            ],
        };

        BetaMessage response;
        try
        {
            response = await _client.Beta.Messages.Create(parameters, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (Translate(ex) is { } translated)
        {
            throw translated;
        }

        if (response.StopReason == "refusal")
        {
            throw new AiProviderException(AiFailure.Refused, "The model declined to answer this request. Rephrase it as a configuration change.");
        }

        var text = new StringBuilder();
        foreach (var block in response.Content)
        {
            if (block.TryPickText(out var part))
            {
                text.Append(part.Text);
            }
        }

        return new AiCompletion(text.ToString(), response.Model, response.Usage.InputTokens, response.Usage.OutputTokens);
    }

    public async Task CheckAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _client.Models.Retrieve(Model, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (Translate(ex) is { } translated)
        {
            throw translated;
        }
    }

    /// <summary>The user message: the sanitized configuration, then the administrator's request.</summary>
    public static string UserMessage(AiRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return $"""
            The gateway's current configuration (a sanitized summary; secret values are replaced by "{Core.Configuration.ConfigurationSecrets.Placeholder}"):
            <configuration>
            {request.Configuration}
            </configuration>

            The administrator's request:
            <request>
            {request.Prompt}
            </request>
            """;
    }

    /// <summary>SDK errors as <see cref="AiProviderException"/> with a plain-language message; null for anything else.</summary>
    private static AiProviderException? Translate(Exception ex) => ex switch
    {
        AnthropicUnauthorizedException or AnthropicForbiddenException =>
            new AiProviderException(AiFailure.InvalidKey, "Anthropic did not accept the API key. Check it under AI assistant.", ex),
        AnthropicRateLimitException =>
            new AiProviderException(AiFailure.RateLimited, "Anthropic's rate limit was reached. Try again in a minute.", ex),
        Anthropic5xxException or AnthropicIOException or HttpRequestException or TaskCanceledException { InnerException: TimeoutException } =>
            new AiProviderException(AiFailure.Unavailable, "Anthropic could not be reached or is overloaded. Try again later.", ex),
        AnthropicApiException =>
            new AiProviderException(AiFailure.Failed, $"Anthropic returned an error: {ex.Message}", ex),
        _ => null,
    };

    public void Dispose() => _client.Dispose();
}
