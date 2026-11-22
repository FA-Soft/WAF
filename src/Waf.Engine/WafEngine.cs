using Waf.Core.Configuration;
using Waf.Core.Net;
using Waf.Engine.Detection;
using Waf.Engine.RateLimiting;

namespace Waf.Engine;

/// <summary>
/// Everything the WAF needs to judge a request, built from one configuration: trusted proxies, rules,
/// rate limits and attack detection. Immutable; replaced as a whole via <see cref="WafEngineHolder"/>, so a
/// request is always judged by one consistent configuration.
/// </summary>
public sealed class WafEngine
{
    private WafEngine(string configTag, CompiledRuleSet rules, RateLimiter rateLimiter, AttackDetector detector, TrustedProxies trustedProxies, bool detectionOnly)
    {
        ConfigTag = configTag;
        Rules = rules;
        TrustedProxies = trustedProxies;
        RateLimiter = rateLimiter;
        Detector = detector;
        DetectionOnly = detectionOnly;
    }

    /// <summary>
    /// Identifies the configuration this engine was built from. The proxy routes of the same configuration
    /// carry the same tag, so a request can be judged by the engine that matches the routes it was routed by.
    /// </summary>
    public string ConfigTag { get; }

    public CompiledRuleSet Rules { get; }

    public RateLimiter RateLimiter { get; }

    public AttackDetector Detector { get; }

    /// <summary>Proxies allowed to report the client IP (X-Forwarded-For).</summary>
    public TrustedProxies TrustedProxies { get; }

    /// <summary>Global detection-only mode: blocks are logged, not enforced.</summary>
    public bool DetectionOnly { get; }

    /// <exception cref="ArgumentException">The configuration is not valid.</exception>
    public static WafEngine Build(GatewayConfiguration configuration, TimeProvider? timeProvider = null, string configTag = "")
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(configTag);

        return new WafEngine(
            configTag,
            CompiledRuleSet.Compile(configuration),
            new RateLimiter(configuration, timeProvider),
            new AttackDetector(configuration.Settings.AttackDetection),
            TrustedProxies.Parse(configuration.Settings.TrustedProxies),
            configuration.Settings.DetectionOnly);
    }
}

/// <summary>
/// Holds the active <see cref="WafEngine"/>, and the previous one for requests that were routed just before
/// a swap. When no engine is active (not built yet, or marked unavailable after a failure) public traffic
/// must be refused: the gateway fails closed.
/// </summary>
public sealed class WafEngineHolder
{
    private State _state = new(null, null, "The WAF engine has not been started yet.");

    /// <summary>The active engine, or null when the WAF is unavailable.</summary>
    public WafEngine? Current => Volatile.Read(ref _state).Engine;

    /// <summary>Why the WAF is unavailable; null while an engine is active.</summary>
    public string? UnavailableReason => Volatile.Read(ref _state).Reason;

    /// <summary>
    /// The engine built from the configuration with <paramref name="configTag"/> (the active or the previous
    /// one); the active engine when the tag is unknown or null (e.g. no route matched). Null while unavailable.
    /// </summary>
    public WafEngine? Resolve(string? configTag)
    {
        var state = Volatile.Read(ref _state);
        if (state.Engine is null)
        {
            return null;
        }

        return configTag is not null && state.Previous is { } previous && previous.ConfigTag == configTag && state.Engine.ConfigTag != configTag
            ? previous
            : state.Engine;
    }

    /// <summary>Activates <paramref name="engine"/>; the engine it replaces stays available via <see cref="Resolve"/>.</summary>
    public void Activate(WafEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);

        var current = Volatile.Read(ref _state).Engine;
        Volatile.Write(ref _state, new State(engine, current, null));
    }

    /// <summary>Takes the engine out of service: from now on public traffic gets 503.</summary>
    public void MarkUnavailable(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        Volatile.Write(ref _state, new State(null, null, reason));
    }

    private sealed record State(WafEngine? Engine, WafEngine? Previous, string? Reason);
}
