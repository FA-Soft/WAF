using Waf.Core.Configuration;
using Waf.Engine.Detection;
using Waf.Engine.RateLimiting;

namespace Waf.Engine;

/// <summary>
/// Everything the WAF needs to judge a request, built from one configuration: rules, rate limits and
/// attack detection. Immutable; replaced as a whole via <see cref="WafEngineHolder"/>, so a request is
/// always judged by one consistent configuration.
/// </summary>
public sealed class WafEngine
{
    private WafEngine(CompiledRuleSet rules, RateLimiter rateLimiter, AttackDetector detector, bool detectionOnly)
    {
        Rules = rules;
        RateLimiter = rateLimiter;
        Detector = detector;
        DetectionOnly = detectionOnly;
    }

    public CompiledRuleSet Rules { get; }

    public RateLimiter RateLimiter { get; }

    public AttackDetector Detector { get; }

    /// <summary>Global detection-only mode: blocks are logged, not enforced.</summary>
    public bool DetectionOnly { get; }

    /// <exception cref="ArgumentException">The configuration is not valid.</exception>
    public static WafEngine Build(GatewayConfiguration configuration, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return new WafEngine(
            CompiledRuleSet.Compile(configuration),
            new RateLimiter(configuration, timeProvider),
            new AttackDetector(configuration.Settings.AttackDetection),
            configuration.Settings.DetectionOnly);
    }
}

/// <summary>
/// Holds the active <see cref="WafEngine"/>. When no engine is active (not built yet, or marked
/// unavailable after a failure) public traffic must be refused: the gateway fails closed.
/// </summary>
public sealed class WafEngineHolder
{
    private State _state = new(null, "The WAF engine has not been started yet.");

    /// <summary>The active engine, or null when the WAF is unavailable.</summary>
    public WafEngine? Current => Volatile.Read(ref _state).Engine;

    /// <summary>Why the WAF is unavailable; null while an engine is active.</summary>
    public string? UnavailableReason => Volatile.Read(ref _state).Reason;

    /// <summary>Activates <paramref name="engine"/>.</summary>
    public void Activate(WafEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);
        Volatile.Write(ref _state, new State(engine, null));
    }

    /// <summary>Takes the engine out of service: from now on public traffic gets 503.</summary>
    public void MarkUnavailable(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        Volatile.Write(ref _state, new State(null, reason));
    }

    private sealed record State(WafEngine? Engine, string? Reason);
}
