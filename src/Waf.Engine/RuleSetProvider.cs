namespace FASoft.Waf.Engine;

/// <summary>
/// Holds the active <see cref="CompiledRuleSet"/> and swaps it atomically. Readers take one snapshot per
/// request via <see cref="Current"/>, so a request is never evaluated against a half-updated set.
/// </summary>
public sealed class RuleSetProvider(CompiledRuleSet initial)
{
    private CompiledRuleSet _current = initial ?? throw new ArgumentNullException(nameof(initial));

    /// <summary>The active rule set.</summary>
    public CompiledRuleSet Current => Volatile.Read(ref _current);

    /// <summary>Activates <paramref name="next"/> and returns the previously active set.</summary>
    public CompiledRuleSet Swap(CompiledRuleSet next)
    {
        ArgumentNullException.ThrowIfNull(next);
        return Interlocked.Exchange(ref _current, next);
    }

    /// <summary>Evaluates <paramref name="request"/> against the active rule set.</summary>
    public WafDecision Evaluate(IWafRequest request) => Current.Evaluate(request);
}
