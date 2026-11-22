using Waf.Core.Configuration;
using Waf.Data;
using Waf.Engine;
using Waf.Proxy;

namespace Waf.Host.Hosting;

/// <summary>Outcome of an activation or rollback.</summary>
/// <param name="Succeeded">True when the configuration is now active.</param>
/// <param name="Errors">Why it was rejected; empty on success.</param>
/// <param name="Version">The stored version that is now active; null on failure.</param>
internal sealed record ActivationResult(bool Succeeded, IReadOnlyList<string> Errors, StoredConfiguration? Version)
{
    internal static ActivationResult Failed(IEnumerable<string> errors) => new(false, [.. errors], null);
}

/// <summary>
/// Changes the running configuration safely. Every change is stored as a version; a configuration only
/// becomes active after it passed every check, and on any failure the running configuration stays as it was.
/// </summary>
/// <remarks>
/// Activation: validate → build the complete WAF engine → translate and validate the routes with YARP →
/// store the version → swap engine and routes → record it as last-known-good. Activations are serialized.
/// </remarks>
internal sealed partial class GatewayConfigurationService(
    ConfigurationStore store,
    WafEngineHolder engines,
    ProxyRouteUpdater routes,
    TimeProvider time,
    ILogger<GatewayConfigurationService> logger) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public void Dispose() => _gate.Dispose();

    /// <summary>Validates <paramref name="candidate"/> and, if everything checks out, makes it the running configuration.</summary>
    public async Task<ActivationResult> ActivateAsync(GatewayConfiguration candidate, string author, string? comment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentException.ThrowIfNullOrWhiteSpace(author);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // 1. Validate.
            var errors = GatewayConfigurationValidator.Validate(candidate);
            if (errors.Count > 0)
            {
                LogRejected(logger, author, errors.Count);
                return ActivationResult.Failed(errors);
            }

            // 2. Build everything before changing anything.
            WafEngine engine;
            try
            {
                engine = WafEngine.Build(candidate, time);
            }
            catch (ArgumentException ex)
            {
                return ActivationResult.Failed([$"The WAF engine could not be built: {ex.Message}"]);
            }

            var (prepared, routeErrors) = await routes.PrepareAsync(candidate.Routes).ConfigureAwait(false);
            if (prepared is null)
            {
                return ActivationResult.Failed(routeErrors);
            }

            // 3. Store, then 4. swap. Nothing is swapped if storing fails.
            var (stored, _) = await store.SaveIfChangedAsync(candidate, author, comment, cancellationToken).ConfigureAwait(false);
            routes.Apply(prepared);
            engines.Activate(engine);
            await store.SetLastKnownGoodAsync(stored.Version, cancellationToken).ConfigureAwait(false);

            LogActivated(logger, stored.Version, author);
            return new ActivationResult(true, [], stored);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Activates the configuration of an earlier version again. It is stored as a new version (history only
    /// grows) after the same checks as any other change.
    /// </summary>
    public async Task<ActivationResult> RollbackAsync(long version, string author, CancellationToken cancellationToken)
    {
        var previous = await store.GetAsync(version, cancellationToken).ConfigureAwait(false);
        if (previous is null)
        {
            return ActivationResult.Failed([$"Configuration version {version} does not exist."]);
        }

        return await ActivateAsync(previous.Configuration, author, $"Rollback to version {version}.", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The running configuration (last-known-good), or null if none was activated yet.</summary>
    public Task<StoredConfiguration?> GetActiveAsync(CancellationToken cancellationToken) =>
        store.GetLastKnownGoodAsync(cancellationToken);

    /// <summary>Stored versions, newest first.</summary>
    public Task<IReadOnlyList<StoredConfiguration>> GetHistoryAsync(int take, CancellationToken cancellationToken) =>
        store.GetHistoryAsync(take, cancellationToken);

    [LoggerMessage(EventId = 20, Level = LogLevel.Information, Message = "Configuration version {Version} activated by {Author}.")]
    private static partial void LogActivated(ILogger logger, long version, string author);

    [LoggerMessage(EventId = 21, Level = LogLevel.Warning, Message = "Configuration change by {Author} rejected with {ErrorCount} error(s); the running configuration is unchanged.")]
    private static partial void LogRejected(ILogger logger, string author, int errorCount);
}
