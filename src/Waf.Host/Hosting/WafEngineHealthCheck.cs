using Microsoft.Extensions.Diagnostics.HealthChecks;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Reports Degraded (still HTTP 200, so the admin endpoint itself stays reachable) while the WAF engine is
/// unavailable and public traffic is being refused.
/// </summary>
internal sealed class WafEngineHealthCheck(WafEngineHolder engines) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(engines.Current is null
            ? HealthCheckResult.Degraded($"WAF engine unavailable, public traffic is refused: {engines.UnavailableReason}")
            : HealthCheckResult.Healthy("WAF engine active."));
}
