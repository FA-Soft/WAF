using Waf.Proxy;

namespace Waf.Host.Hosting;

/// <summary>
/// Request pipeline for public traffic on the HTTP/HTTPS listeners. The admin listener is branched off
/// before this pipeline (see <see cref="GatewayApplication"/>), so none of these steps apply to it.
/// </summary>
/// <remarks>
/// Fail-closed: a request only reaches the proxy after the WAF has judged it; without an active WAF
/// engine, or when judging fails, the request gets 503.
/// </remarks>
internal static class PublicPipeline
{
    public static void Configure(WebApplication app)
    {
        // 0. Request log: every public request, also those answered below (queued, never delays the request).
        app.UseRequestLogging();

        // 1. ACME HTTP-01 challenges: only stored tokens, works even while the WAF is unavailable.
        app.UseAcmeChallenges();

        // 2. Real client IP (X-Forwarded-For honoured only from trusted proxies).
        app.UseClientIpResolution();

        // 3. Fail-closed guard: 503 while no WAF engine is active.
        app.UseFailClosedGuard();

        // Routing selects the proxy route, so the WAF knows the route name. Explicit UseRouting *after* the
        // admin MapWhen branch: otherwise WebApplication inserts routing at the very start of the pipeline,
        // a proxy route would be selected for admin requests too and the admin branch's routing skipped.
        app.UseRouting();

        // 4. WAF: rules (403), rate limits (429), attack detection (403); 503 on any evaluation failure.
        app.UseWaf();

        // 5. HTTPS redirect / HSTS: added with TLS support (issue #67).

        // 6. Reverse proxy. Requests that match no route fall through to the default 404.
        app.MapWafProxy();

        // Security events also go to IWafEventSink (the application log); every request ends up in events.db.
    }
}
