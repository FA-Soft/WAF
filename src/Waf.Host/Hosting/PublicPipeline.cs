using Waf.Proxy;

namespace Waf.Host.Hosting;

/// <summary>
/// Request pipeline for public traffic on the HTTP/HTTPS listeners.
/// The WAF rule engine is inserted between routing and the proxy in later milestones.
/// </summary>
internal static class PublicPipeline
{
    public static void Configure(WebApplication app)
    {
        // Pipeline step 2: real client IP (X-Forwarded-For honoured only from trusted proxies).
        app.UseClientIpResolution();

        // Explicit UseRouting *after* the admin MapWhen branch. Without it, WebApplication inserts routing
        // at the very start of the pipeline, a proxy route would be selected for admin requests too, and
        // the admin branch's own routing would then be skipped.
        app.UseRouting();

        // Rate limits (429). After routing, so per-route limits know the route.
        app.UseWafRateLimiting();

        // Requests that match no route fall through to the default 404.
        app.MapWafProxy();
    }
}
