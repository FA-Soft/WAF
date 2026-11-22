using Waf.Web;

namespace Waf.Host.Hosting;

/// <summary>
/// Request pipeline for the localhost admin listener: the Blazor admin UI (server-side rendered, enhanced
/// navigation and forms), its static files and the health endpoint.
/// </summary>
internal static class AdminPipeline
{
    /// <summary>
    /// Content-Security-Policy of the admin UI: only own scripts, styles and form targets; no framing. The UI
    /// uses no inline scripts or styles, so nothing needs to be relaxed.
    /// </summary>
    public const string ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
        "form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'";

    public static void Configure(IApplicationBuilder admin)
    {
        admin.Use((context, next) =>
        {
            var headers = context.Response.Headers;
            headers.ContentSecurityPolicy = ContentSecurityPolicy;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers.CacheControl = "no-store";
            return next(context);
        });

        admin.UseRouting();
        admin.UseAntiforgery();
        admin.UseEndpoints(endpoints =>
        {
            endpoints.MapStaticAssets();
            endpoints.MapHealthChecks("/healthz");
            endpoints.MapAdminDownloads();
            endpoints.MapLogEndpoints();
            endpoints.MapRazorComponents<App>();
        });
    }
}
