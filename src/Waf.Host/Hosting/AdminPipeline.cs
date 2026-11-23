using FASoft.Waf.Web;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Request pipeline for the localhost admin listener: the Blazor admin UI (server-side rendered, enhanced
/// navigation and forms), its static files and the health endpoint. The UI needs a signed-in admin account;
/// static files and the health endpoint do not.
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
            headers.CacheControl = "no-cache, no-store"; // as antiforgery requires; nothing of the UI is cached
            return next(context);
        });

        admin.UseRouting();
        admin.UseAuthentication();
        admin.UseAuthorization();
        admin.UseAntiforgery();
        admin.UseEndpoints(endpoints =>
        {
            endpoints.MapStaticAssets();
            endpoints.MapHealthChecks("/healthz");
            endpoints.MapAdminAccountEndpoints();

            // Everything else needs a signed-in admin; only the sign-in and first-run pages are marked [AllowAnonymous].
            var signedIn = endpoints.MapGroup(string.Empty).RequireAuthorization();
            signedIn.MapAdminDownloads();
            signedIn.MapLogEndpoints();
            endpoints.MapRazorComponents<App>().RequireAuthorization();
        });
    }
}
