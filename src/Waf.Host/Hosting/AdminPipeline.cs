using FASoft.Waf.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Request pipeline of the admin UI, for the localhost admin listener and for remote admin access: the Blazor admin UI (server-side rendered, enhanced
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

    /// <summary>Browser features the admin UI never uses, switched off for it.</summary>
    public const string PermissionsPolicy =
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()";

    /// <summary>
    /// HSTS for remote admin access (HTTPS only): a browser that has seen it never tries plain HTTP for the admin host
    /// name again, for a year. Not for subdomains: other sites may run under them.
    /// </summary>
    public const string StrictTransportSecurity = "max-age=31536000";

    public static void Configure(IApplicationBuilder admin)
    {
        // Remote admin access only: the real client IP (trusted proxies), then the allowlist. Before anything else, so
        // a refused client gets the same empty 404 as an unknown address.
        var remote = admin.ApplicationServices.GetRequiredService<RemoteAdminAccess>();
        admin.UseWhen(remote.IsRemoteAdmin, branch =>
        {
            branch.UseClientIpResolution();
            branch.UseMiddleware<RemoteAdminGateMiddleware>();
        });

        // The loopback listener: only loopback host names (DNS rebinding). Remote admin requests matched the registered host.
        admin.UseWhen(context => !remote.IsRemoteAdmin(context), branch => branch.UseMiddleware<LoopbackHostGuardMiddleware>());

        admin.Use((context, next) =>
        {
            var headers = context.Response.Headers;
            headers.ContentSecurityPolicy = ContentSecurityPolicy;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = "DENY";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Permissions-Policy"] = PermissionsPolicy;
            headers["Cross-Origin-Opener-Policy"] = "same-origin";
            headers["Cross-Origin-Resource-Policy"] = "same-origin";
            headers.CacheControl = "no-cache, no-store"; // as antiforgery requires; nothing of the UI is cached
            if (context.Request.IsHttps)
            {
                headers.StrictTransportSecurity = StrictTransportSecurity; // remote admin; the loopback listener is plain HTTP
            }

            return next(context);
        });

        // The live traffic hub: refused for requests from another site.
        admin.UseLiveTrafficOriginCheck();

        admin.UseRouting();
        admin.UseAuthentication();

        // The language of the UI (texts, numbers): the account's choice, else the browser's, else English. After
        // authentication, which provides the account's choice. Sign-in pages follow the browser.
        admin.UseRequestLocalization(AdminLanguage.LocalizationOptions());

        // Remote, not signed in: only the sign-in pages; everything else is "not found" (no redirect that reveals the UI).
        admin.UseWhen(RemoteAdminRequest.IsRemote, branch => branch.UseMiddleware<RemoteAdminSignInGateMiddleware>());
        admin.UseAuthorization();
        admin.UseAntiforgery();
        admin.UseEndpoints(endpoints =>
        {
            endpoints.MapStaticAssets();
            endpoints.MapHealthChecks("/healthz");
            endpoints.MapAdminAccountEndpoints();
            endpoints.MapAdminThemeEndpoint();
            endpoints.MapAdminLanguageEndpoint();

            // Everything else needs a signed-in admin; only the sign-in and first-run pages are marked [AllowAnonymous].
            var signedIn = endpoints.MapGroup(string.Empty).RequireAuthorization();
            signedIn.MapAdminDownloads();
            signedIn.MapLogEndpoints();
            signedIn.MapLiveTraffic();
            signedIn.MapPerformanceEndpoints();
            endpoints.MapRazorComponents<App>().RequireAuthorization();
        });
    }
}
