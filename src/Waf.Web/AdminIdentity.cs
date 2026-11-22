using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Waf.Data;

namespace Waf.Web;

/// <summary>
/// Admin accounts of the admin UI: ASP.NET Core Identity with its accounts in <c>identity.db</c>, a sign-in
/// cookie, and the sign-out endpoint. Every page needs a signed-in admin, except the sign-in and first-run pages.
/// </summary>
public static class AdminIdentity
{
    public const string LoginPath = "/account/login";
    public const string SetupPath = "/account/setup";
    public const string LogoutPath = "/account/logout";

    /// <summary>Name of the sign-in cookie.</summary>
    public const string CookieName = "WafAdmin";

    /// <summary>A session ends after this long without a request.</summary>
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromHours(1);

    /// <summary>Minimum password length. Length matters more than character classes, so no other rules apply.</summary>
    public const int MinPasswordLength = 12;

    /// <summary>Help text of password fields.</summary>
    public static readonly string PasswordHelp =
        $"At least {MinPasswordLength} characters. A few unrelated words make a strong password that is easy to type.";

    public static IServiceCollection AddAdminIdentity(this IServiceCollection services, StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        services.AddDbContext<AdminIdentityDbContext>(options => options.UseSqlite(AdminIdentityDbContext.ConnectionString(paths)));
        services.AddAuthentication(IdentityConstants.ApplicationScheme).AddIdentityCookies();
        services
            .AddIdentityCore<IdentityUser>(options =>
            {
                options.Password.RequiredLength = MinPasswordLength;
                options.Password.RequiredUniqueChars = 5;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.User.RequireUniqueEmail = false;
            })
            .AddEntityFrameworkStores<AdminIdentityDbContext>()
            .AddSignInManager();

        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = CookieName;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.LoginPath = LoginPath;
            options.LogoutPath = LogoutPath;
            options.AccessDeniedPath = LoginPath;
            options.ExpireTimeSpan = IdleTimeout;
            options.SlidingExpiration = true;

            // Pages redirect to the sign-in page; data endpoints (the live log, downloads by script) get a plain 401.
            options.Events.OnRedirectToLogin = context =>
            {
                if (WantsPage(context.Request))
                {
                    context.Response.Redirect(context.RedirectUri);
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                }

                return Task.CompletedTask;
            };
        });

        services.AddAuthorization();
        services.AddCascadingAuthenticationState();
        services.AddSingleton<FirstRunSetup>();
        services.AddHostedService(sp => sp.GetRequiredService<FirstRunSetup>());
        return services;
    }

    /// <summary>The sign-out endpoint: a POST form with an antiforgery token, so other sites cannot sign you out.</summary>
    public static IEndpointRouteBuilder MapAdminAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(LogoutPath, async (HttpContext context, IAntiforgery antiforgery, SignInManager<IdentityUser> signIn) =>
            {
                // The antiforgery middleware only records its verdict; an endpoint without form parameters must check it.
                if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
                {
                    return Results.BadRequest();
                }

                await signIn.SignOutAsync().ConfigureAwait(false);
                return Results.LocalRedirect(LoginPath + "?signedOut=true");
            })
            .DisableAntiforgery(); // checked above
        return endpoints;
    }

    /// <summary>
    /// <paramref name="returnUrl"/> if it is a path on this site, otherwise the dashboard: after signing in, never
    /// redirect to another site (open redirect).
    /// </summary>
    public static string LocalReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)
            || returnUrl[0] != '/'
            || (returnUrl.Length > 1 && returnUrl[1] is '/' or '\\')
            || returnUrl.Any(char.IsControl)
            || returnUrl.Contains('\\', StringComparison.Ordinal))
        {
            return "/";
        }

        return returnUrl;
    }

    private static bool WantsPage(HttpRequest request) =>
        request.Headers.Accept.Any(value => value is not null && value.Contains("text/html", StringComparison.OrdinalIgnoreCase))
        && !request.Path.StartsWithSegments(LogEndpoints.LivePath, StringComparison.OrdinalIgnoreCase);
}
