using System.Globalization;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

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

    public const string TwoFactorPath = "/account/two-factor";
    public const string LoginTwoFactorPath = "/account/login/two-factor";
    public const string LoginRecoveryPath = "/account/login/recovery";
    public const string HistoryPath = "/account/history";

    /// <summary>A session ends after this long without a request (the live log's polling does not count).</summary>
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(15);

    /// <summary>A session ends this long after signing in, however active it is.</summary>
    public static readonly TimeSpan MaxSessionLifetime = TimeSpan.FromHours(8);

    /// <summary>Wrong passwords or codes in a row after which an account is locked.</summary>
    public const int MaxFailedAttempts = AdminAccountPolicy.MaxFailedAttempts;

    /// <summary>How long a locked account stays locked.</summary>
    public static readonly TimeSpan LockoutDuration = AdminAccountPolicy.LockoutDuration;

    /// <summary>Number of recovery codes handed out when 2FA is turned on.</summary>
    public const int RecoveryCodeCount = 10;

    /// <summary>Issuer shown in authenticator apps.</summary>
    public const string AuthenticatorIssuer = "WAF Gateway";

    /// <summary>Ticket property with the moment of signing in; unlike the issue time it is not moved on renewal.</summary>
    private const string SignedInAtKey = "waf.signedInAt";

    /// <summary>Minimum password length. Length matters more than character classes, so no other rules apply.</summary>
    public const int MinPasswordLength = AdminAccountPolicy.MinPasswordLength;

    /// <summary>Help text of password fields.</summary>
    public static readonly string PasswordHelp =
        $"At least {MinPasswordLength} characters. A few unrelated words make a strong password that is easy to type.";

    public static IServiceCollection AddAdminIdentity(this IServiceCollection services, StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        services.AddDbContext<AdminIdentityDbContext>(options => options.UseSqlite(AdminIdentityDbContext.ConnectionString(paths)));
        services.AddAuthentication(IdentityConstants.ApplicationScheme).AddIdentityCookies();
        services
            .AddIdentityCore<IdentityUser>(AdminAccountPolicy.Apply)
            .AddEntityFrameworkStores<AdminIdentityDbContext>()
            .AddSignInManager()
            .AddTokenProvider<AuthenticatorTokenProvider<IdentityUser>>(TokenOptions.DefaultAuthenticatorProvider);

        // Check the security stamp on every request: a password change, a 2FA change or "sign out other sessions"
        // ends the other sessions at once. The admin UI has little traffic, so the extra lookup costs nothing.
        services.Configure<SecurityStampValidatorOptions>(options => options.ValidationInterval = TimeSpan.Zero);

        // The short-lived cookie between the password and the 2FA code.
        services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme, options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });

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

            options.Events.OnSigningIn = context =>
            {
                // Kept when the cookie is renewed or refreshed (e.g. after a password change).
                context.Properties.Items.TryAdd(SignedInAtKey, Now(context.HttpContext).ToString("O", CultureInfo.InvariantCulture));
                return Task.CompletedTask;
            };

            // Polling by the live log does not count as activity.
            options.Events.OnCheckSlidingExpiration = context =>
            {
                if (IsBackgroundRequest(context.Request))
                {
                    context.ShouldRenew = false;
                }

                return Task.CompletedTask;
            };

            var validateStamp = options.Events.OnValidatePrincipal;
            options.Events.OnValidatePrincipal = async context =>
            {
                if (IsSessionExpired(context.Properties, Now(context.HttpContext)))
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme).ConfigureAwait(false);
                    return;
                }

                await validateStamp(context).ConfigureAwait(false);
                if (IsBackgroundRequest(context.Request))
                {
                    context.ShouldRenew = false;
                }
            };

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
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<SignInThrottle>();
        services.AddScoped<SignInHistory>();
        services.AddScoped<AdminSignIn>();
        services.AddSingleton<FirstRunSetup>();
        services.AddHostedService(sp => sp.GetRequiredService<FirstRunSetup>());
        return services;
    }

    /// <summary>The sign-out endpoint: a POST form with an antiforgery token, so other sites cannot sign you out.</summary>
    public static IEndpointRouteBuilder MapAdminAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(LogoutPath, async (
                HttpContext context, IAntiforgery antiforgery, SignInManager<IdentityUser> signIn, SignInHistory history) =>
            {
                // The antiforgery middleware only records its verdict; an endpoint without form parameters must check it.
                if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
                {
                    return Results.BadRequest();
                }

                var user = await signIn.UserManager.GetUserAsync(context.User).ConfigureAwait(false);
                await signIn.SignOutAsync().ConfigureAwait(false);
                if (user is not null)
                {
                    await history.RecordAsync(context, SignInOutcome.SignedOut, user).ConfigureAwait(false);
                }

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

    /// <summary>True when the session started more than <see cref="MaxSessionLifetime"/> ago (or its start is unknown).</summary>
    public static bool IsSessionExpired(AuthenticationProperties properties, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(properties);

        return !properties.Items.TryGetValue(SignedInAtKey, out var value)
            || !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var signedInAt)
            || now - signedInAt >= MaxSessionLifetime;
    }

    /// <summary>Requests made by a page's script, not by the admin: they do not keep a session alive.</summary>
    private static bool IsBackgroundRequest(HttpRequest request) =>
        request.Path.StartsWithSegments(LogEndpoints.LivePath, StringComparison.OrdinalIgnoreCase);

    private static DateTimeOffset Now(HttpContext context) =>
        (context.RequestServices.GetService<TimeProvider>() ?? TimeProvider.System).GetUtcNow();

    private static bool WantsPage(HttpRequest request) =>
        request.Headers.Accept.Any(value => value is not null && value.Contains("text/html", StringComparison.OrdinalIgnoreCase))
        && !request.Path.StartsWithSegments(LogEndpoints.LivePath, StringComparison.OrdinalIgnoreCase);
}
