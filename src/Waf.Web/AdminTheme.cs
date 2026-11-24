using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;

namespace FASoft.Waf.Web;

/// <summary>
/// The admin UI's color theme: the system setting (default), light or dark. A choice other than the system setting is
/// stored with the account (a user claim in identity.db), so it applies at the next sign-in, on any device.
/// </summary>
/// <remarks>
/// The sign-in cookie's principal is rebuilt from the database on every request (the security stamp is checked each
/// time, see <see cref="AdminIdentity"/>), so a change also reaches sessions on other devices at their next page.
/// </remarks>
public static class AdminTheme
{
    /// <summary>Claim type of the stored theme; absent means "follow the system setting".</summary>
    public const string ClaimType = "waf:theme";

    public const string System = "system";
    public const string Light = "light";
    public const string Dark = "dark";

    /// <summary>Path of the form that changes it.</summary>
    public const string Path = "/account/theme";

    /// <summary>The choices, in the order the switch shows them.</summary>
    public static readonly IReadOnlyList<(string Value, string Label)> Choices = [(System, Text.N("System")), (Light, Text.N("Light")), (Dark, Text.N("Dark"))];

    /// <summary>The user's theme: <see cref="Light"/>, <see cref="Dark"/> or <see cref="System"/>.</summary>
    public static string Of(ClaimsPrincipal? user) =>
        user?.FindFirst(ClaimType)?.Value switch
        {
            Light => Light,
            Dark => Dark,
            _ => System,
        };

    /// <summary>
    /// The <c>data-theme</c> attribute of the page: only for an explicit choice. Without it the stylesheet follows the
    /// system setting.
    /// </summary>
    public static string? DataAttribute(ClaimsPrincipal? user)
    {
        var theme = Of(user);
        return theme == System ? null : theme;
    }

    public static bool IsValid(string? theme) => theme is System or Light or Dark;

    /// <summary>Stores <paramref name="theme"/> for <paramref name="user"/>; <see cref="System"/> removes the stored choice.</summary>
    public static async Task<IdentityResult> SaveAsync(UserManager<IdentityUser> users, IdentityUser user, string theme)
    {
        ArgumentNullException.ThrowIfNull(users);
        if (!IsValid(theme))
        {
            throw new ArgumentException($"Unknown theme '{theme}'.", nameof(theme));
        }

        var stored = (await users.GetClaimsAsync(user).ConfigureAwait(false)).Where(c => c.Type == ClaimType).ToList();
        if (stored.Count > 0)
        {
            var removed = await users.RemoveClaimsAsync(user, stored).ConfigureAwait(false);
            if (!removed.Succeeded)
            {
                return removed;
            }
        }

        return theme == System
            ? IdentityResult.Success
            : await users.AddClaimAsync(user, new Claim(ClaimType, theme)).ConfigureAwait(false);
    }

    /// <summary>
    /// POST <see cref="Path"/> (form: <c>theme</c>, <c>returnUrl</c>): saves the choice and goes back to the page.
    /// Signed-in admins only; with an antiforgery token, so other sites cannot change it.
    /// </summary>
    public static IEndpointRouteBuilder MapAdminThemeEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(Path, async (HttpContext context, IAntiforgery antiforgery, UserManager<IdentityUser> users) =>
            {
                // The antiforgery middleware only records its verdict; an endpoint without bound form parameters must check it.
                if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
                {
                    return Results.BadRequest();
                }

                var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
                string? theme = form["theme"];
                if (!IsValid(theme))
                {
                    return Results.BadRequest();
                }

                var user = await users.GetUserAsync(context.User).ConfigureAwait(false);
                if (user is null)
                {
                    return Results.Unauthorized();
                }

                var result = await SaveAsync(users, user, theme!).ConfigureAwait(false);
                return result.Succeeded
                    ? Results.LocalRedirect(AdminIdentity.LocalReturnUrl(form["returnUrl"]))
                    : Results.Problem("The theme could not be saved.");
            })
            .RequireAuthorization()
            .DisableAntiforgery(); // checked above
        return endpoints;
    }
}
