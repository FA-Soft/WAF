using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Routing;
using Microsoft.Net.Http.Headers;

// The resources are named after the root namespace (FASoft.Waf.Web), which differs from the assembly name (Waf.Web).
[assembly: Microsoft.Extensions.Localization.RootNamespace("FASoft.Waf.Web")]

namespace FASoft.Waf.Web;

/// <summary>Marker type of the admin UI's text resources (<c>Resources/SharedResource.*.resx</c>).</summary>
#pragma warning disable CA1052 // only a type argument for IStringLocalizer<SharedResource>
public sealed class SharedResource
#pragma warning restore CA1052
{
}

/// <summary>
/// The admin UI's language: English, Dutch, French or German. Per request: the language stored with the signed-in
/// account (a user claim in identity.db, like <see cref="AdminTheme"/>), else the first supported language of the
/// browser's <c>Accept-Language</c>, else English.
/// </summary>
/// <remarks>
/// The sign-in cookie's principal is rebuilt from the database on every request, so a change reaches the user's
/// sessions on other devices at their next page, and applies at the next sign-in anywhere.
/// </remarks>
public static class AdminLanguage
{
    /// <summary>Claim type of the stored language; absent means "follow the browser".</summary>
    public const string ClaimType = "waf:language";

    /// <summary>The switch's value for "follow the browser" (removes the stored choice).</summary>
    public const string Browser = "browser";

    /// <summary>Default, and fallback when the browser asks for none of the supported languages.</summary>
    public const string Default = "en";

    /// <summary>Path of the form that changes it.</summary>
    public const string Path = "/account/language";

    /// <summary>The supported languages, each named in its own language, in the order the switch shows them.</summary>
    public static readonly IReadOnlyList<(string Code, string Name)> Languages =
        [("en", "English"), ("nl", "Nederlands"), ("fr", "Français"), ("de", "Deutsch")];

    /// <summary>The cultures the admin UI supports, for formatting and texts.</summary>
    public static IList<CultureInfo> Cultures => [.. Languages.Select(l => CultureInfo.GetCultureInfo(l.Code))];

    public static bool IsSupported(string? code) => code is not null && Languages.Any(l => l.Code == code);

    /// <summary>True for a value of the switch: a supported language or <see cref="Browser"/>.</summary>
    public static bool IsValid(string? choice) => choice == Browser || IsSupported(choice);

    /// <summary>The language stored with the account, or null when it follows the browser.</summary>
    public static string? Stored(ClaimsPrincipal? user) =>
        user?.FindFirst(ClaimType)?.Value is { } code && IsSupported(code) ? code : null;

    /// <summary>
    /// The first supported language of an <c>Accept-Language</c> header, in order of preference (quality, then
    /// position): <c>nl-BE</c> gives <c>nl</c>. Null when none is supported.
    /// </summary>
    public static string? FromAcceptLanguage(string? header)
    {
        if (string.IsNullOrWhiteSpace(header) || !StringWithQualityHeaderValue.TryParseList([header], out var values))
        {
            return null;
        }

        return values
            .Select((value, index) => (Tag: value.Value.Value ?? string.Empty, Quality: value.Quality ?? 1, index))
            .Where(v => v.Quality > 0)
            .OrderByDescending(v => v.Quality)
            .ThenBy(v => v.index)
            .Select(v => v.Tag.Split('-', 2)[0].ToLowerInvariant())
            .FirstOrDefault(IsSupported);
    }

    /// <summary>The language for a request: the account's choice, else the browser's, else English.</summary>
    public static string For(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return Stored(context.User) ?? FromAcceptLanguage(context.Request.Headers.AcceptLanguage) ?? Default;
    }

    /// <summary>Request localization for the admin UI: <see cref="For"/> decides, English is the fallback.</summary>
    public static RequestLocalizationOptions LocalizationOptions()
    {
        var cultures = Cultures;
        var options = new RequestLocalizationOptions
        {
            DefaultRequestCulture = new RequestCulture(Default),
            SupportedCultures = cultures,
            SupportedUICultures = cultures,
            FallBackToParentCultures = false,
            FallBackToParentUICultures = false,
        };
        options.RequestCultureProviders.Clear();
        options.RequestCultureProviders.Add(new CustomRequestCultureProvider(context =>
        {
            var language = For(context);
            return Task.FromResult<ProviderCultureResult?>(new ProviderCultureResult(language, language));
        }));
        return options;
    }

    /// <summary>Stores <paramref name="choice"/> for <paramref name="user"/>; <see cref="Browser"/> removes the stored choice.</summary>
    public static async Task<IdentityResult> SaveAsync(UserManager<IdentityUser> users, IdentityUser user, string choice)
    {
        ArgumentNullException.ThrowIfNull(users);
        if (!IsValid(choice))
        {
            throw new ArgumentException($"Unknown language '{choice}'.", nameof(choice));
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

        return choice == Browser
            ? IdentityResult.Success
            : await users.AddClaimAsync(user, new Claim(ClaimType, choice)).ConfigureAwait(false);
    }

    /// <summary>
    /// POST <see cref="Path"/> (form: <c>language</c>, <c>returnUrl</c>): saves the choice and goes back to the page.
    /// Signed-in admins only; with an antiforgery token, so other sites cannot change it.
    /// </summary>
    public static IEndpointRouteBuilder MapAdminLanguageEndpoint(this IEndpointRouteBuilder endpoints)
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
                string? language = form["language"];
                if (!IsValid(language))
                {
                    return Results.BadRequest();
                }

                var user = await users.GetUserAsync(context.User).ConfigureAwait(false);
                if (user is null)
                {
                    return Results.Unauthorized();
                }

                var result = await SaveAsync(users, user, language!).ConfigureAwait(false);
                return result.Succeeded
                    ? Results.LocalRedirect(AdminIdentity.LocalReturnUrl(form["returnUrl"]))
                    : Results.Problem("The language could not be saved.");
            })
            .RequireAuthorization()
            .DisableAntiforgery(); // checked above
        return endpoints;
    }
}
