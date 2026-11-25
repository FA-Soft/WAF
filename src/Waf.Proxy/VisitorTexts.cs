using System.Collections.Frozen;
using System.Globalization;
using Microsoft.AspNetCore.Http;
using FASoft.Waf.Core;

namespace FASoft.Waf.Proxy;

/// <summary>
/// The texts website visitors get from the gateway itself (error pages and short refusals), in English, Dutch, French
/// and German. The language comes from the visitor's <c>Accept-Language</c> (visitors have no profile), with English as
/// the fallback. The key is the English text.
/// </summary>
/// <remarks>Like the admin UI's translations, these are unreviewed by native speakers (see docs/translations.md).</remarks>
public static class VisitorTexts
{
    /// <summary>English text → (Dutch, French, German).</summary>
    internal static readonly FrozenDictionary<string, (string Nl, string Fr, string De)> Translations = new Dictionary<string, (string, string, string)>(StringComparer.Ordinal)
    {
        // Error responses when no backend answers.
        ["Service Unavailable"] = ("Dienst niet beschikbaar", "Service indisponible", "Dienst nicht verfügbar"),
        ["Bad Gateway"] = ("Ongeldige gateway", "Passerelle incorrecte", "Fehlerhaftes Gateway"),
        ["Gateway Timeout"] = ("Time-out van de gateway", "Délai de la passerelle dépassé", "Gateway-Zeitüberschreitung"),
        ["No server is available to handle this request. Please try again later."] = (
            "Er is geen server beschikbaar om dit verzoek te behandelen. Probeer het later opnieuw.",
            "Aucun serveur n'est disponible pour traiter cette requête. Veuillez réessayer plus tard.",
            "Kein Server ist verfügbar, um diese Anfrage zu bearbeiten. Bitte versuchen Sie es später erneut."),
        ["The server behind the gateway did not answer in time. Please try again later."] = (
            "De server achter de gateway antwoordde niet op tijd. Probeer het later opnieuw.",
            "Le serveur derrière la passerelle n'a pas répondu à temps. Veuillez réessayer plus tard.",
            "Der Server hinter dem Gateway hat nicht rechtzeitig geantwortet. Bitte versuchen Sie es später erneut."),
        ["The server behind the gateway did not give a valid answer. Please try again later."] = (
            "De server achter de gateway gaf geen geldig antwoord. Probeer het later opnieuw.",
            "Le serveur derrière la passerelle n'a pas donné de réponse valide. Veuillez réessayer plus tard.",
            "Der Server hinter dem Gateway hat keine gültige Antwort gegeben. Bitte versuchen Sie es später erneut."),
        ["This site is temporarily unavailable."] = (
            "Deze site is tijdelijk niet beschikbaar.", "Ce site est temporairement indisponible.", "Diese Website ist vorübergehend nicht verfügbar."),
        ["Please try again in a few minutes."] = (
            "Probeer het over een paar minuten opnieuw.", "Veuillez réessayer dans quelques minutes.", "Bitte versuchen Sie es in ein paar Minuten erneut."),
        ["Error {0} · {1}"] = ("Fout {0} · {1}", "Erreur {0} · {1}", "Fehler {0} · {1}"),
        ["Request ID {0} · {1}"] = ("Verzoek-ID {0} · {1}", "ID de requête {0} · {1}", "Anfrage-ID {0} · {1}"),
        ["{0}: {1}"] = ("{0}: {1}", "{0} : {1}", "{0}: {1}"),

        // The gateway's own short answers.
        ["Forbidden. The request was blocked by the web application firewall."] = (
            "Verboden. Het verzoek is geblokkeerd door de webapplicatiefirewall.",
            "Interdit. La requête a été bloquée par le pare-feu applicatif web.",
            "Verboten. Die Anfrage wurde von der Web Application Firewall blockiert."),
        ["Too many requests. Please slow down."] = (
            "Te veel verzoeken. Doe het wat rustiger aan.", "Trop de requêtes. Veuillez ralentir.", "Zu viele Anfragen. Bitte etwas langsamer."),
        ["Service unavailable. The web application firewall is not ready."] = (
            "Dienst niet beschikbaar. De webapplicatiefirewall is niet klaar.",
            "Service indisponible. Le pare-feu applicatif web n'est pas prêt.",
            "Dienst nicht verfügbar. Die Web Application Firewall ist nicht bereit."),
    }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>The visitor's language: the first supported one of the request's <c>Accept-Language</c>, else English.</summary>
    public static string LanguageOf(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Languages.For(request.Headers.AcceptLanguage);
    }

    /// <summary><paramref name="english"/> in <paramref name="language"/>; English for an unknown text or language.</summary>
    public static string Get(string language, string english)
    {
        ArgumentNullException.ThrowIfNull(english);
        if (!Translations.TryGetValue(english, out var texts))
        {
            return english;
        }

        return language switch
        {
            "nl" => texts.Nl,
            "fr" => texts.Fr,
            "de" => texts.De,
            _ => english,
        };
    }

    /// <summary><paramref name="english"/> in <paramref name="language"/>, with <paramref name="args"/> in its placeholders.</summary>
    public static string Format(string language, string english, params object?[] args) =>
        string.Format(CultureInfo.InvariantCulture, Get(language, english), args);

    /// <summary>
    /// Says which language the answer is in, and that it depends on <c>Accept-Language</c> (so a cache never gives a
    /// visitor another visitor's language).
    /// </summary>
    public static void MarkLanguage(HttpResponse response, string language)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Headers.ContentLanguage = language;
        response.Headers.Append(Microsoft.Net.Http.Headers.HeaderNames.Vary, "Accept-Language");
    }

    /// <summary>A short plain-text answer of the gateway itself (403, 429, 503) in the visitor's language.</summary>
    internal static Task WritePlainAsync(HttpContext context, string english)
    {
        var language = LanguageOf(context.Request);
        context.Response.ContentType = "text/plain; charset=utf-8";
        MarkLanguage(context.Response, language);
        return context.Response.WriteAsync(Get(language, english), context.RequestAborted);
    }
}
