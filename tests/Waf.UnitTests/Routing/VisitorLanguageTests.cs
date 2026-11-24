using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using FASoft.Waf.Core;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Routing;

/// <summary>
/// The answers visitors get from the gateway itself, in their language (English, Dutch, French, German): texts follow
/// the language; status codes, the problem type, SOAP fault codes and the gateway status stay the same.
/// </summary>
public sealed partial class VisitorLanguageTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 24, 10, 42, 7, TimeSpan.Zero);

    public static TheoryData<string> AllLanguages => ["en", "nl", "fr", "de"];

    [Theory]
    [InlineData("nl-BE,nl;q=0.9", "nl")]
    [InlineData("fr-CA", "fr")]
    [InlineData("de-AT, en;q=0.5", "de")]
    [InlineData("ja-JP", "en")]
    [InlineData("es, de;q=0.3", "de")]
    [InlineData("fr;q=0, de;q=0.1", "de")]
    [InlineData("*", "en")]
    [InlineData("", "en")]
    [InlineData(null, "en")]
    [InlineData("not ; a ; header", "en")]
    public void The_language_comes_from_accept_language_with_english_as_the_fallback(string? header, string expected)
    {
        Assert.Equal(expected, Languages.For(header));
        Assert.Equal(expected == "en" ? null : expected, Languages.Match(header)); // no supported language: no match
    }

    [Fact]
    public void Every_visitor_text_has_all_languages_with_the_same_placeholders()
    {
        foreach (var (english, (nl, fr, de)) in VisitorTexts.Translations)
        {
            foreach (var text in new[] { nl, fr, de })
            {
                Assert.False(string.IsNullOrWhiteSpace(text), english);
                Assert.Equal(Placeholders(english), Placeholders(text));
            }
        }
    }

    private static string[] Placeholders(string text) => [.. PlaceholderPattern().Matches(text).Select(m => m.Value).Order(StringComparer.Ordinal)];

    [Theory]
    [MemberData(nameof(AllLanguages))]
    public void Problem_json_has_texts_in_the_language_and_the_same_fields(string language)
    {
        var info = new BackendErrorInfo(BackendErrorKind.NoBackend, "id-1", At, null, language);
        var json = JsonElement.Parse(BackendErrorResponses.Render(ErrorFormat.ProblemJson, info).Body);

        Assert.Equal(("about:blank", 503, "id-1", "2026-11-24T10:42:07Z"),
            (json.GetProperty("type").GetString(), json.GetProperty("status").GetInt32(), json.GetProperty("requestId").GetString(), json.GetProperty("time").GetString()));
        Assert.Equal(VisitorTexts.Get(language, "Service Unavailable"), json.GetProperty("title").GetString());
        Assert.Equal(VisitorTexts.Get(language, "No server is available to handle this request. Please try again later."), json.GetProperty("detail").GetString());
        if (language != "en")
        {
            Assert.NotEqual("Service Unavailable", json.GetProperty("title").GetString());
        }
    }

    [Theory]
    [MemberData(nameof(AllLanguages))]
    public void Problem_xml_has_texts_in_the_language(string language)
    {
        var info = new BackendErrorInfo(BackendErrorKind.Timeout, "id-1", At, null, language);
        var problem = XDocument.Parse(BackendErrorResponses.Render(ErrorFormat.ProblemXml, info).Body).Root!;
        XNamespace ns = "urn:ietf:rfc:7807";

        Assert.Equal(("about:blank", "504"), (problem.Element(ns + "type")!.Value, problem.Element(ns + "status")!.Value));
        Assert.Equal(VisitorTexts.Get(language, "Gateway Timeout"), problem.Element(ns + "title")!.Value);
    }

    [Theory]
    [MemberData(nameof(AllLanguages))]
    public void Soap_faults_keep_their_codes_and_say_their_language(string language)
    {
        var info = new BackendErrorInfo(BackendErrorKind.BackendError, "id-1", At, null, language);
        XNamespace gw = BackendErrorResponses.SoapDetailNamespace;

        // SOAP 1.1: the fault code and the gateway's status and English status phrase are fixed.
        var soap11 = BackendErrorTests.Validated(BackendErrorResponses.Render(ErrorFormat.Soap11, info).Body, BackendErrorTests.Schemas("soap11-envelope.xsd"));
        XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        var fault11 = soap11.Root!.Element(soap + "Body")!.Element(soap + "Fault")!;
        Assert.Equal("soap:Server", fault11.Element("faultcode")!.Value);
        Assert.StartsWith(VisitorTexts.Get(language, "Bad Gateway"), fault11.Element("faultstring")!.Value, StringComparison.Ordinal);
        var detail = fault11.Element("detail")!.Element(gw + "gatewayError")!;
        Assert.Equal(("502", "Bad Gateway"), (detail.Element(gw + "status")!.Value, detail.Element(gw + "title")!.Value));

        // SOAP 1.2: env:Receiver, and the reason's xml:lang is the language.
        var soap12 = BackendErrorTests.Validated(BackendErrorResponses.Render(ErrorFormat.Soap12, info).Body, BackendErrorTests.Schemas("xml.xsd", "soap12-envelope.xsd"));
        XNamespace env = "http://www.w3.org/2003/05/soap-envelope";
        var fault12 = soap12.Root!.Element(env + "Body")!.Element(env + "Fault")!;
        Assert.Equal("env:Receiver", fault12.Element(env + "Code")!.Element(env + "Value")!.Value);
        var text = fault12.Element(env + "Reason")!.Element(env + "Text")!;
        Assert.Equal(language, text.Attribute(XNamespace.Xml + "lang")!.Value);
    }

    [Theory]
    [MemberData(nameof(AllLanguages))]
    public void The_html_page_is_in_the_language_and_says_so(string language)
    {
        var body = BackendErrorResponses.Render(ErrorFormat.Html, new BackendErrorInfo(BackendErrorKind.NoBackend, "id-1", At, "Back soon", language)).Body;
        var decoded = System.Net.WebUtility.HtmlDecode(body);

        Assert.Contains($"<html lang=\"{language}\">", body, StringComparison.Ordinal);
        Assert.Contains(VisitorTexts.Get(language, "This site is temporarily unavailable."), decoded, StringComparison.Ordinal);
        Assert.Contains(VisitorTexts.Format(language, "Request ID {0} · {1}", "id-1", "2026-11-24T10:42:07Z"), decoded, StringComparison.Ordinal);
        Assert.Contains("Back soon", decoded, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Responses_say_their_language_and_vary_by_accept_language()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.AcceptLanguage = "fr-FR";
        context.Response.Body = new MemoryStream();
        context.Response.Headers.Vary = "Accept-Encoding";

        await BackendErrorResponses.WriteAsync(context, new BackendErrorInfo(BackendErrorKind.NoBackend, "id-1", At, null, VisitorTexts.LanguageOf(context.Request)));

        Assert.Equal("fr", context.Response.Headers.ContentLanguage.ToString());
        Assert.Contains("Accept-Language", context.Response.Headers.Vary.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void The_message_for_visitors_has_a_text_per_language_with_english_as_the_fallback()
    {
        var route = new ProxyRouteOptions
        {
            Name = "site",
            Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } },
            ErrorMessage = "Maintenance until 14:00",
            ErrorMessageTranslations = new Dictionary<string, string> { ["nl"] = "Onderhoud tot 14:00", ["de"] = "Wartung bis 14:00" },
        };
        Assert.Empty(ProxyRouteValidator.Validate([route]));

        var (routes, _) = YarpConfigMapper.Map([route]);
        var metadata = routes[0].Metadata!;
        Assert.Equal(("Maintenance until 14:00", "Onderhoud tot 14:00", "Wartung bis 14:00"),
            (metadata[YarpConfigMapper.ErrorMessageMetadataKey], metadata[YarpConfigMapper.ErrorMessageMetadataKey + ".nl"], metadata[YarpConfigMapper.ErrorMessageMetadataKey + ".de"]));
        Assert.False(metadata.ContainsKey(YarpConfigMapper.ErrorMessageMetadataKey + ".fr")); // French visitors get the English text

        // Unknown languages, a translation without the English text, and multi-line texts are refused.
        route.ErrorMessageTranslations["es"] = "Mantenimiento";
        Assert.Contains("Route 'site': 'es' is not a language for the message for visitors (use nl, fr or de).", ProxyRouteValidator.Validate([route]));
        route.ErrorMessageTranslations.Remove("es");
        route.ErrorMessage = null;
        Assert.Contains("Route 'site': translations of the message for visitors need the English message too (it is the fallback).", ProxyRouteValidator.Validate([route]));
        route.ErrorMessage = "Maintenance";
        route.ErrorMessageTranslations["fr"] = "Ligne un\nligne deux";
        Assert.Contains("Route 'site': the message for visitors in 'fr' must be one line of at most 300 characters.", ProxyRouteValidator.Validate([route]));
    }

    [Fact]
    public void Routes_without_translations_keep_their_exact_json_and_the_editor_round_trips_them()
    {
        var plain = new ProxyRouteOptions { Name = "site", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } }, ErrorMessage = "Back soon" };
        Assert.DoesNotContain("ErrorMessageTranslations", GatewayConfigurationJson.Serialize(new GatewayConfiguration { Routes = { plain } }), StringComparison.Ordinal);

        var form = new RouteFormModel { Name = "site", Destinations = "10.0.0.5:80", ErrorMessage = "Back soon", ErrorMessageNl = " Zo terug ", ErrorMessageDe = "Gleich zurück" };
        var route = form.ToRoute();
        Assert.Equal(["de", "nl"], route.ErrorMessageTranslations!.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("Zo terug", route.ErrorMessageTranslations["nl"]);

        var back = RouteFormModel.FromRoute(route, 1);
        Assert.Equal(("Zo terug", null, "Gleich zurück"), (back.ErrorMessageNl, back.ErrorMessageFr, back.ErrorMessageDe));
        Assert.Null(new RouteFormModel { Name = "site", Destinations = "10.0.0.5:80", ErrorMessage = "Back soon" }.ToRoute().ErrorMessageTranslations);
    }

    [GeneratedRegex(@"\{\d+\}")]
    private static partial Regex PlaceholderPattern();
}
