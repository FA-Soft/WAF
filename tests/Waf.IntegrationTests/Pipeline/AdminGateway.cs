using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using FASoft.Waf.Data;
using FASoft.Waf.IntegrationTests.Proxy;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// A gateway with backends A and B and helpers to drive the admin UI through real form posts (with the page's
/// antiforgery token) and to send public requests.
/// </summary>
public abstract partial class AdminGateway : GatewayFixture
{
    public BackendServer A { get; private set; } = null!;

    public BackendServer B { get; private set; } = null!;

    protected AdminGateway()
    {
        Admin = new(new HttpClientHandler { UseCookies = true, CookieContainer = AdminCookies })
        {
            Timeout = TimeSpan.FromSeconds(15),
        };
    }

    /// <summary>The cookies of <see cref="Admin"/> (its session), e.g. for a SignalR client.</summary>
    public CookieContainer AdminCookies { get; } = new();

    public HttpClient Admin { get; }

    public HttpClient Public { get; } = new() { Timeout = TimeSpan.FromSeconds(15) };

    public ConfigurationStore Store => App.Services.GetRequiredService<ConfigurationStore>();

    public AuditLogStore AuditLog => App.Services.GetRequiredService<AuditLogStore>();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    protected override async ValueTask BeforeStartAsync()
    {
        A = await BackendServer.StartAsync("A");
        B = await BackendServer.StartAsync("B");
    }

    protected override async ValueTask AfterStartAsync() => await SignInAsync(Admin);

    protected override async ValueTask AfterStopAsync()
    {
        Admin.Dispose();
        Public.Dispose();
        // Null when starting failed before the backends were up: keep the original error visible.
        if (A is not null)
        {
            await A.DisposeAsync();
        }

        if (B is not null)
        {
            await B.DisposeAsync();
        }
    }

    public async Task<string> GetPageAsync(string path)
    {
        using var response = await Admin.GetAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Ct);
    }

    /// <summary>Opens <paramref name="path"/>, then posts form <paramref name="handler"/> of it with the page's antiforgery token.</summary>
    public async Task<string> PostAsync(string path, string handler, Dictionary<string, string> fields)
    {
        var page = await GetPageAsync(path);
        fields["__RequestVerificationToken"] = AntiforgeryPattern().Match(page).Groups["token"].Value;
        fields["_handler"] = handler;

        using var content = new FormUrlEncodedContent(fields);
        using var response = await Admin.PostAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), content, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); // after the redirect, if any
        return await response.Content.ReadAsStringAsync(Ct);
    }

    /// <summary>
    /// Posts <paramref name="fields"/> as a plain HTML form to <paramref name="path"/> (e.g. a download endpoint), with
    /// the antiforgery token of page <paramref name="tokenPage"/>. The caller disposes the response.
    /// </summary>
    public async Task<HttpResponseMessage> PostPlainFormAsync(string path, string tokenPage, Dictionary<string, string> fields, bool withToken = true)
    {
        var page = await GetPageAsync(tokenPage);
        if (withToken)
        {
            fields["__RequestVerificationToken"] = AntiforgeryPattern().Match(page).Groups["token"].Value;
        }

        using var content = new FormUrlEncodedContent(fields);
        return await Admin.PostAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), content, Ct);
    }

    /// <summary>Like <see cref="PostAsync"/>, but as multipart/form-data with one uploaded file.</summary>
    public async Task<string> PostMultipartAsync(
        string path, string handler, Dictionary<string, string> fields, string fileField, string fileName, byte[] file)
    {
        var page = await GetPageAsync(path);
        fields["__RequestVerificationToken"] = AntiforgeryPattern().Match(page).Groups["token"].Value;
        fields["_handler"] = handler;

        using var content = new MultipartFormDataContent();
        foreach (var (name, value) in fields)
        {
            content.Add(new StringContent(value), name);
        }

        content.Add(new ByteArrayContent(file), fileField, fileName);
        using var response = await Admin.PostAsync(new Uri($"http://127.0.0.1:{AdminPort}{path}"), content, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync(Ct);
    }

    /// <summary>A public request; returns the status code.</summary>
    public async Task<HttpStatusCode> SendAsync(string path, HttpMethod? method = null)
    {
        using var request = new HttpRequestMessage(method ?? HttpMethod.Get, new Uri($"http://127.0.0.1:{HttpPort}{path}"));
        using var response = await Public.SendAsync(request, Ct);
        return response.StatusCode;
    }

    /// <summary>
    /// The fields a browser would post for the form in <paramref name="html"/> that contains the handler
    /// <paramref name="handler"/>: inputs (checkboxes only when ticked), textareas and selected options.
    /// </summary>
    public static Dictionary<string, string> ScrapeForm(string html, string handler)
    {
        var start = html.IndexOf($"name=\"_handler\" value=\"{handler}\"", StringComparison.Ordinal);
        Assert.True(start >= 0, $"Form '{handler}' not found.");
        var formStart = html.LastIndexOf("<form", start, StringComparison.Ordinal);
        var formEnd = html.IndexOf("</form>", start, StringComparison.Ordinal);
        var form = html[formStart..formEnd];

        var fields = new Dictionary<string, string>();
        foreach (Match input in InputPattern().Matches(form))
        {
            var attributes = Attributes(input.Value);
            if (!attributes.TryGetValue("name", out var name) || name is "_handler" or "__RequestVerificationToken")
            {
                continue;
            }

            var type = attributes.GetValueOrDefault("type", "text");
            if (type is "checkbox" or "radio" && !attributes.ContainsKey("checked"))
            {
                continue;
            }

            if (type is not ("submit" or "button" or "file"))
            {
                fields[name] = attributes.GetValueOrDefault("value", type == "checkbox" ? "on" : string.Empty);
            }
        }

        foreach (Match textarea in TextareaPattern().Matches(form))
        {
            fields[Attributes(textarea.Groups["tag"].Value)["name"]] = WebUtility.HtmlDecode(textarea.Groups["content"].Value);
        }

        foreach (Match select in SelectPattern().Matches(form))
        {
            var options = OptionPattern().Matches(select.Groups["options"].Value).Select(o => Attributes(o.Value)).ToList();
            var chosen = options.FirstOrDefault(o => o.ContainsKey("selected")) ?? options.FirstOrDefault();
            if (chosen is not null)
            {
                fields[Attributes(select.Groups["tag"].Value)["name"]] = chosen.GetValueOrDefault("value", string.Empty);
            }
        }

        return fields;
    }

    private static Dictionary<string, string> Attributes(string tag) =>
        AttributePattern().Matches(tag).ToDictionary(
            m => m.Groups["name"].Value,
            m => WebUtility.HtmlDecode(m.Groups["value"].Success ? m.Groups["value"].Value : string.Empty),
            StringComparer.Ordinal);

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex AntiforgeryPattern();

    [GeneratedRegex("""<input\b[^>]*>""")]
    private static partial Regex InputPattern();

    [GeneratedRegex("""<textarea(?<tag>\b[^>]*)>(?<content>[^<]*)</textarea>""")]
    private static partial Regex TextareaPattern();

    [GeneratedRegex("""<select(?<tag>\b[^>]*)>(?<options>.*?)</select>""", RegexOptions.Singleline)]
    private static partial Regex SelectPattern();

    [GeneratedRegex("""<option\b[^>]*>""")]
    private static partial Regex OptionPattern();

    [GeneratedRegex("""(?<name>[a-zA-Z_:][-a-zA-Z0-9_:.\[\]]*)(?:="(?<value>[^"]*)")?""")]
    private static partial Regex AttributePattern();
}
