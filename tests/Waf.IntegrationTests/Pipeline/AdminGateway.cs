using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Waf.Data;
using Waf.IntegrationTests.Proxy;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>
/// A gateway with backends A and B and helpers to drive the admin UI through real form posts (with the page's
/// antiforgery token) and to send public requests.
/// </summary>
public abstract partial class AdminGateway : GatewayFixture
{
    public BackendServer A { get; private set; } = null!;

    public BackendServer B { get; private set; } = null!;

    public HttpClient Admin { get; } = new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() })
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    public HttpClient Public { get; } = new() { Timeout = TimeSpan.FromSeconds(15) };

    public ConfigurationStore Store => App.Services.GetRequiredService<ConfigurationStore>();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    protected override async ValueTask BeforeStartAsync()
    {
        A = await BackendServer.StartAsync("A");
        B = await BackendServer.StartAsync("B");
    }

    protected override async ValueTask AfterStopAsync()
    {
        Admin.Dispose();
        Public.Dispose();
        await A.DisposeAsync();
        await B.DisposeAsync();
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

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex AntiforgeryPattern();
}
