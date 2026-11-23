using System.Globalization;
using System.Net;
using System.Net.Sockets;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Proxy;
using FASoft.Waf.UnitTests.Tls;
using FASoft.Waf.Web;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>HTTP to HTTPS redirects and HSTS per route, against a running gateway with real HTTP and HTTPS listeners.</summary>
public sealed class HttpsEnforcementTests
{
    private const string Secure = "secure.example.test";
    private const string HstsOnly = "hsts.example.test";
    private const string Plain = "plain.example.test";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// secure.example.test: redirect and HSTS; hsts.example.test: HSTS only; plain.example.test: neither. All three
    /// have a certificate (one file with all names), so HTTPS works for each.
    /// </summary>
    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs()
                .Add("secure", [("http", A.Port)], hosts: [Secure])
                .Add("hsts-only", [("http", A.Port)], hosts: [HstsOnly])
                .Add("plain", [("http", B.Port)], hosts: [Plain])
                .ToArray();

        public async Task ConfigureAsync(Action<GatewayConfiguration>? change = null)
        {
            using var certificate = TestCertificates.SelfSigned(Secure, HstsOnly, Plain);
            var certificatePath = Path.Combine(DataDirectory, "site.pem");
            await File.WriteAllTextAsync(certificatePath, TestCertificates.CertificatePem(certificate) + TestCertificates.KeyPem(certificate), Ct);

            var configuration = (await Store.GetLastKnownGoodAsync(Ct))!.Configuration;
            foreach (var host in new[] { Secure, HstsOnly, Plain })
            {
                configuration.Certificates.Add(new CertificateBinding { HostName = host, Source = CertificateSource.File, CertificatePath = certificatePath });
            }

            configuration.Routes.Single(r => r.Name == "secure").Https = new() { RedirectHttp = true, Hsts = true };
            configuration.Routes.Single(r => r.Name == "hsts-only").Https = new() { Hsts = true };
            configuration.Rules.Add(new WafRule
            {
                Name = "block-admin",
                Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/blocked" } } },
            });
            change?.Invoke(configuration);
            var result = await App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct);
            Assert.True(result.Succeeded, string.Join(" ", result.Errors));
        }

        /// <summary>A plain HTTP request to the HTTP port with <paramref name="host"/>; redirects are not followed.</summary>
        public async Task<HttpResponseMessage> HttpAsync(string host, string pathAndQuery, HttpMethod? method = null, string? forwardedProto = null)
        {
            using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };
            using var request = new HttpRequestMessage(method ?? HttpMethod.Get, new Uri($"http://127.0.0.1:{HttpPort}{pathAndQuery}"));
            request.Headers.Host = host;
            if (method == HttpMethod.Post)
            {
                request.Content = new StringContent("form=data");
            }

            if (forwardedProto is not null)
            {
                request.Headers.Add("X-Forwarded-Proto", forwardedProto);
            }

            return await client.SendAsync(request, Ct);
        }

        /// <summary>An HTTPS request to the HTTPS port with <paramref name="host"/> as SNI and Host.</summary>
        public async Task<HttpResponseMessage> HttpsAsync(string host, string path = "/")
        {
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                ConnectCallback = async (_, cancellationToken) =>
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    await socket.ConnectAsync(IPAddress.Loopback, HttpsPort, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                },
#pragma warning disable CA5359 // Self-signed test certificate.
                SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
#pragma warning restore CA5359
            };
            using var client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(10) };
            return await client.GetAsync(new Uri($"https://{host}{path}"), Ct);
        }
    }

    private static async Task<Gateway> StartAsync(Action<GatewayConfiguration>? change = null)
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        await gateway.ConfigureAsync(change);
        return gateway;
    }

    private static string? Hsts(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Strict-Transport-Security", out var values) ? string.Join(" | ", values) : null;

    [Fact]
    public async Task Plain_http_is_redirected_to_the_same_url_over_https()
    {
        await using var gateway = await StartAsync();

        using var get = await gateway.HttpAsync(Secure, "/shop/cart?item=7&x=a%20b");
        Assert.Equal(HttpStatusCode.PermanentRedirect, get.StatusCode);
        Assert.Equal($"https://{Secure}:{gateway.HttpsPort}/shop/cart?item=7&x=a%20b", get.Headers.Location!.OriginalString);
        Assert.Null(Hsts(get)); // never over plain HTTP (RFC 6797)

        using var post = await gateway.HttpAsync(Secure, "/login", HttpMethod.Post);
        Assert.Equal(HttpStatusCode.PermanentRedirect, post.StatusCode); // 308 keeps the method and body

        // Following the redirect works: the certificate is there and the backend answers.
        using var https = await gateway.HttpsAsync(Secure, "/shop/cart");
        Assert.Equal(HttpStatusCode.OK, https.StatusCode);
    }

    [Fact]
    public async Task Hsts_is_sent_over_https_only_for_routes_that_enable_it()
    {
        await using var gateway = await StartAsync();

        using (var secure = await gateway.HttpsAsync(Secure))
        {
            Assert.Equal("max-age=31536000", Hsts(secure));
        }

        using (var hstsOnly = await gateway.HttpsAsync(HstsOnly))
        {
            Assert.Equal("max-age=31536000", Hsts(hstsOnly));
        }

        using (var plain = await gateway.HttpsAsync(Plain))
        {
            Assert.Equal(HttpStatusCode.OK, plain.StatusCode);
            Assert.Null(Hsts(plain));
        }

        // HSTS without redirect: plain HTTP still works and never carries the header.
        using (var overHttp = await gateway.HttpAsync(HstsOnly, "/"))
        {
            Assert.Equal(HttpStatusCode.OK, overHttp.StatusCode);
            Assert.Null(Hsts(overHttp));
        }

        // A backend's own HSTS header is replaced, not duplicated.
        using (var backend = await gateway.HttpsAsync(Secure, "/sets-hsts"))
        {
            Assert.Equal("max-age=31536000", Hsts(backend));
        }
    }

    [Fact]
    public async Task Hsts_settings_change_the_header()
    {
        await using var gateway = await StartAsync(c =>
        {
            c.Settings.Hsts.MaxAgeSeconds = 63_072_000;
            c.Settings.Hsts.IncludeSubDomains = true;
            c.Settings.Hsts.Preload = true;
        });

        using var response = await gateway.HttpsAsync(Secure);
        Assert.Equal("max-age=63072000; includeSubDomains; preload", Hsts(response));
    }

    [Fact]
    public async Task Plain_http_routes_keep_working()
    {
        await using var gateway = await StartAsync();

        using var response = await gateway.HttpAsync(Plain, "/page");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"backend\":\"B\"", await response.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Lets_encrypt_challenges_and_waf_blocks_come_before_the_redirect()
    {
        await using var gateway = await StartAsync();
        gateway.App.Services.GetRequiredService<InMemoryAcmeChallengeStore>().Add("token-123", "token-123.thumbprint");

        using var challenge = await gateway.HttpAsync(Secure, $"{AcmeChallengeMiddleware.PathPrefix}token-123");
        Assert.Equal(HttpStatusCode.OK, challenge.StatusCode);
        Assert.Equal("token-123.thumbprint", await challenge.Content.ReadAsStringAsync(Ct));

        using var blocked = await gateway.HttpAsync(Secure, "/blocked");
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
    }

    [Fact]
    public async Task Behind_a_trusted_proxy_the_forwarded_scheme_counts()
    {
        await using var gateway = await StartAsync(c => c.Settings.TrustedProxies.Add("127.0.0.1"));

        // The proxy received HTTPS and forwards over HTTP: no redirect loop, and the HSTS header goes back.
        using var viaHttps = await gateway.HttpAsync(Secure, "/", forwardedProto: "https");
        Assert.Equal(HttpStatusCode.OK, viaHttps.StatusCode);
        Assert.Equal("max-age=31536000", Hsts(viaHttps));

        // The proxy received plain HTTP: redirected, to the standard HTTPS port the proxy serves.
        using var viaHttp = await gateway.HttpAsync(Secure, "/a?b=c", forwardedProto: "http");
        Assert.Equal(HttpStatusCode.PermanentRedirect, viaHttp.StatusCode);
        Assert.Equal($"https://{Secure}/a?b=c", viaHttp.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Redirects_are_logged_as_redirects()
    {
        await using var gateway = await StartAsync();
        using (await gateway.HttpAsync(Secure, "/logged"))
        {
        }

        var reader = gateway.App.Services.GetRequiredService<RequestLogReader>();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        RequestEvent? entry;
        while ((entry = (await reader.ReadPageAsync(new RequestLogFilter(), null, null, 50, Ct)).Items.FirstOrDefault(e => e.Path == "/logged")) is null)
        {
            Assert.True(DateTime.UtcNow < deadline, "The redirect was not logged.");
            await Task.Delay(100, Ct);
        }

        Assert.Equal((nameof(RequestAction.Redirected), 308, "secure"), (entry.Action, entry.StatusCode, entry.RouteName));
    }

    [Fact]
    public async Task A_redirect_needs_certificates_for_the_route_hosts()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Routes.Single(r => r.Name == "secure").Https.RedirectHttp = true;
        var result = await gateway.App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct);

        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Contains($"needs a certificate for {Secure}", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_route_editor_and_certificates_page_set_https_options()
    {
        await using var gateway = await StartAsync();
        string Version() => gateway.Store.GetLastKnownGoodAsync(Ct).GetAwaiter().GetResult()!.Version.ToString(CultureInfo.InvariantCulture);

        // Edit the plain route: the form shows the options; switching on the redirect works (it has a certificate).
        var page = await gateway.GetPageAsync("/routes/plain/edit");
        Assert.Contains("Redirect http:// to https://", page, StringComparison.Ordinal);
        var fields = AdminGateway.ScrapeForm(page, "route-edit");
        fields["Model.RedirectHttp"] = "True";
        fields["Model.Hsts"] = "True";
        var saved = await gateway.PostAsync("/routes/plain/edit", "route-edit", fields);
        Assert.Contains("Route &#x27;plain&#x27; changed", saved, StringComparison.Ordinal);
        Assert.Contains("HTTPS only, with HSTS", saved, StringComparison.Ordinal);
        var plain = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Routes.Single(r => r.Name == "plain");
        Assert.True(plain.Https.RedirectHttp && plain.Https.Hsts);
        using (var redirected = await gateway.HttpAsync(Plain, "/"))
        {
            Assert.Equal(HttpStatusCode.PermanentRedirect, redirected.StatusCode);
        }

        // HSTS settings on the Certificates page.
        var hsts = await gateway.PostAsync("/certificates", "hsts-settings", new()
        {
            ["Hsts.BaseVersion"] = Version(),
            ["Hsts.MaxAgeDays"] = "1",
            ["Hsts.IncludeSubDomains"] = "true",
        });
        Assert.Contains("HSTS settings saved", hsts, StringComparison.Ordinal);
        Assert.Contains("max-age=86400; includeSubDomains", hsts, StringComparison.Ordinal);
        using var response = await gateway.HttpsAsync(Secure);
        Assert.Equal("max-age=86400; includeSubDomains", Hsts(response));

        // Preload without a year is refused, with the reason.
        var refused = await gateway.PostAsync("/certificates", "hsts-settings", new()
        {
            ["Hsts.BaseVersion"] = Version(),
            ["Hsts.MaxAgeDays"] = "30",
            ["Hsts.IncludeSubDomains"] = "true",
            ["Hsts.Preload"] = "true",
        });
        Assert.Contains("Preload needs IncludeSubDomains and a MaxAgeSeconds of at least 31536000", refused, StringComparison.Ordinal);
    }
}
