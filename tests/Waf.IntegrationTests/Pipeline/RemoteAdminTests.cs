using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using FASoft.Waf.Cli;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Proxy;
using FASoft.Waf.UnitTests.Tls;
using FASoft.Waf.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>Remote admin access on a registered host name, over real HTTPS connections.</summary>
public sealed partial class RemoteAdminTests
{
    private const string AdminHost = "admin.example.test";
    private const string SiteHost = "www.example.test";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A gateway with route "website" (www.example.test) and one certificate file for both host names.</summary>
    private sealed class Gateway(string? dataDirectory = null) : GatewayFixture
    {
        public BackendServer A { get; private set; } = null!;

        protected override async ValueTask BeforeStartAsync() => A = await BackendServer.StartAsync("A");

        protected override IEnumerable<string> ExtraArgs =>
        [
            .. new RouteArgs().Add("website", [("http", A.Port)], hosts: [SiteHost]).ToArray(),
            .. dataDirectory is null ? Array.Empty<string>() : [$"--Gateway:Storage:DataDirectory={dataDirectory}"],
        ];

        protected override async ValueTask AfterStopAsync() => await A.DisposeAsync();

        public string Data => dataDirectory ?? DataDirectory;

        public ConfigurationStore Store => App.Services.GetRequiredService<ConfigurationStore>();

        public RemoteAdminAccess Remote => App.Services.GetRequiredService<RemoteAdminAccess>();

        /// <summary>A certificate (file) for the admin and site host names, activated.</summary>
        public async Task AddCertificateAsync()
        {
            using var certificate = TestCertificates.SelfSigned(AdminHost, SiteHost);
            var path = Path.Combine(Data, "remote.pem");
            await File.WriteAllTextAsync(path, TestCertificates.CertificatePem(certificate) + TestCertificates.KeyPem(certificate), Ct);
            var configuration = (await Store.GetLastKnownGoodAsync(Ct))!.Configuration;
            foreach (var host in new[] { AdminHost, SiteHost })
            {
                configuration.Certificates.Add(new CertificateBinding { HostName = host, Source = CertificateSource.File, CertificatePath = path });
            }

            Assert.True((await App.Services.GetRequiredService<IGatewayConfigurationService>().ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);
        }

        /// <summary>Registers <paramref name="url"/> directly in identity.db (as the Remote access page does) and applies it.</summary>
        public async Task RegisterAsync(string url)
        {
            Assert.True(RemoteAdminUrl.TryParse(url, out var parsed, out _));
            await using (var scope = App.Services.CreateAsyncScope())
            {
                await scope.ServiceProvider.GetRequiredService<AdminAccessStore>().RegisterUrlAsync(parsed!, Ct);
            }

            await Remote.RefreshAsync(Ct);
        }

        /// <summary>Turns on 2FA for the admin account; returns the authenticator key.</summary>
        public async Task<string> EnableTwoFactorAsync()
        {
            await using var scope = App.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var user = (await users.FindByNameAsync(AdminUserName))!;
            await users.ResetAuthenticatorKeyAsync(user);
            await users.SetTwoFactorEnabledAsync(user, true);
            return (await users.GetAuthenticatorKeyAsync(user))!;
        }
    }

    /// <summary>A browser for https://{host}:{port}: SNI and Host are the host name; cookies kept; no redirects followed.</summary>
    private sealed class Browser : IDisposable
    {
        private readonly HttpClient _client;
        private readonly string _origin;

        public Browser(int port, string host = AdminHost)
        {
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = true,
                CookieContainer = new CookieContainer(),
                ConnectCallback = async (_, cancellationToken) =>
                {
                    var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    await socket.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                },
#pragma warning disable CA5359 // Self-signed test certificate.
                SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
#pragma warning restore CA5359
            };
            _client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(10) };
            _origin = $"https://{host}:{port}";
        }

        public async Task<(HttpStatusCode Status, string Body, HttpResponseMessage Response)> GetAsync(string path)
        {
            var response = await _client.GetAsync(new Uri(_origin + path), Ct);
            return (response.StatusCode, await response.Content.ReadAsStringAsync(Ct), response);
        }

        /// <summary>Posts form <paramref name="handler"/> of <paramref name="path"/>; follows one redirect (as a browser would).</summary>
        public async Task<(string Path, string Body)> PostFormAsync(string path, string handler, Dictionary<string, string> fields)
        {
            var (_, page, _) = await GetAsync(path);
            fields["__RequestVerificationToken"] = TokenPattern().Match(page).Groups["token"].Value;
            fields["_handler"] = handler;
            using var content = new FormUrlEncodedContent(fields);
            using var response = await _client.PostAsync(new Uri(_origin + path), content, Ct);
            if (response.Headers.Location is { } location)
            {
                var target = location.IsAbsoluteUri ? location.PathAndQuery : location.OriginalString;
                var (_, body, followed) = await GetAsync(target.StartsWith('/') ? target : "/" + target);
                followed.Dispose();
                return (target, body);
            }

            return (path, await response.Content.ReadAsStringAsync(Ct));
        }

        public void Dispose() => _client.Dispose();
    }

    private static async Task<Gateway> StartAsync()
    {
        var gateway = new Gateway();
        await gateway.InitializeAsync();
        using (var local = NewLocalClient())
        {
            await gateway.SignInAsync(local); // creates the admin account
        }

        await gateway.AddCertificateAsync();
        return gateway;
    }

    private static HttpClient NewLocalClient() =>
        new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() }) { Timeout = TimeSpan.FromSeconds(10) };

    private static Task<(string Path, string Body)> LoginAsync(Browser browser, string password = GatewayFixture.AdminPassword) =>
        browser.PostFormAsync("/account/login", "login", new() { ["Model.UserName"] = GatewayFixture.AdminUserName, ["Model.Password"] = password, ["Model.ReturnUrl"] = "/" });

    [Fact]
    public async Task Remote_access_is_off_by_default()
    {
        await using var gateway = await StartAsync();
        using var browser = new Browser(gateway.HttpsPort);

        var (status, body, response) = await browser.GetAsync("/account/login");
        using (response)
        {
            Assert.Equal(HttpStatusCode.NotFound, status); // public traffic: no route for this host
            Assert.DoesNotContain("Sign in", body, StringComparison.Ordinal);
        }

        Assert.Null(gateway.Remote.Current.Url);
    }

    [Fact]
    public async Task Before_sign_in_only_the_sign_in_page_answers_and_everything_else_is_not_found()
    {
        await using var gateway = await StartAsync();
        await gateway.RegisterAsync($"https://{AdminHost}");
        using var browser = new Browser(gateway.HttpsPort);

        var (loginStatus, login, loginResponse) = await browser.GetAsync("/account/login");
        using (loginResponse)
        {
            Assert.Equal(HttpStatusCode.OK, loginStatus);
            Assert.Contains("Sign in", login, StringComparison.Ordinal);
            Assert.Equal(FASoft.Waf.Host.Hosting.AdminPipeline.StrictTransportSecurity, loginResponse.Headers.GetValues("Strict-Transport-Security").Single());
        }

        foreach (var path in new[] { "/", "/routes", "/healthz", "/account/setup", "/history/1", "/nothing" })
        {
            var (status, body, response) = await browser.GetAsync(path);
            using (response)
            {
                Assert.True(status == HttpStatusCode.NotFound, $"{path}: {status}");
                Assert.Empty(body);
                Assert.False(response.Headers.Contains("Content-Security-Policy"), $"{path} reveals the admin UI's headers");
                Assert.False(response.Headers.Contains("Strict-Transport-Security"), $"{path} reveals the admin UI's headers");
            }
        }

        // The site keeps working on the same HTTPS port.
        using var site = new Browser(gateway.HttpsPort, SiteHost);
        var (siteStatus, _, siteResponse) = await site.GetAsync("/");
        siteResponse.Dispose();
        Assert.Equal(HttpStatusCode.OK, siteStatus);
    }

    [Fact]
    public async Task Https_only_with_matching_server_name()
    {
        await using var gateway = await StartAsync();
        await gateway.RegisterAsync($"https://{AdminHost}");
        gateway.App.Services.GetRequiredService<InMemoryAcmeChallengeStore>().Add("token-1", "token-1.key");

        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };
        async Task<(HttpStatusCode, string)> PlainAsync(string path)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.HttpPort}{path}"));
            request.Headers.Host = AdminHost;
            using var response = await http.SendAsync(request, Ct);
            return (response.StatusCode, await response.Content.ReadAsStringAsync(Ct));
        }

        Assert.Equal((HttpStatusCode.NotFound, string.Empty), await PlainAsync("/account/login"));
        Assert.Equal((HttpStatusCode.OK, "token-1.key"), await PlainAsync($"{AcmeChallengeMiddleware.PathPrefix}token-1")); // Let's Encrypt still works

        // TLS for another host name (SNI), then "Host: admin host": not the admin UI. A raw request, because HttpClient
        // always sends the URL's host as SNI.
        var mismatch = await RawHttpsGetAsync(gateway.HttpsPort, sni: SiteHost, host: AdminHost, "/account/login");
        Assert.StartsWith("HTTP/1.1 404", mismatch, StringComparison.Ordinal);
        Assert.DoesNotContain("Sign in", mismatch, StringComparison.Ordinal);

        // The same raw request with a matching SNI does reach the sign-in page (the check above is meaningful).
        Assert.StartsWith("HTTP/1.1 200", await RawHttpsGetAsync(gateway.HttpsPort, sni: AdminHost, host: AdminHost, "/account/login"), StringComparison.Ordinal);
    }

    /// <summary>GET over TLS with a chosen SNI and Host header; returns the raw response.</summary>
    private static async Task<string> RawHttpsGetAsync(int port, string sni, string host, string path)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port, Ct);
        await using var tls = new System.Net.Security.SslStream(tcp.GetStream());
#pragma warning disable CA5359 // Self-signed test certificate.
        await tls.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
        {
            TargetHost = sni,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
            ApplicationProtocols = [System.Net.Security.SslApplicationProtocol.Http11],
        }, Ct);
#pragma warning restore CA5359
        await tls.WriteAsync(System.Text.Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"), Ct);
        using var reader = new StreamReader(tls);
        return await reader.ReadToEndAsync(Ct);
    }

    [Fact]
    public async Task Remote_sign_in_needs_two_factor()
    {
        await using var gateway = await StartAsync();
        await gateway.RegisterAsync($"https://{AdminHost}");
        using var browser = new Browser(gateway.HttpsPort);

        var (_, refused) = await LoginAsync(browser);
        Assert.Contains("Signing in remotely needs two-factor sign-in", refused, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await browser.GetAsync("/")).Status);

        var key = await gateway.EnableTwoFactorAsync();
        var (path, _) = await LoginAsync(browser);
        Assert.StartsWith("/account/login/two-factor", path, StringComparison.Ordinal);
        var (signedIn, dashboard) = await browser.PostFormAsync($"/account/login/two-factor?returnUrl=%2F", "two-factor", new() { ["Model.Code"] = Totp(key), ["Model.ReturnUrl"] = "/" });
        Assert.Equal("/", signedIn);
        Assert.Contains("Dashboard", dashboard, StringComparison.Ordinal);

        var (status, page, response) = await browser.GetAsync("/routes");
        using (response)
        {
            Assert.Equal(HttpStatusCode.OK, status);
            Assert.Contains("website", page, StringComparison.Ordinal);
            Assert.True(response.Headers.Contains("Content-Security-Policy"));
        }

        // Turning 2FA off is refused remotely.
        var (_, twoFactor) = await browser.PostFormAsync("/account/two-factor", "disable-two-factor", new() { ["Disable.Password"] = GatewayFixture.AdminPassword });
        Assert.Contains("cannot be turned off over remote access", twoFactor, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_allowlist_hides_remote_access_from_other_addresses()
    {
        await using var gateway = await StartAsync();
        await gateway.RegisterAsync($"https://{AdminHost}");
        await using (var scope = gateway.App.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<AdminAccessStore>().SetAllowedNetworksAsync(["203.0.113.0/24"], Ct);
        }

        await gateway.Remote.RefreshAsync(Ct);
        using var browser = new Browser(gateway.HttpsPort);
        var (refusedStatus, refusedBody, refusedResponse) = await browser.GetAsync("/account/login");
        refusedResponse.Dispose();
        Assert.Equal((HttpStatusCode.NotFound, string.Empty), (refusedStatus, refusedBody));

        await using (var scope = gateway.App.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<AdminAccessStore>().SetAllowedNetworksAsync(["203.0.113.0/24", "127.0.0.1"], Ct);
        }

        await gateway.Remote.RefreshAsync(Ct);
        var (status, _, response) = await browser.GetAsync("/account/login");
        response.Dispose();
        Assert.Equal(HttpStatusCode.OK, status);
    }

    [Fact]
    public async Task Wafctl_turns_remote_access_off_while_the_gateway_runs()
    {
        await using var gateway = await StartAsync();
        await gateway.RegisterAsync($"https://{AdminHost}");
        using var browser = new Browser(gateway.HttpsPort);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/account/login")).Status);

        using var output = new StringWriter();
        using var error = new StringWriter();
        var exit = await new WafCtl(output, error, TextReader.Null, new NoTerminal(), TimeProvider.System)
            .RunAsync(["--data-dir", gateway.Data, "admin", "unregister-url"], Ct);
        Assert.Equal(WafCtl.Success, exit);

        // Picked up within a few seconds, without the admin UI being involved.
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while ((await browser.GetAsync("/account/login")).Status != HttpStatusCode.NotFound)
        {
            Assert.True(DateTime.UtcNow < deadline, "Remote access is still on after wafctl turned it off.");
            await Task.Delay(200, Ct);
        }

        Assert.Null(gateway.Remote.Current.Url);
    }

    [Fact]
    public async Task The_remote_access_page_checks_the_requirements_and_registers()
    {
        await using var gateway = await StartAsync();
        using var local = NewLocalClient();
        await gateway.SignInAsync(local);
        var origin = $"http://127.0.0.1:{gateway.AdminPort}";

        async Task<string> PostAsync(HttpClient client, string handler, Dictionary<string, string> fields)
        {
            var page = await client.GetStringAsync(new Uri($"{origin}/remote-access"), Ct);
            fields["__RequestVerificationToken"] = TokenPattern().Match(page).Groups["token"].Value;
            fields["_handler"] = handler;
            using var content = new FormUrlEncodedContent(fields);
            using var response = await client.PostAsync(new Uri($"{origin}/remote-access"), content, Ct);
            return await response.Content.ReadAsStringAsync(Ct);
        }

        Assert.Contains("<span class=\"badge badge-muted\">Off</span>", await local.GetStringAsync(new Uri($"{origin}/remote-access"), Ct), StringComparison.Ordinal);

        var noTwoFactor = await PostAsync(local, "remote-register", new() { ["UrlForm.Url"] = $"https://{AdminHost}" });
        Assert.Contains("Turn on two-factor sign-in for your account first", noTwoFactor, StringComparison.Ordinal);
        var plainHttp = await PostAsync(local, "remote-register", new() { ["UrlForm.Url"] = $"http://{AdminHost}" });
        Assert.Contains("HTTPS only", plainHttp, StringComparison.Ordinal);

        // With 2FA (sign in again: turning it on ends the session).
        var key = await gateway.EnableTwoFactorAsync();
        using var admin = NewLocalClient();
        var login = await admin.GetStringAsync(new Uri($"{origin}/account/login"), Ct);
        using (var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = TokenPattern().Match(login).Groups["token"].Value, ["_handler"] = "login",
            ["Model.UserName"] = GatewayFixture.AdminUserName, ["Model.Password"] = GatewayFixture.AdminPassword,
        }))
        {
            using var _ = await admin.PostAsync(new Uri($"{origin}/account/login"), form, Ct);
        }

        var codePage = await admin.GetStringAsync(new Uri($"{origin}/account/login/two-factor"), Ct);
        using (var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = TokenPattern().Match(codePage).Groups["token"].Value, ["_handler"] = "two-factor",
            ["Model.Code"] = Totp(key), ["Model.ReturnUrl"] = "/",
        }))
        {
            using var _ = await admin.PostAsync(new Uri($"{origin}/account/login/two-factor"), form, Ct);
        }

        var routeHost = await PostAsync(admin, "remote-register", new() { ["UrlForm.Url"] = $"https://{SiteHost}" });
        Assert.Contains("is used by route &#x27;website&#x27;", routeHost, StringComparison.Ordinal);
        var noCertificate = await PostAsync(admin, "remote-register", new() { ["UrlForm.Url"] = "https://other.example.test" });
        Assert.Contains("There is no certificate for other.example.test", noCertificate, StringComparison.Ordinal);
        var reservedPort = await PostAsync(admin, "remote-register", new() { ["UrlForm.Url"] = $"https://{AdminHost}:{gateway.HttpPort}" });
        Assert.Contains($"Port {gateway.HttpPort} is already used", reservedPort, StringComparison.Ordinal);

        var registered = await PostAsync(admin, "remote-register", new() { ["UrlForm.Url"] = $"https://{AdminHost.ToUpperInvariant()}" });
        Assert.Contains($"Remote access is on at https://{AdminHost}.", registered, StringComparison.Ordinal);
        Assert.Equal($"https://{AdminHost}", gateway.Remote.Current.Url?.ToString());

        var badList = await PostAsync(admin, "remote-allowlist", new() { ["Allowlist.Networks"] = "10.0.0.5/8" });
        Assert.Contains("Nothing was changed.", badList, StringComparison.Ordinal);
        var list = await PostAsync(admin, "remote-allowlist", new() { ["Allowlist.Networks"] = "127.0.0.1\n2001:db8::/32" });
        Assert.Contains("Allowed addresses saved.", list, StringComparison.Ordinal);
        Assert.Equal(2, gateway.Remote.Current.Allowed.Count);

        var off = await PostAsync(admin, "remote-off", []);
        Assert.Contains("Remote access is off.", off, StringComparison.Ordinal);
        Assert.Null(gateway.Remote.Current.Url);
    }

    [Fact]
    public async Task A_dedicated_port_opens_at_the_next_start_and_serves_only_the_admin_ui()
    {
        var data = GatewayFixture.NewDataDirectory();
        var port = GatewayFixture.FreePort();
        try
        {
            await using (var first = new Gateway(data))
            {
                await first.InitializeAsync();
                using (var local = NewLocalClient())
                {
                    await first.SignInAsync(local);
                }

                await first.AddCertificateAsync();
                await first.RegisterAsync($"https://{AdminHost}:{port}");
                Assert.False(first.Remote.IsListening(port)); // a restart opens it
            }

            await using var second = new Gateway(data);
            await second.InitializeAsync();
            Assert.True(second.Remote.IsListening(port));

            using (var remote = new Browser(port))
            {
                Assert.Equal(HttpStatusCode.OK, (await remote.GetAsync("/account/login")).Status);
            }

            // The dedicated port serves nothing else; the admin host on the normal HTTPS port is not the admin UI.
            using (var other = new Browser(port, SiteHost))
            {
                Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync("/")).Status);
            }

            using (var normalPort = new Browser(second.HttpsPort))
            {
                var (status, body, response) = await normalPort.GetAsync("/account/login");
                response.Dispose();
                Assert.Equal(HttpStatusCode.NotFound, status);
                Assert.DoesNotContain("Sign in", body, StringComparison.Ordinal);
            }
        }
        finally
        {
            GatewayFixture.DeleteDataDirectory(data);
        }
    }

    private sealed class NoTerminal : ISecretReader
    {
        public string? Read(string prompt) => null;
    }

    /// <summary>RFC 6238 code (SHA-1, 30 s, 6 digits) for <paramref name="base32Key"/>.</summary>
    private static string Totp(string base32Key)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var c in base32Key.TrimEnd('=').ToUpperInvariant())
        {
            buffer = (buffer << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".IndexOf(c, StringComparison.Ordinal);
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                bytes.Add((byte)(buffer >> bits));
            }
        }

#pragma warning disable CA5350 // TOTP is defined on HMAC-SHA1.
        var hash = HMACSHA1.HashData([.. bytes], counter);
#pragma warning restore CA5350
        var offset = hash[^1] & 0x0f;
        var value = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (value % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex TokenPattern();
}
