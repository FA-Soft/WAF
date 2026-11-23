using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.IntegrationTests.Pipeline;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Acme;

/// <summary>
/// Let's Encrypt (ACME HTTP-01) end to end against <see cref="FakeAcmeServer"/>: the gateway registers, answers the
/// challenge on its HTTP port, stores the certificate, serves it over HTTPS and renews it.
/// </summary>
public sealed class AcmeTests
{
    private const string Host = "a.example.test";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway(FakeAcmeServer acme) : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
        [
            .. new RouteArgs().Add("a", [("http", A.Port)], hosts: [Host]).ToArray(),
            $"--Gateway:Acme:DirectoryUrl={acme.DirectoryUrl}",
            "--Gateway:Acme:PollIntervalSeconds=0.05",
        ];

        public CertificateStore Certificates => App.Services.GetRequiredService<CertificateStore>();

        public CertificateService CertificateService => App.Services.GetRequiredService<CertificateService>();

        public AcmeService Acme => App.Services.GetRequiredService<AcmeService>();

        /// <summary>Uses Let's Encrypt for <see cref="Host"/>, with the account settings (one configuration change).</summary>
        public async Task UseLetsEncryptAsync()
        {
            var configuration = (await Store.GetLastKnownGoodAsync(Ct))!.Configuration;
            configuration.Settings.Acme.Email = "admin@example.test";
            configuration.Settings.Acme.AcceptTermsOfService = true;
            configuration.Certificates.Add(new CertificateBinding { HostName = Host, Source = CertificateSource.LetsEncrypt });
            var service = App.Services.GetRequiredService<IGatewayConfigurationService>();
            Assert.True((await service.ActivateAsync(configuration, AuditActor.System("test"), "Let's Encrypt for a.example.test.", Ct)).Succeeded);
        }

        public CertificateStatus Status => CertificateService.Statuses.Single(s => s.HostName == Host);
    }

    private static async Task<(FakeAcmeServer Acme, Gateway Gateway)> StartAsync()
    {
        Gateway? gateway = null;
        var acme = await FakeAcmeServer.StartAsync(() => gateway!.HttpPort);
        gateway = new Gateway(acme);
        await gateway.InitializeAsync();
        return (acme, gateway);
    }

    /// <summary>The certificate the gateway presents for <paramref name="host"/> over HTTPS, or null when the handshake fails.</summary>
    private static async Task<X509Certificate2?> PresentedAsync(Gateway gateway, string host)
    {
        X509Certificate2? presented = null;
        using var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, cancellationToken) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(IPAddress.Loopback, gateway.HttpsPort, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            },
            SslOptions =
            {
#pragma warning disable CA5359 // The test CA is not trusted: record what was presented instead.
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    presented = X509CertificateLoader.LoadCertificate(certificate!.GetRawCertData());
                    return true;
                },
#pragma warning restore CA5359
            },
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        try
        {
            using var response = await client.GetAsync(new Uri($"https://{host}/"), Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return presented;
        }
        catch (HttpRequestException)
        {
            return null;
        }
    }

    private static async Task WaitUntilAsync(Func<Task<bool>> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!await condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"Timed out waiting until {what}.");
            await Task.Delay(100, Ct);
        }
    }

    [Fact]
    public async Task A_certificate_is_issued_served_and_renewed()
    {
        var (acme, gateway) = await StartAsync();
        await using (acme)
        await using (gateway)
        {
            Assert.Null(await PresentedAsync(gateway, Host)); // nothing yet: the handshake is refused

            // First certificate: issued 80 days ago, so with 10 of its 90 days left it is due for renewal right away.
            acme.Backdate = TimeSpan.FromDays(80);
            acme.RejectNextNonce = true; // the client must retry a badNonce
            await gateway.UseLetsEncryptAsync();
            await WaitUntilAsync(async () => await PresentedAsync(gateway, Host) is not null, "the first certificate is served");

            Assert.Contains(Host, acme.Validated); // proven over HTTP-01 through the gateway's port
            Assert.True(acme.BadNoncesSent >= 1);
            using (var first = (await PresentedAsync(gateway, Host))!)
            {
                Assert.Equal("CN=Test Intermediate CA", first.Issuer);
                Assert.Contains(Host, CertificateNames.DnsNames(first));
            }

            // Renewal: the next certificates are new; the renewed one replaces the first, which is deleted.
            acme.Backdate = TimeSpan.FromMinutes(5);
            await gateway.Acme.RunOnceAsync(Ct);
            await WaitUntilAsync(
                async () => (await PresentedAsync(gateway, Host))?.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(80),
                "the renewed certificate is served");

            Assert.True(acme.Issued.Count >= 2);
            var stored = (await gateway.Certificates.GetAllAsync(Ct)).Where(c => c.IsAcme).ToList();
            Assert.Equal(Host, Assert.Single(stored).AcmeHostName);
            Assert.Equal(acme.DirectoryUrl, stored[0].AcmeDirectory);
            Assert.Equal(CertificateState.Ok, gateway.Status.State);
            Assert.Empty(await gateway.CertificateService.GetStoredAsync(Ct)); // not listed as an uploaded certificate

            var security = (await gateway.AuditLog.ReadPageAsync(new AuditFilter { Category = AuditCategory.Security }, null, null, 50, Ct)).Items;
            Assert.Contains(security, e => e.Action == AuditActions.CertificateIssued);
            Assert.Contains(security, e => e.Action == AuditActions.CertificateRenewed);

            // Up to date now: another check issues nothing.
            var issued = acme.Issued.Count;
            Assert.Equal(0, await gateway.Acme.RunOnceAsync(Ct));
            Assert.Equal(issued, acme.Issued.Count);
        }
    }

    [Fact]
    public async Task A_failed_validation_is_shown_and_can_be_retried()
    {
        var (acme, gateway) = await StartAsync();
        await using (acme)
        await using (gateway)
        {
            acme.FailValidation = true;
            await gateway.UseLetsEncryptAsync();
            await WaitUntilAsync(() => Task.FromResult(gateway.Status.State == CertificateState.Missing), "the failure is reported");

            Assert.Contains("Let's Encrypt failed", gateway.Status.Problem, StringComparison.Ordinal);
            Assert.Contains("port 80", gateway.Status.Problem, StringComparison.Ordinal);
            var dashboard = await gateway.GetPageAsync("/");
            Assert.Contains("a.example.test: no certificate could be loaded", dashboard, StringComparison.Ordinal);

            // Backing off: a regular check does not try again right away.
            Assert.Equal(0, await gateway.Acme.RunOnceAsync(Ct));

            // Fixed, then "Request certificates now" in the UI.
            acme.FailValidation = false;
            var page = await gateway.GetPageAsync("/certificates");
            Assert.Contains("Request certificates now", page, StringComparison.Ordinal);
            await gateway.PostAsync("/certificates", "request-letsencrypt", []);
            await WaitUntilAsync(async () => await PresentedAsync(gateway, Host) is not null, "the certificate is issued after the retry");
            Assert.Equal(CertificateState.Ok, gateway.Status.State);
        }
    }

    [Fact]
    public async Task The_admin_ui_chooses_lets_encrypt_per_host_name()
    {
        var (acme, gateway) = await StartAsync();
        await using (acme)
        await using (gateway)
        {
            string Version() => gateway.Store.GetLastKnownGoodAsync(Ct).GetAwaiter().GetResult()!.Version.ToString(CultureInfo.InvariantCulture);

            // Without the account settings the configuration is refused, with the reason.
            var refused = await gateway.PostAsync("/certificates", "use-letsencrypt", new()
            {
                ["LetsEncryptHost.BaseVersion"] = Version(),
                ["LetsEncryptHost.HostName"] = Host,
            });
            Assert.Contains("a valid contact e-mail is required", refused, StringComparison.Ordinal);

            var saved = await gateway.PostAsync("/certificates", "acme-settings", new()
            {
                ["Acme.BaseVersion"] = Version(),
                ["Acme.Email"] = "admin@example.test",
                ["Acme.AcceptTermsOfService"] = "true",
                ["Acme.UseStaging"] = "true",
            });
            Assert.Contains("Let&#x27;s Encrypt settings saved", saved, StringComparison.Ordinal);
            Assert.True((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Settings.Acme.UseStaging);

            var used = await gateway.PostAsync("/certificates", "use-letsencrypt", new()
            {
                ["LetsEncryptHost.BaseVersion"] = Version(),
                ["LetsEncryptHost.HostName"] = " A.Example.Test ",
            });
            Assert.Contains("a.example.test gets its certificate from Let&#x27;s Encrypt", used, StringComparison.Ordinal);
            var binding = Assert.Single((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Certificates);
            Assert.Equal((Host, CertificateSource.LetsEncrypt), (binding.HostName, binding.Source));

            await WaitUntilAsync(async () => await PresentedAsync(gateway, Host) is not null, "the certificate is issued");
        }
    }

    [Theory]
    [InlineData(false, AcmeHostOptions.ProductionDirectory)]
    [InlineData(true, AcmeHostOptions.StagingDirectory)]
    public void The_staging_switch_chooses_the_lets_encrypt_environment(bool staging, string expected)
    {
        Assert.Equal(expected, new AcmeHostOptions().Directory(new AcmeSettings { UseStaging = staging }));
        Assert.Equal("https://acme.test/dir", new AcmeHostOptions { DirectoryUrl = "https://acme.test/dir" }.Directory(new AcmeSettings { UseStaging = staging }));
    }
}
