using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.IntegrationTests.Pipeline;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.Web;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Acme;

/// <summary>
/// Let's Encrypt's own test server, Pebble (https://github.com/letsencrypt/pebble), in Docker: the closest thing to the
/// Let's Encrypt staging environment that a test machine can use (staging itself needs a public host name and port
/// 80 reachable from the internet). Pebble validates HTTP-01 over the network, rejects 5% of nonces on purpose and
/// issues real certificate chains. Opt-in: set WAF_PEBBLE=1 (needs Docker, Linux or Windows containers).
/// </summary>
public sealed class PebbleTests
{
    private const string Host = "pebble.example.test";
    private const string Image = "ghcr.io/letsencrypt/pebble:latest";
    private const string DnsImage = "ghcr.io/letsencrypt/pebble-challtestsrv:latest";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Gateway(string directoryUrl, string rootPath) : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
        [
            .. new RouteArgs().Add("pebble", [("http", A.Port)], hosts: [Host]).ToArray(),
            "--Gateway:Endpoints:PublicBindAddress=*", // Pebble connects from the container network
            $"--Gateway:Acme:DirectoryUrl={directoryUrl}",
            $"--Gateway:Acme:TrustedRootCertificatePath={rootPath}",
            "--Gateway:Acme:PollIntervalSeconds=0.5",
        ];
    }

    private static async Task<string> DockerAsync(params string[] args)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start)!;
        var output = await process.StandardOutput.ReadToEndAsync(Ct);
        var error = await process.StandardError.ReadToEndAsync(Ct);
        await process.WaitForExitAsync(Ct);
        Assert.True(process.ExitCode == 0, $"docker {string.Join(' ', args)} failed: {error}");
        return output.Trim();
    }

    [Fact]
    public async Task Pebble_issues_and_renews_a_certificate()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("WAF_PEBBLE") == "1", "Set WAF_PEBBLE=1 to run against Pebble in Docker.");

        var work = Path.Combine(Path.GetTempPath(), "waf-pebble", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        var name = $"waf-pebble-{Guid.NewGuid():N}"[..24];
        var dnsName = $"{name}-dns";
        var acmePort = GatewayFixture.FreePort();
        await using var gateway = new Gateway($"https://localhost:{acmePort}/dir", Path.Combine(work, "pebble.minica.pem"));
        try
        {
            // Pebble validates HTTP-01 on the gateway's HTTP port; the host name resolves to this machine.
            var windows = await DockerAsync("info", "--format", "{{.OSType}}") == "windows";
            var hostAddress = windows
                ? await DockerAsync("network", "inspect", "nat", "--format", "{{(index .IPAM.Config 0).Gateway}}")
                : "host-gateway";
            var config = new JsonObject
            {
                ["pebble"] = new JsonObject
                {
                    ["listenAddress"] = "0.0.0.0:14000",
                    ["managementListenAddress"] = "0.0.0.0:15000",
                    ["certificate"] = "test/certs/localhost/cert.pem",
                    ["privateKey"] = "test/certs/localhost/key.pem",
                    ["httpPort"] = gateway.HttpPort,
                    ["tlsPort"] = 5001,
                    ["ocspResponderURL"] = string.Empty,
                    ["externalAccountBindingRequired"] = false,
                },
            };
            await File.WriteAllTextAsync(Path.Combine(work, "pebble-config.json"), config.ToJsonString(), Ct);
            // Pebble's test DNS server answers every name with this machine's address (as public DNS would point the
            // host name at the gateway). Its own HTTP-01 and TLS-ALPN servers are not used.
            await DockerAsync("run", "-d", "--name", dnsName, DnsImage,
                "-defaultIPv4", windows ? hostAddress : "172.17.0.1", "-defaultIPv6", string.Empty,
                "-http01", string.Empty, "-https01", string.Empty, "-tlsalpn01", string.Empty, "-doh", string.Empty);
            var dnsAddress = await DockerAsync("inspect", dnsName, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}");

            var mount = windows ? "C:\\cfg" : "/cfg";
            await DockerAsync(
                "run", "-d", "--name", name, "-p", $"{acmePort}:14000", "-e", "PEBBLE_VA_NOSLEEP=1", "-v", $"{work}:{mount}",
                Image, "-config", windows ? "C:\\cfg\\pebble-config.json" : "/cfg/pebble-config.json", "-dnsserver", $"{dnsAddress}:8053");
            // Pebble's own CA, to trust its HTTPS directory (the Linux image has no shell: copy the file out).
            var rootPath = Path.Combine(work, "pebble.minica.pem");
            if (windows)
            {
                await File.WriteAllTextAsync(rootPath, await DockerAsync("exec", name, "cmd", "/c", "type", "C:\\test\\certs\\pebble.minica.pem"), Ct);
            }
            else
            {
                await DockerAsync("cp", $"{name}:/test/certs/pebble.minica.pem", rootPath);
            }

            await gateway.InitializeAsync();
            var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
            configuration.Settings.Acme.Email = "admin@example.test";
            configuration.Settings.Acme.AcceptTermsOfService = true;
            configuration.Settings.Acme.UseStaging = true;
            configuration.Certificates.Add(new CertificateBinding { HostName = Host, Source = CertificateSource.LetsEncrypt });
            var service = gateway.App.Services.GetRequiredService<IGatewayConfigurationService>();
            Assert.True((await service.ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

            var certificates = gateway.App.Services.GetRequiredService<CertificateStore>();
            var directory = $"https://localhost:{acmePort}/dir";
            var deadline = DateTime.UtcNow.AddMinutes(3);
            StoredCertificate? first;
            while ((first = await certificates.FindAcmeAsync(Host, directory, Ct)) is null)
            {
                var status = gateway.App.Services.GetRequiredService<CertificateService>().Statuses.Single(s => s.HostName == Host);
                Assert.True(DateTime.UtcNow < deadline, $"No certificate from Pebble: {status.State} {status.Problem}");
                await Task.Delay(500, Ct);
            }

            Assert.StartsWith("CN=Pebble Intermediate CA", first.Issuer, StringComparison.Ordinal);
            await WaitUntilPresentedAsync(gateway, first.Thumbprint);

            // Renewal against Pebble: a new certificate replaces the first one.
            Assert.True(await gateway.App.Services.GetRequiredService<AcmeService>().RenewNowAsync(Host, Ct));
            var renewed = (await certificates.FindAcmeAsync(Host, directory, Ct))!;
            Assert.NotEqual(first.Thumbprint, renewed.Thumbprint);
            await WaitUntilPresentedAsync(gateway, renewed.Thumbprint);
            Assert.Single(await certificates.GetAllAsync(Ct), c => c.IsAcme);
        }
        finally
        {
            await DockerAsync("rm", "-f", name).ContinueWith(_ => { }, TaskScheduler.Default);
            await DockerAsync("rm", "-f", dnsName).ContinueWith(_ => { }, TaskScheduler.Default);
            try
            {
                Directory.Delete(work, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    /// <summary>Waits until the gateway serves <paramref name="thumbprint"/> (stored first, then swapped in).</summary>
    private static async Task WaitUntilPresentedAsync(Gateway gateway, string thumbprint)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            string? presented = null;
            try
            {
                presented = await PresentedThumbprintAsync(gateway);
            }
            catch (HttpRequestException)
            {
                // not served yet
            }

            if (presented == thumbprint)
            {
                return;
            }

            Assert.True(DateTime.UtcNow < deadline, $"The gateway still presents {presented ?? "nothing"} instead of {thumbprint}.");
            await Task.Delay(200, Ct);
        }
    }

    private static async Task<string> PresentedThumbprintAsync(Gateway gateway)
    {
        string? thumbprint = null;
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
#pragma warning disable CA5359 // Pebble's CA is not trusted here: record what was presented instead.
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    thumbprint = X509CertificateLoader.LoadCertificate(certificate!.GetRawCertData()).GetCertHashString(HashAlgorithmName.SHA256);
                    return true;
                },
#pragma warning restore CA5359
            },
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var response = await client.GetAsync(new Uri($"https://{Host}/"), Ct);
        return thumbprint!;
    }
}
