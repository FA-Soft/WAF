using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.IntegrationTests.Proxy;
using FASoft.Waf.UnitTests.Tls;
using FASoft.Waf.Web;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>Own certificates over real HTTPS connections: upload, SNI selection, encryption at rest, warnings, backups.</summary>
public sealed class CertificatesTests
{
    private const string PfxPassword = "pfx password";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Routes a.example.test → A, b.example.test → B and shop.wild.test → A.</summary>
    private sealed class Gateway : AdminGateway
    {
        protected override IEnumerable<string> ExtraArgs =>
            new RouteArgs()
                .Add("a", [("http", A.Port)], hosts: ["a.example.test"])
                .Add("b", [("http", B.Port)], hosts: ["b.example.test"])
                .Add("wild", [("http", A.Port)], hosts: ["shop.wild.test"])
                .ToArray();

        public CertificateService Certificates => App.Services.GetRequiredService<CertificateService>();

        public async Task<long> ActiveVersionAsync() => (await Store.GetLastKnownGoodAsync(Ct))!.Version;
    }

    private sealed record HttpsResult(HttpStatusCode Status, string Body, string Thumbprint);

    /// <summary>
    /// GET https://{host}/ against the gateway's HTTPS port: the TLS handshake carries <paramref name="host"/> as SNI.
    /// Returns the answer and the certificate the gateway presented.
    /// </summary>
    private static async Task<HttpsResult> HttpsGetAsync(Gateway gateway, string host)
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
                // Test certificates are self-signed: record what was presented instead of validating it.
#pragma warning disable CA5359 // The test checks which certificate was presented, not whether it is trusted.
                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    presented = X509CertificateLoader.LoadCertificate(certificate!.GetRawCertData());
                    return true;
                },
#pragma warning restore CA5359
            },
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var response = await client.GetAsync(new Uri($"https://{host}/"), Ct);
        using (presented)
        {
            // The test backends answer with JSON naming themselves: {"backend":"A",...}.
            var body = await response.Content.ReadAsStringAsync(Ct);
            var backend = body.StartsWith('{') ? System.Text.Json.JsonElement.Parse(body).GetProperty("backend").GetString()! : body;
            return new HttpsResult(response.StatusCode, backend, presented!.GetCertHashString(HashAlgorithmName.SHA256));
        }
    }

    /// <summary>Uploads <paramref name="file"/> through the admin UI and uses it for <paramref name="host"/>; returns its thumbprint.</summary>
    private static async Task<string> UploadAndUseAsync(Gateway gateway, byte[] file, string fileName, string? password, string host)
    {
        var uploaded = await gateway.PostMultipartAsync(
            "/certificates/upload", "upload-certificate", new() { ["Model.Password"] = password ?? string.Empty }, "certificateFile", fileName, file);
        Assert.Contains("The certificate was uploaded; its private key is stored encrypted.", uploaded, StringComparison.Ordinal);

        var thumbprint = (await gateway.Certificates.GetStoredAsync(Ct))[0].Thumbprint;
        var saved = await gateway.PostAsync($"/certificates/{thumbprint}", "certificate-hosts", new()
        {
            ["Model.BaseVersion"] = (await gateway.ActiveVersionAsync()).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["hosts"] = host,
        });
        Assert.Contains($"used for {host}", saved, StringComparison.Ordinal);
        return thumbprint;
    }

    private static string Thumbprint(X509Certificate2 certificate) => certificate.GetCertHashString(HashAlgorithmName.SHA256);

    [Fact]
    public async Task Each_host_name_gets_its_own_certificate_over_https()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using var certificateA = TestCertificates.SelfSigned("a.example.test");
        using var certificateB = TestCertificates.SelfSigned("b.example.test");
        using var wildcard = TestCertificates.SelfSigned("*.wild.test");

        // A as a PFX with password, B as PEM (certificate and key in one file), the wildcard as a PFX without password.
        await UploadAndUseAsync(gateway, TestCertificates.Pfx(certificateA, PfxPassword), "a.pfx", PfxPassword, "a.example.test");
        var pemB = Encoding.ASCII.GetBytes(TestCertificates.CertificatePem(certificateB) + TestCertificates.KeyPem(certificateB));
        await UploadAndUseAsync(gateway, pemB, "b.pem", null, "b.example.test");
        await UploadAndUseAsync(gateway, TestCertificates.Pfx(wildcard), "wild.pfx", null, "*.wild.test");

        var a = await HttpsGetAsync(gateway, "a.example.test");
        var b = await HttpsGetAsync(gateway, "b.example.test");
        var shop = await HttpsGetAsync(gateway, "shop.wild.test");

        Assert.Equal((HttpStatusCode.OK, "A", Thumbprint(certificateA)), (a.Status, a.Body, a.Thumbprint));
        Assert.Equal((HttpStatusCode.OK, "B", Thumbprint(certificateB)), (b.Status, b.Body, b.Thumbprint));
        Assert.Equal((HttpStatusCode.OK, "A", Thumbprint(wildcard)), (shop.Status, shop.Body, shop.Thumbprint));

        // A host name without a certificate gets no TLS connection at all.
        await Assert.ThrowsAsync<HttpRequestException>(() => HttpsGetAsync(gateway, "unknown.example.test"));

        var page = await gateway.GetPageAsync("/certificates");
        Assert.Contains("a.example.test", page, StringComparison.Ordinal);
        Assert.Contains("*.wild.test", page, StringComparison.Ordinal);
        Assert.DoesNotContain("badge-danger", page, StringComparison.Ordinal);

        var audit = await gateway.AuditLog.ReadPageAsync(new AuditFilter { Category = AuditCategory.Security }, null, null, 10, Ct);
        Assert.Equal(3, audit.Items.Count(e => e.Action == AuditActions.CertificateUploaded));
        Assert.Equal(3, (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Certificates.Count);
    }

    [Fact]
    public async Task Private_keys_are_encrypted_at_rest()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using var certificate = TestCertificates.SelfSigned("a.example.test");
        await UploadAndUseAsync(gateway, TestCertificates.Pfx(certificate, PfxPassword), "a.pfx", PfxPassword, "a.example.test");

        byte[] stored;
        await using (var connection = new SqliteConnection($"Data Source={Path.Combine(gateway.DataDirectory, StoragePaths.ConfigDatabaseFileName)};Mode=ReadOnly"))
        {
            await connection.OpenAsync(Ct);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT ProtectedPfx FROM StoredCertificates";
            stored = (byte[])(await command.ExecuteScalarAsync(Ct))!;
        }

        // Neither a PFX nor the raw private key: only the gateway's data-protection keys can read it.
        var privateKey = certificate.GetECDsaPrivateKey()!.ExportParameters(includePrivateParameters: true).D!;
        Assert.True(stored.AsSpan().IndexOf(privateKey) < 0, "The private key is stored in plain text.");
        Assert.ThrowsAny<CryptographicException>(() => X509CertificateLoader.LoadPkcs12(stored, null));
        Assert.ThrowsAny<CryptographicException>(() => X509CertificateLoader.LoadPkcs12(stored, PfxPassword));
        Assert.Equal(Thumbprint(certificate), (await HttpsGetAsync(gateway, "a.example.test")).Thumbprint);
    }

    [Fact]
    public async Task Expiring_wrong_and_missing_certificates_are_warned_about()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using var expiring = TestCertificates.SelfSigned(TimeSpan.FromDays(10), "a.example.test");
        await UploadAndUseAsync(gateway, TestCertificates.Pfx(expiring), "a.pfx", null, "a.example.test");

        // A certificate file on disk that does not exist, and an uploaded one used for a host it does not name.
        var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
        configuration.Certificates.Add(new CertificateBinding
        {
            HostName = "b.example.test", Source = CertificateSource.File, CertificatePath = Path.Combine(gateway.DataDirectory, "missing.pem"),
        });
        configuration.Certificates.Add(new CertificateBinding
        {
            HostName = "shop.wild.test", Source = CertificateSource.Uploaded, Thumbprint = Thumbprint(expiring),
        });
        var service = gateway.App.Services.GetRequiredService<IGatewayConfigurationService>();
        Assert.True((await service.ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

        var dashboard = await gateway.GetPageAsync("/");
        Assert.Contains("3 certificates need attention.", dashboard, StringComparison.Ordinal);
        Assert.Contains("a.example.test: expires in 9 day(s)", dashboard, StringComparison.Ordinal);
        Assert.Contains("b.example.test: no certificate could be loaded", dashboard, StringComparison.Ordinal);
        Assert.Contains("shop.wild.test: the certificate is for another host name", dashboard, StringComparison.Ordinal);

        var page = await gateway.GetPageAsync("/certificates");
        Assert.Contains("Expires soon", page, StringComparison.Ordinal);
        Assert.Contains("Missing", page, StringComparison.Ordinal);
        Assert.Contains("Wrong host name", page, StringComparison.Ordinal);

        // The expiring certificate still works; the missing one refuses the handshake.
        Assert.Equal(HttpStatusCode.OK, (await HttpsGetAsync(gateway, "a.example.test")).Status);
        await Assert.ThrowsAsync<HttpRequestException>(() => HttpsGetAsync(gateway, "b.example.test"));
    }

    [Fact]
    public async Task Certificate_files_on_disk_are_served_and_picked_up_after_renewal()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        var (root, intermediate, leaf) = TestCertificates.Chain("b.example.test");
        using (root)
        using (intermediate)
        using (leaf)
        {
            var certificatePath = Path.Combine(gateway.DataDirectory, "b.crt");
            var keyPath = Path.Combine(gateway.DataDirectory, "b.key");
            await File.WriteAllTextAsync(certificatePath, TestCertificates.CertificatePem(leaf, intermediate), Ct);
            await File.WriteAllTextAsync(keyPath, TestCertificates.KeyPem(leaf), Ct);

            var configuration = (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration;
            configuration.Certificates.Add(new CertificateBinding { HostName = "b.example.test", Source = CertificateSource.File, CertificatePath = certificatePath, KeyPath = keyPath });
            var service = gateway.App.Services.GetRequiredService<IGatewayConfigurationService>();
            Assert.True((await service.ActivateAsync(configuration, AuditActor.System("test"), null, Ct)).Succeeded);

            var result = await HttpsGetAsync(gateway, "b.example.test");
            Assert.Equal((HttpStatusCode.OK, "B", Thumbprint(leaf)), (result.Status, result.Body, result.Thumbprint));

            // Renewed by another tool: picked up at the next reload (every few minutes; here forced).
            using var renewed = TestCertificates.SelfSigned("b.example.test");
            await File.WriteAllTextAsync(certificatePath, TestCertificates.CertificatePem(renewed), Ct);
            await File.WriteAllTextAsync(keyPath, TestCertificates.KeyPem(renewed), Ct);
            await gateway.Certificates.ReloadAsync(Ct);
            Assert.Equal(Thumbprint(renewed), (await HttpsGetAsync(gateway, "b.example.test")).Thumbprint);
        }
    }

    [Fact]
    public async Task Removing_a_host_and_deleting_the_certificate()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using var certificate = TestCertificates.SelfSigned("a.example.test");
        var thumbprint = await UploadAndUseAsync(gateway, TestCertificates.Pfx(certificate), "a.pfx", null, "a.example.test");

        // In use: no delete button, and deleting is refused.
        Assert.DoesNotContain($"delete-{thumbprint}", await gateway.GetPageAsync("/certificates"), StringComparison.Ordinal);
        Assert.NotEmpty(await gateway.Certificates.DeleteAsync(thumbprint, AuditActor.System("test"), Ct));

        var removed = await gateway.PostAsync("/certificates", "remove-a.example.test", []);
        Assert.Contains("a.example.test has no certificate any more", removed, StringComparison.Ordinal);
        await Assert.ThrowsAsync<HttpRequestException>(() => HttpsGetAsync(gateway, "a.example.test"));

        var deleted = await gateway.PostAsync("/certificates", $"delete-{thumbprint}", []);
        Assert.Contains("Certificate deleted.", deleted, StringComparison.Ordinal);
        Assert.Empty(await gateway.Certificates.GetStoredAsync(Ct));
    }

    [Fact]
    public async Task Invalid_uploads_are_explained()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();
        using var certificate = TestCertificates.SelfSigned("a.example.test");

        var wrongPassword = await gateway.PostMultipartAsync(
            "/certificates/upload", "upload-certificate", new() { ["Model.Password"] = "wrong" }, "certificateFile", "a.pfx", TestCertificates.Pfx(certificate, PfxPassword));
        Assert.Contains("The certificate was not uploaded.", wrongPassword, StringComparison.Ordinal);
        Assert.Contains("password may be wrong", wrongPassword, StringComparison.Ordinal);

        using var expired = TestCertificates.SelfSigned(TimeSpan.FromHours(-1), "a.example.test");
        var tooOld = await gateway.PostMultipartAsync(
            "/certificates/upload", "upload-certificate", [], "certificateFile", "old.pfx", TestCertificates.Pfx(expired));
        Assert.Contains("expired", tooOld, StringComparison.Ordinal);

        Assert.Empty(await gateway.Certificates.GetStoredAsync(Ct));
    }

    [Fact]
    public async Task A_backup_with_secrets_brings_https_back_on_another_gateway()
    {
        await using var source = new Gateway();
        await source.InitializeAsync();
        using var certificate = TestCertificates.SelfSigned("a.example.test");
        await UploadAndUseAsync(source, TestCertificates.Pfx(certificate), "a.pfx", null, "a.example.test");

        async Task<byte[]> BackupAsync(bool secrets)
        {
            using var response = await source.PostPlainFormAsync(AdminDownloads.BackupPath, "/backup", secrets ? new() { ["includeSecrets"] = "true" } : []);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            return await response.Content.ReadAsByteArrayAsync(Ct);
        }

        static bool HasCertificates(byte[] zip)
        {
            using var archive = new ZipArchive(new MemoryStream(zip));
            return archive.GetEntry("certificates.json") is not null;
        }

        Assert.False(HasCertificates(await BackupAsync(secrets: false)));
        var backup = await BackupAsync(secrets: true);
        Assert.True(HasCertificates(backup));

        await using var target = new Gateway();
        await target.InitializeAsync();
        var restored = await target.PostMultipartAsync("/backup", "restore-backup", new() { ["Restore.Confirm"] = "True" }, "backupFile", "backup.zip", backup);
        Assert.Contains("Backup restored.", restored, StringComparison.Ordinal);

        var result = await HttpsGetAsync(target, "a.example.test");
        Assert.Equal(Thumbprint(certificate), result.Thumbprint);
    }
}
