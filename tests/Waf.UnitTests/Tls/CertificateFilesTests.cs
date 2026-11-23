using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FASoft.Waf.Core.Tls;

namespace FASoft.Waf.UnitTests.Tls;

/// <summary>Reading uploaded and local certificates (PFX and PEM) and matching host names.</summary>
public sealed class CertificateFilesTests
{
    private static byte[] Ascii(string text) => Encoding.ASCII.GetBytes(text);

    private static void AssertUsableKey(ServerCertificate certificate)
    {
        using var key = certificate.Leaf.GetECDsaPrivateKey();
        Assert.NotNull(key);
        byte[] data = [1, 2, 3];
        var signature = key.SignData(data, HashAlgorithmName.SHA256);
        using var publicKey = certificate.Leaf.GetECDsaPublicKey()!;
        Assert.True(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void Pfx_with_password_is_read_with_its_names_and_key()
    {
        using var original = TestCertificates.SelfSigned("www.example.com", "example.com");

        var read = CertificateFiles.Read(TestCertificates.Pfx(original, "s3cret pass"), "s3cret pass");

        using var certificate = Assert.IsType<ServerCertificate>(read.Certificate);
        Assert.Equal(["www.example.com", "example.com"], certificate.DnsNames);
        Assert.Equal(original.GetCertHashString(HashAlgorithmName.SHA256), certificate.Thumbprint);
        Assert.Equal(64, certificate.Thumbprint.Length);
        AssertUsableKey(certificate);
    }

    [Fact]
    public void Pfx_with_a_wrong_or_missing_password_is_explained()
    {
        using var original = TestCertificates.SelfSigned("www.example.com");
        var pfx = TestCertificates.Pfx(original, "right");

        Assert.Contains("password may be wrong", CertificateFiles.Read(pfx, "wrong").Error, StringComparison.Ordinal);
        Assert.Contains("needs a password", CertificateFiles.Read(pfx).Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Certificate_without_private_key_is_refused()
    {
        using var original = TestCertificates.SelfSigned("www.example.com");
        using var publicOnly = X509CertificateLoader.LoadCertificate(original.RawData);

        var pfx = CertificateFiles.Read(TestCertificates.Pfx(publicOnly));
        Assert.Contains("does not contain a private key", pfx.Error, StringComparison.Ordinal);

        var pem = CertificateFiles.Read(Ascii(TestCertificates.CertificatePem(original)));
        Assert.Contains("private key is missing", pem.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Pem_certificate_with_separate_combined_or_encrypted_key_is_read()
    {
        using var original = TestCertificates.SelfSigned("api.example.com");
        var certificatePem = TestCertificates.CertificatePem(original);
        var keyPem = TestCertificates.KeyPem(original);

        using (var separate = CertificateFiles.Read(Ascii(certificatePem), null, Ascii(keyPem)).Certificate!)
        {
            AssertUsableKey(separate);
        }

        using (var combined = CertificateFiles.Read(Ascii(certificatePem + keyPem)).Certificate!)
        {
            AssertUsableKey(combined);
        }

        var encrypted = Ascii(TestCertificates.EncryptedKeyPem(original, "key pass"));
        using (var decrypted = CertificateFiles.Read(Ascii(certificatePem), "key pass", encrypted).Certificate!)
        {
            AssertUsableKey(decrypted);
        }

        Assert.Contains("check the password", CertificateFiles.Read(Ascii(certificatePem), "nope", encrypted).Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Pem_key_of_another_certificate_is_refused()
    {
        using var first = TestCertificates.SelfSigned("a.example.com");
        using var second = TestCertificates.SelfSigned("b.example.com");

        var read = CertificateFiles.Read(Ascii(TestCertificates.CertificatePem(first)), null, Ascii(TestCertificates.KeyPem(second)));

        Assert.Contains("does not belong to this certificate", read.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Chain_keeps_the_intermediate_and_leaves_out_the_root()
    {
        var (root, intermediate, leaf) = TestCertificates.Chain("shop.example.com");
        using (root)
        using (intermediate)
        using (leaf)
        {
            var pem = TestCertificates.CertificatePem(leaf, intermediate, root) + TestCertificates.KeyPem(leaf);
            using var fromPem = CertificateFiles.Read(Ascii(pem)).Certificate!;
            Assert.Equal("CN=Test Intermediate CA", Assert.Single(fromPem.Intermediates).Subject);

            using var fromPfx = CertificateFiles.Read(TestCertificates.Pfx(leaf, null, intermediate, root)).Certificate!;
            Assert.Equal("CN=shop.example.com", fromPfx.Leaf.Subject);
            Assert.Equal("CN=Test Intermediate CA", Assert.Single(fromPfx.Intermediates).Subject);

            // What is stored: the PFX export keeps the key and the chain.
            using var reloaded = CertificateFiles.LoadPfx(fromPfx.ExportPfx());
            Assert.Equal(fromPfx.Thumbprint, reloaded.Thumbprint);
            Assert.Single(reloaded.Intermediates);
            AssertUsableKey(reloaded);
        }
    }

    [Fact]
    public void Garbage_and_oversized_files_are_refused()
    {
        Assert.Contains("not a readable PFX or PEM", CertificateFiles.Read([1, 2, 3, 4]).Error, StringComparison.Ordinal);
        Assert.Contains("empty", CertificateFiles.Read([]).Error, StringComparison.Ordinal);
        Assert.Contains("too large", CertificateFiles.Read(new byte[CertificateFiles.MaxFileBytes + 1]).Error, StringComparison.Ordinal);
        Assert.Contains("No certificate was found", CertificateFiles.Read(Ascii("-----BEGIN NOTHING-----")).Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_files_on_disk_are_explained()
    {
        var read = CertificateFiles.ReadFiles(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "missing.pem"), null);

        Assert.Contains("could not be read", read.Error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("www.example.com", "www.example.com", true)]
    [InlineData("WWW.Example.com", "www.example.COM", true)]
    [InlineData("www.example.com", "example.com", false)]
    [InlineData("*.example.com", "shop.example.com", true)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("*.example.com", "a.b.example.com", false)]
    [InlineData("*.example.com", "shop.example.org", false)]
    public void Host_names_match_exactly_or_one_wildcard_label(string pattern, string host, bool matches) =>
        Assert.Equal(matches, CertificateNames.Matches(pattern, host));

    [Fact]
    public void Certificate_names_cover_hosts_and_wildcard_bindings()
    {
        string[] names = ["*.example.com", "example.com"];

        Assert.True(CertificateNames.Covers(names, "shop.example.com"));
        Assert.True(CertificateNames.Covers(names, "example.com"));
        Assert.True(CertificateNames.Covers(names, "*.example.com"));
        Assert.False(CertificateNames.Covers(names, "*.other.com"));
        Assert.False(CertificateNames.Covers(["shop.example.com"], "*.example.com")); // a single name does not cover a wildcard
    }
}
