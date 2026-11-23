using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FASoft.Waf.UnitTests.Tls;

/// <summary>Certificates made on the fly for tests: self-signed, or issued by a test CA (root → intermediate → leaf).</summary>
internal static class TestCertificates
{
    public static X509Certificate2 SelfSigned(params string[] dnsNames) => SelfSigned(TimeSpan.FromDays(365), dnsNames);

    public static X509Certificate2 SelfSigned(TimeSpan validFor, params string[] dnsNames)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = LeafRequest(key, dnsNames);
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddDays(-1), now.Add(validFor));
    }

    /// <summary>Root CA, intermediate CA and a leaf for <paramref name="dnsNames"/> issued by the intermediate.</summary>
    public static (X509Certificate2 Root, X509Certificate2 Intermediate, X509Certificate2 Leaf) Chain(params string[] dnsNames)
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Test Root CA", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var root = rootRequest.CreateSelfSigned(now.AddDays(-2), now.AddYears(5));

        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest("CN=Test Intermediate CA", intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var intermediatePublic = intermediateRequest.Create(root, now.AddDays(-1), now.AddYears(4), [1, 2, 3, 4]);
        var intermediate = intermediatePublic.CopyWithPrivateKey(intermediateKey);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leafPublic = LeafRequest(leafKey, dnsNames).Create(intermediate, now.AddHours(-1), now.AddDays(90), [5, 6, 7, 8]);
        return (root, intermediate, leafPublic.CopyWithPrivateKey(leafKey));
    }

    public static byte[] Pfx(X509Certificate2 certificate, string? password = null, params X509Certificate2[] chain)
    {
        var collection = new X509Certificate2Collection(certificate);
        collection.AddRange(chain);
        return collection.Export(X509ContentType.Pkcs12, password)!;
    }

    public static string CertificatePem(params X509Certificate2[] certificates) =>
        string.Concat(certificates.Select(c => c.ExportCertificatePem() + "\n"));

    public static string KeyPem(X509Certificate2 certificate) => certificate.GetECDsaPrivateKey()!.ExportPkcs8PrivateKeyPem();

    public static string EncryptedKeyPem(X509Certificate2 certificate, string password) =>
        certificate.GetECDsaPrivateKey()!.ExportEncryptedPkcs8PrivateKeyPem(
            password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));

    private static CertificateRequest LeafRequest(ECDsa key, string[] dnsNames)
    {
        var request = new CertificateRequest($"CN={dnsNames[0]}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
        {
            names.AddDnsName(name);
        }

        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false)); // server auth
        return request;
    }
}
