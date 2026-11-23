using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace FASoft.Waf.Core.Tls;

/// <summary>A server certificate with its private key, and the intermediate certificates to send with it.</summary>
public sealed class ServerCertificate(X509Certificate2 leaf, X509Certificate2Collection intermediates) : IDisposable
{
    public X509Certificate2 Leaf { get; } = leaf;

    public X509Certificate2Collection Intermediates { get; } = intermediates;

    /// <summary>SHA-256 thumbprint of the leaf, upper-case hex: how uploaded certificates are referenced.</summary>
    public string Thumbprint => Leaf.GetCertHashString(HashAlgorithmName.SHA256);

    /// <summary>The host names the certificate is valid for (subject alternative names, else the common name).</summary>
    public IReadOnlyList<string> DnsNames => CertificateNames.DnsNames(Leaf);

    /// <summary>The certificate and chain as a PFX without password (to be encrypted before it is stored).</summary>
    public byte[] ExportPfx()
    {
        var collection = new X509Certificate2Collection(Leaf);
        collection.AddRange(Intermediates);
        return collection.Export(X509ContentType.Pkcs12)
            ?? throw new CryptographicException("The certificate could not be exported.");
    }

    public void Dispose()
    {
        Leaf.Dispose();
        foreach (var intermediate in Intermediates)
        {
            intermediate.Dispose();
        }
    }
}

/// <summary>Outcome of reading certificate files: the certificate, or why it cannot be used.</summary>
public sealed record CertificateReadResult(ServerCertificate? Certificate, string? Error)
{
    public static CertificateReadResult Failed(string error) => new(null, error);
}

/// <summary>
/// Reads server certificates from PFX (PKCS#12) or PEM files. Only certificates with a matching private key are
/// accepted; extra certificates in the file (the chain) become intermediates.
/// </summary>
public static class CertificateFiles
{
    /// <summary>Largest certificate or key file accepted.</summary>
    public const int MaxFileBytes = 1024 * 1024;

    /// <summary>
    /// Reads an uploaded or local certificate: a PFX (with <paramref name="password"/> if it has one), or a PEM
    /// certificate (optionally followed by its chain) with the PEM private key in <paramref name="keyFile"/> or in the
    /// same file. An encrypted PEM key uses <paramref name="password"/>.
    /// </summary>
    public static CertificateReadResult Read(byte[] certificateFile, string? password = null, byte[]? keyFile = null)
    {
        ArgumentNullException.ThrowIfNull(certificateFile);
        if (certificateFile.Length == 0)
        {
            return CertificateReadResult.Failed("The certificate file is empty.");
        }

        if (certificateFile.Length > MaxFileBytes || keyFile?.Length > MaxFileBytes)
        {
            return CertificateReadResult.Failed($"The file is too large (at most {MaxFileBytes / 1024} KB).");
        }

        try
        {
            return LooksLikePem(certificateFile)
                ? ReadPem(Encoding.ASCII.GetString(certificateFile), keyFile is null ? null : Encoding.ASCII.GetString(keyFile), password)
                : ReadPfx(certificateFile, password);
        }
        catch (CryptographicException ex)
        {
            return CertificateReadResult.Failed(DescribePfxError(ex, password));
        }
        catch (ArgumentException ex)
        {
            return CertificateReadResult.Failed($"The file could not be read: {ex.Message}");
        }
    }

    /// <summary>Reads a certificate configured with paths on disk (Source 'File').</summary>
    public static CertificateReadResult ReadFiles(string certificatePath, string? keyPath)
    {
        try
        {
            var certificate = File.ReadAllBytes(certificatePath);
            var key = keyPath is null ? null : File.ReadAllBytes(keyPath);
            return Read(certificate, null, key);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return CertificateReadResult.Failed($"The certificate file could not be read: {ex.Message}");
        }
    }

    /// <summary>Loads a PFX made by <see cref="ServerCertificate.ExportPfx"/>.</summary>
    public static ServerCertificate LoadPfx(byte[] pfx) => ReadPfx(pfx, null).Certificate
        ?? throw new CryptographicException("The stored certificate has no private key.");

    private static CertificateReadResult ReadPfx(byte[] pfx, string? password)
    {
        // Not ephemeral: on Windows, TLS (SChannel) needs a key it can find again. The key is removed on Dispose.
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfx, password, X509KeyStorageFlags.Exportable);
        var leaf = collection.FirstOrDefault(c => c.HasPrivateKey);
        if (leaf is null)
        {
            foreach (var certificate in collection)
            {
                certificate.Dispose();
            }

            return CertificateReadResult.Failed("The PFX file does not contain a private key; export it including the private key.");
        }

        var intermediates = new X509Certificate2Collection();
        intermediates.AddRange(collection.Where(c => !ReferenceEquals(c, leaf) && !IsSelfSignedRoot(c)).ToArray());
        return new CertificateReadResult(new ServerCertificate(leaf, intermediates), null);
    }

    private static CertificateReadResult ReadPem(string certificatePem, string? keyPem, string? password)
    {
        var all = new X509Certificate2Collection();
        all.ImportFromPem(certificatePem);
        if (all.Count == 0)
        {
            return CertificateReadResult.Failed("No certificate was found in the PEM file (it should contain '-----BEGIN CERTIFICATE-----').");
        }

        var key = keyPem ?? (certificatePem.Contains("PRIVATE KEY-----", StringComparison.Ordinal) ? certificatePem : null);
        if (key is null)
        {
            return CertificateReadResult.Failed("The private key is missing: add the PEM key file ('-----BEGIN PRIVATE KEY-----').");
        }

        var leafPem = all[0].ExportCertificatePem();
        X509Certificate2 withKey;
        try
        {
            withKey = key.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal)
                ? X509Certificate2.CreateFromEncryptedPem(leafPem, key, password ?? string.Empty)
                : X509Certificate2.CreateFromPem(leafPem, key);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return CertificateReadResult.Failed(key.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal)
                ? "The private key could not be decrypted: check the password."
                : $"The private key does not belong to this certificate, or could not be read ({ex.Message}).");
        }

        // A PEM key is ephemeral; reload through PKCS#12 so the key is usable for TLS on every platform.
        using (withKey)
        {
            var leaf = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
            var intermediates = new X509Certificate2Collection();
            intermediates.AddRange(all.Skip(1).Where(c => !IsSelfSignedRoot(c)).ToArray());
            all[0].Dispose();
            return new CertificateReadResult(new ServerCertificate(leaf, intermediates), null);
        }
    }

    private static bool LooksLikePem(byte[] bytes)
    {
        var start = Encoding.ASCII.GetString(bytes, 0, Math.Min(bytes.Length, 4096));
        return start.Contains("-----BEGIN ", StringComparison.Ordinal);
    }

    /// <summary>Roots are not sent: clients have them already.</summary>
    private static bool IsSelfSignedRoot(X509Certificate2 certificate) =>
        certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData)
        && certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(b => b.CertificateAuthority);

    private static string DescribePfxError(CryptographicException ex, string? password) =>
        string.IsNullOrEmpty(password)
            ? $"The file is not a readable PFX or PEM certificate, or it needs a password ({ex.Message})."
            : $"The PFX file could not be opened: the password may be wrong ({ex.Message}).";
}

/// <summary>Host names of certificates and how they match SNI host names.</summary>
public static class CertificateNames
{
    /// <summary>The DNS names a certificate is valid for: its subject alternative names, else its common name.</summary>
    public static IReadOnlyList<string> DnsNames(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var names = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(e => e.EnumerateDnsNames())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (names.Count == 0 && certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false) is { Length: > 0 } commonName)
        {
            names.Add(commonName);
        }

        return names;
    }

    /// <summary>
    /// True when <paramref name="pattern"/> (a host name, or a wildcard such as <c>*.example.com</c>) covers
    /// <paramref name="hostName"/>. A wildcard covers exactly one label: <c>a.example.com</c>, not <c>example.com</c> or
    /// <c>a.b.example.com</c>.
    /// </summary>
    public static bool Matches(string pattern, string hostName)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(hostName);

        if (!pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            return string.Equals(pattern, hostName, StringComparison.OrdinalIgnoreCase);
        }

        var dot = hostName.IndexOf('.', StringComparison.Ordinal);
        return dot > 0 && string.Equals(pattern[1..], hostName[dot..], StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when one of <paramref name="dnsNames"/> covers <paramref name="hostName"/> (which may itself be a wildcard).</summary>
    public static bool Covers(IEnumerable<string> dnsNames, string hostName)
    {
        ArgumentNullException.ThrowIfNull(dnsNames);
        return dnsNames.Any(name => string.Equals(name, hostName, StringComparison.OrdinalIgnoreCase)
            || (!hostName.StartsWith("*.", StringComparison.Ordinal) && Matches(name, hostName)));
    }
}
