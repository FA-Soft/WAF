namespace FASoft.Waf.Core.Configuration;

/// <summary>Which TLS certificate to use for a host name.</summary>
public sealed class CertificateBinding
{
    /// <summary>Host name, e.g. <c>www.example.com</c>, or a wildcard <c>*.example.com</c> (own certificates only).</summary>
    public string HostName { get; set; } = string.Empty;

    /// <summary>Where the certificate comes from.</summary>
    public CertificateSource Source { get; set; } = CertificateSource.LetsEncrypt;

    /// <summary>For <see cref="CertificateSource.File"/>: path to a PFX file, or a PEM certificate file.</summary>
    public string? CertificatePath { get; set; }

    /// <summary>For a PEM certificate: path to the PEM private key file. Not used for PFX.</summary>
    public string? KeyPath { get; set; }
}

/// <summary>Source of a certificate.</summary>
public enum CertificateSource
{
    /// <summary>Requested and renewed automatically from Let's Encrypt (HTTP-01).</summary>
    LetsEncrypt,

    /// <summary>Your own certificate file (PFX or PEM). The password is stored separately, encrypted.</summary>
    File,
}
