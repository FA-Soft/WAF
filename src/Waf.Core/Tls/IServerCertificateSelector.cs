using System.Security.Cryptography.X509Certificates;

namespace Waf.Core.Tls;

/// <summary>
/// Selects the TLS server certificate for an incoming connection based on the SNI host name.
/// </summary>
public interface IServerCertificateSelector
{
    /// <summary>
    /// Returns the certificate for <paramref name="hostName"/>, or <see langword="null"/> when no
    /// certificate is configured, in which case the TLS handshake is rejected.
    /// </summary>
    X509Certificate2? SelectCertificate(string? hostName);
}
