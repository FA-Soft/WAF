using System.Net.Security;

namespace FASoft.Waf.Core.Tls;

/// <summary>
/// Selects the TLS server certificate for an incoming connection based on the SNI host name.
/// </summary>
public interface IServerCertificateSelector
{
    /// <summary>
    /// Returns the certificate (with the intermediates to send) for <paramref name="hostName"/>, or
    /// <see langword="null"/> when no certificate is configured, in which case the TLS handshake is rejected.
    /// </summary>
    SslStreamCertificateContext? SelectCertificate(string? hostName);
}
