using System.Security.Cryptography.X509Certificates;
using Waf.Core.Tls;

namespace Waf.Host.Hosting;

/// <summary>
/// Placeholder selector used until certificate management exists: rejects every TLS handshake.
/// </summary>
internal sealed class NoServerCertificateSelector : IServerCertificateSelector
{
    public X509Certificate2? SelectCertificate(string? hostName) => null;
}
