using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>What must be true before an admin URL can be registered.</summary>
internal static class RemoteAccessRules
{
    /// <summary>The reasons <paramref name="url"/> cannot be registered now; empty when it can.</summary>
    public static IReadOnlyList<string> Check(
        RemoteAdminUrl url,
        bool twoFactorEnabled,
        GatewayConfiguration configuration,
        IReadOnlyList<CertificateStatus> certificates,
        IReadOnlyCollection<int> reservedPorts)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(certificates);
        ArgumentNullException.ThrowIfNull(reservedPorts);

        var problems = new List<string>();
        if (!twoFactorEnabled)
        {
            problems.Add(Text.N("Turn on two-factor sign-in for your account first (Your account → Two-factor sign-in). Remote access always requires it."));
        }

        if (url.Port is { } port && reservedPorts.Contains(port))
        {
            problems.Add(Text.F("Port {0} is already used by the gateway for plain HTTP or the local admin UI; choose another port or none.", port));
        }

        var routes = configuration.Routes
            .Where(r => r.Match.Hosts.Any(h => string.Equals(h, url.Host, StringComparison.OrdinalIgnoreCase) || CertificateNames.Matches(h, url.Host)))
            .Select(r => r.Name)
            .ToList();
        if (routes.Count > 0)
        {
            problems.Add(Text.F("{0} is used by route {1}. Use a host name of its own for the admin UI.", url.Host, string.Join(", ", routes.Select(r => $"'{r}'"))));
        }

        var certificate = certificates.FirstOrDefault(c =>
            string.Equals(c.HostName, url.Host, StringComparison.OrdinalIgnoreCase) || CertificateNames.Matches(c.HostName, url.Host));
        if (certificate is not { State: CertificateState.Ok or CertificateState.ExpiresSoon })
        {
            problems.Add(certificate is null
                ? Text.F("There is no certificate for {0}. Add one on the Certificates page (upload it or use Let's Encrypt) first.", url.Host)
                : certificate.Problem is null
                    ? Text.F("The certificate for {0} is not usable yet ({1}).", url.Host, certificate.State)
                    : Text.F("The certificate for {0} is not usable yet ({1}: {2}).", url.Host, certificate.State, certificate.Problem));
        }

        return problems;
    }
}

/// <summary>The remote access forms.</summary>
internal sealed class RemoteUrlFormModel
{
    public string? Url { get; set; }
}

internal sealed class AllowlistFormModel
{
    public string? Networks { get; set; }
}
