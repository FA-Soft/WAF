using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Tls;

namespace FASoft.Waf.Web;

/// <summary>Changes to which certificate each host name uses (the <c>Certificates</c> list of the configuration).</summary>
internal static class CertificateEditing
{
    /// <summary>
    /// A copy of <paramref name="configuration"/> in which the uploaded certificate <paramref name="thumbprint"/> is used
    /// for exactly <paramref name="hostNames"/>: other certificates of those host names are replaced, and host names that
    /// used this certificate but are not listed lose their binding.
    /// </summary>
    public static GatewayConfiguration UseFor(GatewayConfiguration configuration, string thumbprint, IReadOnlyCollection<string> hostNames)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(hostNames);

        var copy = ConfigurationEditing.Clone(configuration);
        var chosen = new HashSet<string>(hostNames, StringComparer.OrdinalIgnoreCase);
        var keep = copy.Certificates
            .Where(c => !chosen.Contains(c.HostName) && !IsThis(c, thumbprint))
            .ToList();
        copy.Certificates.Clear();
        foreach (var binding in keep)
        {
            copy.Certificates.Add(binding);
        }

        foreach (var host in hostNames.Order(StringComparer.OrdinalIgnoreCase))
        {
            copy.Certificates.Add(new CertificateBinding { HostName = host, Source = CertificateSource.Uploaded, Thumbprint = thumbprint.ToUpperInvariant() });
        }

        return copy;
    }

    /// <summary>A copy without the certificate binding of <paramref name="hostName"/>.</summary>
    public static GatewayConfiguration Without(GatewayConfiguration configuration, string hostName)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var copy = ConfigurationEditing.Clone(configuration);
        foreach (var binding in copy.Certificates.Where(c => string.Equals(c.HostName, hostName, StringComparison.OrdinalIgnoreCase)).ToList())
        {
            copy.Certificates.Remove(binding);
        }

        return copy;
    }

    /// <summary>The host names that use the uploaded certificate <paramref name="thumbprint"/>.</summary>
    public static IReadOnlyList<string> HostsOf(GatewayConfiguration configuration, string thumbprint)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return [.. configuration.Certificates.Where(c => IsThis(c, thumbprint)).Select(c => c.HostName)];
    }

    /// <summary>
    /// The host names this certificate can serve: its DNS names (wildcards included) plus route host names it covers
    /// (e.g. <c>shop.example.com</c> under a <c>*.example.com</c> certificate), sorted.
    /// </summary>
    public static IReadOnlyList<string> Candidates(IReadOnlyList<string> dnsNames, GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(dnsNames);
        ArgumentNullException.ThrowIfNull(configuration);

        var routeHosts = configuration.Routes.SelectMany(r => r.Match.Hosts).Where(h => !h.Contains('*', StringComparison.Ordinal));
        return [.. dnsNames
            .Concat(routeHosts.Where(h => CertificateNames.Covers(dnsNames, h)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>How a binding's source is shown.</summary>
    public static string SourceLabel(CertificateSource source) => source switch
    {
        CertificateSource.Uploaded => "Uploaded",
        CertificateSource.File => "File on disk",
        _ => "Let's Encrypt",
    };

    /// <summary>Badge class and text of a state.</summary>
    public static (string Badge, string Label) StateBadge(CertificateState state) => state switch
    {
        CertificateState.Ok => ("badge-ok", "Valid"),
        CertificateState.ExpiresSoon => ("badge-warning", "Expires soon"),
        CertificateState.Pending => ("badge-muted", "Not issued yet"),
        CertificateState.NotYetValid => ("badge-warning", "Not yet valid"),
        CertificateState.Expired => ("badge-danger", "Expired"),
        CertificateState.WrongHost => ("badge-danger", "Wrong host name"),
        _ => ("badge-danger", "Missing"),
    };

    private static bool IsThis(CertificateBinding binding, string thumbprint) =>
        binding.Source == CertificateSource.Uploaded && string.Equals(binding.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase);
}

/// <summary>The upload form (the files come from the request itself).</summary>
internal sealed class CertificateUploadFormModel
{
    public string? Password { get; set; }
}

/// <summary>The host-name form of a certificate (the ticked host names come from the request itself).</summary>
internal sealed class CertificateHostsFormModel
{
    public long BaseVersion { get; set; }
}
