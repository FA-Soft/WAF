namespace Waf.Core.Hosting;

/// <summary>
/// Listener configuration for the gateway, bound from the <c>Gateway:Endpoints</c> configuration section.
/// </summary>
/// <remarks>
/// The admin listener is always bound to the loopback addresses (<c>127.0.0.1</c> and <c>::1</c>);
/// only its port is configurable. Remote admin access is a separate, opt-in feature.
/// </remarks>
public sealed class GatewayEndpointOptions
{
    /// <summary>The configuration section these options are bound from.</summary>
    public const string SectionName = "Gateway:Endpoints";

    /// <summary>Public plain-HTTP port (ACME challenges, HTTPS redirects, plain HTTP routes).</summary>
    public int HttpPort { get; set; } = 80;

    /// <summary>Public HTTPS port.</summary>
    public int HttpsPort { get; set; } = 443;

    /// <summary>Port of the localhost-only admin UI.</summary>
    public int AdminPort { get; set; } = ProductInfo.DefaultAdminPort;

    /// <summary>
    /// Address the public listeners bind to: <c>*</c> (default) for all interfaces,
    /// or a specific IPv4/IPv6 address.
    /// </summary>
    public string PublicBindAddress { get; set; } = "*";

    /// <summary>Returns a list of validation errors; empty when the options are valid.</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        CheckPort(nameof(HttpPort), HttpPort, errors);
        CheckPort(nameof(HttpsPort), HttpsPort, errors);
        CheckPort(nameof(AdminPort), AdminPort, errors);

        if (HttpPort == HttpsPort)
        {
            errors.Add($"{nameof(HttpPort)} and {nameof(HttpsPort)} must be different (both are {HttpPort}).");
        }

        if (AdminPort == HttpPort || AdminPort == HttpsPort)
        {
            errors.Add($"{nameof(AdminPort)} ({AdminPort}) must differ from the public ports.");
        }

        if (PublicBindAddress != "*" && !Net.StrictIpAddress.TryParse(PublicBindAddress, out _))
        {
            errors.Add(
                $"{nameof(PublicBindAddress)} must be '*', an IPv4 address in dotted-decimal form (e.g. 10.0.0.5) "
                + $"or an IPv6 address (was '{PublicBindAddress}').");
        }

        return errors;
    }

    private static void CheckPort(string name, int port, List<string> errors)
    {
        if (port is < 1 or > 65535)
        {
            errors.Add($"{name} must be between 1 and 65535 (was {port}).");
        }
    }
}
