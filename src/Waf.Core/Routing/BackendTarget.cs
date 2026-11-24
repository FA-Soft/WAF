namespace FASoft.Waf.Core.Routing;

/// <summary>
/// A named backend machine (for example <c>nas</c>) with named ports (for example <c>web</c> → 5000). Routes can
/// forward to "target · port label" instead of an address, so a changed address is changed in one place.
/// </summary>
public sealed class BackendTarget
{
    /// <summary>Unique label (letters, digits, '-', '_' and '.'), e.g. <c>nas</c>.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional note, e.g. "Synology in the cupboard".</summary>
    public string? Description { get; set; }

    /// <summary>
    /// IP address (e.g. <c>192.168.1.20</c>, <c>fd00::20</c>) or host name. With a <see cref="MacAddress"/> it is
    /// optional: the address to use until the MAC address has been found (the last known address).
    /// </summary>
    public string Address { get; set; } = string.Empty;

    /// <summary>
    /// MAC address (<c>aa:bb:cc:dd:ee:ff</c>) of a device whose IP address may change (DHCP): the gateway finds its
    /// current address in the network's neighbour (ARP) table. Only for devices on the gateway's own network.
    /// </summary>
    public string? MacAddress { get; set; }

    /// <summary>Seconds between look-ups of <see cref="MacAddress"/>, 10–3600; default 60.</summary>
    public int? ResolveIntervalSeconds { get; set; }

    /// <summary>Default for <see cref="ResolveIntervalSeconds"/>.</summary>
    public const int DefaultResolveIntervalSeconds = 60;

    /// <summary>The ports routes can use, each with a label unique within this target.</summary>
    public IList<TargetPort> Ports { get; } = [];
}

/// <summary>A labelled port of a <see cref="BackendTarget"/>.</summary>
public sealed class TargetPort
{
    /// <summary>Label, unique within its target (letters, digits, '-', '_' and '.'), e.g. <c>web</c> or <c>admin</c>.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Port number, 1–65535.</summary>
    public int Port { get; set; }

    /// <summary><c>http</c> (default) or <c>https</c>.</summary>
    public string Scheme { get; set; } = "http";
}
