using FASoft.Waf.Core.Configuration;

namespace FASoft.Waf.Core.Routing;

/// <summary>
/// Targets: checks them and the destinations that use them, and turns "target · port label" destinations into
/// addresses for the proxy. Resolution happens when a configuration is activated, so changing a target's address
/// changes every route that uses it at once.
/// </summary>
public static class TargetResolver
{
    /// <summary>Shortest and longest MAC address look-up interval, in seconds.</summary>
    public const int MinResolveIntervalSeconds = 10, MaxResolveIntervalSeconds = 3600;

    /// <summary>"nas · web": how a target destination is shown (UI, request log).</summary>
    public static string Label(string? target, string? port) => $"{target} · {port}";

    /// <summary>The target named <paramref name="name"/> (case-insensitive), or null.</summary>
    public static BackendTarget? Find(IEnumerable<BackendTarget> targets, string? name) =>
        targets.FirstOrDefault(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>The port labelled <paramref name="name"/> (case-insensitive), or null.</summary>
    public static TargetPort? FindPort(BackendTarget target, string? name)
    {
        ArgumentNullException.ThrowIfNull(target);
        return target.Ports.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The routes of <paramref name="configuration"/> with every target destination replaced by its address, scheme
    /// and port (keeping the target and port label, for display). Routes and destinations without targets are
    /// returned as they are; a destination whose target or port is unknown is left unresolved (validation reports it).
    /// A target without an address right now (a MAC address not found for too long, see <see cref="ITargetAddressSource"/>)
    /// is left unresolved too: the proxy leaves such destinations out, so no traffic goes to an address that may now
    /// belong to another device.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <param name="addresses">The current address of each target; null: the configured addresses.</param>
    public static IReadOnlyList<ProxyRouteOptions> Resolve(GatewayConfiguration configuration, ITargetAddressSource? addresses = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        addresses ??= ConfiguredTargetAddresses.Instance;

        var routes = new List<ProxyRouteOptions>(configuration.Routes.Count);
        foreach (var route in configuration.Routes)
        {
            if (!route.Destinations.Any(d => d.UsesTarget))
            {
                routes.Add(route);
                continue;
            }

            var copy = new ProxyRouteOptions
            {
                Name = route.Name,
                Enabled = route.Enabled,
                Match = route.Match,
                PreserveHost = route.PreserveHost,
                AllowInvalidBackendCertificate = route.AllowInvalidBackendCertificate,
                HealthCheck = route.HealthCheck,
                Https = route.Https,
                ErrorMessage = route.ErrorMessage,
                ErrorMessageTranslations = route.ErrorMessageTranslations,
            };
            foreach (var destination in route.Destinations)
            {
                copy.Destinations.Add(ResolveDestination(configuration.Targets, destination, addresses));
            }

            routes.Add(copy);
        }

        return routes;
    }

    /// <summary>True for a destination that is left out of the proxy: a target without an address right now.</summary>
    public static bool IsUnresolved(ProxyDestinationOptions destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        return destination.UsesTarget && string.IsNullOrEmpty(destination.Address) && destination.Port == 0;
    }

    private static ProxyDestinationOptions ResolveDestination(IList<BackendTarget> targets, ProxyDestinationOptions destination, ITargetAddressSource addresses)
    {
        if (!destination.UsesTarget || Find(targets, destination.Target) is not { } target || FindPort(target, destination.TargetPort) is not { } port
            || addresses.CurrentAddress(target) is not { Length: > 0 } address)
        {
            return destination;
        }

        return new ProxyDestinationOptions
        {
            Scheme = port.Scheme,
            Address = address,
            Port = port.Port,
            Target = target.Name,
            TargetPort = port.Name,
            Failover = destination.Failover,
        };
    }

    /// <summary>Checks the targets and every destination that uses one; adds plain-language errors.</summary>
    public static void Validate(GatewayConfiguration configuration, List<string> errors)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(errors);

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < configuration.Targets.Count; i++)
        {
            var target = configuration.Targets[i];
            if (target is null)
            {
                errors.Add($"Target #{i + 1}: is empty.");
                continue;
            }

            var label = string.IsNullOrWhiteSpace(target.Name) ? $"Target #{i + 1}" : $"Target '{target.Name}'";
            if (string.IsNullOrWhiteSpace(target.Name))
            {
                errors.Add($"{label}: a name is required.");
            }
            else if (!ProxyRouteValidator.IsValidName(target.Name))
            {
                errors.Add($"{label}: the name may only contain letters, digits, '-', '_' and '.'.");
            }
            else if (!names.Add(target.Name))
            {
                errors.Add($"{label}: the name is used by more than one target.");
            }

            var hasMac = !string.IsNullOrWhiteSpace(target.MacAddress);
            if (hasMac && !Net.MacAddress.TryNormalize(target.MacAddress, out _))
            {
                errors.Add($"{label}: '{target.MacAddress}' is not a valid MAC address (use e.g. aa:bb:cc:dd:ee:ff).");
            }

            // With a MAC address the address is optional (the last known one); without, it is the address.
            if (string.IsNullOrWhiteSpace(target.Address))
            {
                if (!hasMac)
                {
                    errors.Add($"{label}: an address or a MAC address is required.");
                }
            }
            else if (!ProxyRouteValidator.IsValidAddress(target.Address))
            {
                errors.Add($"{label}: '{target.Address}' is not a valid IP address or host name.");
            }

            if (target.ResolveIntervalSeconds is { } interval)
            {
                if (!hasMac)
                {
                    errors.Add($"{label}: 'ResolveIntervalSeconds' only applies with a MAC address.");
                }
                else if (interval is < MinResolveIntervalSeconds or > MaxResolveIntervalSeconds)
                {
                    errors.Add($"{label}: the MAC address look-up interval must be between {MinResolveIntervalSeconds} and {MaxResolveIntervalSeconds} seconds (was {interval}).");
                }
            }

            ValidatePorts(label, target.Ports, errors);
        }

        foreach (var route in configuration.Routes)
        {
            for (var i = 0; i < route.Destinations.Count; i++)
            {
                var destination = route.Destinations[i];
                if (destination is null || !destination.UsesTarget)
                {
                    continue;
                }

                var where = route.Destinations.Count == 1 ? $"Route '{route.Name}'" : $"Route '{route.Name}', destination #{i + 1}";
                ValidateReference(where, configuration.Targets, destination, errors);
            }
        }
    }

    private static void ValidatePorts(string label, IList<TargetPort> ports, List<string> errors)
    {
        if (ports.Count == 0)
        {
            errors.Add($"{label}: at least one port is required.");
            return;
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < ports.Count; i++)
        {
            var port = ports[i];
            if (port is null)
            {
                errors.Add($"{label}, port #{i + 1}: is empty.");
                continue;
            }

            var where = string.IsNullOrWhiteSpace(port.Name) ? $"{label}, port #{i + 1}" : $"{label}, port '{port.Name}'";
            if (string.IsNullOrWhiteSpace(port.Name))
            {
                errors.Add($"{where}: a label is required.");
            }
            else if (!ProxyRouteValidator.IsValidName(port.Name))
            {
                errors.Add($"{where}: the label may only contain letters, digits, '-', '_' and '.'.");
            }
            else if (!names.Add(port.Name))
            {
                errors.Add($"{where}: the label is used by more than one port of this target.");
            }

            if (port.Port is < 1 or > 65535)
            {
                errors.Add($"{where}: port must be between 1 and 65535 (was {port.Port}).");
            }

            if (!string.Equals(port.Scheme, "http", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(port.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add($"{where}: scheme must be 'http' or 'https' (was '{port.Scheme}').");
            }
        }
    }

    private static void ValidateReference(string where, IList<BackendTarget> targets, ProxyDestinationOptions destination, List<string> errors)
    {
        if (!string.IsNullOrEmpty(destination.Address) || destination.Port != 0
            || !string.Equals(destination.Scheme, "http", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add($"{where}: use either a target or an address, not both (the address, port and scheme come from the target).");
        }

        if (string.IsNullOrEmpty(destination.Target) || string.IsNullOrEmpty(destination.TargetPort))
        {
            errors.Add($"{where}: a target destination needs both 'Target' and 'TargetPort'.");
            return;
        }

        if (Find(targets, destination.Target) is not { } target)
        {
            errors.Add($"{where}: there is no target '{destination.Target}'.");
        }
        else if (FindPort(target, destination.TargetPort) is null)
        {
            var known = string.Join(", ", target.Ports.Where(p => p is not null).Select(p => p.Name));
            errors.Add($"{where}: target '{target.Name}' has no port '{destination.TargetPort}' (it has: {known}).");
        }
    }
}
