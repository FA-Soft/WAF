using Waf.Core.Net;

namespace Waf.Core.Routing;

/// <summary>
/// Validates route configuration and returns plain-language errors.
/// </summary>
public static class ProxyRouteValidator
{
    private const int MaxHealthCheckSeconds = 3600;

    public static IReadOnlyList<string> Validate(IReadOnlyList<ProxyRouteOptions> routes)
    {
        ArgumentNullException.ThrowIfNull(routes);

        var errors = new List<string>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < routes.Count; i++)
        {
            var route = routes[i];
            var label = string.IsNullOrWhiteSpace(route.Name) ? $"Route #{i + 1}" : $"Route '{route.Name}'";

            if (string.IsNullOrWhiteSpace(route.Name))
            {
                errors.Add($"{label}: a name is required.");
            }
            else if (!IsValidName(route.Name))
            {
                errors.Add($"{label}: the name may only contain letters, digits, '-', '_' and '.'.");
            }
            else if (!names.Add(route.Name))
            {
                errors.Add($"{label}: the name is used by more than one route.");
            }

            ValidateMatch(label, route.Match, errors);
            ValidateDestinations(label, route.Destinations, errors);
            ValidateHealthCheck(label, route.HealthCheck, errors);
        }

        return errors;
    }

    /// <summary>True for a non-empty name of letters, digits, '-', '_' and '.' (route and rule names).</summary>
    public static bool IsValidName(string? name) =>
        !string.IsNullOrEmpty(name) && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    /// <summary>
    /// True for an IP address in strict notation or a DNS host name. Rejects legacy numeric forms such as
    /// <c>10</c> or <c>0x0A000001</c>, which URI parsing would silently turn into an IP address.
    /// </summary>
    public static bool IsValidAddress(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return false;
        }

        if (StrictIpAddress.TryParse(address, out _))
        {
            return true;
        }

        return Uri.TryCreate($"http://{address}/", UriKind.Absolute, out var uri)
            && uri.HostNameType == UriHostNameType.Dns
            && string.Equals(uri.Host, address, StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateMatch(string label, RouteMatchOptions? match, List<string> errors)
    {
        if (match is null)
        {
            errors.Add($"{label}: 'Match' is missing.");
            return;
        }

        foreach (var host in match.Hosts)
        {
            var name = host?.StartsWith("*.", StringComparison.Ordinal) == true ? host[2..] : host;
            if (!IsValidAddress(name))
            {
                errors.Add($"{label}: '{host}' is not a valid host name (use e.g. 'api.example.com' or '*.example.com').");
            }
        }

        var prefix = match.PathPrefix;
        if (string.IsNullOrEmpty(prefix) || prefix[0] != '/')
        {
            errors.Add($"{label}: the path prefix must start with '/' (was '{prefix}').");
        }
        else if (prefix.IndexOfAny(['{', '}', '?', '#', '*', '\\', ' ']) >= 0 || prefix.Contains("//", StringComparison.Ordinal))
        {
            errors.Add($"{label}: the path prefix '{prefix}' contains characters that are not allowed ({{ }} ? # * \\ space or //).");
        }

        foreach (var method in match.Methods)
        {
            if (string.IsNullOrEmpty(method) || !method.All(char.IsAsciiLetter))
            {
                errors.Add($"{label}: '{method}' is not a valid HTTP method (use e.g. GET, POST).");
            }
        }
    }

    private static void ValidateDestinations(string label, IList<ProxyDestinationOptions> destinations, List<string> errors)
    {
        if (destinations.Count == 0)
        {
            errors.Add($"{label}: at least one destination is required.");
            return;
        }

        for (var i = 0; i < destinations.Count; i++)
        {
            var destination = destinations[i];
            var where = destinations.Count == 1 ? label : $"{label}, destination #{i + 1}";

            if (!string.Equals(destination.Scheme, "http", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(destination.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add($"{where}: scheme must be 'http' or 'https' (was '{destination.Scheme}').");
            }

            if (!IsValidAddress(destination.Address))
            {
                errors.Add($"{where}: '{destination.Address}' is not a valid IP address or host name.");
            }

            if (destination.Port is < 1 or > 65535)
            {
                errors.Add($"{where}: port must be between 1 and 65535 (was {destination.Port}).");
            }
        }
    }

    private static void ValidateHealthCheck(string label, RouteHealthCheckOptions? health, List<string> errors)
    {
        if (health is null || string.IsNullOrEmpty(health.Path))
        {
            return;
        }

        if (health.Path[0] != '/')
        {
            errors.Add($"{label}: the health check path must start with '/' (was '{health.Path}').");
        }

        if (health.IntervalSeconds is < 1 or > MaxHealthCheckSeconds)
        {
            errors.Add($"{label}: the health check interval must be between 1 and {MaxHealthCheckSeconds} seconds.");
        }

        if (health.TimeoutSeconds is < 1 or > MaxHealthCheckSeconds)
        {
            errors.Add($"{label}: the health check timeout must be between 1 and {MaxHealthCheckSeconds} seconds.");
        }
    }
}
