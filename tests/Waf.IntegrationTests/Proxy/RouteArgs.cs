using System.Globalization;

namespace FASoft.Waf.IntegrationTests.Proxy;

/// <summary>
/// Builds <c>--Gateway:Routes:N:...</c> command-line arguments. All destinations are on 127.0.0.1.
/// </summary>
internal sealed class RouteArgs
{
    private readonly List<string> _args = [];
    private int _index;

    public RouteArgs Add(
        string name,
        IEnumerable<(string Scheme, int Port)> destinations,
        string[]? hosts = null,
        string? pathPrefix = null,
        string[]? methods = null,
        bool? preserveHost = null,
        bool? allowInvalidBackendCertificate = null,
        string? healthPath = null,
        int? healthIntervalSeconds = null)
    {
        var prefix = string.Create(CultureInfo.InvariantCulture, $"--Gateway:Routes:{_index++}");
        Set(prefix, "Name", name);
        AddList(prefix, "Match:Hosts", hosts);
        Set(prefix, "Match:PathPrefix", pathPrefix);
        AddList(prefix, "Match:Methods", methods);
        Set(prefix, "PreserveHost", preserveHost?.ToString());
        Set(prefix, "AllowInvalidBackendCertificate", allowInvalidBackendCertificate?.ToString());
        Set(prefix, "HealthCheck:Path", healthPath);
        Set(prefix, "HealthCheck:IntervalSeconds", healthIntervalSeconds?.ToString(CultureInfo.InvariantCulture));
        Set(prefix, "HealthCheck:TimeoutSeconds", healthIntervalSeconds?.ToString(CultureInfo.InvariantCulture));

        var i = 0;
        foreach (var (scheme, port) in destinations)
        {
            var destination = string.Create(CultureInfo.InvariantCulture, $"Destinations:{i++}");
            Set(prefix, $"{destination}:Scheme", scheme);
            Set(prefix, $"{destination}:Address", "127.0.0.1");
            Set(prefix, $"{destination}:Port", port.ToString(CultureInfo.InvariantCulture));
        }

        return this;
    }

    public string[] ToArray() => [.. _args];

    private void Set(string prefix, string key, string? value)
    {
        if (value is not null)
        {
            _args.Add($"{prefix}:{key}={value}");
        }
    }

    private void AddList(string prefix, string key, string[]? values)
    {
        for (var i = 0; values is not null && i < values.Length; i++)
        {
            Set(prefix, string.Create(CultureInfo.InvariantCulture, $"{key}:{i}"), values[i]);
        }
    }
}
