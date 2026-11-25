using System.ComponentModel.DataAnnotations;
using System.Globalization;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Core.Routing;

namespace FASoft.Waf.Web;

/// <summary>Form model of the route editor: plain fields that map to <see cref="ProxyRouteOptions"/>.</summary>
internal sealed class RouteFormModel : IValidatableObject
{
    /// <summary>HTTP methods offered as checkboxes.</summary>
    public static readonly string[] CommonMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

    /// <summary>The configuration version the form was opened on (to detect concurrent changes).</summary>
    public long BaseVersion { get; set; }

    /// <summary>True when creating a route; false when editing (the name cannot change then).</summary>
    public bool IsNew { get; set; } = true;

    [Required(ErrorMessage = "Give the route a name, e.g. website or api.")]
    public string Name { get; set; } = string.Empty;

    // Checkbox properties default to false: an unticked checkbox is not posted at all, so a default of true could
    // never be switched off. New routes start ticked via ForNewRoute.
    public bool Enabled { get; set; }

    /// <summary>Host names, one per line (or separated by commas or spaces).</summary>
    public string? Hosts { get; set; }

    [Required(ErrorMessage = "Enter a path prefix; use / for all paths.")]
    public string PathPrefix { get; set; } = "/";

    public bool MethodGet { get; set; }
    public bool MethodPost { get; set; }
    public bool MethodPut { get; set; }
    public bool MethodPatch { get; set; }
    public bool MethodDelete { get; set; }
    public bool MethodHead { get; set; }
    public bool MethodOptions { get; set; }

    /// <summary>Backends, one per line: an address (http://10.0.0.5:8080) or a target and port label (nas/web).</summary>
    [Required(ErrorMessage = "Enter at least one backend, e.g. http://10.0.0.5:8080 or a target such as nas/web.")]
    public string Destinations { get; set; } = string.Empty;

    /// <summary>
    /// Failover backends, one per line, in the order they take over (line 1 is failover 1): they only get traffic while
    /// none of <see cref="Destinations"/> is healthy.
    /// </summary>
    public string? FailoverDestinations { get; set; }

    /// <summary>Set by the editor's extra buttons ("add-target", "add-target-failover"); null for Save.</summary>
    public string? Command { get; set; }

    /// <summary>The target line chosen in "Add a target", e.g. <c>nas/web</c>.</summary>
    public string? AddTarget { get; set; }

    /// <summary>
    /// Handles "Add a target": appends the chosen target line to <see cref="Destinations"/> (once). Returns true when
    /// the request was this command, so the form is shown again instead of saved.
    /// </summary>
    public bool TryApplyCommand()
    {
        if (Command is not ("add-target" or "add-target-failover"))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(AddTarget) && RouteFormModel.TryParseTarget(AddTarget, out var target, out var port))
        {
            var line = TargetLine(target, port);
            var failover = Command == "add-target-failover";
            var lines = SplitLines(failover ? FailoverDestinations : Destinations).ToList();
            if (!lines.Contains(line, StringComparer.OrdinalIgnoreCase))
            {
                var text = string.Join(Environment.NewLine, lines.Append(line));
                if (failover)
                {
                    FailoverDestinations = text;
                }
                else
                {
                    Destinations = text;
                }
            }
        }

        Command = null;
        AddTarget = null;
        return true;
    }

    public bool PreserveHost { get; set; }

    public bool AllowInvalidBackendCertificate { get; set; }

    public bool RedirectHttp { get; set; }

    public bool Hsts { get; set; }

    public string? HealthCheckPath { get; set; }

    /// <summary>Optional text for visitors when no backend answers, e.g. "Planned maintenance until 14:00".</summary>
    [StringLength(ProxyRouteValidator.MaxErrorMessageLength, ErrorMessage = "Keep the message to 300 characters or fewer.")]
    public string? ErrorMessage { get; set; }

    /// <summary>The message for visitors whose browser prefers Dutch; empty: the English message.</summary>
    [StringLength(ProxyRouteValidator.MaxErrorMessageLength, ErrorMessage = "Keep the message to 300 characters or fewer.")]
    public string? ErrorMessageNl { get; set; }

    /// <summary>The message for visitors whose browser prefers French; empty: the English message.</summary>
    [StringLength(ProxyRouteValidator.MaxErrorMessageLength, ErrorMessage = "Keep the message to 300 characters or fewer.")]
    public string? ErrorMessageFr { get; set; }

    /// <summary>The message for visitors whose browser prefers German; empty: the English message.</summary>
    [StringLength(ProxyRouteValidator.MaxErrorMessageLength, ErrorMessage = "Keep the message to 300 characters or fewer.")]
    public string? ErrorMessageDe { get; set; }

    /// <summary>The translated messages that are filled in: language → text.</summary>
    private IEnumerable<(string Language, string Text, string Field)> ErrorMessageTranslations() =>
        new[] { ("nl", ErrorMessageNl, nameof(ErrorMessageNl)), ("fr", ErrorMessageFr, nameof(ErrorMessageFr)), ("de", ErrorMessageDe, nameof(ErrorMessageDe)) }
            .Where(t => !string.IsNullOrWhiteSpace(t.Item2))
            .Select(t => (t.Item1, t.Item2!.Trim(), t.Item3));

    [Range(1, 3600, ErrorMessage = "Use a value between 1 and 3600 seconds.")]
    public int HealthCheckIntervalSeconds { get; set; } = 10;

    [Range(1, 3600, ErrorMessage = "Use a value between 1 and 3600 seconds.")]
    public int HealthCheckTimeoutSeconds { get; set; } = 5;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrWhiteSpace(Name) && !ProxyRouteValidator.IsValidName(Name.Trim()))
        {
            yield return new ValidationResult("Use only letters, digits, '-', '_' and '.' (no spaces).", [nameof(Name)]);
        }

        foreach (var host in SplitList(Hosts))
        {
            var name = host.StartsWith("*.", StringComparison.Ordinal) ? host[2..] : host;
            if (!ProxyRouteValidator.IsValidAddress(name))
            {
                yield return new ValidationResult($"'{host}' is not a valid host name. Use e.g. www.example.com or *.example.com.", [nameof(Hosts)]);
            }
        }

        if (!string.IsNullOrEmpty(PathPrefix) && PathPrefix.Trim()[0] != '/')
        {
            yield return new ValidationResult("The path prefix must start with /, e.g. /api.", [nameof(PathPrefix)]);
        }

        var line = 0;
        var primaries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var destination in SplitLines(Destinations))
        {
            line++;
            if (!TryParseDestination(destination, out var parsed, out var error))
            {
                yield return new ValidationResult($"Backend line {line} ('{destination}'): {error}", [nameof(Destinations)]);
            }
            else
            {
                primaries.Add(FormatDestination(parsed));
            }
        }

        line = 0;
        foreach (var destination in SplitLines(FailoverDestinations))
        {
            line++;
            if (line > ProxyRouteValidator.MaxFailover)
            {
                yield return new ValidationResult($"At most {ProxyRouteValidator.MaxFailover} failover backends.", [nameof(FailoverDestinations)]);
                break;
            }

            if (!TryParseDestination(destination, out var parsed, out var error))
            {
                yield return new ValidationResult($"Failover line {line} ('{destination}'): {error}", [nameof(FailoverDestinations)]);
            }
            else if (primaries.Contains(FormatDestination(parsed)))
            {
                yield return new ValidationResult($"Failover line {line} ('{destination}') is already a backend above; a failover is another address or target.", [nameof(FailoverDestinations)]);
            }
        }

        if (ErrorMessage is { } message && message.Any(char.IsControl))
        {
            yield return new ValidationResult("Write the message on one line.", [nameof(ErrorMessage)]);
        }

        foreach (var (_, text, field) in ErrorMessageTranslations())
        {
            if (text.Any(char.IsControl))
            {
                yield return new ValidationResult("Write the message on one line.", [field]);
            }
            else if (string.IsNullOrWhiteSpace(ErrorMessage))
            {
                yield return new ValidationResult("Enter the English message too: visitors in other languages get it.", [nameof(ErrorMessage)]);
                break;
            }
        }

        if (!string.IsNullOrWhiteSpace(HealthCheckPath) && HealthCheckPath.Trim()[0] != '/')
        {
            yield return new ValidationResult("The health check path must start with /, e.g. /health.", [nameof(HealthCheckPath)]);
        }
    }

    /// <summary>The form for a new route, with the recommended defaults ticked, optionally pre-filled from a template.</summary>
    public static RouteFormModel ForNewRoute(long baseVersion, string? template = null)
    {
        var model = new RouteFormModel { BaseVersion = baseVersion, IsNew = true, Enabled = true, PreserveHost = true };
        TemplateLibrary.FindRoute(template)?.Apply(model);
        return model;
    }

    public static RouteFormModel FromRoute(ProxyRouteOptions route, long baseVersion)
    {
        ArgumentNullException.ThrowIfNull(route);

        var methods = new HashSet<string>(route.Match.Methods.Select(m => m.ToUpperInvariant()), StringComparer.Ordinal);
        return new RouteFormModel
        {
            BaseVersion = baseVersion,
            IsNew = false,
            Name = route.Name,
            Enabled = route.Enabled,
            Hosts = string.Join(Environment.NewLine, route.Match.Hosts),
            PathPrefix = route.Match.PathPrefix,
            MethodGet = methods.Contains("GET"),
            MethodPost = methods.Contains("POST"),
            MethodPut = methods.Contains("PUT"),
            MethodPatch = methods.Contains("PATCH"),
            MethodDelete = methods.Contains("DELETE"),
            MethodHead = methods.Contains("HEAD"),
            MethodOptions = methods.Contains("OPTIONS"),
            Destinations = string.Join(Environment.NewLine, route.Destinations.Where(d => !d.IsFailover).Select(FormatDestination)),
            // In failover order; equal numbers keep their order.
            FailoverDestinations = string.Join(Environment.NewLine, route.Destinations.Where(d => d.IsFailover).OrderBy(d => d.Failover).Select(FormatDestination)),
            PreserveHost = route.PreserveHost,
            AllowInvalidBackendCertificate = route.AllowInvalidBackendCertificate,
            RedirectHttp = route.Https.RedirectHttp,
            Hsts = route.Https.Hsts,
            HealthCheckPath = route.HealthCheck.Path,
            HealthCheckIntervalSeconds = route.HealthCheck.IntervalSeconds,
            HealthCheckTimeoutSeconds = route.HealthCheck.TimeoutSeconds,
            ErrorMessage = route.ErrorMessage,
            ErrorMessageNl = route.ErrorMessageTranslations?.TryGetValue("nl", out var nl) == true ? nl : null,
            ErrorMessageFr = route.ErrorMessageTranslations?.TryGetValue("fr", out var fr) == true ? fr : null,
            ErrorMessageDe = route.ErrorMessageTranslations?.TryGetValue("de", out var de) == true ? de : null,
        };
    }

    /// <summary>The route described by the form. Call only after validation succeeded.</summary>
    public ProxyRouteOptions ToRoute()
    {
        var route = new ProxyRouteOptions
        {
            Name = Name.Trim(),
            Enabled = Enabled,
            PreserveHost = PreserveHost,
            AllowInvalidBackendCertificate = AllowInvalidBackendCertificate,
            Https = new RouteHttpsOptions { RedirectHttp = RedirectHttp, Hsts = Hsts },
            ErrorMessage = string.IsNullOrWhiteSpace(ErrorMessage) ? null : ErrorMessage.Trim(),
            // Only the languages that are filled in; none: no translations at all (the configuration stays as it was).
            ErrorMessageTranslations = ErrorMessageTranslations().Any()
                ? ErrorMessageTranslations().ToDictionary(t => t.Language, t => t.Text, StringComparer.Ordinal)
                : null,
            HealthCheck = new RouteHealthCheckOptions
            {
                Path = string.IsNullOrWhiteSpace(HealthCheckPath) ? null : HealthCheckPath.Trim(),
                IntervalSeconds = HealthCheckIntervalSeconds,
                TimeoutSeconds = HealthCheckTimeoutSeconds,
            },
        };

        route.Match.PathPrefix = PathPrefix.Trim();
        foreach (var host in SplitList(Hosts))
        {
            route.Match.Hosts.Add(host);
        }

        foreach (var (method, selected) in new[]
        {
            ("GET", MethodGet), ("POST", MethodPost), ("PUT", MethodPut), ("PATCH", MethodPatch),
            ("DELETE", MethodDelete), ("HEAD", MethodHead), ("OPTIONS", MethodOptions),
        })
        {
            if (selected)
            {
                route.Match.Methods.Add(method);
            }
        }

        foreach (var line in SplitLines(Destinations))
        {
            if (TryParseDestination(line, out var destination, out _))
            {
                route.Destinations.Add(destination);
            }
        }

        var failover = 0;
        foreach (var line in SplitLines(FailoverDestinations))
        {
            if (TryParseDestination(line, out var destination, out _))
            {
                destination.Failover = ++failover;
                route.Destinations.Add(destination);
            }
        }

        return route;
    }

    /// <summary>
    /// Parses a backend address: <c>http://10.0.0.5:8080</c>, <c>https://backend.local</c> (port 443),
    /// <c>10.0.0.5:8080</c> (http), <c>http://[fd00::10]:8080</c>.
    /// </summary>
    public static bool TryParseDestination(string text, out ProxyDestinationOptions destination, out string error)
    {
        destination = new ProxyDestinationOptions();
        var value = text.Trim();
        if (TryParseTarget(value, out var target, out var port))
        {
            // Whether the target and port exist is checked with the whole configuration when saving.
            destination = new ProxyDestinationOptions { Target = target, TargetPort = port };
            error = string.Empty;
            return true;
        }

        if (!value.Contains("://", StringComparison.Ordinal))
        {
            value = "http://" + value;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
        {
            error = "not a valid address. Use e.g. http://10.0.0.5:8080.";
            return false;
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            error = "only http:// and https:// backends are supported.";
            return false;
        }

        if (uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || !string.IsNullOrEmpty(uri.UserInfo))
        {
            error = Text.N("a backend address is only scheme, host and port, without a path (the request path is forwarded as is).");
            return false;
        }

        // Validate the host as typed: Uri silently turns legacy forms such as "10" into 0.0.0.10.
        var host = RawHost(value);
        if (!ProxyRouteValidator.IsValidAddress(host))
        {
            error = Text.F("'{0}' is not a valid IP address or host name.", host);
            return false;
        }

        host = host.ToLowerInvariant();

        destination = new ProxyDestinationOptions { Scheme = uri.Scheme, Address = host, Port = uri.Port };
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// A target line: <c>nas/web</c> (target, then port label), or <c>nas · web</c> as the lists show it. Never an
    /// address: addresses either have <c>://</c> or no slash (a path after an address is refused anyway).
    /// </summary>
    public static bool TryParseTarget(string text, out string target, out string port)
    {
        ArgumentNullException.ThrowIfNull(text);
        target = port = string.Empty;
        if (text.Contains("://", StringComparison.Ordinal))
        {
            return false;
        }

        var parts = text.Split(['/', '·'], StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !ProxyRouteValidator.IsValidName(parts[0]) || !ProxyRouteValidator.IsValidName(parts[1]))
        {
            return false;
        }

        (target, port) = (parts[0], parts[1]);
        return true;
    }

    /// <summary>How a target line is written in the editor: <c>nas/web</c>.</summary>
    public static string TargetLine(string target, string port) => $"{target}/{port}";

    public static string FormatDestination(ProxyDestinationOptions destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.UsesTarget)
        {
            return TargetLine(destination.Target ?? string.Empty, destination.TargetPort ?? string.Empty);
        }

        var host = StrictIpAddress.TryParse(destination.Address, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{destination.Address}]"
            : destination.Address;
        return string.Create(CultureInfo.InvariantCulture, $"{destination.Scheme.ToLowerInvariant()}://{host}:{destination.Port}");
    }

    /// <summary>The host part of "scheme://host:port/…" exactly as written (IPv6 without brackets).</summary>
    private static string RawHost(string url)
    {
        var authority = url[(url.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var end = authority.IndexOfAny(['/', '?', '#']);
        authority = end < 0 ? authority : authority[..end];
        authority = authority[(authority.LastIndexOf('@') + 1)..];

        if (authority.StartsWith('['))
        {
            var close = authority.IndexOf(']', StringComparison.Ordinal);
            return close < 0 ? authority : authority[1..close];
        }

        var colon = authority.LastIndexOf(':');
        return colon < 0 ? authority : authority[..colon];
    }

    private static IEnumerable<string> SplitLines(string? text) =>
        (text ?? string.Empty).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0);

    private static string[] SplitList(string? text) =>
        (text ?? string.Empty).Split(['\n', ',', ' ', '\t', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>Helpers to change a copy of the running configuration.</summary>
internal static class ConfigurationEditing
{
    /// <summary>A deep, independent copy of <paramref name="configuration"/>.</summary>
    public static GatewayConfiguration Clone(GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var parsed = GatewayConfigurationJson.Parse(GatewayConfigurationJson.Serialize(configuration));
        return parsed.Configuration ?? throw new InvalidOperationException("The configuration could not be copied: " + string.Join(" ", parsed.Errors));
    }

    /// <summary>Everything that refers to the route by name (so it cannot be deleted while those exist).</summary>
    public static IReadOnlyList<string> RouteReferences(GatewayConfiguration configuration, string routeName)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var references = new List<string>();
        references.AddRange(configuration.Rules
            .Where(r => r.Routes.Contains(routeName, StringComparer.OrdinalIgnoreCase))
            .Select(r => Text.T("rule '{0}'", r.Name)));
        references.AddRange(configuration.RateLimits
            .Where(l => l.Routes.Contains(routeName, StringComparer.OrdinalIgnoreCase))
            .Select(l => Text.T("rate limit '{0}'", l.Name)));
        references.AddRange(configuration.Settings.AttackDetection.Exclusions
            .Select((e, i) => (e, i))
            .Where(x => x.e.Routes.Contains(routeName, StringComparer.OrdinalIgnoreCase))
            .Select(x => Text.T("detection exclusion #{0} ({1})", x.i + 1, x.e.PathPrefix)));
        return references;
    }
}
