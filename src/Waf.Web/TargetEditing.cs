using System.ComponentModel.DataAnnotations;
using System.Globalization;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;

namespace FASoft.Waf.Web;

/// <summary>Form model of the target editor: a named machine with labelled ports.</summary>
internal sealed class TargetFormModel : IValidatableObject
{
    public long BaseVersion { get; set; }

    public bool IsNew { get; set; } = true;

    /// <summary>The name before editing; a renamed target takes its routes along.</summary>
    public string? OriginalName { get; set; }

    /// <summary>Set by the editor's extra buttons ("add-port", "remove-port-N"); null for Save.</summary>
    public string? Command { get; set; }

    [Required(ErrorMessage = "Give the target a name, e.g. nas.")]
    public string Name { get; set; } = string.Empty;

    public string? Description { get; set; }

    /// <summary>IP address or host name; optional with a MAC address (then the last known address).</summary>
    public string? Address { get; set; }

    /// <summary>MAC address of a device whose IP address changes (DHCP); empty for a fixed address.</summary>
    public string? MacAddress { get; set; }

    /// <summary>Seconds between MAC address look-ups; empty: the default (60).</summary>
    public int? ResolveIntervalSeconds { get; set; }

    /// <summary>Shown after "Look up MAC address": what was found, or why not.</summary>
    public string? LookUpResult { get; set; }

    public List<TargetPortFormModel> Ports { get; set; } = [];

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrWhiteSpace(Name) && !ProxyRouteValidator.IsValidName(Name.Trim()))
        {
            yield return new ValidationResult("The name may only contain letters, digits, '-', '_' and '.', e.g. nas or web-server.", [nameof(Name)]);
        }

        var hasMac = !string.IsNullOrWhiteSpace(MacAddress);
        if (hasMac && !Core.Net.MacAddress.TryNormalize(MacAddress, out _))
        {
            yield return new ValidationResult($"'{MacAddress!.Trim()}' is not a MAC address. Use e.g. aa:bb:cc:dd:ee:ff.", [nameof(MacAddress)]);
        }

        if (string.IsNullOrWhiteSpace(Address) && !hasMac)
        {
            yield return new ValidationResult("Enter the machine's IP address or host name (e.g. 192.168.1.20), or its MAC address.", [nameof(Address)]);
        }

        if (ResolveIntervalSeconds is { } interval && (interval < TargetResolver.MinResolveIntervalSeconds || interval > TargetResolver.MaxResolveIntervalSeconds))
        {
            yield return new ValidationResult($"Look it up every {TargetResolver.MinResolveIntervalSeconds} to {TargetResolver.MaxResolveIntervalSeconds} seconds.", [nameof(ResolveIntervalSeconds)]);
        }

        if (!string.IsNullOrWhiteSpace(Address) && !ProxyRouteValidator.IsValidAddress(Address.Trim()))
        {
            yield return new ValidationResult($"'{Address.Trim()}' is not a valid IP address or host name.", [nameof(Address)]);
        }

        var used = Ports.Where(p => !p.IsEmpty).ToList();
        if (used.Count == 0)
        {
            yield return new ValidationResult("Add at least one port, e.g. web with port 80.", [nameof(Ports)]);
        }

        var labels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < used.Count; i++)
        {
            var port = used[i];
            var where = $"Port {i + 1}";
            if (string.IsNullOrWhiteSpace(port.Name))
            {
                yield return new ValidationResult($"{where}: give it a label, e.g. web or admin.", [nameof(Ports)]);
            }
            else if (!ProxyRouteValidator.IsValidName(port.Name.Trim()))
            {
                yield return new ValidationResult($"{where}: the label may only contain letters, digits, '-', '_' and '.'.", [nameof(Ports)]);
            }
            else if (!labels.Add(port.Name.Trim()))
            {
                yield return new ValidationResult($"{where}: the label '{port.Name.Trim()}' is used twice.", [nameof(Ports)]);
            }

            if (port.Port is not (>= 1 and <= 65535))
            {
                yield return new ValidationResult($"{where}: the port must be a number from 1 to 65535.", [nameof(Ports)]);
            }
        }
    }

    public static TargetFormModel ForNewTarget(long baseVersion) => new()
    {
        BaseVersion = baseVersion,
        Ports = [new TargetPortFormModel { Name = "web", Port = 80 }],
    };

    public static TargetFormModel FromTarget(BackendTarget target, long baseVersion)
    {
        ArgumentNullException.ThrowIfNull(target);
        return new TargetFormModel
        {
            BaseVersion = baseVersion,
            IsNew = false,
            OriginalName = target.Name,
            Name = target.Name,
            Description = target.Description,
            Address = target.Address,
            MacAddress = target.MacAddress,
            ResolveIntervalSeconds = target.ResolveIntervalSeconds,
            Ports = [.. target.Ports.Select(p => new TargetPortFormModel
            {
                OriginalName = p.Name,
                Name = p.Name,
                Port = p.Port,
                Https = string.Equals(p.Scheme, "https", StringComparison.OrdinalIgnoreCase),
            })],
        };
    }

    public BackendTarget ToTarget()
    {
        var target = new BackendTarget
        {
            Name = Name.Trim(),
            Description = string.IsNullOrWhiteSpace(Description) ? null : Description.Trim(),
            Address = Address?.Trim().ToLowerInvariant() ?? string.Empty,
            MacAddress = Core.Net.MacAddress.TryNormalize(MacAddress, out var mac) ? mac : null,
            ResolveIntervalSeconds = Core.Net.MacAddress.TryNormalize(MacAddress, out _) ? ResolveIntervalSeconds : null,
        };
        foreach (var port in Ports.Where(p => !p.IsEmpty))
        {
            target.Ports.Add(new TargetPort { Name = port.Name?.Trim() ?? string.Empty, Port = port.Port ?? 0, Scheme = port.Https ? "https" : "http" });
        }

        return target;
    }

    /// <summary>Applies "add-port" or "remove-port-N"; true when it was one of them (show the form again, save nothing).</summary>
    public bool TryApplyCommand()
    {
        const string RemovePrefix = "remove-port-";
        if (Command == "add-port")
        {
            Ports.Add(new TargetPortFormModel());
        }
        else if (Command?.StartsWith(RemovePrefix, StringComparison.Ordinal) == true
            && int.TryParse(Command[RemovePrefix.Length..], CultureInfo.InvariantCulture, out var index))
        {
            if (index >= 0 && index < Ports.Count)
            {
                Ports.RemoveAt(index);
            }

            if (Ports.Count == 0)
            {
                Ports.Add(new TargetPortFormModel());
            }
        }
        else
        {
            return false;
        }

        Command = null;
        return true;
    }
}

/// <summary>One port row of the target editor.</summary>
internal sealed class TargetPortFormModel
{
    /// <summary>The label before editing; a renamed label takes its routes along.</summary>
    public string? OriginalName { get; set; }

    public string? Name { get; set; }

    public int? Port { get; set; }

    public bool Https { get; set; }

    public bool IsEmpty => string.IsNullOrWhiteSpace(Name) && Port is null;
}

/// <summary>Changes to targets and the routes that use them.</summary>
internal static class TargetEditing
{
    /// <summary>"Route 'files' (port web)": the routes that use <paramref name="targetName"/>.</summary>
    public static IReadOnlyList<string> References(GatewayConfiguration configuration, string targetName)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return [.. configuration.Routes
            .SelectMany(r => r.Destinations
                .Where(d => d.UsesTarget && string.Equals(d.Target, targetName, StringComparison.OrdinalIgnoreCase))
                .Select(d => (Route: r.Name, Port: d.TargetPort)))
            .Distinct()
            .Select(x => $"Route '{x.Route}' (port {x.Port})")];
    }

    /// <summary>The names of the routes that use <paramref name="targetName"/>.</summary>
    public static IReadOnlyList<string> RouteNames(GatewayConfiguration configuration, string targetName)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return [.. configuration.Routes
            .Where(r => r.Destinations.Any(d => d.UsesTarget && string.Equals(d.Target, targetName, StringComparison.OrdinalIgnoreCase)))
            .Select(r => r.Name)];
    }

    /// <summary>
    /// Puts <paramref name="model"/>'s target into <paramref name="configuration"/> (adding it, or replacing the one it
    /// was). A renamed target or port label is renamed in every route that uses it, so the routes keep working.
    /// Returns an error message, or null.
    /// </summary>
    public static string? Apply(GatewayConfiguration configuration, TargetFormModel model)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(model);

        var target = model.ToTarget();
        var existing = TargetResolver.Find(configuration.Targets, target.Name);
        if (model.IsNew)
        {
            if (existing is not null)
            {
                return Text.F("A target named '{0}' already exists. Choose another name.", target.Name);
            }

            configuration.Targets.Add(target);
            return null;
        }

        var original = TargetResolver.Find(configuration.Targets, model.OriginalName);
        if (original is null)
        {
            return Text.F("Target '{0}' no longer exists; it was deleted in the meantime.", model.OriginalName);
        }

        if (existing is not null && !ReferenceEquals(existing, original))
        {
            return Text.F("A target named '{0}' already exists. Choose another name.", target.Name);
        }

        configuration.Targets[configuration.Targets.IndexOf(original)] = target;

        // Port labels: rows keep the label they had, so a renamed label is followed.
        var renamedPorts = model.Ports
            .Where(p => !p.IsEmpty && !string.IsNullOrEmpty(p.OriginalName) && !string.Equals(p.OriginalName, p.Name?.Trim(), StringComparison.OrdinalIgnoreCase))
            .ToDictionary(p => p.OriginalName!, p => p.Name!.Trim(), StringComparer.OrdinalIgnoreCase);

        foreach (var destination in configuration.Routes.SelectMany(r => r.Destinations)
            .Where(d => d.UsesTarget && string.Equals(d.Target, original.Name, StringComparison.OrdinalIgnoreCase)))
        {
            destination.Target = target.Name;
            if (destination.TargetPort is { } port && renamedPorts.TryGetValue(port, out var renamed))
            {
                destination.TargetPort = renamed;
            }
        }

        return null;
    }
}
