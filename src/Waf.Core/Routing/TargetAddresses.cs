namespace FASoft.Waf.Core.Routing;

/// <summary>Where a target's traffic goes right now: for targets with a MAC address, what the gateway found.</summary>
public interface ITargetAddressSource
{
    /// <summary>
    /// The address to forward to: the configured address for an ordinary target; for a target with a MAC address, the
    /// address found for it (or the configured one until it is found). Null when the target is unavailable: its MAC
    /// address has not been seen for too long, so traffic is not sent to an address that may now be another device.
    /// </summary>
    string? CurrentAddress(BackendTarget target);
}

/// <summary>What the gateway knows about a target with a MAC address.</summary>
/// <param name="TargetName">The target.</param>
/// <param name="MacAddress">Its MAC address, normalized.</param>
/// <param name="Address">The address in use; null while unavailable or not found yet without a configured address.</param>
/// <param name="LastSeen">When the MAC address was last found in the neighbour table; null if never.</param>
/// <param name="Available">False once it has not been found for the grace period.</param>
/// <param name="FoundAddress">The address found the last time (may differ from the configured one).</param>
public sealed record TargetAddressStatus(
    string TargetName, string MacAddress, string? Address, DateTimeOffset? LastSeen, bool Available, string? FoundAddress);

/// <summary>The MAC address resolver as the admin UI sees it.</summary>
public interface ITargetAddressMonitor : ITargetAddressSource
{
    /// <summary>The targets with a MAC address in the running configuration, with what was found.</summary>
    IReadOnlyList<TargetAddressStatus> Statuses { get; }

    /// <summary>
    /// The MAC address of <paramref name="address"/> (an IP address on this network): contacts it, then reads the
    /// neighbour table. Null when it did not answer or is not on this network.
    /// </summary>
    Task<string?> LookUpMacAddressAsync(string address, CancellationToken cancellationToken);
}

/// <summary>Configured addresses only: for places without a resolver (tools, tests).</summary>
public sealed class ConfiguredTargetAddresses : ITargetAddressSource
{
    public static readonly ConfiguredTargetAddresses Instance = new();

    public string? CurrentAddress(BackendTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return string.IsNullOrWhiteSpace(target.Address) ? null : target.Address;
    }
}
