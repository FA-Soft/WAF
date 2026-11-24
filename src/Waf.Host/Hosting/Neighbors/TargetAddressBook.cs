using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Core.Routing;

namespace FASoft.Waf.Host.Hosting.Neighbors;

/// <summary>Host settings of the MAC address resolver (<c>Gateway:TargetResolver</c>); the defaults suit every site.</summary>
public sealed class TargetResolverOptions
{
    public const string SectionName = "Gateway:TargetResolver";

    /// <summary>False: no automatic look-ups (targets keep their configured address). On by default.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How often the resolver checks whether a target is due (its own interval decides how often it is looked up).</summary>
    public TimeSpan CheckInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How long the last known address is kept after the MAC address was last seen; then the target is unavailable.</summary>
    public TimeSpan GracePeriod { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Least time between two sweeps of the local network (contacting every address to find a device).</summary>
    public TimeSpan SweepInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long to wait for answers after contacting addresses, before reading the table again.</summary>
    public TimeSpan ProbeWait { get; set; } = TimeSpan.FromSeconds(1.5);
}

/// <summary>What changed for a target after a look-up.</summary>
public enum TargetAddressChange
{
    None,

    /// <summary>Found at another address than before (or found for the first time).</summary>
    Moved,

    /// <summary>Not found for the grace period: no traffic for it until it is found again.</summary>
    Unavailable,
}

/// <summary>
/// The addresses found for targets with a MAC address. Runtime state only: it never changes the configuration, so a
/// device that moves does not create configuration versions.
/// </summary>
public sealed class TargetAddressBook(INeighborTable neighbors, TargetResolverOptions options, TimeProvider time) : ITargetAddressMonitor
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>When the book was created: the grace period of a target never found counts from here.</summary>
    private readonly DateTimeOffset _started = time.GetUtcNow();

    private sealed class Entry(string targetName, string mac, string? configured)
    {
        public string TargetName { get; } = targetName;

        public string Mac { get; } = mac;

        public string? Configured { get; set; } = configured;

        public string? Found { get; set; }

        public DateTimeOffset? LastSeen { get; set; }

        public bool Available { get; set; } = true;

        public DateTimeOffset NextLookUp { get; set; }

        public int IntervalSeconds { get; set; }
    }

    private static string Key(string targetName, string mac) => $"{targetName}|{mac}";

    public string? CurrentAddress(BackendTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        var configured = string.IsNullOrWhiteSpace(target.Address) ? null : target.Address;
        if (!MacAddress.TryNormalize(target.MacAddress, out var mac) || !_entries.TryGetValue(Key(target.Name, mac), out var entry))
        {
            return configured; // an ordinary target, or one not looked up yet
        }

        return entry.Available ? entry.Found ?? configured : null;
    }

    public IReadOnlyList<TargetAddressStatus> Statuses =>
        [.. _entries.Values
            .OrderBy(e => e.TargetName, StringComparer.OrdinalIgnoreCase)
            .Select(e => new TargetAddressStatus(e.TargetName, e.Mac, e.Available ? e.Found ?? e.Configured : null, e.LastSeen, e.Available, e.Found))];

    /// <summary>Takes the targets with a MAC address of the running configuration: adds new ones, forgets removed ones.</summary>
    public void Sync(IEnumerable<BackendTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var target in targets)
        {
            if (!MacAddress.TryNormalize(target.MacAddress, out var mac))
            {
                continue;
            }

            var key = Key(target.Name, mac);
            current.Add(key);
            var entry = _entries.GetOrAdd(key, _ => new Entry(target.Name, mac, null));
            entry.Configured = string.IsNullOrWhiteSpace(target.Address) ? null : target.Address;
            entry.IntervalSeconds = target.ResolveIntervalSeconds ?? BackendTarget.DefaultResolveIntervalSeconds;
        }

        foreach (var key in _entries.Keys.Where(k => !current.Contains(k)))
        {
            _entries.TryRemove(key, out _);
        }
    }

    /// <summary>Makes every target due at once (tests, and after the configuration changed).</summary>
    internal void MakeAllDue()
    {
        foreach (var entry in _entries.Values)
        {
            entry.NextLookUp = DateTimeOffset.MinValue;
        }
    }

    /// <summary>The targets due for a look-up: (name, MAC address, the address currently used).</summary>
    public IReadOnlyList<(string TargetName, string Mac, string? Current)> Due()
    {
        var now = time.GetUtcNow();
        return [.. _entries.Values.Where(e => e.NextLookUp <= now).Select(e => (e.TargetName, e.Mac, e.Found ?? e.Configured))];
    }

    /// <summary>Records a look-up: <paramref name="found"/> is the address found, or null. Returns what changed.</summary>
    public TargetAddressChange Record(string targetName, string mac, string? found)
    {
        if (!_entries.TryGetValue(Key(targetName, mac), out var entry))
        {
            return TargetAddressChange.None;
        }

        var now = time.GetUtcNow();
        entry.NextLookUp = now.AddSeconds(entry.IntervalSeconds);
        if (found is not null)
        {
            var moved = !entry.Available || !string.Equals(found, entry.Found ?? entry.Configured, StringComparison.OrdinalIgnoreCase);
            entry.Found = found;
            entry.LastSeen = now;
            entry.Available = true;
            return moved ? TargetAddressChange.Moved : TargetAddressChange.None;
        }

        if (entry.Available && now - (entry.LastSeen ?? _started) >= options.GracePeriod)
        {
            entry.Available = false;
            return TargetAddressChange.Unavailable;
        }

        return TargetAddressChange.None;
    }

    /// <summary>The address found before <paramref name="found"/> replaced it: for log messages.</summary>
    public string? PreviousAddress(string targetName, string mac) =>
        _entries.TryGetValue(Key(targetName, mac), out var entry) ? entry.Found ?? entry.Configured : null;

    public async Task<string?> LookUpMacAddressAsync(string address, CancellationToken cancellationToken)
    {
        if (!StrictIpAddress.TryParse(address?.Trim(), out var ip))
        {
            return null;
        }

        await neighbors.ProbeAsync([ip], cancellationToken).ConfigureAwait(false);
        await Task.Delay(options.ProbeWait, time, cancellationToken).ConfigureAwait(false);
        var entries = await neighbors.ReadAsync(cancellationToken).ConfigureAwait(false);
        return entries.FirstOrDefault(e => e.Address.Equals(ip))?.MacAddress;
    }

    /// <summary>
    /// Which address to use for <paramref name="mac"/>: entries the system confirmed recently first, then those being
    /// confirmed, then stale ones; among equals the address in use (no needless moves), then IPv4, then the first.
    /// </summary>
    public static NeighborEntry? Choose(IEnumerable<NeighborEntry> entries, string mac, string? current)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return entries
            .Where(e => string.Equals(e.MacAddress, mac, StringComparison.OrdinalIgnoreCase) && !IsLinkLocal(e.Address))
            .OrderByDescending(e => e.State)
            .ThenByDescending(e => string.Equals(e.Address.ToString(), current, StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(e => e.Address.AddressFamily == AddressFamily.InterNetwork)
            .FirstOrDefault();
    }

    /// <summary>IPv6 link-local addresses (fe80::/10) need a zone and are useless as a backend address.</summary>
    private static bool IsLinkLocal(IPAddress address) => address.IsIPv6LinkLocal;
}
