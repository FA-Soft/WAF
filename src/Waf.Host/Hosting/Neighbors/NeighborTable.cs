using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using FASoft.Waf.Core.Net;

namespace FASoft.Waf.Host.Hosting.Neighbors;

/// <summary>How sure the operating system is that a neighbour is there right now.</summary>
public enum NeighborState
{
    /// <summary>Not confirmed recently (STALE), or the table does not say (/proc/net/arp).</summary>
    Stale,

    /// <summary>Being confirmed (DELAY, PROBE).</summary>
    Probing,

    /// <summary>Confirmed recently (REACHABLE), or a fixed entry (PERMANENT).</summary>
    Reachable,
}

/// <summary>One entry of the neighbour (ARP/NDP) table: an IP address and the MAC address that answers for it.</summary>
public sealed record NeighborEntry(IPAddress Address, string MacAddress, NeighborState State);

/// <summary>The operating system's neighbour table, and the ways to make it learn about addresses.</summary>
public interface INeighborTable
{
    /// <summary>The current entries with a MAC address (failed and incomplete ones are left out).</summary>
    Task<IReadOnlyList<NeighborEntry>> ReadAsync(CancellationToken cancellationToken);

    /// <summary>Contacts <paramref name="addresses"/> so the table (re)learns their MAC addresses.</summary>
    Task ProbeAsync(IEnumerable<IPAddress> addresses, CancellationToken cancellationToken);

    /// <summary>Contacts every address of the directly connected IPv4 networks (at most a /22 each), to find a device whose address is unknown.</summary>
    Task SweepAsync(CancellationToken cancellationToken);
}

/// <summary>
/// The neighbour table of this machine: <c>ip neigh</c> (or <c>/proc/net/arp</c>) on Linux, <c>GetIpNetTable2</c> on
/// Windows. Contacting an address is a single UDP datagram to the discard port (9): the kernel looks up the MAC address
/// to send it, which needs no privileges and no ping. Nothing listens there, so nothing answers.
/// </summary>
public sealed class SystemNeighborTable : INeighborTable
{
    /// <summary>The smallest network prefix that is swept: a /22 is 1,022 addresses.</summary>
    public const int MinSweepPrefixLength = 22;

    private const int DiscardPort = 9;

    public async Task<IReadOnlyList<NeighborEntry>> ReadAsync(CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
        {
            return ReadWindows();
        }

        if (OperatingSystem.IsLinux())
        {
            return await ReadLinuxAsync(cancellationToken).ConfigureAwait(false);
        }

        return [];
    }

    public Task ProbeAsync(IEnumerable<IPAddress> addresses, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        foreach (var address in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Probe(address);
        }

        return Task.CompletedTask;
    }

    public async Task SweepAsync(CancellationToken cancellationToken)
    {
        foreach (var address in SweepAddresses(LocalNetworks()))
        {
            cancellationToken.ThrowIfCancellationRequested();
            Probe(address);
            await Task.Yield();
        }
    }

    /// <summary>The directly connected IPv4 networks of this machine: (own address, prefix length).</summary>
    private static IEnumerable<(IPAddress Address, int PrefixLength)> LocalNetworks() =>
        NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a.Address))
            .Select(a => (a.Address, a.PrefixLength));

    /// <summary>
    /// Every host address of the given networks, without the machine's own addresses. Networks larger than a /22 and
    /// link-local ones (169.254/16) are skipped: too many addresses to contact.
    /// </summary>
    public static IEnumerable<IPAddress> SweepAddresses(IEnumerable<(IPAddress Address, int PrefixLength)> networks)
    {
        ArgumentNullException.ThrowIfNull(networks);
        var list = networks.ToList();
        var own = list.Select(n => n.Address).ToHashSet();
        var seen = new HashSet<uint>();
        foreach (var (address, prefixLength) in list)
        {
            var bytes = address.GetAddressBytes();
            if (prefixLength is < MinSweepPrefixLength or > 30 || bytes[0] == 169 && bytes[1] == 254)
            {
                continue;
            }

            var value = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            var mask = uint.MaxValue << (32 - prefixLength);
            var network = value & mask;
            var broadcast = network | ~mask;
            for (var host = network + 1; host < broadcast; host++)
            {
                if (!seen.Add(host))
                {
                    continue;
                }

                var candidate = new IPAddress(BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(host) : host);
                if (!own.Contains(candidate))
                {
                    yield return candidate;
                }
            }
        }
    }

    private static void Probe(IPAddress address)
    {
        try
        {
            using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            socket.SendTo([0], new IPEndPoint(address, DiscardPort));
        }
        catch (SocketException)
        {
            // Unreachable network or similar: the table simply does not learn this address.
        }
    }

    private static async Task<IReadOnlyList<NeighborEntry>> ReadLinuxAsync(CancellationToken cancellationToken)
    {
        // "ip neigh" knows how fresh each entry is; /proc/net/arp (IPv4 only, no states) when ip is not available.
        try
        {
            var start = new ProcessStartInfo("ip") { ArgumentList = { "neigh", "show" }, RedirectStandardOutput = true, UseShellExecute = false };
            using var process = Process.Start(start);
            if (process is not null)
            {
                var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
                await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                if (process.ExitCode == 0)
                {
                    return ParseIpNeigh(output);
                }
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // ip is not installed.
        }

        try
        {
            return ParseProcNetArp(await File.ReadAllTextAsync("/proc/net/arp", cancellationToken).ConfigureAwait(false));
        }
        catch (IOException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
    }

    /// <summary>
    /// Parses <c>ip neigh show</c>: <c>192.168.1.20 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE</c>. Entries without
    /// a MAC address (INCOMPLETE, FAILED) are left out.
    /// </summary>
    public static IReadOnlyList<NeighborEntry> ParseIpNeigh(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var entries = new List<NeighborEntry>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var lladdr = Array.IndexOf(parts, "lladdr");
            if (parts.Length == 0 || lladdr < 0 || lladdr + 1 >= parts.Length
                || !IPAddress.TryParse(parts[0], out var address) || !MacAddress.TryNormalize(parts[lladdr + 1], out var mac))
            {
                continue;
            }

            var state = parts[^1] switch
            {
                "FAILED" or "INCOMPLETE" or "NOARP" => (NeighborState?)null,
                "REACHABLE" or "PERMANENT" => NeighborState.Reachable,
                "DELAY" or "PROBE" => NeighborState.Probing,
                _ => NeighborState.Stale,
            };
            if (state is { } known)
            {
                entries.Add(new NeighborEntry(address, mac, known));
            }
        }

        return entries;
    }

    /// <summary>
    /// Parses <c>/proc/net/arp</c> (IPv4): <c>IP address  HW type  Flags  HW address  Mask  Device</c>. Only complete
    /// entries (flag 0x2) count; the file says nothing about freshness, so they are <see cref="NeighborState.Stale"/>.
    /// </summary>
    public static IReadOnlyList<NeighborEntry> ParseProcNetArp(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        var entries = new List<NeighborEntry>();
        foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4 || !IPAddress.TryParse(parts[0], out var address)
                || !int.TryParse(parts[2].Replace("0x", string.Empty, StringComparison.Ordinal), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var flags)
                || (flags & 0x2) == 0 || !MacAddress.TryNormalize(parts[3], out var mac))
            {
                continue;
            }

            entries.Add(new NeighborEntry(address, mac, NeighborState.Stale));
        }

        return entries;
    }

    private static IReadOnlyList<NeighborEntry> ReadWindows()
    {
        if (GetIpNetTable2(AddressFamilyUnspecified, out var table) != 0)
        {
            return [];
        }

        try
        {
            // MIB_IPNET_TABLE2: NumEntries (4 bytes, padded to 8), then the rows.
            var count = Marshal.ReadInt32(table);
            var rows = new byte[checked(count * RowSize)];
            Marshal.Copy(table + RowsOffset, rows, 0, rows.Length);
            return ParseWindowsRows(rows, count);
        }
        finally
        {
            FreeMibTable(table);
        }
    }

    // MIB_IPNET_ROW2 (netioapi.h): SOCKADDR_INET Address (28) · InterfaceIndex (4) · InterfaceLuid (8) ·
    // PhysicalAddress[32] · PhysicalAddressLength (4) · State (4) · Flags (1, padded to 4) · ReachabilityTime (4) = 88.
    internal const int RowsOffset = 8, RowSize = 88;
    private const int PhysicalAddressOffset = 40, PhysicalAddressLengthOffset = 72, StateOffset = 76;

    /// <summary>Parses the rows of a <c>MIB_IPNET_TABLE2</c> (IPv4 and IPv6).</summary>
    internal static IReadOnlyList<NeighborEntry> ParseWindowsRows(ReadOnlySpan<byte> rows, int count)
    {
        var entries = new List<NeighborEntry>(count);
        for (var i = 0; i < count; i++)
        {
            var row = rows.Slice(i * RowSize, RowSize);
            IPAddress? address = BinaryPrimitives.ReadUInt16LittleEndian(row) switch
            {
                2 => new IPAddress(row.Slice(4, 4)), // AF_INET: sin_addr at 4
                23 => new IPAddress(row.Slice(8, 16), BinaryPrimitives.ReadUInt32LittleEndian(row[24..])), // AF_INET6: sin6_addr at 8, scope id at 24
                _ => null,
            };
            var length = BinaryPrimitives.ReadInt32LittleEndian(row[PhysicalAddressLengthOffset..]);
            var state = BinaryPrimitives.ReadInt32LittleEndian(row[StateOffset..]) switch
            {
                5 or 6 => NeighborState.Reachable, // NlnsReachable, NlnsPermanent
                2 or 3 => NeighborState.Probing,   // NlnsProbe, NlnsDelay
                4 => NeighborState.Stale,          // NlnsStale
                _ => (NeighborState?)null,         // NlnsUnreachable, NlnsIncomplete
            };
            if (address is null || state is null || length != 6 || IsGroupAddress(address)
                || MacAddress.FromBytes(row.Slice(PhysicalAddressOffset, 6)) is not { } mac)
            {
                continue;
            }

            entries.Add(new NeighborEntry(address, mac, state.Value));
        }

        return entries;
    }

    /// <summary>Multicast and broadcast addresses: Windows lists them with fixed MAC addresses, but they are never a device.</summary>
    private static bool IsGroupAddress(IPAddress address) =>
        address.IsIPv6Multicast
        || (address.AddressFamily == AddressFamily.InterNetwork && (address.GetAddressBytes()[0] >= 224 || address.Equals(IPAddress.Broadcast)));

    private const ushort AddressFamilyUnspecified = 0;

    // DllImport with blittable arguments (no marshalling code, no unsafe); only from System32 (CA5392).
#pragma warning disable SYSLIB1054 // LibraryImport would generate unsafe code, which this project does not allow.
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void FreeMibTable(IntPtr memory);
#pragma warning restore SYSLIB1054
}
