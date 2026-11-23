using FASoft.Waf.Core.Net;
using Microsoft.EntityFrameworkCore;

namespace FASoft.Waf.Data;

/// <summary>Reads and changes the remote admin access settings (<see cref="AdminAccess"/>) in <c>identity.db</c>.</summary>
public sealed class AdminAccessStore(AdminIdentityDbContext db, TimeProvider time)
{
    /// <summary>The current settings; defaults (remote access off, no allowlist) when never set.</summary>
    public async Task<AdminAccess> GetAsync(CancellationToken cancellationToken = default) =>
        await db.AdminAccessSettings.AsNoTracking().FirstOrDefaultAsync(a => a.Id == AdminAccess.SingletonId, cancellationToken).ConfigureAwait(false)
            ?? new AdminAccess();

    /// <summary>
    /// Adds an address or CIDR range to the allowlist of remote admin access. Returns the range as stored and whether
    /// it was new (adding a range twice changes nothing).
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="cidr"/> is not a valid address or range.</exception>
    public async Task<(string Network, bool Added)> AllowNetworkAsync(string cidr, CancellationToken cancellationToken = default)
    {
        if (!StrictCidr.TryParse(cidr?.Trim(), out var network, out var error))
        {
            throw new ArgumentException($"'{cidr}' is not a valid address or range: {error}.", nameof(cidr));
        }

        var text = network.ToString();
        var access = await TrackedAsync(cancellationToken).ConfigureAwait(false);
        var entries = access.AllowedNetworkList.ToList();
        if (entries.Contains(text, StringComparer.OrdinalIgnoreCase))
        {
            return (text, false);
        }

        entries.Add(text);
        access.AllowedNetworks = string.Join('\n', entries);
        access.UpdatedAtUtc = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return (text, true);
    }

    /// <summary>Registers <paramref name="url"/> (already checked, see <see cref="RemoteAdminUrl.TryParse"/>): remote access is on.</summary>
    public async Task RegisterUrlAsync(RemoteAdminUrl url, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(url);
        var access = await TrackedAsync(cancellationToken).ConfigureAwait(false);
        access.RemoteUrl = url.ToString();
        access.UpdatedAtUtc = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Replaces the allowlist with <paramref name="entries"/> (addresses and CIDR ranges; empty: any address). Returns
    /// the normalized entries, or the reasons the list was refused (then nothing changes).
    /// </summary>
    public async Task<(IReadOnlyList<string> Entries, IReadOnlyList<string> Errors)> SetAllowedNetworksAsync(
        IEnumerable<string> entries, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var normalized = new List<string>();
        var errors = new List<string>();
        foreach (var entry in entries.Select(e => e.Trim()).Where(e => e.Length > 0))
        {
            if (StrictCidr.TryParse(entry, out var network, out var error))
            {
                if (!normalized.Contains(network.ToString(), StringComparer.OrdinalIgnoreCase))
                {
                    normalized.Add(network.ToString());
                }
            }
            else
            {
                errors.Add($"'{entry}': {error}.");
            }
        }

        if (errors.Count > 0)
        {
            return ([], errors);
        }

        var access = await TrackedAsync(cancellationToken).ConfigureAwait(false);
        access.AllowedNetworks = string.Join('\n', normalized);
        access.UpdatedAtUtc = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return (normalized, []);
    }

    /// <summary>
    /// Reads the settings without dependency injection (at startup, to open a dedicated port). Null when identity.db
    /// does not exist or cannot be read yet.
    /// </summary>
    public static AdminAccess? ReadAtStartup(StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (!File.Exists(Path.Combine(paths.DataDirectory, AdminIdentityDbContext.FileName)))
        {
            return null;
        }

        try
        {
            var options = new DbContextOptionsBuilder<AdminIdentityDbContext>().UseSqlite(AdminIdentityDbContext.ConnectionString(paths)).Options;
            using var db = new AdminIdentityDbContext(options);
            return db.AdminAccessSettings.AsNoTracking().FirstOrDefault(a => a.Id == AdminAccess.SingletonId);
        }
        catch (Microsoft.Data.Sqlite.SqliteException)
        {
            return null; // e.g. a database from before remote access existed; migrated later at startup
        }
    }

    /// <summary>Turns remote admin access off. Returns the URL that was registered; null when none was.</summary>
    public async Task<string?> UnregisterUrlAsync(CancellationToken cancellationToken = default)
    {
        var access = await TrackedAsync(cancellationToken).ConfigureAwait(false);
        var previous = access.RemoteUrl;
        if (previous is null)
        {
            return null;
        }

        access.RemoteUrl = null;
        access.UpdatedAtUtc = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return previous;
    }

    private async Task<AdminAccess> TrackedAsync(CancellationToken cancellationToken)
    {
        var access = await db.AdminAccessSettings.FirstOrDefaultAsync(a => a.Id == AdminAccess.SingletonId, cancellationToken).ConfigureAwait(false);
        if (access is null)
        {
            access = new AdminAccess();
            db.AdminAccessSettings.Add(access);
        }

        return access;
    }
}

/// <summary>
/// A remote admin URL: <c>https://</c>, a host name (not an IP address), optionally a port, nothing else.
/// </summary>
public sealed record RemoteAdminUrl(string Host, int? Port)
{
    /// <summary>The URL as registered, e.g. <c>https://admin.example.com</c> or <c>https://admin.example.com:8443</c>.</summary>
    public override string ToString() => Port is { } port
        ? string.Create(System.Globalization.CultureInfo.InvariantCulture, $"https://{Host}:{port}")
        : $"https://{Host}";

    /// <summary>Parses and checks a URL typed by the administrator (or stored earlier).</summary>
    public static bool TryParse(string? text, out RemoteAdminUrl? url, out string error)
    {
        url = null;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(text) || !Uri.TryCreate(text.Trim(), UriKind.Absolute, out var uri))
        {
            error = "Enter a full address, e.g. https://admin.example.com.";
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            error = "Remote admin access is HTTPS only: the address must start with https://.";
            return false;
        }

        if (uri.HostNameType != UriHostNameType.Dns || !uri.Host.Contains('.', StringComparison.Ordinal))
        {
            error = "Use a host name such as admin.example.com (not an IP address): it needs a certificate.";
            return false;
        }

        if (uri.AbsolutePath != "/" || uri.Query.Length > 0 || uri.Fragment.Length > 0 || uri.UserInfo.Length > 0)
        {
            error = "Only the host name and optionally a port, without a path, e.g. https://admin.example.com:8443.";
            return false;
        }

        url = new RemoteAdminUrl(uri.IdnHost.ToLowerInvariant(), uri.IsDefaultPort ? null : uri.Port);
        return true;
    }
}
