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
