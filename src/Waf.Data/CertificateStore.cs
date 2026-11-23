using FASoft.Waf.Core.Tls;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace FASoft.Waf.Data;

/// <summary>
/// An uploaded certificate in <c>config.db</c>. The certificate, its chain and its private key are kept as a PFX that
/// is encrypted (<see cref="ICertificateProtector"/>); the other columns are plain metadata for lists and warnings.
/// Not part of configuration versions: bindings refer to it by <see cref="Thumbprint"/>.
/// </summary>
public sealed class StoredCertificate
{
    /// <summary>SHA-256 thumbprint, 64 upper-case hex digits.</summary>
    public string Thumbprint { get; set; } = string.Empty;

    public string Subject { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    /// <summary>The host names it is valid for, one per line.</summary>
    public string DnsNames { get; set; } = string.Empty;

    public DateTime NotBeforeUtc { get; set; }

    public DateTime NotAfterUtc { get; set; }

    /// <summary>The PFX (certificate, chain and private key), encrypted.</summary>
    public byte[] ProtectedPfx { get; set; } = [];

    public DateTime UploadedAtUtc { get; set; }

    public string UploadedBy { get; set; } = string.Empty;

    public IReadOnlyList<string> DnsNameList => DnsNames.Split('\n', StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>Encrypts certificate material at rest (implemented with ASP.NET Core Data Protection by the host).</summary>
public interface ICertificateProtector
{
    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] protectedData);
}

/// <summary>A certificate in a backup: the PFX without password (only in backups that include secrets).</summary>
public sealed record BackupCertificate(string Thumbprint, byte[] Pfx);

/// <summary>Uploaded certificates: stored encrypted, loaded for TLS, exported into backups that include secrets.</summary>
public sealed class CertificateStore(IDbContextFactory<ConfigDbContext> contexts, ICertificateProtector protector, TimeProvider time)
{
    /// <summary>Creates a store for <c>config.db</c> in <paramref name="paths"/> without dependency injection.</summary>
    public static CertificateStore Create(StoragePaths paths, ICertificateProtector protector, TimeProvider time)
    {
        var options = new DbContextOptionsBuilder<ConfigDbContext>()
            .UseSqlite(DataServiceCollectionExtensions.ConnectionString(paths))
            .Options;
        return new CertificateStore(new PooledDbContextFactory<ConfigDbContext>(options), protector, time);
    }

    /// <summary>Every stored certificate (metadata only), newest first.</summary>
    public async Task<IReadOnlyList<StoredCertificate>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var all = await db.StoredCertificates.AsNoTracking().ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. all.OrderByDescending(c => c.UploadedAtUtc)];
    }

    /// <summary>
    /// Stores <paramref name="certificate"/> (encrypted). Storing the same certificate again changes nothing.
    /// Returns its metadata and whether it was new.
    /// </summary>
    public async Task<(StoredCertificate Stored, bool Added)> AddAsync(ServerCertificate certificate, string uploadedBy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var thumbprint = certificate.Thumbprint;
        var existing = await db.StoredCertificates.AsNoTracking().FirstOrDefaultAsync(c => c.Thumbprint == thumbprint, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            return (existing, false);
        }

        var leaf = certificate.Leaf;
        var stored = new StoredCertificate
        {
            Thumbprint = thumbprint,
            Subject = leaf.Subject,
            Issuer = leaf.Issuer,
            DnsNames = string.Join('\n', certificate.DnsNames),
            NotBeforeUtc = leaf.NotBefore.ToUniversalTime(),
            NotAfterUtc = leaf.NotAfter.ToUniversalTime(),
            ProtectedPfx = protector.Protect(certificate.ExportPfx()),
            UploadedAtUtc = time.GetUtcNow().UtcDateTime,
            UploadedBy = uploadedBy,
        };
        db.StoredCertificates.Add(stored);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return (stored, true);
    }

    /// <summary>The certificate with its private key, ready for TLS; null when it is not stored.</summary>
    public async Task<ServerCertificate?> LoadAsync(string thumbprint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(thumbprint);
        var upper = thumbprint.ToUpperInvariant();
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var stored = await db.StoredCertificates.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Thumbprint == upper, cancellationToken).ConfigureAwait(false);
        return stored is null ? null : CertificateFiles.LoadPfx(protector.Unprotect(stored.ProtectedPfx));
    }

    /// <summary>Removes a stored certificate; false when it was not there.</summary>
    public async Task<bool> DeleteAsync(string thumbprint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(thumbprint);
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var upper = thumbprint.ToUpperInvariant();
        return await db.StoredCertificates.Where(c => c.Thumbprint == upper).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false) > 0;
    }

    /// <summary>Every certificate as a plain PFX, for a backup that includes secrets.</summary>
    public async Task<IReadOnlyList<BackupCertificate>> ExportAllAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var all = await db.StoredCertificates.AsNoTracking().OrderBy(c => c.UploadedAtUtc).ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. all.Select(c => new BackupCertificate(c.Thumbprint, protector.Unprotect(c.ProtectedPfx)))];
    }
}
