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

    /// <summary>
    /// For a certificate obtained from Let's Encrypt (or another ACME server): the host name it was ordered for;
    /// null for an uploaded certificate.
    /// </summary>
    public string? AcmeHostName { get; set; }

    /// <summary>For an ACME certificate: the directory URL of the server that issued it (production or staging).</summary>
    public string? AcmeDirectory { get; set; }

    /// <summary>True for a certificate obtained automatically (not uploaded).</summary>
    public bool IsAcme => AcmeHostName is not null;

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
    public Task<(StoredCertificate Stored, bool Added)> AddAsync(ServerCertificate certificate, string uploadedBy, CancellationToken cancellationToken) =>
        AddAsync(certificate, uploadedBy, null, null, cancellationToken);

    /// <summary>Stores a certificate obtained from an ACME server for <paramref name="hostName"/>.</summary>
    public Task<(StoredCertificate Stored, bool Added)> AddAcmeAsync(ServerCertificate certificate, string hostName, string directory, CancellationToken cancellationToken) =>
        AddAsync(certificate, "Let's Encrypt", hostName, directory, cancellationToken);

    /// <summary>
    /// The newest certificate obtained for <paramref name="hostName"/> from <paramref name="directory"/>, metadata only;
    /// null when there is none.
    /// </summary>
    public async Task<StoredCertificate?> FindAcmeAsync(string hostName, string directory, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(hostName);
        var host = hostName.ToLowerInvariant();
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var candidates = await db.StoredCertificates.AsNoTracking()
            .Where(c => c.AcmeHostName == host && c.AcmeDirectory == directory)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return candidates.OrderByDescending(c => c.NotAfterUtc).FirstOrDefault();
    }

    /// <summary>Deletes the other ACME certificates of <paramref name="hostName"/> once <paramref name="keep"/> replaced them.</summary>
    public async Task<int> DeleteOtherAcmeAsync(string hostName, string keep, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(hostName);
        var host = hostName.ToLowerInvariant();
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.StoredCertificates
            .Where(c => c.AcmeHostName == host && c.Thumbprint != keep)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<(StoredCertificate Stored, bool Added)> AddAsync(
        ServerCertificate certificate, string uploadedBy, string? acmeHostName, string? acmeDirectory, CancellationToken cancellationToken)
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
            AcmeHostName = acmeHostName?.ToLowerInvariant(),
            AcmeDirectory = acmeDirectory,
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

/// <summary>
/// The account at an ACME server (one per directory URL: production and staging are separate accounts). The account key
/// signs every request; it is stored encrypted like certificate keys.
/// </summary>
public sealed class AcmeAccount
{
    public string DirectoryUrl { get; set; } = string.Empty;

    /// <summary>The account URL the server returned ("kid").</summary>
    public string AccountUrl { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    /// <summary>The account's private key (PKCS#8), encrypted.</summary>
    public byte[] ProtectedKey { get; set; } = [];

    public DateTime CreatedAtUtc { get; set; }
}

/// <summary>Reads and stores ACME accounts in <c>config.db</c>.</summary>
public sealed class AcmeAccountStore(IDbContextFactory<ConfigDbContext> contexts, ICertificateProtector protector, TimeProvider time)
{
    public static AcmeAccountStore Create(StoragePaths paths, ICertificateProtector protector, TimeProvider time)
    {
        var options = new DbContextOptionsBuilder<ConfigDbContext>()
            .UseSqlite(DataServiceCollectionExtensions.ConnectionString(paths))
            .Options;
        return new AcmeAccountStore(new PooledDbContextFactory<ConfigDbContext>(options), protector, time);
    }

    /// <summary>The account for <paramref name="directoryUrl"/> with its decrypted key (PKCS#8); null when there is none.</summary>
    public async Task<(AcmeAccount Account, byte[] Key)?> GetAsync(string directoryUrl, CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var account = await db.AcmeAccounts.AsNoTracking().FirstOrDefaultAsync(a => a.DirectoryUrl == directoryUrl, cancellationToken).ConfigureAwait(false);
        return account is null ? null : (account, protector.Unprotect(account.ProtectedKey));
    }

    /// <summary>Stores (or replaces) the account for its directory URL.</summary>
    public async Task SaveAsync(string directoryUrl, string accountUrl, string email, byte[] pkcs8Key, CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        await db.AcmeAccounts.Where(a => a.DirectoryUrl == directoryUrl).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        db.AcmeAccounts.Add(new AcmeAccount
        {
            DirectoryUrl = directoryUrl,
            AccountUrl = accountUrl,
            Email = email,
            ProtectedKey = protector.Protect(pkcs8Key),
            CreatedAtUtc = time.GetUtcNow().UtcDateTime,
        });
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}
