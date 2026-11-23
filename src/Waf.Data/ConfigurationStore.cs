using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Waf.Core.Configuration;

namespace Waf.Data;

/// <summary>A configuration version read from the database.</summary>
public sealed record StoredConfiguration(
    long Version, DateTime CreatedAtUtc, string Author, string? Comment, string Sha256, GatewayConfiguration Configuration);

/// <summary>The configuration database could not be created, opened or migrated.</summary>
public sealed class StorageInitializationException(string message, Exception innerException)
    : Exception(message, innerException);

/// <summary>
/// Reads and writes configuration versions in <c>config.db</c>. Only valid configurations are stored.
/// Thread-safe (a new <see cref="ConfigDbContext"/> per operation).
/// </summary>
public sealed class ConfigurationStore(IDbContextFactory<ConfigDbContext> contexts, TimeProvider time)
{
    /// <summary>Creates a store for <c>config.db</c> in <paramref name="paths"/> without dependency injection (startup).</summary>
    public static ConfigurationStore Create(StoragePaths paths, TimeProvider time)
    {
        var options = new DbContextOptionsBuilder<ConfigDbContext>()
            .UseSqlite(DataServiceCollectionExtensions.ConnectionString(paths))
            .Options;
        return new ConfigurationStore(new PooledDbContextFactory<ConfigDbContext>(options), time);
    }

    /// <summary>The last-known-good version (the last one activated successfully), or null if none yet.</summary>
    public async Task<StoredConfiguration?> GetLastKnownGoodAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var id = await db.ConfigurationState.AsNoTracking()
            .Where(s => s.Id == ConfigurationState.SingletonId)
            .Select(s => s.LastKnownGoodVersionId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return id is null ? null : await GetAsync(id.Value, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Records <paramref name="version"/> as the last-known-good (active) version.</summary>
    /// <exception cref="ArgumentException">The version does not exist.</exception>
    public async Task SetLastKnownGoodAsync(long version, CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        if (!await db.ConfigurationVersions.AnyAsync(v => v.Id == version, cancellationToken).ConfigureAwait(false))
        {
            throw new ArgumentException($"Configuration version {version} does not exist.", nameof(version));
        }

        var state = await db.ConfigurationState.FirstOrDefaultAsync(s => s.Id == ConfigurationState.SingletonId, cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            state = new ConfigurationState();
            db.ConfigurationState.Add(state);
        }

        state.LastKnownGoodVersionId = version;
        state.ActivatedAtUtc = time.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Fingerprint of the appsettings Gateway section last imported or dismissed; null if never recorded.</summary>
    public async Task<string?> GetAppSettingsFingerprintAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.ConfigurationState.AsNoTracking()
            .Where(s => s.Id == ConfigurationState.SingletonId)
            .Select(s => s.AppSettingsFingerprint)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Records the fingerprint of the appsettings Gateway section (after an import or dismissal).</summary>
    public async Task SetAppSettingsFingerprintAsync(string fingerprint, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(fingerprint);

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var state = await db.ConfigurationState.FirstOrDefaultAsync(s => s.Id == ConfigurationState.SingletonId, cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            state = new ConfigurationState();
            db.ConfigurationState.Add(state);
        }

        state.AppSettingsFingerprint = fingerprint;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The newest versions first (metadata and configuration), at most <paramref name="take"/>.</summary>
    public async Task<IReadOnlyList<StoredConfiguration>> GetHistoryAsync(int take, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(take, 1);

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var versions = await db.ConfigurationVersions.AsNoTracking()
            .OrderByDescending(v => v.Id)
            .Take(take)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. versions.Select(ToStored)];
    }
    /// <summary>
    /// Creates the database if needed, applies pending migrations and enables write-ahead logging
    /// (readers do not block the writer).
    /// </summary>
    /// <exception cref="StorageInitializationException">The database cannot be created or migrated.</exception>
    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
            await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            throw new StorageInitializationException($"The configuration database could not be opened or migrated: {ex.Message}", ex);
        }
    }

    /// <summary>The newest stored version, or null when nothing has been stored yet.</summary>
    public async Task<StoredConfiguration?> GetLatestAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var latest = await db.ConfigurationVersions.AsNoTracking()
            .OrderByDescending(v => v.Id)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return latest is null ? null : ToStored(latest);
    }

    /// <summary>A specific version, or null when it does not exist.</summary>
    public async Task<StoredConfiguration?> GetAsync(long version, CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var stored = await db.ConfigurationVersions.AsNoTracking()
            .FirstOrDefaultAsync(v => v.Id == version, cancellationToken)
            .ConfigureAwait(false);

        return stored is null ? null : ToStored(stored);
    }

    /// <summary>Number of stored versions.</summary>
    public async Task<int> CountAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.ConfigurationVersions.CountAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Stores <paramref name="configuration"/> as a new version, together with its audit entry (who stored it and
    /// what changed compared to the previous version), in one transaction.
    /// </summary>
    /// <exception cref="ArgumentException">The configuration is not valid; nothing is stored.</exception>
    public async Task<StoredConfiguration> SaveAsync(GatewayConfiguration configuration, AuditActor actor, string? comment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentException.ThrowIfNullOrWhiteSpace(actor.UserName);

        var errors = GatewayConfigurationValidator.Validate(configuration);
        if (errors.Count > 0)
        {
            throw new ArgumentException("The configuration is not valid and was not stored: " + string.Join(" ", errors), nameof(configuration));
        }

        var json = Canonical(configuration);
        var entity = new ConfigurationVersion
        {
            CreatedAtUtc = time.GetUtcNow().UtcDateTime,
            Author = actor.UserName,
            Comment = comment,
            SchemaVersion = configuration.SchemaVersion,
            Json = json,
            Sha256 = Hash(json),
        };

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var previousJson = await db.ConfigurationVersions.AsNoTracking()
            .OrderByDescending(v => v.Id)
            .Select(v => v.Json)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
        var previous = previousJson is null ? null : GatewayConfigurationJson.Parse(previousJson).Configuration;

        db.ConfigurationVersions.Add(entity);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        db.AuditEntries.Add(AuditLogStore.Create(
            time,
            AuditCategory.Configuration,
            AuditActions.ConfigSaved,
            actor,
            $"Version {entity.Id}: {(string.IsNullOrWhiteSpace(comment) ? "configuration changed." : comment)}",
            AuditLogStore.DescribeChanges(previous, configuration),
            entity.Id));
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return ToStored(entity);
    }

    /// <summary>
    /// Stores <paramref name="configuration"/> unless it is identical to the latest version; returns the
    /// version that now matches it.
    /// </summary>
    public async Task<(StoredConfiguration Stored, bool Created)> SaveIfChangedAsync(
        GatewayConfiguration configuration, AuditActor actor, string? comment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var latest = await GetLatestAsync(cancellationToken).ConfigureAwait(false);
        if (latest is not null && latest.Sha256 == Hash(Canonical(configuration)))
        {
            return (latest, false);
        }

        return (await SaveAsync(configuration, actor, comment, cancellationToken).ConfigureAwait(false), true);
    }

    /// <summary>Every stored version, oldest first.</summary>
    public async Task<IReadOnlyList<StoredConfiguration>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var versions = await db.ConfigurationVersions.AsNoTracking()
            .OrderBy(v => v.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return [.. versions.Select(ToStored)];
    }

    /// <summary>
    /// A full backup of every version. Without <paramref name="includeSecrets"/>, secret values are replaced by
    /// <see cref="ConfigurationSecrets.Placeholder"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">No configuration has been activated yet.</exception>
    public async Task<GatewayBackup> CreateBackupAsync(bool includeSecrets, CancellationToken cancellationToken)
    {
        var active = await GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("There is no active configuration to back up.");
        var versions = await GetAllAsync(cancellationToken).ConfigureAwait(false);

        return new GatewayBackup(
            time.GetUtcNow().UtcDateTime,
            Waf.Core.ProductInfo.Version,
            active.Version,
            includeSecrets,
            [.. versions.Select(v =>
            {
                // Every StoredConfiguration is freshly parsed, so redacting it changes nothing else.
                if (!includeSecrets)
                {
                    ConfigurationSecrets.Redact(v.Configuration);
                }

                return new BackupVersion(v.Version, v.CreatedAtUtc, v.Author, v.Comment, v.Configuration);
            })]);
    }

    /// <summary>
    /// Replaces every stored version with <paramref name="versions"/> (keeping their numbers) and makes
    /// <paramref name="activeVersion"/> the last-known-good, in one transaction: on any failure nothing changes.
    /// </summary>
    /// <remarks>The audit log is kept; restored versions without an entry get one recorded for <paramref name="restoredBy"/>.</remarks>
    /// <exception cref="ArgumentException">A configuration is not valid, or <paramref name="activeVersion"/> is not among them.</exception>
    public async Task ReplaceAllAsync(IReadOnlyList<BackupVersion> versions, long activeVersion, AuditActor restoredBy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(versions);

        if (versions.All(v => v.Version != activeVersion))
        {
            throw new ArgumentException($"Version {activeVersion} is not among the versions to store.", nameof(activeVersion));
        }

        foreach (var version in versions)
        {
            var errors = GatewayConfigurationValidator.Validate(version.Configuration);
            if (errors.Count > 0)
            {
                throw new ArgumentException($"Version {version.Version} is not valid: {string.Join(" ", errors)}", nameof(versions));
            }
        }

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var state = await db.ConfigurationState.FirstOrDefaultAsync(s => s.Id == ConfigurationState.SingletonId, cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            state = new ConfigurationState();
            db.ConfigurationState.Add(state);
        }

        // Versions that stay exactly the same keep their audit entry; the others get a new one below.
        var unchanged = await db.ConfigurationVersions.AsNoTracking()
            .Select(v => new { v.Id, v.Sha256 })
            .ToDictionaryAsync(v => v.Id, v => v.Sha256, cancellationToken)
            .ConfigureAwait(false);

        state.LastKnownGoodVersionId = null;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await db.ConfigurationVersions.ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);

        foreach (var version in versions.OrderBy(v => v.Version))
        {
            var json = Canonical(version.Configuration);
            db.ConfigurationVersions.Add(new ConfigurationVersion
            {
                Id = version.Version,
                CreatedAtUtc = version.CreatedAtUtc,
                Author = version.Author,
                Comment = version.Comment,
                SchemaVersion = version.Configuration.SchemaVersion,
                Json = json,
                Sha256 = Hash(json),
            });
        }

        // The audit log itself is kept. A restored version keeps the entry it already has only when it is the same
        // version as before (same number, same content); every other one gets an entry now, so every version links
        // to an audit entry that describes it.
        var restoredIds = versions.Select(v => v.Version).ToList();
        var audited = (await db.AuditEntries.AsNoTracking()
            .Where(e => e.ConfigurationVersionId != null && restoredIds.Contains(e.ConfigurationVersionId.Value))
            .Select(e => e.ConfigurationVersionId!.Value)
            .Distinct()
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false)).ToHashSet();
        foreach (var version in versions.OrderBy(v => v.Version))
        {
            if (audited.Contains(version.Version)
                && unchanged.TryGetValue(version.Version, out var hash)
                && hash == Hash(Canonical(version.Configuration)))
            {
                continue;
            }

            db.AuditEntries.Add(AuditLogStore.Create(
                time,
                AuditCategory.Configuration,
                AuditActions.ConfigRestored,
                restoredBy,
                $"Version {version.Version}: restored from a backup.",
                string.Create(CultureInfo.InvariantCulture, $"Originally stored by {version.Author} at {version.CreatedAtUtc:yyyy-MM-dd HH:mm:ss} UTC")
                    + (string.IsNullOrWhiteSpace(version.Comment) ? "." : $": {version.Comment}"),
                version.Version));
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        state.LastKnownGoodVersionId = activeVersion;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Writes a consistent copy of the whole database to <paramref name="path"/> (which must not exist yet).</summary>
    public async Task CopyDatabaseToAsync(string path, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        await db.Database.ExecuteSqlAsync($"VACUUM INTO {path}", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Canonical JSON: the editor-only <c>$schema</c> hint is not part of the stored configuration.</summary>
    private static string Canonical(GatewayConfiguration configuration)
    {
        var schema = configuration.Schema;
        try
        {
            configuration.Schema = null;
            return GatewayConfigurationJson.Serialize(configuration);
        }
        finally
        {
            configuration.Schema = schema;
        }
    }

    private static string Hash(string json) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(json)));

    /// <summary>SHA-256 (hex) of the canonical JSON of <paramref name="configuration"/>, as stored in <see cref="StoredConfiguration.Sha256"/>.</summary>
    public static string ComputeHash(GatewayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return Hash(Canonical(configuration));
    }

    /// <summary>
    /// Short tag identifying a configuration's content (first 16 hex digits of its hash); used to pair the
    /// WAF engine with the proxy routes of the same configuration.
    /// </summary>
    public static string ConfigTag(string sha256)
    {
        ArgumentException.ThrowIfNullOrEmpty(sha256);
        return sha256[..Math.Min(16, sha256.Length)];
    }

    private static StoredConfiguration ToStored(ConfigurationVersion version)
    {
        var parsed = GatewayConfigurationJson.Parse(version.Json);
        if (parsed.Configuration is null)
        {
            throw new InvalidDataException($"Configuration version {version.Id} cannot be read: {string.Join(" ", parsed.Errors)}");
        }

        return new StoredConfiguration(version.Id, version.CreatedAtUtc, version.Author, version.Comment, version.Sha256, parsed.Configuration);
    }
}
