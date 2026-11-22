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

    /// <summary>Stores <paramref name="configuration"/> as a new version.</summary>
    /// <exception cref="ArgumentException">The configuration is not valid; nothing is stored.</exception>
    public async Task<StoredConfiguration> SaveAsync(GatewayConfiguration configuration, string author, string? comment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(author);

        var errors = GatewayConfigurationValidator.Validate(configuration);
        if (errors.Count > 0)
        {
            throw new ArgumentException("The configuration is not valid and was not stored: " + string.Join(" ", errors), nameof(configuration));
        }

        var json = Canonical(configuration);
        var entity = new ConfigurationVersion
        {
            CreatedAtUtc = time.GetUtcNow().UtcDateTime,
            Author = author,
            Comment = comment,
            SchemaVersion = configuration.SchemaVersion,
            Json = json,
            Sha256 = Hash(json),
        };

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        db.ConfigurationVersions.Add(entity);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return ToStored(entity);
    }

    /// <summary>
    /// Stores <paramref name="configuration"/> unless it is identical to the latest version; returns the
    /// version that now matches it.
    /// </summary>
    public async Task<(StoredConfiguration Stored, bool Created)> SaveIfChangedAsync(
        GatewayConfiguration configuration, string author, string? comment, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var latest = await GetLatestAsync(cancellationToken).ConfigureAwait(false);
        if (latest is not null && latest.Sha256 == Hash(Canonical(configuration)))
        {
            return (latest, false);
        }

        return (await SaveAsync(configuration, author, comment, cancellationToken).ConfigureAwait(false), true);
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
