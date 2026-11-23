using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace FASoft.Waf.Data;

/// <summary>
/// The AI provider settings (one row in <c>config.db</c>): which provider, and its API key, encrypted. Machine-local
/// like certificate keys: never part of configuration versions, exports or backups. No row, or no key: the AI features
/// are off.
/// </summary>
public sealed class AiSettings
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;

    /// <summary>Provider name, e.g. "anthropic".</summary>
    public string Provider { get; set; } = string.Empty;

    /// <summary>The API key, encrypted (<see cref="IApiKeyProtector"/>).</summary>
    public byte[] ProtectedApiKey { get; set; } = [];

    /// <summary>The last four characters of the key, to recognize it; the key itself is never shown again.</summary>
    public string KeyHint { get; set; } = string.Empty;

    public DateTime UpdatedAtUtc { get; set; }

    public string UpdatedBy { get; set; } = string.Empty;
}

/// <summary>Encrypts API keys at rest (ASP.NET Core Data Protection, with a purpose of its own).</summary>
public interface IApiKeyProtector
{
    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] protectedData);
}

/// <summary>What is known about the configured AI provider, without the key.</summary>
/// <param name="Provider">Provider name.</param>
/// <param name="KeyHint">Last four characters of the key.</param>
/// <param name="UpdatedAtUtc">When the key was saved.</param>
/// <param name="UpdatedBy">Who saved it.</param>
public sealed record AiSettingsInfo(string Provider, string KeyHint, DateTime UpdatedAtUtc, string UpdatedBy);

/// <summary>Reads and writes <see cref="AiSettings"/>.</summary>
public sealed class AiSettingsStore(IDbContextFactory<ConfigDbContext> contexts, IApiKeyProtector protector, TimeProvider time)
{
    public static AiSettingsStore Create(StoragePaths paths, IApiKeyProtector protector, TimeProvider time)
    {
        var options = new DbContextOptionsBuilder<ConfigDbContext>()
            .UseSqlite(DataServiceCollectionExtensions.ConnectionString(paths))
            .Options;
        return new AiSettingsStore(new PooledDbContextFactory<ConfigDbContext>(options), protector, time);
    }

    /// <summary>The configured provider, without its key; null when none is configured (AI off).</summary>
    public async Task<AiSettingsInfo?> GetAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var settings = await db.AiSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == AiSettings.SingletonId, cancellationToken).ConfigureAwait(false);
        return settings is null ? null : new AiSettingsInfo(settings.Provider, settings.KeyHint, settings.UpdatedAtUtc, settings.UpdatedBy);
    }

    /// <summary>The provider and its decrypted API key; null when none is configured.</summary>
    public async Task<(string Provider, string ApiKey)?> GetKeyAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var settings = await db.AiSettings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == AiSettings.SingletonId, cancellationToken).ConfigureAwait(false);
        return settings is null ? null : (settings.Provider, System.Text.Encoding.UTF8.GetString(protector.Unprotect(settings.ProtectedApiKey)));
    }

    /// <summary>Stores <paramref name="apiKey"/> (encrypted) for <paramref name="provider"/>, replacing an earlier key.</summary>
    public async Task SaveAsync(string provider, string apiKey, string updatedBy, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentException.ThrowIfNullOrWhiteSpace(apiKey);

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var settings = await db.AiSettings.FirstOrDefaultAsync(s => s.Id == AiSettings.SingletonId, cancellationToken).ConfigureAwait(false);
        if (settings is null)
        {
            settings = new AiSettings();
            db.AiSettings.Add(settings);
        }

        settings.Provider = provider;
        settings.ProtectedApiKey = protector.Protect(System.Text.Encoding.UTF8.GetBytes(apiKey));
        settings.KeyHint = apiKey.Length > 8 ? apiKey[^4..] : string.Empty;
        settings.UpdatedAtUtc = time.GetUtcNow().UtcDateTime;
        settings.UpdatedBy = updatedBy;
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Removes the key: the AI features are off. False when none was configured.</summary>
    public async Task<bool> RemoveAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.AiSettings.Where(s => s.Id == AiSettings.SingletonId).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false) > 0;
    }
}
