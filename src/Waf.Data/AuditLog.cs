using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Waf.Core.Configuration;

namespace Waf.Data;

/// <summary>What an audit entry is about.</summary>
public enum AuditCategory
{
    /// <summary>A configuration change: every configuration version has one.</summary>
    Configuration,

    /// <summary>Signing in and out of the admin UI.</summary>
    SignIn,

    /// <summary>Account and security settings: password, two-factor authentication, sessions.</summary>
    Security,

    /// <summary>Backups, downloads and log cleanup.</summary>
    Maintenance,
}

/// <summary>
/// One entry of the audit log in <c>config.db</c>: who did what, and when. Entries are never changed or deleted.
/// </summary>
public sealed class AuditEntry
{
    public const int MaxUserNameLength = 256;
    public const int MaxClientIpLength = 64;
    public const int MaxSourceLength = 100;
    public const int MaxActionLength = 64;
    public const int MaxSummaryLength = 500;
    public const int MaxDetailsLength = 4000;

    public long Id { get; set; }

    /// <summary>When it happened (UTC).</summary>
    public DateTime TimestampUtc { get; set; }

    public AuditCategory Category { get; set; }

    /// <summary>Short code, e.g. <c>config.saved</c> or <c>password.changed</c> (see <see cref="AuditActions"/>).</summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>Who did it: the admin's user name, or the system part that did it (e.g. "appsettings import").</summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>Address of the browser, when it was done in the admin UI.</summary>
    public string? ClientIp { get; set; }

    /// <summary>Where it was done, e.g. "admin UI" or "startup".</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>One line describing it.</summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>More detail, e.g. which routes and rules a configuration change touched.</summary>
    public string? Details { get; set; }

    /// <summary>The configuration version it created or restored, if any.</summary>
    public long? ConfigurationVersionId { get; set; }
}

/// <summary>The action codes in the audit log.</summary>
public static class AuditActions
{
    public const string ConfigSaved = "config.saved";
    public const string ConfigRestored = "config.restored";
    public const string ConfigBackfilled = "config.recorded";
    public const string BackupRestored = "backup.restored";
    public const string BackupDownloaded = "backup.downloaded";
    public const string ConfigDownloaded = "config.downloaded";
    public const string AppSettingsDismissed = "appsettings.dismissed";
    public const string LogsCleaned = "logs.cleaned";
    public const string SignedIn = "signin.succeeded";
    public const string SignedInWithRecoveryCode = "signin.recovery-code";
    public const string SignedOut = "signin.signed-out";
    public const string LockedOut = "signin.locked-out";
    public const string SessionsEnded = "sessions.ended";
    public const string AdminCreated = "admin.created";
    public const string PasswordChanged = "password.changed";
    public const string TwoFactorEnabled = "2fa.enabled";
    public const string TwoFactorDisabled = "2fa.disabled";
    public const string RecoveryCodesGenerated = "2fa.recovery-codes";
}

/// <summary>Who did something, for the audit log.</summary>
/// <param name="UserName">The admin's user name, or the system part that did it.</param>
/// <param name="ClientIp">Address of the browser; null when not done over HTTP.</param>
/// <param name="Source">Where it was done, e.g. "admin UI".</param>
public sealed record AuditActor(string UserName, string? ClientIp, string Source)
{
    /// <summary>Something the gateway did by itself, e.g. the appsettings import at the first start.</summary>
    public static AuditActor System(string name) => new(name, null, "system");
}

/// <summary>Which audit entries to show.</summary>
public sealed record AuditFilter
{
    public AuditCategory? Category { get; init; }

    /// <summary>Exact user name (case-insensitive).</summary>
    public string? UserName { get; init; }

    /// <summary>Only the entries of this configuration version.</summary>
    public long? Version { get; init; }
}

/// <summary>One page of the audit log, newest first.</summary>
public sealed record AuditPage(IReadOnlyList<AuditEntry> Items, bool HasOlder, bool HasNewer);

/// <summary>
/// Reads and writes the audit log in <c>config.db</c>. Configuration versions get their entry from
/// <see cref="ConfigurationStore"/>, in the same transaction; everything else is recorded here.
/// Thread-safe (a new context per operation).
/// </summary>
public sealed class AuditLogStore(IDbContextFactory<ConfigDbContext> contexts, TimeProvider time)
{
    /// <summary>Largest page size.</summary>
    public const int MaxPageSize = 200;

    /// <summary>Creates a store for <c>config.db</c> in <paramref name="paths"/> without dependency injection (startup).</summary>
    public static AuditLogStore Create(StoragePaths paths, TimeProvider time)
    {
        var options = new DbContextOptionsBuilder<ConfigDbContext>()
            .UseSqlite(DataServiceCollectionExtensions.ConnectionString(paths))
            .Options;
        return new AuditLogStore(new PooledDbContextFactory<ConfigDbContext>(options), time);
    }

    public async Task<AuditEntry> RecordAsync(
        AuditCategory category, string action, AuditActor actor, string summary, string? details = null, CancellationToken cancellationToken = default)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var entry = Create(time, category, action, actor, summary, details, null);
        db.AuditEntries.Add(entry);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return entry;
    }

    /// <summary>A page of entries matching <paramref name="filter"/>: the newest, or those before / after an id.</summary>
    public async Task<AuditPage> ReadPageAsync(AuditFilter filter, long? before, long? after, int size, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filter);
        size = Math.Clamp(size, 1, MaxPageSize);

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var query = Filtered(db, filter);

        if (after is not null)
        {
            var rows = await query.Where(e => e.Id > after).OrderBy(e => e.Id).Take(size + 1).ToListAsync(cancellationToken).ConfigureAwait(false);
            var hasOlder = await query.AnyAsync(e => e.Id <= after, cancellationToken).ConfigureAwait(false);
            return new AuditPage([.. rows.Take(size).Reverse()], hasOlder, rows.Count > size);
        }

        var older = before is null ? query : query.Where(e => e.Id < before);
        var page = await older.OrderByDescending(e => e.Id).Take(size + 1).ToListAsync(cancellationToken).ConfigureAwait(false);
        var hasNewer = before is not null && await query.AnyAsync(e => e.Id >= before, cancellationToken).ConfigureAwait(false);
        return new AuditPage([.. page.Take(size)], page.Count > size, hasNewer);
    }

    /// <summary>The entries of configuration versions, oldest first.</summary>
    public async Task<IReadOnlyList<AuditEntry>> GetForVersionsAsync(IEnumerable<long> versions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(versions);
        var ids = versions.Distinct().ToList();
        if (ids.Count == 0)
        {
            return [];
        }

        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.AuditEntries.AsNoTracking()
            .Where(e => e.ConfigurationVersionId != null && ids.Contains(e.ConfigurationVersionId.Value))
            .OrderBy(e => e.Id)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The user names in the log, for the filter.</summary>
    public async Task<IReadOnlyList<string>> GetUserNamesAsync(CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.AuditEntries.AsNoTracking().Select(e => e.UserName).Distinct().OrderBy(n => n).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    private static IQueryable<AuditEntry> Filtered(ConfigDbContext db, AuditFilter filter)
    {
        var query = db.AuditEntries.AsNoTracking();
        if (filter.Category is { } category)
        {
            query = query.Where(e => e.Category == category);
        }

        if (filter.UserName is { Length: > 0 } user)
        {
            query = query.Where(e => EF.Functions.Collate(e.UserName, "NOCASE") == user);
        }

        if (filter.Version is { } version)
        {
            query = query.Where(e => e.ConfigurationVersionId == version);
        }

        return query;
    }

    internal static AuditEntry Create(
        TimeProvider time, AuditCategory category, string action, AuditActor actor, string summary, string? details, long? version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentNullException.ThrowIfNull(actor);
        ArgumentException.ThrowIfNullOrWhiteSpace(summary);

        return new AuditEntry
        {
            TimestampUtc = time.GetUtcNow().UtcDateTime,
            Category = category,
            Action = Cut(action, AuditEntry.MaxActionLength)!,
            UserName = Cut(string.IsNullOrWhiteSpace(actor.UserName) ? "unknown" : actor.UserName, AuditEntry.MaxUserNameLength)!,
            ClientIp = Cut(actor.ClientIp, AuditEntry.MaxClientIpLength),
            Source = Cut(actor.Source, AuditEntry.MaxSourceLength) ?? string.Empty,
            Summary = Cut(summary, AuditEntry.MaxSummaryLength)!,
            Details = Cut(details, AuditEntry.MaxDetailsLength),
            ConfigurationVersionId = version,
        };
    }

    /// <summary>The changes from <paramref name="before"/> to <paramref name="after"/>, one per line, for <see cref="AuditEntry.Details"/>.</summary>
    public static string DescribeChanges(GatewayConfiguration? before, GatewayConfiguration after)
    {
        ArgumentNullException.ThrowIfNull(after);

        if (before is null)
        {
            return $"First configuration: {after.Routes.Count} route(s), {after.Rules.Count} rule(s), {after.RateLimits.Count} rate limit(s).";
        }

        var changes = ConfigurationDiff.Compare(before, after);
        if (changes.Count == 0)
        {
            return "Same content as the previous version.";
        }

        var text = new StringBuilder();
        foreach (var change in changes)
        {
            var section = change.Section switch
            {
                ConfigurationSection.Settings => "Setting",
                ConfigurationSection.RateLimit => "Rate limit",
                _ => change.Section.ToString(),
            };
            var kind = change.Kind.ToString().ToLowerInvariant();
            text.Append(section).Append(" '").Append(change.Name).Append("' ").Append(kind).Append('\n');
        }

        return text.ToString().TrimEnd();
    }

    private static string? Cut(string? value, int max)
    {
        if (value is null)
        {
            return null;
        }

        return value.Length <= max ? value : value[..(max - 1)] + "…";
    }
}
