using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace FASoft.Waf.Data;

/// <summary>Where an AI proposal stands.</summary>
public enum AiProposalStatus
{
    /// <summary>Valid against the configuration it was made for; waiting for review.</summary>
    Ready,

    /// <summary>Failed the checks (format, allowed sections, schema or validation); can never be applied.</summary>
    Invalid,

    /// <summary>The model proposed no change and explained why.</summary>
    NoChange,

    /// <summary>Approved: stored and active as <see cref="AiProposal.AppliedVersion"/>.</summary>
    Applied,

    /// <summary>Applied and then undone: <see cref="AiProposal.UndoneVersion"/> restored the configuration before it.</summary>
    Undone,

    /// <summary>Not applied, by choice.</summary>
    Discarded,
}

/// <summary>
/// One request to the AI assistant and what came back (a row in <c>config.db</c>). Machine-local like the API key: not
/// part of configuration versions, exports or backups.
/// </summary>
public sealed class AiProposal
{
    public long Id { get; set; }

    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Who asked.</summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>What the administrator asked for.</summary>
    public string Prompt { get; set; } = string.Empty;

    /// <summary>The model's summary of the change, or why there is none.</summary>
    public string Summary { get; set; } = string.Empty;

    /// <summary>The proposed sections as JSON, exactly as the model returned them; null when it proposed none.</summary>
    public string? ProposalJson { get; set; }

    /// <summary>Why the proposal cannot be applied, one per line; null when it is valid.</summary>
    public string? Errors { get; set; }

    public AiProposalStatus Status { get; set; }

    /// <summary>The configuration version the proposal was made for.</summary>
    public long BaseVersion { get; set; }

    /// <summary>The version created by approving it.</summary>
    public long? AppliedVersion { get; set; }

    /// <summary>The version created by undoing it (a rollback to <see cref="BaseVersion"/>).</summary>
    public long? UndoneVersion { get; set; }

    /// <summary>Who approved, discarded or undid it last.</summary>
    public string? DecidedBy { get; set; }

    public DateTime? DecidedAtUtc { get; set; }

    public string Model { get; set; } = string.Empty;

    public long InputTokens { get; set; }

    public long OutputTokens { get; set; }

    /// <summary>The errors as a list.</summary>
    public IReadOnlyList<string> ErrorList => string.IsNullOrEmpty(Errors) ? [] : Errors.Split('\n');
}

/// <summary>Reads and writes <see cref="AiProposal"/> rows.</summary>
public sealed class AiProposalStore(IDbContextFactory<ConfigDbContext> contexts, TimeProvider time)
{
    public static AiProposalStore Create(StoragePaths paths, TimeProvider time)
    {
        var options = new DbContextOptionsBuilder<ConfigDbContext>()
            .UseSqlite(DataServiceCollectionExtensions.ConnectionString(paths))
            .Options;
        return new AiProposalStore(new PooledDbContextFactory<ConfigDbContext>(options), time);
    }

    /// <summary>Stores a new proposal (its <see cref="AiProposal.CreatedAtUtc"/> is set here); returns its id.</summary>
    public async Task<long> AddAsync(AiProposal proposal, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proposal);
        proposal.CreatedAtUtc = time.GetUtcNow().UtcDateTime;
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        db.AiProposals.Add(proposal);
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return proposal.Id;
    }

    public async Task<AiProposal?> GetAsync(long id, CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.AiProposals.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The newest proposals first.</summary>
    public async Task<IReadOnlyList<AiProposal>> ListRecentAsync(int count, CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        return await db.AiProposals.AsNoTracking().OrderByDescending(p => p.Id).Take(count).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Moves proposal <paramref name="id"/> from <paramref name="expected"/> to <paramref name="status"/>; false when it
    /// is not (or no longer) in <paramref name="expected"/>, so a decision is never made twice.
    /// </summary>
    public async Task<bool> DecideAsync(
        long id, AiProposalStatus expected, AiProposalStatus status, string decidedBy, long? appliedVersion, long? undoneVersion, CancellationToken cancellationToken)
    {
        await using var db = await contexts.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
        var now = time.GetUtcNow().UtcDateTime;
        return await db.AiProposals
            .Where(p => p.Id == id && p.Status == expected)
            .ExecuteUpdateAsync(
                set => set
                    .SetProperty(p => p.Status, status)
                    .SetProperty(p => p.DecidedBy, decidedBy)
                    .SetProperty(p => p.DecidedAtUtc, now)
                    .SetProperty(p => p.AppliedVersion, p => appliedVersion ?? p.AppliedVersion)
                    .SetProperty(p => p.UndoneVersion, p => undoneVersion ?? p.UndoneVersion),
                cancellationToken)
            .ConfigureAwait(false) == 1;
    }
}
