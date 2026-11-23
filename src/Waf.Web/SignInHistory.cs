using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>Last successful sign-in before the current one, and the failed attempts since.</summary>
public sealed record SignInSummary(SignInEvent? PreviousSignIn, int FailedSince);

/// <summary>
/// The login history in <c>identity.db</c>: sign-ins, failed attempts, lockouts, sign-outs. Keeps the newest
/// <see cref="MaxEvents"/> entries of at most <see cref="MaxAge"/>. Sign-ins, sign-outs, lockouts and ended sessions
/// are also written to the audit log (kept forever); single failed attempts are not, so guessing cannot flood it.
/// </summary>
public sealed class SignInHistory(AdminIdentityDbContext db, AuditLogStore audit, TimeProvider time)
{
    public const int MaxEvents = 1000;
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(90);

    /// <summary>Results that are failed or refused attempts.</summary>
    public static readonly IReadOnlySet<SignInOutcome> Failures = new HashSet<SignInOutcome>
    {
        SignInOutcome.WrongPassword, SignInOutcome.UnknownUser, SignInOutcome.LockedOut, SignInOutcome.Throttled, SignInOutcome.TwoFactorFailed,
        SignInOutcome.RemoteNeedsTwoFactor,
    };

    public async Task RecordAsync(HttpContext context, SignInOutcome result, IdentityUser? user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var userAgent = context.Request.Headers.UserAgent.ToString();
        db.SignInEvents.Add(new SignInEvent
        {
            TimestampMs = time.GetUtcNow().ToUnixTimeMilliseconds(),
            UserId = user?.Id,
            UserName = user?.UserName,
            ClientIp = ClientIp(context),
            UserAgent = userAgent.Length == 0 ? null : userAgent[..Math.Min(userAgent.Length, SignInEvent.MaxUserAgentLength)],
            Result = result,
        });
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        if (AuditOf(result) is { } audited)
        {
            var name = user?.UserName;
            await audit.RecordAsync(
                audited.Category, audited.Action, AdminActor.From(context, name, AdminActor.AdminUi), audited.Summary, null, cancellationToken)
                .ConfigureAwait(false);
        }

        var cutoff = (time.GetUtcNow() - MaxAge).ToUnixTimeMilliseconds();
        var newest = await db.SignInEvents.MaxAsync(e => e.Id, cancellationToken).ConfigureAwait(false);
        await db.SignInEvents
            .Where(e => e.TimestampMs < cutoff || e.Id <= newest - MaxEvents)
            .ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
    }

    private static (AuditCategory Category, string Action, string Summary)? AuditOf(SignInOutcome result) => result switch
    {
        SignInOutcome.Succeeded => (AuditCategory.SignIn, AuditActions.SignedIn, "Signed in."),
        SignInOutcome.RecoveryCodeUsed => (AuditCategory.SignIn, AuditActions.SignedInWithRecoveryCode, "Signed in with a recovery code."),
        SignInOutcome.SignedOut => (AuditCategory.SignIn, AuditActions.SignedOut, "Signed out."),
        SignInOutcome.LockedOut => (AuditCategory.SignIn, AuditActions.LockedOut, "Account locked after too many failed sign-in attempts."),
        SignInOutcome.SessionsEnded => (AuditCategory.Security, AuditActions.SessionsEnded, "Signed out all other sessions."),
        _ => null,
    };

    /// <summary>The newest <paramref name="count"/> entries, newest first.</summary>
    public Task<List<SignInEvent>> GetRecentAsync(int count, CancellationToken cancellationToken = default) =>
        db.SignInEvents.AsNoTracking().OrderByDescending(e => e.Id).Take(count).ToListAsync(cancellationToken);

    /// <summary>
    /// For the account page: the sign-in before the current one, and how many attempts failed since then (for any
    /// account or user name: someone guessing names shows up here too).
    /// </summary>
    public async Task<SignInSummary> SummaryAsync(string userId, CancellationToken cancellationToken = default)
    {
        var signIns = await db.SignInEvents.AsNoTracking()
            .Where(e => e.UserId == userId && (e.Result == SignInOutcome.Succeeded || e.Result == SignInOutcome.RecoveryCodeUsed))
            .OrderByDescending(e => e.Id).Take(2).ToListAsync(cancellationToken).ConfigureAwait(false);
        var previous = signIns.Count > 1 ? signIns[1] : null;
        var since = previous?.Id ?? 0;
        var failures = Failures.ToList();
        var failed = await db.SignInEvents.CountAsync(e => e.Id > since && failures.Contains(e.Result), cancellationToken).ConfigureAwait(false);
        return new SignInSummary(previous, failed);
    }

    /// <summary>The address the request came from, as recorded and throttled.</summary>
    public static string ClientIp(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var address = context.Connection.RemoteIpAddress;
        if (address is null)
        {
            return "unknown";
        }

        return (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();
    }

    /// <summary>Plain-language description of a result.</summary>
    public static string Describe(SignInOutcome result) => result switch
    {
        SignInOutcome.Succeeded => "Signed in",
        SignInOutcome.WrongPassword => "Wrong password",
        SignInOutcome.UnknownUser => "Unknown user name",
        SignInOutcome.LockedOut => "Refused: account locked",
        SignInOutcome.Throttled => "Refused: too many attempts from this address",
        SignInOutcome.TwoFactorRequired => "Password correct, waiting for the 2FA code",
        SignInOutcome.TwoFactorFailed => "Wrong 2FA code",
        SignInOutcome.RecoveryCodeUsed => "Signed in with a recovery code",
        SignInOutcome.SignedOut => "Signed out",
        SignInOutcome.SessionsEnded => "Other sessions signed out",
        SignInOutcome.RemoteNeedsTwoFactor => "Refused: remote sign-in needs two-factor sign-in",
        _ => result.ToString(),
    };
}
