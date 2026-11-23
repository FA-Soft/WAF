using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>Where a sign-in attempt ended.</summary>
public enum SignInStep
{
    /// <summary>Signed in.</summary>
    SignedIn,

    /// <summary>The password was right; the 2FA code is next.</summary>
    NeedsTwoFactor,

    /// <summary>Wrong user name, password or code.</summary>
    Failed,

    /// <summary>The account is locked after too many failed attempts.</summary>
    LockedOut,

    /// <summary>Too many failed attempts from this address.</summary>
    Throttled,

    /// <summary>No password was entered first, or that was too long ago.</summary>
    NoPendingSignIn,
}

/// <summary>Outcome of a sign-in attempt, with how long a lock or block lasts.</summary>
public sealed record SignInAttempt(SignInStep Step, TimeSpan RetryAfter = default)
{
    /// <summary>The message for the sign-in page; null when signed in or the code is next.</summary>
    public string? Message => Step switch
    {
        SignInStep.Failed => null,
        SignInStep.LockedOut => $"Too many failed attempts: this account is locked for {Minutes(RetryAfter)}. Try again later.",
        SignInStep.Throttled => $"Too many failed attempts from your address: signing in is blocked for {Minutes(RetryAfter)}.",
        SignInStep.NoPendingSignIn => "Enter your user name and password first.",
        _ => null,
    };

    private static string Minutes(TimeSpan span)
    {
        var minutes = Math.Max(1, (int)Math.Ceiling(span.TotalMinutes));
        return minutes == 1 ? "another minute" : $"another {minutes} minutes";
    }
}

/// <summary>
/// Signing in to the admin UI with a password, then a 2FA code or recovery code: applies the per-address
/// throttle (<see cref="SignInThrottle"/>), account lockout and the login history in one place.
/// </summary>
public sealed class AdminSignIn(SignInManager<IdentityUser> signIn, SignInThrottle throttle, SignInHistory history, TimeProvider time)
{
    public async Task<SignInAttempt> PasswordAsync(HttpContext context, string userName, string password)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(userName);

        var ip = SignInHistory.ClientIp(context);
        var user = await signIn.UserManager.FindByNameAsync(userName.Trim()).ConfigureAwait(false);
        if (throttle.IsBlocked(ip, out var remaining))
        {
            await history.RecordAsync(context, SignInOutcome.Throttled, user).ConfigureAwait(false);
            return new SignInAttempt(SignInStep.Throttled, remaining);
        }

        if (user is null)
        {
            throttle.RecordFailure(ip);
            await history.RecordAsync(context, SignInOutcome.UnknownUser, null).ConfigureAwait(false);
            return new SignInAttempt(SignInStep.Failed);
        }

        var result = await signIn.PasswordSignInAsync(user, password, isPersistent: false, lockoutOnFailure: true).ConfigureAwait(false);
        return await RecordAsync(context, ip, user, result, SignInOutcome.Succeeded, SignInOutcome.WrongPassword).ConfigureAwait(false);
    }

    /// <summary>The second step: a code from the authenticator app, or (<paramref name="recovery"/>) a recovery code.</summary>
    public async Task<SignInAttempt> CodeAsync(HttpContext context, string code, bool recovery)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(code);

        var ip = SignInHistory.ClientIp(context);
        var user = await signIn.GetTwoFactorAuthenticationUserAsync().ConfigureAwait(false);
        if (user is null)
        {
            return new SignInAttempt(SignInStep.NoPendingSignIn);
        }

        if (throttle.IsBlocked(ip, out var remaining))
        {
            await history.RecordAsync(context, SignInOutcome.Throttled, user).ConfigureAwait(false);
            return new SignInAttempt(SignInStep.Throttled, remaining);
        }

        var result = recovery
            ? await signIn.TwoFactorRecoveryCodeSignInAsync(code.Replace(" ", string.Empty, StringComparison.Ordinal).Trim()).ConfigureAwait(false)
            : await signIn.TwoFactorAuthenticatorSignInAsync(NormalizeCode(code), isPersistent: false, rememberClient: false).ConfigureAwait(false);
        return await RecordAsync(context, ip, user, result,
            recovery ? SignInOutcome.RecoveryCodeUsed : SignInOutcome.Succeeded, SignInOutcome.TwoFactorFailed).ConfigureAwait(false);
    }

    /// <summary>"123 456" or "123-456" as typed or pasted → "123456".</summary>
    public static string NormalizeCode(string code) =>
        new([.. (code ?? string.Empty).Where(c => !char.IsWhiteSpace(c) && c != '-')]);

    private async Task<SignInAttempt> RecordAsync(
        HttpContext context, string ip, IdentityUser user, Microsoft.AspNetCore.Identity.SignInResult result, SignInOutcome success, SignInOutcome failure)
    {
        if (result.Succeeded)
        {
            throttle.RecordSuccess(ip);
            await history.RecordAsync(context, success, user).ConfigureAwait(false);
            return new SignInAttempt(SignInStep.SignedIn);
        }

        if (result.RequiresTwoFactor)
        {
            await history.RecordAsync(context, SignInOutcome.TwoFactorRequired, user).ConfigureAwait(false);
            return new SignInAttempt(SignInStep.NeedsTwoFactor);
        }

        throttle.RecordFailure(ip);
        if (result.IsLockedOut)
        {
            await history.RecordAsync(context, SignInOutcome.LockedOut, user).ConfigureAwait(false);
            var end = await signIn.UserManager.GetLockoutEndDateAsync(user).ConfigureAwait(false);
            return new SignInAttempt(SignInStep.LockedOut, end is { } until ? until - time.GetUtcNow() : AdminIdentity.LockoutDuration);
        }

        await history.RecordAsync(context, failure, user).ConfigureAwait(false);
        return new SignInAttempt(SignInStep.Failed);
    }
}
