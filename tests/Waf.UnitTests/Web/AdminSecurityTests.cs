using Microsoft.AspNetCore.Authentication;
using Waf.Web;

namespace Waf.UnitTests.Web;

public sealed class AdminSecurityTests
{
    private sealed class ManualTime(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static readonly DateTimeOffset Start = new(2026, 11, 23, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void An_address_is_blocked_after_ten_failures_within_fifteen_minutes()
    {
        var time = new ManualTime(Start);
        var throttle = new SignInThrottle(time);

        for (var i = 0; i < SignInThrottle.MaxFailures - 1; i++)
        {
            throttle.RecordFailure("203.0.113.9");
            time.Now += TimeSpan.FromSeconds(30);
        }

        Assert.False(throttle.IsBlocked("203.0.113.9", out _));
        throttle.RecordFailure("203.0.113.9");

        Assert.True(throttle.IsBlocked("203.0.113.9", out var remaining));
        Assert.Equal(SignInThrottle.BlockDuration, remaining);
        Assert.False(throttle.IsBlocked("198.51.100.1", out _)); // other addresses are not affected

        time.Now += SignInThrottle.BlockDuration;
        Assert.False(throttle.IsBlocked("203.0.113.9", out _));
    }

    [Fact]
    public void Failures_older_than_the_window_do_not_count()
    {
        var time = new ManualTime(Start);
        var throttle = new SignInThrottle(time);

        for (var i = 0; i < 30; i++)
        {
            throttle.RecordFailure("203.0.113.9");
            time.Now += TimeSpan.FromMinutes(2); // at most 8 within any 15 minutes
        }

        Assert.False(throttle.IsBlocked("203.0.113.9", out _));
    }

    [Fact]
    public void A_successful_sign_in_forgets_earlier_failures()
    {
        var throttle = new SignInThrottle(new ManualTime(Start));
        for (var i = 0; i < SignInThrottle.MaxFailures - 1; i++)
        {
            throttle.RecordFailure("127.0.0.1");
        }

        throttle.RecordSuccess("127.0.0.1");
        throttle.RecordFailure("127.0.0.1");

        Assert.False(throttle.IsBlocked("127.0.0.1", out _));
    }

    [Fact]
    public void Tracking_many_addresses_stays_bounded()
    {
        var time = new ManualTime(Start);
        var throttle = new SignInThrottle(time);

        for (var i = 0; i < SignInThrottle.MaxTrackedClients + 500; i++)
        {
            throttle.RecordFailure($"10.{i / 65536}.{i / 256 % 256}.{i % 256}");
        }

        Assert.True(throttle.TrackedClients <= SignInThrottle.MaxTrackedClients);
    }

    [Fact]
    public void A_session_ends_eight_hours_after_signing_in()
    {
        var properties = new AuthenticationProperties();
        Assert.True(AdminIdentity.IsSessionExpired(properties, Start)); // start unknown: not accepted

        properties.Items["waf.signedInAt"] = Start.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        Assert.False(AdminIdentity.IsSessionExpired(properties, Start.AddHours(7.9)));
        Assert.True(AdminIdentity.IsSessionExpired(properties, Start + AdminIdentity.MaxSessionLifetime));
        Assert.Equal(TimeSpan.FromMinutes(15), AdminIdentity.IdleTimeout);
    }

    [Theory]
    [InlineData("123456", "123456")]
    [InlineData("123 456", "123456")]
    [InlineData(" 123-456 ", "123456")]
    public void Codes_are_accepted_as_typed_or_pasted(string typed, string expected) =>
        Assert.Equal(expected, AdminSignIn.NormalizeCode(typed));

    [Fact]
    public void The_authenticator_key_and_link_are_shown_for_manual_entry()
    {
        Assert.Equal("abcd efgh ijkl mnop qr", Authenticator.FormatKey("ABCDEFGHIJKLMNOPQR"));

        var uri = Authenticator.SetupUri("frank admin", "ABCDEFGH");
        Assert.Equal("otpauth://totp/WAF%20Gateway:frank%20admin?secret=ABCDEFGH&issuer=WAF%20Gateway&digits=6", uri.AbsoluteUri);

        var qr = Authenticator.QrCodeDataUri(uri);
        Assert.StartsWith("data:image/png;base64,iVBORw0KGgo", qr, StringComparison.Ordinal); // PNG signature
    }

    [Fact]
    public void Lockout_and_block_messages_say_how_long()
    {
        Assert.Equal(
            "Too many failed attempts: this account is locked for another 15 minutes. Try again later.",
            new SignInAttempt(SignInStep.LockedOut, TimeSpan.FromMinutes(14.2)).Message);
        Assert.Equal(
            "Too many failed attempts from your address: signing in is blocked for another minute.",
            new SignInAttempt(SignInStep.Throttled, TimeSpan.FromSeconds(20)).Message);
        Assert.Null(new SignInAttempt(SignInStep.SignedIn).Message);
    }
}
