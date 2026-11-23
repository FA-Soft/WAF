using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Waf.Data;
using Waf.Web;

namespace Waf.IntegrationTests.Pipeline;

/// <summary>Lockout, brute-force protection, two-factor sign-in, the login history and session security.</summary>
public sealed partial class AdminSecurityTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<GatewayFixture> StartWithAccountAsync()
    {
        var gateway = new GatewayFixture();
        await gateway.InitializeAsync();
        using var creator = NewClient();
        await gateway.SignInAsync(creator);
        return gateway;
    }

    private static HttpClient NewClient(bool followRedirects = true) =>
        new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer(), AllowAutoRedirect = followRedirects })
        {
            Timeout = TimeSpan.FromSeconds(15),
        };

    private static Uri Admin(GatewayFixture gateway, string path) => new($"http://127.0.0.1:{gateway.AdminPort}{path}");

    /// <summary>Opens <paramref name="path"/> and posts its form <paramref name="handler"/>; returns where the browser ends up.</summary>
    private static async Task<(string Path, string Html)> PostFormAsync(
        HttpClient client, GatewayFixture gateway, string path, string handler, Dictionary<string, string> fields)
    {
        var page = await client.GetStringAsync(Admin(gateway, path), Ct);
        fields["__RequestVerificationToken"] = AntiforgeryPattern().Match(page).Groups["token"].Value;
        fields["_handler"] = handler;
        using var content = new FormUrlEncodedContent(fields);
        using var response = await client.PostAsync(Admin(gateway, path), content, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (response.RequestMessage!.RequestUri!.AbsolutePath, await response.Content.ReadAsStringAsync(Ct));
    }

    private static Task<(string Path, string Html)> LoginAsync(HttpClient client, GatewayFixture gateway, string password, string userName = GatewayFixture.AdminUserName, string? returnUrl = null)
    {
        var fields = new Dictionary<string, string> { ["Model.UserName"] = userName, ["Model.Password"] = password };
        if (returnUrl is not null)
        {
            fields["Model.ReturnUrl"] = returnUrl;
        }

        return PostFormAsync(client, gateway, "/account/login", "login", fields);
    }

    private static Task<(string Path, string Html)> CodeAsync(HttpClient client, GatewayFixture gateway, string code, string returnUrl = "/") =>
        PostFormAsync(client, gateway, $"/account/login/two-factor?returnUrl={Uri.EscapeDataString(returnUrl)}", "two-factor", new()
        {
            ["Model.Code"] = code,
            ["Model.ReturnUrl"] = returnUrl,
        });

    private static async Task<bool> IsSignedInAsync(HttpClient client, GatewayFixture gateway)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, Admin(gateway, "/routes"));
        request.Headers.Accept.ParseAdd("text/html");
        using var response = await client.SendAsync(request, Ct);
        return response.RequestMessage!.RequestUri!.AbsolutePath == "/routes";
    }

    private static async Task<List<SignInOutcome>> HistoryAsync(GatewayFixture gateway)
    {
        await using var scope = gateway.App.Services.CreateAsyncScope();
        return [.. (await scope.ServiceProvider.GetRequiredService<SignInHistory>().GetRecentAsync(100, Ct)).Select(e => e.Result).Reverse()];
    }

    /// <summary>Turns 2FA on for the signed-in <paramref name="client"/>; returns the key and the recovery codes.</summary>
    private static async Task<(string Key, List<string> RecoveryCodes)> EnableTwoFactorAsync(HttpClient client, GatewayFixture gateway)
    {
        var setup = await client.GetStringAsync(Admin(gateway, "/account/two-factor"), Ct);
        Assert.Contains("src=\"data:image/png;base64,", setup, StringComparison.Ordinal);
        var key = KeyPattern().Match(setup).Groups["key"].Value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

        var (_, wrong) = await PostFormAsync(client, gateway, "/account/two-factor", "enable-two-factor", new() { ["Enable.Code"] = WrongCode(key) });
        Assert.Contains("The code is not correct.", wrong, StringComparison.Ordinal);
        Assert.Contains("Signing in needs only your password.", wrong, StringComparison.Ordinal);

        var (_, enabled) = await PostFormAsync(client, gateway, "/account/two-factor", "enable-two-factor", new() { ["Enable.Code"] = Totp.Code(key) });
        Assert.Contains("Two-factor sign-in is on.", enabled, StringComparison.Ordinal);
        var codes = RecoveryCodePattern().Matches(enabled).Select(m => m.Groups["code"].Value).ToList();
        Assert.Equal(AdminIdentity.RecoveryCodeCount, codes.Count);
        return (key, codes);
    }

    /// <summary>A code that is wrong now (and in the adjacent time steps the server also accepts).</summary>
    private static string WrongCode(string key)
    {
        var valid = new[] { -1, 0, 1 }.Select(step => Totp.Code(key, DateTimeOffset.UtcNow.AddSeconds(30 * step))).ToHashSet();
        return Enumerable.Range(0, 10).Select(i => $"{i}{i}{i}{i}{i}{i}").First(code => !valid.Contains(code));
    }

    [Fact]
    public async Task Five_wrong_passwords_lock_the_account()
    {
        await using var gateway = await StartWithAccountAsync();
        using var browser = NewClient();

        for (var i = 1; i < AdminIdentity.MaxFailedAttempts; i++)
        {
            var (_, html) = await LoginAsync(browser, gateway, $"wrong password {i}");
            Assert.Contains("The user name or password is not correct.", html, StringComparison.Ordinal);
        }

        var (_, locked) = await LoginAsync(browser, gateway, "wrong password 5");
        Assert.Contains("this account is locked for another 15 minutes", locked, StringComparison.Ordinal);

        // Even the right password is refused now.
        var (path, refused) = await LoginAsync(browser, gateway, GatewayFixture.AdminPassword);
        Assert.Equal("/account/login", path);
        Assert.Contains("this account is locked", refused, StringComparison.Ordinal);
        Assert.False(await IsSignedInAsync(browser, gateway));

        Assert.Equal(
            [SignInOutcome.WrongPassword, SignInOutcome.WrongPassword, SignInOutcome.WrongPassword, SignInOutcome.WrongPassword, SignInOutcome.LockedOut, SignInOutcome.LockedOut],
            (await HistoryAsync(gateway)).Skip(1)); // after the sign-in that created the account

        // Once the lockout has passed, the right password works again.
        await using (var scope = gateway.App.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var user = (await users.FindByNameAsync(GatewayFixture.AdminUserName))!;
            Assert.True(await users.IsLockedOutAsync(user));
            await users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(-1));
        }

        Assert.Equal("/", (await LoginAsync(browser, gateway, GatewayFixture.AdminPassword)).Path);

        var history = await browser.GetStringAsync(Admin(gateway, "/account/history"), Ct);
        Assert.Contains("Refused: account locked", history, StringComparison.Ordinal);
        Assert.Contains("Wrong password", history, StringComparison.Ordinal);
        Assert.Contains("class=\"row-failed\"", history, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Many_failed_attempts_from_one_address_block_it_whatever_the_user_name()
    {
        await using var gateway = await StartWithAccountAsync();
        using var browser = NewClient();

        // Guessing user names: no account is locked, but the address is.
        for (var i = 0; i < SignInThrottle.MaxFailures; i++)
        {
            var (_, html) = await LoginAsync(browser, gateway, "secret123secret", userName: $"guess{i}");
            Assert.Contains("The user name or password is not correct.", html, StringComparison.Ordinal);
        }

        var (_, blocked) = await LoginAsync(browser, gateway, GatewayFixture.AdminPassword);
        Assert.Contains("Too many failed attempts from your address", blocked, StringComparison.Ordinal);
        Assert.False(await IsSignedInAsync(browser, gateway));

        var history = await HistoryAsync(gateway);
        Assert.Equal(SignInThrottle.MaxFailures, history.Count(r => r == SignInOutcome.UnknownUser));
        Assert.Equal(SignInOutcome.Throttled, history[^1]);

        // The names typed are not stored: one of them might have been a password.
        await using var scope = gateway.App.Services.CreateAsyncScope();
        var events = await scope.ServiceProvider.GetRequiredService<SignInHistory>().GetRecentAsync(100, Ct);
        Assert.All(events.Where(e => e.Result == SignInOutcome.UnknownUser), e => Assert.Null(e.UserName));
        Assert.DoesNotContain(events, e => e.UserName?.StartsWith("guess", StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task Two_factor_setup_and_sign_in_with_a_code()
    {
        await using var gateway = await StartWithAccountAsync();
        using var owner = NewClient();
        await gateway.SignInAsync(owner);
        Assert.Contains("Two-factor sign-in is off.", await owner.GetStringAsync(Admin(gateway, "/"), Ct), StringComparison.Ordinal);

        var (key, _) = await EnableTwoFactorAsync(owner, gateway);
        Assert.DoesNotContain("Two-factor sign-in is off.", await owner.GetStringAsync(Admin(gateway, "/"), Ct), StringComparison.Ordinal);

        // The password alone is not enough any more.
        using var browser = NewClient();
        var (path, _) = await LoginAsync(browser, gateway, GatewayFixture.AdminPassword, returnUrl: "/routes");
        Assert.Equal("/account/login/two-factor", path);
        Assert.False(await IsSignedInAsync(browser, gateway));

        var (_, wrong) = await CodeAsync(browser, gateway, WrongCode(key), "/routes");
        Assert.Contains("The code is not correct.", wrong, StringComparison.Ordinal);
        Assert.False(await IsSignedInAsync(browser, gateway));

        var (signedIn, _) = await CodeAsync(browser, gateway, Totp.Code(key), "/routes");
        Assert.Equal("/routes", signedIn);
        Assert.True(await IsSignedInAsync(browser, gateway));

        Assert.Equal(
            [SignInOutcome.TwoFactorRequired, SignInOutcome.TwoFactorFailed, SignInOutcome.Succeeded],
            (await HistoryAsync(gateway)).TakeLast(3));

        // A code without a password first gets nowhere.
        using var stranger = NewClient();
        var (strangerPath, _) = await CodeAsync(stranger, gateway, Totp.Code(key));
        Assert.Equal("/account/login", strangerPath);
        Assert.False(await IsSignedInAsync(stranger, gateway));
    }

    [Fact]
    public async Task Wrong_codes_lock_the_account_too()
    {
        await using var gateway = await StartWithAccountAsync();
        using var owner = NewClient();
        await gateway.SignInAsync(owner);
        var (key, _) = await EnableTwoFactorAsync(owner, gateway);

        using var browser = NewClient();
        await LoginAsync(browser, gateway, GatewayFixture.AdminPassword);
        for (var i = 0; i < AdminIdentity.MaxFailedAttempts; i++)
        {
            await CodeAsync(browser, gateway, WrongCode(key));
        }

        var (_, locked) = await CodeAsync(browser, gateway, Totp.Code(key));
        Assert.Contains("this account is locked", locked, StringComparison.Ordinal);
        Assert.False(await IsSignedInAsync(browser, gateway));
    }

    [Fact]
    public async Task A_recovery_code_works_once()
    {
        await using var gateway = await StartWithAccountAsync();
        using var owner = NewClient();
        await gateway.SignInAsync(owner);
        var (_, codes) = await EnableTwoFactorAsync(owner, gateway);

        using var browser = NewClient();
        await LoginAsync(browser, gateway, GatewayFixture.AdminPassword);
        var (path, _) = await PostFormAsync(browser, gateway, "/account/login/recovery?returnUrl=%2F", "recovery", new()
        {
            ["Model.Code"] = codes[0],
            ["Model.ReturnUrl"] = "/",
        });
        Assert.Equal("/", path);
        Assert.Contains($"{AdminIdentity.RecoveryCodeCount - 1} recovery codes left", await browser.GetStringAsync(Admin(gateway, "/account"), Ct), StringComparison.Ordinal);
        Assert.Equal(SignInOutcome.RecoveryCodeUsed, (await HistoryAsync(gateway))[^1]);

        using var again = NewClient();
        await LoginAsync(again, gateway, GatewayFixture.AdminPassword);
        var (_, refused) = await PostFormAsync(again, gateway, "/account/login/recovery?returnUrl=%2F", "recovery", new()
        {
            ["Model.Code"] = codes[0],
            ["Model.ReturnUrl"] = "/",
        });
        Assert.Contains("That recovery code is not correct, or was used before.", refused, StringComparison.Ordinal);
        Assert.False(await IsSignedInAsync(again, gateway));
    }

    [Fact]
    public async Task Turning_two_factor_off_needs_the_password()
    {
        await using var gateway = await StartWithAccountAsync();
        using var owner = NewClient();
        await gateway.SignInAsync(owner);
        await EnableTwoFactorAsync(owner, gateway);

        var (_, wrong) = await PostFormAsync(owner, gateway, "/account/two-factor", "disable-two-factor", new() { ["Disable.Password"] = "not the password" });
        Assert.Contains("The password is not correct.", wrong, StringComparison.Ordinal);
        Assert.Contains("Signing in needs your password and a code", wrong, StringComparison.Ordinal);

        var (path, off) = await PostFormAsync(owner, gateway, "/account/two-factor", "disable-two-factor", new() { ["Disable.Password"] = GatewayFixture.AdminPassword });
        Assert.Equal("/account", path);
        Assert.Contains("Two-factor sign-in is off.", off, StringComparison.Ordinal);
        Assert.True(await IsSignedInAsync(owner, gateway));

        using var browser = NewClient();
        Assert.Equal("/", (await LoginAsync(browser, gateway, GatewayFixture.AdminPassword)).Path);
    }

    [Fact]
    public async Task Sign_out_other_sessions_and_password_changes_end_other_sessions_at_once()
    {
        await using var gateway = await StartWithAccountAsync();
        using var mine = NewClient();
        using var other = NewClient();
        await gateway.SignInAsync(mine);
        await gateway.SignInAsync(other);

        var (_, ended) = await PostFormAsync(mine, gateway, "/account", "end-sessions", []);
        Assert.Contains("All other sessions were signed out.", ended, StringComparison.Ordinal);
        Assert.True(await IsSignedInAsync(mine, gateway));
        Assert.False(await IsSignedInAsync(other, gateway));
        Assert.Equal(SignInOutcome.SessionsEnded, (await HistoryAsync(gateway))[^1]);

        await gateway.SignInAsync(other);
        const string NewPassword = "a brand new long password";
        await PostFormAsync(mine, gateway, "/account", "change-password", new()
        {
            ["Model.CurrentPassword"] = GatewayFixture.AdminPassword,
            ["Model.NewPassword"] = NewPassword,
            ["Model.ConfirmPassword"] = NewPassword,
        });
        Assert.True(await IsSignedInAsync(mine, gateway));
        Assert.False(await IsSignedInAsync(other, gateway));
    }

    [Fact]
    public async Task Pages_renew_the_session_but_live_log_polling_does_not()
    {
        await using var gateway = await StartWithAccountAsync();
        using var browser = NewClient();
        await gateway.SignInAsync(browser);

        static bool RenewsCookie(HttpResponseMessage response) =>
            response.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(c => c.StartsWith(AdminIdentity.CookieName + "=", StringComparison.Ordinal));

        using (var page = await browser.GetAsync(Admin(gateway, "/routes"), Ct))
        {
            Assert.Equal(HttpStatusCode.OK, page.StatusCode);
            Assert.True(RenewsCookie(page));
            var cookie = page.Headers.GetValues("Set-Cookie").First(c => c.StartsWith(AdminIdentity.CookieName + "=", StringComparison.Ordinal));
            Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
        }

        using var live = await browser.GetAsync(Admin(gateway, "/logs/live?after=0"), Ct);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.False(RenewsCookie(live));
    }

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex AntiforgeryPattern();

    [GeneratedRegex("""<code class="authenticator-key">(?<key>[^<]+)</code>""")]
    private static partial Regex KeyPattern();

    [GeneratedRegex("""<li><code>(?<code>[^<]+)</code></li>""")]
    private static partial Regex RecoveryCodePattern();

    /// <summary>RFC 6238 time-based codes (SHA-1, 30 s, 6 digits), as an authenticator app computes them.</summary>
    private static class Totp
    {
        public static string Code(string base32Key, DateTimeOffset? at = null)
        {
            Span<byte> counter = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(counter, (at ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / 30);
#pragma warning disable CA5350 // TOTP is defined on HMAC-SHA1; this is what authenticator apps compute.
            var hash = HMACSHA1.HashData(Base32(base32Key), counter);
#pragma warning restore CA5350
            var offset = hash[^1] & 0x0f;
            var value = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
            return (value % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
        }

        private static byte[] Base32(string text)
        {
            const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bytes = new List<byte>();
            int buffer = 0, bits = 0;
            foreach (var c in text.TrimEnd('='))
            {
                buffer = (buffer << 5) | Alphabet.IndexOf(c, StringComparison.Ordinal);
                bits += 5;
                if (bits >= 8)
                {
                    bits -= 8;
                    bytes.Add((byte)(buffer >> bits));
                }
            }

            return [.. bytes];
        }
    }
}
