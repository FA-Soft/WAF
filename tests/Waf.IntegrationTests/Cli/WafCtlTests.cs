using System.Net;
using System.Text.RegularExpressions;
using FASoft.Waf.Cli;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using FASoft.Waf.Host.Hosting;
using FASoft.Waf.IntegrationTests.Proxy;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.IntegrationTests.Cli;

/// <summary>
/// The recovery tool <c>wafctl</c>, run against the real data folder of a gateway: while it runs (changes are
/// picked up within seconds) and while it is stopped (changes are used at the next start).
/// </summary>
public sealed partial class WafCtlTests
{
    private const string NewPassword = "a completely new long password";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A gateway with one route to backend A and a rule that blocks /blocked, on a given data folder.</summary>
    private sealed class Gateway(string dataDirectory) : GatewayFixture
    {
        public BackendServer A { get; private set; } = null!;

        public HttpClient Public { get; } = new() { Timeout = TimeSpan.FromSeconds(10) };

        public ConfigurationStore Store => App.Services.GetRequiredService<ConfigurationStore>();

        public AuditLogStore AuditLog => App.Services.GetRequiredService<AuditLogStore>();

        protected override async ValueTask BeforeStartAsync() => A = await BackendServer.StartAsync("A");

        protected override IEnumerable<string> ExtraArgs =>
        [
            .. new RouteArgs().Add("website", [("http", A.Port)]).ToArray(),
            $"--Gateway:Storage:DataDirectory={dataDirectory}",
        ];

        protected override async ValueTask AfterStopAsync()
        {
            Public.Dispose();
            await A.DisposeAsync();
        }

        public async Task<HttpStatusCode> SendAsync(string path)
        {
            using var response = await Public.GetAsync(new Uri($"http://127.0.0.1:{HttpPort}{path}"), Ct);
            return response.StatusCode;
        }

        /// <summary>Adds a rule blocking /blocked through the gateway itself (version 2).</summary>
        public async Task AddBlockingRuleAsync()
        {
            var configuration = (await Store.GetLastKnownGoodAsync(Ct))!.Configuration;
            configuration.Rules.Add(new WafRule
            {
                Name = "block-path",
                Conditions = { new RuleCondition { Field = ConditionField.Path, Operator = ConditionOperator.StartsWith, Values = { "/blocked" } } },
            });
            var service = App.Services.GetRequiredService<GatewayConfigurationService>();
            Assert.True((await service.ActivateAsync(configuration, AuditActor.System("test"), "Block /blocked.", Ct)).Succeeded);
        }

        /// <summary>True when the running WAF engine is the one of the active (last-known-good) version.</summary>
        public async Task<bool> RunsActiveVersionAsync()
        {
            var head = await Store.GetLastKnownGoodHeadAsync(Ct);
            return App.Services.GetRequiredService<WafEngineHolder>().Current?.ConfigTag == ConfigurationStore.ConfigTag(head!.Value.Sha256);
        }

        public async Task WithUsersAsync(Func<UserManager<IdentityUser>, IdentityUser, Task> action)
        {
            await using var scope = App.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            await action(users, (await users.FindByNameAsync(AdminUserName))!);
        }
    }

    private sealed record Result(int ExitCode, string Output, string Error);

    private sealed class NoTerminal : ISecretReader
    {
        public string? Read(string prompt) => null;
    }

    private static async Task<Result> WafCtlWithInputAsync(string dataDirectory, string? stdin, params string[] args)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        using var input = new StringReader(stdin ?? string.Empty);
        var exit = await new WafCtl(output, error, input, new NoTerminal(), TimeProvider.System)
            .RunAsync(["--data-dir", dataDirectory, .. args], Ct);
        return new Result(exit, output.ToString(), error.ToString());
    }

    private static Task<Result> WafCtlAsync(string dataDirectory, params string[] args) => WafCtlWithInputAsync(dataDirectory, null, args);

    /// <summary>Runs <paramref name="test"/> with a started gateway (admin account created) on a fresh data folder.</summary>
    private static async Task WithGatewayAsync(Func<Gateway, string, Task> test)
    {
        var dataDirectory = GatewayFixture.NewDataDirectory();
        try
        {
            await using var gateway = new Gateway(dataDirectory);
            await gateway.InitializeAsync();
            using (var browser = NewBrowser())
            {
                await gateway.SignInAsync(browser); // creates the admin account
            }

            await test(gateway, dataDirectory);
        }
        finally
        {
            GatewayFixture.DeleteDataDirectory(dataDirectory);
        }
    }

    private static HttpClient NewBrowser() =>
        new(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() }) { Timeout = TimeSpan.FromSeconds(10) };

    /// <summary>Waits until a running gateway has applied the active version (the watcher checks every 2 seconds).</summary>
    private static async Task WaitUntilAppliedAsync(Gateway gateway)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!await gateway.RunsActiveVersionAsync())
        {
            Assert.True(DateTime.UtcNow < deadline, "The running gateway did not pick up the change made by wafctl.");
            await Task.Delay(100, Ct);
        }
    }

    /// <summary>
    /// Waits until requests to <paramref name="path"/> get <paramref name="expected"/>: the running gateway applied the
    /// change (engine and routes swap a moment apart, so a single request right after the engine swap may still be
    /// judged by the previous engine).
    /// </summary>
    private static async Task WaitForStatusAsync(Gateway gateway, string path, HttpStatusCode expected)
    {
        await WaitUntilAppliedAsync(gateway);
        var deadline = DateTime.UtcNow.AddSeconds(15);
        HttpStatusCode status;
        while ((status = await gateway.SendAsync(path)) != expected)
        {
            Assert.True(DateTime.UtcNow < deadline, $"{path}: still {status}, expected {expected}.");
            await Task.Delay(100, Ct);
        }
    }

    /// <summary>Signs in with the login form; true when it worked (no 2FA code asked).</summary>
    private static async Task<bool> LoginAsync(Gateway gateway, HttpClient browser, string password)
    {
        var login = new Uri($"http://127.0.0.1:{gateway.AdminPort}/account/login");
        var page = await browser.GetStringAsync(login, Ct);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = TokenPattern().Match(page).Groups["token"].Value,
            ["_handler"] = "login",
            ["Model.UserName"] = GatewayFixture.AdminUserName,
            ["Model.Password"] = password,
        });
        using var response = await browser.PostAsync(login, content, Ct);
        return (await response.Content.ReadAsStringAsync(Ct)).Contains("Sign out", StringComparison.Ordinal);
    }

    private static async Task<bool> IsSignedInAsync(Gateway gateway, HttpClient browser)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://127.0.0.1:{gateway.AdminPort}/routes"));
        request.Headers.Accept.ParseAdd("text/html"); // as a browser: a page, so a lost session redirects to sign-in
        using var response = await browser.SendAsync(request, Ct);
        return response.StatusCode == HttpStatusCode.OK && response.RequestMessage!.RequestUri!.AbsolutePath == "/routes";
    }

    [Fact]
    public async Task Rules_disable_all_takes_effect_in_a_running_gateway()
    {
        await WithGatewayAsync(async (gateway, data) =>
        {
            await gateway.AddBlockingRuleAsync();
            Assert.Equal(HttpStatusCode.Forbidden, await gateway.SendAsync("/blocked"));

            var result = await WafCtlAsync(data, "rules", "disable-all");

            Assert.Equal(WafCtl.Success, result.ExitCode);
            Assert.Contains("Disabled 1 rule(s): block-path.", result.Output, StringComparison.Ordinal);
            var active = (await gateway.Store.GetLastKnownGoodAsync(Ct))!;
            Assert.Equal(3, active.Version);
            Assert.All(active.Configuration.Rules, r => Assert.False(r.Enabled));
            Assert.EndsWith("(wafctl)", active.Author, StringComparison.Ordinal);
            var audit = Assert.Single((await gateway.AuditLog.GetForVersionsAsync([3], Ct)));
            Assert.Equal(("wafctl", AuditActions.ConfigSaved), (audit.Source, audit.Action));

            await WaitForStatusAsync(gateway, "/blocked", HttpStatusCode.OK);

            var again = await WafCtlAsync(data, "rules", "disable-all");
            Assert.Equal(WafCtl.Success, again.ExitCode);
            Assert.Contains("already disabled; nothing changed", again.Output, StringComparison.Ordinal);
            Assert.Equal(3, (await gateway.Store.GetLastKnownGoodAsync(Ct))!.Version);
        });
    }

    [Fact]
    public async Task Mode_detection_only_and_enforce_switch_blocking_off_and_on()
    {
        await WithGatewayAsync(async (gateway, data) =>
        {
            await gateway.AddBlockingRuleAsync();

            var off = await WafCtlAsync(data, "mode", "detection-only");
            Assert.Equal(WafCtl.Success, off.ExitCode);
            Assert.True((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Settings.DetectionOnly);
            await WaitForStatusAsync(gateway, "/blocked", HttpStatusCode.OK);

            var on = await WafCtlAsync(data, "mode", "enforce");
            Assert.Equal(WafCtl.Success, on.ExitCode);
            Assert.False((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Settings.DetectionOnly);
            await WaitForStatusAsync(gateway, "/blocked", HttpStatusCode.Forbidden);

            Assert.Contains("already enforced; nothing changed", (await WafCtlAsync(data, "mode", "enforce")).Output, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Config_restore_last_good_goes_back_to_the_previous_or_a_chosen_version()
    {
        await WithGatewayAsync(async (gateway, data) =>
        {
            var first = (await gateway.Store.GetLastKnownGoodAsync(Ct))!;
            await gateway.AddBlockingRuleAsync(); // version 2

            var restored = await WafCtlAsync(data, "config", "restore-last-good");

            Assert.Equal(WafCtl.Success, restored.ExitCode);
            Assert.Contains("Restored version 1", restored.Output, StringComparison.Ordinal);
            var active = (await gateway.Store.GetLastKnownGoodAsync(Ct))!;
            Assert.Equal((3L, first.Sha256), (active.Version, active.Sha256));
            Assert.Equal("Restored version 1 with wafctl (was version 2).", active.Comment);
            await WaitForStatusAsync(gateway, "/blocked", HttpStatusCode.OK);

            var chosen = await WafCtlAsync(data, "config", "restore-last-good", "--version", "2");
            Assert.Equal(WafCtl.Success, chosen.ExitCode);
            await WaitForStatusAsync(gateway, "/blocked", HttpStatusCode.Forbidden);

            var missing = await WafCtlAsync(data, "config", "restore-last-good", "--version", "99");
            Assert.Equal(WafCtl.Failed, missing.ExitCode);
            Assert.Contains("version 99 does not exist", missing.Error, StringComparison.Ordinal);

            var history = await WafCtlAsync(data, "config", "history");
            Assert.Equal(WafCtl.Success, history.ExitCode);
            Assert.Contains("*     4", history.Output, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Changes_made_while_the_gateway_is_stopped_are_used_at_the_next_start()
    {
        var dataDirectory = GatewayFixture.NewDataDirectory();
        try
        {
            await using (var first = new Gateway(dataDirectory))
            {
                await first.InitializeAsync();
                await first.AddBlockingRuleAsync();
            }

            var result = await WafCtlAsync(dataDirectory, "rules", "disable-all");
            Assert.Equal(WafCtl.Success, result.ExitCode);

            await using var second = new Gateway(dataDirectory);
            await second.InitializeAsync();
            Assert.Equal(3, (await second.Store.GetLastKnownGoodAsync(Ct))!.Version);
            Assert.True(await second.RunsActiveVersionAsync());
            Assert.NotEqual(HttpStatusCode.Forbidden, await second.SendAsync("/blocked"));
        }
        finally
        {
            GatewayFixture.DeleteDataDirectory(dataDirectory);
        }
    }

    [Fact]
    public async Task Admin_reset_password_unlocks_the_account_and_ends_all_sessions()
    {
        await WithGatewayAsync(async (gateway, data) =>
        {
            using var session = NewBrowser();
            Assert.True(await LoginAsync(gateway, session, GatewayFixture.AdminPassword));
            await gateway.WithUsersAsync((users, user) => users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(15)));

            var tooShort = await WafCtlWithInputAsync(data, "short\n","admin", "reset-password", "--password-stdin");
            Assert.Equal(WafCtl.Failed, tooShort.ExitCode);
            Assert.Contains("The password was not changed", tooShort.Error, StringComparison.Ordinal);
            Assert.True(await IsSignedInAsync(gateway, session));

            var noTerminal = await WafCtlAsync(data, "admin", "reset-password");
            Assert.Equal(WafCtl.Failed, noTerminal.ExitCode);
            Assert.Contains("--password-stdin", noTerminal.Error, StringComparison.Ordinal);

            var result = await WafCtlWithInputAsync(data, NewPassword + "\n","admin", "reset-password", "--password-stdin");

            Assert.Equal(WafCtl.Success, result.ExitCode);
            await gateway.WithUsersAsync(async (users, user) => Assert.False(await users.IsLockedOutAsync(user)));
            Assert.False(await IsSignedInAsync(gateway, session));
            using var browser = NewBrowser();
            Assert.False(await LoginAsync(gateway, browser, GatewayFixture.AdminPassword));
            Assert.True(await LoginAsync(gateway, browser, NewPassword));
            var security = await gateway.AuditLog.ReadPageAsync(new AuditFilter { Category = AuditCategory.Security }, null, null, 1, Ct);
            Assert.Equal((AuditActions.PasswordReset, "wafctl"), (security.Items[0].Action, security.Items[0].Source));
        });
    }

    [Fact]
    public async Task Admin_reset_2fa_turns_two_factor_sign_in_off()
    {
        await WithGatewayAsync(async (gateway, data) =>
        {
            await gateway.WithUsersAsync(async (users, user) =>
            {
                await users.ResetAuthenticatorKeyAsync(user);
                await users.SetTwoFactorEnabledAsync(user, true);
            });
            using (var browser = NewBrowser())
            {
                Assert.False(await LoginAsync(gateway, browser, GatewayFixture.AdminPassword)); // a 2FA code is asked
            }

            var result = await WafCtlAsync(data, "admin", "reset-2fa");

            Assert.Equal(WafCtl.Success, result.ExitCode);
            Assert.Contains("is off", result.Output, StringComparison.Ordinal);
            await gateway.WithUsersAsync(async (users, user) => Assert.False(await users.GetTwoFactorEnabledAsync(user)));
            using (var browser = NewBrowser())
            {
                Assert.True(await LoginAsync(gateway, browser, GatewayFixture.AdminPassword));
            }

            var security = await gateway.AuditLog.ReadPageAsync(new AuditFilter { Category = AuditCategory.Security }, null, null, 1, Ct);
            Assert.Equal(AuditActions.TwoFactorReset, security.Items[0].Action);
        });
    }

    [Fact]
    public async Task Admin_allow_ip_and_unregister_url_change_remote_admin_access()
    {
        await WithGatewayAsync(async (gateway, data) =>
        {
            var added = await WafCtlAsync(data, "admin", "allow-ip", "203.0.113.0/24");
            Assert.Equal(WafCtl.Success, added.ExitCode);
            Assert.Contains("203.0.113.0/24 added", added.Output, StringComparison.Ordinal);
            Assert.Contains("Remote admin access is off", added.Output, StringComparison.Ordinal);
            Assert.Contains("already on the remote admin allowlist", (await WafCtlAsync(data, "admin", "allow-ip", "203.0.113.0/24")).Output, StringComparison.Ordinal);
            Assert.Equal(WafCtl.Success, (await WafCtlAsync(data, "admin", "allow-ip", "2001:db8::1")).ExitCode);

            var invalid = await WafCtlAsync(data, "admin", "allow-ip", "10.0.0.5/8");
            Assert.Equal(WafCtl.Failed, invalid.ExitCode);
            Assert.Contains("not a valid address or range", invalid.Error, StringComparison.Ordinal);

            await using (var scope = gateway.App.Services.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
                var access = await new AdminAccessStore(db, TimeProvider.System).GetAsync(Ct);
                Assert.Equal(["203.0.113.0/24", "2001:db8::1/128"], access.AllowedNetworkList);

                // As step 30 will do: a registered remote admin URL.
                var row = await db.AdminAccessSettings.FindAsync([AdminAccess.SingletonId], Ct);
                row!.RemoteUrl = "https://admin.example.com";
                await db.SaveChangesAsync(Ct);
            }

            var unregistered = await WafCtlAsync(data, "admin", "unregister-url");
            Assert.Equal(WafCtl.Success, unregistered.ExitCode);
            Assert.Contains("https://admin.example.com was unregistered", unregistered.Output, StringComparison.Ordinal);
            Assert.Contains("already off", (await WafCtlAsync(data, "admin", "unregister-url")).Output, StringComparison.Ordinal);

            var status = await WafCtlAsync(data, "status");
            Assert.Equal(WafCtl.Success, status.ExitCode);
            Assert.Contains("Remote admin:    off", status.Output, StringComparison.Ordinal);
            Assert.Contains("203.0.113.0/24, 2001:db8::1/128", status.Output, StringComparison.Ordinal);
            Assert.Contains($"Admin account:   {GatewayFixture.AdminUserName} (two-factor sign-in off)", status.Output, StringComparison.Ordinal);

            var security = (await gateway.AuditLog.ReadPageAsync(new AuditFilter { Category = AuditCategory.Security }, null, null, 10, Ct)).Items;
            Assert.Equal(
                [AuditActions.AdminUrlUnregistered, AuditActions.AdminIpAllowed, AuditActions.AdminIpAllowed],
                security.Take(3).Select(e => e.Action));
        });
    }

    /// <summary>
    /// wafctl.dll in src/Waf.Cli/bin/&lt;configuration&gt;/&lt;framework&gt;: the copy next to the tests cannot run on its own,
    /// because the test folder takes some libraries from the ASP.NET Core framework, which wafctl does not use.
    /// </summary>
    private static string WafCtlProgram()
    {
        var output = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        var framework = output.Name;
        var configuration = output.Parent!.Name;
        var root = output;
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "WafGateway.sln")))
        {
            root = root.Parent;
        }

        return Path.Combine(root!.FullName, "src", "Waf.Cli", "bin", configuration, framework, "wafctl.dll");
    }

    [Fact]
    public async Task The_wafctl_program_runs_as_its_own_process()
    {
        await WithGatewayAsync(async (gateway, data) =>
        {
            // The real program from its own build output, as an administrator would run it, on this OS.
            var start = new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                ArgumentList = { WafCtlProgram(), "--data-dir", data, "mode", "detection-only" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = System.Diagnostics.Process.Start(start)!;
            var output = await process.StandardOutput.ReadToEndAsync(Ct);
            var errors = await process.StandardError.ReadToEndAsync(Ct);
            await process.WaitForExitAsync(Ct);

            Assert.True(process.ExitCode == WafCtl.Success, $"exit {process.ExitCode}: {output} {errors}");
            Assert.Contains("Detection-only mode is on", output, StringComparison.Ordinal);
            await WaitUntilAppliedAsync(gateway);
            Assert.True((await gateway.Store.GetLastKnownGoodAsync(Ct))!.Configuration.Settings.DetectionOnly);
        });
    }

    [Fact]
    public async Task Wrong_usage_and_a_missing_data_folder_are_reported()
    {
        var missing = GatewayFixture.NewDataDirectory();
        var noData = await WafCtlAsync(missing, "status");
        Assert.Equal(WafCtl.Failed, noData.ExitCode);
        Assert.Contains("No gateway data found", noData.Error, StringComparison.Ordinal);
        Assert.False(Directory.Exists(missing)); // nothing is created

        Assert.Equal(WafCtl.UsageError, (await WafCtlAsync(missing, "rules", "enable-all")).ExitCode);
        Assert.Equal(WafCtl.UsageError, (await WafCtlAsync(missing, "admin", "allow-ip")).ExitCode);
        Assert.Equal(WafCtl.UsageError, (await WafCtlAsync(missing, "status", "--bogus")).ExitCode);
        Assert.Equal(WafCtl.Success, (await WafCtlAsync(missing, "--help")).ExitCode);
    }

    [Fact]
    public async Task Without_an_account_database_admin_commands_refuse_and_create_nothing()
    {
        // Run as root, a new identity.db would belong to root and the service account could not write it.
        var data = GatewayFixture.NewDataDirectory();
        try
        {
            Directory.CreateDirectory(data);
            await File.WriteAllBytesAsync(Path.Combine(data, StoragePaths.ConfigDatabaseFileName), [], Ct);

            var reset = await WafCtlAsync(data, "admin", "reset-2fa");
            Assert.Equal(WafCtl.Failed, reset.ExitCode);
            Assert.Contains("no account database", reset.Error, StringComparison.Ordinal);
            Assert.Equal(WafCtl.Failed, (await WafCtlAsync(data, "admin", "allow-ip", "10.0.0.0/8")).ExitCode);

            var status = await WafCtlAsync(data, "status");
            Assert.Equal(WafCtl.Success, status.ExitCode);
            Assert.Contains("Configuration:   none activated yet", status.Output, StringComparison.Ordinal);
            Assert.Equal(WafCtl.Failed, (await WafCtlAsync(data, "rules", "disable-all")).ExitCode);

            Assert.False(File.Exists(Path.Combine(data, AdminIdentityDbContext.FileName)));
        }
        finally
        {
            GatewayFixture.DeleteDataDirectory(data);
        }
    }

    [GeneratedRegex("""name="__RequestVerificationToken" value="(?<token>[^"]+)""")]
    private static partial Regex TokenPattern();
}
