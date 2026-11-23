using System.Globalization;
using System.Text;
using FASoft.Waf.Core;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.Cli;

/// <summary>Reads a secret (a password) without showing it.</summary>
internal interface ISecretReader
{
    /// <summary>Asks for a secret; null when there is no terminal to ask on.</summary>
    string? Read(string prompt);
}

/// <summary>
/// <c>wafctl</c>: local recovery for when the admin UI cannot help, because the service is down or you are locked
/// out. It works directly on the data folder (<c>config.db</c>, <c>identity.db</c>), so it needs only local file
/// access: run it as Administrator (Windows) or with sudo / as the service account (Linux). Configuration changes are
/// stored as new, checked versions, exactly as from the admin UI; a running gateway applies them within seconds.
/// Everything it changes is recorded in the audit log.
/// </summary>
internal sealed class WafCtl(TextWriter output, TextWriter error, TextReader input, ISecretReader secrets, TimeProvider time)
{
    public const int Success = 0;
    public const int Failed = 1;
    public const int UsageError = 2;

    public const string Usage = """
        Usage: wafctl [--data-dir <path>] <command>

        Configuration (stored as a new version; a running gateway applies it within seconds):
          rules disable-all                 Disable every rule.
          mode detection-only               Log instead of block (rules, rate limits and attack detection).
          mode enforce                      Block again.
          config restore-last-good          Activate the version that was active before the current one.
          config restore-last-good --version <n>
                                            Activate version <n> again.
          config history                    List the newest configuration versions.

        Admin account and access:
          admin reset-password [--user <name>] [--password-stdin]
                                            Set a new password, unlock the account and end all sessions.
          admin reset-2fa [--user <name>]   Turn two-factor sign-in off (it can be set up again in the admin UI).
          admin allow-ip <address-or-cidr>  Add an address range to the remote admin allowlist.
          admin unregister-url              Turn remote admin access off (localhost access always works).

        Other:
          status                            Data folder, active configuration, admin accounts and remote access.

        Options:
          --data-dir <path>   The gateway's data folder (default: as configured for the service, else
                              %ProgramData%\WafGateway on Windows or /var/lib/wafgateway on Linux).
          -h, --help          Show this help.
        """;

    private readonly Dictionary<string, string?> _options = new(StringComparer.Ordinal);

    private static AuditActor Actor => new($"{Environment.UserName} (wafctl)", null, "wafctl");

    public static async Task<int> RunConsoleAsync(string[] args) =>
        await new WafCtl(Console.Out, Console.Error, Console.In, new ConsoleSecretReader(), TimeProvider.System)
            .RunAsync(args, CancellationToken.None).ConfigureAwait(false);

    public async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);

        List<string> words;
        try
        {
            words = Parse(args);
        }
        catch (ArgumentException ex)
        {
            error.WriteLine(ex.Message);
            error.WriteLine("Run 'wafctl --help' for the commands.");
            return UsageError;
        }

        if (words.Count == 0 || _options.ContainsKey("--help"))
        {
            output.WriteLine($"wafctl {ProductInfo.Version} - {ProductInfo.Name} recovery tool");
            output.WriteLine();
            output.WriteLine(Usage);
            return words.Count == 0 && !_options.ContainsKey("--help") ? UsageError : Success;
        }

        Func<Session, CancellationToken, Task<int>>? command = (string.Join(' ', words.Take(2)), words.Count) switch
        {
            ("rules disable-all", 2) => DisableAllRulesAsync,
            ("mode detection-only", 2) => (s, ct) => SetDetectionOnlyAsync(s, true, ct),
            ("mode enforce", 2) => (s, ct) => SetDetectionOnlyAsync(s, false, ct),
            ("config restore-last-good", 2) => RestoreLastGoodAsync,
            ("config history", 2) => HistoryAsync,
            ("admin reset-password", 2) => ResetPasswordAsync,
            ("admin reset-2fa", 2) => ResetTwoFactorAsync,
            ("admin allow-ip", 3) => (s, ct) => AllowIpAsync(s, words[2], ct),
            ("admin unregister-url", 2) => UnregisterUrlAsync,
            ("status", 1) => StatusAsync,
            _ => null,
        };
        if (command is null)
        {
            error.WriteLine($"Unknown command: {string.Join(' ', words)}");
            error.WriteLine("Run 'wafctl --help' for the commands.");
            return UsageError;
        }

        var paths = DataFolder.Resolve(_options.GetValueOrDefault("--data-dir"));
        if (!File.Exists(paths.ConfigDatabasePath))
        {
            error.WriteLine($"No gateway data found in {paths.DataDirectory} (config.db is missing).");
            error.WriteLine("Point wafctl at the gateway's data folder with --data-dir <path>.");
            return Failed;
        }

        try
        {
            await using var session = await Session.OpenAsync(paths, time, cancellationToken).ConfigureAwait(false);
            return await command(session, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is StorageInitializationException or SqliteException or UnauthorizedAccessException or IOException)
        {
            error.WriteLine($"The data folder {paths.DataDirectory} could not be used: {ex.Message}");
            error.WriteLine(
                "wafctl needs read and write access to it: run it as Administrator (Windows), or with sudo or as the service account (Linux).");
            return Failed;
        }
    }

    private List<string> Parse(string[] args)
    {
        var words = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "-h" or "--help" or "/?":
                    _options["--help"] = null;
                    break;
                case "--password-stdin":
                    _options[arg] = null;
                    break;
                case "--data-dir" or "--user" or "--version":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        throw new ArgumentException($"{arg} needs a value.");
                    }

                    _options[arg] = args[++i];
                    break;
                default:
                    if (arg.StartsWith("--", StringComparison.Ordinal))
                    {
                        throw new ArgumentException($"Unknown option: {arg}");
                    }

                    words.Add(arg);
                    break;
            }
        }

        return words;
    }

    // ---- Configuration ----

    private async Task<int> DisableAllRulesAsync(Session session, CancellationToken cancellationToken)
    {
        if (await ActiveAsync(session, cancellationToken).ConfigureAwait(false) is not { } active)
        {
            return Failed;
        }

        var configuration = active.Configuration;
        var enabled = configuration.Rules.Where(r => r.Enabled).ToList();
        if (enabled.Count == 0)
        {
            output.WriteLine($"All {configuration.Rules.Count} rules are already disabled; nothing changed.");
            return Success;
        }

        foreach (var rule in enabled)
        {
            rule.Enabled = false;
        }

        var stored = await ActivateAsync(session, configuration, $"All rules disabled with wafctl ({enabled.Count} rule(s)).", cancellationToken).ConfigureAwait(false);
        if (stored is null)
        {
            return Failed;
        }

        output.WriteLine($"Disabled {enabled.Count} rule(s): {string.Join(", ", enabled.Select(r => r.Name))}.");
        output.WriteLine($"Stored and activated as configuration version {stored.Version}.");
        output.WriteLine("Attack detection and rate limits still apply; 'wafctl mode detection-only' only logs them.");
        RunningHint();
        return Success;
    }

    private async Task<int> SetDetectionOnlyAsync(Session session, bool detectionOnly, CancellationToken cancellationToken)
    {
        if (await ActiveAsync(session, cancellationToken).ConfigureAwait(false) is not { } active)
        {
            return Failed;
        }

        var configuration = active.Configuration;
        if (configuration.Settings.DetectionOnly == detectionOnly)
        {
            output.WriteLine(detectionOnly
                ? "Detection-only mode is already on; nothing changed."
                : "Blocks are already enforced; nothing changed.");
            return Success;
        }

        configuration.Settings.DetectionOnly = detectionOnly;
        var comment = detectionOnly ? "Detection-only mode switched on with wafctl." : "Detection-only mode switched off with wafctl.";
        var stored = await ActivateAsync(session, configuration, comment, cancellationToken).ConfigureAwait(false);
        if (stored is null)
        {
            return Failed;
        }

        output.WriteLine(detectionOnly
            ? "Detection-only mode is on: rules, rate limits and attack detection log what they would block, and nothing is blocked."
            : "Detection-only mode is off: blocks are enforced again.");
        output.WriteLine($"Stored and activated as configuration version {stored.Version}.");
        RunningHint();
        return Success;
    }

    private async Task<int> RestoreLastGoodAsync(Session session, CancellationToken cancellationToken)
    {
        if (await ActiveAsync(session, cancellationToken).ConfigureAwait(false) is not { } active)
        {
            return Failed;
        }

        StoredConfiguration? target;
        if (_options.TryGetValue("--version", out var versionText))
        {
            if (!long.TryParse(versionText, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
                || await session.Store.GetAsync(number, cancellationToken).ConfigureAwait(false) is not { } chosen)
            {
                error.WriteLine($"Configuration version {versionText} does not exist. 'wafctl config history' lists them.");
                return Failed;
            }

            target = chosen;
        }
        else
        {
            // The newest earlier version with different content: what was running before the current configuration.
            var history = await session.Store.GetHistoryAsync(500, cancellationToken).ConfigureAwait(false);
            target = history.FirstOrDefault(v => v.Version < active.Version && v.Sha256 != active.Sha256);
            if (target is null)
            {
                error.WriteLine($"There is no earlier configuration than the active version {active.Version} to go back to.");
                return Failed;
            }
        }

        if (target.Sha256 == active.Sha256)
        {
            output.WriteLine($"Version {target.Version} is the same as the active version {active.Version}; nothing changed.");
            return Success;
        }

        var stored = await ActivateAsync(
            session, target.Configuration, $"Restored version {target.Version} with wafctl (was version {active.Version}).", cancellationToken)
            .ConfigureAwait(false);
        if (stored is null)
        {
            return Failed;
        }

        output.WriteLine(
            $"Restored version {target.Version} (stored {Format(target.CreatedAtUtc)} by {target.Author}) as configuration version {stored.Version}.");
        RunningHint();
        return Success;
    }

    private async Task<int> HistoryAsync(Session session, CancellationToken cancellationToken)
    {
        var active = await session.Store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
        var history = await session.Store.GetHistoryAsync(15, cancellationToken).ConfigureAwait(false);
        if (history.Count == 0)
        {
            output.WriteLine("No configuration versions are stored yet.");
            return Success;
        }

        foreach (var version in history)
        {
            var marker = version.Version == active?.Version ? "*" : " ";
            output.WriteLine(
                $"{marker} {version.Version,5}  {Format(version.CreatedAtUtc)}  {version.Author}  {version.Comment}".TrimEnd());
        }

        output.WriteLine("* = active");
        return Success;
    }

    /// <summary>The active configuration (a fresh copy that may be changed); writes an error when there is none.</summary>
    private async Task<StoredConfiguration?> ActiveAsync(Session session, CancellationToken cancellationToken)
    {
        var active = await session.Store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
        if (active is null)
        {
            error.WriteLine("No configuration has been activated yet: start the gateway once first.");
        }

        return active;
    }

    /// <summary>
    /// Checks <paramref name="configuration"/> like the gateway does (validation and building the WAF engine), then
    /// stores it as a new version with its audit entry and makes it the active one. Null (with the errors written)
    /// when it is not valid.
    /// </summary>
    private async Task<StoredConfiguration?> ActivateAsync(Session session, GatewayConfiguration configuration, string comment, CancellationToken cancellationToken)
    {
        var errors = GatewayConfigurationValidator.Validate(configuration);
        if (errors.Count == 0)
        {
            try
            {
                WafEngine.Build(configuration, time, ConfigurationStore.ConfigTag(ConfigurationStore.ComputeHash(configuration)));
            }
            catch (ArgumentException ex)
            {
                errors = [$"The WAF engine could not be built: {ex.Message}"];
            }
        }

        if (errors.Count > 0)
        {
            error.WriteLine("The configuration was not changed, because the result would not be valid:");
            foreach (var problem in errors)
            {
                error.WriteLine($"  - {problem}");
            }

            return null;
        }

        var stored = await session.Store.SaveAsync(configuration, Actor, comment, cancellationToken).ConfigureAwait(false);
        await session.Store.SetLastKnownGoodAsync(stored.Version, cancellationToken).ConfigureAwait(false);
        return stored;
    }

    private void RunningHint() =>
        output.WriteLine("A running gateway applies it within a few seconds; otherwise it is used at the next start.");

    // ---- Admin account and access ----

    private async Task<int> ResetPasswordAsync(Session session, CancellationToken cancellationToken)
    {
        var (users, user) = await AdminAsync(session).ConfigureAwait(false);
        if (user is null)
        {
            return Failed;
        }

        var password = await ReadNewPasswordAsync().ConfigureAwait(false);
        if (password is null)
        {
            return Failed;
        }

        var problems = new List<string>();
        foreach (var validator in users.PasswordValidators)
        {
            var result = await validator.ValidateAsync(users, user, password).ConfigureAwait(false);
            problems.AddRange(result.Errors.Select(e => e.Description));
        }

        if (problems.Count > 0)
        {
            error.WriteLine("The password was not changed:");
            foreach (var problem in problems)
            {
                error.WriteLine($"  - {problem}");
            }

            error.WriteLine($"Use at least {AdminAccountPolicy.MinPasswordLength} characters; a few unrelated words make a strong password.");
            return Failed;
        }

        // Validated first, so the account is never left without a usable password. A new security stamp ends
        // every session at its next request.
        user.PasswordHash = users.PasswordHasher.HashPassword(user, password);
        Check(await users.UpdateSecurityStampAsync(user).ConfigureAwait(false));
        Check(await users.SetLockoutEndDateAsync(user, null).ConfigureAwait(false));
        Check(await users.ResetAccessFailedCountAsync(user).ConfigureAwait(false));

        await session.Audit.RecordAsync(
            AuditCategory.Security, AuditActions.PasswordReset, Actor,
            $"Password of '{user.UserName}' reset with wafctl; the account was unlocked and all sessions were signed out.",
            cancellationToken: cancellationToken).ConfigureAwait(false);
        output.WriteLine($"The password of '{user.UserName}' was changed. The account is unlocked and every session was signed out.");
        return Success;
    }

    private async Task<int> ResetTwoFactorAsync(Session session, CancellationToken cancellationToken)
    {
        var (users, user) = await AdminAsync(session).ConfigureAwait(false);
        if (user is null)
        {
            return Failed;
        }

        var wasOn = await users.GetTwoFactorEnabledAsync(user).ConfigureAwait(false);
        Check(await users.SetTwoFactorEnabledAsync(user, false).ConfigureAwait(false));
        Check(await users.ResetAuthenticatorKeyAsync(user).ConfigureAwait(false)); // a new setup gets a new key
        await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 0).ConfigureAwait(false); // old recovery codes stop working
        Check(await users.UpdateSecurityStampAsync(user).ConfigureAwait(false));

        await session.Audit.RecordAsync(
            AuditCategory.Security, AuditActions.TwoFactorReset, Actor,
            $"Two-factor sign-in of '{user.UserName}' reset with wafctl{(wasOn ? string.Empty : " (it was off)")}; all sessions were signed out.",
            cancellationToken: cancellationToken).ConfigureAwait(false);
        output.WriteLine(wasOn
            ? $"Two-factor sign-in of '{user.UserName}' is off; signing in needs only the password. Set it up again under Your account in the admin UI."
            : $"Two-factor sign-in of '{user.UserName}' was already off; its key and recovery codes were reset anyway.");
        output.WriteLine("Every session was signed out.");
        return Success;
    }

    private async Task<int> AllowIpAsync(Session session, string cidr, CancellationToken cancellationToken)
    {
        if (!session.HasIdentity)
        {
            NoIdentity();
            return Failed;
        }

        string network;
        bool added;
        try
        {
            (network, added) = await session.AdminAccess.AllowNetworkAsync(cidr, cancellationToken).ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            error.WriteLine(ex.Message);
            return Failed;
        }

        if (!added)
        {
            output.WriteLine($"{network} is already on the remote admin allowlist; nothing changed.");
            return Success;
        }

        await session.Audit.RecordAsync(
            AuditCategory.Security, AuditActions.AdminIpAllowed, Actor, $"{network} added to the remote admin allowlist with wafctl.",
            cancellationToken: cancellationToken).ConfigureAwait(false);
        var access = await session.AdminAccess.GetAsync(cancellationToken).ConfigureAwait(false);
        output.WriteLine($"{network} added to the remote admin allowlist ({access.AllowedNetworkList.Count} entr{(access.AllowedNetworkList.Count == 1 ? "y" : "ies")}).");
        if (access.RemoteUrl is null)
        {
            output.WriteLine("Remote admin access is off; the allowlist applies once an admin URL is registered.");
        }

        return Success;
    }

    private async Task<int> UnregisterUrlAsync(Session session, CancellationToken cancellationToken)
    {
        if (!session.HasIdentity)
        {
            NoIdentity();
            return Failed;
        }

        var previous = await session.AdminAccess.UnregisterUrlAsync(cancellationToken).ConfigureAwait(false);
        if (previous is null)
        {
            output.WriteLine("Remote admin access was already off; nothing changed.");
            return Success;
        }

        await session.Audit.RecordAsync(
            AuditCategory.Security, AuditActions.AdminUrlUnregistered, Actor, $"Remote admin URL {previous} unregistered with wafctl; remote admin access is off.",
            cancellationToken: cancellationToken).ConfigureAwait(false);
        output.WriteLine($"Remote admin access is off ({previous} was unregistered). The admin UI stays available on this machine.");
        return Success;
    }

    /// <summary>The admin account to change: the only one, or the one named with --user. Writes an error when unclear.</summary>
    private async Task<(UserManager<IdentityUser> Users, IdentityUser? User)> AdminAsync(Session session)
    {
        var users = session.Users;
        if (!session.HasIdentity)
        {
            NoIdentity();
            return (users, null);
        }

        var accounts = await users.Users.OrderBy(u => u.UserName).ToListAsync().ConfigureAwait(false);
        if (accounts.Count == 0)
        {
            error.WriteLine("No admin account exists yet. Create it in the admin UI on this machine (http://127.0.0.1:8900).");
            return (users, null);
        }

        if (_options.TryGetValue("--user", out var name))
        {
            var match = accounts.FirstOrDefault(u => string.Equals(u.UserName, name, StringComparison.OrdinalIgnoreCase));
            if (match is null)
            {
                error.WriteLine($"There is no admin account '{name}'. Accounts: {string.Join(", ", accounts.Select(u => u.UserName))}.");
            }

            return (users, match);
        }

        if (accounts.Count > 1)
        {
            error.WriteLine($"There are several admin accounts; choose one with --user: {string.Join(", ", accounts.Select(u => u.UserName))}.");
            return (users, null);
        }

        return (users, accounts[0]);
    }

    /// <summary>identity.db is created by the service at its first start; wafctl never creates it (see Session).</summary>
    private void NoIdentity() =>
        error.WriteLine("There is no account database (identity.db) yet: start the gateway once and create the admin account in the admin UI.");

    private async Task<string?> ReadNewPasswordAsync()
    {
        if (_options.ContainsKey("--password-stdin"))
        {
            var line = await input.ReadLineAsync().ConfigureAwait(false);
            if (string.IsNullOrEmpty(line))
            {
                error.WriteLine("No password was given on standard input.");
                return null;
            }

            return line;
        }

        var password = secrets.Read("New password: ");
        if (password is null)
        {
            error.WriteLine("There is no terminal to ask for the password: pass it with --password-stdin.");
            return null;
        }

        if (secrets.Read("New password again: ") != password)
        {
            error.WriteLine("The passwords do not match; nothing changed.");
            return null;
        }

        return password;
    }

    private static void Check(IdentityResult result)
    {
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(string.Join(" ", result.Errors.Select(e => e.Description)));
        }
    }

    // ---- Status ----

    private async Task<int> StatusAsync(Session session, CancellationToken cancellationToken)
    {
        var active = await session.Store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
        var text = new StringBuilder();
        text.AppendLine(CultureInfo.InvariantCulture, $"Data folder:     {session.Paths.DataDirectory}");
        if (active is null)
        {
            text.AppendLine("Configuration:   none activated yet");
        }
        else
        {
            var configuration = active.Configuration;
            text.AppendLine(CultureInfo.InvariantCulture, $"Configuration:   version {active.Version}, stored {Format(active.CreatedAtUtc)} by {active.Author}");
            text.AppendLine(CultureInfo.InvariantCulture, $"Mode:            {(configuration.Settings.DetectionOnly ? "detection only (nothing is blocked)" : "blocking")}");
            text.AppendLine(CultureInfo.InvariantCulture, $"Rules:           {configuration.Rules.Count(r => r.Enabled)} of {configuration.Rules.Count} enabled");
            text.AppendLine(CultureInfo.InvariantCulture, $"Routes:          {configuration.Routes.Count}");
        }

        var accounts = session.HasIdentity
            ? await session.Users.Users.OrderBy(u => u.UserName).ToListAsync(cancellationToken).ConfigureAwait(false)
            : [];
        if (accounts.Count == 0)
        {
            text.AppendLine("Admin accounts:  none yet (create one in the admin UI on this machine)");
        }

        foreach (var account in accounts)
        {
            var locked = account.LockoutEnd is { } end && end > time.GetUtcNow() ? $", locked until {Format(end.UtcDateTime)}" : string.Empty;
            text.AppendLine(CultureInfo.InvariantCulture, $"Admin account:   {account.UserName} (two-factor sign-in {(account.TwoFactorEnabled ? "on" : "off")}{locked})");
        }

        var access = session.HasIdentity ? await session.AdminAccess.GetAsync(cancellationToken).ConfigureAwait(false) : new AdminAccess();
        text.AppendLine(CultureInfo.InvariantCulture, $"Remote admin:    {access.RemoteUrl ?? "off"}");
        text.Append(CultureInfo.InvariantCulture, $"Admin allowlist: {(access.AllowedNetworkList.Count == 0 ? "(empty)" : string.Join(", ", access.AllowedNetworkList))}");
        output.WriteLine(text.ToString());
        return Success;
    }

    private static string Format(DateTime utc) => utc.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    /// <summary>
    /// The databases of one data folder, opened and migrated like the service does at start. identity.db is only
    /// opened when it exists: run as root, wafctl must not create a file the service account cannot write.
    /// </summary>
    private sealed class Session : IAsyncDisposable
    {
        private readonly ServiceProvider _services;
        private readonly AsyncServiceScope _scope;

        private Session(StoragePaths paths, ConfigurationStore store, AuditLogStore audit, ServiceProvider services, TimeProvider time)
        {
            Paths = paths;
            Store = store;
            Audit = audit;
            _services = services;
            _scope = services.CreateAsyncScope();
            Users = _scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            AdminAccess = new AdminAccessStore(_scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>(), time);
        }

        public StoragePaths Paths { get; }

        public ConfigurationStore Store { get; }

        public AuditLogStore Audit { get; }

        public UserManager<IdentityUser> Users { get; }

        /// <summary>True when identity.db exists (the service created it at its first start).</summary>
        public bool HasIdentity { get; private init; }

        public AdminAccessStore AdminAccess { get; }

        public static async Task<Session> OpenAsync(StoragePaths paths, TimeProvider time, CancellationToken cancellationToken)
        {
            var store = ConfigurationStore.Create(paths, time);
            await store.InitializeAsync(cancellationToken).ConfigureAwait(false);

            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton(time);
            services.AddDbContext<AdminIdentityDbContext>(options => options.UseSqlite(AdminIdentityDbContext.ConnectionString(paths)));
            services.AddIdentityCore<IdentityUser>(AdminAccountPolicy.Apply).AddEntityFrameworkStores<AdminIdentityDbContext>();
            var provider = services.BuildServiceProvider();

            var session = new Session(paths, store, AuditLogStore.Create(paths, time), provider, time)
            {
                HasIdentity = File.Exists(Path.Combine(paths.DataDirectory, AdminIdentityDbContext.FileName)),
            };
            if (session.HasIdentity)
            {
                await session._scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>().Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
            }

            return session;
        }

        public async ValueTask DisposeAsync()
        {
            await _scope.DisposeAsync().ConfigureAwait(false);
            await _services.DisposeAsync().ConfigureAwait(false);
            SqliteConnection.ClearAllPools(); // release the database files right away
        }
    }
}

/// <summary>Asks for a password on the terminal without echoing it.</summary>
internal sealed class ConsoleSecretReader : ISecretReader
{
    public string? Read(string prompt)
    {
        if (Console.IsInputRedirected)
        {
            return null;
        }

        Console.Write(prompt);
        var text = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return text.ToString();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (text.Length > 0)
                {
                    text.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                text.Append(key.KeyChar);
            }
        }
    }
}
