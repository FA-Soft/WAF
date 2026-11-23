using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace FASoft.Waf.Data;

/// <summary>
/// ASP.NET Core Identity store of the admin accounts, in <c>identity.db</c> in the data folder. Kept apart from
/// <c>config.db</c>: accounts are not configuration, so they are not part of exports, backups or restores.
/// </summary>
public sealed class AdminIdentityDbContext(DbContextOptions<AdminIdentityDbContext> options) : IdentityDbContext<IdentityUser>(options)
{
    /// <summary>File name of the account database in the data folder.</summary>
    public const string FileName = "identity.db";

    /// <summary>The login history.</summary>
    public DbSet<SignInEvent> SignInEvents => Set<SignInEvent>();

    /// <summary>Remote admin access of this machine (one row).</summary>
    public DbSet<AdminAccess> AdminAccessSettings => Set<AdminAccess>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        base.OnModelCreating(builder);
        builder.Entity<SignInEvent>(entity =>
        {
            entity.ToTable("SignInEvents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.UserId).HasMaxLength(450);
            entity.Property(e => e.UserName).HasMaxLength(256);
            entity.Property(e => e.ClientIp).IsRequired().HasMaxLength(45);
            entity.Property(e => e.UserAgent).HasMaxLength(SignInEvent.MaxUserAgentLength);
            entity.Property(e => e.Result).IsRequired().HasConversion<string>().HasMaxLength(32);
            entity.HasIndex(e => e.TimestampMs);
        });
        builder.Entity<AdminAccess>(entity =>
        {
            entity.ToTable("AdminAccess");
            entity.HasKey(a => a.Id);
            entity.Property(a => a.Id).ValueGeneratedNever();
            entity.Property(a => a.RemoteUrl).HasMaxLength(AdminAccess.MaxUrlLength);
            entity.Property(a => a.AllowedNetworks).IsRequired();
        });
    }

    public static string ConnectionString(StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        return new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(paths.DataDirectory, FileName),
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
        }.ToString();
    }
}

/// <summary>
/// Remote admin access of this machine: the registered admin URL and the networks allowed to use it. Single row
/// (<see cref="SingletonId"/>) in <c>identity.db</c>: machine-local like the admin account, so never part of
/// configuration versions, exports or backups. Localhost access to the admin UI does not depend on it.
/// </summary>
public sealed class AdminAccess
{
    public const int SingletonId = 1;

    public const int MaxUrlLength = 300;

    public int Id { get; set; } = SingletonId;

    /// <summary>The registered remote admin URL, e.g. <c>https://admin.example.com</c>; null: remote access is off.</summary>
    public string? RemoteUrl { get; set; }

    /// <summary>Addresses and CIDR ranges allowed to use remote admin access, one per line; empty: any address.</summary>
    public string AllowedNetworks { get; set; } = string.Empty;

    /// <summary>When it was last changed (UTC).</summary>
    public DateTime? UpdatedAtUtc { get; set; }

    /// <summary>The entries of <see cref="AllowedNetworks"/>.</summary>
    public IReadOnlyList<string> AllowedNetworkList =>
        AllowedNetworks.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>
/// Rules for admin accounts, shared by the admin UI and <c>wafctl</c> so both accept the same passwords.
/// </summary>
public static class AdminAccountPolicy
{
    /// <summary>Minimum password length. Length matters more than character classes, so no other rules apply.</summary>
    public const int MinPasswordLength = 12;

    /// <summary>Wrong passwords or codes in a row after which an account is locked.</summary>
    public const int MaxFailedAttempts = 5;

    /// <summary>How long a locked account stays locked.</summary>
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    /// <summary>Applies the password, user and lockout rules.</summary>
    public static void Apply(IdentityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.Password.RequiredLength = MinPasswordLength;
        options.Password.RequiredUniqueChars = 5;
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;
        options.User.RequireUniqueEmail = false;
        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = MaxFailedAttempts;
        options.Lockout.DefaultLockoutTimeSpan = LockoutDuration;
    }
}

/// <summary>What happened in a sign-in attempt or session event.</summary>
public enum SignInOutcome
{
    Succeeded,
    WrongPassword,
    UnknownUser,
    LockedOut,
    Throttled,
    TwoFactorRequired,
    TwoFactorFailed,
    RecoveryCodeUsed,
    SignedOut,
    SessionsEnded,

    /// <summary>Password correct, but refused: signing in remotely needs two-factor sign-in.</summary>
    RemoteNeedsTwoFactor,
}

/// <summary>One entry of the login history.</summary>
public sealed class SignInEvent
{
    public const int MaxUserAgentLength = 200;

    public long Id { get; set; }

    /// <summary>When it happened, as Unix time in milliseconds (UTC).</summary>
    public long TimestampMs { get; set; }

    /// <summary>The account; null when the user name did not match an account.</summary>
    public string? UserId { get; set; }

    /// <summary>
    /// The account's user name; null for an unknown name. What was typed is never stored: it may be a
    /// password typed into the wrong field.
    /// </summary>
    public string? UserName { get; set; }

    public string ClientIp { get; set; } = string.Empty;

    public string? UserAgent { get; set; }

    public SignInOutcome Result { get; set; }
}

/// <summary>Used by <c>dotnet ef</c> to create migrations.</summary>
internal sealed class AdminIdentityDbContextDesignTimeFactory : IDesignTimeDbContextFactory<AdminIdentityDbContext>
{
    public AdminIdentityDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<AdminIdentityDbContext>().UseSqlite("Data Source=design-time-identity.db").Options);
}
