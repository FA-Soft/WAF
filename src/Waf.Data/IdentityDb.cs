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
