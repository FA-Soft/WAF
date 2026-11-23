using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace FASoft.Waf.Data;

/// <summary>
/// A stored version of the complete gateway configuration. Versions are never changed after they are
/// written; every change adds a new version.
/// </summary>
public sealed class ConfigurationVersion
{
    /// <summary>Version number, increasing.</summary>
    public long Id { get; set; }

    /// <summary>When the version was stored (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Who stored it, e.g. a user name or "appsettings import".</summary>
    public string Author { get; set; } = string.Empty;

    /// <summary>Optional description of the change.</summary>
    public string? Comment { get; set; }

    /// <summary>Configuration schema version of <see cref="Json"/>.</summary>
    public int SchemaVersion { get; set; }

    /// <summary>The complete configuration as canonical JSON (see <c>GatewayConfigurationJson</c>).</summary>
    public string Json { get; set; } = string.Empty;

    /// <summary>SHA-256 of <see cref="Json"/> (hex), to detect unchanged configurations cheaply.</summary>
    public string Sha256 { get; set; } = string.Empty;
}

/// <summary>EF Core context for <c>config.db</c>.</summary>
public sealed class ConfigDbContext(DbContextOptions<ConfigDbContext> options) : DbContext(options)
{
    public DbSet<ConfigurationVersion> ConfigurationVersions => Set<ConfigurationVersion>();

    public DbSet<ConfigurationState> ConfigurationState => Set<ConfigurationState>();

    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    public DbSet<StoredCertificate> StoredCertificates => Set<StoredCertificate>();

    public DbSet<AcmeAccount> AcmeAccounts => Set<AcmeAccount>();

    public DbSet<AiSettings> AiSettings => Set<AiSettings>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<ConfigurationVersion>(entity =>
        {
            entity.ToTable("ConfigurationVersions");
            entity.HasKey(v => v.Id);
            entity.Property(v => v.Id).ValueGeneratedOnAdd();
            entity.Property(v => v.CreatedAtUtc).IsRequired();
            entity.Property(v => v.Author).IsRequired().HasMaxLength(200);
            entity.Property(v => v.Comment).HasMaxLength(2000);
            entity.Property(v => v.Json).IsRequired();
            entity.Property(v => v.Sha256).IsRequired().HasMaxLength(64).IsFixedLength();
            entity.HasIndex(v => v.CreatedAtUtc);
        });

        modelBuilder.Entity<ConfigurationState>(entity =>
        {
            entity.ToTable("ConfigurationState");
            entity.HasKey(s => s.Id);
            entity.Property(s => s.Id).ValueGeneratedNever();
            entity.Property(s => s.AppSettingsFingerprint).HasMaxLength(64);
            entity.HasOne<ConfigurationVersion>()
                .WithMany()
                .HasForeignKey(s => s.LastKnownGoodVersionId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        // No foreign key to the version: versions are replaced by a backup restore, the audit log is not.
        modelBuilder.Entity<AuditEntry>(entity =>
        {
            entity.ToTable("AuditEntries");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.TimestampUtc).IsRequired();
            entity.Property(e => e.Category).IsRequired().HasConversion<string>().HasMaxLength(32);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(AuditEntry.MaxActionLength);
            entity.Property(e => e.UserName).IsRequired().HasMaxLength(AuditEntry.MaxUserNameLength);
            entity.Property(e => e.ClientIp).HasMaxLength(AuditEntry.MaxClientIpLength);
            entity.Property(e => e.Source).IsRequired().HasMaxLength(AuditEntry.MaxSourceLength);
            entity.Property(e => e.Summary).IsRequired().HasMaxLength(AuditEntry.MaxSummaryLength);
            entity.Property(e => e.Details).HasMaxLength(AuditEntry.MaxDetailsLength);
            entity.HasIndex(e => e.TimestampUtc);
            entity.HasIndex(e => e.ConfigurationVersionId);
        });

        modelBuilder.Entity<StoredCertificate>(entity =>
        {
            entity.ToTable("StoredCertificates");
            entity.HasKey(c => c.Thumbprint);
            entity.Property(c => c.Thumbprint).HasMaxLength(64).IsFixedLength();
            entity.Property(c => c.Subject).IsRequired().HasMaxLength(1000);
            entity.Property(c => c.Issuer).IsRequired().HasMaxLength(1000);
            entity.Property(c => c.DnsNames).IsRequired();
            entity.Property(c => c.ProtectedPfx).IsRequired();
            entity.Property(c => c.UploadedBy).IsRequired().HasMaxLength(256);
            entity.Property(c => c.AcmeHostName).HasMaxLength(253);
            entity.Property(c => c.AcmeDirectory).HasMaxLength(500);
            entity.HasIndex(c => c.AcmeHostName);
            entity.Ignore(c => c.DnsNameList);
            entity.Ignore(c => c.IsAcme);
        });

        modelBuilder.Entity<AiSettings>(entity =>
        {
            entity.ToTable("AiSettings");
            entity.HasKey(s => s.Id);
            entity.Property(s => s.Id).ValueGeneratedNever();
            entity.Property(s => s.Provider).IsRequired().HasMaxLength(50);
            entity.Property(s => s.ProtectedApiKey).IsRequired();
            entity.Property(s => s.KeyHint).IsRequired().HasMaxLength(8);
            entity.Property(s => s.UpdatedBy).IsRequired().HasMaxLength(256);
        });

        modelBuilder.Entity<AcmeAccount>(entity =>
        {
            entity.ToTable("AcmeAccounts");
            entity.HasKey(a => a.DirectoryUrl);
            entity.Property(a => a.DirectoryUrl).HasMaxLength(500);
            entity.Property(a => a.AccountUrl).IsRequired().HasMaxLength(500);
            entity.Property(a => a.Email).IsRequired().HasMaxLength(320);
            entity.Property(a => a.ProtectedKey).IsRequired();
        });
    }
}

/// <summary>
/// Single-row table (<see cref="SingletonId"/>) pointing to the last-known-good version: the version that
/// was most recently activated successfully. Only validated configurations are ever activated, so it is
/// also the active version.
/// </summary>
public sealed class ConfigurationState
{
    /// <summary>The id of the only row.</summary>
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;

    /// <summary>Version that was last activated successfully; null before the first activation.</summary>
    public long? LastKnownGoodVersionId { get; set; }

    /// <summary>When it was activated (UTC).</summary>
    public DateTime? ActivatedAtUtc { get; set; }

    /// <summary>
    /// Fingerprint of the appsettings Gateway section when it was last imported or dismissed. The database is
    /// the source of truth; a different fingerprint means appsettings was edited since and is not applied.
    /// </summary>
    public string? AppSettingsFingerprint { get; set; }
}

/// <summary>Used by <c>dotnet ef</c> to create migrations; not used at runtime.</summary>
internal sealed class ConfigDbContextDesignTimeFactory : IDesignTimeDbContextFactory<ConfigDbContext>
{
    public ConfigDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<ConfigDbContext>().UseSqlite("Data Source=design-time.db").Options);
}
