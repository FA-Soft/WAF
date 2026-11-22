using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Waf.Data;

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
    }
}

/// <summary>Used by <c>dotnet ef</c> to create migrations; not used at runtime.</summary>
internal sealed class ConfigDbContextDesignTimeFactory : IDesignTimeDbContextFactory<ConfigDbContext>
{
    public ConfigDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<ConfigDbContext>().UseSqlite("Data Source=design-time.db").Options);
}
