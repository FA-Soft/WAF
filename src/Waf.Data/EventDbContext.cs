using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Waf.Data;

/// <summary>One request in <c>events.db</c> (see <c>Waf.Engine.RequestLogEntry</c>).</summary>
public sealed class RequestEvent
{
    public long Id { get; set; }

    /// <summary>When the request arrived, as Unix time in milliseconds (UTC); indexed for time ranges.</summary>
    public long TimestampMs { get; set; }

    public string ClientIp { get; set; } = string.Empty;

    public string Method { get; set; } = string.Empty;

    public string Host { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    public string? RouteName { get; set; }

    /// <summary><c>RequestAction</c> name, e.g. Forwarded or Blocked.</summary>
    public string Action { get; set; } = string.Empty;

    /// <summary><c>WafEventKind</c> name, e.g. RuleDetected; null when no rule or detector matched.</summary>
    public string? Event { get; set; }

    public string? RuleName { get; set; }

    public string? Detail { get; set; }

    public string? Destination { get; set; }

    public int StatusCode { get; set; }

    public double LatencyMs { get; set; }
}

/// <summary>EF Core context for <c>events.db</c>: the schema and (later) queries of the log viewer.</summary>
public sealed class EventDbContext(DbContextOptions<EventDbContext> options) : DbContext(options)
{
    public DbSet<RequestEvent> RequestEvents => Set<RequestEvent>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<RequestEvent>(entity =>
        {
            entity.ToTable("RequestEvents");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).ValueGeneratedOnAdd();
            entity.Property(e => e.ClientIp).IsRequired().HasMaxLength(45);
            entity.Property(e => e.Method).IsRequired().HasMaxLength(32);
            entity.Property(e => e.Host).IsRequired().HasMaxLength(255);
            entity.Property(e => e.Path).IsRequired().HasMaxLength(2048);
            entity.Property(e => e.RouteName).HasMaxLength(200);
            entity.Property(e => e.Action).IsRequired().HasMaxLength(32);
            entity.Property(e => e.Event).HasMaxLength(32);
            entity.Property(e => e.RuleName).HasMaxLength(200);
            entity.Property(e => e.Detail).HasMaxLength(1000);
            entity.Property(e => e.Destination).HasMaxLength(300);
            entity.HasIndex(e => e.TimestampMs);
            entity.HasIndex(e => e.ClientIp);
            entity.HasIndex(e => e.Action);
        });
    }
}

/// <summary>Used by <c>dotnet ef</c> to create migrations.</summary>
internal sealed class EventDbContextDesignTimeFactory : IDesignTimeDbContextFactory<EventDbContext>
{
    public EventDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<EventDbContext>().UseSqlite("Data Source=design-time-events.db").Options);
}
