using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Waf.Data;

/// <summary>
/// ASP.NET Core Identity store of the admin accounts, in <c>identity.db</c> in the data folder. Kept apart from
/// <c>config.db</c>: accounts are not configuration, so they are not part of exports, backups or restores.
/// </summary>
public sealed class AdminIdentityDbContext(DbContextOptions<AdminIdentityDbContext> options) : IdentityDbContext<IdentityUser>(options)
{
    /// <summary>File name of the account database in the data folder.</summary>
    public const string FileName = "identity.db";

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

/// <summary>Used by <c>dotnet ef</c> to create migrations.</summary>
internal sealed class AdminIdentityDbContextDesignTimeFactory : IDesignTimeDbContextFactory<AdminIdentityDbContext>
{
    public AdminIdentityDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<AdminIdentityDbContext>().UseSqlite("Data Source=design-time-identity.db").Options);
}
