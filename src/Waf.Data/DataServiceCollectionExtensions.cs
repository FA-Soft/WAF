using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FASoft.Waf.Data;

/// <summary>Registration of the data layer.</summary>
public static class DataServiceCollectionExtensions
{
    /// <summary>Registers <see cref="ConfigDbContext"/> on <paramref name="paths"/>, <see cref="ConfigurationStore"/> and <see cref="AuditLogStore"/>.</summary>
    public static IServiceCollection AddWafData(this IServiceCollection services, StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        services.AddSingleton(paths);
        services.AddDbContextFactory<ConfigDbContext>(options => options.UseSqlite(ConnectionString(paths)));
        services.AddSingleton<ConfigurationStore>();
        services.AddSingleton<AuditLogStore>();
        return services;
    }

    /// <summary>Connection string for <c>config.db</c> in <paramref name="paths"/>.</summary>
    public static string ConnectionString(StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        return new SqliteConnectionStringBuilder
        {
            DataSource = paths.ConfigDatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
        }.ToString();
    }
}
