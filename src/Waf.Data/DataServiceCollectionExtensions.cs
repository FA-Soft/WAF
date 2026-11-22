using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Waf.Data;

/// <summary>Registration of the data layer.</summary>
public static class DataServiceCollectionExtensions
{
    /// <summary>Registers <see cref="ConfigDbContext"/> on <paramref name="paths"/> and <see cref="ConfigurationStore"/>.</summary>
    public static IServiceCollection AddWafData(this IServiceCollection services, StoragePaths paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = paths.ConfigDatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
        }.ToString();

        services.AddSingleton(paths);
        services.AddDbContextFactory<ConfigDbContext>(options => options.UseSqlite(connectionString));
        services.AddSingleton<ConfigurationStore>();
        return services;
    }
}
