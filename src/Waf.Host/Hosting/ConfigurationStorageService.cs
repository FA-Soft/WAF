using Waf.Core.Configuration;
using Waf.Data;

namespace Waf.Host.Hosting;

/// <summary>
/// At startup: creates the data folder and <c>config.db</c> (fresh install), applies migrations and stores the
/// active configuration as a new version when it differs from the latest stored one.
/// </summary>
/// <remarks>
/// Until the web UI exists, appsettings is where the configuration is edited; the database keeps the history.
/// Failing to open the database stops startup (<see cref="StorageInitializationException"/>), with a message
/// that names the folder, rather than running without durable storage.
/// </remarks>
internal sealed partial class ConfigurationStorageService(
    StoragePaths paths, ConfigurationStore store, GatewayConfiguration configuration, ILogger<ConfigurationStorageService> logger) : IHostedService
{
    /// <summary>Author recorded for versions imported from appsettings.</summary>
    public const string ImportAuthor = "appsettings import";

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            paths.EnsureDataDirectory();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new StorageInitializationException(
                $"The data folder '{paths.DataDirectory}' could not be created: {ex.Message} Check the permissions of the service account, or set Gateway:Storage:DataDirectory.", ex);
        }

        try
        {
            await store.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (StorageInitializationException ex)
        {
            throw new StorageInitializationException(
                $"{ex.Message} Database: '{paths.ConfigDatabasePath}'. Check that the service account can write to '{paths.DataDirectory}', or set Gateway:Storage:DataDirectory.", ex.InnerException ?? ex);
        }

        var (stored, created) = await store.SaveIfChangedAsync(configuration, ImportAuthor, "Imported from appsettings at startup.", cancellationToken).ConfigureAwait(false);
        if (created)
        {
            LogVersionStored(logger, stored.Version, paths.ConfigDatabasePath);
        }
        else
        {
            LogVersionUnchanged(logger, stored.Version);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(EventId = 10, Level = LogLevel.Information, Message = "Configuration stored as version {Version} in {DatabasePath}.")]
    private static partial void LogVersionStored(ILogger logger, long version, string databasePath);

    [LoggerMessage(EventId = 11, Level = LogLevel.Information, Message = "Configuration unchanged since version {Version}.")]
    private static partial void LogVersionUnchanged(ILogger logger, long version);
}
