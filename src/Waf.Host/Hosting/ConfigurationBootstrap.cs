using Microsoft.Extensions.Options;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.Engine;

namespace Waf.Host.Hosting;

/// <summary>Which configuration the gateway starts with, and why.</summary>
/// <param name="Configuration">The configuration to run.</param>
/// <param name="Version">Its stored version.</param>
/// <param name="Created">True when the appsettings configuration was stored as a new version.</param>
/// <param name="RejectedErrors">
/// Why the appsettings configuration was rejected when the last-known-good is used instead; empty otherwise.
/// </param>
internal sealed record BootstrapResult(GatewayConfiguration Configuration, StoredConfiguration Version, bool Created, IReadOnlyList<string> RejectedErrors)
{
    public bool UsesLastKnownGood => RejectedErrors.Count > 0;
}

/// <summary>
/// Startup: opens (or creates and migrates) <c>config.db</c> and decides which configuration runs.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>The appsettings configuration is valid and the WAF engine can be built from it: it is stored as a
/// new version if it changed, becomes the last-known-good and runs.</item>
/// <item>It is invalid, but a last-known-good version exists: the gateway runs the last-known-good, and the
/// rejection is logged. An invalid change never replaces a working configuration.</item>
/// <item>It is invalid and there is no last-known-good (fresh install): startup fails with the errors.</item>
/// </list>
/// </remarks>
internal static class ConfigurationBootstrap
{
    /// <summary>Author recorded for versions imported from appsettings.</summary>
    public const string ImportAuthor = "appsettings import";

    /// <exception cref="StorageInitializationException">The data folder or database cannot be used.</exception>
    /// <exception cref="OptionsValidationException">The configuration is invalid and there is no last-known-good.</exception>
    public static BootstrapResult Run(IConfiguration configuration, StoragePaths paths, ConfigurationStore store, TimeProvider time)
    {
        InitializeStorage(paths, store);

        var (candidate, errors) = GatewayConfigurationLoader.TryLoad(configuration);
        if (candidate is not null)
        {
            try
            {
                _ = WafEngine.Build(candidate, time);
            }
            catch (ArgumentException ex)
            {
                errors = [$"The WAF engine could not be built: {ex.Message}"];
                candidate = null;
            }
        }

        if (candidate is not null)
        {
            var (stored, created) = store.SaveIfChangedAsync(candidate, ImportAuthor, "Imported from appsettings at startup.", CancellationToken.None)
                .GetAwaiter().GetResult();
            store.SetLastKnownGoodAsync(stored.Version, CancellationToken.None).GetAwaiter().GetResult();
            return new BootstrapResult(candidate, stored, created, []);
        }

        var lastKnownGood = store.GetLastKnownGoodAsync(CancellationToken.None).GetAwaiter().GetResult()
            ?? throw new OptionsValidationException(GatewayConfigurationLoader.SectionName, typeof(GatewayConfiguration), errors);

        return new BootstrapResult(lastKnownGood.Configuration, lastKnownGood, false, errors);
    }

    private static void InitializeStorage(StoragePaths paths, ConfigurationStore store)
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
            store.InitializeAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (StorageInitializationException ex)
        {
            throw new StorageInitializationException(
                $"{ex.Message} Database: '{paths.ConfigDatabasePath}'. Check that the service account can write to '{paths.DataDirectory}', or set Gateway:Storage:DataDirectory.", ex.InnerException ?? ex);
        }
    }
}
