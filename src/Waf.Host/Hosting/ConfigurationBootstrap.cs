using Microsoft.Extensions.Options;
using Waf.Core.Configuration;
using Waf.Data;
using Waf.Engine;

namespace Waf.Host.Hosting;

/// <summary>Which configuration the gateway starts with.</summary>
/// <param name="Configuration">The configuration to run.</param>
/// <param name="Version">Its stored version.</param>
/// <param name="Seeded">True on a fresh install: the appsettings configuration was stored as the first version.</param>
/// <param name="Notice">Set when appsettings was edited since its last import/dismissal (not applied).</param>
internal sealed record BootstrapResult(GatewayConfiguration Configuration, StoredConfiguration Version, bool Seeded, AppSettingsNotice? Notice);

/// <summary>
/// Startup: opens (or creates and migrates) <c>config.db</c> and decides which configuration runs.
/// </summary>
/// <remarks>
/// The configuration database is the source of truth.
/// <list type="bullet">
/// <item>Fresh install (no last-known-good yet): the appsettings Gateway section seeds the first version. It
/// must be valid; otherwise startup fails with the errors.</item>
/// <item>Otherwise the last-known-good version runs. If the appsettings Gateway section was edited since it was
/// last imported or dismissed, that is reported (<see cref="AppSettingsNotice"/>) but not applied.</item>
/// </list>
/// </remarks>
internal static class ConfigurationBootstrap
{
    /// <summary>Author recorded for versions imported from appsettings.</summary>
    public const string ImportAuthor = "appsettings import";

    /// <exception cref="StorageInitializationException">The data folder or database cannot be used.</exception>
    /// <exception cref="OptionsValidationException">Fresh install and the appsettings configuration is invalid.</exception>
    public static BootstrapResult Run(IConfiguration configuration, StoragePaths paths, ConfigurationStore store, TimeProvider time)
    {
        InitializeStorage(paths, store);

        var lastKnownGood = store.GetLastKnownGoodAsync(CancellationToken.None).GetAwaiter().GetResult();
        var fingerprint = GatewayConfigurationLoader.Fingerprint(configuration);

        if (lastKnownGood is null)
        {
            var (candidate, errors) = Load(configuration, time);
            if (candidate is null)
            {
                throw new OptionsValidationException(GatewayConfigurationLoader.SectionName, typeof(GatewayConfiguration), errors);
            }

            var (stored, _) = store.SaveIfChangedAsync(candidate, ImportAuthor, "Imported from appsettings at startup.", CancellationToken.None)
                .GetAwaiter().GetResult();
            store.SetLastKnownGoodAsync(stored.Version, CancellationToken.None).GetAwaiter().GetResult();
            store.SetAppSettingsFingerprintAsync(fingerprint, CancellationToken.None).GetAwaiter().GetResult();
            return new BootstrapResult(candidate, stored, true, null);
        }

        var recorded = store.GetAppSettingsFingerprintAsync(CancellationToken.None).GetAwaiter().GetResult();
        if (recorded is null)
        {
            // Database from before this setting existed: treat the current appsettings as already seen.
            store.SetAppSettingsFingerprintAsync(fingerprint, CancellationToken.None).GetAwaiter().GetResult();
            recorded = fingerprint;
        }

        return new BootstrapResult(lastKnownGood.Configuration, lastKnownGood, false, Check(configuration, recorded, time));
    }

    /// <summary>
    /// Compares the appsettings Gateway section with the fingerprint recorded at its last import/dismissal;
    /// returns a notice (with the parsed configuration or the errors) when it was edited since, else null.
    /// </summary>
    public static AppSettingsNotice? Check(IConfiguration configuration, string? recordedFingerprint, TimeProvider time)
    {
        var fingerprint = GatewayConfigurationLoader.Fingerprint(configuration);
        if (fingerprint == recordedFingerprint)
        {
            return null;
        }

        var (candidate, errors) = Load(configuration, time);
        return new AppSettingsNotice(fingerprint, candidate, errors, time.GetUtcNow());
    }

    /// <summary>Reads and validates the appsettings configuration, including building the WAF engine.</summary>
    private static (GatewayConfiguration? Candidate, IReadOnlyList<string> Errors) Load(IConfiguration configuration, TimeProvider time)
    {
        var (candidate, errors) = GatewayConfigurationLoader.TryLoad(configuration);
        if (candidate is null)
        {
            return (null, errors);
        }

        try
        {
            _ = WafEngine.Build(candidate, time);
            return (candidate, []);
        }
        catch (ArgumentException ex)
        {
            return (null, [$"The WAF engine could not be built: {ex.Message}"]);
        }
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
