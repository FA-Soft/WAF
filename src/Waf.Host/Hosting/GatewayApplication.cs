using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Waf.Core;
using Waf.Core.Hosting;
using Waf.Core.Net;
using Waf.Core.Tls;
using Waf.Engine;
using Waf.Core.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Waf.Data;
using Waf.Proxy;

namespace Waf.Host.Hosting;

/// <summary>
/// Builds and runs the gateway: Kestrel listeners, service hosting and the admin/public pipelines.
/// </summary>
internal static partial class GatewayApplication
{
    /// <summary>The Windows service name and systemd identifier.</summary>
    public const string ServiceName = "WafGateway";

    /// <summary>Process exit code used when the gateway cannot start.</summary>
    public const int StartupFailureExitCode = 1;

    public static WebApplication Build(string[] args)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            // Fixed, so the admin UI's static assets manifest (WafGateway.staticwebassets.endpoints.json) is
            // found whichever process hosts the gateway (the service, or a test runner).
            ApplicationName = typeof(GatewayApplication).Assembly.GetName().Name,
            // A Windows service starts in System32; resolve appsettings next to the executable instead.
            ContentRootPath = WindowsServiceHelpers.IsWindowsService() ? AppContext.BaseDirectory : null,
        });

        // Both are no-ops unless the process is actually running under the service manager.
        builder.Host.UseWindowsService(options => options.ServiceName = ServiceName);
        builder.Host.UseSystemd();

        builder.Services
            .AddOptions<GatewayEndpointOptions>()
            .Bind(builder.Configuration.GetSection(GatewayEndpointOptions.SectionName))
            .Validate(o => o.Validate().Count == 0, "Invalid Gateway:Endpoints configuration.")
            .ValidateOnStart();

        var storagePaths = ConfigureStorage(builder);

        // Decide which configuration runs: appsettings if valid, otherwise the last-known-good from config.db.
        var store = ConfigurationStore.Create(storagePaths, TimeProvider.System);
        var bootstrap = ConfigurationBootstrap.Run(builder.Configuration, storagePaths, store, TimeProvider.System);
        var gatewayConfiguration = bootstrap.Configuration;
        var configTag = ConfigurationStore.ConfigTag(bootstrap.Version.Sha256);
        var configurationStatus = new ConfigurationStatus();
        if (bootstrap.UsesLastKnownGood)
        {
            configurationStatus.Rejected("appsettings at startup", bootstrap.RejectedErrors, TimeProvider.System.GetUtcNow());
        }

        builder.Services.AddSingleton<IServerCertificateSelector, NoServerCertificateSelector>();
        builder.Services.AddSingleton<ListenerClassifier>();
        builder.Services.AddRazorComponents();
        builder.Services.AddHealthChecks()
            .AddCheck<WafEngineHealthCheck>("waf-engine")
            .AddCheck<ConfigurationHealthCheck>("configuration");
        builder.Services.AddSingleton(storagePaths);
        builder.Services.AddSingleton(store);
        builder.Services.AddSingleton(configurationStatus);
        builder.Services.AddSingleton<GatewayConfigurationService>();
        builder.Services.AddHostedService<ConfigurationReloadService>();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<WafEngineHolder>();
        builder.Services.AddSingleton<IWafEventSink, LoggingWafEventSink>();
        builder.Services.AddSingleton<InMemoryAcmeChallengeStore>();
        builder.Services.AddSingleton<IAcmeChallengeStore>(sp => sp.GetRequiredService<InMemoryAcmeChallengeStore>());
        builder.Services.AddWafProxy(gatewayConfiguration.Routes, configTag);

        var endpoints = builder.Configuration
            .GetSection(GatewayEndpointOptions.SectionName)
            .Get<GatewayEndpointOptions>() ?? new GatewayEndpointOptions();

        var errors = endpoints.Validate();
        if (errors.Count > 0)
        {
            throw new OptionsValidationException(
                GatewayEndpointOptions.SectionName, typeof(GatewayEndpointOptions), errors);
        }

        builder.WebHost.ConfigureKestrel(kestrel => KestrelListeners.Configure(kestrel, endpoints));

        var app = builder.Build();

        LogBootstrap(app.Logger, bootstrap, storagePaths);
        ActivateWafEngine(app, gatewayConfiguration, configTag);

        var classifier = app.Services.GetRequiredService<ListenerClassifier>();
        app.MapWhen(classifier.IsAdminListener, AdminPipeline.Configure);
        PublicPipeline.Configure(app);

        return app;
    }

    public static async Task<int> RunAsync(string[] args)
    {
        WebApplication app;
        try
        {
            app = Build(args);
        }
        catch (OptionsValidationException ex)
        {
            await Console.Error.WriteLineAsync($"{ProductInfo.Name} configuration error: {ex.Message}").ConfigureAwait(false);
            return StartupFailureExitCode;
        }
        catch (StorageInitializationException ex)
        {
            await Console.Error.WriteLineAsync($"{ProductInfo.Name} could not start. {ex.Message}").ConfigureAwait(false);
            return StartupFailureExitCode;
        }

        await using (app.ConfigureAwait(false))
        {
            // Start and wait separately (not RunAsync): RunAsync disposes the host, including its
            // loggers, before a startup exception reaches us.
            try
            {
                await app.StartAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (StartupErrorReporter.TryDescribe(ex, OperatingSystem.IsWindows(), out var message))
            {
                LogStartupFailed(app.Logger, ex, ProductInfo.Name, message);
                return StartupFailureExitCode;
            }

            await app.WaitForShutdownAsync().ConfigureAwait(false);
            return 0;
        }
    }

    /// <summary>
    /// Resolves the data and config folders and loads the administrator's <c>appsettings.json</c> from the
    /// config folder (e.g. <c>/etc/wafgateway</c>). It overrides the built-in appsettings files but not
    /// environment variables or command-line arguments, so those can still override it.
    /// </summary>
    private static StoragePaths ConfigureStorage(WebApplicationBuilder builder)
    {
        var contentRoot = builder.Environment.ContentRootPath;
        var configDirectory = StoragePaths.Resolve(
            builder.Configuration.GetSection(StorageOptions.SectionName).Get<StorageOptions>(), contentRoot).ConfigDirectory;
        var settingsFile = Path.Combine(configDirectory, StoragePaths.SettingsFileName);

        if (File.Exists(settingsFile))
        {
            var sources = builder.Configuration.Sources;
            var lastJson = sources.Select((source, index) => (source, index)).LastOrDefault(s => s.source is JsonConfigurationSource).index;
            var source = new JsonConfigurationSource { Path = settingsFile, Optional = true, ReloadOnChange = true };
            source.ResolveFileProvider();
            sources.Insert(lastJson + 1, source);
        }

        // Resolve again: the administrator file may itself set Gateway:Storage:DataDirectory.
        return StoragePaths.Resolve(builder.Configuration.GetSection(StorageOptions.SectionName).Get<StorageOptions>(), contentRoot);
    }

    /// <summary>
    /// Builds the WAF engine. If that fails, the gateway still starts but fails closed: the admin UI is
    /// reachable to fix the configuration and public traffic gets 503.
    /// </summary>
    private static void ActivateWafEngine(WebApplication app, GatewayConfiguration configuration, string configTag)
    {
        var holder = app.Services.GetRequiredService<WafEngineHolder>();
        try
        {
            holder.Activate(WafEngine.Build(configuration, app.Services.GetRequiredService<TimeProvider>(), configTag));
        }
#pragma warning disable CA1031 // Any failure must leave the gateway closed, not crashed or open.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            holder.MarkUnavailable($"The WAF engine could not be built: {ex.Message}");
            LogEngineUnavailable(app.Logger, ex);
        }
    }

    private static void LogBootstrap(ILogger logger, BootstrapResult bootstrap, StoragePaths paths)
    {
        if (bootstrap.UsesLastKnownGood)
        {
            LogUsingLastKnownGood(logger, bootstrap.Version.Version, string.Join(" ", bootstrap.RejectedErrors));
        }
        else if (bootstrap.Created)
        {
            LogVersionStored(logger, bootstrap.Version.Version, paths.ConfigDatabasePath);
        }
        else
        {
            LogVersionUnchanged(logger, bootstrap.Version.Version);
        }
    }

    [LoggerMessage(EventId = 10, Level = LogLevel.Information, Message = "Configuration stored as version {Version} in {DatabasePath}.")]
    private static partial void LogVersionStored(ILogger logger, long version, string databasePath);

    [LoggerMessage(EventId = 11, Level = LogLevel.Information, Message = "Configuration unchanged since version {Version}.")]
    private static partial void LogVersionUnchanged(ILogger logger, long version);

    [LoggerMessage(EventId = 12, Level = LogLevel.Critical,
        Message = "The configuration in appsettings is invalid and was NOT activated; running the last-known-good version {Version} instead. Errors: {Errors}")]
    private static partial void LogUsingLastKnownGood(ILogger logger, long version, string errors);

    [LoggerMessage(EventId = 2, Level = LogLevel.Critical, Message = "The WAF engine could not be built; public traffic is refused with 503 until the configuration is fixed.")]
    private static partial void LogEngineUnavailable(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 1, Level = LogLevel.Critical, Message = "{ProductName} could not start. {Reason}")]
    private static partial void LogStartupFailed(ILogger logger, Exception exception, string productName, string reason);
}
