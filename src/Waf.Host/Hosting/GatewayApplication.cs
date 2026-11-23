using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using FASoft.Waf.Core;
using FASoft.Waf.Core.Hosting;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Engine;
using FASoft.Waf.Core.Configuration;
using Microsoft.Extensions.Configuration.Json;
using FASoft.Waf.Data;
using FASoft.Waf.Proxy;
using FASoft.Waf.Web;

namespace FASoft.Waf.Host.Hosting;

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
        if (bootstrap.Notice is not null)
        {
            configurationStatus.SetNotice(bootstrap.Notice);
        }

        builder.Services.AddSingleton<IServerCertificateSelector, NoServerCertificateSelector>();
        builder.Services.AddSingleton<ListenerClassifier>();
        builder.Services.AddRazorComponents();
        builder.Services.AddAdminIdentity(storagePaths);
        AddDataProtection(builder, storagePaths);
        builder.Services.AddHealthChecks().AddCheck<WafEngineHealthCheck>("waf-engine");
        builder.Services.AddSingleton(storagePaths);
        builder.Services.AddSingleton(store);
        builder.Services.AddSingleton(AuditLogStore.Create(storagePaths, TimeProvider.System));
        builder.Services.AddSingleton(configurationStatus);
        builder.Services.AddSingleton<GatewayConfigurationService>();
        builder.Services.AddSingleton<FASoft.Waf.Web.IGatewayConfigurationService>(sp => sp.GetRequiredService<GatewayConfigurationService>());
        builder.Services.AddHostedService<AppSettingsWatcher>();
        builder.Services.AddHostedService<StoreChangeWatcher>();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<WafEngineHolder>();
        builder.Services.AddSingleton<IWafEventSink, LoggingWafEventSink>();
        AddRequestLog(builder, storagePaths);
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
    /// <summary>
    /// Keys that protect the sign-in cookie and antiforgery tokens, kept in the data folder so a restart does not
    /// sign the admin out. On Windows they are encrypted with DPAPI for the service account.
    /// </summary>
    private static void AddDataProtection(WebApplicationBuilder builder, StoragePaths paths)
    {
        var dataProtection = builder.Services
            .AddDataProtection()
            .SetApplicationName(ServiceName)
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(paths.DataDirectory, KeysDirectoryName)));
        if (OperatingSystem.IsWindows())
        {
            dataProtection.ProtectKeysWithDpapi();
        }
    }

    /// <summary>Folder in the data folder with the data protection keys.</summary>
    public const string KeysDirectoryName = "keys";

    /// <summary>The request log (events.db), or a log that discards everything when it is switched off.</summary>
    private static void AddRequestLog(WebApplicationBuilder builder, StoragePaths paths)
    {
        // The viewer reads events.db whether or not new requests are logged.
        builder.Services.AddSingleton(new RequestLogReader(paths));

        // Retention runs whether or not new requests are logged, so an existing events.db stays within its limits.
        builder.Services.AddSingleton(new RequestLogMaintenance(paths));
        builder.Services.AddSingleton<LogRetentionService>();
        builder.Services.AddSingleton<FASoft.Waf.Web.ILogRetention>(sp => sp.GetRequiredService<LogRetentionService>());
        builder.Services.AddHostedService(sp => sp.GetRequiredService<LogRetentionService>());

        var options = builder.Configuration.GetSection(EventLogOptions.SectionName).Get<EventLogOptions>() ?? new EventLogOptions();
        var errors = options.Validate();
        if (errors.Count > 0)
        {
            throw new OptionsValidationException(EventLogOptions.SectionName, typeof(EventLogOptions), errors);
        }

        if (!options.Enabled)
        {
            builder.Services.AddSingleton<NullRequestLog>();
            builder.Services.AddSingleton<IRequestLog>(sp => sp.GetRequiredService<NullRequestLog>());
            builder.Services.AddSingleton<IRequestLogMonitor>(sp => sp.GetRequiredService<NullRequestLog>());
            return;
        }

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<IRequestLogStore>(new SqliteRequestLogStore(paths));
        builder.Services.AddSingleton<RequestLogWriter>();
        builder.Services.AddSingleton<IRequestLog>(sp => sp.GetRequiredService<RequestLogWriter>());
        builder.Services.AddSingleton<IRequestLogMonitor>(sp => sp.GetRequiredService<RequestLogWriter>());
        builder.Services.AddHostedService(sp => sp.GetRequiredService<RequestLogWriter>());
    }

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
        if (bootstrap.Seeded)
        {
            LogVersionStored(logger, bootstrap.Version.Version, paths.ConfigDatabasePath);
        }
        else
        {
            LogRunningStoredVersion(logger, bootstrap.Version.Version);
        }

        if (bootstrap.Notice is { } notice)
        {
            LogAppSettingsIgnored(logger, notice.CanImport ? "valid" : "not valid");
        }
    }

    [LoggerMessage(EventId = 10, Level = LogLevel.Information, Message = "First start: configuration from appsettings stored as version {Version} in {DatabasePath}.")]
    private static partial void LogVersionStored(ILogger logger, long version, string databasePath);

    [LoggerMessage(EventId = 11, Level = LogLevel.Information, Message = "Running configuration version {Version} from the configuration database.")]
    private static partial void LogRunningStoredVersion(ILogger logger, long version);

    [LoggerMessage(EventId = 12, Level = LogLevel.Warning,
        Message = "The Gateway section in appsettings was edited ({Validity}). It is NOT applied: the configuration database is the source of truth. Import or dismiss the change in the admin UI.")]
    private static partial void LogAppSettingsIgnored(ILogger logger, string validity);

    [LoggerMessage(EventId = 2, Level = LogLevel.Critical, Message = "The WAF engine could not be built; public traffic is refused with 503 until the configuration is fixed.")]
    private static partial void LogEngineUnavailable(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 1, Level = LogLevel.Critical, Message = "{ProductName} could not start. {Reason}")]
    private static partial void LogStartupFailed(ILogger logger, Exception exception, string productName, string reason);
}
