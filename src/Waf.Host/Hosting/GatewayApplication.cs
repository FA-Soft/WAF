using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Waf.Core;
using Waf.Core.Hosting;
using Waf.Core.Net;
using Waf.Core.Tls;
using Waf.Engine;
using Waf.Engine.RateLimiting;
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

        builder.Services.AddSingleton<IServerCertificateSelector, NoServerCertificateSelector>();
        builder.Services.AddSingleton<ListenerClassifier>();
        builder.Services.AddHealthChecks();
        var gatewayConfiguration = GatewayConfigurationLoader.Load(builder.Configuration);
        builder.Services.AddSingleton(gatewayConfiguration);
        builder.Services.AddSingleton(TrustedProxies.Parse(gatewayConfiguration.Settings.TrustedProxies));
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(sp => new RateLimiter(gatewayConfiguration, sp.GetRequiredService<TimeProvider>()));
        builder.Services.AddSingleton<IWafEventSink, LoggingWafEventSink>();
        builder.Services.AddWafProxy(gatewayConfiguration.Routes);

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

    [LoggerMessage(EventId = 1, Level = LogLevel.Critical, Message = "{ProductName} could not start. {Reason}")]
    private static partial void LogStartupFailed(ILogger logger, Exception exception, string productName, string reason);
}
