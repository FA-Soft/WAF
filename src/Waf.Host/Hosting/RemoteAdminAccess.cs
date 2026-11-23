using System.Net;
using FASoft.Waf.Core.Hosting;
using FASoft.Waf.Core.Net;
using FASoft.Waf.Data;
using FASoft.Waf.Web;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Remote admin access: the registered admin URL and allowlist (stored in identity.db, changed in the admin UI or with
/// wafctl), and which requests it applies to. Off unless a URL is registered.
/// </summary>
/// <remarks>
/// The settings are kept as an immutable snapshot, read again every <see cref="RefreshInterval"/> and right after a
/// change in the admin UI, so <c>wafctl admin unregister-url</c> takes effect within seconds while the gateway runs.
/// A request is remote admin when it arrives over HTTPS on the gateway's HTTPS port (or the dedicated port of the
/// URL), and both the TLS server name (SNI) and the Host header are the registered host name.
/// </remarks>
internal sealed partial class RemoteAdminAccess(
    IServiceScopeFactory scopes,
    StoragePaths paths,
    IOptions<GatewayEndpointOptions> endpoints,
    ILogger<RemoteAdminAccess> logger) : IRemoteAdminAccess
{
    /// <summary>How often identity.db is checked for changes made outside the UI (wafctl).</summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

    private Snapshot _current = Snapshot.Off;

    /// <summary>The registered URL and allowlist as last read.</summary>
    public sealed record Snapshot(RemoteAdminUrl? Url, IReadOnlyList<IPNetwork> Allowed)
    {
        public static readonly Snapshot Off = new(null, []);
    }

    public Snapshot Current => Volatile.Read(ref _current);

    /// <summary>The dedicated port opened at startup (from the URL registered then); null when there is none.</summary>
    public int? DedicatedPort { get; init; }

    public int HttpsPort => endpoints.Value.HttpsPort;

    public IReadOnlyCollection<int> ReservedPorts => [endpoints.Value.HttpPort, endpoints.Value.AdminPort];

    public bool IsListening(int port) => port == HttpsPort || port == DedicatedPort;

    /// <summary>The port remote admin requests must arrive on: the URL's port, else the HTTPS port.</summary>
    private int ExpectedPort(RemoteAdminUrl url) => url.Port ?? HttpsPort;

    /// <summary>True for an HTTPS request to the registered host name on its port (see the class remarks).</summary>
    public bool IsRemoteAdmin(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var url = Current.Url;
        return url is not null
            && context.Request.IsHttps
            && context.Connection.LocalPort == ExpectedPort(url)
            && string.Equals(context.Request.Host.Host, url.Host, StringComparison.OrdinalIgnoreCase)
            && string.Equals(context.Features.Get<ITlsHandshakeFeature>()?.HostName, url.Host, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A plain HTTP request for the registered host name: never served (HTTPS only), except Let's Encrypt challenges.</summary>
    public bool IsPlainHttpToAdminHost(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return Current.Url is { } url
            && !context.Request.IsHttps
            && string.Equals(context.Request.Host.Host, url.Host, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Any request on the dedicated port that is not remote admin: it only ever serves the admin UI.</summary>
    public bool IsOtherOnDedicatedPort(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return DedicatedPort is { } port && context.Connection.LocalPort == port && !IsRemoteAdmin(context);
    }

    /// <summary>True when <paramref name="client"/> may use remote access (an empty allowlist allows everyone).</summary>
    public bool IsAllowed(IPAddress client)
    {
        ArgumentNullException.ThrowIfNull(client);
        var allowed = Current.Allowed;
        var address = client.IsIPv4MappedToIPv6 ? client.MapToIPv4() : client;
        return allowed.Count == 0 || allowed.Any(network => network.Contains(address));
    }

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(Path.Combine(paths.DataDirectory, AdminIdentityDbContext.FileName)))
        {
            Volatile.Write(ref _current, Snapshot.Off);
            return;
        }

        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var access = await scope.ServiceProvider.GetRequiredService<AdminAccessStore>().GetAsync(cancellationToken).ConfigureAwait(false);
            var url = access.RemoteUrl is { } text && RemoteAdminUrl.TryParse(text, out var parsed, out _) ? parsed : null;
            var allowed = access.AllowedNetworkList
                .Select(entry => StrictCidr.TryParse(entry, out var network) ? network : (IPNetwork?)null)
                .OfType<IPNetwork>()
                .ToList();
            var previous = Interlocked.Exchange(ref _current, new Snapshot(url, allowed));
            if (previous.Url?.ToString() != url?.ToString())
            {
                LogChanged(logger, url?.ToString() ?? "off");
            }
        }
        catch (SqliteException ex)
        {
            LogRefreshFailed(logger, ex); // e.g. identity.db not migrated yet: keep the last state
        }
    }

    [LoggerMessage(EventId = 700, Level = LogLevel.Warning, Message = "Remote admin access: {Url}.")]
    private static partial void LogChanged(ILogger logger, string url);

    [LoggerMessage(EventId = 701, Level = LogLevel.Error, Message = "Remote admin access settings could not be read; keeping the last ones.")]
    private static partial void LogRefreshFailed(ILogger logger, Exception exception);
}

/// <summary>Reads the remote admin settings at startup and every few seconds (changes made with wafctl).</summary>
internal sealed class RemoteAdminRefresher(RemoteAdminAccess access, TimeProvider time) : BackgroundService
{
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await access.RefreshAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(RemoteAdminAccess.RefreshInterval, time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await access.RefreshAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }
}

/// <summary>
/// First step for remote admin requests: marks them remote and answers clients outside the allowlist with the same
/// empty 404 as an unknown address, so the admin UI cannot be discovered from there.
/// </summary>
internal sealed class RemoteAdminGateMiddleware(RequestDelegate next, RemoteAdminAccess access)
{
    public Task InvokeAsync(HttpContext context)
    {
        RemoteAdminRequest.MarkRemote(context);
        if (context.Connection.RemoteIpAddress is not { } client || !access.IsAllowed(client))
        {
            return GenericNotFound.WriteAsync(context);
        }

        return next(context);
    }
}

/// <summary>
/// After authentication: before signing in, a remote request only reaches the sign-in pages (and their style sheet and
/// script); every other address gets the generic 404, not a redirect that would reveal the admin UI.
/// </summary>
internal sealed class RemoteAdminSignInGateMiddleware(RequestDelegate next)
{
    private static readonly string[] OpenPaths = ["/account/login", "/account/login/two-factor", "/account/login/recovery"];
    private static readonly string[] OpenPrefixes = ["/_content/", "/_framework/"];

    public Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "/";
        var open = OpenPaths.Contains(path.TrimEnd('/'), StringComparer.OrdinalIgnoreCase)
            || OpenPrefixes.Any(prefix => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        if (context.User.Identity?.IsAuthenticated != true && !open)
        {
            return GenericNotFound.WriteAsync(context);
        }

        return next(context);
    }
}

/// <summary>The answer for anything that must not be found: 404, no body, no telling headers (like an unknown host).</summary>
internal static class GenericNotFound
{
    public static Task WriteAsync(HttpContext context)
    {
        context.Response.Headers.Clear();
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        return Task.CompletedTask;
    }

    public static void Run(IApplicationBuilder app) => app.Run(WriteAsync);
}
