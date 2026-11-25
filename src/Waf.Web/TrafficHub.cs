using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Web;

/// <summary>
/// Live traffic numbers for the dashboards, pushed once a second (SignalR). Mapped on the admin listener only, for
/// signed-in admins; the broadcaster (<see cref="LiveTrafficBroadcaster"/>) does the work.
/// </summary>
/// <remarks>
/// A client calls <see cref="Watch"/> with a route name (or nothing, for all traffic) and then receives
/// <c>snapshot</c> messages (<see cref="LiveTrafficSnapshot"/>) every second, and <c>sessionEnded</c> when its
/// session ends (sign-out elsewhere, password change, expiry), after which the connection is closed.
/// </remarks>
[Authorize]
public sealed class TrafficHub(LiveTrafficBroadcaster broadcaster) : Hub
{
    /// <summary>Path of the hub on the admin listener.</summary>
    public const string Path = "/hubs/traffic";

    /// <summary>Longest message a client may send (it only ever calls <see cref="Watch"/>).</summary>
    public const long MaxMessageBytes = 4 * 1024;

    public override async Task OnConnectedAsync()
    {
        // The authentication middleware checked the cookie of the request that opened the connection; its ticket says
        // when the session expires.
        var result = Context.GetHttpContext()?.Features.Get<Microsoft.AspNetCore.Authentication.IAuthenticateResultFeature>()?.AuthenticateResult;
        if (result is not { Succeeded: true, Principal: { } principal, Properties: { } properties })
        {
            Context.Abort();
            return;
        }

        broadcaster.Connect(Context, principal, properties);
        await base.OnConnectedAsync().ConfigureAwait(false);
    }

    /// <summary>Receive the live numbers of <paramref name="route"/>, or of all traffic when it is empty.</summary>
    public Task Watch(string? route) => broadcaster.WatchAsync(Context.ConnectionId, route);

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        broadcaster.Disconnect(Context.ConnectionId);
        await base.OnDisconnectedAsync(exception).ConfigureAwait(false);
    }

    /// <summary>
    /// Refuses requests to the hub from another site: a browser sends an <c>Origin</c> header with cross-origin
    /// requests and WebSocket handshakes, and it must be this admin address. (The session cookie is
    /// <c>SameSite=Strict</c> too, so another site's page cannot use it anyway.)
    /// </summary>
    public static bool IsSameOrigin(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var origin = request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin))
        {
            return true; // not a browser's cross-origin request (the cookie is still required)
        }

        return Uri.TryCreate(origin, UriKind.Absolute, out var uri)
            && string.Equals(uri.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(uri.Authority, request.Host.Value, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>Registration of the live traffic hub.</summary>
public static class TrafficHubExtensions
{
    /// <summary>SignalR for the hub: small messages only, no detailed errors, enum values as names.</summary>
    public static IServiceCollection AddLiveTraffic(this IServiceCollection services)
    {
        services.AddSignalR(options =>
            {
                options.MaximumReceiveMessageSize = TrafficHub.MaxMessageBytes;
                options.EnableDetailedErrors = false;
            })
            .AddJsonProtocol(options => options.PayloadSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter()));
        services.AddSingleton<LiveTraffic>();
        services.AddSingleton<LiveTrafficBroadcaster>();
        services.AddHostedService(sp => sp.GetRequiredService<LiveTrafficBroadcaster>());
        return services;
    }

    /// <summary>Maps the hub (WebSockets, falling back to Server-Sent Events and long polling).</summary>
    public static IEndpointConventionBuilder MapLiveTraffic(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return endpoints.MapHub<TrafficHub>(TrafficHub.Path, options =>
            options.Transports = HttpTransportType.WebSockets | HttpTransportType.ServerSentEvents | HttpTransportType.LongPolling);
    }

    /// <summary>Answers 403 to a request for the hub from another site (see <see cref="TrafficHub.IsSameOrigin"/>).</summary>
    public static IApplicationBuilder UseLiveTrafficOriginCheck(this IApplicationBuilder app) =>
        app.Use((context, next) =>
        {
            if (context.Request.Path.StartsWithSegments(TrafficHub.Path, StringComparison.OrdinalIgnoreCase) && !TrafficHub.IsSameOrigin(context.Request))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            }

            return next(context);
        });
}

/// <summary>
/// Sends the live traffic snapshot to every watching dashboard once a second, and closes connections whose session
/// ended. One snapshot is built per watched view (all traffic, or one route), not per viewer; with nobody watching,
/// nothing is counted or built.
/// </summary>
public sealed partial class LiveTrafficBroadcaster(
    LiveTraffic live,
    IHubContext<TrafficHub> hub,
    IServiceScopeFactory scopes,
    TimeProvider time,
    ILogger<LiveTrafficBroadcaster> logger) : BackgroundService
{
    /// <summary>How often the sessions of connected dashboards are checked.</summary>
    public static readonly TimeSpan DefaultRevalidateInterval = TimeSpan.FromSeconds(10);

    /// <summary>Most seconds sent at once after a pause (for example a slow machine).</summary>
    private const int MaxCatchUpSeconds = 5;

    private const string AllGroup = "all";

    private readonly ConcurrentDictionary<string, Viewer> _viewers = new(StringComparer.Ordinal);
    private readonly List<LiveSourceHit> _sourceWindow = [];
    private readonly Dictionary<long, List<TrafficCount>> _pending = [];
    private readonly SemaphoreSlim _tickLock = new(1, 1);
    private long _lastSent;
    private long _snapshotsBuilt;
    private DateTimeOffset _lastRevalidation;

    /// <summary>How often sessions are checked; shorter in tests.</summary>
    public TimeSpan RevalidateInterval { get; set; } = DefaultRevalidateInterval;

    /// <summary>Snapshots built since start (for tests and diagnostics).</summary>
    public long SnapshotsBuilt => Interlocked.Read(ref _snapshotsBuilt);

    /// <summary>Connected dashboards.</summary>
    public int Viewers => _viewers.Count;

    internal void Connect(HubCallerContext context, ClaimsPrincipal principal, AuthenticationProperties properties) =>
        _viewers[context.ConnectionId] = new Viewer(context, principal, properties);

    internal async Task WatchAsync(string connectionId, string? route)
    {
        if (route is { Length: > TrafficClassifier.MaxNameLength } || (route is not null && route.Any(char.IsControl)))
        {
            throw new HubException("Unknown route.");
        }

        if (!_viewers.TryGetValue(connectionId, out var viewer))
        {
            return;
        }

        var group = string.IsNullOrEmpty(route) ? AllGroup : "route:" + route;
        if (viewer.Group is { } previous)
        {
            await hub.Groups.RemoveFromGroupAsync(connectionId, previous).ConfigureAwait(false);
        }
        else
        {
            live.AddWatcher();
        }

        viewer.Group = group;
        viewer.Route = string.IsNullOrEmpty(route) ? null : route;
        await hub.Groups.AddToGroupAsync(connectionId, group).ConfigureAwait(false);
    }

    internal void Disconnect(string connectionId)
    {
        if (_viewers.TryRemove(connectionId, out var viewer) && viewer.Group is not null)
        {
            live.RemoveWatcher();
        }
    }

    /// <summary>Builds and sends the snapshots of the seconds completed since the last tick. Used by the loop and by tests.</summary>
    public async Task TickAsync(CancellationToken cancellationToken)
    {
        await _tickLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await TickCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _tickLock.Release();
        }
    }

    public override void Dispose()
    {
        _tickLock.Dispose();
        base.Dispose();
    }

    private async Task TickCoreAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        if (now - _lastRevalidation >= RevalidateInterval)
        {
            _lastRevalidation = now;
            await RevalidateAsync(now, cancellationToken).ConfigureAwait(false);
        }

        var current = now.ToUnixTimeSeconds();
        if (!live.IsWatched)
        {
            _lastSent = 0;
            _sourceWindow.Clear();
            _pending.Clear();
            return;
        }

        var (counts, sources) = live.TakeCompleted(current);
        foreach (var count in counts)
        {
            if (!_pending.TryGetValue(count.BucketStart, out var list))
            {
                _pending[count.BucketStart] = list = [];
            }

            list.Add(count);
        }

        _sourceWindow.AddRange(sources);
        _sourceWindow.RemoveAll(s => s.Second <= current - (long)LiveTraffic.SourceWindow.TotalSeconds - 1);

        var first = Math.Max(_lastSent + 1, current - MaxCatchUpSeconds);
        var groups = _viewers.Values.Select(v => (v.Group, v.Route)).Where(g => g.Group is not null).Distinct().ToList();
        for (var second = first; second < current; second++)
        {
            var secondCounts = _pending.Remove(second, out var list) ? list : [];
            foreach (var (group, route) in groups)
            {
                var snapshot = LiveTraffic.Build(second, route, secondCounts, _sourceWindow);
                Interlocked.Increment(ref _snapshotsBuilt);
                await hub.Clients.Group(group!).SendAsync("snapshot", snapshot, cancellationToken).ConfigureAwait(false);
            }
        }

        _lastSent = current - 1;
        foreach (var old in _pending.Keys.Where(s => s < current - MaxCatchUpSeconds).ToList())
        {
            _pending.Remove(old);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1), time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await TickAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    LogTickFailed(logger, ex);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Shutting down.
        }
    }

    /// <summary>Closes the connections whose session ended: expired, too old, or ended by a password or security change.</summary>
    private async Task RevalidateAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (_viewers.IsEmpty)
        {
            return;
        }

        await using var scope = scopes.CreateAsyncScope();
        var signIn = scope.ServiceProvider.GetRequiredService<SignInManager<IdentityUser>>();
        foreach (var (connectionId, viewer) in _viewers)
        {
            var ended = viewer.Properties.ExpiresUtc is { } expires && expires <= now
                || AdminIdentity.IsSessionExpired(viewer.Properties, now)
                || await signIn.ValidateSecurityStampAsync(viewer.Principal).ConfigureAwait(false) is null;
            if (!ended)
            {
                continue;
            }

            LogSessionEnded(logger, viewer.Principal.Identity?.Name ?? "?");
            try
            {
                await hub.Clients.Client(connectionId).SendAsync("sessionEnded", cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                viewer.Context.Abort();
                Disconnect(connectionId);
            }
        }
    }

    [LoggerMessage(EventId = 430, Level = LogLevel.Information, Message = "Live traffic: closed a dashboard connection of {User} because the session ended.")]
    private static partial void LogSessionEnded(ILogger logger, string user);

    [LoggerMessage(EventId = 431, Level = LogLevel.Warning, Message = "Live traffic: sending the snapshot failed; trying again next second.")]
    private static partial void LogTickFailed(ILogger logger, Exception exception);

    private sealed class Viewer(HubCallerContext context, ClaimsPrincipal principal, AuthenticationProperties properties)
    {
        public HubCallerContext Context { get; } = context;

        public ClaimsPrincipal Principal { get; } = principal;

        public AuthenticationProperties Properties { get; } = properties;

        public string? Group { get; set; }

        public string? Route { get; set; }
    }
}
