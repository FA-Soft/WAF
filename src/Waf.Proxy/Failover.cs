using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using FASoft.Waf.Core.Routing;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Model;

namespace FASoft.Waf.Proxy;

/// <summary>Host settings of failover (<c>Gateway:Failover</c>); the defaults suit every site.</summary>
public sealed class FailoverOptions
{
    public const string SectionName = "Gateway:Failover";

    /// <summary>
    /// How long a primary must stay healthy before its traffic returns from the failover, so a primary that keeps
    /// going up and down does not bounce traffic back and forth.
    /// </summary>
    public TimeSpan HoldTime { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long to wait for a connection to a destination of a route with failover destinations; then the request
    /// goes to the next candidate.
    /// </summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>How long a destination that could not be connected to gets no traffic (then it is tried again).</summary>
    public TimeSpan RefusedPeriod { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Chooses where a route with failover destinations sends its traffic: to its healthy primaries; only when none is
/// healthy, to the healthy failover with the lowest number; back to the primaries once one has been healthy for
/// <see cref="FailoverOptions.HoldTime"/>. Decided per request, so the hold time needs no timers.
/// </summary>
public sealed partial class FailoverMonitor(FailoverOptions options, TimeProvider time, ILogger<FailoverMonitor> logger, IProxyStateLookup? proxyState = null)
    : IRouteFailoverMonitor
{
    private readonly ConcurrentDictionary<string, State> _states = new(StringComparer.OrdinalIgnoreCase);

    private sealed class State
    {
        public bool OnFailover { get; set; }

        public int Failover { get; set; }

        public string Destinations { get; set; } = string.Empty;

        public DateTimeOffset Since { get; set; }

        /// <summary>When a primary became healthy again while on failover (the hold time counts from here).</summary>
        public DateTimeOffset? PrimaryBackSince { get; set; }

        /// <summary>True while no destination at all is healthy (logged once).</summary>
        public bool NoneHealthy { get; set; }
    }

    /// <summary>Routes on failover right now. Each route is evaluated again, so this is current without traffic too.</summary>
    public IReadOnlyList<RouteFailoverStatus> Statuses
    {
        get
        {
            if (proxyState is not null)
            {
                foreach (var cluster in proxyState.GetClusters())
                {
                    if (cluster.Model?.Config is { } config && YarpConfigMapper.HasFailover(config))
                    {
                        Choose(cluster.ClusterId, cluster.DestinationsState.AllDestinations);
                    }
                }
            }

            var live = proxyState?.GetClusters().Select(c => c.ClusterId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            return [.. _states
                .Where(pair => live is null || live.Contains(pair.Key))
                .Select(pair => (Route: pair.Key, State: pair.Value))
                .Where(x => x.State.OnFailover)
                .Select(x => new RouteFailoverStatus(x.Route, x.State.Failover, x.State.Destinations, x.State.Since))
                .OrderBy(s => s.RouteName, StringComparer.OrdinalIgnoreCase)];
        }
    }

    /// <summary>True when the destination may get traffic: neither the active nor the passive health check marks it down.</summary>
    public static bool IsHealthy(DestinationState destination)
    {
        ArgumentNullException.ThrowIfNull(destination);
        return destination.Health.Active != DestinationHealth.Unhealthy && destination.Health.Passive != DestinationHealth.Unhealthy;
    }

    /// <summary>
    /// The destinations of route <paramref name="route"/> that get this request: the healthy primaries, or the healthy
    /// failover(s) with the lowest number; empty when nothing is healthy (the request then gets 503).
    /// </summary>
    public IReadOnlyList<DestinationState> Choose(string route, IReadOnlyList<DestinationState> destinations)
    {
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(destinations);

        var primaries = destinations.Where(d => YarpConfigMapper.FailoverOf(d.Model.Config) is null && IsHealthy(d)).ToList();
        var failovers = destinations
            .Where(d => YarpConfigMapper.FailoverOf(d.Model.Config) is not null && IsHealthy(d))
            .GroupBy(d => YarpConfigMapper.FailoverOf(d.Model.Config)!.Value)
            .OrderBy(g => g.Key)
            .ToList();

        var state = _states.GetOrAdd(route, _ => new State());
        lock (state)
        {
            var now = time.GetUtcNow();
            if (primaries.Count > 0)
            {
                state.NoneHealthy = false;
                if (!state.OnFailover)
                {
                    return primaries;
                }

                state.PrimaryBackSince ??= now;
                var current = failovers.FirstOrDefault(g => g.Key == state.Failover);
                if (current is not null && now - state.PrimaryBackSince.Value < options.HoldTime)
                {
                    return [.. current]; // the primary has to prove itself for the hold time first
                }

                state.OnFailover = false;
                state.PrimaryBackSince = null;
                var onFailover = Duration(now - state.Since);
                LogBackOnPrimary(logger, route, onFailover);
                return primaries;
            }

            state.PrimaryBackSince = null;
            var first = failovers.FirstOrDefault();
            if (first is null)
            {
                if (!state.NoneHealthy)
                {
                    state.NoneHealthy = true;
                    LogNoneHealthy(logger, route);
                }

                return [];
            }

            state.NoneHealthy = false;
            var described = string.Join(", ", first.Select(d => YarpConfigMapper.DescribeDestination(d.Model.Config, withFailover: false)));
            if (!state.OnFailover || state.Failover != first.Key)
            {
                if (!state.OnFailover)
                {
                    state.Since = now;
                }

                state.OnFailover = true;
                state.Failover = first.Key;
                LogOnFailover(logger, route, first.Key, described);
            }

            state.Destinations = described;
            return [.. first];
        }
    }

    /// <summary>"45 seconds", "1 minute", "3 hours".</summary>
    internal static string Duration(TimeSpan duration)
    {
        var (amount, unit) = duration.TotalHours >= 1 ? ((int)duration.TotalHours, "hour")
            : duration.TotalMinutes >= 1 ? ((int)duration.TotalMinutes, "minute")
            : ((int)Math.Max(0, duration.TotalSeconds), "second");
        return string.Create(CultureInfo.InvariantCulture, $"{amount} {unit}{(amount == 1 ? string.Empty : "s")}");
    }

    [LoggerMessage(EventId = 900, Level = LogLevel.Warning, Message = "Route '{Route}' switched to failover {Failover} ({Destinations}): no primary destination is healthy.")]
    private static partial void LogOnFailover(ILogger logger, string route, int failover, string destinations);

    [LoggerMessage(EventId = 901, Level = LogLevel.Information, Message = "Route '{Route}' is back on its primary destination after {Duration} on failover.")]
    private static partial void LogBackOnPrimary(ILogger logger, string route, string duration);

    [LoggerMessage(EventId = 902, Level = LogLevel.Warning, Message = "Route '{Route}': no destination is healthy, primary or failover; its requests get 503.")]
    private static partial void LogNoneHealthy(ILogger logger, string route);
}

/// <summary>
/// In the proxy pipeline, before load balancing: lets <see cref="FailoverMonitor"/> choose the destinations of a route
/// with failover destinations, and sends a request again, at once, to the next candidate when the connection to its
/// destination could not be opened. Only then: once sending has started, a request is never repeated (not safe for
/// POST), and the error stands.
/// </summary>
internal sealed partial class FailoverMiddleware(
    RequestDelegate next, FailoverMonitor monitor, IDestinationHealthUpdater health, FailoverOptions options, ILogger<FailoverMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var feature = context.GetReverseProxyFeature();
        var cluster = feature.Route.Cluster;
        var hasFailover = cluster is not null && YarpConfigMapper.HasFailover(feature.Cluster.Config);
        if (hasFailover)
        {
            feature.AvailableDestinations = monitor.Choose(cluster!.ClusterId, feature.AllDestinations);
        }

        if (cluster is null || feature.AllDestinations.Count < 2)
        {
            await next(context).ConfigureAwait(false);
            return; // nowhere else to go
        }

        var candidates = feature.AvailableDestinations;
        List<DestinationState>? refused = null;
        while (true)
        {
            await next(context).ConfigureAwait(false);

            var failed = feature.ProxiedDestination;
            if (failed is null || context.Response.HasStarted || !IsConnectFailure(context.Features.Get<IForwarderErrorFeature>()))
            {
                return;
            }

            // Nothing was sent: skip this destination for a while (health checks will bring it back) and try the next.
            (refused ??= []).Add(failed);
            health.SetPassive(cluster, failed, DestinationHealth.Unhealthy, options.RefusedPeriod);
            var remaining = (hasFailover ? monitor.Choose(cluster.ClusterId, feature.AllDestinations) : candidates)
                .Where(d => !refused.Contains(d))
                .ToList();
            if (remaining.Count == 0)
            {
                return; // the error response stands
            }

            if (logger.IsEnabled(LogLevel.Information))
            {
                var described = YarpConfigMapper.DescribeDestination(failed.Model.Config);
                LogRetried(logger, cluster.ClusterId, described);
            }

            context.Features.Set<IForwarderErrorFeature>(null);
            context.Response.StatusCode = StatusCodes.Status200OK;
            feature.ProxiedDestination = null;
            feature.AvailableDestinations = remaining;
        }
    }

    /// <summary>
    /// True when the connection to the destination could not be opened (refused, unreachable, timed out, unknown host
    /// name): the request never left the gateway, so sending it elsewhere is safe, for POST too.
    /// </summary>
    internal static bool IsConnectFailure(IForwarderErrorFeature? error)
    {
        if (error is not { Error: ForwarderError.Request })
        {
            return false;
        }

        for (var exception = error.Exception; exception is not null; exception = exception.InnerException)
        {
            if (exception is HttpRequestException { HttpRequestError: HttpRequestError.ConnectionError or HttpRequestError.NameResolutionError })
            {
                return true;
            }
        }

        return false;
    }

    [LoggerMessage(EventId = 903, Level = LogLevel.Information, Message = "Route '{Route}': no connection to {Destination}; the request was sent to the next destination.")]
    private static partial void LogRetried(ILogger logger, string route, string destination);
}

/// <summary>
/// YARP's HTTP clients, with a short connect time-out for routes with failover destinations: a primary that does
/// not answer at all sends the request on to the failover after <see cref="FailoverOptions.ConnectTimeout"/>.
/// </summary>
internal sealed class FailoverHttpClientFactory(FailoverOptions options, ILogger<ForwarderHttpClientFactory> logger) : ForwarderHttpClientFactory(logger)
{
    protected override bool CanReuseOldClient(ForwarderHttpClientContext context) =>
        base.CanReuseOldClient(context) && HasFailover(context.OldMetadata) == HasFailover(context.NewMetadata);

    protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        base.ConfigureHandler(context, handler);
        if (HasFailover(context.NewMetadata))
        {
            var timeout = options.ConnectTimeout;
            handler.ConnectCallback = (connection, cancellationToken) => ConnectAsync(connection.DnsEndPoint, timeout, cancellationToken);
        }
    }

    private static bool HasFailover(IReadOnlyDictionary<string, string>? metadata) =>
        metadata?.ContainsKey(YarpConfigMapper.HasFailoverMetadataKey) == true;

    /// <summary>
    /// Opens the connection like the default handler does, but gives up after <paramref name="timeout"/> with a socket
    /// error, which the handler reports as a connection error (so the request may go elsewhere).
    /// </summary>
    internal static async ValueTask<Stream> ConnectAsync(DnsEndPoint endPoint, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            limit.CancelAfter(timeout);
            await socket.ConnectAsync(endPoint, limit.Token).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            socket.Dispose();
            throw new SocketException((int)SocketError.TimedOut);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
