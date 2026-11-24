namespace FASoft.Waf.Core.Routing;

/// <summary>A route whose primary destinations are all down, so its traffic goes to a failover destination.</summary>
/// <param name="RouteName">The route.</param>
/// <param name="Failover">The failover number in use (1 is tried first).</param>
/// <param name="Destinations">The failover destination(s) in use, as the request log shows them.</param>
/// <param name="Since">When the route switched to its failover.</param>
public sealed record RouteFailoverStatus(string RouteName, int Failover, string Destinations, DateTimeOffset Since);

/// <summary>Which routes run on a failover destination right now (runtime state, never configuration).</summary>
public interface IRouteFailoverMonitor
{
    /// <summary>The routes on a failover destination; empty when every route runs on its primaries.</summary>
    IReadOnlyList<RouteFailoverStatus> Statuses { get; }
}

/// <summary>For hosts without a proxy (and tests): no route is ever on failover.</summary>
public sealed class NoRouteFailover : IRouteFailoverMonitor
{
    public static NoRouteFailover Instance { get; } = new();

    public IReadOnlyList<RouteFailoverStatus> Statuses => [];
}

/// <summary>How often a route's requests got an error because no backend answered, since the gateway started.</summary>
/// <param name="RouteName">The route.</param>
/// <param name="NoBackend">503: no healthy backend.</param>
/// <param name="BackendError">502: the connection failed or the answer was invalid.</param>
/// <param name="Timeout">504: the backend did not answer in time.</param>
/// <param name="Last">When the last of them happened.</param>
public sealed record RouteBackendErrors(string RouteName, long NoBackend, long BackendError, long Timeout, DateTimeOffset Last);

/// <summary>Backend errors per route since the gateway started (runtime state).</summary>
public interface IBackendErrorStatistics
{
    /// <summary>Routes with at least one backend error, by name.</summary>
    IReadOnlyList<RouteBackendErrors> Routes { get; }
}
