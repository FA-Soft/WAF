using System.Net;

namespace FASoft.Waf.Engine;

/// <summary>
/// The parts of an HTTP request the rule engine looks at. Implemented by an adapter over the real
/// request, so the engine does not depend on ASP.NET Core and needs no copies.
/// </summary>
public interface IWafRequest
{
    /// <summary>Resolved client IP (after trusted-proxy handling).</summary>
    IPAddress ClientIp { get; }

    /// <summary>Host name without port.</summary>
    string Host { get; }

    /// <summary>URL path, e.g. <c>/admin/users</c>.</summary>
    string Path { get; }

    /// <summary>Query string without the leading '?'; empty when there is none.</summary>
    string QueryString { get; }

    /// <summary>HTTP method, e.g. GET.</summary>
    string Method { get; }

    /// <summary>Name of the matched route, or null when no route matched.</summary>
    string? RouteName { get; }

    /// <summary>Header value (multiple values joined by ", "), or null when the header is absent.</summary>
    string? GetHeader(string name);
}
