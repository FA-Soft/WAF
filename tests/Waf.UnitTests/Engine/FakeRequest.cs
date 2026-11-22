using System.Net;
using Waf.Engine;

namespace Waf.UnitTests.Engine;

/// <summary>Simple in-memory request for engine tests.</summary>
internal sealed record FakeRequest : IWafRequest
{
    public IPAddress ClientIp { get; init; } = IPAddress.Parse("198.51.100.20");
    public string Host { get; init; } = "www.example.com";
    public string Path { get; init; } = "/";
    public string QueryString { get; init; } = string.Empty;
    public string Method { get; init; } = "GET";
    public string? RouteName { get; init; } = "website";
    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);

    public string? GetHeader(string name) => Headers.TryGetValue(name, out var value) ? value : null;

    public static FakeRequest From(string ip) => new() { ClientIp = IPAddress.Parse(ip) };
}
