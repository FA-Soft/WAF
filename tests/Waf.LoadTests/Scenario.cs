using System.Net;
using System.Text;

namespace FASoft.Waf.LoadTests;

/// <summary>One kind of request, sent over and over: what it is, and the answer it must get.</summary>
internal sealed record Scenario(string Name, string Description, HttpMethod Method, string PathAndQuery, byte[]? JsonBody, HttpStatusCode Expected)
{
    /// <summary>A normal page request: forwarded to the backend after the rules and detectors found nothing.</summary>
    public static readonly Scenario Clean = new(
        "clean", "GET, clean", HttpMethod.Get, "/api/items/42?sort=name&page=2&q=blue+shoes", null, HttpStatusCode.OK);

    /// <summary>An API call with a 2 KB JSON body (inspected when the gateway inspects bodies).</summary>
    public static readonly Scenario Post = new(
        "post", "POST, 2 KB JSON", HttpMethod.Post, "/api/items", JsonPayload(), HttpStatusCode.OK);

    /// <summary>SQL injection in the query string: blocked by the gateway (403), never reaches the backend.</summary>
    public static readonly Scenario Attack = new(
        "attack", "GET, SQL injection (blocked)", HttpMethod.Get, "/api/items?id=1%27%20OR%20%271%27%3D%271", null, HttpStatusCode.Forbidden);

    public static readonly IReadOnlyList<Scenario> All = [Clean, Post, Attack];

    public static Scenario Find(string name) =>
        All.FirstOrDefault(s => string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase))
        ?? throw new ArgumentException($"Unknown scenario '{name}'. Known: {string.Join(", ", All.Select(s => s.Name))}.");

    /// <summary>The same request with the answer a backend gives (it blocks nothing).</summary>
    public Scenario Direct() => this with { Expected = HttpStatusCode.OK };

    public HttpRequestMessage CreateRequest(Uri baseUrl, string? host)
    {
        var request = new HttpRequestMessage(Method, new Uri(baseUrl, PathAndQuery));
        request.Headers.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) waf-loadtest");
        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/html;q=0.9");
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-GB,en;q=0.8");
        if (host is not null)
        {
            request.Headers.Host = host;
        }

        if (JsonBody is not null)
        {
            request.Content = new ByteArrayContent(JsonBody);
            request.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json");
        }

        return request;
    }

    private static byte[] JsonPayload()
    {
        var json = new StringBuilder("{\"order\":\"A-10042\",\"customer\":{\"name\":\"Jane Example\",\"email\":\"jane@example.com\"},\"lines\":[");
        for (var i = 0; json.Length < 2000; i++)
        {
            json.Append(i == 0 ? string.Empty : ",")
                .Append("{\"sku\":\"SKU-").Append(1000 + i).Append("\",\"quantity\":").Append(i % 5 + 1)
                .Append(",\"note\":\"Please deliver to the back door, thank you.\"}");
        }

        return Encoding.UTF8.GetBytes(json.Append("]}").ToString());
    }
}
