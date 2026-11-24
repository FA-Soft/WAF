using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.IntegrationTests.Pipeline;

/// <summary>
/// With the backend down, every kind of client gets a clear error in its own format, with the right status, and no
/// internal details; the request log and the dashboard have the details.
/// </summary>
public sealed class BackendErrorTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>
    /// Route "internal-orders" forwards to a closed port of target "secret-box" (502); route "lab-gone" forwards to a
    /// target known only by a MAC address that is not found (503).
    /// </summary>
    private sealed class Gateway : AdminGateway
    {
        public int ClosedPort { get; } = FreePort();

        protected override IEnumerable<string> ExtraArgs =>
        [
            "--Gateway:Targets:0:Name=secret-box",
            "--Gateway:Targets:0:Address=127.0.0.1",
            "--Gateway:Targets:0:Ports:0:Name=web",
            $"--Gateway:Targets:0:Ports:0:Port={ClosedPort.ToString(CultureInfo.InvariantCulture)}",
            "--Gateway:Targets:1:Name=lab",
            "--Gateway:Targets:1:MacAddress=aa:bb:cc:dd:ee:01",
            "--Gateway:Targets:1:Ports:0:Name=web",
            "--Gateway:Targets:1:Ports:0:Port=8080",
            "--Gateway:TargetResolver:Enabled=false",
            "--Gateway:Routes:0:Name=internal-orders",
            "--Gateway:Routes:0:Match:Hosts:0=orders.example.com",
            "--Gateway:Routes:0:Destinations:0:Target=secret-box",
            "--Gateway:Routes:0:Destinations:0:TargetPort=web",
            "--Gateway:Routes:1:Name=lab-gone",
            "--Gateway:Routes:1:Match:Hosts:0=lab.example.com",
            "--Gateway:Routes:1:Destinations:0:Target=lab",
            "--Gateway:Routes:1:Destinations:0:TargetPort=web",
            "--Gateway:Routes:1:ErrorMessage=Planned maintenance until 14:00",
        ];

        public async Task<HttpResponseMessage> SendAsync(string host, HttpMethod method, string? accept = null, string? contentType = null, string? soapAction = null)
        {
            using var request = new HttpRequestMessage(method, new Uri($"http://127.0.0.1:{HttpPort}/service"));
            request.Headers.Host = host;
            if (accept is not null)
            {
                request.Headers.TryAddWithoutValidation("Accept", accept);
            }

            if (soapAction is not null)
            {
                request.Headers.TryAddWithoutValidation("SOAPAction", soapAction);
            }

            if (contentType is not null)
            {
                request.Content = new StringContent("<x/>");
                request.Content.Headers.Remove("Content-Type");
                request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            }

            return await Public.SendAsync(request, Ct);
        }

        public async Task<List<RequestEvent>> LogAsync(int count)
        {
            var options = new DbContextOptionsBuilder<EventDbContext>()
                .UseSqlite(SqliteRequestLogStore.ConnectionString(new StoragePaths(DataDirectory, DataDirectory)))
                .Options;
            for (var attempt = 0; ; attempt++)
            {
                await using var db = new EventDbContext(options);
                var rows = await db.RequestEvents.AsNoTracking().OrderBy(e => e.Id).ToListAsync(Ct);
                if (rows.Count >= count || attempt > 100)
                {
                    return rows;
                }

                await Task.Delay(50, Ct);
            }
        }
    }

    /// <summary>Nothing in an error response may name the backend, its port, the route or the target.</summary>
    private static void AssertNoInternals(Gateway gateway, string body)
    {
        foreach (var secret in new[] { "127.0.0.1", gateway.ClosedPort.ToString(CultureInfo.InvariantCulture), "internal-orders", "lab-gone", "secret-box", "Exception", "refused" })
        {
            Assert.DoesNotContain(secret, body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Every_kind_of_client_gets_a_clear_error_in_its_format_without_internals()
    {
        await using var gateway = new Gateway();
        await gateway.InitializeAsync();

        // A browser: the HTML page, 502.
        using (var browser = await gateway.SendAsync("orders.example.com", HttpMethod.Get, accept: "text/html,application/xhtml+xml,*/*;q=0.8"))
        {
            var body = await browser.Content.ReadAsStringAsync(Ct);
            Assert.Equal(HttpStatusCode.BadGateway, browser.StatusCode);
            Assert.Equal("text/html", browser.Content.Headers.ContentType!.MediaType);
            Assert.True(browser.Headers.CacheControl!.NoStore);
            Assert.Contains("This site is temporarily unavailable.", body, StringComparison.Ordinal);
            AssertNoInternals(gateway, body);
        }

        // A JSON client: problem+json, 503 with Retry-After and the route's message.
        string requestId;
        using (var json = await gateway.SendAsync("lab.example.com", HttpMethod.Get, accept: "application/json"))
        {
            var body = await json.Content.ReadAsStringAsync(Ct);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, json.StatusCode);
            Assert.Equal("application/problem+json", json.Content.Headers.ContentType!.MediaType);
            Assert.Equal(TimeSpan.FromSeconds(30), json.Headers.RetryAfter!.Delta);
            var problem = JsonElement.Parse(body);
            Assert.Equal((503, "Planned maintenance until 14:00"), (problem.GetProperty("status").GetInt32(), problem.GetProperty("message").GetString()));
            requestId = problem.GetProperty("requestId").GetString()!;
            AssertNoInternals(gateway, body);
        }

        // An XML client: problem+xml.
        using (var xml = await gateway.SendAsync("orders.example.com", HttpMethod.Get, accept: "application/xml"))
        {
            var body = await xml.Content.ReadAsStringAsync(Ct);
            Assert.Equal(HttpStatusCode.BadGateway, xml.StatusCode);
            Assert.Equal("application/problem+xml", xml.Content.Headers.ContentType!.MediaType);
            Assert.Equal("502", XDocument.Parse(body).Root!.Element(XName.Get("status", "urn:ietf:rfc:7807"))!.Value);
            AssertNoInternals(gateway, body);
        }

        // SOAP 1.1 and 1.2 clients: HTTP 500 with a Fault, the gateway's status in its detail.
        using (var soap11 = await gateway.SendAsync("orders.example.com", HttpMethod.Post, contentType: "text/xml; charset=utf-8", soapAction: "\"urn:orders/Get\""))
        {
            var body = await soap11.Content.ReadAsStringAsync(Ct);
            Assert.Equal(HttpStatusCode.InternalServerError, soap11.StatusCode);
            Assert.Contains("<faultcode>soap:Server</faultcode>", body, StringComparison.Ordinal);
            Assert.Contains("<gw:status>502</gw:status>", body, StringComparison.Ordinal);
            AssertNoInternals(gateway, body);
        }

        using (var soap12 = await gateway.SendAsync("lab.example.com", HttpMethod.Post, contentType: "application/soap+xml; charset=utf-8"))
        {
            var body = await soap12.Content.ReadAsStringAsync(Ct);
            Assert.Equal(HttpStatusCode.InternalServerError, soap12.StatusCode);
            Assert.Equal("application/soap+xml", soap12.Content.Headers.ContentType!.MediaType);
            Assert.Contains("<env:Value>env:Receiver</env:Value>", body, StringComparison.Ordinal);
            Assert.Contains("<gw:status>503</gw:status>", body, StringComparison.Ordinal);
            Assert.True(soap12.Headers.RetryAfter is not null);
            AssertNoInternals(gateway, body);
        }

        // HEAD: the status and headers, no body.
        using (var head = await gateway.SendAsync("lab.example.com", HttpMethod.Head))
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, head.StatusCode);
            Assert.Empty(await head.Content.ReadAsByteArrayAsync(Ct));
        }

        // The details are in the request log, and the dashboard counts the errors per route.
        var rows = await gateway.LogAsync(6);
        var refused = rows.First(r => r.RouteName == "internal-orders");
        Assert.Equal(nameof(RequestAction.BackendUnavailable), refused.Action);
        Assert.StartsWith("Backend error: ", refused.Detail, StringComparison.Ordinal);
        Assert.Contains("secret-box · web", refused.Destination, StringComparison.Ordinal);
        Assert.StartsWith("No backend available (request ID ", rows.First(r => r.RouteName == "lab-gone").Detail, StringComparison.Ordinal);
        Assert.Single(rows, r => r.Detail?.Contains(requestId, StringComparison.Ordinal) == true); // findable by the ID the client got

        var dashboard = await gateway.GetPageAsync("/");
        Assert.Contains("Backend errors since the start", dashboard, StringComparison.Ordinal);
        Assert.Contains("<td>internal-orders</td>", dashboard, StringComparison.Ordinal);
    }
}
