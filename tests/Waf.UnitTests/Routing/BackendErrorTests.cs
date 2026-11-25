using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using Microsoft.AspNetCore.Http;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Routing;
using FASoft.Waf.Proxy;
using FASoft.Waf.Web;
using Yarp.ReverseProxy.Forwarder;

namespace FASoft.Waf.UnitTests.Routing;

/// <summary>Error responses when no backend answers: the format per client, the bodies, the headers, the log text.</summary>
public class BackendErrorTests
{
    private static readonly DateTimeOffset At = new(2026, 11, 24, 10, 42, 7, TimeSpan.Zero);

    private static BackendErrorInfo Info(BackendErrorKind kind = BackendErrorKind.NoBackend, string? message = null) =>
        new(kind, "0HNABC:00000001", At, message);

    private static DefaultHttpContext Context(string? accept = null, string? contentType = null, bool soapAction = false, string method = "GET")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        if (accept is not null)
        {
            context.Request.Headers.Accept = accept;
        }

        if (contentType is not null)
        {
            context.Request.ContentType = contentType;
        }

        if (soapAction)
        {
            context.Request.Headers["SOAPAction"] = "\"urn:orders/Get\"";
        }

        context.Response.Body = new MemoryStream();
        return context;
    }

    [Theory]
    [InlineData(null, null, false, ErrorFormat.Html)]
    [InlineData("*/*", null, false, ErrorFormat.Html)]
    [InlineData("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", null, false, ErrorFormat.Html)]
    [InlineData("application/json", null, false, ErrorFormat.ProblemJson)]
    [InlineData("application/vnd.api+json", null, false, ErrorFormat.ProblemJson)]
    [InlineData("text/html;q=0.5, application/json", null, false, ErrorFormat.ProblemJson)]
    [InlineData("*/*", "application/json", false, ErrorFormat.ProblemJson)]
    [InlineData("application/xml", null, false, ErrorFormat.ProblemXml)]
    [InlineData("text/xml", null, false, ErrorFormat.ProblemXml)]
    [InlineData(null, "application/atom+xml", false, ErrorFormat.ProblemXml)]
    [InlineData("text/xml", "text/xml; charset=utf-8", true, ErrorFormat.Soap11)]
    [InlineData(null, "text/xml; charset=utf-8", true, ErrorFormat.Soap11)]
    [InlineData("application/soap+xml", null, false, ErrorFormat.Soap12)]
    [InlineData("*/*", "application/soap+xml; charset=utf-8; action=\"urn:orders/Get\"", false, ErrorFormat.Soap12)]
    [InlineData("text/html", "application/soap+xml", false, ErrorFormat.Soap12)]
    [InlineData("application/json;q=0, text/html", null, false, ErrorFormat.Html)]
    public void The_format_follows_the_request(string? accept, string? contentType, bool soapAction, ErrorFormat expected)
    {
        Assert.Equal(expected, BackendErrorResponses.Negotiate(Context(accept, contentType, soapAction).Request));
    }

    [Theory]
    [InlineData(BackendErrorKind.NoBackend, 503)]
    [InlineData(BackendErrorKind.BackendError, 502)]
    [InlineData(BackendErrorKind.Timeout, 504)]
    public void Soap_faults_use_http_500_and_the_other_formats_the_gateway_status(BackendErrorKind kind, int status)
    {
        Assert.Equal(status, BackendErrorResponses.HttpStatus(ErrorFormat.ProblemJson, Info(kind)));
        Assert.Equal(status, BackendErrorResponses.HttpStatus(ErrorFormat.Html, Info(kind)));
        Assert.Equal(500, BackendErrorResponses.HttpStatus(ErrorFormat.Soap11, Info(kind)));
        Assert.Equal(500, BackendErrorResponses.HttpStatus(ErrorFormat.Soap12, Info(kind)));
    }

    [Fact]
    public void Problem_json_has_the_rfc_9457_members_and_the_request_id()
    {
        var (type, body) = BackendErrorResponses.Render(ErrorFormat.ProblemJson, Info(message: "Planned maintenance until 14:00"));
        var json = JsonElement.Parse(body);

        Assert.Equal("application/problem+json", type);
        Assert.Equal("about:blank", json.GetProperty("type").GetString());
        Assert.Equal("Service Unavailable", json.GetProperty("title").GetString());
        Assert.Equal(503, json.GetProperty("status").GetInt32());
        Assert.StartsWith("No server is available", json.GetProperty("detail").GetString(), StringComparison.Ordinal);
        Assert.Equal("Planned maintenance until 14:00", json.GetProperty("message").GetString());
        Assert.Equal("0HNABC:00000001", json.GetProperty("requestId").GetString());
        Assert.Equal("2026-11-24T10:42:07Z", json.GetProperty("time").GetString());
    }

    [Fact]
    public void Problem_xml_uses_the_rfc_namespace()
    {
        var (type, body) = BackendErrorResponses.Render(ErrorFormat.ProblemXml, Info(BackendErrorKind.Timeout));
        var problem = XDocument.Parse(body).Root!;
        XNamespace ns = "urn:ietf:rfc:7807";

        Assert.Equal("application/problem+xml; charset=utf-8", type);
        Assert.Equal(ns + "problem", problem.Name);
        Assert.Equal(("Gateway Timeout", "504"), (problem.Element(ns + "title")!.Value, problem.Element(ns + "status")!.Value));
        Assert.Null(problem.Element(ns + "message"));
    }

    internal static XmlSchemaSet Schemas(params string[] files)
    {
        var set = new XmlSchemaSet { XmlResolver = null };
        foreach (var file in files)
        {
            using var reader = XmlReader.Create(Path.Combine(AppContext.BaseDirectory, "Routing", "Schemas", file), new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore });
            set.Add(null, reader);
        }

        set.Compile();
        return set;
    }

    internal static XDocument Validated(string body, XmlSchemaSet schemas)
    {
        var document = XDocument.Parse(body);
        var errors = new List<string>();
        document.Validate(schemas, (_, e) => errors.Add(e.Message));
        Assert.Empty(errors);
        return document;
    }

    [Fact]
    public void The_soap_1_1_fault_is_valid_and_carries_the_gateway_status_in_its_detail()
    {
        var (type, body) = BackendErrorResponses.Render(ErrorFormat.Soap11, Info(message: "Back at 14:00"));
        var document = Validated(body, Schemas("soap11-envelope.xsd"));
        XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
        XNamespace gw = BackendErrorResponses.SoapDetailNamespace;
        var fault = document.Root!.Element(soap + "Body")!.Element(soap + "Fault")!;

        Assert.Equal("text/xml; charset=utf-8", type);
        Assert.Equal("soap:Server", fault.Element("faultcode")!.Value);
        Assert.Equal("Service Unavailable: Back at 14:00", fault.Element("faultstring")!.Value);
        var detail = fault.Element("detail")!.Element(gw + "gatewayError")!;
        Assert.Equal(("503", "30", "0HNABC:00000001"), (detail.Element(gw + "status")!.Value, detail.Element(gw + "retryAfterSeconds")!.Value, detail.Element(gw + "requestId")!.Value));
    }

    [Fact]
    public void The_soap_1_2_fault_is_valid_and_carries_the_gateway_status_in_its_detail()
    {
        var (type, body) = BackendErrorResponses.Render(ErrorFormat.Soap12, Info(BackendErrorKind.BackendError));
        var document = Validated(body, Schemas("xml.xsd", "soap12-envelope.xsd"));
        XNamespace env = "http://www.w3.org/2003/05/soap-envelope";
        XNamespace gw = BackendErrorResponses.SoapDetailNamespace;
        var fault = document.Root!.Element(env + "Body")!.Element(env + "Fault")!;

        Assert.Equal("application/soap+xml; charset=utf-8", type);
        Assert.Equal("env:Receiver", fault.Element(env + "Code")!.Element(env + "Value")!.Value);
        Assert.StartsWith("Bad Gateway: ", fault.Element(env + "Reason")!.Element(env + "Text")!.Value, StringComparison.Ordinal);
        var detail = fault.Element(env + "Detail")!.Element(gw + "gatewayError")!;
        Assert.Equal("502", detail.Element(gw + "status")!.Value);
        Assert.Null(detail.Element(gw + "retryAfterSeconds")); // only for 503
    }

    [Fact]
    public void The_html_page_is_friendly_has_no_scripts_and_encodes_the_message()
    {
        var (type, body) = BackendErrorResponses.Render(ErrorFormat.Html, Info(message: "<b>Maintenance</b> & more"));

        Assert.Equal("text/html; charset=utf-8", type);
        Assert.Contains("This site is temporarily unavailable.", body, StringComparison.Ordinal);
        Assert.Contains("Please try again in a few minutes.", body, StringComparison.Ordinal);
        Assert.Contains("&lt;b&gt;Maintenance&lt;/b&gt; &amp; more", body, StringComparison.Ordinal);
        Assert.Contains("Error 503 · Service Unavailable", System.Net.WebUtility.HtmlDecode(body), StringComparison.Ordinal);
        Assert.Contains("Request ID 0HNABC:00000001 · 2026-11-24T10:42:07Z", System.Net.WebUtility.HtmlDecode(body), StringComparison.Ordinal);
        Assert.Contains("prefers-color-scheme: dark", body, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_response_is_not_cached_asks_to_retry_a_503_and_has_no_body_for_head()
    {
        var context = Context(accept: "application/json");
        await BackendErrorResponses.WriteAsync(context, Info());
        Assert.Equal((503, "no-store", "30"), (context.Response.StatusCode, context.Response.Headers.CacheControl.ToString(), context.Response.Headers.RetryAfter.ToString()));
        Assert.True(context.Response.Body.Length > 0);

        var timeout = Context();
        await BackendErrorResponses.WriteAsync(timeout, Info(BackendErrorKind.Timeout));
        Assert.Equal(504, timeout.Response.StatusCode);
        Assert.Empty(timeout.Response.Headers.RetryAfter.ToString());
        Assert.Contains("default-src 'none'", timeout.Response.Headers.ContentSecurityPolicy.ToString(), StringComparison.Ordinal);

        var head = Context(method: "HEAD");
        await BackendErrorResponses.WriteAsync(head, Info());
        Assert.Equal(503, head.Response.StatusCode);
        Assert.Equal(0, head.Response.Body.Length);
    }

    [Theory]
    [InlineData(ForwarderError.NoAvailableDestinations, BackendErrorKind.NoBackend)]
    [InlineData(ForwarderError.Request, BackendErrorKind.BackendError)]
    [InlineData(ForwarderError.ResponseHeaders, BackendErrorKind.BackendError)]
    [InlineData(ForwarderError.RequestBodyDestination, BackendErrorKind.BackendError)]
    [InlineData(ForwarderError.RequestTimedOut, BackendErrorKind.Timeout)]
    [InlineData(ForwarderError.RequestCanceled, null)]
    [InlineData(ForwarderError.RequestBodyClient, null)]
    [InlineData(ForwarderError.None, null)]
    public void Forwarder_errors_map_to_the_error_kind_and_client_problems_are_left_alone(ForwarderError error, BackendErrorKind? kind)
    {
        Assert.Equal(kind, BackendErrorMiddleware.Classify(error));
    }

    [Fact]
    public void The_request_log_names_the_error_with_the_innermost_reason()
    {
        var refused = new HttpRequestException("outer", new System.Net.Sockets.SocketException(10061));

        Assert.Equal("No backend available", BackendErrorMiddleware.LogText(BackendErrorKind.NoBackend, null));
        Assert.StartsWith("Backend error: ", BackendErrorMiddleware.LogText(BackendErrorKind.BackendError, refused), StringComparison.Ordinal);
        Assert.Equal("Backend timeout", BackendErrorMiddleware.LogText(BackendErrorKind.Timeout, null));
    }

    [Fact]
    public void The_counter_counts_per_route_and_kind()
    {
        var counter = new BackendErrorCounter();
        counter.Add("api", BackendErrorKind.NoBackend, At);
        counter.Add("API", BackendErrorKind.Timeout, At.AddMinutes(1));
        counter.Add("site", BackendErrorKind.BackendError, At);

        Assert.Equal([new RouteBackendErrors("api", 1, 0, 1, At.AddMinutes(1)), new RouteBackendErrors("site", 0, 1, 0, At)], counter.Routes);
    }

    [Fact]
    public void The_visitor_message_is_one_short_line_and_omitted_from_the_json_when_empty()
    {
        var route = new ProxyRouteOptions { Name = "site", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } } };
        Assert.DoesNotContain("ErrorMessage", GatewayConfigurationJson.Serialize(new GatewayConfiguration { Routes = { route } }), StringComparison.Ordinal);

        route.ErrorMessage = "Line one\nline two";
        Assert.Contains("Route 'site': the message for visitors must be one line of at most 300 characters.", ProxyRouteValidator.Validate([route]));
        route.ErrorMessage = new string('x', 301);
        Assert.NotEmpty(ProxyRouteValidator.Validate([route]));

        var (routes, _) = YarpConfigMapper.Map([new ProxyRouteOptions { Name = "m", ErrorMessage = " Back at 14:00 ", Destinations = { new ProxyDestinationOptions { Address = "10.0.0.5", Port = 80 } } }]);
        Assert.Equal("Back at 14:00", routes[0].Metadata![YarpConfigMapper.ErrorMessageMetadataKey]);
    }

    [Fact]
    public void The_route_editor_keeps_the_message()
    {
        var form = new RouteFormModel { Name = "site", Destinations = "10.0.0.5:80", ErrorMessage = "  Planned maintenance until 14:00 " };
        var route = form.ToRoute();

        Assert.Equal("Planned maintenance until 14:00", route.ErrorMessage);
        Assert.Equal("Planned maintenance until 14:00", RouteFormModel.FromRoute(route, 1).ErrorMessage);
        Assert.Null(new RouteFormModel { Name = "site", Destinations = "10.0.0.5:80", ErrorMessage = " " }.ToRoute().ErrorMessage);
    }
}
