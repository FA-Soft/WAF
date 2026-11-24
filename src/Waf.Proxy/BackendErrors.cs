using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using FASoft.Waf.Core.Routing;
using Yarp.ReverseProxy.Forwarder;

namespace FASoft.Waf.Proxy;

/// <summary>Why no backend answered.</summary>
public enum BackendErrorKind
{
    /// <summary>503: no healthy backend (or none at all) for the route.</summary>
    NoBackend,

    /// <summary>502: the connection was refused or reset, or the backend's answer was invalid.</summary>
    BackendError,

    /// <summary>504: the backend did not answer in time.</summary>
    Timeout,
}

/// <summary>The format of an error response, chosen from the request.</summary>
public enum ErrorFormat
{
    Html,

    /// <summary><c>application/problem+json</c> (RFC 9457).</summary>
    ProblemJson,

    /// <summary><c>application/problem+xml</c> (RFC 9457, XML form).</summary>
    ProblemXml,

    /// <summary>A SOAP 1.1 Fault (<c>soap:Server</c>), HTTP 500.</summary>
    Soap11,

    /// <summary>A SOAP 1.2 Fault (<c>env:Receiver</c>), HTTP 500.</summary>
    Soap12,
}

/// <summary>What an error response says. Never anything internal: no addresses, ports, route or target names, exceptions.</summary>
/// <param name="Kind">Why no backend answered.</param>
/// <param name="RequestId">The request's ID, also in the request log.</param>
/// <param name="Time">When it happened.</param>
/// <param name="Message">The route's message for visitors (in <paramref name="Language"/> when it has a translation), if it has one.</param>
/// <param name="Language">The visitor's language (en, nl, fr, de) for the texts; status codes, the problem type and SOAP
/// fault codes are the same in every language.</param>
public sealed record BackendErrorInfo(BackendErrorKind Kind, string RequestId, DateTimeOffset Time, string? Message = null, string Language = "en")
{
    /// <summary>The gateway's status: 503, 502 or 504.</summary>
    public int Status => Kind switch
    {
        BackendErrorKind.NoBackend => StatusCodes.Status503ServiceUnavailable,
        BackendErrorKind.Timeout => StatusCodes.Status504GatewayTimeout,
        _ => StatusCodes.Status502BadGateway,
    };

    /// <summary>The HTTP status phrase in English, the same in every language (the Fault detail's <c>title</c>).</summary>
    public string StatusPhrase => Kind switch
    {
        BackendErrorKind.NoBackend => "Service Unavailable",
        BackendErrorKind.Timeout => "Gateway Timeout",
        _ => "Bad Gateway",
    };

    /// <summary>The status phrase in the visitor's language (the problem's <c>title</c>).</summary>
    public string Title => VisitorTexts.Get(Language, StatusPhrase);

    /// <summary>What happened, in the visitor's language (the problem's <c>detail</c>).</summary>
    public string Detail => VisitorTexts.Get(Language, Kind switch
    {
        BackendErrorKind.NoBackend => "No server is available to handle this request. Please try again later.",
        BackendErrorKind.Timeout => "The server behind the gateway did not answer in time. Please try again later.",
        _ => "The server behind the gateway did not give a valid answer. Please try again later.",
    });

    /// <summary>"2026-11-24T10:42:07Z".</summary>
    public string TimeText => Time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}

/// <summary>Writes the error response for a request that no backend answered, in the format the client expects.</summary>
public static class BackendErrorResponses
{
    /// <summary>Seconds a client is asked to wait before trying again after a 503.</summary>
    public const int RetryAfterSeconds = 30;

    /// <summary>Namespace of the gateway's element in a SOAP Fault's detail.</summary>
    public const string SoapDetailNamespace = "urn:fa-soft:waf-gateway:error";

    private const string ProblemXmlNamespace = "urn:ietf:rfc:7807";
    private const string Soap11Namespace = "http://schemas.xmlsoap.org/soap/envelope/";
    private const string Soap12Namespace = "http://www.w3.org/2003/05/soap-envelope";

    /// <summary>
    /// The format for <paramref name="request"/>. A SOAP request always gets a Fault (SOAP clients only read
    /// envelopes): SOAP 1.2 for <c>application/soap+xml</c>, SOAP 1.1 for <c>text/xml</c> with a <c>SOAPAction</c>
    /// header. Otherwise the <c>Accept</c> header decides (by quality), then the request's <c>Content-Type</c>, then HTML.
    /// </summary>
    public static ErrorFormat Negotiate(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var accept = MediaTypeHeaderValue.TryParseList(request.Headers.Accept, out var parsed)
            ? parsed.OrderByDescending(m => m.Quality ?? 1).Where(m => m.Quality is not 0).Select(m => m.MediaType.Value?.ToLowerInvariant() ?? string.Empty).ToList()
            : [];
        var contentType = MediaTypeHeaderValue.TryParse(request.ContentType, out var type) ? type.MediaType.Value?.ToLowerInvariant() : null;
        var soapAction = request.Headers.ContainsKey("SOAPAction");

        if (contentType == "application/soap+xml" || accept.Contains("application/soap+xml"))
        {
            return ErrorFormat.Soap12;
        }

        if (soapAction && (contentType == "text/xml" || accept.Contains("text/xml")))
        {
            return ErrorFormat.Soap11;
        }

        foreach (var mediaType in accept)
        {
            if (FromMediaType(mediaType, soapAction) is { } format)
            {
                return format;
            }
        }

        return contentType is not null && FromMediaType(contentType, soapAction) is { } fromBody and not ErrorFormat.Html
            ? fromBody
            : ErrorFormat.Html;
    }

    private static ErrorFormat? FromMediaType(string mediaType, bool soapAction) => mediaType switch
    {
        "text/html" or "application/xhtml+xml" => ErrorFormat.Html,
        "application/json" or "application/problem+json" => ErrorFormat.ProblemJson,
        "application/soap+xml" => ErrorFormat.Soap12,
        "text/xml" when soapAction => ErrorFormat.Soap11,
        "application/xml" or "text/xml" or "application/problem+xml" => ErrorFormat.ProblemXml,
        _ when mediaType.EndsWith("+json", StringComparison.Ordinal) => ErrorFormat.ProblemJson,
        _ when mediaType.EndsWith("+xml", StringComparison.Ordinal) => ErrorFormat.ProblemXml,
        _ => null,
    };

    /// <summary>The HTTP status of the response: 500 for SOAP Faults (as SOAP over HTTP requires), else the gateway's status.</summary>
    public static int HttpStatus(ErrorFormat format, BackendErrorInfo error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return format is ErrorFormat.Soap11 or ErrorFormat.Soap12 ? StatusCodes.Status500InternalServerError : error.Status;
    }

    /// <summary>The content type and body of the response.</summary>
    public static (string ContentType, string Body) Render(ErrorFormat format, BackendErrorInfo error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return format switch
        {
            ErrorFormat.ProblemJson => ("application/problem+json", Json(error)),
            ErrorFormat.ProblemXml => ("application/problem+xml; charset=utf-8", ProblemXml(error)),
            ErrorFormat.Soap11 => ("text/xml; charset=utf-8", Soap11(error)),
            ErrorFormat.Soap12 => ("application/soap+xml; charset=utf-8", Soap12(error)),
            _ => ("text/html; charset=utf-8", Html(error)),
        };
    }

    /// <summary>Writes the error response; nothing when the response has already started.</summary>
    public static async Task WriteAsync(HttpContext context, BackendErrorInfo error)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(error);
        if (context.Response.HasStarted)
        {
            return;
        }

        var format = Negotiate(context.Request);
        var (contentType, body) = Render(format, error);
        var bytes = Encoding.UTF8.GetBytes(body);

        var response = context.Response;
        response.Clear();
        response.StatusCode = HttpStatus(format, error);
        response.ContentType = contentType;
        VisitorTexts.MarkLanguage(response, error.Language);
        response.Headers.CacheControl = "no-store";
        response.Headers.XContentTypeOptions = "nosniff";
        if (error.Kind == BackendErrorKind.NoBackend)
        {
            response.Headers.RetryAfter = RetryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        }

        if (format == ErrorFormat.Html)
        {
            // The page has no scripts and only inline styles and an inline image.
            response.Headers.ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
        }

        response.ContentLength = bytes.Length;
        if (HttpMethods.IsHead(context.Request.Method))
        {
            return; // the headers only
        }

        await response.Body.WriteAsync(bytes, context.RequestAborted).ConfigureAwait(false);
    }

    private static string Json(BackendErrorInfo error)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("type", "about:blank");
            writer.WriteString("title", error.Title);
            writer.WriteNumber("status", error.Status);
            writer.WriteString("detail", error.Detail);
            if (!string.IsNullOrEmpty(error.Message))
            {
                writer.WriteString("message", error.Message);
            }

            writer.WriteString("requestId", error.RequestId);
            writer.WriteString("time", error.TimeText);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static string Xml(Action<XmlWriter> write)
    {
        var builder = new StringBuilder();
        using (var writer = XmlWriter.Create(builder, new XmlWriterSettings { Indent = true, OmitXmlDeclaration = true }))
        {
            write(writer);
        }

        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" + builder;
    }

    private static string ProblemXml(BackendErrorInfo error) => Xml(writer =>
    {
        writer.WriteStartElement("problem", ProblemXmlNamespace);
        writer.WriteElementString("type", ProblemXmlNamespace, "about:blank");
        writer.WriteElementString("title", ProblemXmlNamespace, error.Title);
        writer.WriteElementString("status", ProblemXmlNamespace, error.Status.ToString(CultureInfo.InvariantCulture));
        writer.WriteElementString("detail", ProblemXmlNamespace, error.Detail);
        if (!string.IsNullOrEmpty(error.Message))
        {
            writer.WriteElementString("message", ProblemXmlNamespace, error.Message);
        }

        writer.WriteElementString("requestId", ProblemXmlNamespace, error.RequestId);
        writer.WriteElementString("time", ProblemXmlNamespace, error.TimeText);
        writer.WriteEndElement();
    });

    /// <summary>The gateway's own status and its meaning, inside the Fault's detail.</summary>
    private static void WriteGatewayError(XmlWriter writer, BackendErrorInfo error)
    {
        writer.WriteStartElement("gw", "gatewayError", SoapDetailNamespace);
        writer.WriteElementString("gw", "status", SoapDetailNamespace, error.Status.ToString(CultureInfo.InvariantCulture));
        writer.WriteElementString("gw", "title", SoapDetailNamespace, error.StatusPhrase); // fixed, for programs
        writer.WriteElementString("gw", "detail", SoapDetailNamespace, error.Detail);
        if (!string.IsNullOrEmpty(error.Message))
        {
            writer.WriteElementString("gw", "message", SoapDetailNamespace, error.Message);
        }

        if (error.Kind == BackendErrorKind.NoBackend)
        {
            writer.WriteElementString("gw", "retryAfterSeconds", SoapDetailNamespace, RetryAfterSeconds.ToString(CultureInfo.InvariantCulture));
        }

        writer.WriteElementString("gw", "requestId", SoapDetailNamespace, error.RequestId);
        writer.WriteElementString("gw", "time", SoapDetailNamespace, error.TimeText);
        writer.WriteEndElement();
    }

    private static string FaultString(BackendErrorInfo error) =>
        VisitorTexts.Format(error.Language, "{0}: {1}", error.Title, string.IsNullOrEmpty(error.Message) ? error.Detail : error.Message);

    private static string Soap11(BackendErrorInfo error) => Xml(writer =>
    {
        writer.WriteStartElement("soap", "Envelope", Soap11Namespace);
        writer.WriteStartElement("soap", "Body", Soap11Namespace);
        writer.WriteStartElement("soap", "Fault", Soap11Namespace);
        writer.WriteElementString("faultcode", "soap:Server"); // unqualified children, as SOAP 1.1 defines them
        writer.WriteElementString("faultstring", FaultString(error));
        writer.WriteStartElement("detail");
        WriteGatewayError(writer, error);
        writer.WriteEndElement();
        writer.WriteEndElement();
        writer.WriteEndElement();
        writer.WriteEndElement();
    });

    private static string Soap12(BackendErrorInfo error) => Xml(writer =>
    {
        writer.WriteStartElement("env", "Envelope", Soap12Namespace);
        writer.WriteStartElement("env", "Body", Soap12Namespace);
        writer.WriteStartElement("env", "Fault", Soap12Namespace);
        writer.WriteStartElement("env", "Code", Soap12Namespace);
        writer.WriteElementString("env", "Value", Soap12Namespace, "env:Receiver");
        writer.WriteEndElement();
        writer.WriteStartElement("env", "Reason", Soap12Namespace);
        writer.WriteStartElement("env", "Text", Soap12Namespace);
        writer.WriteAttributeString("xml", "lang", null, error.Language);
        writer.WriteString(FaultString(error));
        writer.WriteEndElement();
        writer.WriteEndElement();
        writer.WriteStartElement("env", "Detail", Soap12Namespace);
        WriteGatewayError(writer, error);
        writer.WriteEndElement();
        writer.WriteEndElement();
        writer.WriteEndElement();
        writer.WriteEndElement();
    });

    /// <summary>The shield of the logo, inline (the page loads nothing else).</summary>
    private const string Logo =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\" width=\"56\" height=\"56\" aria-hidden=\"true\">" +
        "<path d=\"M32 4 L54 12 V29 C54 43.5 45 54 32 60 C19 54 10 43.5 10 29 V12 Z\" fill=\"#0E1A2B\" stroke=\"#8FA3BF\" stroke-width=\"1\"/>" +
        "<path d=\"M32 15 V26 C32 31.5 24 31.5 24 37 V42 M32 26 C32 31.5 40 31.5 40 37 V45\" fill=\"none\" stroke=\"#FFFFFF\" stroke-width=\"4\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>" +
        "<path d=\"M35.2 41 L40 45.8 L44.8 41\" fill=\"none\" stroke=\"#22C9A0\" stroke-width=\"4\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>" +
        "<path d=\"M19.5 47.5 H28.5\" stroke=\"#F5A524\" stroke-width=\"4\" stroke-linecap=\"round\"/></svg>";

    private static string Html(BackendErrorInfo error)
    {
        var e = HtmlEncoder.Default;
        var status = error.Status.ToString(CultureInfo.InvariantCulture);
        var message = string.IsNullOrEmpty(error.Message) ? string.Empty : $"<p class=\"message\">{e.Encode(error.Message)}</p>";
        return $$"""
            <!doctype html>
            <html lang="{{error.Language}}">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="robots" content="noindex">
            <meta name="color-scheme" content="light dark">
            <title>{{status}} {{e.Encode(error.Title)}}</title>
            <style>
            :root { --bg: #f5f6f8; --card: #ffffff; --text: #1b2330; --muted: #5b6676; --border: #dde2e8; --accent: #f5a524; }
            @media (prefers-color-scheme: dark) { :root { --bg: #0b121c; --card: #131d2b; --text: #e6ebf2; --muted: #9aa7b8; --border: #26344a; } }
            * { box-sizing: border-box; }
            body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;
                   background: var(--bg); color: var(--text); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
            main { max-width: 34rem; width: 100%; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; }
            h1 { font-size: 1.4rem; margin: 1rem 0 .5rem; }
            p { margin: .5rem 0; }
            .message { border-left: 4px solid var(--accent); padding-left: .75rem; font-weight: 600; }
            .meta { margin-top: 1.5rem; color: var(--muted); font-size: .85rem; overflow-wrap: anywhere; }
            </style>
            </head>
            <body>
            <main>
            {{Logo}}
            <h1>{{e.Encode(VisitorTexts.Get(error.Language, "This site is temporarily unavailable."))}}</h1>
            <p>{{e.Encode(VisitorTexts.Get(error.Language, "Please try again in a few minutes."))}}</p>
            {{message}}
            <p class="meta">{{e.Encode(VisitorTexts.Format(error.Language, "Error {0} · {1}", status, error.Title))}}<br>{{e.Encode(VisitorTexts.Format(error.Language, "Request ID {0} · {1}", error.RequestId, error.TimeText))}}</p>
            </main>
            </body>
            </html>
            """;
    }
}

/// <summary>Counts backend errors per route since the gateway started, for the dashboard.</summary>
public sealed class BackendErrorCounter : IBackendErrorStatistics
{
    private readonly ConcurrentDictionary<string, Counts> _routes = new(StringComparer.OrdinalIgnoreCase);

    private sealed class Counts
    {
        public long NoBackend;
        public long BackendError;
        public long Timeout;
        public long LastTicks;
    }

    public IReadOnlyList<RouteBackendErrors> Routes =>
    [
        .. _routes
            .Select(pair => new RouteBackendErrors(
                pair.Key,
                Interlocked.Read(ref pair.Value.NoBackend),
                Interlocked.Read(ref pair.Value.BackendError),
                Interlocked.Read(ref pair.Value.Timeout),
                new DateTimeOffset(Interlocked.Read(ref pair.Value.LastTicks), TimeSpan.Zero)))
            .OrderBy(r => r.RouteName, StringComparer.OrdinalIgnoreCase),
    ];

    public void Add(string route, BackendErrorKind kind, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(route);
        var counts = _routes.GetOrAdd(route, _ => new Counts());
        _ = kind switch
        {
            BackendErrorKind.NoBackend => Interlocked.Increment(ref counts.NoBackend),
            BackendErrorKind.Timeout => Interlocked.Increment(ref counts.Timeout),
            _ => Interlocked.Increment(ref counts.BackendError),
        };
        Interlocked.Exchange(ref counts.LastTicks, at.UtcTicks);
    }
}

/// <summary>
/// First in the proxy pipeline: when the forwarder could not get an answer from a backend (no healthy backend, a
/// failed connection, an invalid answer, a time-out) and nothing was sent to the client yet, writes a clear error
/// response in the client's format. What went wrong, with the backend, goes to the request log only.
/// </summary>
internal sealed class BackendErrorMiddleware(RequestDelegate next, BackendErrorCounter counter, TimeProvider time)
{
    public async Task InvokeAsync(HttpContext context)
    {
        await next(context).ConfigureAwait(false);

        var failure = context.Features.Get<IForwarderErrorFeature>();
        if (failure is null || context.Response.HasStarted || Classify(failure.Error) is not { } kind)
        {
            return; // answered, a client-side problem, or too late: a failure halfway through a response just ends it
        }

        var feature = context.GetReverseProxyFeature();
        var route = feature.Route.Config.RouteId;
        // The route's message in the visitor's language, falling back to its English text.
        var language = VisitorTexts.LanguageOf(context.Request);
        var metadata = feature.Route.Config.Metadata;
        var message = metadata?.GetValueOrDefault(YarpConfigMapper.ErrorMessageMetadataKey + "." + language)
            ?? metadata?.GetValueOrDefault(YarpConfigMapper.ErrorMessageMetadataKey);
        var now = time.GetUtcNow();

        counter.Add(route, kind, now);
        // The request ID is on the error the client got: searching the request log for it finds this entry.
        RequestLogFeature.RecordBackendError(context, $"{LogText(kind, failure.Exception)} (request ID {context.TraceIdentifier})");
        await BackendErrorResponses.WriteAsync(context, new BackendErrorInfo(kind, context.TraceIdentifier, now, message, language)).ConfigureAwait(false);
    }

    /// <summary>The kind of error for a forwarder error; null when the client caused it (cancelled, bad request body).</summary>
    internal static BackendErrorKind? Classify(ForwarderError error) => error switch
    {
        ForwarderError.None => null,
        ForwarderError.NoAvailableDestinations => BackendErrorKind.NoBackend,
        ForwarderError.RequestTimedOut => BackendErrorKind.Timeout,
        ForwarderError.RequestCanceled or ForwarderError.RequestBodyCanceled or ForwarderError.RequestBodyClient
            or ForwarderError.ResponseBodyCanceled or ForwarderError.ResponseBodyClient
            or ForwarderError.UpgradeRequestCanceled or ForwarderError.UpgradeRequestClient
            or ForwarderError.UpgradeResponseCanceled or ForwarderError.UpgradeResponseClient => null,
        _ => BackendErrorKind.BackendError,
    };

    /// <summary>For the request log: "Backend error: No connection could be made…" (the innermost exception's text).</summary>
    internal static string LogText(BackendErrorKind kind, Exception? exception)
    {
        var text = kind switch
        {
            BackendErrorKind.NoBackend => "No backend available",
            BackendErrorKind.Timeout => "Backend timeout",
            _ => "Backend error",
        };

        while (exception?.InnerException is not null)
        {
            exception = exception.InnerException;
        }

        return exception is null || string.IsNullOrWhiteSpace(exception.Message) ? text : $"{text}: {exception.Message}";
    }
}
