using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Engine;
using FASoft.Waf.Proxy;
using FASoft.Waf.UnitTests.Engine;
using static FASoft.Waf.UnitTests.Engine.RuleBuilder;

namespace FASoft.Waf.UnitTests.Pipeline;

internal sealed class CapturingSink : IWafEventSink
{
    public List<WafEvent> Events { get; } = [];

    public void Publish(WafEvent wafEvent) => Events.Add(wafEvent);
}

public class WafMiddlewareTests
{
    private readonly CapturingSink _events = new();
    private readonly ManualTimeProvider _time = new();
    private readonly WafEngineHolder _engines = new();
    private int _forwarded;

    private WafMiddleware Middleware(GatewayConfiguration? configuration = null)
    {
        if (configuration is not null)
        {
            _engines.Activate(WafEngine.Build(configuration, _time));
        }

        return new WafMiddleware(_ => { _forwarded++; return Task.CompletedTask; }, _engines, _events, _time, NullLogger<WafMiddleware>.Instance);
    }

    private static DefaultHttpContext Request(string path = "/", string query = "", string method = "GET", string? body = null, string contentType = "application/x-www-form-urlencoded", params (string, string)[] headers)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.7");
        context.Request.Method = method;
        context.Request.Host = new HostString("www.example.com");
        context.Request.Path = path;
        context.Request.QueryString = query.Length == 0 ? QueryString.Empty : new QueryString("?" + query);
        foreach (var (name, value) in headers)
        {
            context.Request.Headers[name] = value;
        }

        if (body is not null)
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            context.Request.Body = new MemoryStream(bytes);
            context.Request.ContentLength = bytes.Length;
            context.Request.ContentType = contentType;
        }

        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task<string> ResponseText(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return await new StreamReader(context.Response.Body).ReadToEndAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Without_an_engine_requests_fail_closed_with_503()
    {
        var context = Request();

        await Middleware().InvokeAsync(context);

        Assert.Equal(0, _forwarded);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, context.Response.StatusCode);
        Assert.Equal("30", context.Response.Headers.RetryAfter.ToString());
        Assert.Equal(FailClosedGuardMiddleware.UnavailableMessage, await ResponseText(context));
        Assert.Equal(WafEventKind.FailClosed, Assert.Single(_events.Events).Kind);
    }

    [Fact]
    public async Task Clean_request_is_forwarded_without_events()
    {
        await Middleware(Config()).InvokeAsync(Request("/products/42", "color=red"));

        Assert.Equal(1, _forwarded);
        Assert.Empty(_events.Events);
    }

    [Fact]
    public async Task Block_rule_returns_a_generic_403()
    {
        var context = Request("/admin");

        await Middleware(Config(Rule("no-admin", RuleAction.Block, 10, When(ConditionField.Path, ConditionOperator.StartsWith, "/admin")))).InvokeAsync(context);

        Assert.Equal(0, _forwarded);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        Assert.Equal(WafMiddleware.ForbiddenMessage, await ResponseText(context));
        var wafEvent = Assert.Single(_events.Events);
        Assert.Equal((WafEventKind.RuleBlocked, "no-admin", 403), (wafEvent.Kind, wafEvent.RuleName, wafEvent.StatusCode));
    }

    [Fact]
    public async Task Explicit_allow_rule_skips_rate_limits_and_attack_detection()
    {
        var configuration = Config(Rule("trusted", RuleAction.Allow, 1, When(ConditionField.Header, ConditionOperator.Equals, false, false, "X-Trusted", "yes")));
        configuration.RateLimits.Add(new RateLimitRule { Name = "one", PermitLimit = 1 });
        var middleware = Middleware(configuration);

        for (var i = 0; i < 3; i++)
        {
            await middleware.InvokeAsync(Request("/", "q=<script>alert(1)</script>", headers: ("X-Trusted", "yes")));
        }

        Assert.Equal(3, _forwarded);
        Assert.Empty(_events.Events);
    }

    [Fact]
    public async Task LogOnly_and_detection_only_rule_matches_are_reported_and_forwarded()
    {
        var tryOut = Rule("try-out", RuleAction.Block, 20);
        tryOut.DetectionOnly = true;

        await Middleware(Config(Rule("watch", RuleAction.LogOnly, 10), tryOut)).InvokeAsync(Request());

        Assert.Equal(1, _forwarded);
        Assert.Equal([WafEventKind.RuleLogged, WafEventKind.RuleDetected], _events.Events.Select(e => e.Kind));
    }

    [Fact]
    public async Task Rate_limit_returns_429_with_retry_after()
    {
        var configuration = Config();
        configuration.RateLimits.Add(new RateLimitRule { Name = "one-per-minute", PermitLimit = 1, WindowSeconds = 60 });
        var middleware = Middleware(configuration);
        await middleware.InvokeAsync(Request());

        var limited = Request();
        await middleware.InvokeAsync(limited);

        Assert.Equal(1, _forwarded);
        Assert.Equal(StatusCodes.Status429TooManyRequests, limited.Response.StatusCode);
        Assert.Equal("60", limited.Response.Headers.RetryAfter.ToString());
        Assert.Equal((WafEventKind.RateLimited, "one-per-minute"), (_events.Events[0].Kind, _events.Events[0].RuleName));
    }

    [Fact]
    public async Task Detection_only_rate_limit_is_reported_and_forwarded()
    {
        var configuration = Config();
        configuration.RateLimits.Add(new RateLimitRule { Name = "try", PermitLimit = 1, DetectionOnly = true });
        var middleware = Middleware(configuration);

        await middleware.InvokeAsync(Request());
        await middleware.InvokeAsync(Request());

        Assert.Equal(2, _forwarded);
        Assert.Equal(WafEventKind.RateLimitDetected, Assert.Single(_events.Events).Kind);
    }

    [Fact]
    public async Task Attack_returns_403_and_reports_category_location_and_snippet()
    {
        var context = Request("/search", "q=1%27%20UNION%20SELECT%20password%20FROM%20users--");

        await Middleware(Config()).InvokeAsync(context);

        Assert.Equal(0, _forwarded);
        Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        var wafEvent = Assert.Single(_events.Events);
        Assert.Equal((WafEventKind.AttackBlocked, "sqli-union-select"), (wafEvent.Kind, wafEvent.RuleName));
        Assert.StartsWith("SqlInjection in QueryString 'q': ", wafEvent.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Global_detection_only_reports_attacks_but_forwards_them()
    {
        var configuration = Config();
        configuration.Settings.DetectionOnly = true;

        await Middleware(configuration).InvokeAsync(Request("/", "q=<script>alert(1)</script>"));

        Assert.Equal(1, _forwarded);
        Assert.Equal(WafEventKind.AttackDetected, Assert.Single(_events.Events).Kind);
    }

    [Fact]
    public async Task Body_is_inspected_when_enabled_and_stays_readable()
    {
        var configuration = Config();
        configuration.Settings.AttackDetection.InspectBody = true;
        var middleware = Middleware(configuration);

        var attack = Request("/login", method: "POST", body: "user=admin&pass=x%27+or+%271%27%3D%271");
        await middleware.InvokeAsync(attack);
        Assert.Equal(StatusCodes.Status403Forbidden, attack.Response.StatusCode);

        string? forwardedBody = null;
        var capture = new WafMiddleware(async ctx => forwardedBody = await new StreamReader(ctx.Request.Body).ReadToEndAsync(), _engines, _events, _time, NullLogger<WafMiddleware>.Instance);
        await capture.InvokeAsync(Request("/login", method: "POST", body: "user=frank&pass=secret"));
        Assert.Equal("user=frank&pass=secret", forwardedBody);
    }

    [Fact]
    public async Task Get_requests_do_not_have_their_body_read()
    {
        var configuration = Config();
        configuration.Settings.AttackDetection.InspectBody = true;

        await Middleware(configuration).InvokeAsync(Request("/", method: "GET", body: "<script>alert(1)</script>", contentType: "text/plain"));

        Assert.Equal(1, _forwarded);
    }

    [Fact]
    public async Task Evaluation_failure_fails_closed_with_503()
    {
        var configuration = Config();
        configuration.Settings.AttackDetection.InspectBody = true;
        var context = Request("/upload", method: "POST", body: "x", contentType: "text/plain");
        context.Request.Body = new ThrowingStream(new IOException("disk error"));

        await Middleware(configuration).InvokeAsync(context);

        Assert.Equal(0, _forwarded);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, context.Response.StatusCode);
        Assert.Equal(WafEventKind.FailClosed, Assert.Single(_events.Events).Kind);
    }

    [Fact]
    public async Task Aborted_request_is_dropped_without_forwarding()
    {
        var configuration = Config();
        configuration.Settings.AttackDetection.InspectBody = true;
        using var aborted = new CancellationTokenSource();
        await aborted.CancelAsync();
        var context = Request("/upload", method: "POST", body: "x", contentType: "text/plain");
        context.RequestAborted = aborted.Token;
        context.Request.Body = new ThrowingStream(new OperationCanceledException(aborted.Token));

        await Middleware(configuration).InvokeAsync(context);

        Assert.Equal(0, _forwarded);
        Assert.Empty(_events.Events);
    }

    [Fact]
    public async Task Guard_refuses_without_engine_and_passes_with_one()
    {
        var passed = 0;
        var guard = new FailClosedGuardMiddleware(_ => { passed++; return Task.CompletedTask; }, _engines, _events, _time);

        var refused = Request();
        await guard.InvokeAsync(refused);
        _engines.Activate(WafEngine.Build(Config(), _time));
        await guard.InvokeAsync(Request());

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refused.Response.StatusCode);
        Assert.Equal(1, passed);
    }

    [Fact]
    public void Holder_reports_why_the_engine_is_unavailable()
    {
        Assert.Null(_engines.Current);
        Assert.NotNull(_engines.UnavailableReason);

        _engines.Activate(WafEngine.Build(Config(), _time));
        Assert.NotNull(_engines.Current);
        Assert.Null(_engines.UnavailableReason);

        _engines.MarkUnavailable("maintenance");
        Assert.Null(_engines.Current);
        Assert.Equal("maintenance", _engines.UnavailableReason);
    }

    private sealed class ThrowingStream(Exception exception) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw exception;
        public override long Position { get => 0; set => throw exception; }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw exception;
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.FromException<int>(exception);
        public override long Seek(long offset, SeekOrigin origin) => throw exception;
        public override void SetLength(long value) => throw exception;
        public override void Write(byte[] buffer, int offset, int count) => throw exception;
    }
}
