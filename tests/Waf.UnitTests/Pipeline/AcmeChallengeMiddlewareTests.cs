using Microsoft.AspNetCore.Http;
using FASoft.Waf.Proxy;

namespace FASoft.Waf.UnitTests.Pipeline;

public class AcmeChallengeMiddlewareTests
{
    private readonly InMemoryAcmeChallengeStore _store = new();
    private int _passedOn;

    private async Task<HttpContext> SendAsync(string path, string method = "GET")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        await new AcmeChallengeMiddleware(_ => { _passedOn++; return Task.CompletedTask; }, _store).InvokeAsync(context);
        return context;
    }

    [Fact]
    public async Task Pending_token_is_answered_with_its_key_authorization()
    {
        _store.Add("abc-DEF_123", "abc-DEF_123.thumbprint");

        var context = await SendAsync("/.well-known/acme-challenge/abc-DEF_123");

        context.Response.Body.Position = 0;
        Assert.Equal("abc-DEF_123.thumbprint", await new StreamReader(context.Response.Body).ReadToEndAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, _passedOn);
    }

    [Theory]
    [InlineData("/.well-known/acme-challenge/unknown", "GET")]
    [InlineData("/.well-known/acme-challenge/abc-DEF_123", "POST")]
    [InlineData("/.well-known/acme-challenge/../secret", "GET")]
    [InlineData("/.well-known/acme-challenge/", "GET")]
    [InlineData("/other", "GET")]
    public async Task Anything_else_continues_down_the_pipeline(string path, string method)
    {
        _store.Add("abc-DEF_123", "x");

        await SendAsync(path, method);

        Assert.Equal(1, _passedOn);
    }

    [Fact]
    public async Task Removed_token_is_no_longer_answered()
    {
        _store.Add("t1", "x");
        _store.Remove("t1");

        await SendAsync("/.well-known/acme-challenge/t1");

        Assert.Equal(1, _passedOn);
    }
}
