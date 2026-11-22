using System.Text;
using Microsoft.AspNetCore.Http;
using Waf.Proxy;

namespace Waf.UnitTests.Detection;

public class RequestBodyReaderTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static DefaultHttpContext WithBody(string content, string contentType = "text/plain")
    {
        var context = new DefaultHttpContext();
        var bytes = Encoding.UTF8.GetBytes(content);
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;
        context.Request.ContentType = contentType;
        return context;
    }

    [Fact]
    public async Task Small_body_is_read_completely_and_left_readable()
    {
        var context = WithBody("hello world");

        var body = await RequestBodyReader.ReadAsync(context.Request, 1024, Ct);

        Assert.Equal("hello world", Encoding.UTF8.GetString(body!.Content.Span));
        Assert.Equal("text/plain", body.ContentType);
        Assert.Equal("hello world", await new StreamReader(context.Request.Body).ReadToEndAsync(Ct));
    }

    [Fact]
    public async Task Large_body_is_inspected_only_up_to_the_limit_but_forwarded_in_full()
    {
        var content = new string('a', 10_000) + "TAIL";
        var context = WithBody(content);

        var body = await RequestBodyReader.ReadAsync(context.Request, 100, Ct);

        Assert.Equal(100, body!.Content.Length);
        Assert.Equal(content, await new StreamReader(context.Request.Body).ReadToEndAsync(Ct));
    }

    [Fact]
    public async Task Missing_body_returns_null()
    {
        var context = new DefaultHttpContext();
        context.Request.ContentLength = 0;

        Assert.Null(await RequestBodyReader.ReadAsync(context.Request, 100, Ct));
    }
}
