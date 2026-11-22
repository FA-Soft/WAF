using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Waf.Core.Hosting;
using Waf.Data;
using Waf.Web;

namespace Waf.UnitTests.Web;

public sealed class AdminIdentityTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "waf-tests", Guid.NewGuid().ToString("N"));
    private readonly CapturingLoggerProvider _logs = new();
    private ServiceProvider _services = null!;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public ValueTask InitializeAsync()
    {
        Directory.CreateDirectory(_directory);
        _services = NewServices();
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await _services.DisposeAsync();
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, recursive: true);
    }

    private ServiceProvider NewServices()
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(_logs));
        services.AddOptions<GatewayEndpointOptions>();
        services.AddAdminIdentity(new StoragePaths(_directory, _directory));
        return services.BuildServiceProvider();
    }

    private static DefaultHttpContext Request(string remoteIp, params (string Name, string Value)[] headers)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(remoteIp);
        foreach (var (name, value) in headers)
        {
            context.Request.Headers[name] = value;
        }

        return context;
    }

    private async Task<(IdentityResult Result, IdentityUser? User)> CreateAsync(FirstRunSetup setup, string password = "correct horse battery staple")
    {
        await using var scope = _services.CreateAsyncScope();
        return await setup.CreateAdminAsync(scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>(), "admin", password);
    }

    [Fact]
    public async Task Without_an_account_a_one_time_token_is_printed_to_the_log()
    {
        var setup = _services.GetRequiredService<FirstRunSetup>();
        await setup.StartAsync(Ct);

        Assert.True(setup.IsRequired);
        Assert.Equal(43, setup.Token!.Length);
        var message = Assert.Single(_logs.Messages, m => m.Contains("No admin account exists yet", StringComparison.Ordinal));
        Assert.Contains(setup.Token, message, StringComparison.Ordinal);
        Assert.Contains("http://127.0.0.1:8900/account/setup", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Remote_requests_need_the_token_and_setup_closes_once_the_account_exists()
    {
        var setup = _services.GetRequiredService<FirstRunSetup>();
        await setup.StartAsync(Ct);
        var token = setup.Token!;

        Assert.True(setup.IsAllowed(Request("127.0.0.1"), null));
        Assert.True(setup.IsAllowed(Request("::1"), null));
        Assert.False(setup.IsAllowed(Request("203.0.113.9"), null));
        Assert.False(setup.IsAllowed(Request("203.0.113.9"), "wrong"));
        Assert.False(setup.IsAllowed(Request("203.0.113.9"), token[..^1]));
        Assert.True(setup.IsAllowed(Request("203.0.113.9"), token));
        Assert.True(setup.IsAllowed(Request("203.0.113.9"), $" {token} ")); // pasted with spaces

        // A proxy on this machine: the connection is local, the client is not.
        Assert.False(setup.IsAllowed(Request("127.0.0.1", ("X-Forwarded-For", "203.0.113.9")), null));
        Assert.True(setup.IsAllowed(Request("127.0.0.1", ("X-Forwarded-For", "203.0.113.9")), token));

        var (result, user) = await CreateAsync(setup);
        Assert.True(result.Succeeded);
        Assert.Equal("admin", user!.UserName);

        Assert.False(setup.IsRequired);
        Assert.Null(setup.Token);
        Assert.False(setup.IsAllowed(Request("127.0.0.1"), null));
        Assert.False(setup.IsAllowed(Request("203.0.113.9"), token));

        var (again, _) = await CreateAsync(setup);
        Assert.Equal("AdminExists", Assert.Single(again.Errors).Code);
    }

    [Fact]
    public async Task After_a_restart_setup_stays_closed()
    {
        var setup = _services.GetRequiredService<FirstRunSetup>();
        await setup.StartAsync(Ct);
        Assert.True((await CreateAsync(setup)).Result.Succeeded);
        await _services.DisposeAsync();
        _logs.Messages.Clear();

        _services = NewServices();
        var restarted = _services.GetRequiredService<FirstRunSetup>();
        await restarted.StartAsync(Ct);

        Assert.False(restarted.IsRequired);
        Assert.Null(restarted.Token);
        Assert.DoesNotContain(_logs.Messages, m => m.Contains("setup token", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Short_passwords_are_refused_and_keep_setup_open()
    {
        var setup = _services.GetRequiredService<FirstRunSetup>();
        await setup.StartAsync(Ct);

        var (result, user) = await CreateAsync(setup, "short pass");

        Assert.Null(user);
        Assert.Contains(result.Errors, e => e.Description.Contains("12 characters", StringComparison.Ordinal));
        Assert.True(setup.IsRequired);
        Assert.NotNull(setup.Token);

        // Length counts, not character classes.
        Assert.True((await CreateAsync(setup, "only lowercase words")).Result.Succeeded);
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.10.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("::ffff:127.0.0.1", true)]
    [InlineData("192.168.1.10", false)]
    [InlineData("::ffff:192.168.1.10", false)]
    [InlineData("fe80::1", false)]
    public void Only_loopback_requests_are_local(string remoteIp, bool local) =>
        Assert.Equal(local, FirstRunSetup.IsLocalRequest(Request(remoteIp)));

    [Theory]
    [InlineData("Forwarded")]
    [InlineData("X-Forwarded-For")]
    [InlineData("X-Forwarded-Host")]
    [InlineData("X-Real-IP")]
    public void Requests_passed_on_by_a_proxy_are_not_local(string header) =>
        Assert.False(FirstRunSetup.IsLocalRequest(Request("127.0.0.1", (header, "203.0.113.9"))));

    [Fact]
    public void A_request_without_a_remote_address_is_not_local() =>
        Assert.False(FirstRunSetup.IsLocalRequest(new DefaultHttpContext()));

    [Theory]
    [InlineData(null, "/")]
    [InlineData("", "/")]
    [InlineData("/", "/")]
    [InlineData("/routes", "/routes")]
    [InlineData("/logs?ip=203.0.113.7&live=1", "/logs?ip=203.0.113.7&live=1")]
    [InlineData("//evil.example/", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData("https://evil.example/", "/")]
    [InlineData("evil.example", "/")]
    [InlineData("/routes\r\nSet-Cookie: x=1", "/")]
    public void After_signing_in_only_local_pages_are_opened(string? returnUrl, string expected) =>
        Assert.Equal(expected, AdminIdentity.LocalReturnUrl(returnUrl));

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public List<string> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Logger(this);

        public void Dispose()
        {
        }

        private sealed class Logger(CapturingLoggerProvider provider) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (provider.Messages)
                {
                    provider.Messages.Add(formatter(state, exception));
                }
            }
        }
    }
}
