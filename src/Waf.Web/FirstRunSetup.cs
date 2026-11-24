using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using FASoft.Waf.Core.Hosting;
using FASoft.Waf.Data;

namespace FASoft.Waf.Web;

/// <summary>
/// Creating the first admin account. As long as no account exists, the setup page accepts one, but only from
/// this machine, or with a one-time token that is printed to the service log at startup. Once an account exists,
/// setup is closed for good.
/// </summary>
/// <remarks>
/// At startup this creates or migrates <c>identity.db</c>, so it is ready before the first request.
/// </remarks>
public sealed partial class FirstRunSetup(
    IServiceScopeFactory scopes,
    IOptions<GatewayEndpointOptions> endpoints,
    ILogger<FirstRunSetup> logger) : IHostedService, IDisposable
{
    /// <summary>Headers set by proxies; a request carrying one may come from anywhere, even when it arrives via loopback.</summary>
    private static readonly string[] ForwardingHeaders = ["Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP"];

    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile bool _hasAdmin;
    private volatile string? _token;

    /// <summary>True while no admin account exists.</summary>
    public bool IsRequired => !_hasAdmin;

    /// <summary>The one-time setup token; null once an account exists.</summary>
    internal string? Token => _token;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
        _hasAdmin = await db.Users.AnyAsync(cancellationToken).ConfigureAwait(false);
        if (!_hasAdmin)
        {
            _token = NewToken();
            LogSetupRequired(logger, $"http://127.0.0.1:{endpoints.Value.AdminPort}{AdminIdentity.SetupPath}", _token);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public void Dispose() => _gate.Dispose();

    /// <summary>
    /// True when the request comes from this machine: from a loopback address, and not passed on by a proxy
    /// (a reverse proxy or tunnel on this machine would make every remote client look local).
    /// </summary>
    public static bool IsLocalRequest(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var remote = context.Connection.RemoteIpAddress;
        if (remote is null)
        {
            return false;
        }

        if (remote.IsIPv4MappedToIPv6)
        {
            remote = remote.MapToIPv4();
        }

        return IPAddress.IsLoopback(remote) && !ForwardingHeaders.Any(context.Request.Headers.ContainsKey);
    }

    /// <summary>Whether this request may create the first account: from this machine, or with the setup token.</summary>
    public bool IsAllowed(HttpContext context, string? token)
    {
        if (!IsRequired)
        {
            return false;
        }

        if (IsLocalRequest(context))
        {
            return true;
        }

        var expected = _token;
        return expected is not null && token is not null && CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(token.Trim()));
    }

    /// <summary>Creates the first admin account; fails when one already exists (also when two requests race).</summary>
    public async Task<(IdentityResult Result, IdentityUser? User)> CreateAdminAsync(
        UserManager<IdentityUser> users, string userName, string password)
    {
        ArgumentNullException.ThrowIfNull(users);

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_hasAdmin || await users.Users.AnyAsync().ConfigureAwait(false))
            {
                _hasAdmin = true;
                return (IdentityResult.Failed(new IdentityError { Code = "AdminExists", Description = Text.N("An admin account already exists. Sign in instead.") }), null);
            }

            var user = new IdentityUser(userName.Trim());
            var result = await users.CreateAsync(user, password).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return (result, null);
            }

            _hasAdmin = true;
            _token = null; // used up
            LogAdminCreated(logger, user.UserName!);
            return (result, user);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>256 random bits, as 43 URL-safe characters.</summary>
    private static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [LoggerMessage(EventId = 500, Level = LogLevel.Warning,
        Message = "No admin account exists yet. Create it at {SetupUrl} on this machine. From another machine, enter this one-time setup token: {SetupToken}")]
    private static partial void LogSetupRequired(ILogger logger, string setupUrl, string setupToken);

    [LoggerMessage(EventId = 501, Level = LogLevel.Information, Message = "Admin account '{UserName}' created; first-run setup is closed.")]
    private static partial void LogAdminCreated(ILogger logger, string userName);
}
