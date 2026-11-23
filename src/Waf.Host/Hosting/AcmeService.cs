using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;
using FASoft.Waf.Proxy;
using FASoft.Waf.Proxy.Acme;
using Microsoft.Extensions.Options;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// Host settings for Let's Encrypt (<c>Gateway:Acme</c> in appsettings, not part of the configuration). Normally all
/// empty: the configuration's <c>Settings.Acme.UseStaging</c> chooses between Let's Encrypt production and staging.
/// </summary>
public sealed class AcmeHostOptions
{
    public const string SectionName = "Gateway:Acme";

    public const string ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory";
    public const string StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// <summary>Another ACME server instead of Let's Encrypt, e.g. a test server such as Pebble.</summary>
    public string? DirectoryUrl { get; set; }

    /// <summary>PEM file with the root certificate to trust for <see cref="DirectoryUrl"/> (a test server's own CA).</summary>
    public string? TrustedRootCertificatePath { get; set; }

    /// <summary>How often certificates are checked for renewal (minutes).</summary>
    public int CheckIntervalMinutes { get; set; } = 60;

    /// <summary>Seconds between status checks while the ACME server works.</summary>
    public double PollIntervalSeconds { get; set; } = 2;

    /// <summary>The directory to use for <paramref name="settings"/>.</summary>
    public string Directory(AcmeSettings? settings) =>
        !string.IsNullOrWhiteSpace(DirectoryUrl) ? DirectoryUrl : settings?.UseStaging == true ? StagingDirectory : ProductionDirectory;
}

/// <summary>Let's Encrypt state per host name (last error, when to try again) and the "check now" signal.</summary>
public sealed class AcmeState : IDisposable
{
    /// <summary>Waits after a failed attempt: Let's Encrypt limits failed validations, so retries slow down.</summary>
    private static readonly TimeSpan[] Backoff = [TimeSpan.FromMinutes(10), TimeSpan.FromHours(1), TimeSpan.FromHours(6), TimeSpan.FromHours(24)];

    private readonly Dictionary<string, HostState> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _signal = new(0, 1);

    public void Dispose() => _signal.Dispose();

    public sealed record HostState(string? LastError, DateTime? LastFailureUtc, DateTime? NextAttemptUtc, int Failures);

    public HostState? Get(string hostName)
    {
        lock (_hosts)
        {
            return _hosts.GetValueOrDefault(hostName);
        }
    }

    public bool MayTry(string hostName, DateTime nowUtc) => Get(hostName)?.NextAttemptUtc is not { } next || next <= nowUtc;

    public void Failed(string hostName, string error, DateTime nowUtc)
    {
        lock (_hosts)
        {
            var failures = (_hosts.GetValueOrDefault(hostName)?.Failures ?? 0) + 1;
            _hosts[hostName] = new HostState(error, nowUtc, nowUtc + Backoff[Math.Min(failures, Backoff.Length) - 1], failures);
        }
    }

    public void Succeeded(string hostName)
    {
        lock (_hosts)
        {
            _hosts.Remove(hostName);
        }
    }

    /// <summary>Asks for a check now; with <paramref name="resetBackoff"/> also for host names that failed recently.</summary>
    public void Trigger(bool resetBackoff = false)
    {
        if (resetBackoff)
        {
            lock (_hosts)
            {
                foreach (var host in _hosts.Keys.ToList())
                {
                    _hosts[host] = _hosts[host] with { NextAttemptUtc = null };
                }
            }
        }

        try
        {
            _signal.Release();
        }
        catch (SemaphoreFullException)
        {
            // a check is already requested
        }
    }

    /// <summary>Waits until <see cref="Trigger"/> or <paramref name="timeout"/>.</summary>
    public Task<bool> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken) => _signal.WaitAsync(timeout, cancellationToken);
}

/// <summary>
/// Obtains and renews Let's Encrypt certificates (ACME HTTP-01) for the host names whose certificate source is
/// LetsEncrypt. Checks after every configuration change and every hour; renews 30 days before the end date. The
/// challenge is answered on port 80 by <see cref="AcmeChallengeMiddleware"/>, which runs before everything else.
/// </summary>
internal sealed partial class AcmeService(
    ConfigurationStore configurations,
    CertificateStore certificates,
    AcmeAccountStore accounts,
    InMemoryAcmeChallengeStore challenges,
    CertificateService certificateService,
    AcmeState state,
    AuditLogStore audit,
    IOptions<AcmeHostOptions> options,
    TimeProvider time,
    ILogger<AcmeService> logger) : BackgroundService
{
    /// <summary>Renewal starts at the latest this long before the end date.</summary>
    public static readonly TimeSpan RenewBefore = TimeSpan.FromDays(30);

    /// <summary>
    /// True when <paramref name="certificate"/> should be renewed: a third of its lifetime is left, and at most 30 days
    /// (Let's Encrypt's advice: day 60 of a 90-day certificate, day 4 of a 6-day one).
    /// </summary>
    public static bool IsDue(StoredCertificate certificate, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var lifetime = certificate.NotAfterUtc - certificate.NotBeforeUtc;
        var threshold = lifetime / 3 < RenewBefore ? lifetime / 3 : RenewBefore;
        return certificate.NotAfterUtc - nowUtc <= threshold;
    }

    private static readonly AuditActor Actor = AuditActor.System("Let's Encrypt");

    private readonly SemaphoreSlim _run = new(1, 1);

    public override void Dispose()
    {
        _run.Dispose();
        base.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Max(1, options.Value.CheckIntervalMinutes));
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await RunOnceAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    throw;
                }
#pragma warning disable CA1031 // Certificate renewal must never stop the gateway.
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    LogRunFailed(logger, ex);
                }

                await state.WaitAsync(interval, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    /// <summary>Obtains or renews what is due; returns how many certificates were issued.</summary>
    public async Task<int> RunOnceAsync(CancellationToken cancellationToken)
    {
        await _run.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var active = await configurations.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
            var hosts = active?.Configuration.Certificates
                .Where(c => c.Source == CertificateSource.LetsEncrypt)
                .Select(c => c.HostName)
                .ToList() ?? [];
            var settings = active?.Configuration.Settings.Acme;
            if (hosts.Count == 0 || settings is not { AcceptTermsOfService: true, Email: { Length: > 0 } email })
            {
                return 0;
            }

            var directory = options.Value.Directory(settings);
            var now = time.GetUtcNow().UtcDateTime;
            var due = new List<string>();
            foreach (var host in hosts)
            {
                var current = await certificates.FindAcmeAsync(host, directory, cancellationToken).ConfigureAwait(false);
                if ((current is null || IsDue(current, now)) && state.MayTry(host, now))
                {
                    due.Add(host);
                }
            }

            if (due.Count == 0)
            {
                return 0;
            }

            using var http = CreateHttpClient();
            AcmeClient client;
            try
            {
                client = await ClientAsync(http, directory, email, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsAcmeFailure(ex))
            {
                foreach (var host in due)
                {
                    Failed(host, $"The Let's Encrypt account could not be set up: {Describe(ex)}");
                }

                await certificateService.ReloadAsync(cancellationToken).ConfigureAwait(false);
                return 0;
            }

            var issued = 0;
            foreach (var host in due)
            {
                if (await IssueAsync(client, host, directory, cancellationToken).ConfigureAwait(false))
                {
                    issued++;
                }
            }

            // New certificates go live, and failures show up in the statuses and on the dashboard.
            await certificateService.ReloadAsync(cancellationToken).ConfigureAwait(false);
            return issued;
        }
        finally
        {
            _run.Release();
        }
    }

    /// <summary>Renews the certificate of <paramref name="hostName"/> now, whether it is due or not (for tests).</summary>
    internal async Task<bool> RenewNowAsync(string hostName, CancellationToken cancellationToken)
    {
        await _run.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var settings = (await configurations.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false))?.Configuration.Settings.Acme;
            var directory = options.Value.Directory(settings);
            using var http = CreateHttpClient();
            var client = await ClientAsync(http, directory, settings!.Email!, cancellationToken).ConfigureAwait(false);
            var renewed = await IssueAsync(client, hostName, directory, cancellationToken).ConfigureAwait(false);
            await certificateService.ReloadAsync(cancellationToken).ConfigureAwait(false);
            return renewed;
        }
        finally
        {
            _run.Release();
        }
    }

    private async Task<bool> IssueAsync(AcmeClient client, string host, string directory, CancellationToken cancellationToken)
    {
        var renewal = await certificates.FindAcmeAsync(host, directory, cancellationToken).ConfigureAwait(false) is not null;
        try
        {
            var obtained = await client.IssueAsync(host, challenges.Add, challenges.Remove, cancellationToken).ConfigureAwait(false);
            var read = CertificateFiles.Read(Encoding.ASCII.GetBytes(obtained.ChainPem), null, Encoding.ASCII.GetBytes(obtained.PrivateKeyPem));
            if (read.Certificate is not { } certificate)
            {
                Failed(host, $"The certificate from Let's Encrypt could not be read: {read.Error}");
                return false;
            }

            using (certificate)
            {
                var (stored, _) = await certificates.AddAcmeAsync(certificate, host, directory, cancellationToken).ConfigureAwait(false);
                await certificates.DeleteOtherAcmeAsync(host, stored.Thumbprint, cancellationToken).ConfigureAwait(false);
                state.Succeeded(host);
                LogIssued(logger, host, renewal ? "renewed" : "issued", stored.NotAfterUtc);
                await audit.RecordAsync(
                    AuditCategory.Security,
                    renewal ? AuditActions.CertificateRenewed : AuditActions.CertificateIssued,
                    Actor,
                    $"Let's Encrypt certificate for {host} {(renewal ? "renewed" : "issued")} (valid until {stored.NotAfterUtc:yyyy-MM-dd}).",
                    $"SHA-256 thumbprint {stored.Thumbprint}; issuer {stored.Issuer}; ACME directory {directory}.",
                    cancellationToken).ConfigureAwait(false);
                return true;
            }
        }
        catch (Exception ex) when (IsAcmeFailure(ex))
        {
            Failed(host, Describe(ex));
            return false;
        }
    }

    private void Failed(string host, string error)
    {
        state.Failed(host, error, time.GetUtcNow().UtcDateTime);
        LogFailed(logger, host, error, state.Get(host)?.NextAttemptUtc);
    }

    /// <summary>The message with the inner causes (e.g. why a TLS connection to the ACME server failed).</summary>
    private static string Describe(Exception ex)
    {
        var text = new StringBuilder(ex.Message);
        for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
        {
            text.Append(' ').Append(inner.Message);
        }

        return text.ToString();
    }

    private static bool IsAcmeFailure(Exception ex) =>
        ex is AcmeException or HttpRequestException or System.Text.Json.JsonException or CryptographicException
        || (ex is TaskCanceledException && ex.InnerException is TimeoutException);

    /// <summary>The account for <paramref name="directory"/>: stored, or created now (accepting the terms of service).</summary>
    private async Task<AcmeClient> ClientAsync(HttpClient http, string directory, string email, CancellationToken cancellationToken)
    {
        var pollInterval = TimeSpan.FromSeconds(Math.Clamp(options.Value.PollIntervalSeconds, 0.05, 60));
        var stored = await accounts.GetAsync(directory, cancellationToken).ConfigureAwait(false);
        if (stored is { } existing)
        {
            var key = ECDsa.Create();
            key.ImportPkcs8PrivateKey(existing.Key, out _);
            return new AcmeClient(http, new Uri(directory), key, time) { AccountUrl = existing.Account.AccountUrl, PollInterval = pollInterval };
        }

        var newKey = AcmeClient.CreateAccountKey();
        var client = new AcmeClient(http, new Uri(directory), newKey, time) { PollInterval = pollInterval };
        var accountUrl = await client.RegisterAsync(email, cancellationToken).ConfigureAwait(false);
        await accounts.SaveAsync(directory, accountUrl, email, newKey.ExportPkcs8PrivateKey(), cancellationToken).ConfigureAwait(false);
        LogAccountCreated(logger, directory);
        return client;
    }

    private HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
        if (options.Value.TrustedRootCertificatePath is { Length: > 0 } rootPath)
        {
            // A test ACME server with its own CA: trust exactly that root, nothing else.
            var roots = new X509Certificate2Collection();
            roots.ImportFromPemFile(rootPath);
            // A test CA publishes no revocation lists.
            handler.SslOptions.CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
            };
            handler.SslOptions.CertificateChainPolicy.CustomTrustStore.AddRange(roots);
        }

        var http = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(60) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"WafGateway/{Core.ProductInfo.Version}");
        return http;
    }

    [LoggerMessage(EventId = 610, Level = LogLevel.Information, Message = "Let's Encrypt certificate for {HostName} {What}, valid until {NotAfter:u}.")]
    private static partial void LogIssued(ILogger logger, string hostName, string what, DateTime notAfter);

    [LoggerMessage(EventId = 611, Level = LogLevel.Warning, Message = "Let's Encrypt certificate for {HostName} could not be obtained: {Error} Next attempt: {NextAttempt:u}.")]
    private static partial void LogFailed(ILogger logger, string hostName, string error, DateTime? nextAttempt);

    [LoggerMessage(EventId = 612, Level = LogLevel.Information, Message = "Let's Encrypt account created at {Directory}.")]
    private static partial void LogAccountCreated(ILogger logger, string directory);

    [LoggerMessage(EventId = 613, Level = LogLevel.Error, Message = "Checking Let's Encrypt certificates failed; retrying later.")]
    private static partial void LogRunFailed(ILogger logger, Exception exception);
}
