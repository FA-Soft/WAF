using System.Net.Security;
using FASoft.Waf.Core.Configuration;
using FASoft.Waf.Core.Tls;
using FASoft.Waf.Data;
using Microsoft.AspNetCore.DataProtection;

namespace FASoft.Waf.Host.Hosting;

/// <summary>Encrypts uploaded certificates with ASP.NET Core Data Protection (keys in the data folder; DPAPI on Windows).</summary>
internal sealed class DataProtectionCertificateProtector(IDataProtectionProvider provider) : ICertificateProtector
{
    private readonly IDataProtector _protector = provider.CreateProtector("FASoft.Waf.Certificates.v1");

    public byte[] Protect(byte[] plaintext) => _protector.Protect(plaintext);

    public byte[] Unprotect(byte[] protectedData) => _protector.Unprotect(protectedData);
}

/// <summary>Encrypts AI provider API keys with ASP.NET Core Data Protection (a purpose of its own).</summary>
internal sealed class DataProtectionApiKeyProtector(IDataProtectionProvider provider) : IApiKeyProtector
{
    private readonly IDataProtector _protector = provider.CreateProtector("FASoft.Waf.AiApiKey.v1");

    public byte[] Protect(byte[] plaintext) => _protector.Protect(plaintext);

    public byte[] Unprotect(byte[] protectedData) => _protector.Unprotect(protectedData);
}

/// <summary>
/// The TLS certificates of the active configuration: picks the certificate for each handshake by SNI host name and
/// reports per host name whether its certificate is fine, expiring, expired or missing.
/// </summary>
/// <remarks>
/// Certificates are loaded into an immutable snapshot, rebuilt after every activation, after uploads and every
/// <see cref="RefreshInterval"/> (so renewed certificate files on disk and approaching end dates are noticed).
/// A handshake only reads the snapshot. An exact host name wins over a wildcard.
/// </remarks>
internal sealed partial class CertificateService(
    ConfigurationStore configurations,
    CertificateStore store,
    AuditLogStore audit,
    AcmeState acme,
    Microsoft.Extensions.Options.IOptions<AcmeHostOptions> acmeOptions,
    TimeProvider time,
    ILogger<CertificateService> logger) : IServerCertificateSelector, Web.ICertificateManager, IDisposable
{
    /// <summary>How often certificates are reloaded and checked.</summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(5);

    /// <summary>Old certificates are disposed this long after a reload, when no handshake uses them any more.</summary>
    private static readonly TimeSpan DisposeDelay = TimeSpan.FromMinutes(1);

    private readonly SemaphoreSlim _reload = new(1, 1);
    private readonly Dictionary<string, DateOnly> _warned = new(StringComparer.OrdinalIgnoreCase);
    private Snapshot _snapshot = Snapshot.Empty;

    public IReadOnlyList<CertificateStatus> Statuses => Volatile.Read(ref _snapshot).Statuses;

    public void Dispose() => _reload.Dispose();

    public SslStreamCertificateContext? SelectCertificate(string? hostName)
    {
        if (string.IsNullOrEmpty(hostName))
        {
            return null; // no SNI (e.g. https://203.0.113.5/): there is no certificate to choose
        }

        var snapshot = Volatile.Read(ref _snapshot);
        if (snapshot.Exact.TryGetValue(hostName, out var exact))
        {
            return exact;
        }

        foreach (var (pattern, context) in snapshot.Wildcards)
        {
            if (CertificateNames.Matches(pattern, hostName))
            {
                return context;
            }
        }

        return null;
    }

    /// <summary>Uploaded certificates only; Let's Encrypt certificates are managed automatically.</summary>
    public async Task<IReadOnlyList<StoredCertificate>> GetStoredAsync(CancellationToken cancellationToken) =>
        [.. (await store.GetAllAsync(cancellationToken).ConfigureAwait(false)).Where(c => !c.IsAcme)];

    public void RequestLetsEncryptNow() => acme.Trigger(resetBackoff: true);

    public async Task<Web.CertificateUploadResult> UploadAsync(
        byte[] certificateFile, string? password, byte[]? keyFile, AuditActor actor, CancellationToken cancellationToken)
    {
        var read = CertificateFiles.Read(certificateFile, password, keyFile);
        if (read.Certificate is not { } certificate)
        {
            return Web.CertificateUploadResult.Failed(read.Error!);
        }

        using (certificate)
        {
            if (certificate.Leaf.NotAfter.ToUniversalTime() < time.GetUtcNow().UtcDateTime)
            {
                return Web.CertificateUploadResult.Failed($"This certificate expired on {certificate.Leaf.NotAfter.ToUniversalTime():yyyy-MM-dd}; upload a current one.");
            }

            if (certificate.DnsNames.Count == 0)
            {
                return Web.CertificateUploadResult.Failed("This certificate names no host (no subject alternative names or common name).");
            }

            var (stored, added) = await store.AddAsync(certificate, actor.UserName, cancellationToken).ConfigureAwait(false);
            if (added)
            {
                await audit.RecordAsync(
                    AuditCategory.Security, AuditActions.CertificateUploaded, actor,
                    $"Certificate for {string.Join(", ", stored.DnsNameList)} uploaded (valid until {stored.NotAfterUtc:yyyy-MM-dd}).",
                    $"SHA-256 thumbprint {stored.Thumbprint}; subject {stored.Subject}; issuer {stored.Issuer}.",
                    cancellationToken).ConfigureAwait(false);
            }

            return new Web.CertificateUploadResult(stored, added, []);
        }
    }

    public async Task<IReadOnlyList<string>> DeleteAsync(string thumbprint, AuditActor actor, CancellationToken cancellationToken)
    {
        var active = await configurations.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
        var users = active?.Configuration.Certificates
            .Where(c => c.Source == CertificateSource.Uploaded && string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
            .Select(c => c.HostName)
            .ToList() ?? [];
        if (users.Count > 0)
        {
            return [$"The certificate is still used for {string.Join(", ", users)}. Remove it from those host names first."];
        }

        var stored = (await store.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(c => string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
        if (stored is null || !await store.DeleteAsync(thumbprint, cancellationToken).ConfigureAwait(false))
        {
            return ["The certificate was not found."];
        }

        await audit.RecordAsync(
            AuditCategory.Security, AuditActions.CertificateDeleted, actor,
            $"Certificate for {string.Join(", ", stored.DnsNameList)} deleted.", $"SHA-256 thumbprint {stored.Thumbprint}.",
            cancellationToken).ConfigureAwait(false);
        return [];
    }

    /// <summary>Reloads every certificate of the active configuration and swaps the snapshot.</summary>
    public async Task ReloadAsync(CancellationToken cancellationToken)
    {
        await _reload.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var active = await configurations.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
            var snapshot = await BuildAsync(active?.Configuration, cancellationToken).ConfigureAwait(false);
            var previous = Interlocked.Exchange(ref _snapshot, snapshot);
            WarnAboutProblems(snapshot.Statuses);
            if (previous.Loaded.Count > 0)
            {
                _ = DisposeLaterAsync(previous);
            }
        }
        finally
        {
            _reload.Release();
        }
    }

    private async Task<Snapshot> BuildAsync(GatewayConfiguration? configuration, CancellationToken cancellationToken)
    {
        var bindings = configuration?.Certificates ?? [];
        var directory = acmeOptions.Value.Directory(configuration?.Settings.Acme);
        var acmeDue = false;
        var now = time.GetUtcNow().UtcDateTime;
        var exact = new Dictionary<string, SslStreamCertificateContext>(StringComparer.OrdinalIgnoreCase);
        var wildcards = new List<(string, SslStreamCertificateContext)>();
        var statuses = new List<CertificateStatus>();
        var loaded = new Dictionary<string, (ServerCertificate Certificate, SslStreamCertificateContext Context)>(StringComparer.OrdinalIgnoreCase);

        foreach (var binding in bindings)
        {
            string? acmeThumbprint = null;
            if (binding.Source == CertificateSource.LetsEncrypt)
            {
                // The newest certificate from the current directory: switching staging to production gets a new one.
                var issued = await store.FindAcmeAsync(binding.HostName, directory, cancellationToken).ConfigureAwait(false);
                var failure = acme.Get(binding.HostName)?.LastError;
                if (issued is null)
                {
                    acmeDue = true;
                    statuses.Add(failure is null
                        ? new CertificateStatus(binding.HostName, binding.Source, CertificateState.Pending, null, null, null,
                            "Requested from Let's Encrypt; this usually takes less than a minute.")
                        : new CertificateStatus(binding.HostName, binding.Source, CertificateState.Missing, null, null, null,
                            $"Let's Encrypt failed: {failure}"));
                    continue;
                }

                acmeDue |= AcmeService.IsDue(issued, now);
                acmeThumbprint = issued.Thumbprint;
            }

            // One load per certificate, shared by the host names that use it.
            var key = binding.Source switch
            {
                CertificateSource.Uploaded => $"store:{binding.Thumbprint}",
                CertificateSource.LetsEncrypt => $"store:{acmeThumbprint}",
                _ => $"file:{binding.CertificatePath}|{binding.KeyPath}",
            };
            if (!loaded.TryGetValue(key, out var entry))
            {
                var (certificate, problem) = await LoadAsync(binding, acmeThumbprint, cancellationToken).ConfigureAwait(false);
                if (certificate is null)
                {
                    statuses.Add(new CertificateStatus(binding.HostName, binding.Source, CertificateState.Missing, null, binding.Thumbprint, null, problem));
                    continue;
                }

                entry = (certificate, SslStreamCertificateContext.Create(certificate.Leaf, certificate.Intermediates, offline: true));
                loaded[key] = entry;
            }

            if (binding.HostName.StartsWith("*.", StringComparison.Ordinal))
            {
                wildcards.Add((binding.HostName, entry.Context));
            }
            else
            {
                exact[binding.HostName] = entry.Context;
            }

            statuses.Add(Status(binding, entry.Certificate, now));
        }

        if (acmeDue)
        {
            acme.Trigger();
        }

        return new Snapshot(exact, wildcards, statuses, [.. loaded.Values.Select(v => v.Certificate)]);
    }

    private async Task<(ServerCertificate? Certificate, string? Problem)> LoadAsync(CertificateBinding binding, string? acmeThumbprint, CancellationToken cancellationToken)
    {
        try
        {
            if (binding.Source is CertificateSource.Uploaded or CertificateSource.LetsEncrypt)
            {
                var certificate = await store.LoadAsync(acmeThumbprint ?? binding.Thumbprint!, cancellationToken).ConfigureAwait(false);
                return certificate is null
                    ? (null, "The uploaded certificate is not in the certificate store (deleted, or a backup was restored without secrets). Upload it again.")
                    : (certificate, null);
            }

            var read = CertificateFiles.ReadFiles(binding.CertificatePath!, binding.KeyPath);
            return (read.Certificate, read.Error);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            // E.g. the data-protection keys of another machine: the stored key cannot be decrypted here.
            return (null, $"The certificate could not be decrypted or read: {ex.Message}");
        }
    }

    private CertificateStatus Status(CertificateBinding binding, ServerCertificate certificate, DateTime now)
    {
        // Let's Encrypt certificates renew 30 days ahead: only warn when renewal is clearly not working.
        var warningPeriod = binding.Source == CertificateSource.LetsEncrypt ? TimeSpan.FromDays(20) : CertificateStatus.WarningPeriod;
        var acmeError = binding.Source == CertificateSource.LetsEncrypt && acme.Get(binding.HostName)?.LastError is { } error
            ? $" Renewal failed: {error}"
            : string.Empty;
        var leaf = certificate.Leaf;
        var notBefore = leaf.NotBefore.ToUniversalTime();
        var notAfter = leaf.NotAfter.ToUniversalTime();
        var (state, problem) = true switch
        {
            _ when !CertificateNames.Covers(certificate.DnsNames, binding.HostName) =>
                (CertificateState.WrongHost, $"The certificate is for {string.Join(", ", certificate.DnsNames)}, not {binding.HostName}."),
            _ when notAfter <= now => (CertificateState.Expired, $"Expired on {notAfter:yyyy-MM-dd}."),
            _ when notBefore > now => (CertificateState.NotYetValid, $"Valid from {notBefore:yyyy-MM-dd HH:mm} UTC."),
            _ when notAfter - now <= warningPeriod => (CertificateState.ExpiresSoon, $"Expires on {notAfter:yyyy-MM-dd}.{acmeError}"),
            _ => (CertificateState.Ok, (string?)null),
        };
        return new CertificateStatus(binding.HostName, binding.Source, state, leaf.Subject, certificate.Thumbprint, notAfter, problem);
    }

    /// <summary>Logs a warning for each host name that needs attention, at most once a day per host name.</summary>
    private void WarnAboutProblems(IReadOnlyList<CertificateStatus> statuses)
    {
        var today = DateOnly.FromDateTime(time.GetUtcNow().UtcDateTime);
        lock (_warned)
        {
            foreach (var status in statuses.Where(s => s.NeedsAttention))
            {
                var key = $"{status.HostName}|{status.State}";
                if (_warned.TryGetValue(key, out var day) && day == today)
                {
                    continue;
                }

                _warned[key] = today;
                LogProblem(logger, status.HostName, status.State, status.Problem ?? string.Empty);
            }
        }
    }

    private async Task DisposeLaterAsync(Snapshot previous)
    {
        await Task.Delay(DisposeDelay, time).ConfigureAwait(false);
        foreach (var certificate in previous.Loaded)
        {
            certificate.Dispose();
        }
    }

    [LoggerMessage(EventId = 600, Level = LogLevel.Warning, Message = "Certificate for {HostName}: {State}. {Problem}")]
    private static partial void LogProblem(ILogger logger, string hostName, CertificateState state, string problem);

    private sealed record Snapshot(
        IReadOnlyDictionary<string, SslStreamCertificateContext> Exact,
        IReadOnlyList<(string Pattern, SslStreamCertificateContext Context)> Wildcards,
        IReadOnlyList<CertificateStatus> Statuses,
        IReadOnlyList<ServerCertificate> Loaded)
    {
        public static readonly Snapshot Empty = new(new Dictionary<string, SslStreamCertificateContext>(), [], [], []);
    }
}

/// <summary>Loads the certificates before the listeners accept connections, then reloads them periodically.</summary>
internal sealed partial class CertificateRefresher(CertificateService certificates, TimeProvider time, ILogger<CertificateRefresher> logger) : IHostedService, IDisposable
{
    private readonly CancellationTokenSource _stopping = new();
    private Task? _loop;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await ReloadAsync(cancellationToken).ConfigureAwait(false);
        _loop = LoopAsync(_stopping.Token);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        if (_loop is not null)
        {
            await _loop.ConfigureAwait(false);
        }
    }

    public void Dispose() => _stopping.Dispose();

    private async Task LoopAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(CertificateService.RefreshInterval, time);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await ReloadAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // shutting down
        }
    }

    private async Task ReloadAsync(CancellationToken cancellationToken)
    {
        try
        {
            await certificates.ReloadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // Loading certificates must never stop the gateway.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            LogReloadFailed(logger, ex);
        }
    }

    [LoggerMessage(EventId = 601, Level = LogLevel.Error, Message = "Loading the TLS certificates failed; retrying in a few minutes.")]
    private static partial void LogReloadFailed(ILogger logger, Exception exception);
}
