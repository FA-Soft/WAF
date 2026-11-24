using FASoft.Waf.Data;

namespace FASoft.Waf.Host.Hosting.Neighbors;

/// <summary>
/// Looks up the current IP address of every target with a MAC address, each at its own interval, and moves its routes
/// to that address without a new configuration version. Steps per round:
/// <list type="number">
/// <item>read the neighbour table; a recently confirmed entry for the MAC address is taken as it is;</item>
/// <item>otherwise contact the stale candidates (and the address in use) so the system confirms them, and read again;</item>
/// <item>still nothing: sweep the local networks (at most every <see cref="TargetResolverOptions.SweepInterval"/>) and read again.</item>
/// </list>
/// A target not found for <see cref="TargetResolverOptions.GracePeriod"/> becomes unavailable: its routes get no
/// traffic, rather than traffic for an address that may now belong to another device.
/// </summary>
internal sealed partial class TargetAddressResolver(
    TargetAddressBook book,
    INeighborTable neighbors,
    GatewayConfigurationService configurations,
    ConfigurationStore store,
    AuditLogStore audit,
    TargetResolverOptions options,
    TimeProvider time,
    ILogger<TargetAddressResolver> logger) : BackgroundService
{
    private static readonly AuditActor Actor = AuditActor.System("MAC address resolver");

    private DateTimeOffset _lastSweep = DateTimeOffset.MinValue;
    private string? _syncedHash;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        if (!options.Enabled)
        {
            return;
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
#pragma warning disable CA1031 // A failed round must not stop the resolver; the next round tries again.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                LogRoundFailed(logger, ex);
            }

            try
            {
                await Task.Delay(options.CheckInterval, time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>One round: looks up the targets that are due, records what changed, and re-applies routes if needed.</summary>
    internal async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        // The targets of the running configuration (reloaded only when it changed).
        var head = await store.GetLastKnownGoodHeadAsync(cancellationToken).ConfigureAwait(false);
        if (head is null)
        {
            return;
        }

        if (head.Value.Sha256 != _syncedHash)
        {
            var running = await store.GetLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
            book.Sync(running?.Configuration.Targets ?? []);
            _syncedHash = head.Value.Sha256;
        }

        var due = book.Due();
        if (due.Count == 0)
        {
            return;
        }

        var table = await neighbors.ReadAsync(cancellationToken).ConfigureAwait(false);
        var found = due.ToDictionary(d => d.TargetName, d => TargetAddressBook.Choose(table, d.Mac, d.Current), StringComparer.OrdinalIgnoreCase);

        // 2. Stale or missing: let the system confirm the candidates and the address in use.
        var unsure = due.Where(d => found[d.TargetName] is not { State: NeighborState.Reachable }).ToList();
        if (unsure.Count > 0)
        {
            var probe = unsure
                .SelectMany(d => table.Where(e => string.Equals(e.MacAddress, d.Mac, StringComparison.OrdinalIgnoreCase)).Select(e => e.Address)
                    .Concat(System.Net.IPAddress.TryParse(d.Current, out var current) ? [current] : []))
                .Distinct()
                .ToList();
            if (probe.Count > 0)
            {
                await neighbors.ProbeAsync(probe, cancellationToken).ConfigureAwait(false);
                await Task.Delay(options.ProbeWait, time, cancellationToken).ConfigureAwait(false);
                table = await neighbors.ReadAsync(cancellationToken).ConfigureAwait(false);
                foreach (var d in unsure)
                {
                    found[d.TargetName] = TargetAddressBook.Choose(table, d.Mac, d.Current);
                }
            }
        }

        // 3. Still not found: sweep the local networks, not too often.
        var missing = due.Where(d => found[d.TargetName] is null).ToList();
        if (missing.Count > 0 && time.GetUtcNow() - _lastSweep >= options.SweepInterval)
        {
            _lastSweep = time.GetUtcNow();
            await neighbors.SweepAsync(cancellationToken).ConfigureAwait(false);
            await Task.Delay(options.ProbeWait, time, cancellationToken).ConfigureAwait(false);
            table = await neighbors.ReadAsync(cancellationToken).ConfigureAwait(false);
            foreach (var d in missing)
            {
                found[d.TargetName] = TargetAddressBook.Choose(table, d.Mac, d.Current);
            }
        }

        var changed = false;
        foreach (var (name, mac, _) in due)
        {
            var before = book.PreviousAddress(name, mac);
            var address = found[name]?.Address.ToString();
            switch (book.Record(name, mac, address))
            {
                case TargetAddressChange.Moved:
                    changed = true;
                    LogMoved(logger, name, mac, before ?? "(unknown)", address!);
                    await audit.RecordAsync(
                        AuditCategory.Maintenance, AuditActions.TargetAddressChanged, Actor,
                        $"Target '{name}' ({mac}) is at {address}" + (before is null || before == address ? "." : $" (was {before})."),
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    break;

                case TargetAddressChange.Unavailable:
                    changed = true;
                    LogUnavailable(logger, name, mac, Duration(options.GracePeriod));
                    await audit.RecordAsync(
                        AuditCategory.Maintenance, AuditActions.TargetUnavailable, Actor,
                        $"Target '{name}' ({mac}) was not found for {Duration(options.GracePeriod)}; its routes get no traffic until it is found again.",
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    break;
            }
        }

        if (changed)
        {
            await configurations.ReapplyTargetAddressesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    [LoggerMessage(EventId = 800, Level = LogLevel.Warning, Message = "Target '{Target}' ({Mac}) moved from {Before} to {After}; its routes follow.")]
    private static partial void LogMoved(ILogger logger, string target, string mac, string before, string after);

    [LoggerMessage(EventId = 801, Level = LogLevel.Warning, Message = "Target '{Target}' ({Mac}) was not found for {Duration}; its routes get no traffic until it is found again.")]
    private static partial void LogUnavailable(ILogger logger, string target, string mac, string duration);

    /// <summary>"10 minutes", "1 minute" or "30 seconds".</summary>
    internal static string Duration(TimeSpan span) =>
        span.TotalMinutes >= 1
            ? Plural((int)Math.Round(span.TotalMinutes), "minute")
            : Plural((int)Math.Max(1, Math.Round(span.TotalSeconds)), "second");

    private static string Plural(int count, string unit) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{count} {unit}{(count == 1 ? string.Empty : "s")}");

    [LoggerMessage(EventId = 802, Level = LogLevel.Error, Message = "Looking up the MAC addresses of targets failed; trying again in the next round.")]
    private static partial void LogRoundFailed(ILogger logger, Exception exception);
}
