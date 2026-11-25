using FASoft.Waf.Data;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Host.Hosting;

/// <summary>
/// The country database of <c>Gateway:Metrics:GeoIpFile</c>, loaded in the background at start (a large file takes a
/// few seconds, which the start must not wait for). Until it is loaded, or without one, sources have no country.
/// </summary>
internal sealed partial class CountryDatabase(MetricsOptions options, StoragePaths paths, ILogger<CountryDatabase> logger) : BackgroundService
{
    private CountryLookup? _lookup;

    /// <summary>The loaded database; null when none is configured, it is still loading, or it could not be read.</summary>
    public CountryLookup? Lookup => Volatile.Read(ref _lookup);

    /// <summary>The configured file (full path); null when none is configured.</summary>
    public string? FilePath => string.IsNullOrWhiteSpace(options.GeoIpFile) ? null : Path.GetFullPath(options.GeoIpFile, paths.DataDirectory);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (FilePath is not { } path)
        {
            return;
        }

        await Task.Yield();
        try
        {
            var lookup = await Task.Run(() => CountryLookup.Load(path), stoppingToken).ConfigureAwait(false);
            Volatile.Write(ref _lookup, lookup);
            LogLoaded(logger, lookup.Count, path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            LogLoadFailed(logger, ex, path);
        }
    }

    [LoggerMessage(EventId = 425, Level = LogLevel.Information, Message = "Country database: {Count} IP ranges read from {Path}.")]
    private static partial void LogLoaded(ILogger logger, int count, string path);

    [LoggerMessage(EventId = 426, Level = LogLevel.Warning, Message = "Country database {Path} could not be read; sources are shown without their country.")]
    private static partial void LogLoadFailed(ILogger logger, Exception exception, string path);
}
