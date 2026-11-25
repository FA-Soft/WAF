using Microsoft.Data.Sqlite;
using FASoft.Waf.Engine;

namespace FASoft.Waf.Data;

/// <summary>Which traffic a notice is about.</summary>
public enum AlertMetric
{
    Total = 0,
    Bad = 1,
    Failed = 2,
}

/// <summary>
/// The usual traffic per hour of the week (Monday 00:00 UTC is slot 0), in requests per second, for total, bad and
/// failed requests: the median of the same hour on the same weekday over the last four weeks of history, or, while
/// there are fewer than two of those, of the same hour on any day.
/// </summary>
public sealed class UsualProfile
{
    /// <summary>Hours of history needed before notices are given: one day.</summary>
    public const int MinimumHours = 24;

    private readonly double[][] _rates; // [metric][slot]

    internal UsualProfile(double[][] rates, int hours)
    {
        _rates = rates;
        Hours = hours;
    }

    /// <summary>Hours of history the profile was made from.</summary>
    public int Hours { get; }

    /// <summary>True when there is enough history to tell what is unusual.</summary>
    public bool IsReady => Hours >= MinimumHours;

    /// <summary>The usual requests per second of <paramref name="metric"/> at <paramref name="time"/>.</summary>
    public double RateAt(AlertMetric metric, DateTimeOffset time) => _rates[(int)metric][Slot(time.ToUnixTimeSeconds())];

    /// <summary>The hour of the week of a moment: 0 for Monday 00:00 to 00:59 UTC.</summary>
    public static int Slot(long unixSeconds)
    {
        var week = MetricsBuckets.Start(MetricsTier.Week, unixSeconds);
        return (int)((unixSeconds - week) / 3600);
    }
}

/// <summary>A notice of unusual traffic: open while it lasts, kept afterwards in the list of past notices.</summary>
/// <param name="Id">Its number.</param>
/// <param name="Metric">Total, bad or failed traffic.</param>
/// <param name="Start">When it began.</param>
/// <param name="End">When the traffic was back to normal; null while it lasts.</param>
/// <param name="Usual">The usual requests per second at the start.</param>
/// <param name="Peak">The highest requests per second (over a minute) while it lasted.</param>
/// <param name="Kind">For bad traffic: the kind most of it was.</param>
/// <param name="Name">The rule, attack category or limit of <paramref name="Kind"/>.</param>
/// <param name="Network">For bad traffic: the network most of it came from, when known.</param>
public sealed record TrafficAlert(long Id, AlertMetric Metric, DateTimeOffset Start, DateTimeOffset? End, double Usual, double Peak, TrafficKind? Kind, string? Name, string? Network)
{
    /// <summary>How many times the usual level the peak was; null when the usual level is zero.</summary>
    public double? Ratio => Usual > 0 ? Peak / Usual : null;
}

/// <summary>The usual-traffic profile and the notices of unusual traffic in <c>metrics.db</c>.</summary>
/// <remarks><c>TrafficAlerts(Id, Metric, Start, End, Usual, Peak, Kind, Name, Network)</c>; kept as long as the month tier.</remarks>
public sealed partial class SqliteMetricsStore
{
    /// <summary>Weeks of history the usual traffic is learned from (hours are kept four weeks).</summary>
    public const int ProfileWeeks = 4;

    /// <summary>The usual traffic per hour of the week, from the hour tier of the last four weeks before <paramref name="now"/>.</summary>
    public async Task<UsualProfile> ReadUsualProfileAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var to = MetricsBuckets.Start(MetricsTier.Hour, now.ToUnixTimeSeconds());
        var from = to - (ProfileWeeks * 7 * 24 * 3600L);
        var sums = new Dictionary<long, long[]>();
        long? oldest = null;

        if (File.Exists(DatabasePath))
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT BucketStart, Outcome, SUM(Count) FROM TrafficCounts
                WHERE Tier = $tier AND BucketStart >= $from AND BucketStart < $to
                GROUP BY BucketStart, Outcome
                """;
            command.Parameters.AddWithValue("$tier", (int)MetricsTier.Hour);
            command.Parameters.AddWithValue("$from", from);
            command.Parameters.AddWithValue("$to", to);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var hour = reader.GetInt64(0);
                var outcome = reader.GetInt32(1);
                if (outcome is < 0 or > 2)
                {
                    continue;
                }

                if (!sums.TryGetValue(hour, out var row))
                {
                    sums[hour] = row = new long[3];
                }

                row[outcome] += reader.GetInt64(2);
                oldest = oldest is { } o ? Math.Min(o, hour) : hour;
            }
        }

        // Every hour from the first one with traffic up to now counts, quiet hours (no rows) as zero.
        var bySlot = Enumerable.Range(0, 168).Select(_ => new List<long[]>()).ToArray();
        var hours = 0;
        if (oldest is { } first)
        {
            for (var hour = first; hour < to; hour += 3600)
            {
                bySlot[UsualProfile.Slot(hour)].Add(sums.GetValueOrDefault(hour) ?? new long[3]);
                hours++;
            }
        }

        var rates = new double[3][];
        for (var metric = 0; metric < 3; metric++)
        {
            rates[metric] = new double[168];
            for (var slot = 0; slot < 168; slot++)
            {
                // The rows hold good, bad and failed requests; the total is their sum.
                var m = metric;
                double Rate(long[] r) => (m == (int)AlertMetric.Total ? r[0] + r[1] + r[2] : r[m]) / 3600.0;
                var sameWeekday = bySlot[slot].Select(Rate).ToList();
                var sameHour = Enumerable.Range(0, 7).SelectMany(day => bySlot[(day * 24) + (slot % 24)]).Select(Rate).ToList();
                rates[metric][slot] = sameWeekday.Count >= 2 ? Median(sameWeekday) : sameHour.Count > 0 ? Median(sameHour) : 0;
            }
        }

        return new UsualProfile(rates, hours);
    }

    private static double Median(List<double> values)
    {
        values.Sort();
        var middle = values.Count / 2;
        return values.Count % 2 == 1 ? values[middle] : (values[middle - 1] + values[middle]) / 2;
    }

    /// <summary>Starts a notice; returns its number.</summary>
    public async Task<long> OpenAlertAsync(AlertMetric metric, DateTimeOffset start, double usual, double peak, TrafficKind? kind, string? name, string? network, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO TrafficAlerts (Metric, Start, End, Usual, Peak, Kind, Name, Network) VALUES ($metric, $start, NULL, $usual, $peak, $kind, $name, $network);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$metric", (int)metric);
        command.Parameters.AddWithValue("$start", start.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$usual", usual);
        command.Parameters.AddWithValue("$peak", peak);
        command.Parameters.AddWithValue("$kind", kind is { } k ? (int)k : DBNull.Value);
        command.Parameters.AddWithValue("$name", (object?)name ?? DBNull.Value);
        command.Parameters.AddWithValue("$network", (object?)network ?? DBNull.Value);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Updates a running notice: a higher peak and what most of the traffic is now.</summary>
    public async Task UpdateAlertAsync(long id, double peak, TrafficKind? kind, string? name, string? network, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE TrafficAlerts SET Peak = MAX(Peak, $peak), Kind = COALESCE($kind, Kind), Name = COALESCE($name, Name), Network = COALESCE($network, Network)
            WHERE Id = $id
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$peak", peak);
        command.Parameters.AddWithValue("$kind", kind is { } k ? (int)k : DBNull.Value);
        command.Parameters.AddWithValue("$name", (object?)name ?? DBNull.Value);
        command.Parameters.AddWithValue("$network", (object?)network ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Ends a notice (or every running one when <paramref name="id"/> is null, e.g. when notices are switched off).</summary>
    public async Task CloseAlertsAsync(long? id, DateTimeOffset end, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE TrafficAlerts SET End = $end WHERE End IS NULL AND ($id IS NULL OR Id = $id)";
        command.Parameters.AddWithValue("$end", end.ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$id", (object?)id ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The newest notices, running ones first.</summary>
    public async Task<List<TrafficAlert>> ReadAlertsAsync(int limit, bool runningOnly, CancellationToken cancellationToken)
    {
        var result = new List<TrafficAlert>();
        if (!File.Exists(DatabasePath))
        {
            return result;
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT Id, Metric, Start, End, Usual, Peak, Kind, Name, Network FROM TrafficAlerts
            {(runningOnly ? "WHERE End IS NULL" : string.Empty)}
            ORDER BY End IS NOT NULL, Start DESC LIMIT $limit
            """;
        command.Parameters.AddWithValue("$limit", limit);
        try
        {
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                result.Add(new TrafficAlert(
                    reader.GetInt64(0),
                    (AlertMetric)reader.GetInt32(1),
                    DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(2)),
                    reader.IsDBNull(3) ? null : DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64(3)),
                    reader.GetDouble(4),
                    reader.GetDouble(5),
                    reader.IsDBNull(6) ? null : (TrafficKind)reader.GetInt32(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetString(8)));
            }
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 1)
        {
            // No such table yet: the database is being created or upgraded.
        }

        return result;
    }

    /// <summary>Removes notices that ended before <paramref name="cutoff"/>.</summary>
    private static async Task<long> DeleteOldAlertsAsync(SqliteConnection connection, DateTimeOffset cutoff, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM TrafficAlerts WHERE End IS NOT NULL AND End < $cutoff";
        command.Parameters.AddWithValue("$cutoff", cutoff.ToUnixTimeSeconds());
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
