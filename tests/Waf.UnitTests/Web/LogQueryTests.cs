using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using FASoft.Waf.Data;
using FASoft.Waf.Web;

namespace FASoft.Waf.UnitTests.Web;

public class LogQueryTests
{
    private static LogQuery Parse(string query) => LogQuery.Parse(new QueryCollection(QueryHelpers.ParseQuery(query)));

    [Fact]
    public void Defaults_are_the_last_24_hours_and_50_per_page()
    {
        var query = Parse("");

        Assert.Equal(("24h", LogView.All, 50, false, true), (query.Range, query.Show, query.Size, query.IsFiltered, query.IsFirstPage));
        Assert.Equal(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero), query.ToFilter(new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero)).From);
        Assert.Equal("logs", query.Url("logs"));
    }

    [Fact]
    public void Filters_round_trip_through_the_url()
    {
        var query = Parse("range=1h&show=blocked&ip=203.0.113.7&host=www.example.com&route=api&rule=no-admin&status=403&q=%2Fadmin&size=100&before=42");

        Assert.Equal(("1h", LogView.Blocked, "203.0.113.7", "/admin", 403, 100, 42L), (query.Range, query.Show, query.Ip, query.Search, query.Status, query.Size, query.Before));
        Assert.True(query.IsFiltered);
        Assert.False(query.IsFirstPage);

        var again = Parse(new Uri("http://x/" + query.Url("logs")).Query);
        Assert.Equal(query with { Before = null }, again);
        Assert.Equal(query.ToFilter(DateTimeOffset.UnixEpoch.AddDays(1)), again.ToFilter(DateTimeOffset.UnixEpoch.AddDays(1)));
    }

    [Fact]
    public void Invalid_values_fall_back_to_defaults()
    {
        var query = Parse("range=1y&show=nonsense&size=7&status=999&before=-5&after=abc&q=%20%20");

        Assert.Equal(("24h", LogView.All, 50, (int?)null, (long?)null, (long?)null, (string?)null), (query.Range, query.Show, query.Size, query.Status, query.Before, query.After, query.Search));
        Assert.Null(Parse("range=all").ToFilter(DateTimeOffset.UtcNow).From);
    }

    [Fact]
    public void Url_with_replaces_one_filter()
    {
        var query = Parse("show=Blocked&ip=1.2.3.4");

        Assert.Equal("logs?show=Blocked&ip=5.6.7.8", query.UrlWith("ip", "5.6.7.8"));
    }
}
