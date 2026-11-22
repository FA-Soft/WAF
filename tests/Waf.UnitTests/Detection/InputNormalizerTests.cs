using Waf.Engine.Detection;

namespace Waf.UnitTests.Detection;

public class InputNormalizerTests
{
    [Theory]
    [InlineData("%3Cscript%3E", "<script>")]
    [InlineData("%253Cscript%253E", "<script>")]            // double encoded
    [InlineData("%25253C", "<")]                            // triple encoded
    [InlineData("%u003Cscript%u003E", "<script>")]          // IIS %u encoding
    [InlineData("%E2%82%AC", "€")]                          // UTF-8 bytes
    [InlineData("100%", "100%")]                            // malformed: kept
    [InlineData("%zz%4", "%zz%4")]
    [InlineData("&lt;script&gt;", "<script>")]
    [InlineData("&#x3C;&#60;", "<<")]
    [InlineData("%26lt%3B", "<")]                           // percent, then HTML
    [InlineData("＜ＳＣＲＩＰＴ＞", "<script>")]              // full-width (NFKC)
    [InlineData("UNION/**/SELECT", "union select")]
    [InlineData("UNION/*comment*/SELECT", "union select")]
    [InlineData("a/*unterminated", "a ")]
    [InlineData("a \t\r\n  b", "a b")]
    [InlineData("..\\..\\win.ini", "../../win.ini")]
    [InlineData("a%00b", "a\0b")]                           // null byte kept
    [InlineData("MiXeD CaSe", "mixed case")]
    [InlineData("", "")]
    public void Values_are_decoded_and_canonicalized(string raw, string expected)
    {
        Assert.Equal(expected, InputNormalizer.Normalize(raw));
    }

    [Fact]
    public void Plus_is_a_space_only_where_requested()
    {
        Assert.Equal("union select", InputNormalizer.Normalize("UNION+SELECT", plusIsSpace: true));
        Assert.Equal("1+1", InputNormalizer.Normalize("1+1"));
        Assert.Equal("1+1", InputNormalizer.Normalize("1%2B1", plusIsSpace: true)); // encoded plus stays a plus
    }

    [Fact]
    public void Decoding_stops_after_a_bounded_number_of_passes()
    {
        // Four levels of encoding: only three are undone.
        Assert.Equal("%3c", InputNormalizer.Normalize("%2525253C"));
    }
}
