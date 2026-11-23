namespace FASoft.Waf.Cli;

/// <summary>Entry point of <c>wafctl</c>, the recovery tool.</summary>
internal static class Program
{
    public static Task<int> Main(string[] args) => WafCtl.RunConsoleAsync(args);
}
