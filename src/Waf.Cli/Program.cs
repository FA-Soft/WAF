using FASoft.Waf.Core;

namespace FASoft.Waf.Cli;

/// <summary>Entry point of <c>wafctl</c>, the recovery tool.</summary>
internal static class Program
{
    public static int Main(string[] args)
    {
        Console.WriteLine($"wafctl - {ProductInfo.Name} recovery tool");
        Console.WriteLine("No commands are available yet.");
        return args.Length == 0 ? 0 : 1;
    }
}
