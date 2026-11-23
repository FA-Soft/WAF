using BenchmarkDotNet.Running;

namespace FASoft.Waf.Benchmarks;

/// <summary>Runs the benchmarks chosen on the command line.</summary>
internal static class Program
{
    public static void Main(string[] args) => BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
}
