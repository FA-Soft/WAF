using FASoft.Waf.Host.Hosting;

namespace FASoft.Waf.Host;

/// <summary>Entry point of the gateway.</summary>
internal static class Program
{
    public static async Task<int> Main(string[] args) =>
        await GatewayApplication.RunAsync(args).ConfigureAwait(false);
}
