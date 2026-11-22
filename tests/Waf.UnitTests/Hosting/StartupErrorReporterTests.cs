using System.Net.Sockets;
using Microsoft.AspNetCore.Connections;
using Waf.Host.Hosting;

namespace Waf.UnitTests.Hosting;

public class StartupErrorReporterTests
{
    private static IOException KestrelBindFailure(string address, Exception inner) =>
        new($"Failed to bind to address {address}: address already in use.", inner);

    [Fact]
    public void Port_in_use_on_windows_mentions_port_and_iis()
    {
        var ex = KestrelBindFailure("http://[::]:80", new AddressInUseException("in use"));

        Assert.True(StartupErrorReporter.TryDescribe(ex, isWindows: true, out var message));
        Assert.Contains("Port 80 is already in use", message, StringComparison.Ordinal);
        Assert.Contains("IIS", message, StringComparison.Ordinal);
        Assert.Contains("netsh http show servicestate", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Port_in_use_on_linux_suggests_ss()
    {
        var ex = KestrelBindFailure("https://0.0.0.0:443", new AddressInUseException("in use"));

        Assert.True(StartupErrorReporter.TryDescribe(ex, isWindows: false, out var message));
        Assert.Contains("Port 443 is already in use", message, StringComparison.Ordinal);
        Assert.Contains("ss -ltnp", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Socket_address_in_use_without_kestrel_wrapper_is_recognised()
    {
        var ex = new SocketException((int)SocketError.AddressAlreadyInUse);

        Assert.True(StartupErrorReporter.TryDescribe(ex, isWindows: false, out var message));
        Assert.Contains("(unknown)", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Permission_denied_on_linux_mentions_capability()
    {
        var ex = KestrelBindFailure("http://[::]:80", new SocketException((int)SocketError.AccessDenied));

        Assert.True(StartupErrorReporter.TryDescribe(ex, isWindows: false, out var message));
        Assert.Contains("Permission denied when binding port 80", message, StringComparison.Ordinal);
        Assert.Contains("CAP_NET_BIND_SERVICE", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Unrelated_exception_is_not_described()
    {
        Assert.False(StartupErrorReporter.TryDescribe(new InvalidOperationException("boom"), isWindows: true, out var message));
        Assert.Empty(message);
    }
}
