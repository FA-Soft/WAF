using System.Diagnostics;

namespace FASoft.Waf.UnitTests.Deploy;

/// <summary>
/// Static checks of the Linux installer: the scripts parse in bash and keep LF line endings, and the systemd unit
/// runs the gateway as its own user with only the port capability and the hardening options. The full install,
/// upgrade and uninstall run is deploy/linux/test-install.sh (CI, real systemd).
/// </summary>
public sealed class LinuxInstallerScriptTests
{
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !System.IO.File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static string DeployFile(string name) => Path.Combine(RepositoryRoot(), "deploy", "linux", name);

    /// <summary>bash: /bin/bash on Linux, Git Bash on Windows (never the WSL launcher, which may have no Linux).</summary>
    private static string? Bash()
    {
        var candidates = OperatingSystem.IsWindows()
            ? new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "bin", "bash.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Git", "bin", "bash.exe"),
            }
            : ["/bin/bash", "/usr/bin/bash"];
        return candidates.FirstOrDefault(System.IO.File.Exists);
    }

    [Theory]
    [InlineData("install.sh")]
    [InlineData("build-package.sh")]
    [InlineData("test-install.sh")]
    [InlineData("smoke-test.sh")]
    public async Task The_scripts_parse_in_bash(string name)
    {
        var bash = Bash();
        Assert.SkipWhen(bash is null, "bash is not installed.");
        var start = new ProcessStartInfo(bash!) { RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("-n");
        start.ArgumentList.Add(DeployFile(name));

        using var process = Process.Start(start)!;
        var error = await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await process.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.True(process.ExitCode == 0, error);
    }

    [Theory]
    [InlineData("install.sh")]
    [InlineData("build-package.sh")]
    [InlineData("test-install.sh")]
    [InlineData("smoke-test.sh")]
    [InlineData("wafgateway.service")]
    public void Linux_files_have_LF_line_endings(string name) =>
        Assert.DoesNotContain('\r', System.IO.File.ReadAllText(DeployFile(name)));

    [Fact]
    public void The_unit_runs_the_gateway_unprivileged_and_hardened()
    {
        var settings = System.IO.File.ReadAllLines(DeployFile("wafgateway.service"))
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#') && l.Contains('=', StringComparison.Ordinal))
            .Select(l => l.Split('=', 2))
            .ToLookup(p => p[0], p => p[1]);

        Assert.Equal("wafgateway", Assert.Single(settings["User"]));
        Assert.Equal("CAP_NET_BIND_SERVICE", Assert.Single(settings["AmbientCapabilities"]));
        Assert.Equal("CAP_NET_BIND_SERVICE", Assert.Single(settings["CapabilityBoundingSet"]));
        Assert.Equal("notify", Assert.Single(settings["Type"]));
        foreach (var (key, value) in new[]
        {
            ("NoNewPrivileges", "true"), ("ProtectSystem", "strict"), ("ProtectHome", "true"), ("PrivateTmp", "true"),
            ("PrivateDevices", "true"), ("ProtectKernelTunables", "true"), ("ProtectKernelModules", "true"),
            ("ProtectControlGroups", "true"), ("RestrictSUIDSGID", "true"), ("RestrictNamespaces", "true"),
            ("StateDirectory", "wafgateway"), ("ConfigurationDirectory", "wafgateway"),
        })
        {
            Assert.Equal(value, Assert.Single(settings[key]));
        }
    }

    [Fact]
    public void The_installer_uses_the_folders_the_gateway_expects()
    {
        var script = System.IO.File.ReadAllText(DeployFile("install.sh"));

        // The gateway's defaults on Linux (StoragePaths): data in /var/lib/wafgateway, settings in /etc/wafgateway.
        var paths = FASoft.Waf.Data.StoragePaths.Resolve(null, "/opt/wafgateway", isWindows: false);
        Assert.Contains($"DATA_DIR={paths.DataDirectory}", script, StringComparison.Ordinal);
        Assert.Contains($"CONFIG_DIR={paths.ConfigDirectory}", script, StringComparison.Ordinal);
        Assert.Contains("--shell /usr/sbin/nologin", script, StringComparison.Ordinal);
        Assert.DoesNotContain("User=root", System.IO.File.ReadAllText(DeployFile("wafgateway.service")), StringComparison.Ordinal);
    }
}
