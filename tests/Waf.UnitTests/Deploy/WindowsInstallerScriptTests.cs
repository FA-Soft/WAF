using System.Diagnostics;

namespace FASoft.Waf.UnitTests.Deploy;

/// <summary>
/// Static checks of the Windows installer scripts with the Windows PowerShell 5.1 parser (the PowerShell every
/// supported Windows version has). The full install/upgrade/uninstall run is deploy/windows/Test-Install.ps1 (CI).
/// </summary>
public sealed class WindowsInstallerScriptTests
{
    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static string Script(string name) => Path.Combine(RepositoryRoot(), "deploy", "windows", name);

    /// <summary>Runs <paramref name="script"/> in Windows PowerShell 5.1 with the path of <paramref name="target"/>; returns its output.</summary>
    private static async Task<string> PowerShellAsync(string script, string target)
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows PowerShell 5.1 is only on Windows.");
        var file = Path.Combine(Path.GetTempPath(), $"waf-ps-{Guid.NewGuid():N}.ps1");
        await File.WriteAllTextAsync(file, script, TestContext.Current.CancellationToken);
        try
        {
            var start = new ProcessStartInfo("powershell.exe")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file, "-Path", target })
            {
                start.ArgumentList.Add(argument);
            }

            using var process = Process.Start(start)!;
            var output = await process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
            var error = await process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
            await process.WaitForExitAsync(TestContext.Current.CancellationToken);
            Assert.True(process.ExitCode == 0, $"PowerShell failed ({process.ExitCode}): {error}");
            return output.Trim();
        }
        finally
        {
            File.Delete(file);
        }
    }

    private const string ParseErrors = """
        param([string] $Path)
        $errors = $null
        [void] [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $null, [ref] $errors)
        $errors | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" }
        "errors: $($errors.Count)"
        """;

    [Theory]
    [InlineData("Install.ps1")]
    [InlineData("Build-Package.ps1")]
    [InlineData("Test-Install.ps1")]
    [InlineData("Smoke-Test.ps1")]
    public async Task The_scripts_parse_in_Windows_PowerShell_5_1(string name)
    {
        var output = await PowerShellAsync(ParseErrors, Script(name));

        Assert.Equal("errors: 0", output);
    }

    [Fact]
    public async Task IIS_is_only_changed_behind_MoveIisBindings()
    {
        // Every call that backs up or changes IIS must sit inside "if ($MoveIisBindings)"; ServerManager.CommitChanges
        // (the only write to applicationHost.config) only in Move-IisBinding.
        const string Check = """
            param([string] $Path)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $null, [ref] $null)
            $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                $n.GetCommandName() -in @('Move-IisBinding', 'Backup-IisConfiguration') }, $true)
            foreach ($call in $calls) {
                $guarded = $false
                for ($parent = $call.Parent; $null -ne $parent; $parent = $parent.Parent) {
                    if ($parent -is [System.Management.Automation.Language.IfStatementAst] -and
                        @($parent.Clauses | Where-Object { $_.Item1.Extent.Text -eq '$MoveIisBindings' }).Count -gt 0) { $guarded = $true }
                }
                "$($call.GetCommandName()) line $($call.Extent.StartLineNumber): guarded=$guarded"
            }
            $commits = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                $n.Member.Extent.Text -eq 'CommitChanges' }, $true)
            foreach ($commit in $commits) {
                $function = $commit.Parent
                while ($null -ne $function -and $function -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $function = $function.Parent }
                "CommitChanges in $(if ($function) { $function.Name } else { 'script' })"
            }
            """;

        var lines = (await PowerShellAsync(Check, Script("Install.ps1"))).Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        Assert.Contains(lines, l => l.StartsWith("Move-IisBinding", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.StartsWith("Backup-IisConfiguration", StringComparison.Ordinal));
        Assert.All(lines.Where(l => !l.StartsWith("CommitChanges", StringComparison.Ordinal)), l => Assert.EndsWith("guarded=True", l, StringComparison.Ordinal));
        Assert.Equal(["CommitChanges in Move-IisBinding"], lines.Where(l => l.StartsWith("CommitChanges", StringComparison.Ordinal)));
    }

    [Fact]
    public void The_installer_needs_an_administrator_and_supports_WhatIf()
    {
        var text = File.ReadAllText(Script("Install.ps1"));

        Assert.Contains("#Requires -RunAsAdministrator", text, StringComparison.Ordinal);
        Assert.Contains("#Requires -Version 5.1", text, StringComparison.Ordinal);
        Assert.Contains("SupportsShouldProcess = $true", text, StringComparison.Ordinal);
        Assert.Contains(@"""NT SERVICE\$ServiceName""", text, StringComparison.Ordinal); // never LocalSystem
    }
}
