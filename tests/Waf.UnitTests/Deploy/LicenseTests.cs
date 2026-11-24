using System.Text.Json;

namespace FASoft.Waf.UnitTests.Deploy;

/// <summary>
/// The license files: LICENSE (proprietary) and THIRD-PARTY-NOTICES.md, which must name every package the shipped
/// programs include, since their licenses (MIT, Apache-2.0) require the notices to go with the release packages.
/// </summary>
public sealed class LicenseTests
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

    private static string Read(string relativePath) => File.ReadAllText(Path.Combine(RepositoryRoot(), relativePath));

    [Fact]
    public void The_license_is_proprietary_to_FA_Soft()
    {
        var license = Read("LICENSE");

        Assert.Contains("Copyright (c) 2026 FA-Soft. All rights reserved.", license, StringComparison.Ordinal);
        Assert.Contains("THIRD-PARTY-NOTICES.md", license, StringComparison.Ordinal);
    }

    /// <summary>The packages restored for the gateway and wafctl (and everything they reference).</summary>
    public static TheoryData<string> ShippedPackages()
    {
        var packages = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var project in new[] { "Waf.Host", "Waf.Cli" })
        {
            var assets = Path.Combine(RepositoryRoot(), "src", project, "obj", "project.assets.json");
            using var document = JsonDocument.Parse(File.ReadAllText(assets));
            foreach (var library in document.RootElement.GetProperty("libraries").EnumerateObject())
            {
                if (library.Value.GetProperty("type").GetString() == "package")
                {
                    packages.Add(library.Name[..library.Name.IndexOf('/', StringComparison.Ordinal)]);
                }
            }
        }

        return [.. packages];
    }

    [Theory]
    [MemberData(nameof(ShippedPackages))]
    public void Every_shipped_package_is_in_the_third_party_notices(string package)
    {
        var notices = Read("THIRD-PARTY-NOTICES.md");

        Assert.True(
            notices.Contains($" {package},", StringComparison.Ordinal) || notices.Contains($" {package} |", StringComparison.Ordinal),
            $"{package} is shipped but not named in THIRD-PARTY-NOTICES.md: add it with its license.");
    }

    [Fact]
    public void The_notices_contain_the_full_license_texts()
    {
        var notices = Read("THIRD-PARTY-NOTICES.md");

        Assert.Contains("Permission is hereby granted, free of charge", notices, StringComparison.Ordinal); // MIT
        Assert.Contains("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", notices, StringComparison.Ordinal); // Apache-2.0
        Assert.Contains("END OF TERMS AND CONDITIONS", notices, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("deploy/linux/build-package.sh")]
    [InlineData("deploy/windows/Build-Package.ps1")]
    public void Release_packages_include_the_license_and_the_notices(string script)
    {
        var text = Read(script);

        Assert.Contains("LICENSE", text, StringComparison.Ordinal);
        Assert.Contains("THIRD-PARTY-NOTICES.md", text, StringComparison.Ordinal);
    }
}
