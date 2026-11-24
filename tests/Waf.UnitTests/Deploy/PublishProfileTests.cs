using System.Xml.Linq;

namespace FASoft.Waf.UnitTests.Deploy;

/// <summary>
/// The release publish profiles: one per runtime for the gateway and wafctl, all with the shared settings of
/// Publish.props (self-contained single file; the low-memory garbage collector on linux-arm64). CI publishes with them.
/// </summary>
public sealed class PublishProfileTests
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

    private static XElement Property(XDocument document, string name, string? condition = null) =>
        Assert.Single(document.Root!.Elements("PropertyGroup")
            .Where(g => (string?)g.Attribute("Condition") == condition)
            .Elements(name));

    [Theory]
    [InlineData("Waf.Host", "win-x64")]
    [InlineData("Waf.Host", "linux-arm64")]
    [InlineData("Waf.Host", "linux-x64")]
    [InlineData("Waf.Cli", "win-x64")]
    [InlineData("Waf.Cli", "linux-arm64")]
    [InlineData("Waf.Cli", "linux-x64")]
    public void Every_runtime_has_a_profile_with_the_shared_release_settings(string project, string runtime)
    {
        var directory = Path.Combine(RepositoryRoot(), "src", project, "Properties", "PublishProfiles");
        var profile = XDocument.Load(Path.Combine(directory, runtime + ".pubxml"));

        Assert.Equal(runtime, Property(profile, "RuntimeIdentifier").Value);
        var import = Assert.Single(profile.Root!.Elements("Import")).Attribute("Project")!.Value
            .Replace("$(MSBuildThisFileDirectory)", directory + Path.DirectorySeparatorChar, StringComparison.Ordinal);
        Assert.Equal(Path.Combine(RepositoryRoot(), "Publish.props"), Path.GetFullPath(import));
    }

    [Fact]
    public void Releases_are_self_contained_single_files_and_the_pi_build_saves_memory()
    {
        var settings = XDocument.Load(Path.Combine(RepositoryRoot(), "Publish.props"));

        Assert.Equal("true", Property(settings, "SelfContained").Value);
        Assert.Equal("true", Property(settings, "PublishSingleFile").Value);
        Assert.Equal("false", Property(settings, "PublishReadyToRun").Value);

        const string Pi = "'$(RuntimeIdentifier)' == 'linux-arm64'";
        Assert.Equal("false", Property(settings, "ServerGarbageCollection", Pi).Value);
        Assert.Equal("false", Property(settings, "ConcurrentGarbageCollection", Pi).Value);
    }
}
