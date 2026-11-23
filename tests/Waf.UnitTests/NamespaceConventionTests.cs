using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace FASoft.Waf.UnitTests;

/// <summary>
/// Repository rule: every namespace starts with <see cref="Prefix"/>, so every class, record, struct, interface, enum
/// and Razor component lives under it. New files get it by default (RootNamespace in Directory.Build.props); these
/// tests fail the build for anything that does not.
/// </summary>
public sealed partial class NamespaceConventionTests
{
    private const string Prefix = "FASoft.";

    private static readonly string[] SourceFolders = ["src", "tests"];

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WafGateway.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("Repository root (WafGateway.sln) not found.");
    }

    /// <summary>Hand-written C# and Razor files (generated code in obj and bin is left out).</summary>
    private static IEnumerable<string> SourceFiles(string pattern)
    {
        var root = RepositoryRoot();
        return SourceFolders
            .Select(folder => Path.Combine(root, folder))
            .Where(Directory.Exists)
            .SelectMany(folder => Directory.EnumerateFiles(folder, pattern, SearchOption.AllDirectories))
            .Where(path => !path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(part => part is "obj" or "bin"));
    }

    private static string Relative(string path) => Path.GetRelativePath(RepositoryRoot(), path);

    [Fact]
    public void Every_namespace_in_the_source_starts_with_FASoft()
    {
        var wrong = new List<string>();
        foreach (var file in SourceFiles("*.cs"))
        {
            var text = File.ReadAllText(file);
            var namespaces = NamespacePattern().Matches(text).Select(m => m.Groups["name"].Value).ToList();
            if (namespaces.Count == 0)
            {
                wrong.Add($"{Relative(file)}: no namespace (its types would be in the global namespace)");
            }

            wrong.AddRange(namespaces.Where(n => !n.StartsWith(Prefix, StringComparison.Ordinal)).Select(n => $"{Relative(file)}: namespace {n}"));
        }

        foreach (var file in SourceFiles("*.razor"))
        {
            var match = RazorNamespacePattern().Match(File.ReadAllText(file));
            if (match.Success && !match.Groups["name"].Value.StartsWith(Prefix, StringComparison.Ordinal))
            {
                wrong.Add($"{Relative(file)}: @namespace {match.Groups["name"].Value}");
            }
        }

        Assert.True(wrong.Count == 0, $"Every namespace must start with \"{Prefix}\":{Environment.NewLine}{string.Join(Environment.NewLine, wrong)}");
    }

    [Fact]
    public void Every_compiled_type_is_in_a_FASoft_namespace()
    {
        // The product assemblies this project references, and this one; Razor components get their namespace from
        // RootNamespace and the folder, so this also covers them.
        var assemblies = new[]
        {
            typeof(global::FASoft.Waf.Core.ProductInfo).Assembly,
            typeof(global::FASoft.Waf.Engine.WafEngine).Assembly,
            typeof(global::FASoft.Waf.Data.ConfigurationStore).Assembly,
            typeof(global::FASoft.Waf.Web.AdminActor).Assembly,
            typeof(global::FASoft.Waf.Host.Hosting.GatewayApplication).Assembly,
            typeof(global::FASoft.Waf.Proxy.ProxyRouteUpdater).Assembly,
            typeof(NamespaceConventionTests).Assembly,
        }.Distinct();

        var wrong = assemblies
            .SelectMany(a => a.GetTypes())
            .Where(t => !t.IsNested && t.Name != "<Module>" && !IsGenerated(t))
            .Where(t => t.Namespace is null || !t.Namespace.StartsWith(Prefix, StringComparison.Ordinal))
            .Select(t => $"{t.Assembly.GetName().Name}: {t.FullName}")
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.True(wrong.Count == 0, $"Every type must be in a namespace starting with \"{Prefix}\":{Environment.NewLine}{string.Join(Environment.NewLine, wrong)}");
    }

    /// <summary>Types the compiler or a source generator adds (not written in this repository).</summary>
    private static bool IsGenerated(Type type) =>
        type.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)
        || type.Namespace is { } ns && (ns.StartsWith("Microsoft.", StringComparison.Ordinal) || ns.StartsWith("System.", StringComparison.Ordinal) || ns.StartsWith("Xunit.", StringComparison.Ordinal) || ns.StartsWith("__Blazor.", StringComparison.Ordinal))
        || type.Name.StartsWith('<')
        || type.GetCustomAttribute<System.CodeDom.Compiler.GeneratedCodeAttribute>() is not null && type.Namespace is null;

    [GeneratedRegex(@"^\s*namespace\s+(?<name>[A-Za-z_][\w.]*)", RegexOptions.Multiline)]
    private static partial Regex NamespacePattern();

    [GeneratedRegex(@"^@namespace\s+(?<name>[A-Za-z_][\w.]*)", RegexOptions.Multiline)]
    private static partial Regex RazorNamespacePattern();
}
