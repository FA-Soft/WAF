using System.Reflection;

namespace Waf.Core;

/// <summary>
/// Product-wide constants shared by every WAF Gateway component.
/// </summary>
public static class ProductInfo
{
    /// <summary>The product's display name.</summary>
    public const string Name = "WAF Gateway";

    /// <summary>The product version (informational version of the build, without source revision).</summary>
    public static string Version { get; } =
        (typeof(ProductInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0").Split('+')[0];

    /// <summary>Default port of the localhost-only admin UI.</summary>
    public const int DefaultAdminPort = 8900;
}
