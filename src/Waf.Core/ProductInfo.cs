namespace Waf.Core;

/// <summary>
/// Product-wide constants shared by every WAF Gateway component.
/// </summary>
public static class ProductInfo
{
    /// <summary>The product's display name.</summary>
    public const string Name = "WAF Gateway";

    /// <summary>Default port of the localhost-only admin UI.</summary>
    public const int DefaultAdminPort = 8900;
}
