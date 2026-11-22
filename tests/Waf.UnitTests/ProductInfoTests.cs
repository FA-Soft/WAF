using Waf.Core;

namespace Waf.UnitTests;

public class ProductInfoTests
{
    [Fact]
    public void Admin_port_defaults_to_8900()
    {
        Assert.Equal(8900, ProductInfo.DefaultAdminPort);
    }
}
