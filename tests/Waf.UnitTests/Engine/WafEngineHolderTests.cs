using Waf.Engine;
using static Waf.UnitTests.Engine.RuleBuilder;

namespace Waf.UnitTests.Engine;

public class WafEngineHolderTests
{
    private static WafEngine Engine(string tag) => WafEngine.Build(Config(), configTag: tag);

    [Fact]
    public void Requests_get_the_engine_of_the_configuration_that_routed_them()
    {
        var holder = new WafEngineHolder();
        var first = Engine("v1");
        var second = Engine("v2");
        holder.Activate(first);
        holder.Activate(second);

        Assert.Same(second, holder.Resolve("v2"));
        Assert.Same(first, holder.Resolve("v1"));   // routed just before the swap: judged by the old engine
        Assert.Same(second, holder.Resolve(null));  // no route matched: the active engine
        Assert.Same(second, holder.Resolve("v0"));  // unknown (older) tag: the active engine
        Assert.Same(second, holder.Current);
    }

    [Fact]
    public void Only_one_previous_engine_is_kept()
    {
        var holder = new WafEngineHolder();
        holder.Activate(Engine("v1"));
        holder.Activate(Engine("v2"));
        holder.Activate(Engine("v3"));

        Assert.Equal("v3", holder.Resolve("v1")!.ConfigTag);
        Assert.Equal("v2", holder.Resolve("v2")!.ConfigTag);
    }

    [Fact]
    public void Unavailable_holder_resolves_nothing()
    {
        var holder = new WafEngineHolder();
        holder.Activate(Engine("v1"));
        holder.MarkUnavailable("maintenance");

        Assert.Null(holder.Resolve("v1"));
        Assert.Null(holder.Resolve(null));
    }
}
