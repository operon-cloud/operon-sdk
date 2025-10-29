using System;
using Operon.Sdk;
using Xunit;

namespace Operon.Sdk.Tests;

public sealed class ConfigTests
{
    [Fact]
    public void DefaultsAreApplied()
    {
        var config = new OperonConfig("client", "secret");

        Assert.Equal(new Uri("https://api.operon.cloud/client-api/"), config.BaseUri);
        Assert.Equal(new Uri("https://auth.operon.cloud/oauth2/token"), config.TokenUri);
        Assert.Equal(TimeSpan.FromSeconds(30), config.HttpTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), config.TokenLeeway);
        Assert.False(config.DisableSelfSign);
        Assert.Empty(config.Audience);
        Assert.Null(config.Scope);
    }

    [Fact]
    public void ThrowsWhenMissingCredentials()
    {
        Assert.Throws<ArgumentException>(() => new OperonConfig(string.Empty, "secret"));
        Assert.Throws<ArgumentException>(() => new OperonConfig("client", " "));
    }

    [Fact]
    public void TrimsAudienceAndScope()
    {
        var config = new OperonConfig(
            clientId: "client",
            clientSecret: "secret",
            scope: " transactions:write ",
            audience: new[] { " https://example.com " },
            httpTimeout: TimeSpan.FromSeconds(10),
            tokenLeeway: TimeSpan.FromSeconds(5)
        );

        Assert.Equal("transactions:write", config.Scope);
        Assert.Single(config.Audience);
        Assert.Equal("https://example.com", config.Audience[0]);
        Assert.Equal(TimeSpan.FromSeconds(10), config.HttpTimeout);
        Assert.Equal(TimeSpan.FromSeconds(5), config.TokenLeeway);
    }
}
