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
        Assert.Equal("EdDSA", config.SigningAlgorithm);
        Assert.Empty(config.Audience);
        Assert.Null(config.Scope);
        Assert.Equal(TimeSpan.Zero, config.SessionHeartbeatInterval);
        Assert.Equal(TimeSpan.Zero, config.SessionHeartbeatTimeout);
        Assert.Null(config.SessionHeartbeatUri);
    }

    [Fact]
    public void ThrowsWhenMissingCredentialsOrInvalidInputs()
    {
        Assert.Throws<ArgumentException>(() => new OperonConfig(string.Empty, "secret"));
        Assert.Throws<ArgumentException>(() => new OperonConfig("client", " "));
        Assert.Throws<ArgumentException>(() => new OperonConfig("client", "secret", signingAlgorithm: "RS256"));
        Assert.Throws<ArgumentException>(() =>
            new OperonConfig("client", "secret", sessionHeartbeatInterval: TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public void TrimsAudienceScopeAndHeartbeat()
    {
        var config = new OperonConfig(
            clientId: "client",
            clientSecret: "secret",
            scope: " transactions:write ",
            audience: new[] { " https://example.com " },
            httpTimeout: TimeSpan.FromSeconds(10),
            tokenLeeway: TimeSpan.FromSeconds(5),
            signingAlgorithm: "es256",
            sessionHeartbeatInterval: TimeSpan.FromSeconds(60),
            sessionHeartbeatTimeout: TimeSpan.FromSeconds(5),
            sessionHeartbeatUri: new Uri("https://internal.example.com/custom-heartbeat"));

        Assert.Equal("transactions:write", config.Scope);
        Assert.Single(config.Audience);
        Assert.Equal("https://example.com", config.Audience[0]);
        Assert.Equal(TimeSpan.FromSeconds(10), config.HttpTimeout);
        Assert.Equal(TimeSpan.FromSeconds(5), config.TokenLeeway);
        Assert.Equal("ES256", config.SigningAlgorithm);
        Assert.Equal(TimeSpan.FromSeconds(60), config.SessionHeartbeatInterval);
        Assert.Equal(TimeSpan.FromSeconds(5), config.SessionHeartbeatTimeout);
        Assert.Equal(new Uri("https://internal.example.com/custom-heartbeat"), config.SessionHeartbeatUri);
    }
}
