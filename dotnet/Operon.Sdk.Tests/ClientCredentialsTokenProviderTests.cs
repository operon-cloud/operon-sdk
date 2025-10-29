using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Auth;
using Operon.Sdk.Models;
using Operon.Sdk.Tests.Helpers;
using Xunit;

namespace Operon.Sdk.Tests;

public sealed class ClientCredentialsTokenProviderTests
{
    [Fact]
    public async Task FetchesAndCachesToken()
    {
        var config = new OperonConfig("client", "secret");
        var handler = new StubHttpMessageHandler();
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            access_token = BuildToken(new
            {
                participant_did = "did:test:123",
                channel_id = "chnl-1"
            }),
            expires_in = 120,
            token_type = "Bearer"
        }));

        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = config.TokenUri
        };

        var provider = new ClientCredentialsTokenProvider(config, httpClient);
        var first = await provider.GetTokenAsync(CancellationToken.None);
        var second = await provider.GetTokenAsync(CancellationToken.None);

        Assert.Equal(first.Value, second.Value);
        Assert.Equal("did:test:123", first.ParticipantDid);
        Assert.Equal("chnl-1", first.ChannelId);
    }

    [Fact]
    public async Task RefreshesWhenExpired()
    {
        var config = new OperonConfig("client", "secret", tokenLeeway: TimeSpan.FromSeconds(5));
        var handler = new StubHttpMessageHandler();
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { access_token = BuildToken(new { nonce = "first" }), expires_in = 1 }));
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { access_token = BuildToken(new { nonce = "second" }), expires_in = 120 }));

        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = config.TokenUri
        };

        var provider = new ClientCredentialsTokenProvider(config, httpClient);
        var first = await provider.GetTokenAsync(CancellationToken.None);
        await Task.Delay(TimeSpan.FromSeconds(2));
        var second = await provider.GetTokenAsync(CancellationToken.None);

        Assert.NotEqual(first.Value, second.Value);
    }

    private static string BuildToken(object claims)
    {
        var header = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" })).Trim('=').Replace('+', '-').Replace('/', '_');
        var payload = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(claims)).Trim('=').Replace('+', '-').Replace('/', '_');
        return $"{header}.{payload}.signature";
    }
}
