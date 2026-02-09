using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Tests.Helpers;
using Xunit;

namespace Operon.Sdk.Tests;

public sealed class SessionValidatorTests
{
    [Fact]
    public async Task ValidateSessionAsync_ReturnsNormalizedSessionInfo()
    {
        var exp = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
        var pat = BuildToken(new
        {
            participant_did = "did:test:source",
            participant_id = "part-1",
            workstream_id = "wstr-1",
            workspace_id = "wksp-1",
            session_id = "sess-1",
            client_id = "client-1",
            exp
        });

        var handler = new StubHttpMessageHandler();
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            user_id = "user-1",
            email = "user@example.com",
            name = "User",
            customer_id = "cust-1",
            roles = new[] { "sandbox" },
            feature_flags = new { demo = true }
        }));

        using var httpClient = new HttpClient(handler);
        var info = await SessionValidator.ValidateSessionAsync(
            new SessionValidationConfig
            {
                BaseUri = new Uri("https://example.com/client-api/"),
                HttpClient = httpClient
            },
            pat,
            CancellationToken.None);

        Assert.Equal("user-1", info.UserId);
        Assert.Equal("wstr-1", info.WorkstreamId);
        Assert.Equal("wstr-1", info.ChannelId);
        Assert.Equal("did:test:source", info.ParticipantDid);
        Assert.Equal("client-1", info.ClientId);
        Assert.True(info.ExpiresInSeconds > 0);
    }

    private static string BuildToken(object claims)
    {
        var header = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" })).Trim('=').Replace('+', '-').Replace('/', '_');
        var payload = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(claims)).Trim('=').Replace('+', '-').Replace('/', '_');
        return $"{header}.{payload}.signature";
    }
}
