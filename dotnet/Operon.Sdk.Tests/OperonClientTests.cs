using System;
using System.Linq;
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

public sealed class OperonClientTests
{
    [Fact]
    public async Task SubmitTransactionAsync_SelfSignsWhenEnabled()
    {
        var config = new OperonConfig("client", "secret");
        var handler = new StubHttpMessageHandler();

        handler.Enqueue(request =>
        {
            Assert.Equal(config.TokenUri, request.RequestUri);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new { access_token = BuildToken(new { participant_did = "did:test:123", channel_id = "chnl-1" }), expires_in = 300 });
        });

        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/interactions", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                data = new[]
                {
                    new
                    {
                        id = "int-123",
                        channelId = "chnl-1",
                        sourceParticipantId = "part-1",
                        targetParticipantId = "part-2"
                    }
                }
            });
        });

        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/participants", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                data = new[]
                {
                    new { id = "part-1", did = "did:test:123" },
                    new { id = "part-2", did = "did:test:456" }
                }
            });
        });

        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/dids/self/sign", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                signature = new
                {
                    algorithm = "EdDSA",
                    value = "signed-value",
                    keyId = "did:test:123#keys-1"
                }
            });
        });

        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/transactions", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            var body = JsonSerializer.Deserialize<JsonElement>(request.Content!.ReadAsStringAsync().Result);
            Assert.Equal("signed-value", body.GetProperty("signature").GetProperty("value").GetString());
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                id = "txn-1",
                correlationId = "corr-1",
                channelId = "chnl-1",
                interactionId = "int-123",
                timestamp = DateTime.UtcNow,
                sourceDid = "did:test:123",
                targetDid = "did:test:456",
                signature = new { algorithm = "EdDSA", value = "signed-value", keyId = "did:test:123#keys-1" },
                payloadHash = "hash",
                status = "PENDING",
                createdAt = DateTime.UtcNow,
                updatedAt = DateTime.UtcNow
            });
        });

        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = config.BaseUri,
            Timeout = config.HttpTimeout
        };

        var client = new OperonClient(config, httpClient, new ClientCredentialsTokenProvider(config, httpClient));
        var result = await client.SubmitTransactionAsync(new TransactionRequest
        {
            CorrelationId = "corr-1",
            InteractionId = "int-123",
            PayloadBytes = new byte[] { 1, 2, 3 }
        }, CancellationToken.None);

        Assert.Equal("txn-1", result.Id);
        Assert.Equal("signed-value", result.Signature.Value);
    }

    [Fact]
    public async Task SubmitTransactionAsync_UsesProvidedSignatureWhenSelfSignDisabled()
    {
        var config = new OperonConfig("client", "secret", disableSelfSign: true);
        var handler = new StubHttpMessageHandler();

        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { access_token = BuildToken(new { participant_did = "did:test:999", channel_id = "chnl-9" }), expires_in = 300 }));
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { data = Array.Empty<object>() }));
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { data = Array.Empty<object>() }));
        handler.Enqueue(request =>
        {
            var body = JsonSerializer.Deserialize<JsonElement>(request.Content!.ReadAsStringAsync().Result);
            Assert.Equal("manual", body.GetProperty("signature").GetProperty("value").GetString());
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                id = "txn-2",
                correlationId = "corr-2",
                channelId = "chnl-9",
                interactionId = "int-999",
                timestamp = DateTime.UtcNow,
                sourceDid = "did:test:999",
                targetDid = "did:test:888",
                signature = new { algorithm = "EdDSA", value = "manual", keyId = "did:test:999#keys-1" },
                payloadHash = "hash",
                status = "PENDING",
                createdAt = DateTime.UtcNow,
                updatedAt = DateTime.UtcNow
            });
        });

        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = config.BaseUri,
            Timeout = config.HttpTimeout
        };

        var client = new OperonClient(config, httpClient, new ClientCredentialsTokenProvider(config, httpClient));
        var result = await client.SubmitTransactionAsync(new TransactionRequest
        {
            CorrelationId = "corr-2",
            InteractionId = "int-999",
            ChannelId = "chnl-9",
            SourceDid = "did:test:999",
            TargetDid = "did:test:888",
            PayloadHash = "hash",
            Signature = new Signature { Algorithm = "EdDSA", Value = "manual" }
        }, CancellationToken.None);

        Assert.Equal("manual", result.Signature.Value);
    }

    private static string BuildToken(object claims)
    {
        var header = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" })).Trim('=').Replace('+', '-').Replace('/', '_');
        var payload = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(claims)).Trim('=').Replace('+', '-').Replace('/', '_');
        return $"{header}.{payload}.signature";
    }
}
