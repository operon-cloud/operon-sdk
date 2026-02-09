#pragma warning disable xUnit1031
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
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
    public async Task SubmitTransactionAsync_SelfSignsAndSendsActorAssigneeFields()
    {
        var config = new OperonConfig("client", "secret");
        var handler = new StubHttpMessageHandler();

        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            access_token = BuildToken(new { participant_did = "did:test:source", workstream_id = "wstr-1" }),
            expires_in = 300
        }));

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
                        workstreamId = "wstr-1",
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
                    new { id = "part-1", did = "did:test:source" },
                    new { id = "part-2", did = "did:test:target" }
                }
            });
        });

        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            signature = new
            {
                algorithm = "EdDSA",
                value = "signed-value",
                keyId = string.Empty
            }
        }));

        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/transactions", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            var body = ReadJsonBody(request);
            Assert.Equal("wstr-1", body.GetProperty("workstreamId").GetString());
            Assert.Equal("did:test:source", body.GetProperty("sourceDid").GetString());
            Assert.Equal("did:test:target", body.GetProperty("targetDid").GetString());
            Assert.Equal("agent-1", body.GetProperty("actorExternalId").GetString());
            Assert.Equal("crm", body.GetProperty("actorExternalSource").GetString());
            Assert.Equal("owner-2", body.GetProperty("assigneeExternalId").GetString());
            Assert.Equal("crm", body.GetProperty("assigneeExternalSource").GetString());
            Assert.Equal("did:test:source#keys-1", body.GetProperty("signature").GetProperty("keyId").GetString());

            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                id = "txn-1",
                correlationId = "corr-1",
                workstreamId = "wstr-1",
                interactionId = "int-123",
                timestamp = DateTimeOffset.UtcNow,
                sourceDid = "did:test:source",
                targetDid = "did:test:target",
                signature = new { algorithm = "EdDSA", value = "signed-value", keyId = "did:test:source#keys-1" },
                payloadHash = body.GetProperty("payloadHash").GetString(),
                status = "PENDING",
                createdAt = DateTimeOffset.UtcNow,
                updatedAt = DateTimeOffset.UtcNow
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
            PayloadBytes = Encoding.UTF8.GetBytes("{\"lead\":1}"),
            ActorExternalId = "agent-1",
            ActorExternalDisplayName = "Agent One",
            ActorExternalSource = "crm",
            AssigneeExternalId = "owner-2",
            AssigneeExternalDisplayName = "Owner Two",
            AssigneeExternalSource = "crm"
        }, CancellationToken.None);

        Assert.Equal("txn-1", result.Id);
        Assert.Equal("wstr-1", result.WorkstreamId);
        Assert.Equal("wstr-1", result.ChannelId);
        Assert.Equal("signed-value", result.Signature.Value);
    }

    [Fact]
    public async Task SubmitTransactionAsync_UsesManualSignatureWhenSelfSignDisabled()
    {
        var config = new OperonConfig("client", "secret", disableSelfSign: true);
        var handler = new StubHttpMessageHandler();

        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            access_token = BuildToken(new { participant_did = "did:test:src", workstream_id = "wstr-9" }),
            expires_in = 300
        }));
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            data = new[]
            {
                new
                {
                    id = "int-999",
                    workstreamId = "wstr-9",
                    sourceParticipantId = "part-1",
                    targetParticipantId = "part-2"
                }
            }
        }));
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            data = new[]
            {
                new { id = "part-1", did = "did:test:src" },
                new { id = "part-2", did = "did:test:dst" }
            }
        }));

        handler.Enqueue(request =>
        {
            var body = ReadJsonBody(request);
            Assert.Equal("manual", body.GetProperty("signature").GetProperty("value").GetString());
            Assert.Equal("wstr-9", body.GetProperty("workstreamId").GetString());

            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                id = "txn-2",
                correlationId = "corr-2",
                workstreamId = "wstr-9",
                interactionId = "int-999",
                timestamp = DateTimeOffset.UtcNow,
                sourceDid = "did:test:src",
                targetDid = "did:test:dst",
                signature = new { algorithm = "EdDSA", value = "manual", keyId = "did:test:src#keys-1" },
                payloadHash = body.GetProperty("payloadHash").GetString(),
                status = "PENDING",
                createdAt = DateTimeOffset.UtcNow,
                updatedAt = DateTimeOffset.UtcNow
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
            ChannelId = "wstr-9",
            InteractionId = "int-999",
            SourceDid = "did:test:src",
            TargetDid = "did:test:dst",
            PayloadHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Signature = new Signature { Algorithm = "EdDSA", Value = "manual" }
        }, CancellationToken.None);

        Assert.Equal("manual", result.Signature.Value);
        Assert.Equal("wstr-9", result.WorkstreamId);
    }

    [Fact]
    public async Task GeneratesAndValidatesSignatureHeaders()
    {
        var config = new OperonConfig("client", "secret", signingAlgorithm: "ES256");
        var handler = new StubHttpMessageHandler();

        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            access_token = BuildToken(new { participant_did = "did:test:source", workstream_id = "wstr-1" }),
            expires_in = 300
        }));

        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            signature = new { algorithm = "ES256", value = "sig-value", keyId = "did:test:source#keys-1" }
        }));

        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/dids/did%3Atest%3Asource/signature/verify", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                status = "VALID",
                message = "ok",
                did = "did:test:source",
                payloadHash = "x",
                algorithm = "ES256",
                keyId = "did:test:source#keys-1"
            });
        });

        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = config.BaseUri,
            Timeout = config.HttpTimeout
        };

        var client = new OperonClient(config, httpClient, new ClientCredentialsTokenProvider(config, httpClient));
        var payload = Encoding.UTF8.GetBytes("{\"demo\":true}");

        var headers = await client.GenerateSignatureHeadersAsync(payload);
        Assert.Equal("did:test:source", headers["X-Operon-DID"]);

        var result = await client.ValidateSignatureHeadersAsync(payload, headers);
        Assert.Equal("VALID", result.Status);
    }

    [Fact]
    public async Task GetWorkstreamInteractions_UsesTokenScopedWorkstream()
    {
        var config = new OperonConfig("client", "secret");
        var handler = new StubHttpMessageHandler();

        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            access_token = BuildToken(new { participant_did = "did:test:123", workstream_id = "wstr-abc" }),
            expires_in = 300
        }));

        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/workstreams/wstr-abc/interactions", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                interactions = new[]
                {
                    new { id = "int-1", workstreamId = "wstr-abc" }
                },
                totalCount = 1,
                page = 1,
                pageSize = 1000,
                hasMore = false
            });
        });

        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = config.BaseUri,
            Timeout = config.HttpTimeout
        };

        var client = new OperonClient(config, httpClient, new ClientCredentialsTokenProvider(config, httpClient));
        var response = await client.GetWorkstreamInteractionsAsync();

        Assert.Single(response.Interactions);
        Assert.Equal("int-1", response.Interactions[0].Id);
    }

    [Fact]
    public async Task HeartbeatForcesTokenRefreshOnUnauthorized()
    {
        var config = new OperonConfig(
            "client",
            "secret",
            sessionHeartbeatInterval: TimeSpan.FromMilliseconds(50),
            sessionHeartbeatTimeout: TimeSpan.FromMilliseconds(100));

        var handler = new StubHttpMessageHandler();
        handler.Enqueue(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        for (var i = 0; i < 5; i++)
        {
            handler.Enqueue(_ => new HttpResponseMessage(HttpStatusCode.OK));
        }

        using var httpClient = new HttpClient(handler)
        {
            BaseAddress = config.BaseUri,
            Timeout = config.HttpTimeout
        };

        var tokenProvider = new StubTokenProvider();
        await using var client = new OperonClient(config, httpClient, tokenProvider);
        await client.InitAsync();
        await Task.Delay(200);

        Assert.True(tokenProvider.ForceRefreshCount >= 1);
    }

    private sealed class StubTokenProvider : ITokenProvider
    {
        private AccessToken _token = new()
        {
            Value = "stub-token",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        public int ForceRefreshCount { get; private set; }

        public Task<AccessToken> GetTokenAsync(CancellationToken cancellationToken)
            => Task.FromResult(_token);

        public void Clear()
        {
        }

        public Task<AccessToken> ForceRefreshAsync(CancellationToken cancellationToken)
        {
            ForceRefreshCount++;
            _token = new AccessToken
            {
                Value = $"refreshed-{ForceRefreshCount}",
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
            };
            return Task.FromResult(_token);
        }
    }

    private static JsonElement ReadJsonBody(HttpRequestMessage request)
    {
        var raw = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
        return JsonSerializer.Deserialize<JsonElement>(raw);
    }

    private static string BuildToken(object claims)
    {
        var header = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" })).Trim('=').Replace('+', '-').Replace('/', '_');
        var payload = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(claims)).Trim('=').Replace('+', '-').Replace('/', '_');
        return $"{header}.{payload}.signature";
    }
}
#pragma warning restore xUnit1031
