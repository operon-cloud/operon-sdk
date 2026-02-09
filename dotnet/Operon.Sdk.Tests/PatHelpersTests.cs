#pragma warning disable xUnit1031
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Models;
using Operon.Sdk.Tests.Helpers;
using Xunit;

namespace Operon.Sdk.Tests;

public sealed class PatHelpersTests
{
    [Fact]
    public async Task SignHashWithPatAsync_FillsMissingKeyIdFromClaims()
    {
        var pat = BuildToken(new { participant_did = "did:test:source" });
        var handler = new StubHttpMessageHandler();
        handler.Enqueue(_ => StubHttpMessageHandler.Json(HttpStatusCode.OK, new
        {
            signature = new { algorithm = "EdDSA", value = "signed", keyId = string.Empty }
        }));

        using var httpClient = new HttpClient(handler);
        var signature = await PatHelpers.SignHashWithPatAsync(
            new ClientApiConfig { BaseUri = new Uri("https://example.com/client-api/"), HttpClient = httpClient },
            pat,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "EdDSA",
            CancellationToken.None);

        Assert.Equal("did:test:source#keys-1", signature.KeyId);
    }

    [Fact]
    public async Task SubmitTransactionWithPatAsync_UsesClaimDefaults()
    {
        var pat = BuildToken(new { participant_did = "did:test:source", workstream_id = "wstr-123" });
        var handler = new StubHttpMessageHandler();
        handler.Enqueue(request =>
        {
            var body = ReadJsonBody(request);
            Assert.Equal("wstr-123", body.GetProperty("workstreamId").GetString());
            Assert.Equal("did:test:source", body.GetProperty("sourceDid").GetString());

            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                id = "txn-1",
                correlationId = body.GetProperty("correlationId").GetString(),
                workstreamId = body.GetProperty("workstreamId").GetString(),
                interactionId = body.GetProperty("interactionId").GetString(),
                sourceDid = body.GetProperty("sourceDid").GetString(),
                targetDid = body.GetProperty("targetDid").GetString(),
                signature = body.GetProperty("signature"),
                payloadHash = body.GetProperty("payloadHash").GetString(),
                status = "received",
                timestamp = DateTimeOffset.UtcNow,
                createdAt = DateTimeOffset.UtcNow,
                updatedAt = DateTimeOffset.UtcNow
            });
        });

        using var httpClient = new HttpClient(handler);
        var txn = await PatHelpers.SubmitTransactionWithPatAsync(
            new ClientApiConfig { BaseUri = new Uri("https://example.com/client-api/"), HttpClient = httpClient },
            pat,
            new TransactionRequest
            {
                CorrelationId = "corr-1",
                InteractionId = "int-1",
                PayloadBytes = Encoding.UTF8.GetBytes("hello"),
                TargetDid = "did:test:target",
                Signature = new Signature { Algorithm = "EdDSA", Value = "manual", KeyId = "did:test:source#keys-1" }
            },
            CancellationToken.None);

        Assert.Equal("txn-1", txn.Id);
    }

    [Fact]
    public async Task FetchWorkstreamInteractionsAsync_UsesOverride()
    {
        var pat = BuildToken(new { participant_did = "did:test:source" });
        var handler = new StubHttpMessageHandler();
        handler.Enqueue(request =>
        {
            Assert.EndsWith("/v1/workstreams/wstr-override/interactions", request.RequestUri!.AbsolutePath, StringComparison.Ordinal);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, new
            {
                interactions = new[] { new { id = "int-1", workstreamId = "wstr-override" } },
                totalCount = 1,
                page = 1,
                pageSize = 1000,
                hasMore = false
            });
        });

        using var httpClient = new HttpClient(handler);
        var response = await PatHelpers.FetchWorkstreamInteractionsAsync(
            new WorkstreamDataConfig { BaseUri = new Uri("https://example.com/client-api/"), HttpClient = httpClient },
            pat,
            "wstr-override",
            CancellationToken.None);

        Assert.Single(response.Interactions);
        Assert.Equal("int-1", response.Interactions[0].Id);
    }

    [Fact]
    public async Task ValidateSignatureWithPatAsync_RejectsHashMismatch()
    {
        var pat = BuildToken(new { participant_did = "did:test:source" });

        await Assert.ThrowsAsync<Operon.Sdk.Errors.ValidationException>(() =>
            PatHelpers.ValidateSignatureWithPatAsync(
                new ClientApiConfig { BaseUri = new Uri("https://example.com/client-api/") },
                pat,
                Encoding.UTF8.GetBytes("payload"),
                new Dictionary<string, string>
                {
                    ["X-Operon-DID"] = "did:test:source",
                    ["X-Operon-Payload-Hash"] = "mismatch",
                    ["X-Operon-Signature"] = "sig",
                    ["X-Operon-Signature-KeyId"] = "did:test:source#keys-1",
                    ["X-Operon-Signature-Alg"] = "EdDSA"
                },
                CancellationToken.None));
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
