using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Auth;
using Operon.Sdk.Catalog;
using Operon.Sdk.Errors;
using Operon.Sdk.Models;

namespace Operon.Sdk;

/// <summary>
/// Token-aware client for interacting with Operon APIs.
/// </summary>
public sealed class OperonClient : IAsyncDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly OperonConfig _config;
    private readonly HttpClient _httpClient;
    private readonly ITokenProvider _tokenProvider;
    private readonly CatalogRegistry _registry = new();

    private AccessToken? _cachedToken;
    private bool _disposed;

    public OperonClient(OperonConfig config, HttpClient? httpClient = null, ITokenProvider? tokenProvider = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _httpClient = httpClient ?? CreateHttpClient(config);
        _tokenProvider = tokenProvider ?? new ClientCredentialsTokenProvider(config, _httpClient);
    }

    /// <summary>
    /// Preemptively acquires an access token. Optional but recommended to surface errors early.
    /// </summary>
    public async Task InitAsync(CancellationToken cancellationToken = default)
    {
        _cachedToken = await _tokenProvider.GetTokenAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Submit a transaction to Operon, applying automatic signing when enabled.
    /// </summary>
    public async Task<Transaction> SubmitTransactionAsync(TransactionRequest request, CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        var token = _cachedToken ?? await _tokenProvider.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        _cachedToken = token;

        await PopulateInteractionMetadataAsync(request, token, cancellationToken).ConfigureAwait(false);

        var payload = ResolvePayload(request);
        var signature = await ResolveSignatureAsync(request, payload.PayloadHash, token, cancellationToken).ConfigureAwait(false);
        request.Signature = signature;

        ValidateRequest(request);

        var model = new TransactionSubmission
        {
            CorrelationId = request.CorrelationId.Trim(),
            ChannelId = request.ChannelId!,
            InteractionId = request.InteractionId.Trim(),
            Timestamp = (request.Timestamp ?? DateTimeOffset.UtcNow).UtcDateTime,
            SourceDid = request.SourceDid!,
            TargetDid = request.TargetDid!,
            Signature = request.Signature,
            PayloadData = payload.PayloadData,
            PayloadHash = payload.PayloadHash,
            Label = string.IsNullOrWhiteSpace(request.Label) ? null : request.Label,
            Tags = request.Tags?.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToArray()
        };

        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, new Uri("v1/transactions", UriKind.Relative))
        {
            Content = JsonContent.Create(model, options: SerializerOptions)
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);

        try
        {
            using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw await DecodeErrorAsync(response).ConfigureAwait(false);
            }

            var transaction = await response.Content.ReadFromJsonAsync<Transaction>(SerializerOptions, cancellationToken).ConfigureAwait(false)
                ?? throw new OperonSdkException("Transaction response was empty");

            return transaction;
        }
        catch (OperonSdkException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new TransportException("Failed to submit transaction", ex);
        }
    }

    /// <summary>
    /// Returns cached interaction catalogue items (loads on first access).
    /// </summary>
    public async Task<IReadOnlyCollection<InteractionSummary>> GetInteractionsAsync(CancellationToken cancellationToken = default)
    {
        if (!_registry.Interactions.Any())
        {
            await RefreshRegistryAsync(cancellationToken).ConfigureAwait(false);
        }
        return _registry.Interactions;
    }

    /// <summary>
    /// Returns cached participant directory (loads on first access).
    /// </summary>
    public async Task<IReadOnlyCollection<ParticipantSummary>> GetParticipantsAsync(CancellationToken cancellationToken = default)
    {
        if (!_registry.Participants.Any())
        {
            await RefreshRegistryAsync(cancellationToken).ConfigureAwait(false);
        }
        return _registry.Participants;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        if (_tokenProvider is IDisposable disposableProvider)
        {
            disposableProvider.Dispose();
        }

        _httpClient.Dispose();
        _disposed = true;
        await Task.CompletedTask;
    }

    private static HttpClient CreateHttpClient(OperonConfig config)
    {
        var client = new HttpClient
        {
            BaseAddress = config.BaseUri,
            Timeout = config.HttpTimeout
        };
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }

    private async Task PopulateInteractionMetadataAsync(TransactionRequest request, AccessToken token, CancellationToken cancellationToken)
    {
        request.ChannelId = Coalesce(request.ChannelId, token.ChannelId);

        if (string.IsNullOrWhiteSpace(request.InteractionId))
        {
            request.SourceDid = Coalesce(request.SourceDid, token.ParticipantDid);
            return;
        }

        if (!_registry.TryGetInteraction(request.InteractionId, out var interaction))
        {
            await RefreshRegistryAsync(cancellationToken).ConfigureAwait(false);
            _registry.TryGetInteraction(request.InteractionId, out interaction);
        }

        if (interaction is null)
        {
            throw new ValidationException($"Interaction '{request.InteractionId}' not found.");
        }

        request.ChannelId = Coalesce(request.ChannelId, interaction.ChannelId);
        request.SourceDid = Coalesce(request.SourceDid, interaction.SourceDid, token.ParticipantDid);
        request.TargetDid = Coalesce(request.TargetDid, interaction.TargetDid);
    }

    private async Task RefreshRegistryAsync(CancellationToken cancellationToken)
    {
        var token = _cachedToken ?? await _tokenProvider.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        _cachedToken = token;

        using var interactionsRequest = new HttpRequestMessage(HttpMethod.Get, new Uri("v1/interactions", UriKind.Relative));
        interactionsRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        using var interactionsResponse = await _httpClient.SendAsync(interactionsRequest, cancellationToken).ConfigureAwait(false);
        if (!interactionsResponse.IsSuccessStatusCode)
        {
            throw await DecodeErrorAsync(interactionsResponse).ConfigureAwait(false);
        }

        var interactionsPayload = await interactionsResponse.Content.ReadFromJsonAsync<DataResponse<InteractionSummary>>(SerializerOptions, cancellationToken).ConfigureAwait(false)
            ?? new DataResponse<InteractionSummary>();

        using var participantsRequest = new HttpRequestMessage(HttpMethod.Get, new Uri("v1/participants", UriKind.Relative));
        participantsRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        using var participantsResponse = await _httpClient.SendAsync(participantsRequest, cancellationToken).ConfigureAwait(false);
        if (!participantsResponse.IsSuccessStatusCode)
        {
            throw await DecodeErrorAsync(participantsResponse).ConfigureAwait(false);
        }

        var participantsPayload = await participantsResponse.Content.ReadFromJsonAsync<DataResponse<ParticipantSummary>>(SerializerOptions, cancellationToken).ConfigureAwait(false)
            ?? new DataResponse<ParticipantSummary>();

        foreach (var interaction in interactionsPayload.Data)
        {
            if (!string.IsNullOrWhiteSpace(interaction.SourceParticipantId) && participantsPayload.TryFind(interaction.SourceParticipantId, out var source))
            {
                interaction.SourceDid = source.Did;
            }
            if (!string.IsNullOrWhiteSpace(interaction.TargetParticipantId) && participantsPayload.TryFind(interaction.TargetParticipantId, out var target))
            {
                interaction.TargetDid = target.Did;
            }
        }

        _registry.UpdateParticipants(participantsPayload.Data);
        _registry.UpdateInteractions(interactionsPayload.Data);
    }

    private static (string? PayloadData, string PayloadHash) ResolvePayload(TransactionRequest request)
    {
        if (request.PayloadBytes is { Length: > 0 } bytes)
        {
            var hash = ComputeSha256(bytes);
            if (!string.IsNullOrWhiteSpace(request.PayloadHash) && !string.Equals(request.PayloadHash, hash, StringComparison.Ordinal))
            {
                throw new ValidationException("Provided payload hash does not match payload bytes.");
            }
            return (Convert.ToBase64String(bytes), hash);
        }

        if (!string.IsNullOrWhiteSpace(request.PayloadHash))
        {
            return (null, request.PayloadHash!);
        }

        throw new ValidationException("Either payload bytes or payload hash must be supplied.");
    }

    private async Task<Signature> ResolveSignatureAsync(TransactionRequest request, string payloadHash, AccessToken token, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(request.Signature?.Value))
        {
            var signature = request.Signature.Clone();
            signature.Algorithm = string.IsNullOrWhiteSpace(signature.Algorithm) ? "EdDSA" : signature.Algorithm;
            signature.KeyId = string.IsNullOrWhiteSpace(signature.KeyId) ? BuildKeyId(request.SourceDid ?? token.ParticipantDid) : signature.KeyId;
            return signature;
        }

        if (_config.DisableSelfSign)
        {
            throw new ValidationException("Signature is required when self signing is disabled.");
        }

        using var requestMessage = new HttpRequestMessage(HttpMethod.Post, new Uri("v1/dids/self/sign", UriKind.Relative))
        {
            Content = JsonContent.Create(new SelfSignRequest
            {
                PayloadHash = payloadHash,
                HashAlgorithm = "SHA-256",
                Algorithm = request.Signature?.Algorithm ?? "EdDSA"
            }, options: SerializerOptions)
        };
        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);

        using var response = await _httpClient.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await DecodeErrorAsync(response).ConfigureAwait(false);
        }

        var payload = await response.Content.ReadFromJsonAsync<SelfSignResponse>(SerializerOptions, cancellationToken).ConfigureAwait(false)
            ?? throw new OperonSdkException("Self sign response was empty");

        var signatureResult = payload.Signature ?? throw new OperonSdkException("Self sign payload missing signature");
        signatureResult.KeyId ??= BuildKeyId(request.SourceDid ?? token.ParticipantDid);
        return signatureResult;
    }

    private static string? BuildKeyId(string? sourceDid)
        => string.IsNullOrWhiteSpace(sourceDid) ? null : $"{sourceDid}#keys-1";

    private static string? Coalesce(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }
        return null;
    }

    private static void ValidateRequest(TransactionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CorrelationId))
        {
            throw new ValidationException("CorrelationId is required");
        }
        if (string.IsNullOrWhiteSpace(request.ChannelId))
        {
            throw new ValidationException("ChannelId is required");
        }
        if (string.IsNullOrWhiteSpace(request.InteractionId))
        {
            throw new ValidationException("InteractionId is required");
        }
        if (string.IsNullOrWhiteSpace(request.SourceDid))
        {
            throw new ValidationException("Source DID is required");
        }
        if (string.IsNullOrWhiteSpace(request.TargetDid))
        {
            throw new ValidationException("Target DID is required");
        }
        if (string.IsNullOrWhiteSpace(request.Signature?.Algorithm))
        {
            throw new ValidationException("Signature algorithm is required");
        }
        if (string.IsNullOrWhiteSpace(request.Signature?.Value))
        {
            throw new ValidationException("Signature value is required");
        }
    }

    private static string ComputeSha256(byte[] payload)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(payload);
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static async Task<OperonApiException> DecodeErrorAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Deserialize<JsonElement>(body);
            var message = json.TryGetProperty("message", out var msg) ? msg.GetString() ?? response.ReasonPhrase ?? string.Empty : response.ReasonPhrase ?? string.Empty;
            var code = json.TryGetProperty("code", out var codeProp) ? codeProp.GetString() : null;
            return new OperonApiException(string.IsNullOrWhiteSpace(message) ? response.StatusCode.ToString() : message, response.StatusCode, code, json);
        }
        catch
        {
            return new OperonApiException(string.IsNullOrWhiteSpace(body) ? response.StatusCode.ToString() : body, response.StatusCode);
        }
    }

    private sealed record TransactionSubmission
    {
        public required string CorrelationId { get; init; }
            = string.Empty;
        public required string ChannelId { get; init; }
            = string.Empty;
        public required string InteractionId { get; init; }
            = string.Empty;
        public required DateTime Timestamp { get; init; }
            = DateTime.UtcNow;
        public required string SourceDid { get; init; }
            = string.Empty;
        public required string TargetDid { get; init; }
            = string.Empty;
        public required Signature Signature { get; init; }
            = new();
        public string? PayloadData { get; init; }
            = string.Empty;
        public required string PayloadHash { get; init; }
            = string.Empty;
        public string? Label { get; init; }
            = string.Empty;
        public string[]? Tags { get; init; }
            = Array.Empty<string>();
    }

    private sealed record DataResponse<T>
    {
        public IReadOnlyList<T> Data { get; init; } = Array.Empty<T>();

        public bool TryFind(string id, out ParticipantSummary summary)
        {
            if (typeof(T) == typeof(ParticipantSummary))
            {
                foreach (var item in Data)
                {
                    if (item is ParticipantSummary participant && participant.Id == id)
                    {
                        summary = participant;
                        return true;
                    }
                }
            }

            summary = default!;
            return false;
        }
    }

    private sealed record SelfSignRequest
    {
        public required string PayloadHash { get; init; }
            = string.Empty;
        public required string HashAlgorithm { get; init; }
            = "SHA-256";
        public required string Algorithm { get; init; }
            = "EdDSA";
    }

    private sealed record SelfSignResponse
    {
        public Signature? Signature { get; init; }
            = new();
    }
}
