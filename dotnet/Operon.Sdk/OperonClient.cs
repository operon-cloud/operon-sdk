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

    /// <summary>
    /// Initializes a new instance of the <see cref="OperonClient"/> class.
    /// </summary>
    /// <param name="config">Client configuration describing endpoints and authentication.</param>
    /// <param name="httpClient">Optional custom <see cref="HttpClient"/> instance.</param>
    /// <param name="tokenProvider">Optional token provider; defaults to <see cref="ClientCredentialsTokenProvider"/>.</param>
    public OperonClient(OperonConfig config, HttpClient? httpClient = null, ITokenProvider? tokenProvider = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _httpClient = httpClient ?? CreateHttpClient(config);
        _tokenProvider = tokenProvider ?? new ClientCredentialsTokenProvider(config, _httpClient);
    }

    /// <summary>
    /// Preemptively acquires an access token. Optional but recommended to surface errors early.
    /// </summary>
    /// <param name="cancellationToken">Token used to cancel the asynchronous operation.</param>
    /// <returns>A task that completes once initialization finishes.</returns>
    public async Task InitAsync(CancellationToken cancellationToken = default)
    {
        _cachedToken = await _tokenProvider.GetTokenAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Submit a transaction to Operon, applying automatic signing when enabled.
    /// </summary>
    /// <param name="request">Transaction details to submit.</param>
    /// <param name="cancellationToken">Token used to cancel the asynchronous operation.</param>
    /// <returns>The persisted <see cref="Transaction"/> metadata.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="request"/> is null.</exception>
    /// <exception cref="ValidationException">Thrown when required fields are missing.</exception>
    /// <exception cref="OperonApiException">Thrown when the Operon API returns an error.</exception>
    /// <exception cref="TransportException">Thrown when a transport issue prevents submission.</exception>
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
    /// <param name="cancellationToken">Token used to cancel the asynchronous operation.</param>
    /// <returns>Known interactions accessible to the client.</returns>
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
    /// <param name="cancellationToken">Token used to cancel the asynchronous operation.</param>
    /// <returns>Participants available to the client.</returns>
    public async Task<IReadOnlyCollection<ParticipantSummary>> GetParticipantsAsync(CancellationToken cancellationToken = default)
    {
        if (!_registry.Participants.Any())
        {
            await RefreshRegistryAsync(cancellationToken).ConfigureAwait(false);
        }
        return _registry.Participants;
    }

    /// <summary>
    /// Disposes the underlying HTTP client and token provider resources.
    /// </summary>
    /// <returns>A task representing completion of the dispose operation.</returns>
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
            request.SourceDid = Coalesce(request.SourceDid, token.ParticipantDid);
            if (!string.IsNullOrWhiteSpace(request.ChannelId)
                && !string.IsNullOrWhiteSpace(request.SourceDid)
                && !string.IsNullOrWhiteSpace(request.TargetDid))
            {
                return;
            }

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

        var channelId = Coalesce(token.ChannelId);
        if (string.IsNullOrWhiteSpace(channelId))
        {
            throw new ValidationException("ChannelId is required to load registry data.");
        }

        var encodedChannel = Uri.EscapeDataString(channelId);

        using var interactionsRequest = new HttpRequestMessage(HttpMethod.Get, new Uri($"v1/channels/{encodedChannel}/interactions", UriKind.Relative));
        interactionsRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        using var interactionsResponse = await _httpClient.SendAsync(interactionsRequest, cancellationToken).ConfigureAwait(false);
        if (!interactionsResponse.IsSuccessStatusCode)
        {
            throw await DecodeErrorAsync(interactionsResponse).ConfigureAwait(false);
        }

        var interactionsPayload = await interactionsResponse.Content.ReadFromJsonAsync<ChannelInteractionsResponse>(SerializerOptions, cancellationToken).ConfigureAwait(false)
            ?? new ChannelInteractionsResponse();

        using var participantsRequest = new HttpRequestMessage(HttpMethod.Get, new Uri($"v1/channels/{encodedChannel}/participants", UriKind.Relative));
        participantsRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        using var participantsResponse = await _httpClient.SendAsync(participantsRequest, cancellationToken).ConfigureAwait(false);
        if (!participantsResponse.IsSuccessStatusCode)
        {
            throw await DecodeErrorAsync(participantsResponse).ConfigureAwait(false);
        }

        var participantsPayload = await participantsResponse.Content.ReadFromJsonAsync<ChannelParticipantsResponse>(SerializerOptions, cancellationToken).ConfigureAwait(false)
            ?? new ChannelParticipantsResponse();

        foreach (var interaction in interactionsPayload.Interactions)
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

        _registry.UpdateParticipants(participantsPayload.Participants);
        _registry.UpdateInteractions(interactionsPayload.Interactions);
    }

    private static (byte[]? PayloadBytes, string PayloadHash) ResolvePayload(TransactionRequest request)
    {
        if (request.PayloadBytes is { Length: > 0 } bytes)
        {
            var hash = ComputeSha256(bytes);
            if (!string.IsNullOrWhiteSpace(request.PayloadHash) && !string.Equals(request.PayloadHash, hash, StringComparison.Ordinal))
            {
                throw new ValidationException("Provided payload hash does not match payload bytes.");
            }
            return (bytes, hash);
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
        public required string PayloadHash { get; init; }
            = string.Empty;
        public string? Label { get; init; }
            = string.Empty;
        public string[]? Tags { get; init; }
            = Array.Empty<string>();
    }

    private sealed record ChannelInteractionsResponse
    {
        public IReadOnlyList<InteractionSummary> Interactions { get; init; } = Array.Empty<InteractionSummary>();
        public int TotalCount { get; init; }
        public int Page { get; init; }
        public int PageSize { get; init; }
        public bool HasMore { get; init; }
    }

    private sealed record ChannelParticipantsResponse
    {
        public IReadOnlyList<ParticipantSummary> Participants { get; init; } = Array.Empty<ParticipantSummary>();
        public int TotalCount { get; init; }
        public int Page { get; init; }
        public int PageSize { get; init; }
        public bool HasMore { get; init; }

        public bool TryFind(string id, out ParticipantSummary summary)
        {
            foreach (var participant in Participants)
            {
                if (participant.Id == id)
                {
                    summary = participant;
                    return true;
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
