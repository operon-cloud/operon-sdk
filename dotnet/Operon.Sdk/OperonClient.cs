using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Auth;
using Operon.Sdk.Catalog;
using Operon.Sdk.Errors;
using Operon.Sdk.Internal;
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
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly OperonConfig _config;
    private readonly HttpClient _httpClient;
    private readonly ITokenProvider _tokenProvider;
    private readonly CatalogRegistry _registry = new();
    private readonly SemaphoreSlim _referenceLock = new(1, 1);

    private AccessToken? _cachedToken;
    private bool _referenceLoaded;
    private bool _disposed;

    private string? _participantDid;
    private string? _workstreamId;

    private readonly TimeSpan _heartbeatInterval;
    private readonly TimeSpan _heartbeatTimeout;
    private readonly Uri? _heartbeatUri;
    private CancellationTokenSource? _heartbeatCts;
    private Task? _heartbeatTask;

    /// <summary>
    /// Initializes a new instance of the <see cref="OperonClient"/> class.
    /// </summary>
    public OperonClient(OperonConfig config, HttpClient? httpClient = null, ITokenProvider? tokenProvider = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _httpClient = httpClient ?? CreateHttpClient(config);
        if (_httpClient.BaseAddress is null)
        {
            _httpClient.BaseAddress = config.BaseUri;
        }

        _tokenProvider = tokenProvider ?? new ClientCredentialsTokenProvider(config, _httpClient);
        _heartbeatInterval = config.SessionHeartbeatInterval;
        _heartbeatTimeout = config.SessionHeartbeatTimeout;
        _heartbeatUri = config.SessionHeartbeatUri;
    }

    /// <summary>
    /// Preemptively acquires an access token and starts optional heartbeat.
    /// </summary>
    public async Task InitAsync(CancellationToken cancellationToken = default)
    {
        await TokenValueAsync(cancellationToken).ConfigureAwait(false);
        StartHeartbeat();
    }

    /// <summary>
    /// Submit a transaction to Operon, applying automatic signing when enabled.
    /// </summary>
    public async Task<Transaction> SubmitTransactionAsync(TransactionRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        await InitAsync(cancellationToken).ConfigureAwait(false);
        await PopulateInteractionMetadataAsync(request, cancellationToken).ConfigureAwait(false);

        var payloadHash = SdkModelHelpers.ResolvePayloadHash(request);
        request.PayloadHash = payloadHash;

        var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);
        var signature = await ResolveSignatureAsync(request, payloadHash, token, cancellationToken).ConfigureAwait(false);
        request.Signature = signature;

        SdkModelHelpers.ValidateTransactionForSubmit(request);

        var timestamp = request.Timestamp ?? DateTimeOffset.UtcNow;
        var submission = new TransactionSubmission
        {
            CorrelationId = request.CorrelationId.Trim(),
            WorkstreamId = request.WorkstreamId!.Trim(),
            InteractionId = request.InteractionId.Trim(),
            Timestamp = timestamp.UtcDateTime,
            SourceDid = request.SourceDid!.Trim(),
            TargetDid = request.TargetDid!.Trim(),
            RoiClassification = TrimOrNull(request.RoiClassification),
            RoiCost = request.RoiCost,
            RoiTime = request.RoiTime,
            State = TrimOrNull(request.State),
            StateId = TrimOrNull(request.StateId),
            StateLabel = TrimOrNull(request.StateLabel),
            RoiBaseCost = request.RoiBaseCost,
            RoiBaseTime = request.RoiBaseTime,
            RoiCostSaving = request.RoiCostSaving,
            RoiTimeSaving = request.RoiTimeSaving,
            Signature = signature,
            PayloadHash = payloadHash,
            Label = TrimOrNull(request.Label),
            Tags = request.Tags?.Where(tag => !string.IsNullOrWhiteSpace(tag)).Select(tag => tag.Trim()).ToArray(),
            ActorExternalId = TrimOrNull(request.ActorExternalId),
            ActorExternalDisplayName = TrimOrNull(request.ActorExternalDisplayName),
            ActorExternalSource = TrimOrNull(request.ActorExternalSource),
            AssigneeExternalId = TrimOrNull(request.AssigneeExternalId),
            AssigneeExternalDisplayName = TrimOrNull(request.AssigneeExternalDisplayName),
            AssigneeExternalSource = TrimOrNull(request.AssigneeExternalSource),
            CustomerId = TrimOrNull(request.CustomerId),
            WorkspaceId = TrimOrNull(request.WorkspaceId),
            CreatedBy = TrimOrNull(request.CreatedBy)
        };

        using var response = await AuthorizedJsonRequestAsync(
            HttpMethod.Post,
            "v1/transactions",
            token.Value,
            submission,
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
        }

        var transaction = await response.Content
            .ReadFromJsonAsync<Transaction>(SerializerOptions, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new OperonSdkException("Transaction response was empty");

        transaction.NormalizeAliases();
        return transaction;
    }

    /// <summary>
    /// Returns cached interaction catalogue items (loads on first access).
    /// </summary>
    public async Task<IReadOnlyCollection<InteractionSummary>> GetInteractionsAsync(CancellationToken cancellationToken = default)
    {
        await InitAsync(cancellationToken).ConfigureAwait(false);
        await EnsureReferenceDataLoadedAsync(cancellationToken).ConfigureAwait(false);
        return _registry.Interactions;
    }

    /// <summary>
    /// Returns cached participant directory (loads on first access).
    /// </summary>
    public async Task<IReadOnlyCollection<ParticipantSummary>> GetParticipantsAsync(CancellationToken cancellationToken = default)
    {
        await InitAsync(cancellationToken).ConfigureAwait(false);
        await EnsureReferenceDataLoadedAsync(cancellationToken).ConfigureAwait(false);
        return _registry.Participants;
    }

    /// <summary>
    /// Returns workstream details scoped to the current token.
    /// </summary>
    public async Task<Workstream> GetWorkstreamAsync(string? workstreamId = null, CancellationToken cancellationToken = default)
    {
        await InitAsync(cancellationToken).ConfigureAwait(false);
        var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);
        var target = ResolveWorkstreamId(workstreamId);

        using var response = await AuthorizedJsonRequestAsync(
            HttpMethod.Get,
            $"v1/workstreams/{Uri.EscapeDataString(target)}",
            token.Value,
            null,
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
        }

        return await response.Content.ReadFromJsonAsync<Workstream>(SerializerOptions, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new OperonSdkException("Workstream response was empty");
    }

    /// <summary>
    /// Returns workstream interactions scoped to the current token.
    /// </summary>
    public async Task<WorkstreamInteractionsResponse> GetWorkstreamInteractionsAsync(
        string? workstreamId = null,
        CancellationToken cancellationToken = default)
    {
        await InitAsync(cancellationToken).ConfigureAwait(false);
        var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);
        var target = ResolveWorkstreamId(workstreamId);

        using var response = await AuthorizedJsonRequestAsync(
            HttpMethod.Get,
            $"v1/workstreams/{Uri.EscapeDataString(target)}/interactions",
            token.Value,
            null,
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
        }

        var payload = await response.Content.ReadFromJsonAsync<WorkstreamInteractionsResponse>(SerializerOptions, cancellationToken)
            .ConfigureAwait(false)
            ?? new WorkstreamInteractionsResponse();

        payload.NormalizeAliases();
        return payload;
    }

    /// <summary>
    /// Returns workstream participants scoped to the current token.
    /// </summary>
    public async Task<WorkstreamParticipantsResponse> GetWorkstreamParticipantsAsync(
        string? workstreamId = null,
        CancellationToken cancellationToken = default)
    {
        await InitAsync(cancellationToken).ConfigureAwait(false);
        var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);
        var target = ResolveWorkstreamId(workstreamId);

        using var response = await AuthorizedJsonRequestAsync(
            HttpMethod.Get,
            $"v1/workstreams/{Uri.EscapeDataString(target)}/participants",
            token.Value,
            null,
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
        }

        var payload = await response.Content.ReadFromJsonAsync<WorkstreamParticipantsResponse>(SerializerOptions, cancellationToken)
            .ConfigureAwait(false)
            ?? new WorkstreamParticipantsResponse();

        payload.NormalizeAliases();
        return payload;
    }

    /// <summary>
    /// Generates Operon signature headers for the supplied payload bytes.
    /// </summary>
    public async Task<IReadOnlyDictionary<string, string>> GenerateSignatureHeadersAsync(
        byte[] payload,
        string? algorithm = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        await InitAsync(cancellationToken).ConfigureAwait(false);

        var selectedAlgorithm = SdkModelHelpers.CanonicalSigningAlgorithm(
            string.IsNullOrWhiteSpace(algorithm) ? _config.SigningAlgorithm : algorithm);
        if (selectedAlgorithm is null)
        {
            throw new ValidationException($"unsupported signing algorithm {algorithm}");
        }

        if (_config.DisableSelfSign)
        {
            throw new ValidationException("automatic signing disabled: enable self signing to generate headers");
        }

        var payloadHash = SdkModelHelpers.ComputeSha256Base64Url(payload);
        var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);
        var signature = await RequestSelfSignatureAsync(token.Value, payloadHash, selectedAlgorithm, cancellationToken)
            .ConfigureAwait(false);

        var participantDid = SdkModelHelpers.Coalesce(_participantDid, token.ParticipantDid);
        if (string.IsNullOrWhiteSpace(participantDid))
        {
            throw new ValidationException("participant DID unavailable on access token");
        }

        var signatureValue = TrimOrNull(signature.Value);
        if (string.IsNullOrWhiteSpace(signatureValue))
        {
            throw new ValidationException("signature value missing from signing response");
        }

        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [SdkModelHelpers.HeaderOperonDid] = participantDid!,
            [SdkModelHelpers.HeaderOperonPayloadHash] = payloadHash,
            [SdkModelHelpers.HeaderOperonSignature] = signatureValue!,
            [SdkModelHelpers.HeaderOperonSignatureKey] = SdkModelHelpers.Coalesce(signature.KeyId, SdkModelHelpers.BuildKeyId(participantDid))!,
            [SdkModelHelpers.HeaderOperonSignatureAlgo] = SdkModelHelpers.Coalesce(signature.Algorithm, selectedAlgorithm)!
        };
    }

    /// <summary>
    /// Generates Operon signature headers for UTF-8 string payloads.
    /// </summary>
    public Task<IReadOnlyDictionary<string, string>> GenerateSignatureHeadersFromStringAsync(
        string payload,
        string? algorithm = null,
        CancellationToken cancellationToken = default)
    {
        payload ??= string.Empty;
        return GenerateSignatureHeadersAsync(Encoding.UTF8.GetBytes(payload), algorithm, cancellationToken);
    }

    /// <summary>
    /// Validates Operon signature headers against payload bytes.
    /// </summary>
    public async Task<SignatureValidationResult> ValidateSignatureHeadersAsync(
        byte[] payload,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        await InitAsync(cancellationToken).ConfigureAwait(false);

        var sanitized = SdkModelHelpers.SanitizeOperonHeaders(headers);
        var computedHash = SdkModelHelpers.ComputeSha256Base64Url(payload);
        var expectedHash = sanitized[SdkModelHelpers.HeaderOperonPayloadHash];
        if (!string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new ValidationException($"payload hash mismatch: expected {computedHash}, got {expectedHash}");
        }

        var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);
        var did = sanitized[SdkModelHelpers.HeaderOperonDid];

        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri($"v1/dids/{Uri.EscapeDataString(did)}/signature/verify", UriKind.Relative))
        {
            Content = new ByteArrayContent(payload)
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        foreach (var pair in sanitized)
        {
            request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
        }

        return await response.Content.ReadFromJsonAsync<SignatureValidationResult>(SerializerOptions, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new OperonSdkException("Signature validation response was empty");
    }

    /// <summary>
    /// Validates Operon signature headers against UTF-8 string payloads.
    /// </summary>
    public Task<SignatureValidationResult> ValidateSignatureHeadersFromStringAsync(
        string payload,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken = default)
    {
        payload ??= string.Empty;
        return ValidateSignatureHeadersAsync(Encoding.UTF8.GetBytes(payload), headers, cancellationToken);
    }

    /// <summary>
    /// Disposes managed resources and stops heartbeat loop.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await StopHeartbeatAsync().ConfigureAwait(false);
        _referenceLock.Dispose();

        if (_tokenProvider is IDisposable provider)
        {
            provider.Dispose();
        }

        _httpClient.Dispose();
        _disposed = true;
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

    private async Task<AccessToken> TokenValueAsync(CancellationToken cancellationToken)
    {
        var token = _cachedToken ?? await _tokenProvider.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        _cachedToken = token;

        if (!string.IsNullOrWhiteSpace(token.ParticipantDid))
        {
            _participantDid = token.ParticipantDid;
        }

        if (!string.IsNullOrWhiteSpace(token.WorkstreamId))
        {
            _workstreamId = token.WorkstreamId;
        }

        return token;
    }

    private async Task PopulateInteractionMetadataAsync(TransactionRequest request, CancellationToken cancellationToken)
    {
        request.WorkstreamId = SdkModelHelpers.Coalesce(request.WorkstreamId, request.ChannelId, _workstreamId);

        if (string.IsNullOrWhiteSpace(request.InteractionId))
        {
            request.SourceDid = SdkModelHelpers.Coalesce(request.SourceDid, _participantDid);
            request.ChannelId = request.WorkstreamId;
            return;
        }

        await EnsureReferenceDataLoadedAsync(cancellationToken).ConfigureAwait(false);

        if (!_registry.TryGetInteraction(request.InteractionId.Trim(), out var interaction) || interaction is null)
        {
            _referenceLoaded = false;
            await EnsureReferenceDataLoadedAsync(cancellationToken).ConfigureAwait(false);
            _registry.TryGetInteraction(request.InteractionId.Trim(), out interaction);
        }

        if (interaction is null)
        {
            throw new ValidationException($"interaction {request.InteractionId} not found");
        }

        request.WorkstreamId = SdkModelHelpers.Coalesce(request.WorkstreamId, interaction.WorkstreamId, _workstreamId);

        if (string.IsNullOrWhiteSpace(request.SourceDid))
        {
            if (string.IsNullOrWhiteSpace(interaction.SourceDid))
            {
                throw new ValidationException($"interaction {request.InteractionId} missing source DID");
            }

            request.SourceDid = interaction.SourceDid;
        }

        if (string.IsNullOrWhiteSpace(request.TargetDid))
        {
            if (string.IsNullOrWhiteSpace(interaction.TargetDid))
            {
                throw new ValidationException($"interaction {request.InteractionId} missing target DID");
            }

            request.TargetDid = interaction.TargetDid;
        }

        request.SourceDid = SdkModelHelpers.Coalesce(request.SourceDid, _participantDid);
        request.ChannelId = request.WorkstreamId;
    }

    private async Task EnsureReferenceDataLoadedAsync(CancellationToken cancellationToken)
    {
        if (_referenceLoaded)
        {
            return;
        }

        await _referenceLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_referenceLoaded)
            {
                return;
            }

            var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);

            using var interactionsResponse = await AuthorizedJsonRequestAsync(
                HttpMethod.Get,
                "v1/interactions",
                token.Value,
                null,
                cancellationToken).ConfigureAwait(false);

            if (!interactionsResponse.IsSuccessStatusCode)
            {
                throw await SdkModelHelpers.DecodeApiErrorAsync(interactionsResponse).ConfigureAwait(false);
            }

            var interactionsPayload = await interactionsResponse.Content
                .ReadFromJsonAsync<ReferenceDataEnvelope<InteractionSummary>>(SerializerOptions, cancellationToken)
                .ConfigureAwait(false)
                ?? new ReferenceDataEnvelope<InteractionSummary>();

            using var participantsResponse = await AuthorizedJsonRequestAsync(
                HttpMethod.Get,
                "v1/participants",
                token.Value,
                null,
                cancellationToken).ConfigureAwait(false);

            if (!participantsResponse.IsSuccessStatusCode)
            {
                throw await SdkModelHelpers.DecodeApiErrorAsync(participantsResponse).ConfigureAwait(false);
            }

            var participantsPayload = await participantsResponse.Content
                .ReadFromJsonAsync<ReferenceDataEnvelope<ParticipantSummary>>(SerializerOptions, cancellationToken)
                .ConfigureAwait(false)
                ?? new ReferenceDataEnvelope<ParticipantSummary>();

            var didById = participantsPayload.Data
                .Where(item => !string.IsNullOrWhiteSpace(item.Id) && !string.IsNullOrWhiteSpace(item.Did))
                .ToDictionary(item => item.Id, item => item.Did, StringComparer.Ordinal);

            foreach (var interaction in interactionsPayload.Data)
            {
                interaction.NormalizeAliases();

                if (string.IsNullOrWhiteSpace(interaction.SourceDid)
                    && !string.IsNullOrWhiteSpace(interaction.SourceParticipantId)
                    && didById.TryGetValue(interaction.SourceParticipantId, out var sourceDid))
                {
                    interaction.SourceDid = sourceDid;
                }

                if (string.IsNullOrWhiteSpace(interaction.TargetDid)
                    && !string.IsNullOrWhiteSpace(interaction.TargetParticipantId)
                    && didById.TryGetValue(interaction.TargetParticipantId, out var targetDid))
                {
                    interaction.TargetDid = targetDid;
                }
            }

            foreach (var participant in participantsPayload.Data)
            {
                participant.NormalizeAliases();
            }

            _registry.UpdateInteractions(interactionsPayload.Data);
            _registry.UpdateParticipants(participantsPayload.Data);
            _referenceLoaded = true;
        }
        finally
        {
            _referenceLock.Release();
        }
    }

    private async Task<Signature> ResolveSignatureAsync(
        TransactionRequest request,
        string payloadHash,
        AccessToken token,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(request.Signature?.Value))
        {
            var algorithm = SdkModelHelpers.CanonicalSigningAlgorithm(request.Signature.Algorithm)
                ?? SdkModelHelpers.CanonicalSigningAlgorithm(_config.SigningAlgorithm)
                ?? SdkModelHelpers.AlgorithmEd25519;

            return new Signature
            {
                Algorithm = algorithm,
                Value = request.Signature.Value!.Trim(),
                KeyId = SdkModelHelpers.Coalesce(request.Signature.KeyId, SdkModelHelpers.BuildKeyId(request.SourceDid))
            };
        }

        if (_config.DisableSelfSign)
        {
            throw new ValidationException(
                "automatic signing disabled: provide signature manually or enable self signing");
        }

        var requestedAlgorithm = SdkModelHelpers.CanonicalSigningAlgorithm(request.Signature?.Algorithm)
            ?? SdkModelHelpers.CanonicalSigningAlgorithm(_config.SigningAlgorithm)
            ?? SdkModelHelpers.AlgorithmEd25519;

        return await RequestSelfSignatureAsync(token.Value, payloadHash, requestedAlgorithm, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<Signature> RequestSelfSignatureAsync(
        string pat,
        string payloadHash,
        string algorithm,
        CancellationToken cancellationToken)
    {
        using var response = await AuthorizedJsonRequestAsync(
            HttpMethod.Post,
            "v1/dids/self/sign",
            pat,
            new SelfSignRequest
            {
                PayloadHash = payloadHash,
                HashAlgorithm = "SHA-256",
                Algorithm = algorithm
            },
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
        }

        var payload = await response.Content.ReadFromJsonAsync<SelfSignResponse>(SerializerOptions, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new OperonSdkException("Self sign response was empty");

        if (payload.Signature is null || string.IsNullOrWhiteSpace(payload.Signature.Value))
        {
            throw new OperonSdkException("Self sign payload missing signature");
        }

        payload.Signature.Algorithm = SdkModelHelpers.CanonicalSigningAlgorithm(payload.Signature.Algorithm)
            ?? algorithm;
        payload.Signature.KeyId = SdkModelHelpers.Coalesce(
            payload.Signature.KeyId,
            SdkModelHelpers.BuildKeyId(_participantDid));

        return payload.Signature;
    }

    private async Task<HttpResponseMessage> AuthorizedJsonRequestAsync(
        HttpMethod method,
        string relativePath,
        string accessToken,
        object? payload,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, new Uri(relativePath, UriKind.Relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (payload is not null)
        {
            request.Content = JsonContent.Create(payload, options: SerializerOptions);
        }

        try
        {
            return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperonSdkException)
        {
            request.Dispose();
            throw;
        }
        catch (Exception ex)
        {
            request.Dispose();
            throw new TransportException($"Failed to call {relativePath}", ex);
        }
    }

    private string ResolveWorkstreamId(string? overrideWorkstreamId)
    {
        var resolved = SdkModelHelpers.Coalesce(overrideWorkstreamId, _workstreamId);
        if (string.IsNullOrWhiteSpace(resolved))
        {
            throw new ValidationException(
                "workstream ID is required: token not scoped to a workstream and no override provided");
        }

        return resolved;
    }

    private void StartHeartbeat()
    {
        if (_heartbeatUri is null || _heartbeatInterval <= TimeSpan.Zero || _heartbeatTask is not null)
        {
            return;
        }

        _heartbeatCts = new CancellationTokenSource();
        _heartbeatTask = Task.Run(() => HeartbeatLoopAsync(_heartbeatCts.Token));
    }

    private async Task StopHeartbeatAsync()
    {
        if (_heartbeatTask is null || _heartbeatCts is null)
        {
            return;
        }

        _heartbeatCts.Cancel();
        try
        {
            await _heartbeatTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // expected during shutdown
        }
        finally
        {
            _heartbeatCts.Dispose();
            _heartbeatCts = null;
            _heartbeatTask = null;
        }
    }

    private async Task HeartbeatLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await PerformHeartbeatAsync(cancellationToken).ConfigureAwait(false);
                await Task.Delay(_heartbeatInterval, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
    }

    private async Task PerformHeartbeatAsync(CancellationToken cancellationToken)
    {
        if (_heartbeatUri is null)
        {
            return;
        }

        try
        {
            var token = await TokenValueAsync(cancellationToken).ConfigureAwait(false);
            using var request = new HttpRequestMessage(HttpMethod.Get, _heartbeatUri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            linked.CancelAfter(_heartbeatTimeout);

            using var response = await _httpClient.SendAsync(request, linked.Token).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _cachedToken = await _tokenProvider.ForceRefreshAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // ignore heartbeat cancellation and timeout
        }
        catch
        {
            // ignore transient heartbeat failures
        }
    }

    private static string? TrimOrNull(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record ReferenceDataEnvelope<T>
    {
        public T[] Data { get; init; } = Array.Empty<T>();
    }

    private sealed record TransactionSubmission
    {
        public string CorrelationId { get; init; } = string.Empty;
        public string WorkstreamId { get; init; } = string.Empty;
        public string InteractionId { get; init; } = string.Empty;
        public DateTime Timestamp { get; init; }
        public string SourceDid { get; init; } = string.Empty;
        public string TargetDid { get; init; } = string.Empty;
        public string? RoiClassification { get; init; }
        public int? RoiCost { get; init; }
        public int? RoiTime { get; init; }
        public string? State { get; init; }
        public string? StateId { get; init; }
        public string? StateLabel { get; init; }
        public int? RoiBaseCost { get; init; }
        public int? RoiBaseTime { get; init; }
        public int? RoiCostSaving { get; init; }
        public int? RoiTimeSaving { get; init; }
        public Signature Signature { get; init; } = new();
        public string PayloadHash { get; init; } = string.Empty;
        public string? Label { get; init; }
        public string[]? Tags { get; init; }
        public string? ActorExternalId { get; init; }
        public string? ActorExternalDisplayName { get; init; }
        public string? ActorExternalSource { get; init; }
        public string? AssigneeExternalId { get; init; }
        public string? AssigneeExternalDisplayName { get; init; }
        public string? AssigneeExternalSource { get; init; }
        public string? CustomerId { get; init; }
        public string? WorkspaceId { get; init; }
        public string? CreatedBy { get; init; }
    }

    private sealed record SelfSignRequest
    {
        public string PayloadHash { get; init; } = string.Empty;
        public string HashAlgorithm { get; init; } = "SHA-256";
        public string Algorithm { get; init; } = SdkModelHelpers.AlgorithmEd25519;
    }

    private sealed record SelfSignResponse
    {
        public Signature? Signature { get; init; }
    }
}
