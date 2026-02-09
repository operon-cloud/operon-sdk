using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Auth;
using Operon.Sdk.Errors;
using Operon.Sdk.Internal;
using Operon.Sdk.Models;

namespace Operon.Sdk;

/// <summary>
/// PAT-scoped helper APIs for signing, transaction submission, and workstream lookups.
/// </summary>
public static class PatHelpers
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Requests a managed signature for a payload hash using a PAT.
    /// </summary>
    public static async Task<Signature> SignHashWithPatAsync(
        ClientApiConfig config,
        string pat,
        string payloadHash,
        string algorithm,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(pat))
        {
            throw new ValidationException("pat is required");
        }

        if (string.IsNullOrWhiteSpace(payloadHash))
        {
            throw new ValidationException("payload hash is required");
        }

        SdkModelHelpers.ValidatePayloadHashFormat(payloadHash.Trim());

        var selectedAlgorithm = SdkModelHelpers.CanonicalSigningAlgorithm(algorithm);
        if (selectedAlgorithm is null)
        {
            throw new ValidationException($"unsupported signing algorithm {algorithm}");
        }

        var normalized = NormalizeClientApiConfig(config);
        try
        {
            using var response = await SendJsonAsync(
                normalized.HttpClient,
                normalized.BaseUri,
                HttpMethod.Post,
                "v1/dids/self/sign",
                pat.Trim(),
                new
                {
                    payloadHash = payloadHash.Trim(),
                    hashAlgorithm = "SHA-256",
                    algorithm = selectedAlgorithm
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
                ?? selectedAlgorithm;

            if (string.IsNullOrWhiteSpace(payload.Signature.KeyId))
            {
                var claims = DecodedClaims.Decode(pat);
                payload.Signature.KeyId = SdkModelHelpers.BuildKeyId(claims.ParticipantDid);
            }

            return payload.Signature;
        }
        finally
        {
            if (normalized.OwnsHttpClient)
            {
                normalized.HttpClient.Dispose();
            }
        }
    }

    /// <summary>
    /// Submits a signed transaction with PAT authorization.
    /// </summary>
    public static async Task<Transaction> SubmitTransactionWithPatAsync(
        ClientApiConfig config,
        string pat,
        TransactionRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(pat))
        {
            throw new ValidationException("pat is required");
        }

        var claims = DecodedClaims.Decode(pat);
        request.WorkstreamId = SdkModelHelpers.Coalesce(request.WorkstreamId, request.ChannelId, claims.WorkstreamId);
        request.SourceDid = SdkModelHelpers.Coalesce(request.SourceDid, claims.ParticipantDid);
        request.ChannelId = request.WorkstreamId;

        var payloadHash = SdkModelHelpers.ResolvePayloadHash(request);
        request.PayloadHash = payloadHash;

        SdkModelHelpers.ValidateTransactionForSubmit(request);

        var timestamp = request.Timestamp ?? DateTimeOffset.UtcNow;
        var payload = new TransactionSubmission
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
            Signature = request.Signature,
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

        var normalized = NormalizeClientApiConfig(config);
        try
        {
            using var response = await SendJsonAsync(
                normalized.HttpClient,
                normalized.BaseUri,
                HttpMethod.Post,
                "v1/transactions",
                pat.Trim(),
                payload,
                cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
            }

            var transaction = await response.Content.ReadFromJsonAsync<Transaction>(SerializerOptions, cancellationToken)
                .ConfigureAwait(false)
                ?? throw new OperonSdkException("Transaction response was empty");

            transaction.NormalizeAliases();
            return transaction;
        }
        finally
        {
            if (normalized.OwnsHttpClient)
            {
                normalized.HttpClient.Dispose();
            }
        }
    }

    /// <summary>
    /// Validates Operon signature headers against payload bytes using PAT authorization.
    /// </summary>
    public static async Task<SignatureValidationResult> ValidateSignatureWithPatAsync(
        ClientApiConfig config,
        string pat,
        byte[] payload,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (string.IsNullOrWhiteSpace(pat))
        {
            throw new ValidationException("pat is required");
        }

        var sanitized = SdkModelHelpers.SanitizeOperonHeaders(headers);

        var computedHash = SdkModelHelpers.ComputeSha256Base64Url(payload);
        var expectedHash = sanitized[SdkModelHelpers.HeaderOperonPayloadHash];
        if (!string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new ValidationException($"payload hash mismatch: expected {computedHash}, got {expectedHash}");
        }

        var did = sanitized[SdkModelHelpers.HeaderOperonDid];
        var normalized = NormalizeClientApiConfig(config);

        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri(normalized.BaseUri, $"v1/dids/{Uri.EscapeDataString(did)}/signature/verify"))
            {
                Content = new ByteArrayContent(payload)
            };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pat.Trim());
            foreach (var pair in sanitized)
            {
                request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }

            using var response = await normalized.HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
            }

            return await response.Content.ReadFromJsonAsync<SignatureValidationResult>(SerializerOptions, cancellationToken)
                .ConfigureAwait(false)
                ?? throw new OperonSdkException("Signature validation response was empty");
        }
        catch (OperonSdkException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new TransportException("Failed to validate signature with PAT", ex);
        }
        finally
        {
            if (normalized.OwnsHttpClient)
            {
                normalized.HttpClient.Dispose();
            }
        }
    }

    /// <summary>
    /// Validates Operon signature headers against UTF-8 string payloads.
    /// </summary>
    public static Task<SignatureValidationResult> ValidateSignatureWithPatFromStringAsync(
        ClientApiConfig config,
        string pat,
        string payload,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken = default)
    {
        payload ??= string.Empty;
        return ValidateSignatureWithPatAsync(config, pat, Encoding.UTF8.GetBytes(payload), headers, cancellationToken);
    }

    /// <summary>
    /// Fetches workstream metadata using PAT authorization.
    /// </summary>
    public static async Task<Workstream> FetchWorkstreamAsync(
        WorkstreamDataConfig config,
        string pat,
        string? workstreamId = null,
        CancellationToken cancellationToken = default)
    {
        var (baseUri, httpClient, ownsClient) = NormalizeWorkstreamConfig(config);
        try
        {
            var target = ResolveWorkstreamIdFromPat(pat, workstreamId);
            using var response = await SendJsonAsync(
                httpClient,
                baseUri,
                HttpMethod.Get,
                $"v1/workstreams/{Uri.EscapeDataString(target)}",
                pat.Trim(),
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
        finally
        {
            if (ownsClient)
            {
                httpClient.Dispose();
            }
        }
    }

    /// <summary>
    /// Fetches workstream interactions using PAT authorization.
    /// </summary>
    public static async Task<WorkstreamInteractionsResponse> FetchWorkstreamInteractionsAsync(
        WorkstreamDataConfig config,
        string pat,
        string? workstreamId = null,
        CancellationToken cancellationToken = default)
    {
        var payload = await FetchWorkstreamDatasetAsync<WorkstreamInteractionsResponse>(
            config,
            pat,
            "interactions",
            workstreamId,
            cancellationToken).ConfigureAwait(false);
        payload.NormalizeAliases();
        return payload;
    }

    /// <summary>
    /// Fetches workstream participants using PAT authorization.
    /// </summary>
    public static async Task<WorkstreamParticipantsResponse> FetchWorkstreamParticipantsAsync(
        WorkstreamDataConfig config,
        string pat,
        string? workstreamId = null,
        CancellationToken cancellationToken = default)
    {
        var payload = await FetchWorkstreamDatasetAsync<WorkstreamParticipantsResponse>(
            config,
            pat,
            "participants",
            workstreamId,
            cancellationToken).ConfigureAwait(false);
        payload.NormalizeAliases();
        return payload;
    }

    /// <summary>
    /// Decodes base64 payload strings for compatibility with payloadData fields.
    /// </summary>
    public static byte[] DecodePayloadBase64(string payloadData)
        => SdkModelHelpers.DecodePayloadBase64(payloadData);

    private static async Task<T> FetchWorkstreamDatasetAsync<T>(
        WorkstreamDataConfig config,
        string pat,
        string resource,
        string? workstreamId,
        CancellationToken cancellationToken)
        where T : class, new()
    {
        var (baseUri, httpClient, ownsClient) = NormalizeWorkstreamConfig(config);
        try
        {
            var target = ResolveWorkstreamIdFromPat(pat, workstreamId);
            using var response = await SendJsonAsync(
                httpClient,
                baseUri,
                HttpMethod.Get,
                $"v1/workstreams/{Uri.EscapeDataString(target)}/{resource}",
                pat.Trim(),
                null,
                cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
            }

            return await response.Content.ReadFromJsonAsync<T>(SerializerOptions, cancellationToken)
                .ConfigureAwait(false)
                ?? new T();
        }
        finally
        {
            if (ownsClient)
            {
                httpClient.Dispose();
            }
        }
    }

    private static string ResolveWorkstreamIdFromPat(string pat, string? overrideWorkstreamId)
    {
        if (string.IsNullOrWhiteSpace(pat))
        {
            throw new ValidationException("pat is required");
        }

        var resolved = SdkModelHelpers.Coalesce(overrideWorkstreamId, DecodedClaims.Decode(pat).WorkstreamId);
        if (string.IsNullOrWhiteSpace(resolved))
        {
            throw new ValidationException(
                "workstream ID is required: token not scoped to a workstream and no override provided");
        }

        return resolved;
    }

    private static (Uri BaseUri, HttpClient HttpClient, bool OwnsHttpClient) NormalizeClientApiConfig(ClientApiConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var baseUri = EnsureClientApiBaseUri(config.BaseUri);
        if (config.HttpClient is null)
        {
            var client = new HttpClient
            {
                BaseAddress = baseUri,
                Timeout = TimeSpan.FromSeconds(30)
            };
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return (baseUri, client, true);
        }

        if (config.HttpClient.BaseAddress is null)
        {
            config.HttpClient.BaseAddress = baseUri;
        }

        return (baseUri, config.HttpClient, false);
    }

    private static (Uri BaseUri, HttpClient HttpClient, bool OwnsHttpClient) NormalizeWorkstreamConfig(WorkstreamDataConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var baseUri = EnsureClientApiBaseUri(config.BaseUri);
        if (config.HttpClient is null)
        {
            var client = new HttpClient
            {
                BaseAddress = baseUri,
                Timeout = TimeSpan.FromSeconds(30)
            };
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return (baseUri, client, true);
        }

        if (config.HttpClient.BaseAddress is null)
        {
            config.HttpClient.BaseAddress = baseUri;
        }

        return (baseUri, config.HttpClient, false);
    }

    private static Uri EnsureClientApiBaseUri(Uri? baseUri)
    {
        var resolved = (baseUri ?? OperonConfig.DefaultBaseUri).EnsureTrailingSlash();
        if (!resolved.IsAbsoluteUri)
        {
            throw new ValidationException("baseUri must be absolute");
        }

        return resolved;
    }

    private static async Task<HttpResponseMessage> SendJsonAsync(
        HttpClient httpClient,
        Uri baseUri,
        HttpMethod method,
        string relativePath,
        string pat,
        object? payload,
        CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(method, new Uri(baseUri, relativePath));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pat);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (payload is not null)
        {
            request.Content = JsonContent.Create(payload, options: SerializerOptions);
        }

        try
        {
            return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            request.Dispose();
            throw new TransportException($"Failed to call {relativePath}", ex);
        }
    }

    private static string? TrimOrNull(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record SelfSignResponse
    {
        public Signature? Signature { get; init; }
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
}
