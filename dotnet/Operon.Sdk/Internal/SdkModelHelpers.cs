using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Operon.Sdk.Errors;
using Operon.Sdk.Models;

namespace Operon.Sdk.Internal;

internal static class SdkModelHelpers
{
    public const string AlgorithmEd25519 = "EdDSA";
    public const string AlgorithmEs256 = "ES256";
    public const string AlgorithmEs256k = "ES256K";

    public const string RoiClassificationBaseline = "baseline";
    public const string RoiClassificationIncrement = "increment";
    public const string RoiClassificationSavings = "savings";

    public const string HeaderOperonDid = "X-Operon-DID";
    public const string HeaderOperonPayloadHash = "X-Operon-Payload-Hash";
    public const string HeaderOperonSignature = "X-Operon-Signature";
    public const string HeaderOperonSignatureKey = "X-Operon-Signature-KeyId";
    public const string HeaderOperonSignatureAlgo = "X-Operon-Signature-Alg";

    private static readonly string[] SigningAlgorithms =
    [
        AlgorithmEd25519,
        AlgorithmEs256,
        AlgorithmEs256k
    ];

    private static readonly string[] RoiClassifications =
    [
        RoiClassificationBaseline,
        RoiClassificationIncrement,
        RoiClassificationSavings
    ];

    public static string? CanonicalSigningAlgorithm(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        return SigningAlgorithms.FirstOrDefault(candidate =>
            string.Equals(candidate, trimmed, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsRoiClassification(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return RoiClassifications.Any(candidate =>
            string.Equals(candidate, value.Trim(), StringComparison.Ordinal));
    }

    public static string ComputeSha256Base64Url(byte[] payload)
    {
        var hash = SHA256.HashData(payload);
        return ToBase64Url(hash);
    }

    public static string ToBase64Url(byte[] payload)
    {
        return Convert.ToBase64String(payload)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static byte[] DecodeBase64Url(string segment)
    {
        var normalized = segment
            .Replace('-', '+')
            .Replace('_', '/');
        var padded = normalized.PadRight(normalized.Length + (4 - normalized.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }

    public static string? BuildKeyId(string? sourceDid)
    {
        if (string.IsNullOrWhiteSpace(sourceDid))
        {
            return null;
        }

        return $"{sourceDid.Trim()}#keys-1";
    }

    public static string? Coalesce(params string?[] values)
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

    public static string ResolvePayloadHash(TransactionRequest request)
    {
        if (request.PayloadBytes is { Length: > 0 } payload)
        {
            var computed = ComputeSha256Base64Url(payload);
            if (!string.IsNullOrWhiteSpace(request.PayloadHash)
                && !string.Equals(computed, request.PayloadHash.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                throw new ValidationException(
                    $"provided payload hash does not match payload content: expected {computed} got {request.PayloadHash}");
            }

            return computed;
        }

        if (string.IsNullOrWhiteSpace(request.PayloadHash))
        {
            throw new ValidationException("payload bytes or payload hash is required");
        }

        var payloadHash = request.PayloadHash.Trim();
        ValidatePayloadHashFormat(payloadHash);
        return payloadHash;
    }

    public static void ValidatePayloadHashFormat(string payloadHash)
    {
        if (payloadHash.Length != 43)
        {
            throw new ValidationException($"payload hash must be 43 characters, got {payloadHash.Length}");
        }

        try
        {
            _ = DecodeBase64Url(payloadHash);
        }
        catch (Exception ex)
        {
            throw new ValidationException($"payload hash must be base64url encoded: {ex.Message}");
        }
    }

    public static void ValidateTransactionForSubmit(TransactionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CorrelationId))
        {
            throw new ValidationException("CorrelationID is required");
        }

        if (string.IsNullOrWhiteSpace(request.WorkstreamId))
        {
            throw new ValidationException("WorkstreamID is required");
        }

        if (string.IsNullOrWhiteSpace(request.InteractionId))
        {
            throw new ValidationException("InteractionID is required");
        }

        if (string.IsNullOrWhiteSpace(request.SourceDid))
        {
            throw new ValidationException("SourceDID is required");
        }

        if (!request.SourceDid.Trim().StartsWith("did:", StringComparison.OrdinalIgnoreCase))
        {
            throw new ValidationException("SourceDID must be a valid DID");
        }

        if (string.IsNullOrWhiteSpace(request.TargetDid))
        {
            throw new ValidationException("TargetDID is required");
        }

        if (!request.TargetDid.Trim().StartsWith("did:", StringComparison.OrdinalIgnoreCase))
        {
            throw new ValidationException("TargetDID must be a valid DID");
        }

        if (request.PayloadBytes is not { Length: > 0 } && string.IsNullOrWhiteSpace(request.PayloadHash))
        {
            throw new ValidationException("payload bytes or payload hash is required");
        }

        if (string.IsNullOrWhiteSpace(request.Signature.Algorithm))
        {
            throw new ValidationException("Signature algorithm is required");
        }

        if (string.IsNullOrWhiteSpace(request.Signature.Value))
        {
            throw new ValidationException("Signature value is required");
        }

        if (!string.IsNullOrWhiteSpace(request.RoiClassification) && !IsRoiClassification(request.RoiClassification))
        {
            throw new ValidationException("ROIClassification must be one of baseline, increment, savings");
        }

        if (request.RoiBaseCost is < 0)
        {
            throw new ValidationException("ROIBaseCost cannot be negative");
        }

        if (request.RoiBaseTime is < 0)
        {
            throw new ValidationException("ROIBaseTime cannot be negative");
        }

        if (request.RoiCostSaving is < 0)
        {
            throw new ValidationException("ROICostSaving cannot be negative");
        }

        if (request.RoiTimeSaving is < 0)
        {
            throw new ValidationException("ROITimeSaving cannot be negative");
        }

        if (string.IsNullOrWhiteSpace(request.ActorExternalSource)
            && (!string.IsNullOrWhiteSpace(request.ActorExternalId)
                || !string.IsNullOrWhiteSpace(request.ActorExternalDisplayName)))
        {
            throw new ValidationException(
                "ActorExternalSource is required when ActorExternalID or ActorExternalDisplayName is set");
        }

        if (string.IsNullOrWhiteSpace(request.AssigneeExternalSource)
            && (!string.IsNullOrWhiteSpace(request.AssigneeExternalId)
                || !string.IsNullOrWhiteSpace(request.AssigneeExternalDisplayName)))
        {
            throw new ValidationException(
                "AssigneeExternalSource is required when AssigneeExternalID or AssigneeExternalDisplayName is set");
        }
    }

    public static Dictionary<string, string> SanitizeOperonHeaders(IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        var required = new[]
        {
            HeaderOperonDid,
            HeaderOperonPayloadHash,
            HeaderOperonSignature,
            HeaderOperonSignatureKey,
            HeaderOperonSignatureAlgo
        };

        var sanitized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in required)
        {
            if (!headers.TryGetValue(header, out var value) || string.IsNullOrWhiteSpace(value))
            {
                throw new ValidationException($"header {header} is required");
            }

            sanitized[header] = value.Trim();
        }

        return sanitized;
    }

    public static byte[] DecodePayloadBase64(string payloadData)
    {
        if (string.IsNullOrWhiteSpace(payloadData))
        {
            return Array.Empty<byte>();
        }

        try
        {
            return Convert.FromBase64String(payloadData.Trim());
        }
        catch (Exception ex)
        {
            throw new ValidationException($"payloadData must be valid base64: {ex.Message}");
        }
    }

    public static async Task<OperonApiException> DecodeApiErrorAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Deserialize<JsonElement>(body);
            var message = json.TryGetProperty("message", out var msg)
                ? msg.GetString() ?? response.ReasonPhrase ?? string.Empty
                : response.ReasonPhrase ?? string.Empty;
            var code = json.TryGetProperty("code", out var codeProp) ? codeProp.GetString() : null;
            return new OperonApiException(
                string.IsNullOrWhiteSpace(message) ? response.StatusCode.ToString() : message,
                response.StatusCode,
                code,
                json);
        }
        catch
        {
            return new OperonApiException(
                string.IsNullOrWhiteSpace(body) ? response.StatusCode.ToString() : body,
                response.StatusCode);
        }
    }
}
