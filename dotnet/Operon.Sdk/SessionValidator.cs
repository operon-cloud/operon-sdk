using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
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
/// PAT session validation helper.
/// </summary>
public static class SessionValidator
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Validates PAT session metadata via the client API.
    /// </summary>
    public static async Task<SessionInfo> ValidateSessionAsync(
        SessionValidationConfig config,
        string pat,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(pat))
        {
            throw new ValidationException("pat is required");
        }

        var normalized = NormalizeConfig(config);
        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(normalized.BaseUri, "v1/session/validate"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", pat.Trim());

            using var response = await normalized.HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
            }

            var payload = await response.Content.ReadFromJsonAsync<ValidationResponse>(SerializerOptions, cancellationToken)
                .ConfigureAwait(false)
                ?? new ValidationResponse();

            var claims = DecodedClaims.Decode(pat);
            var expiresAt = claims.ExpiresAtUnix > 0
                ? DateTimeOffset.FromUnixTimeSeconds(claims.ExpiresAtUnix)
                : (DateTimeOffset?)null;
            var expiresIn = expiresAt.HasValue
                ? Math.Max(0, (int)Math.Floor((expiresAt.Value - DateTimeOffset.UtcNow).TotalSeconds))
                : 0;

            var featureFlags = payload.FeatureFlags ?? new Dictionary<string, object?>();
            var roles = payload.Roles?.Where(role => !string.IsNullOrWhiteSpace(role)).Select(role => role.Trim()).ToArray()
                ?? Array.Empty<string>();

            return new SessionInfo
            {
                UserId = payload.UserId ?? string.Empty,
                Email = payload.Email ?? string.Empty,
                Name = payload.Name ?? string.Empty,
                CustomerId = payload.CustomerId ?? string.Empty,
                Roles = roles,
                FeatureFlags = featureFlags,
                WorkstreamId = claims.WorkstreamId ?? string.Empty,
                ChannelId = claims.WorkstreamId ?? string.Empty,
                WorkspaceId = claims.WorkspaceId ?? string.Empty,
                ParticipantDid = claims.ParticipantDid ?? string.Empty,
                ParticipantId = claims.ParticipantId ?? string.Empty,
                ClientId = SdkModelHelpers.Coalesce(claims.ClientId, claims.AuthorizedParty) ?? string.Empty,
                SessionId = claims.SessionId ?? string.Empty,
                ExpiresAt = expiresAt,
                ExpiresInSeconds = expiresIn
            };
        }
        finally
        {
            if (normalized.OwnsHttpClient)
            {
                normalized.HttpClient.Dispose();
            }
        }
    }

    private static (Uri BaseUri, HttpClient HttpClient, bool OwnsHttpClient) NormalizeConfig(SessionValidationConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var baseUri = (config.BaseUri ?? OperonConfig.DefaultBaseUri).EnsureTrailingSlash();
        if (!baseUri.IsAbsoluteUri)
        {
            throw new ValidationException("baseUri must be absolute");
        }

        if (config.HttpClient is null)
        {
            var client = new HttpClient
            {
                BaseAddress = baseUri,
                Timeout = TimeSpan.FromSeconds(30)
            };
            return (baseUri, client, true);
        }

        if (config.HttpClient.BaseAddress is null)
        {
            config.HttpClient.BaseAddress = baseUri;
        }

        return (baseUri, config.HttpClient, false);
    }

    private sealed record ValidationResponse
    {
        [JsonPropertyName("user_id")]
        public string? UserId { get; init; }

        [JsonPropertyName("email")]
        public string? Email { get; init; }

        [JsonPropertyName("name")]
        public string? Name { get; init; }

        [JsonPropertyName("customer_id")]
        public string? CustomerId { get; init; }

        [JsonPropertyName("roles")]
        public string[]? Roles { get; init; }

        [JsonPropertyName("feature_flags")]
        public Dictionary<string, object?>? FeatureFlags { get; init; }
    }
}
