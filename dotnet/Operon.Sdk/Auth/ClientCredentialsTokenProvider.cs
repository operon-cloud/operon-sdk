using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Errors;
using Operon.Sdk.Internal;
using Operon.Sdk.Models;

namespace Operon.Sdk.Auth;

/// <summary>
/// Defines a provider capable of returning OAuth access tokens for Operon APIs.
/// </summary>
public interface ITokenProvider
{
    Task<AccessToken> GetTokenAsync(CancellationToken cancellationToken);
    void Clear();
    Task<AccessToken> ForceRefreshAsync(CancellationToken cancellationToken);
}

/// <summary>
/// OAuth2 client credentials token provider with in-memory caching.
/// </summary>
public sealed class ClientCredentialsTokenProvider : ITokenProvider
{
    private readonly OperonConfig _config;
    private readonly HttpClient _httpClient;
    private readonly object _gate = new();
    private AccessToken? _cachedToken;

    public ClientCredentialsTokenProvider(OperonConfig config, HttpClient httpClient)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    public async Task<AccessToken> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (_cachedToken is { } cached && cached.ExpiresAt - _config.TokenLeeway > DateTimeOffset.UtcNow)
        {
            return cached;
        }

        return await FetchFreshTokenAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Clear()
    {
        lock (_gate)
        {
            _cachedToken = null;
        }
    }

    public Task<AccessToken> ForceRefreshAsync(CancellationToken cancellationToken)
        => FetchFreshTokenAsync(cancellationToken);

    private async Task<AccessToken> FetchFreshTokenAsync(CancellationToken cancellationToken)
    {
        using var request = BuildTokenRequest();
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await SdkModelHelpers.DecodeApiErrorAsync(response).ConfigureAwait(false);
        }

        var payload = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? throw new OperonSdkException("Token response payload was empty");

        if (string.IsNullOrWhiteSpace(payload.AccessToken))
        {
            throw new OperonSdkException("Token response missing access_token");
        }

        var expiresIn = payload.ExpiresIn <= 0 ? 60 : payload.ExpiresIn;
        var expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn);

        var claims = DecodedClaims.Decode(payload.AccessToken);

        var token = new AccessToken
        {
            Value = payload.AccessToken,
            ExpiresAt = expiresAt,
            ParticipantDid = claims.ParticipantDid,
            WorkstreamId = claims.WorkstreamId,
            ChannelId = claims.WorkstreamId,
            CustomerId = claims.CustomerId,
            WorkspaceId = claims.WorkspaceId,
            Email = claims.Email,
            Name = claims.Name,
            TenantIds = claims.TenantIds is string[] tenantIds ? tenantIds : new List<string>(claims.TenantIds).ToArray(),
            Roles = claims.Roles is string[] roles ? roles : new List<string>(claims.Roles).ToArray(),
            MemberId = claims.MemberId,
            SessionId = claims.SessionId,
            OrgId = claims.OrgId,
            ParticipantId = claims.ParticipantId,
            ClientId = claims.ClientId,
            AuthorizedParty = claims.AuthorizedParty,
            ExpiresAtUnix = claims.ExpiresAtUnix
        };

        lock (_gate)
        {
            _cachedToken = token;
        }

        return token;
    }

    private HttpRequestMessage BuildTokenRequest()
    {
        if (_config.TokenUri.AbsolutePath.Contains("/v1/session/m2m", StringComparison.OrdinalIgnoreCase))
        {
            var body = new
            {
                client_id = _config.ClientId,
                client_secret = _config.ClientSecret,
                grant_type = "client_credentials",
                scope = _config.Scope,
                audience = _config.Audience
            };

            var request = new HttpRequestMessage(HttpMethod.Post, _config.TokenUri)
            {
                Content = JsonContent.Create(body)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            return request;
        }

        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "client_credentials")
        };

        if (!string.IsNullOrWhiteSpace(_config.Scope))
        {
            form.Add(new KeyValuePair<string, string>("scope", _config.Scope));
        }

        foreach (var audience in _config.Audience)
        {
            form.Add(new KeyValuePair<string, string>("audience", audience));
        }

        var basicCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_config.ClientId}:{_config.ClientSecret}"));
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, _config.TokenUri)
        {
            Content = new FormUrlEncodedContent(form)
        };
        requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicCredentials);
        return requestMessage;
    }

    private sealed record TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; init; } = string.Empty;

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; init; } = 60;

        [JsonPropertyName("token_type")]
        public string TokenType { get; init; } = "Bearer";

        [JsonPropertyName("scope")]
        public string? Scope { get; init; }
    }
}
