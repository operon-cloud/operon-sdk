using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Operon.Sdk.Errors;
using Operon.Sdk.Models;

namespace Operon.Sdk.Auth;

internal interface ITokenProvider
{
    Task<AccessToken> GetTokenAsync(CancellationToken cancellationToken);
    void Clear();
}

internal sealed class ClientCredentialsTokenProvider : ITokenProvider
{
    private readonly OperonConfig _config;
    private readonly HttpClient _httpClient;
    private AccessToken? _cachedToken;
    private readonly object _gate = new();

    public ClientCredentialsTokenProvider(OperonConfig config, HttpClient httpClient)
    {
        _config = config;
        _httpClient = httpClient;
    }

    public async Task<AccessToken> GetTokenAsync(CancellationToken cancellationToken)
    {
        if (_cachedToken is { } cached && cached.ExpiresAt - _config.TokenLeeway > DateTimeOffset.UtcNow)
        {
            return cached;
        }

        return await FetchFreshTokenAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Clear() => _cachedToken = null;

    private async Task<AccessToken> FetchFreshTokenAsync(CancellationToken cancellationToken)
    {
        using var request = BuildTokenRequest();
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await DecodeErrorAsync(response).ConfigureAwait(false);
        }

        var payload = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken).ConfigureAwait(false)
            ?? throw new OperonSdkException("Token response payload was empty");

        if (string.IsNullOrWhiteSpace(payload.AccessToken))
        {
            throw new OperonSdkException("Token response missing access_token");
        }

        var expires = DateTimeOffset.UtcNow.AddSeconds(payload.ExpiresIn <= 0 ? 60 : payload.ExpiresIn);
        var claims = ExtractClaims(payload.AccessToken!);

        var token = new AccessToken
        {
            Value = payload.AccessToken!,
            ExpiresAt = expires,
            ParticipantDid = claims.TryGetValue("participant_did", out var did) ? did : null,
            ChannelId = claims.TryGetValue("channel_id", out var channelId) ? channelId : null,
            CustomerId = claims.TryGetValue("customer_id", out var customerId) ? customerId : null,
            WorkspaceId = claims.TryGetValue("workspace_id", out var workspaceId) ? workspaceId : null,
            Email = claims.TryGetValue("email", out var email) ? email : null,
            Name = claims.TryGetValue("name", out var name) ? name : null,
            MemberId = claims.TryGetValue("member_id", out var member) ? member : null,
            SessionId = claims.TryGetValue("session_id", out var session) ? session : null,
            OrgId = claims.TryGetValue("org_id", out var org) ? org : null,
            TenantIds = claims.TryGetValue("tenant_ids", out var tenantCsv) ? tenantCsv?.Split(',') : Array.Empty<string>(),
            Roles = claims.TryGetValue("roles", out var rolesCsv) ? rolesCsv?.Split(',') : Array.Empty<string>()
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
        else
        {
            var form = new List<KeyValuePair<string, string>>
            {
                new("grant_type", "client_credentials")
            };
            if (!string.IsNullOrWhiteSpace(_config.Scope))
            {
                form.Add(new("scope", _config.Scope!));
            }
            foreach (var audience in _config.Audience)
            {
                form.Add(new("audience", audience));
            }

            var request = new HttpRequestMessage(HttpMethod.Post, _config.TokenUri)
            {
                Content = new FormUrlEncodedContent(form)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_config.ClientId}:{_config.ClientSecret}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            return request;
        }
    }

    private static async Task<OperonApiException> DecodeErrorAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Deserialize<JsonElement>(body);
            var message = json.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? response.ReasonPhrase ?? "" : response.ReasonPhrase ?? string.Empty;
            var code = json.TryGetProperty("code", out var codeProp) ? codeProp.GetString() : null;
            return new OperonApiException(string.IsNullOrWhiteSpace(message) ? response.StatusCode.ToString() : message, response.StatusCode, code, json);
        }
        catch
        {
            return new OperonApiException(string.IsNullOrWhiteSpace(body) ? response.StatusCode.ToString() : body, response.StatusCode);
        }
    }

    private static Dictionary<string, string?> ExtractClaims(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2)
        {
            return new Dictionary<string, string?>();
        }

        var payloadSegment = parts[1];
        var buffer = Convert.FromBase64String(ToBase64(payloadSegment));
        var json = JsonDocument.Parse(buffer);
        var result = new Dictionary<string, string?>();
        foreach (var property in json.RootElement.EnumerateObject())
        {
            if (property.Value.ValueKind == JsonValueKind.String)
            {
                result[property.Name] = property.Value.GetString();
            }
        }
        return result;
    }

    private static string ToBase64(string segment)
    {
        var builder = segment.Replace('-', '+').Replace('_', '/');
        return builder.PadRight(builder.Length + (4 - builder.Length % 4) % 4, '=');
    }

    private sealed record TokenResponse
    {
        public string? AccessToken { get; init; }
            = string.Empty;

        public int ExpiresIn { get; init; }
            = 60;

        public string TokenType { get; init; } = "Bearer";

        public string? Scope { get; init; } = string.Empty;
    }
}
