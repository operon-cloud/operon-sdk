using System;
using System.Collections.Generic;

namespace Operon.Sdk;

/// <summary>
/// Provides configuration values for the Operon SDK.
/// </summary>
public sealed class OperonConfig
{
    /// <summary>
    /// Default API base URI used when none is supplied.
    /// </summary>
    public static readonly Uri DefaultBaseUri = new("https://api.operon.cloud/client-api/");

    /// <summary>
    /// Default OAuth2 token endpoint used for client credential flows.
    /// </summary>
    public static readonly Uri DefaultTokenUri = new("https://auth.operon.cloud/oauth2/token");

    /// <summary>
    /// Initializes a new instance of the <see cref="OperonConfig"/> class.
    /// </summary>
    /// <param name="clientId">The issued client identifier.</param>
    /// <param name="clientSecret">The issued client secret.</param>
    /// <param name="baseUri">Optional override for the Operon API base URI.</param>
    /// <param name="tokenUri">Optional override for the token endpoint URI.</param>
    /// <param name="scope">Optional OAuth scope request.</param>
    /// <param name="audience">Optional OAuth audience values.</param>
    /// <param name="httpTimeout">Optional HTTP timeout for outbound calls.</param>
    /// <param name="tokenLeeway">Time window before expiry to refresh cached tokens.</param>
    /// <param name="disableSelfSign">When true, disables automatic request signing.</param>
    public OperonConfig(
        string clientId,
        string clientSecret,
        Uri? baseUri = null,
        Uri? tokenUri = null,
        string? scope = null,
        IEnumerable<string>? audience = null,
        TimeSpan? httpTimeout = null,
        TimeSpan? tokenLeeway = null,
        bool disableSelfSign = false)
    {
        ClientId = string.IsNullOrWhiteSpace(clientId)
            ? throw new ArgumentException("Client ID is required", nameof(clientId))
            : clientId.Trim();
        ClientSecret = string.IsNullOrWhiteSpace(clientSecret)
            ? throw new ArgumentException("Client secret is required", nameof(clientSecret))
            : clientSecret.Trim();

        BaseUri = (baseUri ?? DefaultBaseUri).EnsureTrailingSlash();
        TokenUri = tokenUri ?? DefaultTokenUri;
        Scope = string.IsNullOrWhiteSpace(scope) ? null : scope.Trim();
        Audience = audience is null ? Array.Empty<string>() : new List<string>(TrimAudience(audience));
        HttpTimeout = httpTimeout is { } timeout && timeout > TimeSpan.Zero ? timeout : TimeSpan.FromSeconds(30);
        TokenLeeway = tokenLeeway is { } leeway && leeway > TimeSpan.Zero ? leeway : TimeSpan.FromSeconds(30);
        DisableSelfSign = disableSelfSign;
    }

    /// <summary>Primary API base URL, ending with a slash.</summary>
    public Uri BaseUri { get; }

    /// <summary>OAuth2 token endpoint used for client credential flows.</summary>
    public Uri TokenUri { get; }

    /// <summary>Issued client identifier.</summary>
    public string ClientId { get; }

    /// <summary>Issued client secret.</summary>
    public string ClientSecret { get; }

    /// <summary>Optional OAuth scope override.</summary>
    public string? Scope { get; }

    /// <summary>Optional OAuth audience list.</summary>
    public IReadOnlyList<string> Audience { get; }

    /// <summary>Timeout applied to outbound HTTP calls (defaults to 30s).</summary>
    public TimeSpan HttpTimeout { get; }

    /// <summary>Duration before token expiry when the SDK proactively refreshes credentials.</summary>
    public TimeSpan TokenLeeway { get; }

    /// <summary>When true, callers must provide signatures manually (no self-sign API usage).</summary>
    public bool DisableSelfSign { get; }

    private static IEnumerable<string> TrimAudience(IEnumerable<string> audience)
    {
        foreach (var value in audience)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                yield return value.Trim();
            }
        }
    }
}

/// <summary>
/// Extension helpers for working with <see cref="Uri"/> values.
/// </summary>
internal static class UriExtensions
{
    /// <summary>
    /// Ensures the supplied URI ends with a trailing slash.
    /// </summary>
    /// <param name="uri">The URI to normalize.</param>
    /// <returns>A URI guaranteed to contain a trailing slash.</returns>
    public static Uri EnsureTrailingSlash(this Uri uri)
    {
        if (!uri.AbsoluteUri.EndsWith("/", StringComparison.Ordinal))
        {
            return new Uri(uri.AbsoluteUri + "/");
        }
        return uri;
    }
}
