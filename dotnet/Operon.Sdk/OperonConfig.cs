using System;
using System.Collections.Generic;
using Operon.Sdk.Internal;

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
    public OperonConfig(
        string clientId,
        string clientSecret,
        Uri? baseUri = null,
        Uri? tokenUri = null,
        string? scope = null,
        IEnumerable<string>? audience = null,
        TimeSpan? httpTimeout = null,
        TimeSpan? tokenLeeway = null,
        bool disableSelfSign = false,
        string? signingAlgorithm = null,
        TimeSpan? sessionHeartbeatInterval = null,
        TimeSpan? sessionHeartbeatTimeout = null,
        Uri? sessionHeartbeatUri = null)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException("Client ID is required", nameof(clientId));
        }

        if (string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new ArgumentException("Client secret is required", nameof(clientSecret));
        }

        ClientId = clientId.Trim();
        ClientSecret = clientSecret.Trim();

        BaseUri = EnsureAbsoluteUri(baseUri ?? DefaultBaseUri, nameof(baseUri)).EnsureTrailingSlash();
        TokenUri = EnsureAbsoluteUri(tokenUri ?? DefaultTokenUri, nameof(tokenUri));

        Scope = string.IsNullOrWhiteSpace(scope) ? null : scope.Trim();
        Audience = audience is null ? Array.Empty<string>() : new List<string>(TrimAudience(audience));
        HttpTimeout = httpTimeout is { } timeout && timeout > TimeSpan.Zero ? timeout : TimeSpan.FromSeconds(30);
        TokenLeeway = tokenLeeway is { } leeway && leeway > TimeSpan.Zero ? leeway : TimeSpan.FromSeconds(30);
        DisableSelfSign = disableSelfSign;

        var canonicalAlgorithm = SdkModelHelpers.CanonicalSigningAlgorithm(
            string.IsNullOrWhiteSpace(signingAlgorithm) ? SdkModelHelpers.AlgorithmEd25519 : signingAlgorithm);
        if (canonicalAlgorithm is null)
        {
            throw new ArgumentException($"Unsupported signing algorithm '{signingAlgorithm}'", nameof(signingAlgorithm));
        }

        SigningAlgorithm = canonicalAlgorithm;

        if (sessionHeartbeatInterval is { } interval && interval < TimeSpan.Zero)
        {
            throw new ArgumentException("Session heartbeat interval cannot be negative", nameof(sessionHeartbeatInterval));
        }

        SessionHeartbeatInterval = sessionHeartbeatInterval is { } validInterval && validInterval > TimeSpan.Zero
            ? validInterval
            : TimeSpan.Zero;

        SessionHeartbeatTimeout = SessionHeartbeatInterval > TimeSpan.Zero
            ? (sessionHeartbeatTimeout is { } validTimeout && validTimeout > TimeSpan.Zero
                ? validTimeout
                : TimeSpan.FromSeconds(10))
            : TimeSpan.Zero;

        if (SessionHeartbeatInterval > TimeSpan.Zero)
        {
            SessionHeartbeatUri = EnsureAbsoluteUri(
                sessionHeartbeatUri ?? new Uri(BaseUri, "v1/session/heartbeat"),
                nameof(sessionHeartbeatUri));
        }
        else
        {
            SessionHeartbeatUri = null;
        }
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

    /// <summary>Default signing algorithm for automatic self-sign operations.</summary>
    public string SigningAlgorithm { get; }

    /// <summary>Interval for the optional session heartbeat loop (zero to disable).</summary>
    public TimeSpan SessionHeartbeatInterval { get; }

    /// <summary>Timeout applied to each heartbeat call.</summary>
    public TimeSpan SessionHeartbeatTimeout { get; }

    /// <summary>Absolute URI for the heartbeat endpoint, or null when disabled.</summary>
    public Uri? SessionHeartbeatUri { get; }

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

    private static Uri EnsureAbsoluteUri(Uri uri, string parameterName)
    {
        if (!uri.IsAbsoluteUri)
        {
            throw new ArgumentException("URI must be absolute", parameterName);
        }

        return uri;
    }
}

internal static class UriExtensions
{
    public static Uri EnsureTrailingSlash(this Uri uri)
    {
        if (!uri.AbsoluteUri.EndsWith("/", StringComparison.Ordinal))
        {
            return new Uri(uri.AbsoluteUri + "/", UriKind.Absolute);
        }

        return uri;
    }
}
