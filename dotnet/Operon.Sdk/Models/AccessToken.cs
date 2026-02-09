using System;

namespace Operon.Sdk.Models;

/// <summary>
/// Represents an OAuth access token issued for an Operon client.
/// </summary>
public sealed class AccessToken
{
    private string? _workstreamId;
    private string? _channelId;

    /// <summary>
    /// Raw JWT token value used for authorization headers.
    /// </summary>
    public required string Value { get; init; } = string.Empty;

    /// <summary>
    /// UTC timestamp when the token expires.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// DID associated with the authenticated participant, when present.
    /// </summary>
    public string? ParticipantDid { get; init; }

    /// <summary>
    /// Workstream identifier the token is scoped to, if applicable.
    /// </summary>
    public string? WorkstreamId
    {
        get => string.IsNullOrWhiteSpace(_workstreamId) ? null : _workstreamId;
        init
        {
            _workstreamId = value;
            if (string.IsNullOrWhiteSpace(_channelId))
            {
                _channelId = value;
            }
        }
    }

    /// <summary>
    /// Legacy channel alias for compatibility.
    /// </summary>
    public string? ChannelId
    {
        get => string.IsNullOrWhiteSpace(_channelId) ? _workstreamId : _channelId;
        init
        {
            _channelId = value;
            if (string.IsNullOrWhiteSpace(_workstreamId))
            {
                _workstreamId = value;
            }
        }
    }

    /// <summary>
    /// Customer identifier linked to the token, when available.
    /// </summary>
    public string? CustomerId { get; init; }

    /// <summary>
    /// Workspace identifier linked to the token, when available.
    /// </summary>
    public string? WorkspaceId { get; init; }

    /// <summary>
    /// Email address associated with the authenticated user.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Display name associated with the authenticated user.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// Tenant identifiers granted to the token.
    /// </summary>
    public string[] TenantIds { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Roles assigned to the authenticated principal.
    /// </summary>
    public string[] Roles { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Member identifier embedded in the token, if available.
    /// </summary>
    public string? MemberId { get; init; }

    /// <summary>
    /// Session identifier embedded in the token, if available.
    /// </summary>
    public string? SessionId { get; init; }

    /// <summary>
    /// Organization identifier embedded in the token, if available.
    /// </summary>
    public string? OrgId { get; init; }

    /// <summary>
    /// Participant identifier embedded in the token.
    /// </summary>
    public string? ParticipantId { get; init; }

    /// <summary>
    /// OAuth client identifier embedded in the token.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// Authorized party claim (`azp`) embedded in the token.
    /// </summary>
    public string? AuthorizedParty { get; init; }

    /// <summary>
    /// Expiration claim from the token payload (unix seconds).
    /// </summary>
    public long ExpiresAtUnix { get; init; }
}
