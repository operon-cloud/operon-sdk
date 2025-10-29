using System;

namespace Operon.Sdk.Models;

/// <summary>
/// Represents an OAuth access token issued for an Operon client.
/// </summary>
public sealed class AccessToken
{
    /// <summary>
    /// Raw JWT token value used for authorization headers.
    /// </summary>
    public required string Value { get; init; }
        = string.Empty;

    /// <summary>
    /// UTC timestamp when the token expires.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
        = DateTimeOffset.UtcNow;

    /// <summary>
    /// DID associated with the authenticated participant, when present.
    /// </summary>
    public string? ParticipantDid { get; init; }
        = string.Empty;

    /// <summary>
    /// Channel identifier the token is scoped to, if applicable.
    /// </summary>
    public string? ChannelId { get; init; }
        = string.Empty;

    /// <summary>
    /// Customer identifier linked to the token, when available.
    /// </summary>
    public string? CustomerId { get; init; }
        = string.Empty;

    /// <summary>
    /// Workspace identifier linked to the token, when available.
    /// </summary>
    public string? WorkspaceId { get; init; }
        = string.Empty;

    /// <summary>
    /// Email address associated with the authenticated user.
    /// </summary>
    public string? Email { get; init; }
        = string.Empty;

    /// <summary>
    /// Display name associated with the authenticated user.
    /// </summary>
    public string? Name { get; init; }
        = string.Empty;

    /// <summary>
    /// Tenant identifiers granted to the token, when multi-tenant access is used.
    /// </summary>
    public string[]? TenantIds { get; init; }
        = Array.Empty<string>();

    /// <summary>
    /// Roles assigned to the authenticated principal.
    /// </summary>
    public string[]? Roles { get; init; }
        = Array.Empty<string>();

    /// <summary>
    /// Member identifier embedded in the token, if available.
    /// </summary>
    public string? MemberId { get; init; }
        = string.Empty;

    /// <summary>
    /// Session identifier embedded in the token, if available.
    /// </summary>
    public string? SessionId { get; init; }
        = string.Empty;

    /// <summary>
    /// Organization identifier embedded in the token, if available.
    /// </summary>
    public string? OrgId { get; init; }
        = string.Empty;
}
