using System;

namespace Operon.Sdk.Models;

internal sealed class AccessToken
{
    public required string Value { get; init; }
        = string.Empty;

    public required DateTimeOffset ExpiresAt { get; init; }
        = DateTimeOffset.UtcNow;

    public string? ParticipantDid { get; init; }
        = string.Empty;

    public string? ChannelId { get; init; }
        = string.Empty;

    public string? CustomerId { get; init; }
        = string.Empty;

    public string? WorkspaceId { get; init; }
        = string.Empty;

    public string? Email { get; init; }
        = string.Empty;

    public string? Name { get; init; }
        = string.Empty;

    public string[]? TenantIds { get; init; }
        = Array.Empty<string>();

    public string[]? Roles { get; init; }
        = Array.Empty<string>();

    public string? MemberId { get; init; }
        = string.Empty;

    public string? SessionId { get; init; }
        = string.Empty;

    public string? OrgId { get; init; }
        = string.Empty;
}
