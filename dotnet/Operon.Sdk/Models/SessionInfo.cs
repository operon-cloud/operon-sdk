using System;
using System.Collections.Generic;

namespace Operon.Sdk.Models;

/// <summary>
/// Session metadata derived from PAT validation and token claims.
/// </summary>
public sealed class SessionInfo
{
    public string UserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string CustomerId { get; set; } = string.Empty;
    public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, object?> FeatureFlags { get; set; } = new Dictionary<string, object?>();
    public string WorkstreamId { get; set; } = string.Empty;
    public string ChannelId { get; set; } = string.Empty;
    public string WorkspaceId { get; set; } = string.Empty;
    public string ParticipantDid { get; set; } = string.Empty;
    public string ParticipantId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string SessionId { get; set; } = string.Empty;
    public DateTimeOffset? ExpiresAt { get; set; }
    public int ExpiresInSeconds { get; set; }
}
