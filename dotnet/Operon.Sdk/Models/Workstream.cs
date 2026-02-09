using System;

namespace Operon.Sdk.Models;

/// <summary>
/// Workstream configuration details.
/// </summary>
public sealed class Workstream
{
    public string Id { get; set; } = string.Empty;
    public DateTimeOffset? CreatedAt { get; set; }
    public DateTimeOffset? UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public int? Version { get; set; }
    public string? CustomerId { get; set; }
    public string? WorkspaceId { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public string? Mode { get; set; }
    public string? Type { get; set; }
    public string? Status { get; set; }
    public WorkstreamState[]? States { get; set; }
    public string? DefaultStateId { get; set; }
    public string[]? InteractionIds { get; set; }
    public string? HcsTestTopicId { get; set; }
    public string? HcsLiveTopicId { get; set; }
}
