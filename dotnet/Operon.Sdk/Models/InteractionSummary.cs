namespace Operon.Sdk.Models;

/// <summary>
/// Lightweight description of an interaction known to Operon.
/// </summary>
public sealed class InteractionSummary
{
    public string Id { get; init; } = string.Empty;
    public string ChannelId { get; init; } = string.Empty;
    public string SourceParticipantId { get; init; } = string.Empty;
    public string TargetParticipantId { get; init; } = string.Empty;
    public string? SourceDid { get; set; }
        = string.Empty;
    public string? TargetDid { get; set; }
        = string.Empty;
}
