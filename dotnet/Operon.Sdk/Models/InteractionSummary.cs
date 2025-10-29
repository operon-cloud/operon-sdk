namespace Operon.Sdk.Models;

/// <summary>
/// Lightweight description of an interaction known to Operon.
/// </summary>
public sealed class InteractionSummary
{
    /// <summary>
    /// Unique interaction identifier.
    /// </summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Channel identifier the interaction belongs to.
    /// </summary>
    public string ChannelId { get; init; } = string.Empty;

    /// <summary>
    /// Internal participant identifier for the source.
    /// </summary>
    public string SourceParticipantId { get; init; } = string.Empty;

    /// <summary>
    /// Internal participant identifier for the target.
    /// </summary>
    public string TargetParticipantId { get; init; } = string.Empty;

    /// <summary>
    /// Source DID, when resolved.
    /// </summary>
    public string? SourceDid { get; set; }
        = string.Empty;

    /// <summary>
    /// Target DID, when resolved.
    /// </summary>
    public string? TargetDid { get; set; }
        = string.Empty;
}
