namespace Operon.Sdk.Models;

/// <summary>
/// Minimal participant record containing ID and DID mapping.
/// </summary>
public sealed class ParticipantSummary
{
    /// <summary>
    /// Participant identifier referenced by interactions.
    /// </summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Decentralized identifier belonging to the participant.
    /// </summary>
    public string Did { get; init; } = string.Empty;
}
