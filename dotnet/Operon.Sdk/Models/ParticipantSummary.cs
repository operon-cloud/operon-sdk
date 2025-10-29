namespace Operon.Sdk.Models;

/// <summary>
/// Minimal participant record containing ID and DID mapping.
/// </summary>
public sealed class ParticipantSummary
{
    public string Id { get; init; } = string.Empty;
    public string Did { get; init; } = string.Empty;
}
