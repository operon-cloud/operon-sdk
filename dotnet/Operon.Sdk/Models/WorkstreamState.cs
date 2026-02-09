namespace Operon.Sdk.Models;

/// <summary>
/// Workstream state definition.
/// </summary>
public sealed class WorkstreamState
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Status { get; set; }
}
