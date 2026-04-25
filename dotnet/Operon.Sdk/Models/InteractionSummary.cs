namespace Operon.Sdk.Models;

/// <summary>
/// Lightweight description of an interaction known to Operon.
/// </summary>
public sealed class InteractionSummary
{
    private string? _workstreamId;
    private string? _channelId;

    public string Id { get; set; } = string.Empty;

    public string? WorkstreamId
    {
        get => string.IsNullOrWhiteSpace(_workstreamId) ? null : _workstreamId;
        set
        {
            _workstreamId = value;
            if (string.IsNullOrWhiteSpace(_channelId))
            {
                _channelId = value;
            }
        }
    }

    /// <summary>
    /// Legacy channel alias for backward compatibility.
    /// </summary>
    public string? ChannelId
    {
        get => string.IsNullOrWhiteSpace(_channelId) ? _workstreamId : _channelId;
        set
        {
            _channelId = value;
            if (string.IsNullOrWhiteSpace(_workstreamId))
            {
                _workstreamId = value;
            }
        }
    }

    public string? WorkstreamName { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public string? Status { get; set; }
    public string SourceParticipantId { get; set; } = string.Empty;
    public string TargetParticipantId { get; set; } = string.Empty;
    public string? SourceDid { get; set; }
    public string? TargetDid { get; set; }
    public string? Type { get; set; }
    public string? Actor { get; set; }
    public string[]? States { get; set; }
    public string? FromStateId { get; set; }
    public string? FromStateLabel { get; set; }
    public string? ToStateId { get; set; }
    public string? ToStateLabel { get; set; }
    public string? RoiClassification { get; set; }
    public int? RoiCost { get; set; }
    public int? RoiTime { get; set; }

    internal void NormalizeAliases()
    {
        var effective = string.IsNullOrWhiteSpace(WorkstreamId) ? ChannelId : WorkstreamId;
        WorkstreamId = effective;
        ChannelId = effective;
    }
}
