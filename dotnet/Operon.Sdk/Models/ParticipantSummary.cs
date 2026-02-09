namespace Operon.Sdk.Models;

/// <summary>
/// Minimal participant record containing ID and DID mapping.
/// </summary>
public sealed class ParticipantSummary
{
    private string? _workstreamId;
    private string? _channelId;

    public string Id { get; set; } = string.Empty;
    public string Did { get; set; } = string.Empty;
    public string? Name { get; set; }
    public string? Status { get; set; }
    public string? CustomerId { get; set; }

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

    internal void NormalizeAliases()
    {
        var effective = string.IsNullOrWhiteSpace(WorkstreamId) ? ChannelId : WorkstreamId;
        WorkstreamId = effective;
        ChannelId = effective;
    }
}
