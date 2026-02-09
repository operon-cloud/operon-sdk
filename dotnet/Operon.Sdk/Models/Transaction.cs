using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Representation of a transaction stored in Operon.
/// </summary>
public sealed class Transaction
{
    private string? _workstreamId;
    private string? _channelId;

    public string Id { get; set; } = string.Empty;
    public string CorrelationId { get; set; } = string.Empty;

    [JsonPropertyName("workstreamId")]
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
    public string? CustomerId { get; set; }
    public string? WorkspaceId { get; set; }
    public string InteractionId { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; }
    public string SourceDid { get; set; } = string.Empty;
    public string TargetDid { get; set; } = string.Empty;
    public string? State { get; set; }
    public string? StateId { get; set; }
    public string? StateLabel { get; set; }
    public string? RoiClassification { get; set; }
    public int? RoiCostIncrement { get; set; }
    public int? RoiTimeIncrement { get; set; }
    public int? RoiCostSavings { get; set; }
    public int? RoiTimeSavings { get; set; }
    public int? RoiBaseCost { get; set; }
    public int? RoiBaseTime { get; set; }
    public int? RoiCostSaving { get; set; }
    public int? RoiTimeSaving { get; set; }
    public Signature Signature { get; set; } = new();
    public string? Label { get; set; }
    public IReadOnlyList<string>? Tags { get; set; }
    public string PayloadHash { get; set; } = string.Empty;
    public string? ActorExternalId { get; set; }
    public string? ActorExternalDisplayName { get; set; }
    public string? ActorExternalSource { get; set; }
    public string? AssigneeExternalId { get; set; }
    public string? AssigneeExternalDisplayName { get; set; }
    public string? AssigneeExternalSource { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? HcsTopicId { get; set; }
    public long? HcsSequenceNumber { get; set; }
    public string? HcsConsensusTimestamp { get; set; }
    public string? HcsTransactionId { get; set; }
    public string? HcsRunningHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public string? UpdatedBy { get; set; }
    public int? Version { get; set; }

    internal void NormalizeAliases()
    {
        var effective = string.IsNullOrWhiteSpace(WorkstreamId) ? ChannelId : WorkstreamId;
        WorkstreamId = effective;
        ChannelId = effective;
    }
}
