using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Describes the payload submitted to Operon when recording a transaction.
/// </summary>
public sealed class TransactionRequest
{
    private string? _workstreamId;
    private string? _channelId;

    /// <summary>
    /// Correlation identifier used to match the transaction to upstream processing.
    /// </summary>
    public string CorrelationId { get; set; } = string.Empty;

    /// <summary>
    /// Workstream identifier. If omitted, the SDK derives it from token claims or interaction metadata.
    /// </summary>
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
    [JsonIgnore]
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

    /// <summary>
    /// Interaction identifier describing the transaction template.
    /// </summary>
    public string InteractionId { get; set; } = string.Empty;

    /// <summary>
    /// Optional timestamp; when omitted, the current UTC time is used.
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }

    /// <summary>
    /// Source DID for the transaction. Populated automatically when possible.
    /// </summary>
    public string? SourceDid { get; set; }

    /// <summary>
    /// Target DID for the transaction. Populated automatically when possible.
    /// </summary>
    public string? TargetDid { get; set; }

    /// <summary>
    /// Optional ROI classification (`baseline`, `increment`, `savings`).
    /// </summary>
    public string? RoiClassification { get; set; }

    /// <summary>
    /// Optional ROI cost increment.
    /// </summary>
    public int? RoiCost { get; set; }

    /// <summary>
    /// Optional ROI time increment.
    /// </summary>
    public int? RoiTime { get; set; }

    /// <summary>
    /// Optional state label for transaction status modeling.
    /// </summary>
    public string? State { get; set; }

    /// <summary>
    /// Optional state identifier.
    /// </summary>
    public string? StateId { get; set; }

    /// <summary>
    /// Optional human-friendly state name.
    /// </summary>
    public string? StateLabel { get; set; }

    /// <summary>
    /// Optional legacy ROI baseline cost.
    /// </summary>
    public int? RoiBaseCost { get; set; }

    /// <summary>
    /// Optional legacy ROI baseline time.
    /// </summary>
    public int? RoiBaseTime { get; set; }

    /// <summary>
    /// Optional legacy ROI cost saving.
    /// </summary>
    public int? RoiCostSaving { get; set; }

    /// <summary>
    /// Optional legacy ROI time saving.
    /// </summary>
    public int? RoiTimeSaving { get; set; }

    /// <summary>
    /// Signature to attach to the transaction. When self-signing is enabled, this is populated automatically.
    /// </summary>
    public Signature Signature { get; set; } = new();

    /// <summary>
    /// Optional human-readable label that helps describe the transaction.
    /// </summary>
    public string? Label { get; set; }

    /// <summary>
    /// Optional tags persisted with the transaction.
    /// </summary>
    public IList<string>? Tags { get; set; }

    /// <summary>
    /// Raw payload bytes, typically the UTF-8 JSON body.
    /// </summary>
    [JsonIgnore]
    public byte[]? PayloadBytes { get; set; }

    /// <summary>
    /// Optional payload hash override. When omitted, the SDK hashes <see cref="PayloadBytes"/>.
    /// </summary>
    public string? PayloadHash { get; set; }

    /// <summary>
    /// Optional external actor identifier.
    /// </summary>
    public string? ActorExternalId { get; set; }

    /// <summary>
    /// Optional external actor display name.
    /// </summary>
    public string? ActorExternalDisplayName { get; set; }

    /// <summary>
    /// External source system for actor fields.
    /// </summary>
    public string? ActorExternalSource { get; set; }

    /// <summary>
    /// Optional external assignee identifier.
    /// </summary>
    public string? AssigneeExternalId { get; set; }

    /// <summary>
    /// Optional external assignee display name.
    /// </summary>
    public string? AssigneeExternalDisplayName { get; set; }

    /// <summary>
    /// External source system for assignee fields.
    /// </summary>
    public string? AssigneeExternalSource { get; set; }

    /// <summary>
    /// Optional customer identifier override.
    /// </summary>
    public string? CustomerId { get; set; }

    /// <summary>
    /// Optional workspace identifier override.
    /// </summary>
    public string? WorkspaceId { get; set; }

    /// <summary>
    /// Optional audit identifier for creator.
    /// </summary>
    public string? CreatedBy { get; set; }
}
