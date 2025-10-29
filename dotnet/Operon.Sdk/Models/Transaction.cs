using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Representation of a transaction stored in Operon.
/// </summary>
public sealed class Transaction
{
    public string Id { get; init; } = string.Empty;
    public string CorrelationId { get; init; } = string.Empty;
    public string ChannelId { get; init; } = string.Empty;
    public string? CustomerId { get; init; }
        = string.Empty;
    public string? WorkspaceId { get; init; }
        = string.Empty;
    public string InteractionId { get; init; } = string.Empty;
    public DateTimeOffset Timestamp { get; init; }
        = DateTimeOffset.MinValue;
    public string SourceDid { get; init; } = string.Empty;
    public string TargetDid { get; init; } = string.Empty;
    public Signature Signature { get; init; } = new();
    public string? Label { get; init; }
        = string.Empty;
    public IReadOnlyList<string>? Tags { get; init; }
        = Array.Empty<string>();
    public string PayloadHash { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public string? HcsTopicId { get; init; }
        = string.Empty;
    public long? HcsSequenceNumber { get; init; }
        = null;
    public string? HcsConsensusTimestamp { get; init; }
        = string.Empty;
    public string? HcsTransactionId { get; init; }
        = string.Empty;
    public string? HcsRunningHash { get; init; }
        = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
        = DateTimeOffset.MinValue;
    public DateTimeOffset UpdatedAt { get; init; }
        = DateTimeOffset.MinValue;
    public string? CreatedBy { get; init; }
        = string.Empty;
    public string? UpdatedBy { get; init; }
        = string.Empty;
    public int? Version { get; init; }
        = null;
}
