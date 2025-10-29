using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Representation of a transaction stored in Operon.
/// </summary>
public sealed class Transaction
{
    /// <summary>
    /// Unique identifier assigned by Operon.
    /// </summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Upstream correlation identifier supplied at submission time.
    /// </summary>
    public string CorrelationId { get; init; } = string.Empty;

    /// <summary>
    /// Channel identifier that processed the transaction.
    /// </summary>
    public string ChannelId { get; init; } = string.Empty;

    /// <summary>
    /// Customer identifier linked to the transaction, when known.
    /// </summary>
    public string? CustomerId { get; init; }
        = string.Empty;

    /// <summary>
    /// Workspace identifier linked to the transaction, when known.
    /// </summary>
    public string? WorkspaceId { get; init; }
        = string.Empty;

    /// <summary>
    /// Interaction identifier that describes the transaction template.
    /// </summary>
    public string InteractionId { get; init; } = string.Empty;

    /// <summary>
    /// Timestamp recorded for transaction submission.
    /// </summary>
    public DateTimeOffset Timestamp { get; init; }
        = DateTimeOffset.MinValue;

    /// <summary>
    /// Source DID associated with the transaction.
    /// </summary>
    public string SourceDid { get; init; } = string.Empty;

    /// <summary>
    /// Target DID associated with the transaction.
    /// </summary>
    public string TargetDid { get; init; } = string.Empty;

    /// <summary>
    /// Signature persisted alongside the transaction payload.
    /// </summary>
    public Signature Signature { get; init; } = new();

    /// <summary>
    /// Optional label displayed in Operon product surfaces.
    /// </summary>
    public string? Label { get; init; }
        = string.Empty;

    /// <summary>
    /// Tags attached to the transaction for filtering.
    /// </summary>
    public IReadOnlyList<string>? Tags { get; init; }
        = Array.Empty<string>();

    /// <summary>
    /// Hash of the transaction payload at submission time.
    /// </summary>
    public string PayloadHash { get; init; } = string.Empty;

    /// <summary>
    /// Current processing status of the transaction.
    /// </summary>
    public string Status { get; init; } = string.Empty;

    /// <summary>
    /// Hedera topic identifier (when published to HCS).
    /// </summary>
    public string? HcsTopicId { get; init; }
        = string.Empty;

    /// <summary>
    /// Sequence number assigned by Hedera consensus, if available.
    /// </summary>
    public long? HcsSequenceNumber { get; init; }
        = null;

    /// <summary>
    /// Hedera consensus timestamp, if the transaction was mirrored.
    /// </summary>
    public string? HcsConsensusTimestamp { get; init; }
        = string.Empty;

    /// <summary>
    /// Hedera transaction identifier, when available.
    /// </summary>
    public string? HcsTransactionId { get; init; }
        = string.Empty;

    /// <summary>
    /// Hedera running hash captured at the time of consensus.
    /// </summary>
    public string? HcsRunningHash { get; init; }
        = string.Empty;

    /// <summary>
    /// Timestamp when Operon created the record.
    /// </summary>
    public DateTimeOffset CreatedAt { get; init; }
        = DateTimeOffset.MinValue;

    /// <summary>
    /// Timestamp when Operon last updated the record.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; init; }
        = DateTimeOffset.MinValue;

    /// <summary>
    /// Internal identifier of the creator, if captured.
    /// </summary>
    public string? CreatedBy { get; init; }
        = string.Empty;

    /// <summary>
    /// Internal identifier of the last modifier, if captured.
    /// </summary>
    public string? UpdatedBy { get; init; }
        = string.Empty;

    /// <summary>
    /// Version number of the record, when optimistic concurrency is used.
    /// </summary>
    public int? Version { get; init; }
        = null;
}
