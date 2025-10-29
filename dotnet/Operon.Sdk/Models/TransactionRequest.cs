using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Describes the payload submitted to Operon when recording a transaction.
/// </summary>
public sealed class TransactionRequest
{
    /// <summary>
    /// Correlation identifier used to match the transaction to upstream processing.
    /// </summary>
    public required string CorrelationId { get; init; }
        = string.Empty;

    /// <summary>
    /// Optional channel identifier; if omitted, the SDK derives it from the interaction catalog.
    /// </summary>
    public string? ChannelId { get; set; }
        = string.Empty;

    /// <summary>
    /// Interaction identifier describing the transaction template.
    /// </summary>
    public required string InteractionId { get; set; }
        = string.Empty;

    /// <summary>
    /// Optional timestamp; when omitted, the current UTC time is used.
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }
        = null;

    /// <summary>
    /// Source DID for the transaction. Populated automatically when possible.
    /// </summary>
    public string? SourceDid { get; set; }
        = string.Empty;

    /// <summary>
    /// Target DID for the transaction. Populated automatically when possible.
    /// </summary>
    public string? TargetDid { get; set; }
        = string.Empty;

    /// <summary>
    /// Signature to attach to the transaction. When self-signing is enabled, this is populated automatically.
    /// </summary>
    public Signature Signature { get; set; } = new();

    /// <summary>
    /// Optional human-readable label that helps describe the transaction.
    /// </summary>
    public string? Label { get; set; }
        = string.Empty;

    /// <summary>
    /// Optional tags persisted with the transaction.
    /// </summary>
    public IList<string>? Tags { get; set; }
        = null;

    /// <summary>Raw payload bytes, typically the UTF-8 JSON body.</summary>
    [JsonIgnore]
    public byte[]? PayloadBytes { get; set; }
        = null;

    /// <summary>When provided, the SDK skips hashing <see cref="PayloadBytes"/>.</summary>
    public string? PayloadHash { get; set; }
        = string.Empty;
}
