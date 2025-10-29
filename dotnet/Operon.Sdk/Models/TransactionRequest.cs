using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Describes the payload submitted to Operon when recording a transaction.
/// </summary>
public sealed class TransactionRequest
{
    public required string CorrelationId { get; init; }
        = string.Empty;

    public string? ChannelId { get; set; }
        = string.Empty;

    public required string InteractionId { get; set; }
        = string.Empty;

    public DateTimeOffset? Timestamp { get; set; }
        = null;

    public string? SourceDid { get; set; }
        = string.Empty;

    public string? TargetDid { get; set; }
        = string.Empty;

    public Signature Signature { get; set; } = new();

    public string? Label { get; set; }
        = string.Empty;

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
