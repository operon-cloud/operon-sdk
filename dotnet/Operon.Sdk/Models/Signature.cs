using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Represents a digital signature attached to an Operon transaction payload.
/// </summary>
public sealed class Signature
{
    /// <summary>
    /// Algorithm used to produce the signature (e.g., EdDSA).
    /// </summary>
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "EdDSA";

    /// <summary>
    /// Base64 encoded signature payload.
    /// </summary>
    [JsonPropertyName("value")]
    public string? Value { get; set; }
        = string.Empty;

    /// <summary>
    /// Optional identifier of the signing key.
    /// </summary>
    [JsonPropertyName("keyId")]
    public string? KeyId { get; set; }
        = string.Empty;

    /// <summary>
    /// Creates a deep copy of the current signature.
    /// </summary>
    /// <returns>A copy of the signature.</returns>
    public Signature Clone() => new()
    {
        Algorithm = Algorithm,
        Value = Value,
        KeyId = KeyId
    };
}
