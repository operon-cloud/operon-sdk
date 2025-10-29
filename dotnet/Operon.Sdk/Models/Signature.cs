using System.Text.Json.Serialization;

namespace Operon.Sdk.Models;

/// <summary>
/// Represents a digital signature attached to an Operon transaction payload.
/// </summary>
public sealed class Signature
{
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "EdDSA";

    [JsonPropertyName("value")]
    public string? Value { get; set; }
        = string.Empty;

    [JsonPropertyName("keyId")]
    public string? KeyId { get; set; }
        = string.Empty;

    public Signature Clone() => new()
    {
        Algorithm = Algorithm,
        Value = Value,
        KeyId = KeyId
    };
}
