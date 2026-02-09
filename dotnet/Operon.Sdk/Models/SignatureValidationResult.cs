namespace Operon.Sdk.Models;

/// <summary>
/// Response returned by signature validation endpoint.
/// </summary>
public sealed class SignatureValidationResult
{
    public string Status { get; set; } = string.Empty;
    public string? Message { get; set; }
    public string Did { get; set; } = string.Empty;
    public string PayloadHash { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
}
