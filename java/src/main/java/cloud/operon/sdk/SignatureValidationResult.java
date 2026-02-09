package cloud.operon.sdk;

/**
 * Signature validation response payload.
 */
public record SignatureValidationResult(
    String status,
    String message,
    String did,
    String payloadHash,
    String algorithm,
    String keyId
) {
}
