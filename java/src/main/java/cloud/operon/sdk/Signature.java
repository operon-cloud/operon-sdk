package cloud.operon.sdk;

/**
 * Encapsulates a digital signature suitable for Operon Client API submissions. The payload hash is supplied as part
 * of {@link TransactionRequest}; this record captures the algorithm used, the signature value (base64 encoded), and
 * the key identifier. {@code keyId} is optional—when self-signing is enabled the SDK will populate it automatically.
 *
 * @param algorithm signing algorithm identifier (for example {@code EdDSA}).
 * @param value     base64 encoded signature material.
 * @param keyId     optional key identifier referencing the signing key.
 */
public record Signature(String algorithm, String value, String keyId) {

    /**
     * Returns a copy with the key id replaced. Useful for callers who want to reuse the same signature but attach
     * a different key reference without constructing a new {@link Signature} manually.
     */
    public Signature withKeyId(String keyId) {
        return new Signature(algorithm, value, keyId);
    }
}
