package cloud.operon.sdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Represents a transaction submission request.
 */
public final class TransactionRequest {

    private final String correlationId;
    private final String channelId;
    private final String interactionId;
    private final Instant timestamp;
    private final String sourceDid;
    private final String targetDid;
    private final Signature signature;
    private final String label;
    private final List<String> tags;
    private final byte[] payload;
    private final String payloadHash;

    private TransactionRequest(Builder builder) {
        this.correlationId = builder.correlationId;
        this.channelId = builder.channelId;
        this.interactionId = builder.interactionId;
        this.timestamp = builder.timestamp;
        this.sourceDid = builder.sourceDid;
        this.targetDid = builder.targetDid;
        this.signature = builder.signature;
        this.label = builder.label;
        this.tags = builder.tags == null ? List.of() : List.copyOf(builder.tags);
        this.payload = builder.payload == null ? null : builder.payload.clone();
        this.payloadHash = builder.payloadHash;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public String getChannelId() {
        return channelId;
    }

    public String getInteractionId() {
        return interactionId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceDid() {
        return sourceDid;
    }

    public String getTargetDid() {
        return targetDid;
    }

    public Signature getSignature() {
        return signature;
    }

    public String getLabel() {
        return label;
    }

    public List<String> getTags() {
        return tags;
    }

    public byte[] getPayload() {
        return payload == null ? null : payload.clone();
    }

    public String getPayloadHash() {
        return payloadHash;
    }

    /**
     * Ensures the request satisfies the platform contract. Invoked internally by {@link OperonClient} immediately
     * before issuing the HTTP call.
     *
     * @throws OperonException when required fields are missing or malformed.
     */
    public void validateForSubmit() throws OperonException {
        if (correlationId == null || correlationId.isBlank()) {
            throw new OperonException("CorrelationID is required");
        }
        if (channelId == null || channelId.isBlank()) {
            throw new OperonException("ChannelID is required");
        }
        if (interactionId == null || interactionId.isBlank()) {
            throw new OperonException("InteractionID is required");
        }
        if (sourceDid == null || sourceDid.isBlank()) {
            throw new OperonException("SourceDID is required");
        }
        if (!sourceDid.startsWith("did:")) {
            throw new OperonException("SourceDID must be a valid DID");
        }
        if (targetDid == null || targetDid.isBlank()) {
            throw new OperonException("TargetDID is required");
        }
        if (!targetDid.startsWith("did:")) {
            throw new OperonException("TargetDID must be a valid DID");
        }
        if ((payload == null || payload.length == 0) && (payloadHash == null || payloadHash.isBlank())) {
            throw new OperonException("payload bytes or payload hash is required");
        }
        if (signature == null || signature.algorithm() == null || signature.algorithm().isBlank()) {
            throw new OperonException("Signature algorithm is required");
        }
        if (signature.value() == null || signature.value().isBlank()) {
            throw new OperonException("Signature value is required");
        }
    }

    /**
     * Resolves the payload into the wire format expected by the Operon API. The method returns both the base64 encoded
     * payload (when bytes were provided) and the authoritative payload hash.
     *
     * @return payload information ready for serialisation.
     * @throws OperonException when neither payload bytes nor hash are supplied, or when the provided hash is invalid.
     */
    public PayloadResolution resolvePayload() throws OperonException {
        if (payload != null && payload.length > 0) {
            String payloadData = Base64.getEncoder().encodeToString(payload);
            String computedHash = computePayloadHash(payload);
            if (payloadHash != null && !payloadHash.isBlank() && !payloadHash.equals(computedHash)) {
                throw new OperonException("provided payload hash does not match payload content");
            }
            return new PayloadResolution(payloadData, computedHash);
        }

        String trimmedHash = Optional.ofNullable(payloadHash).map(String::trim).orElse("");
        if (trimmedHash.isEmpty()) {
            throw new OperonException("payload bytes or payload hash is required");
        }
        validatePayloadHashFormat(trimmedHash);
        return new PayloadResolution(null, trimmedHash);
    }

    private static void validatePayloadHashFormat(String hash) throws OperonException {
        if (hash.length() != 43) {
            throw new OperonException("payload hash must be 43 characters");
        }
        try {
            Base64.getUrlDecoder().decode(hash);
        } catch (IllegalArgumentException ex) {
            throw new OperonException("payload hash must be base64url encoded");
        }
    }

    private static String computePayloadHash(byte[] payload) throws OperonException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] sum = digest.digest(payload);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sum);
        } catch (NoSuchAlgorithmException ex) {
            throw new OperonException("SHA-256 not available", ex);
        }
    }

    /**
     * Captures the encoded payload and its base64url SHA-256 hash. {@code payloadData} will be {@code null} when the
     * caller supplied only a hash.
     *
     * @param payloadData base64 encoded payload bytes (nullable).
     * @param payloadHash base64url encoded SHA-256 hash (never {@code null}).
     */
    public record PayloadResolution(String payloadData, String payloadHash) {
    }

    /**
     * Fluent builder for {@link TransactionRequest}.
     *
     * <p>Builders are mutable and not thread-safe—create a fresh instance per request.</p>
     */
    public static final class Builder {
        private String correlationId;
        private String channelId;
        private String interactionId;
        private Instant timestamp;
        private String sourceDid;
        private String targetDid;
        private Signature signature = new Signature(null, null, null);
        private String label;
        private List<String> tags;
        private byte[] payload;
        private String payloadHash;

        /**
         * Sets the caller-specified idempotency key used to deduplicate submissions.
         */
        public Builder correlationId(String correlationId) {
            this.correlationId = correlationId;
            return this;
        }

        /**
         * Overrides the channel identifier. Omit to let the client resolve it from the interaction cache or PAT.
         */
        public Builder channelId(String channelId) {
            this.channelId = channelId;
            return this;
        }

        /**
         * Sets the interaction driving the transaction. Required.
         */
        public Builder interactionId(String interactionId) {
            this.interactionId = interactionId;
            return this;
        }

        /**
         * Supplies an explicit timestamp. When unspecified the client uses {@link Instant#now()}.
         */
        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        /**
         * Overrides the source DID. Optional; leave unset to derive from the interaction metadata or PAT.
         */
        public Builder sourceDid(String sourceDid) {
            this.sourceDid = sourceDid;
            return this;
        }

        /**
         * Overrides the target DID. Optional; leave unset to derive from the interaction metadata.
         */
        public Builder targetDid(String targetDid) {
            this.targetDid = targetDid;
            return this;
        }

        /**
         * Supplies a pre-computed signature. Required when self-signing is disabled.
         */
        public Builder signature(Signature signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Adds a human-readable label for analytics and audit records.
         */
        public Builder label(String label) {
            this.label = label;
            return this;
        }

        /**
         * Associates free-form tags with the transaction. Leading/trailing whitespace is trimmed and empty entries are ignored.
         */
        public Builder tags(List<String> tags) {
            this.tags = tags == null ? null : new ArrayList<>(tags);
            return this;
        }

        /**
         * Provides the raw payload bytes. The SDK encodes the data and calculates the hash automatically.
         */
        public Builder payload(byte[] payload) {
            this.payload = payload == null ? null : payload.clone();
            return this;
        }

        /**
         * Convenience helper that accepts a UTF-8 string payload.
         */
        public Builder payload(String payload) {
            this.payload = payload == null ? null : payload.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        /**
         * Supplies a pre-computed base64url SHA-256 payload hash. Use this when you stream the payload separately.
         * If {@link #payload(byte[])} is also set the SDK validates the hash matches the supplied bytes.
         */
        public Builder payloadHash(String payloadHash) {
            this.payloadHash = payloadHash;
            return this;
        }

        /**
         * Creates the immutable {@link TransactionRequest}. The returned instance contains defensive copies of mutable inputs.
         */
        public TransactionRequest build() {
            return new TransactionRequest(this);
        }
    }
}
