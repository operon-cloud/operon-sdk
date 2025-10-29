package com.operoncloud.sdk;

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

    public record PayloadResolution(String payloadData, String payloadHash) {
    }

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

        public Builder correlationId(String correlationId) {
            this.correlationId = correlationId;
            return this;
        }

        public Builder channelId(String channelId) {
            this.channelId = channelId;
            return this;
        }

        public Builder interactionId(String interactionId) {
            this.interactionId = interactionId;
            return this;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder sourceDid(String sourceDid) {
            this.sourceDid = sourceDid;
            return this;
        }

        public Builder targetDid(String targetDid) {
            this.targetDid = targetDid;
            return this;
        }

        public Builder signature(Signature signature) {
            this.signature = signature;
            return this;
        }

        public Builder label(String label) {
            this.label = label;
            return this;
        }

        public Builder tags(List<String> tags) {
            this.tags = tags == null ? null : new ArrayList<>(tags);
            return this;
        }

        public Builder payload(byte[] payload) {
            this.payload = payload == null ? null : payload.clone();
            return this;
        }

        public Builder payload(String payload) {
            this.payload = payload == null ? null : payload.getBytes(StandardCharsets.UTF_8);
            return this;
        }

        public Builder payloadHash(String payloadHash) {
            this.payloadHash = payloadHash;
            return this;
        }

        public TransactionRequest build() {
            return new TransactionRequest(this);
        }
    }
}
