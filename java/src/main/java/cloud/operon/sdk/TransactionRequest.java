package cloud.operon.sdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Represents a transaction submission request.
 */
public final class TransactionRequest {

    private static final List<String> ROI_CLASSIFICATIONS = List.of("baseline", "increment", "savings");

    private final String correlationId;
    private final String workstreamId;
    private final String interactionId;
    private final Instant timestamp;
    private final String sourceDid;
    private final String targetDid;
    private final String roiClassification;
    private final Integer roiCost;
    private final Integer roiTime;
    private final String state;
    private final String stateId;
    private final String stateLabel;
    private final Integer roiBaseCost;
    private final Integer roiBaseTime;
    private final Integer roiCostSaving;
    private final Integer roiTimeSaving;
    private final Signature signature;
    private final String label;
    private final List<String> tags;
    private final byte[] payload;
    private final String payloadHash;
    private final String actorExternalId;
    private final String actorExternalDisplayName;
    private final String actorExternalSource;
    private final String assigneeExternalId;
    private final String assigneeExternalDisplayName;
    private final String assigneeExternalSource;
    private final String customerId;
    private final String workspaceId;
    private final String createdBy;

    private TransactionRequest(Builder builder) {
        this.correlationId = builder.correlationId;
        this.workstreamId = builder.workstreamId;
        this.interactionId = builder.interactionId;
        this.timestamp = builder.timestamp;
        this.sourceDid = builder.sourceDid;
        this.targetDid = builder.targetDid;
        this.roiClassification = builder.roiClassification;
        this.roiCost = builder.roiCost;
        this.roiTime = builder.roiTime;
        this.state = builder.state;
        this.stateId = builder.stateId;
        this.stateLabel = builder.stateLabel;
        this.roiBaseCost = builder.roiBaseCost;
        this.roiBaseTime = builder.roiBaseTime;
        this.roiCostSaving = builder.roiCostSaving;
        this.roiTimeSaving = builder.roiTimeSaving;
        this.signature = builder.signature;
        this.label = builder.label;
        this.tags = builder.tags == null ? List.of() : List.copyOf(builder.tags);
        this.payload = builder.payload == null ? null : builder.payload.clone();
        this.payloadHash = builder.payloadHash;
        this.actorExternalId = builder.actorExternalId;
        this.actorExternalDisplayName = builder.actorExternalDisplayName;
        this.actorExternalSource = builder.actorExternalSource;
        this.assigneeExternalId = builder.assigneeExternalId;
        this.assigneeExternalDisplayName = builder.assigneeExternalDisplayName;
        this.assigneeExternalSource = builder.assigneeExternalSource;
        this.customerId = builder.customerId;
        this.workspaceId = builder.workspaceId;
        this.createdBy = builder.createdBy;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public String getWorkstreamId() {
        return workstreamId;
    }

    /**
     * Legacy alias for compatibility with old channel terminology.
     */
    public String getChannelId() {
        return workstreamId;
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

    public String getRoiClassification() {
        return roiClassification;
    }

    public Integer getRoiCost() {
        return roiCost;
    }

    public Integer getRoiTime() {
        return roiTime;
    }

    public String getState() {
        return state;
    }

    public String getStateId() {
        return stateId;
    }

    public String getStateLabel() {
        return stateLabel;
    }

    public Integer getRoiBaseCost() {
        return roiBaseCost;
    }

    public Integer getRoiBaseTime() {
        return roiBaseTime;
    }

    public Integer getRoiCostSaving() {
        return roiCostSaving;
    }

    public Integer getRoiTimeSaving() {
        return roiTimeSaving;
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

    public String getActorExternalId() {
        return actorExternalId;
    }

    public String getActorExternalDisplayName() {
        return actorExternalDisplayName;
    }

    public String getActorExternalSource() {
        return actorExternalSource;
    }

    public String getAssigneeExternalId() {
        return assigneeExternalId;
    }

    public String getAssigneeExternalDisplayName() {
        return assigneeExternalDisplayName;
    }

    public String getAssigneeExternalSource() {
        return assigneeExternalSource;
    }

    public String getCustomerId() {
        return customerId;
    }

    public String getWorkspaceId() {
        return workspaceId;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void validateForSubmit() throws OperonException {
        if (isBlank(correlationId)) {
            throw new OperonException("CorrelationID is required");
        }
        if (isBlank(workstreamId)) {
            throw new OperonException("WorkstreamID is required");
        }
        if (isBlank(interactionId)) {
            throw new OperonException("InteractionID is required");
        }
        if (isBlank(sourceDid)) {
            throw new OperonException("SourceDID is required");
        }
        if (!sourceDid.startsWith("did:")) {
            throw new OperonException("SourceDID must be a valid DID");
        }
        if (isBlank(targetDid)) {
            throw new OperonException("TargetDID is required");
        }
        if (!targetDid.startsWith("did:")) {
            throw new OperonException("TargetDID must be a valid DID");
        }
        if ((payload == null || payload.length == 0) && isBlank(payloadHash)) {
            throw new OperonException("payload bytes or payload hash is required");
        }
        if (signature == null || isBlank(signature.algorithm())) {
            throw new OperonException("Signature algorithm is required");
        }
        if (isBlank(signature.value())) {
            throw new OperonException("Signature value is required");
        }
        if (!isBlank(roiClassification) && !ROI_CLASSIFICATIONS.contains(roiClassification)) {
            throw new OperonException("ROIClassification must be one of baseline, increment, savings");
        }
        if (roiBaseCost != null && roiBaseCost < 0) {
            throw new OperonException("ROIBaseCost cannot be negative");
        }
        if (roiBaseTime != null && roiBaseTime < 0) {
            throw new OperonException("ROIBaseTime cannot be negative");
        }
        if (roiCostSaving != null && roiCostSaving < 0) {
            throw new OperonException("ROICostSaving cannot be negative");
        }
        if (roiTimeSaving != null && roiTimeSaving < 0) {
            throw new OperonException("ROITimeSaving cannot be negative");
        }
        if (isBlank(actorExternalSource) && (!isBlank(actorExternalId) || !isBlank(actorExternalDisplayName))) {
            throw new OperonException(
                "ActorExternalSource is required when ActorExternalID or ActorExternalDisplayName is set"
            );
        }
        if (isBlank(assigneeExternalSource)
            && (!isBlank(assigneeExternalId) || !isBlank(assigneeExternalDisplayName))) {
            throw new OperonException(
                "AssigneeExternalSource is required when AssigneeExternalID or AssigneeExternalDisplayName is set"
            );
        }
    }

    public PayloadResolution resolvePayload() throws OperonException {
        if (payload != null && payload.length > 0) {
            String computedHash = computePayloadHash(payload);
            if (!isBlank(payloadHash) && !payloadHash.equalsIgnoreCase(computedHash)) {
                throw new OperonException(
                    "provided payload hash does not match payload content: expected " + computedHash
                        + " got " + payloadHash
                );
            }
            return new PayloadResolution(payload.clone(), computedHash);
        }

        String trimmedHash = Optional.ofNullable(payloadHash).map(String::trim).orElse("");
        if (trimmedHash.isEmpty()) {
            throw new OperonException("payload bytes or payload hash is required");
        }
        validatePayloadHashFormat(trimmedHash);
        return new PayloadResolution(null, trimmedHash);
    }

    public static void validatePayloadHashFormat(String hash) throws OperonException {
        if (hash.length() != 43) {
            throw new OperonException("payload hash must be 43 characters, got " + hash.length());
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

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    public record PayloadResolution(byte[] payloadBytes, String payloadHash) {
        public PayloadResolution {
            payloadBytes = payloadBytes == null ? null : payloadBytes.clone();
        }
    }

    public static final class Builder {
        private String correlationId;
        private String workstreamId;
        private String interactionId;
        private Instant timestamp;
        private String sourceDid;
        private String targetDid;
        private String roiClassification;
        private Integer roiCost;
        private Integer roiTime;
        private String state;
        private String stateId;
        private String stateLabel;
        private Integer roiBaseCost;
        private Integer roiBaseTime;
        private Integer roiCostSaving;
        private Integer roiTimeSaving;
        private Signature signature = new Signature(null, null, null);
        private String label;
        private List<String> tags;
        private byte[] payload;
        private String payloadHash;
        private String actorExternalId;
        private String actorExternalDisplayName;
        private String actorExternalSource;
        private String assigneeExternalId;
        private String assigneeExternalDisplayName;
        private String assigneeExternalSource;
        private String customerId;
        private String workspaceId;
        private String createdBy;

        public Builder correlationId(String correlationId) {
            this.correlationId = correlationId;
            return this;
        }

        public Builder workstreamId(String workstreamId) {
            this.workstreamId = workstreamId;
            return this;
        }

        /**
         * Legacy alias for compatibility with old channel terminology.
         */
        public Builder channelId(String channelId) {
            this.workstreamId = channelId;
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

        public Builder roiClassification(String roiClassification) {
            this.roiClassification = Optional.ofNullable(roiClassification)
                .map(v -> v.trim().toLowerCase(Locale.ROOT))
                .orElse(null);
            return this;
        }

        public Builder roiCost(Integer roiCost) {
            this.roiCost = roiCost;
            return this;
        }

        public Builder roiTime(Integer roiTime) {
            this.roiTime = roiTime;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder stateId(String stateId) {
            this.stateId = stateId;
            return this;
        }

        public Builder stateLabel(String stateLabel) {
            this.stateLabel = stateLabel;
            return this;
        }

        public Builder roiBaseCost(Integer roiBaseCost) {
            this.roiBaseCost = roiBaseCost;
            return this;
        }

        public Builder roiBaseTime(Integer roiBaseTime) {
            this.roiBaseTime = roiBaseTime;
            return this;
        }

        public Builder roiCostSaving(Integer roiCostSaving) {
            this.roiCostSaving = roiCostSaving;
            return this;
        }

        public Builder roiTimeSaving(Integer roiTimeSaving) {
            this.roiTimeSaving = roiTimeSaving;
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

        public Builder tags(Collection<String> tags) {
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

        public Builder actorExternalId(String actorExternalId) {
            this.actorExternalId = actorExternalId;
            return this;
        }

        public Builder actorExternalDisplayName(String actorExternalDisplayName) {
            this.actorExternalDisplayName = actorExternalDisplayName;
            return this;
        }

        public Builder actorExternalSource(String actorExternalSource) {
            this.actorExternalSource = actorExternalSource;
            return this;
        }

        public Builder assigneeExternalId(String assigneeExternalId) {
            this.assigneeExternalId = assigneeExternalId;
            return this;
        }

        public Builder assigneeExternalDisplayName(String assigneeExternalDisplayName) {
            this.assigneeExternalDisplayName = assigneeExternalDisplayName;
            return this;
        }

        public Builder assigneeExternalSource(String assigneeExternalSource) {
            this.assigneeExternalSource = assigneeExternalSource;
            return this;
        }

        public Builder customerId(String customerId) {
            this.customerId = customerId;
            return this;
        }

        public Builder workspaceId(String workspaceId) {
            this.workspaceId = workspaceId;
            return this;
        }

        public Builder createdBy(String createdBy) {
            this.createdBy = createdBy;
            return this;
        }

        public TransactionRequest build() {
            return new TransactionRequest(this);
        }
    }
}
