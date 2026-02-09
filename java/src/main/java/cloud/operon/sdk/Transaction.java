package cloud.operon.sdk;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;

/**
 * Full transaction representation returned by the Operon Client API.
 */
public record Transaction(
    String id,
    String correlationId,
    @JsonProperty("workstreamId") @JsonAlias("channelId") String workstreamId,
    String workstreamName,
    String customerId,
    String workspaceId,
    String interactionId,
    Instant timestamp,
    String sourceDid,
    String targetDid,
    String state,
    String stateId,
    String stateLabel,
    String roiClassification,
    Integer roiCostIncrement,
    Integer roiTimeIncrement,
    Integer roiCostSavings,
    Integer roiTimeSavings,
    Integer roiBaseCost,
    Integer roiBaseTime,
    Integer roiCostSaving,
    Integer roiTimeSaving,
    Signature signature,
    String label,
    List<String> tags,
    String payloadHash,
    String actorExternalId,
    String actorExternalDisplayName,
    String actorExternalSource,
    String assigneeExternalId,
    String assigneeExternalDisplayName,
    String assigneeExternalSource,
    String status,
    String hcsTopicId,
    Long hcsSequenceNumber,
    String hcsConsensusTimestamp,
    String hcsTransactionId,
    String hcsRunningHash,
    Instant createdAt,
    Instant updatedAt,
    String createdBy,
    String updatedBy,
    Integer version
) {
    /**
     * Legacy alias for compatibility with old channel terminology.
     */
    public String channelId() {
        return workstreamId;
    }
}
