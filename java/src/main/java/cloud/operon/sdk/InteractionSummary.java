package cloud.operon.sdk;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Lightweight projection of an interaction.
 */
public record InteractionSummary(
    String id,
    @JsonProperty("workstreamId") @JsonAlias("channelId") String workstreamId,
    String workstreamName,
    String name,
    String description,
    String status,
    String sourceParticipantId,
    String targetParticipantId,
    String sourceDid,
    String targetDid,
    String type,
    String actor,
    List<String> states,
    String roiClassification,
    Integer roiCost,
    Integer roiTime
) {
    /**
     * Legacy alias for compatibility with old channel terminology.
     */
    public String channelId() {
        return workstreamId;
    }
}
