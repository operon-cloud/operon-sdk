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
    String fromStateId,
    String fromStateLabel,
    String toStateId,
    String toStateLabel,
    String roiClassification,
    Integer roiCost,
    Integer roiTime
) {
    public InteractionSummary(
        String id,
        String workstreamId,
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
        this(
            id,
            workstreamId,
            workstreamName,
            name,
            description,
            status,
            sourceParticipantId,
            targetParticipantId,
            sourceDid,
            targetDid,
            type,
            actor,
            states,
            null,
            null,
            null,
            null,
            roiClassification,
            roiCost,
            roiTime
        );
    }

    /**
     * Legacy alias for compatibility with old channel terminology.
     */
    public String channelId() {
        return workstreamId;
    }
}
