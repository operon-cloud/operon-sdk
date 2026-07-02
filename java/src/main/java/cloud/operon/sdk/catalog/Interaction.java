package cloud.operon.sdk.catalog;

import java.util.List;

public record Interaction(
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
    public Interaction withSourceDid(String did) {
        return new Interaction(
            id,
            workstreamId,
            workstreamName,
            name,
            description,
            status,
            sourceParticipantId,
            targetParticipantId,
            did,
            targetDid,
            type,
            actor,
            states,
            roiClassification,
            roiCost,
            roiTime
        );
    }

    public Interaction withTargetDid(String did) {
        return new Interaction(
            id,
            workstreamId,
            workstreamName,
            name,
            description,
            status,
            sourceParticipantId,
            targetParticipantId,
            sourceDid,
            did,
            type,
            actor,
            states,
            roiClassification,
            roiCost,
            roiTime
        );
    }
}
