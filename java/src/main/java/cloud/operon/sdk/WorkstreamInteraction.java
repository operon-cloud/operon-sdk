package cloud.operon.sdk;

import java.time.Instant;
import java.util.List;

/**
 * Detailed interaction projection for a specific workstream.
 */
public record WorkstreamInteraction(
    String id,
    String workstreamId,
    String workstreamName,
    String name,
    String description,
    String status,
    String sourceParticipantId,
    String targetParticipantId,
    List<String> workstreams,
    String type,
    String actor,
    List<String> states,
    String roiClassification,
    Integer roiCost,
    Integer roiTime,
    List<String> tags,
    Instant createdAt,
    Instant updatedAt,
    Integer version
) {
}
