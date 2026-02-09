package cloud.operon.sdk;

import java.time.Instant;
import java.util.List;

/**
 * Workstream configuration entity returned by Operon APIs.
 */
public record Workstream(
    String id,
    Instant createdAt,
    Instant updatedAt,
    String createdBy,
    String updatedBy,
    Integer version,
    String customerId,
    String workspaceId,
    String name,
    String description,
    String mode,
    String type,
    String status,
    List<WorkstreamState> states,
    String defaultStateId,
    List<String> interactionIds,
    String hcsTestTopicId,
    String hcsLiveTopicId
) {
}
