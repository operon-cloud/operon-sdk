package cloud.operon.sdk;

import java.time.Instant;
import java.util.List;

/**
 * Participant projection scoped to a workstream.
 */
public record WorkstreamParticipant(
    String id,
    String did,
    String name,
    String description,
    String url,
    String status,
    String type,
    String customerId,
    String workstreamId,
    String workstreamName,
    List<String> tags,
    Instant createdAt,
    Instant updatedAt,
    Integer version
) {
}
