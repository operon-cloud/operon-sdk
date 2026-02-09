package cloud.operon.sdk;

import java.util.List;

/**
 * Response wrapper for workstream participants endpoint.
 */
public record WorkstreamParticipantsResponse(
    List<WorkstreamParticipant> participants,
    int totalCount,
    int page,
    int pageSize,
    boolean hasMore
) {
}
