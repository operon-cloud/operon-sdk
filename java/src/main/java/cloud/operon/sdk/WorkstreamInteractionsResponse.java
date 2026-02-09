package cloud.operon.sdk;

import java.util.List;

/**
 * Response wrapper for workstream interactions endpoint.
 */
public record WorkstreamInteractionsResponse(
    List<WorkstreamInteraction> interactions,
    int totalCount,
    int page,
    int pageSize,
    boolean hasMore
) {
}
