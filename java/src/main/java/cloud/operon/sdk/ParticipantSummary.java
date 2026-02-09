package cloud.operon.sdk;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Participant projection used in reference datasets.
 */
public record ParticipantSummary(
    String id,
    String did,
    String name,
    String status,
    String customerId,
    @JsonProperty("workstreamId") @JsonAlias("channelId") String workstreamId,
    String workstreamName
) {
    /**
     * Legacy alias for compatibility with old channel terminology.
     */
    public String channelId() {
        return workstreamId;
    }
}
