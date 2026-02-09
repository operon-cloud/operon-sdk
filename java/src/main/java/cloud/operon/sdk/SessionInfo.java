package cloud.operon.sdk;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Session metadata derived from PAT claims and validation endpoint payload.
 */
public record SessionInfo(
    String userId,
    String email,
    String name,
    String customerId,
    List<String> roles,
    Map<String, Object> featureFlags,
    String workstreamId,
    String workspaceId,
    String participantDid,
    String participantId,
    String clientId,
    String sessionId,
    Instant expiresAt,
    int expiresInSeconds
) {
}
