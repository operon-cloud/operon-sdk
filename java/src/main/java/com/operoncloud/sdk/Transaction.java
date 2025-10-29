package com.operoncloud.sdk;

import java.time.Instant;
import java.util.List;

public record Transaction(
    String id,
    String correlationId,
    String channelId,
    String customerId,
    String workspaceId,
    String interactionId,
    Instant timestamp,
    String sourceDid,
    String targetDid,
    Signature signature,
    String label,
    List<String> tags,
    String payloadHash,
    String status,
    String hcsTopicId,
    Long hcsSequenceNumber,
    String hcsConsensusTimestamp,
    String hcsTransactionId,
    String hcsRunningHash,
    Instant createdAt,
    Instant updatedAt,
    String createdBy,
    String updatedBy,
    Integer version
) {
}
