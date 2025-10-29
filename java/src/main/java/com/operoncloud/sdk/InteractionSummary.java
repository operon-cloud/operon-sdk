package com.operoncloud.sdk;

public record InteractionSummary(
    String id,
    String channelId,
    String sourceParticipantId,
    String targetParticipantId,
    String sourceDid,
    String targetDid
) {
}
