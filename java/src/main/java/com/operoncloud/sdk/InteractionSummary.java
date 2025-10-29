package com.operoncloud.sdk;

/**
 * Lightweight projection of an interaction. Returned by {@link OperonClient#interactions()} and designed to power
 * administrative UIs or build pipelines that need to pre-populate interaction-dependent fields.
 *
 * @param id                  interaction identifier.
 * @param channelId           channel associated with the interaction.
 * @param sourceParticipantId source participant id.
 * @param targetParticipantId target participant id.
 * @param sourceDid           resolved source DID (nullable when not yet hydrated).
 * @param targetDid           resolved target DID (nullable when not yet hydrated).
 */
public record InteractionSummary(
    String id,
    String channelId,
    String sourceParticipantId,
    String targetParticipantId,
    String sourceDid,
    String targetDid
) {
}
