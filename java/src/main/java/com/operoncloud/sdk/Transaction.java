package com.operoncloud.sdk;

import java.time.Instant;
import java.util.List;

/**
 * Full transaction representation returned by the Operon Client API. Every field maps directly to the data persisted
 * by the platform, making this record useful for audit logging, analytics, or piping to downstream systems.
 *
 * <p>
 * Fields prefixed with {@code hcs*} expose Hedera Consensus Service metadata when the transaction has been anchored
 * on-chain. Optional fields will be {@code null} when the information is not applicable.
 * </p>
 *
 * @param id                    server-assigned transaction identifier.
 * @param correlationId         caller-supplied idempotency key.
 * @param channelId             channel used to deliver the interaction.
 * @param customerId            owning customer (nullable when not applicable).
 * @param workspaceId           workspace context (nullable).
 * @param interactionId         interaction binding.
 * @param timestamp             logical transaction time.
 * @param sourceDid             DID that initiated the transaction.
 * @param targetDid             receiving DID.
 * @param signature             signature metadata attached to the submission.
 * @param label                 optional human-readable label.
 * @param tags                  caller-supplied tags.
 * @param payloadHash           base64url encoded SHA-256 hash of the payload.
 * @param status                current processing status.
 * @param hcsTopicId            Hedera topic identifier, when anchored.
 * @param hcsSequenceNumber     Hedera sequence number.
 * @param hcsConsensusTimestamp Hedera consensus timestamp.
 * @param hcsTransactionId      Hedera transaction id.
 * @param hcsRunningHash        Hedera running hash.
 * @param createdAt             platform creation timestamp.
 * @param updatedAt             platform last-update timestamp.
 * @param createdBy             identifier describing who created the transaction.
 * @param updatedBy             identifier describing who last mutated the record.
 * @param version               optimistic lock version number.
 */
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
