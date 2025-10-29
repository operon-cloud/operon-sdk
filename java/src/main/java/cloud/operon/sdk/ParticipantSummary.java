package cloud.operon.sdk;

/**
 * Simple DTO returned by {@link OperonClient#participants()} mapping participant identifiers to their associated DIDs.
 *
 * @param id  participant identifier.
 * @param did decentralised identifier.
 */
public record ParticipantSummary(String id, String did) {
}
