package cloud.operon.sdk.catalog;

public record Participant(
    String id,
    String did,
    String name,
    String status,
    String customerId,
    String workstreamId,
    String workstreamName
) {
}
