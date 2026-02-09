package cloud.operon.sdk;

/**
 * Workstream state definition.
 */
public record WorkstreamState(
    String id,
    String name,
    String status
) {
}
