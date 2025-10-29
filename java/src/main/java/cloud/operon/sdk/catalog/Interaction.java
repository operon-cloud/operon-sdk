package cloud.operon.sdk.catalog;

public record Interaction(
    String id,
    String channelId,
    String sourceParticipantId,
    String targetParticipantId,
    String sourceDid,
    String targetDid
) {
    public Interaction withSourceDid(String did) {
        return new Interaction(id, channelId, sourceParticipantId, targetParticipantId, did, targetDid);
    }

    public Interaction withTargetDid(String did) {
        return new Interaction(id, channelId, sourceParticipantId, targetParticipantId, sourceDid, did);
    }
}
