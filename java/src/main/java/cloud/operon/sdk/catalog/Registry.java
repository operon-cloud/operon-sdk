package cloud.operon.sdk.catalog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe registry storing interaction and participant reference data.
 */
public final class Registry {

    private final Map<String, Interaction> interactions = new ConcurrentHashMap<>();
    private final Map<String, Participant> participants = new ConcurrentHashMap<>();

    public void replaceInteractions(List<Interaction> items) {
        interactions.clear();
        if (items == null) {
            return;
        }
        for (Interaction item : items) {
            if (item == null || item.id() == null || item.id().isBlank()) {
                continue;
            }
            interactions.put(item.id(), item);
        }
    }

    public Interaction interaction(String id) {
        if (id == null) {
            return null;
        }
        return interactions.get(id);
    }

    public List<Interaction> interactions() {
        return Collections.unmodifiableList(new ArrayList<>(interactions.values()));
    }

    public void replaceParticipants(List<Participant> items) {
        participants.clear();
        if (items == null) {
            return;
        }
        for (Participant item : items) {
            if (item == null || item.id() == null || item.id().isBlank() || item.did() == null || item.did().isBlank()) {
                continue;
            }
            participants.put(item.id(), item);
        }
    }

    public List<Participant> participants() {
        return Collections.unmodifiableList(new ArrayList<>(participants.values()));
    }

    public String participantDid(String id) {
        Participant participant = participants.get(id);
        return participant == null ? null : participant.did();
    }
}
