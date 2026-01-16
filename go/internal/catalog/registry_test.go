package catalog

import "testing"

func TestRegistryStoresInteractionsAndParticipants(t *testing.T) {
	reg := NewRegistry()

	reg.ReplaceInteractions([]Interaction{{ID: "i1", WorkstreamID: "w1"}})
	reg.ReplaceParticipants([]Participant{{ID: "p1", DID: "did:example:p1"}})

	if _, ok := reg.Interaction("i1"); !ok {
		t.Fatal("expected interaction to exist")
	}
	if did, ok := reg.ParticipantDID("p1"); !ok || did != "did:example:p1" {
		t.Fatalf("unexpected participant lookup: %v %v", ok, did)
	}

	interactions := reg.Interactions()
	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}

	participants := reg.Participants()
	if len(participants) != 1 {
		t.Fatalf("expected 1 participant, got %d", len(participants))
	}
}
