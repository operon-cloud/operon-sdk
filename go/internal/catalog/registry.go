package catalog

import "sync"

// InteractionType describes whether an interaction represents a touch, transition, or transfer event.
type InteractionType string

const (
	InteractionTypeTouch      InteractionType = "touch"
	InteractionTypeTransition InteractionType = "transition"
	InteractionTypeTransfer   InteractionType = "transfer"
)

// InteractionActor describes the agent responsible for an interaction.
type InteractionActor string

const (
	InteractionActorHuman  InteractionActor = "human"
	InteractionActorAI     InteractionActor = "ai"
	InteractionActorHybrid InteractionActor = "hybrid"
	InteractionActorNonAI  InteractionActor = "non-ai"
)

// ROIClassification describes how an interaction affects ROI metrics.
type ROIClassification string

const (
	ROIClassificationBaseline  ROIClassification = "baseline"
	ROIClassificationIncrement ROIClassification = "increment"
	ROIClassificationSavings   ROIClassification = "savings"
)

// Interaction holds the subsets of interaction metadata cached by the SDK.
type Interaction struct {
	ID                  string
	WorkstreamID        string
	SourceParticipantID string
	TargetParticipantID string
	SourceDID           string
	TargetDID           string
	Type                InteractionType
	Actor               InteractionActor
	States              []string
	ROIClassification   ROIClassification
	ROICost             int
	ROITime             int
}

// Participant captures an ID to DID mapping for cached directory lookups.
type Participant struct {
	ID           string
	DID          string
	Name         string
	Status       string
	CustomerID   string
	WorkstreamID string
}

// Registry is a threadsafe cache for interaction and participant directories.
type Registry struct {
	mu           sync.RWMutex
	interactions map[string]Interaction
	participants map[string]Participant
}

// NewRegistry constructs an empty registry instance.
func NewRegistry() *Registry {
	return &Registry{
		interactions: make(map[string]Interaction),
		participants: make(map[string]Participant),
	}
}

// ReplaceInteractions swaps the cached interaction metadata for the provided set.
func (r *Registry) ReplaceInteractions(items []Interaction) {
	snapshot := make(map[string]Interaction, len(items))
	for _, item := range items {
		if item.ID == "" {
			continue
		}
		snapshot[item.ID] = item
	}

	r.mu.Lock()
	r.interactions = snapshot
	r.mu.Unlock()
}

// Interaction returns the cached metadata for the supplied interaction ID.
func (r *Registry) Interaction(id string) (Interaction, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.interactions[id]
	return item, ok
}

// Interactions returns a snapshot of all cached interaction records.
func (r *Registry) Interactions() []Interaction {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Interaction, 0, len(r.interactions))
	for _, item := range r.interactions {
		result = append(result, item)
	}
	return result
}

// ReplaceParticipants swaps the cached participant directory for the provided set.
func (r *Registry) ReplaceParticipants(items []Participant) {
	snapshot := make(map[string]Participant, len(items))
	for _, item := range items {
		if item.ID == "" || item.DID == "" {
			continue
		}
		snapshot[item.ID] = item
	}

	r.mu.Lock()
	r.participants = snapshot
	r.mu.Unlock()
}

// Participants returns a snapshot of all cached participant records.
func (r *Registry) Participants() []Participant {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Participant, 0, len(r.participants))
	for _, item := range r.participants {
		result = append(result, item)
	}
	return result
}

// ParticipantDID returns the DID for a participant ID, if present in the cache.
func (r *Registry) ParticipantDID(id string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.participants[id]
	if !ok {
		return "", false
	}
	return item.DID, true
}
