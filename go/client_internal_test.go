package operon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/operon-cloud/operon-sdk/go/internal/catalog"
)

func TestClientCachedParticipantDID(t *testing.T) {
	var client Client
	require.Equal(t, "", client.cachedParticipantDID())
	client.participantDID = "did:example:participant"
	require.Equal(t, "did:example:participant", client.cachedParticipantDID())
}

func TestPopulateInteractionFieldsFillsFromRegistry(t *testing.T) {
	client := &Client{registry: catalog.NewRegistry()}
	client.registry.ReplaceInteractions([]catalog.Interaction{{
		ID:           "intr-1",
		WorkstreamID: "workstream-1",
		SourceDID:    "did:example:source",
		TargetDID:    "did:example:target",
	}})

	req := TransactionRequest{CorrelationID: "corr-1", InteractionID: "intr-1"}
	require.NoError(t, client.populateInteractionFields(context.Background(), &req))
	require.Equal(t, "workstream-1", req.WorkstreamID)
	require.Equal(t, "did:example:source", req.SourceDID)
	require.Equal(t, "did:example:target", req.TargetDID)
}

func TestPopulateInteractionFieldsMissingDIDs(t *testing.T) {
	client := &Client{registry: catalog.NewRegistry()}
	client.registry.ReplaceInteractions([]catalog.Interaction{{
		ID:           "intr-2",
		WorkstreamID: "workstream-2",
	}})

	req := TransactionRequest{CorrelationID: "corr-2", InteractionID: "intr-2"}
	err := client.populateInteractionFields(context.Background(), &req)
	require.Error(t, err)
}

func TestPopulateInteractionFieldsUsesParticipantFallback(t *testing.T) {
	client := &Client{registry: catalog.NewRegistry()}
	client.participantDID = "did:example:fallback"
	client.workstreamID = "wrk-fallback"

	req := TransactionRequest{CorrelationID: "corr-3"}
	require.NoError(t, client.populateInteractionFields(context.Background(), &req))
	require.Equal(t, "did:example:fallback", req.SourceDID)
	require.Equal(t, "wrk-fallback", req.WorkstreamID)
}

func TestPopulateInteractionFieldsUsesWorkstreamFallbackWhenInteractionMetadataMissing(t *testing.T) {
	client := &Client{registry: catalog.NewRegistry()}
	client.workstreamID = "wrk-fallback"
	client.registry.ReplaceInteractions([]catalog.Interaction{{
		ID:        "intr-3",
		SourceDID: "did:example:source",
		TargetDID: "did:example:target",
	}})

	req := TransactionRequest{CorrelationID: "corr-4", InteractionID: "intr-3"}
	require.NoError(t, client.populateInteractionFields(context.Background(), &req))
	require.Equal(t, "wrk-fallback", req.WorkstreamID)
	require.Equal(t, "did:example:source", req.SourceDID)
	require.Equal(t, "did:example:target", req.TargetDID)
}

func TestCloseSilentlyHandlesNil(t *testing.T) {
	closeSilently(nil)
}
