package operon_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operon "github.com/operon-cloud/operon-sdk/go"
)

func TestClientGetChannelInteractionsUsesTokenChannel(t *testing.T) {
	tokenValue := newTokenWithClaims(map[string]any{
		"participant_did": "did:example:source",
		"channel_id":      "channel-abc",
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: tokenValue, TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/channels/channel-abc/interactions":
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "Bearer "+tokenValue, r.Header.Get("Authorization"))
			payload := operon.ChannelInteractionsResponse{
				Interactions: []operon.ChannelInteraction{
					{
						ID:                  "interaction-1",
						Status:              "active",
						SourceParticipantID: "participant-src",
						TargetParticipantID: "participant-dst",
						Channels:            []string{"channel-abc"},
						CreatedAt:           time.Now().UTC(),
						UpdatedAt:           time.Now().UTC(),
					},
				},
				TotalCount: 1,
				Page:       1,
				PageSize:   1000,
				HasMore:    false,
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.GetChannelInteractions(ctx)
	require.NoError(t, err)
	require.Len(t, resp.Interactions, 1)
	require.Equal(t, "interaction-1", resp.Interactions[0].ID)
}

func TestClientGetChannelParticipantsAllowsOverride(t *testing.T) {
	tokenValue := newTokenWithoutParticipantDID()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: tokenValue, TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/channels/channel-override/participants":
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "Bearer "+tokenValue, r.Header.Get("Authorization"))
			payload := operon.ChannelParticipantsResponse{
				Participants: []operon.ChannelParticipant{
					{
						ID:        "participant-1",
						DID:       "did:example:participant",
						Status:    "active",
						CreatedAt: time.Now().UTC(),
						UpdatedAt: time.Now().UTC(),
					},
				},
				TotalCount: 1,
				Page:       1,
				PageSize:   1000,
				HasMore:    false,
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := client.GetChannelParticipants(ctx, "channel-override")
	require.NoError(t, err)
	require.Len(t, resp.Participants, 1)
	require.Equal(t, "participant-1", resp.Participants[0].ID)
}

func TestClientGetChannelInteractionsErrorsWithoutChannel(t *testing.T) {
	var pathCalled string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathCalled = r.URL.Path
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newTokenWithoutParticipantDID(), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.GetChannelInteractions(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "channel ID is required")
	require.Equal(t, "/token", pathCalled)
}
