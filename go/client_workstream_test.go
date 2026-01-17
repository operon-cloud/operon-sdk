package operon_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operon "github.com/operon-cloud/operon-sdk/go"
)

func TestClientGetWorkstreamUsesTokenWorkstream(t *testing.T) {
	tokenValue := newTokenWithClaims(map[string]any{
		"participant_did": "did:example:source",
		"workstream_id":   "wstr-abc",
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: tokenValue, TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/workstreams/wstr-abc":
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "Bearer "+tokenValue, r.Header.Get("Authorization"))
			payload := operon.Workstream{
				ID:          "wstr-abc",
				Name:        "Claims",
				CustomerID:  "cust-1",
				WorkspaceID: "wksp-1",
				Status:      operon.WorkstreamStatusActive,
				Mode:        operon.WorkstreamModeOn,
				States: []operon.WorkstreamState{
					{ID: "state-1", Name: "Intake", Status: operon.WorkstreamStateStatusActive},
				},
				DefaultStateID: "state-1",
				CreatedAt:      time.Now().UTC(),
				UpdatedAt:      time.Now().UTC(),
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

	workstream, err := client.GetWorkstream(ctx)
	require.NoError(t, err)
	require.NotNil(t, workstream)
	require.Equal(t, "wstr-abc", workstream.ID)
	require.Equal(t, operon.WorkstreamStatusActive, workstream.Status)
	require.Len(t, workstream.States, 1)
}

func TestClientGetWorkstreamAllowsOverride(t *testing.T) {
	tokenValue := newTokenWithoutParticipantDID()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: tokenValue, TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/workstreams/wstr-override":
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "Bearer "+tokenValue, r.Header.Get("Authorization"))
			require.NoError(t, json.NewEncoder(w).Encode(operon.Workstream{
				ID:     "wstr-override",
				Name:   "Support",
				Status: operon.WorkstreamStatusDraft,
			}))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	workstream, err := client.GetWorkstream(ctx, "wstr-override")
	require.NoError(t, err)
	require.NotNil(t, workstream)
	require.Equal(t, "wstr-override", workstream.ID)
}

func TestClientGetWorkstreamErrorsWithoutWorkstream(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	_, err := client.GetWorkstream(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "workstream ID is required")
}

func TestFetchWorkstreamUsesPATClaim(t *testing.T) {
	pat := newTokenWithClaims(map[string]any{
		"participant_did": "did:example:source",
		"workstream_id":   "wstr-xyz",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/workstreams/wstr-xyz", r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "Bearer "+pat, r.Header.Get("Authorization"))
		require.NoError(t, json.NewEncoder(w).Encode(operon.Workstream{
			ID:     "wstr-xyz",
			Name:   "Ops",
			Status: operon.WorkstreamStatusActive,
		}))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cfg := operon.WorkstreamDataConfig{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	}

	workstream, err := operon.FetchWorkstream(ctx, cfg, pat)
	require.NoError(t, err)
	require.NotNil(t, workstream)
	require.Equal(t, "wstr-xyz", workstream.ID)
}
