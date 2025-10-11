package operon_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operon "github.com/operonmaster/operon-sdk/go"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type transactionSubmission struct {
	CorrelationID string           `json:"correlationId"`
	ChannelID     string           `json:"channelId"`
	InteractionID string           `json:"interactionId"`
	Timestamp     string           `json:"timestamp"`
	SourceDID     string           `json:"sourceDid"`
	TargetDID     string           `json:"targetDid"`
	PayloadData   string           `json:"payloadData,omitempty"`
	PayloadHash   string           `json:"payloadHash"`
	Signature     operon.Signature `json:"signature"`
	Tags          []string         `json:"tags,omitempty"`
	Label         string           `json:"label,omitempty"`
}

func newTestClient(t *testing.T, handler http.HandlerFunc, cfg operon.Config) (*operon.Client, func()) {
	t.Helper()

	srv := httptest.NewServer(handler)

	if cfg.BaseURL == "" {
		cfg.BaseURL = srv.URL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = srv.URL + "/token"
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "test-client"
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = "test-secret"
	}

	client, err := operon.NewClient(cfg)
	require.NoError(t, err)

	cleanup := func() {
		require.NoError(t, client.Close())
		srv.Close()
	}

	return client, cleanup
}

func TestClientSubmitTransactionWithSelfSigning(t *testing.T) {
	var tokenCalls int32
	var captured transactionSubmission

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			atomic.AddInt32(&tokenCalls, 1)
			resp := tokenResponse{AccessToken: newToken("did:example:source"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			require.Equal(t, "Bearer "+newToken("did:example:source"), r.Header.Get("Authorization"))
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "interaction-xyz",
						"channelId":           "channel-abc",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/dids/self/sign":
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "Bearer "+newToken("did:example:source"), r.Header.Get("Authorization"))

			var requestBody map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&requestBody))
			require.Equal(t, "SHA-256", requestBody["hashAlgorithm"])

			payload := map[string]any{
				"signature": map[string]any{
					"algorithm": "EdDSA",
					"value":     "c2lnbmF0dXJl",
					"keyId":     "did:example:source#keys-1",
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/transactions":
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))

			now := time.Now().UTC()
			response := map[string]any{
				"id":            "txn-123",
				"correlationId": captured.CorrelationID,
				"channelId":     captured.ChannelID,
				"interactionId": captured.InteractionID,
				"sourceDid":     captured.SourceDID,
				"targetDid":     captured.TargetDID,
				"signature": map[string]any{
					"algorithm": captured.Signature.Algorithm,
					"value":     captured.Signature.Value,
					"keyId":     captured.Signature.KeyID,
				},
				"payloadHash": captured.PayloadHash,
				"status":      "received",
				"timestamp":   now,
				"createdAt":   now,
				"updatedAt":   now,
			}
			require.NoError(t, json.NewEncoder(w).Encode(response))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req := operon.TransactionRequest{
		CorrelationID: "ext-001",
		InteractionID: "interaction-xyz",
		Payload:       []byte("hello world"),
		Tags:          []string{" env:demo ", ""},
	}

	txn, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "txn-123", txn.ID)
	require.Equal(t, "received", txn.Status)
	require.Equal(t, "channel-abc", txn.ChannelID)
	require.Equal(t, "did:example:target", txn.TargetDID)
	require.Equal(t, []string{"env:demo"}, captured.Tags)
	require.Equal(t, int32(1), atomic.LoadInt32(&tokenCalls))

	interactions, err := client.Interactions(ctx)
	require.NoError(t, err)
	require.Len(t, interactions, 1)
	require.Equal(t, "did:example:source", interactions[0].SourceDID)
	require.Equal(t, "did:example:target", interactions[0].TargetDID)
}

func TestClientSubmitTransactionWithManualSignature(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:source"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "manual-interaction",
						"channelId":           "manual-channel",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/transactions":
			var body transactionSubmission
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "manual-signature", body.Signature.Value)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"id": "txn-456", "status": "received", "correlationId": body.CorrelationID, "channelId": body.ChannelID, "interactionId": body.InteractionID, "sourceDid": body.SourceDID, "targetDid": body.TargetDID, "timestamp": time.Now(), "createdAt": time.Now(), "updatedAt": time.Now(), "signature": map[string]any{"algorithm": body.Signature.Algorithm, "value": body.Signature.Value}}))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{DisableSelfSign: true})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req := operon.TransactionRequest{
		CorrelationID: "ext-002",
		ChannelID:     "manual-channel",
		InteractionID: "manual-interaction",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Payload:       []byte("payload"),
		Signature: operon.Signature{
			Algorithm: operon.AlgorithmEd25519,
			Value:     "manual-signature",
			KeyID:     "did:example:source#keys-1",
		},
	}

	txn, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "txn-456", txn.ID)
}

func newToken(participantDID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"participant_did":"%s"}`, participantDID)))
	return header + "." + payload + ".signature"
}

func TestClientParticipantsReturnsCopy(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:source"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "interaction-abc",
						"channelId":           "channel-abc",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
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

	participants, err := client.Participants(ctx)
	require.NoError(t, err)
	require.Len(t, participants, 2)

	sourcePreserved := false
	targetPreserved := false
	for _, p := range participants {
		switch p.ID {
		case "participant-src":
			require.Equal(t, "did:example:source", p.DID)
			sourcePreserved = true
		case "participant-tgt":
			require.Equal(t, "did:example:target", p.DID)
			targetPreserved = true
		}
	}
	require.True(t, sourcePreserved)
	require.True(t, targetPreserved)

	participants[0].DID = "tampered"

	fresh, err := client.Participants(ctx)
	require.NoError(t, err)
	sourceRestored := false
	for _, p := range fresh {
		if p.ID == "participant-src" {
			sourceRestored = p.DID == "did:example:source"
		}
	}
	require.True(t, sourceRestored)
}

func TestClientInitFailsWhenParticipantsFail(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:error"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "interaction-abc",
						"channelId":           "channel-abc",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("oops"))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := client.Init(ctx)
	require.Error(t, err)
}

func TestSubmitTransactionAddsKeyIDWhenMissing(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:source"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "interaction-xyz",
						"channelId":           "channel-abc",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/dids/self/sign":
			payload := map[string]any{
				"signature": map[string]any{
					"algorithm": "EdDSA",
					"value":     "c2ln",
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/transactions":
			var body transactionSubmission
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "did:example:source#keys-1", body.Signature.KeyID)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"id":            "txn-789",
				"status":        "received",
				"correlationId": body.CorrelationID,
				"channelId":     body.ChannelID,
				"interactionId": body.InteractionID,
				"sourceDid":     body.SourceDID,
				"targetDid":     body.TargetDID,
				"timestamp":     time.Now(),
				"createdAt":     time.Now(),
				"updatedAt":     time.Now(),
				"signature": map[string]any{
					"algorithm": body.Signature.Algorithm,
					"value":     body.Signature.Value,
					"keyId":     body.Signature.KeyID,
				},
			}))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req := operon.TransactionRequest{
		CorrelationID: "ext-003",
		InteractionID: "interaction-xyz",
		Payload:       []byte("payload"),
	}

	txn, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "txn-789", txn.ID)
}

func TestSubmitTransactionValidatesInput(t *testing.T) {
	client, cleanup := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:source"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			payload := map[string]any{"data": []map[string]any{}}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			payload := map[string]any{"data": []map[string]any{}}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/transactions":
			t.Fatalf("transactions endpoint should not be reached")
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}), operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req := operon.TransactionRequest{CorrelationID: "corr"}
	_, err := client.SubmitTransaction(ctx, req)
	require.Error(t, err)
}

func TestClientInitFailsWhenInteractionDecodeFails(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:error"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			_, _ = w.Write([]byte("{"))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := client.Init(ctx)
	require.Error(t, err)
}

func TestClientInitFailsWhenParticipantDecodeFails(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:error"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "interaction-abc",
						"channelId":           "channel-abc",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			_, _ = w.Write([]byte("{"))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := client.Init(ctx)
	require.Error(t, err)
}

func TestClientInitFailsWhenInteractionsFail(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:error"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("{\"message\":\"invalid\"}"))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := client.Init(ctx)
	require.Error(t, err)
}
