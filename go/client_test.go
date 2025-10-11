package operon_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustoperon/operon-sdk/go"
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

type transactionResponse struct {
	ID            string           `json:"id"`
	CorrelationID string           `json:"correlationId"`
	ChannelID     string           `json:"channelId"`
	InteractionID string           `json:"interactionId"`
	SourceDID     string           `json:"sourceDid"`
	TargetDID     string           `json:"targetDid"`
	Signature     operon.Signature `json:"signature"`
	PayloadHash   string           `json:"payloadHash"`
	Status        string           `json:"status"`
	Timestamp     time.Time        `json:"timestamp"`
	CreatedAt     time.Time        `json:"createdAt"`
	UpdatedAt     time.Time        `json:"updatedAt"`
}

func newTestClient(t *testing.T, handler http.HandlerFunc) (*operon.Client, func()) {
	cfg := operon.Config{}
	return newTestClientWithConfig(t, handler, cfg)
}

func newTestClientWithConfig(t *testing.T, handler http.HandlerFunc, cfg operon.Config) (*operon.Client, func()) {
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

func TestSubmitTransactionSuccess(t *testing.T) {
	var tokenCalls int32
	var captured transactionSubmission

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			atomic.AddInt32(&tokenCalls, 1)
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))

			resp := tokenResponse{AccessToken: "token-123", TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/interactions":
			require.Equal(t, "Bearer token-123", r.Header.Get("Authorization"))
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
			require.Equal(t, "Bearer token-123", r.Header.Get("Authorization"))
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/transactions":
			require.Equal(t, "Bearer token-123", r.Header.Get("Authorization"))
			require.Equal(t, "application/json", r.Header.Get("Content-Type"))

			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
			require.NotEmpty(t, captured.PayloadHash)
			require.NotZero(t, captured.Timestamp)
			require.Contains(t, captured.Tags, "env:demo")

			now := time.Now().UTC()
			ref := transactionResponse{
				ID:            "txn-123",
				CorrelationID: captured.CorrelationID,
				ChannelID:     captured.ChannelID,
				InteractionID: captured.InteractionID,
				SourceDID:     captured.SourceDID,
				TargetDID:     captured.TargetDID,
				Signature:     captured.Signature,
				PayloadHash:   captured.PayloadHash,
				Status:        "received",
				Timestamp:     now,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			require.NoError(t, json.NewEncoder(w).Encode(ref))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler)
	defer cleanup()

	req := operon.TransactionRequest{
		CorrelationID: "ext-001",
		ChannelID:     "channel-abc",
		InteractionID: "interaction-xyz",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Payload:       []byte("hello world"),
		Signature: operon.Signature{
			Algorithm: "EdDSA",
			Value:     "c2lnbmF0dXJl",
			KeyID:     "did:example:source#keys-1",
		},
		Label: "Demo payload",
		Tags:  []string{"env:demo"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	txn, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "txn-123", txn.ID)
	require.Equal(t, "received", txn.Status)
	require.Equal(t, "ext-001", txn.CorrelationID)
	require.Equal(t, "channel-abc", txn.ChannelID)
	require.Equal(t, "did:example:source", txn.SourceDID)
	require.Equal(t, "did:example:target", txn.TargetDID)
	require.Equal(t, int32(1), atomic.LoadInt32(&tokenCalls))
}

func TestSubmitTransactionAllowsOmittingLabelAndTags(t *testing.T) {
	var tokenCalls int32
	var captured map[string]any

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			atomic.AddInt32(&tokenCalls, 1)
			require.NoError(t, json.NewEncoder(w).Encode(tokenResponse{AccessToken: "token-abc", TokenType: "Bearer", ExpiresIn: 3600}))
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
		case "/v1/transactions":
			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
			require.NotContains(t, captured, "label")
			require.NotContains(t, captured, "tags")

			now := time.Now().UTC()
			require.NoError(t, json.NewEncoder(w).Encode(transactionResponse{
				ID:            "txn-omit",
				CorrelationID: "ext-omit",
				ChannelID:     "channel-abc",
				InteractionID: "interaction-xyz",
				SourceDID:     "did:example:source",
				TargetDID:     "did:example:target",
				Signature: operon.Signature{
					Algorithm: "EdDSA",
					Value:     base64.StdEncoding.EncodeToString([]byte("signature")),
				},
				PayloadHash: captured["payloadHash"].(string),
				Status:      "received",
				Timestamp:   now,
				CreatedAt:   now,
				UpdatedAt:   now,
			}))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler)
	defer cleanup()

	req := operon.TransactionRequest{
		CorrelationID: "ext-omit",
		InteractionID: "interaction-xyz",
		ChannelID:     "channel-abc",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Payload:       []byte("hello world"),
		Signature: operon.Signature{
			Algorithm: "EdDSA",
			Value:     base64.StdEncoding.EncodeToString([]byte("signature")),
		},
		Tags:  nil,
		Label: " \t\n",
	}

	ctx := context.Background()
	txn, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "txn-omit", txn.ID)
	require.Equal(t, int32(1), atomic.LoadInt32(&tokenCalls))
}

func TestSubmitTransactionReusesToken(t *testing.T) {
	var tokenCalls int32
	var interactionCalls int32
	var participantCalls int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			atomic.AddInt32(&tokenCalls, 1)
			json.NewEncoder(w).Encode(tokenResponse{AccessToken: "token-reuse", ExpiresIn: 3600, TokenType: "Bearer"})
		case "/v1/interactions":
			atomic.AddInt32(&interactionCalls, 1)
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "int",
						"channelId":           "chan",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			json.NewEncoder(w).Encode(payload)
		case "/v1/participants":
			atomic.AddInt32(&participantCalls, 1)
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			json.NewEncoder(w).Encode(payload)
		case "/v1/transactions":
			now := time.Now().UTC()
			json.NewEncoder(w).Encode(transactionResponse{
				ID:            "txn",
				CorrelationID: "one",
				ChannelID:     "chan",
				InteractionID: "int",
				SourceDID:     "did:example:source",
				TargetDID:     "did:example:target",
				Signature:     operon.Signature{Algorithm: "EdDSA", Value: "c2lnbmF0dXJl"},
				PayloadHash:   "hash",
				Status:        "received",
				Timestamp:     now,
				CreatedAt:     now,
				UpdatedAt:     now,
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler)
	defer cleanup()

	req := operon.TransactionRequest{
		CorrelationID: "one",
		ChannelID:     "chan",
		InteractionID: "int",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Payload:       []byte("payload"),
		Signature:     operon.Signature{Algorithm: "EdDSA", Value: "c2lnbmF0dXJl"},
	}

	ctx := context.Background()

	_, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)

	req.CorrelationID = "two"
	_, err = client.SubmitTransaction(ctx, req)
	require.NoError(t, err)

	require.Equal(t, int32(1), atomic.LoadInt32(&tokenCalls))
	require.Equal(t, int32(1), atomic.LoadInt32(&interactionCalls))
	require.Equal(t, int32(1), atomic.LoadInt32(&participantCalls))
}

func TestSubmitTransactionAutoFillsDIDs(t *testing.T) {
	var captured transactionSubmission
	signatureValue := base64.StdEncoding.EncodeToString([]byte("signed"))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			json.NewEncoder(w).Encode(tokenResponse{AccessToken: "token-abc", TokenType: "Bearer", ExpiresIn: 3600})
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "interaction-123",
						"channelId":           "channel-from-interaction",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			json.NewEncoder(w).Encode(payload)
		case "/v1/participants":
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			json.NewEncoder(w).Encode(payload)
		case "/v1/dids/self/sign":
			var body map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			json.NewEncoder(w).Encode(map[string]any{
				"signature": map[string]string{
					"algorithm": "EdDSA",
					"value":     signatureValue,
					"keyId":     "did:example:source#keys-1",
				},
			})
		case "/v1/transactions":
			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
			now := time.Now().UTC()
			json.NewEncoder(w).Encode(transactionResponse{
				ID:            "txn",
				CorrelationID: captured.CorrelationID,
				ChannelID:     captured.ChannelID,
				InteractionID: captured.InteractionID,
				SourceDID:     captured.SourceDID,
				TargetDID:     captured.TargetDID,
				Signature:     captured.Signature,
				PayloadHash:   captured.PayloadHash,
				Status:        "received",
				Timestamp:     now,
				CreatedAt:     now,
				UpdatedAt:     now,
			})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler)
	defer cleanup()

	req := operon.TransactionRequest{
		CorrelationID: "auto-correlation",
		InteractionID: "interaction-123",
		Payload:       []byte("payload"),
	}

	_, err := client.SubmitTransaction(context.Background(), req)
	require.NoError(t, err)

	require.Equal(t, "channel-from-interaction", captured.ChannelID)
	require.Equal(t, "did:example:source", captured.SourceDID)
	require.Equal(t, "did:example:target", captured.TargetDID)
	require.Equal(t, operon.AlgorithmEd25519, captured.Signature.Algorithm)
	require.Equal(t, signatureValue, captured.Signature.Value)
	require.Equal(t, "did:example:source#keys-1", captured.Signature.KeyID)
}

func TestSubmitTransactionAPIErrorsSurface(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			json.NewEncoder(w).Encode(tokenResponse{AccessToken: "token", TokenType: "Bearer", ExpiresIn: 3600})
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "int",
						"channelId":           "chan",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			json.NewEncoder(w).Encode(payload)
		case "/v1/participants":
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			json.NewEncoder(w).Encode(payload)
		case "/v1/transactions":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"code":"VALIDATION_ERROR","message":"invalid"}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler)
	defer cleanup()

	req := operon.TransactionRequest{
		CorrelationID: "one",
		ChannelID:     "chan",
		InteractionID: "int",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Payload:       []byte("payload"),
		Signature:     operon.Signature{Algorithm: "EdDSA", Value: "c2lnbmF0dXJl"},
	}

	_, err := client.SubmitTransaction(context.Background(), req)
	require.Error(t, err)

	apiErr, ok := err.(*operon.APIError)
	require.True(t, ok)
	require.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
	require.Equal(t, "VALIDATION_ERROR", apiErr.Code)
}

func TestInteractionsAccessor(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			json.NewEncoder(w).Encode(tokenResponse{AccessToken: "token", TokenType: "Bearer", ExpiresIn: 3600})
		case "/v1/interactions":
			payload := map[string]any{
				"data": []map[string]any{
					{
						"id":                  "interaction-1",
						"channelId":           "channel-1",
						"sourceParticipantId": "participant-src",
						"targetParticipantId": "participant-tgt",
					},
				},
			}
			json.NewEncoder(w).Encode(payload)
		case "/v1/participants":
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			json.NewEncoder(w).Encode(payload)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler)
	defer cleanup()

	list, err := client.Interactions(context.Background())
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "interaction-1", list[0].ID)
	require.Equal(t, "did:example:source", list[0].SourceDID)
	require.Equal(t, "did:example:target", list[0].TargetDID)

	participants, err := client.Participants(context.Background())
	require.NoError(t, err)
	require.Len(t, participants, 2)
}

func TestSubmitTransactionTokenError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"code":"INVALID_CLIENT","message":"bad creds"}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler)
	defer cleanup()

	req := operon.TransactionRequest{
		CorrelationID: "one",
		ChannelID:     "chan",
		InteractionID: "int",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Payload:       []byte("payload"),
		Signature:     operon.Signature{Algorithm: "EdDSA", Value: "c2lnbmF0dXJl"},
	}

	_, err := client.SubmitTransaction(context.Background(), req)
	require.Error(t, err)
}

func TestTransactionValidateForSubmit(t *testing.T) {
	req := operon.TransactionRequest{}
	require.Error(t, req.ValidateForSubmit())

	req = operon.TransactionRequest{
		CorrelationID: "1",
		ChannelID:     "chan",
		InteractionID: "int",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Payload:       []byte("abc"),
		Signature:     operon.Signature{Algorithm: "EdDSA", Value: "c2lnbmF0dXJl"},
	}
	require.NoError(t, req.ValidateForSubmit())
}

func TestConfigDefaultsBaseAndToken(t *testing.T) {
	cfg := operon.Config{
		ClientID:     "client",
		ClientSecret: "secret",
	}

	require.NoError(t, (&cfg).Validate())
	require.Equal(t, operon.DefaultBaseURL, cfg.BaseURL)
	require.Equal(t, operon.DefaultTokenURL, cfg.TokenURL)
}
