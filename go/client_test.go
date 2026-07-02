package operon_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operon "github.com/operon-cloud/operon-sdk/go"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type transactionSubmission struct {
	CorrelationID               string           `json:"correlationId"`
	WorkstreamID                string           `json:"workstreamId"`
	InteractionID               string           `json:"interactionId"`
	Timestamp                   string           `json:"timestamp"`
	SourceDID                   string           `json:"sourceDid"`
	TargetDID                   string           `json:"targetDid"`
	ROIBaseCost                 int              `json:"roiBaseCost,omitempty"`
	ROIBaseTime                 int              `json:"roiBaseTime,omitempty"`
	ROICostSaving               int              `json:"roiCostSaving,omitempty"`
	ROITimeSaving               int              `json:"roiTimeSaving,omitempty"`
	ActiveTimeSeconds           *int             `json:"activeTimeSeconds,omitempty"`
	StateID                     string           `json:"stateId,omitempty"`
	StateLabel                  string           `json:"stateLabel,omitempty"`
	PayloadHash                 string           `json:"payloadHash"`
	Signature                   operon.Signature `json:"signature"`
	Tags                        []string         `json:"tags,omitempty"`
	Label                       string           `json:"label,omitempty"`
	ActorExternalID             string           `json:"actorExternalId,omitempty"`
	ActorExternalDisplayName    string           `json:"actorExternalDisplayName,omitempty"`
	ActorExternalSource         string           `json:"actorExternalSource,omitempty"`
	AssigneeExternalID          string           `json:"assigneeExternalId,omitempty"`
	AssigneeExternalDisplayName string           `json:"assigneeExternalDisplayName,omitempty"`
	AssigneeExternalSource      string           `json:"assigneeExternalSource,omitempty"`
	CustomerID                  string           `json:"customerId,omitempty"`
	WorkspaceID                 string           `json:"workspaceId,omitempty"`
	CreatedBy                   string           `json:"createdBy,omitempty"`
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
	if cfg.TokenProvider == nil {
		if cfg.ClientID == "" {
			cfg.ClientID = "test-client"
		}
		if cfg.ClientSecret == "" {
			cfg.ClientSecret = "test-secret"
		}
	}

	client, err := operon.NewClient(cfg)
	require.NoError(t, err)

	cleanup := func() {
		require.NoError(t, client.Close())
		srv.Close()
	}

	return client, cleanup
}

type rotatingTokenProvider struct {
	tokens []operon.Token
	err    error
	calls  atomic.Int32
}

func (p *rotatingTokenProvider) Token(context.Context) (operon.Token, error) {
	if p.err != nil {
		return operon.Token{}, p.err
	}
	if len(p.tokens) == 0 {
		return operon.Token{}, fmt.Errorf("no tokens configured")
	}
	call := int(p.calls.Add(1)) - 1
	if call >= len(p.tokens) {
		call = len(p.tokens) - 1
	}
	return p.tokens[call], nil
}

func TestClientSubmitTransactionWithInjectedTokenProvider(t *testing.T) {
	token := newTokenWithClaims(map[string]any{
		"participant_did": "did:example:source",
		"workstream_id":   "wstr-injected",
		"customer_id":     "cust-1",
		"workspace_id":    "wksp-1",
	})
	provider := &rotatingTokenProvider{tokens: []operon.Token{{
		AccessToken:    token,
		ExpiresAt:      time.Now().Add(time.Hour),
		ParticipantDID: "did:example:source",
		WorkstreamID:   "wstr-injected",
		CustomerID:     "cust-1",
		WorkspaceID:    "wksp-1",
	}}}

	var signAuth string
	var submitAuth string
	var captured transactionSubmission

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			t.Fatalf("token endpoint should not be called in injected-token mode")
		case "/v1/interactions":
			require.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
			payload := map[string]any{
				"data": []map[string]any{{
					"id":                  "intr-injected",
					"workstreamId":        "wstr-injected",
					"sourceParticipantId": "participant-src",
					"targetParticipantId": "participant-tgt",
				}},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/participants":
			require.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
			payload := map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		case "/v1/dids/self/sign":
			signAuth = r.Header.Get("Authorization")
			require.Equal(t, "Bearer "+token, signAuth)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"signature": map[string]any{
					"algorithm": operon.AlgorithmEd25519,
					"value":     "injected-signature",
					"keyId":     "did:example:source#keys-1",
				},
			}))
		case "/v1/transactions":
			submitAuth = r.Header.Get("Authorization")
			require.Equal(t, "Bearer "+token, submitAuth)
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var bodyMap map[string]any
			require.NoError(t, json.Unmarshal(body, &bodyMap))
			require.NotContains(t, bodyMap, "payloadData")
			require.NotContains(t, bodyMap, "sourceCode")
			require.NotContains(t, bodyMap, "stateSourceCode")
			require.NotContains(t, bodyMap, "stateId")
			require.NotContains(t, bodyMap, "stateLabel")
			require.NoError(t, json.Unmarshal(body, &captured))

			now := time.Now().UTC()
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"id":            "txn-injected",
				"correlationId": captured.CorrelationID,
				"workstreamId":  captured.WorkstreamID,
				"interactionId": captured.InteractionID,
				"sourceDid":     captured.SourceDID,
				"targetDid":     captured.TargetDID,
				"signature":     captured.Signature,
				"payloadHash":   captured.PayloadHash,
				"status":        "received",
				"timestamp":     now,
				"createdAt":     now,
				"updatedAt":     now,
			}))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{TokenProvider: provider})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	txn, err := client.SubmitTransaction(ctx, operon.TransactionRequest{
		CorrelationID: "corr-injected",
		InteractionID: "intr-injected",
		Payload:       []byte(`{"event":"submitted"}`),
	})
	require.NoError(t, err)
	require.Equal(t, "txn-injected", txn.ID)
	require.Equal(t, "wstr-injected", captured.WorkstreamID)
	require.Equal(t, "did:example:source", captured.SourceDID)
	require.Equal(t, "did:example:target", captured.TargetDID)
	require.Equal(t, signAuth, submitAuth)
}

func TestClientSubmitTransactionUsesSameInjectedTokenForSignAndSubmit(t *testing.T) {
	tokens := make([]operon.Token, 0, 4)
	for i := 1; i <= 4; i++ {
		value := newTokenWithClaims(map[string]any{
			"participant_did": "did:example:source",
			"workstream_id":   "wstr-injected",
			"token_index":     i,
		})
		tokens = append(tokens, operon.Token{
			AccessToken:    value,
			ExpiresAt:      time.Now().Add(time.Hour),
			ParticipantDID: "did:example:source",
			WorkstreamID:   "wstr-injected",
		})
	}
	provider := &rotatingTokenProvider{tokens: tokens}

	var signAuth string
	var submitAuth string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/interactions":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":                  "intr-injected",
					"workstreamId":        "wstr-injected",
					"sourceParticipantId": "participant-src",
					"targetParticipantId": "participant-tgt",
				}},
			}))
		case "/v1/participants":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}))
		case "/v1/dids/self/sign":
			signAuth = r.Header.Get("Authorization")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"signature": map[string]any{
					"algorithm": operon.AlgorithmEd25519,
					"value":     "same-token-signature",
				},
			}))
		case "/v1/transactions":
			submitAuth = r.Header.Get("Authorization")
			var captured transactionSubmission
			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
			now := time.Now().UTC()
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"id":            "txn-same-token",
				"correlationId": captured.CorrelationID,
				"workstreamId":  captured.WorkstreamID,
				"interactionId": captured.InteractionID,
				"sourceDid":     captured.SourceDID,
				"targetDid":     captured.TargetDID,
				"signature":     captured.Signature,
				"payloadHash":   captured.PayloadHash,
				"status":        "received",
				"timestamp":     now,
				"createdAt":     now,
				"updatedAt":     now,
			}))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{TokenProvider: provider})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.SubmitTransaction(ctx, operon.TransactionRequest{
		CorrelationID: "corr-same-token",
		InteractionID: "intr-injected",
		Payload:       []byte("payload"),
	})
	require.NoError(t, err)
	require.NotEmpty(t, signAuth)
	require.Equal(t, signAuth, submitAuth)
}

func TestClientSubmitTransactionWithInjectedTokenRequiresParticipantDIDForSelfSigning(t *testing.T) {
	token := newTokenWithoutParticipantDID()
	provider := &rotatingTokenProvider{tokens: []operon.Token{{
		AccessToken:  token,
		ExpiresAt:    time.Now().Add(time.Hour),
		WorkstreamID: "wstr-injected",
	}}}
	var signCalls atomic.Int32
	var submitCalls atomic.Int32

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/interactions":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"id":                  "intr-injected",
					"workstreamId":        "wstr-injected",
					"sourceParticipantId": "participant-src",
					"targetParticipantId": "participant-tgt",
				}},
			}))
		case "/v1/participants":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"id": "participant-src", "did": "did:example:source"},
					{"id": "participant-tgt", "did": "did:example:target"},
				},
			}))
		case "/v1/dids/self/sign":
			signCalls.Add(1)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"signature": map[string]any{
					"algorithm": operon.AlgorithmEd25519,
					"value":     "unexpected-signature",
				},
			}))
		case "/v1/transactions":
			submitCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{TokenProvider: provider})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.SubmitTransaction(ctx, operon.TransactionRequest{
		CorrelationID: "corr-missing-did",
		InteractionID: "intr-injected",
		Payload:       []byte("payload"),
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "participant DID unavailable on access token")
	require.Equal(t, int32(0), signCalls.Load())
	require.Equal(t, int32(0), submitCalls.Load())
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
						"workstreamId":        "channel-abc",
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

			payloadBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)

			var payloadMap map[string]any
			require.NoError(t, json.Unmarshal(payloadBytes, &payloadMap))
			_, hasPayloadData := payloadMap["payloadData"]
			require.False(t, hasPayloadData, "payloadData must not be transmitted")

			require.NoError(t, json.Unmarshal(payloadBytes, &captured))

			now := time.Now().UTC()
			response := map[string]any{
				"id":            "txn-123",
				"correlationId": captured.CorrelationID,
				"workstreamId":  captured.WorkstreamID,
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
	activeTimeSeconds := 42
	req.ActiveTimeSeconds = &activeTimeSeconds

	txn, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "txn-123", txn.ID)
	require.Equal(t, "received", txn.Status)
	require.Equal(t, "channel-abc", txn.WorkstreamID)
	require.Equal(t, "did:example:target", txn.TargetDID)
	require.Equal(t, []string{"env:demo"}, captured.Tags)
	require.NotNil(t, captured.ActiveTimeSeconds)
	require.Equal(t, 42, *captured.ActiveTimeSeconds)
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
						"workstreamId":        "manual-channel",
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
			bodyBytes, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			var bodyMap map[string]any
			require.NoError(t, json.Unmarshal(bodyBytes, &bodyMap))
			require.NotContains(t, bodyMap, "sourceCode")
			require.NotContains(t, bodyMap, "stateSourceCode")

			var body transactionSubmission
			require.NoError(t, json.Unmarshal(bodyBytes, &body))
			require.Equal(t, "manual-signature", body.Signature.Value)
			require.Equal(t, "stat-review", body.StateID)
			require.Empty(t, body.StateLabel)
			require.Equal(t, 15, body.ROIBaseCost)
			require.Equal(t, 7, body.ROIBaseTime)
			require.Equal(t, 4, body.ROICostSaving)
			require.Equal(t, 2, body.ROITimeSaving)
			require.Equal(t, "agent-42", body.ActorExternalID)
			require.Equal(t, "Agent Smith", body.ActorExternalDisplayName)
			require.Equal(t, "salesforce", body.ActorExternalSource)
			require.Equal(t, "owner-77", body.AssigneeExternalID)
			require.Equal(t, "Owner Jones", body.AssigneeExternalDisplayName)
			require.Equal(t, "salesforce", body.AssigneeExternalSource)
			require.Equal(t, "cust-1", body.CustomerID)
			require.Equal(t, "wksp-1", body.WorkspaceID)
			require.Equal(t, "user-1", body.CreatedBy)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"id": "txn-456", "status": "received", "correlationId": body.CorrelationID, "workstreamId": body.WorkstreamID, "interactionId": body.InteractionID, "sourceDid": body.SourceDID, "targetDid": body.TargetDID, "stateId": body.StateID, "stateLabel": "Review", "timestamp": time.Now(), "createdAt": time.Now(), "updatedAt": time.Now(), "signature": map[string]any{"algorithm": body.Signature.Algorithm, "value": body.Signature.Value}}))
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
		WorkstreamID:  "manual-channel",
		InteractionID: "manual-interaction",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		StateID:       "stat-review",
		Payload:       []byte("payload"),
		Signature: operon.Signature{
			Algorithm: operon.AlgorithmEd25519,
			Value:     "manual-signature",
			KeyID:     "did:example:source#keys-1",
		},
		ROIBaseCost:                 15,
		ROIBaseTime:                 7,
		ROICostSaving:               4,
		ROITimeSaving:               2,
		ActorExternalID:             "agent-42",
		ActorExternalDisplayName:    "Agent Smith",
		ActorExternalSource:         "salesforce",
		AssigneeExternalID:          "owner-77",
		AssigneeExternalDisplayName: "Owner Jones",
		AssigneeExternalSource:      "salesforce",
		CustomerID:                  "cust-1",
		WorkspaceID:                 "wksp-1",
		CreatedBy:                   "user-1",
	}

	txn, err := client.SubmitTransaction(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "txn-456", txn.ID)
	require.Equal(t, "stat-review", txn.StateID)
	require.Equal(t, "Review", txn.StateLabel)
}

func TestGenerateSignatureHeadersUsesDefaultAlgorithm(t *testing.T) {
	payload := []byte("demo-payload")
	digest := sha256.Sum256(payload)
	expectedHash := base64.RawURLEncoding.EncodeToString(digest[:])

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:source"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/dids/self/sign":
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "Bearer "+newToken("did:example:source"), r.Header.Get("Authorization"))

			var requestBody map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&requestBody))
			require.Equal(t, expectedHash, requestBody["payloadHash"])
			require.Equal(t, "SHA-256", requestBody["hashAlgorithm"])
			require.Equal(t, operon.AlgorithmES256, requestBody["algorithm"])

			payload := map[string]any{
				"signature": map[string]any{
					"algorithm": operon.AlgorithmES256,
					"value":     "signed-value",
					"keyId":     "did:example:source#keys-1",
				},
			}
			require.NoError(t, json.NewEncoder(w).Encode(payload))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{SigningAlgorithm: operon.AlgorithmES256})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	headers, err := client.GenerateSignatureHeaders(ctx, payload, "")
	require.NoError(t, err)
	require.Equal(t, "did:example:source", headers[operon.HeaderOperonDID])
	require.Equal(t, expectedHash, headers[operon.HeaderOperonPayloadHash])
	require.Equal(t, "signed-value", headers[operon.HeaderOperonSignature])
	require.Equal(t, operon.AlgorithmES256, headers[operon.HeaderOperonSignatureAlgo])
	require.Equal(t, "did:example:source#keys-1", headers[operon.HeaderOperonSignatureKey])
}

func TestGenerateSignatureHeadersOverridesAlgorithm(t *testing.T) {
	payload := "override-payload"
	digest := sha256.Sum256([]byte(payload))
	expectedHash := base64.RawURLEncoding.EncodeToString(digest[:])

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:source"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/dids/self/sign":
			var requestBody map[string]string
			require.NoError(t, json.NewDecoder(r.Body).Decode(&requestBody))
			require.Equal(t, expectedHash, requestBody["payloadHash"])
			require.Equal(t, operon.AlgorithmES256K, requestBody["algorithm"])

			payload := map[string]any{
				"signature": map[string]any{
					"algorithm": operon.AlgorithmES256K,
					"value":     "override-signature",
					"keyId":     "",
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

	headers, err := client.GenerateSignatureHeadersFromString(ctx, payload, operon.AlgorithmES256K)
	require.NoError(t, err)
	require.Equal(t, expectedHash, headers[operon.HeaderOperonPayloadHash])
	require.Equal(t, operon.AlgorithmES256K, headers[operon.HeaderOperonSignatureAlgo])
	require.Equal(t, "override-signature", headers[operon.HeaderOperonSignature])
	require.Equal(t, "did:example:source#keys-1", headers[operon.HeaderOperonSignatureKey])
}

func TestGenerateSignatureHeadersRequiresParticipantDID(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newTokenWithoutParticipantDID(), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case "/v1/dids/self/sign":
			payload := map[string]any{
				"signature": map[string]any{
					"algorithm": operon.AlgorithmEd25519,
					"value":     "any",
					"keyId":     "",
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

	_, err := client.GenerateSignatureHeaders(ctx, []byte("payload"), "")
	require.Error(t, err)
}

func TestValidateSignatureHeadersSuccess(t *testing.T) {
	payload := []byte(`{"demo":true}`)
	digest := sha256.Sum256(payload)
	expectedHash := base64.RawURLEncoding.EncodeToString(digest[:])

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:receiver"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case fmt.Sprintf("/v1/dids/%s/signature/verify", url.PathEscape("did:example:source")):
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, expectedHash, r.Header.Get(operon.HeaderOperonPayloadHash))
			require.Equal(t, "did:example:source", r.Header.Get(operon.HeaderOperonDID))
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.Equal(t, payload, body)

			respPayload := map[string]any{
				"status":      "VALID",
				"message":     "Signature verified successfully",
				"did":         "did:example:source",
				"payloadHash": expectedHash,
				"algorithm":   operon.AlgorithmES256,
				"keyId":       "did:example:source#keys-1",
			}
			require.NoError(t, json.NewEncoder(w).Encode(respPayload))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	headers := operon.OperonHeaders{
		operon.HeaderOperonDID:           "did:example:source",
		operon.HeaderOperonPayloadHash:   expectedHash,
		operon.HeaderOperonSignature:     "signed",
		operon.HeaderOperonSignatureKey:  "did:example:source#keys-1",
		operon.HeaderOperonSignatureAlgo: operon.AlgorithmES256,
	}

	result, err := client.ValidateSignatureHeaders(ctx, payload, headers)
	require.NoError(t, err)
	require.Equal(t, "VALID", result.Status)
	require.Equal(t, expectedHash, result.PayloadHash)
	require.Equal(t, operon.AlgorithmES256, result.Algorithm)
	require.Equal(t, "did:example:source#keys-1", result.KeyID)
}

func TestValidateSignatureHeadersRejectsHashMismatch(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:receiver"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		case fmt.Sprintf("/v1/dids/%s/signature/verify", url.PathEscape("did:example:source")):
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	headers := operon.OperonHeaders{
		operon.HeaderOperonDID:           "did:example:source",
		operon.HeaderOperonPayloadHash:   "mismatched",
		operon.HeaderOperonSignature:     "signed",
		operon.HeaderOperonSignatureKey:  "did:example:source#keys-1",
		operon.HeaderOperonSignatureAlgo: operon.AlgorithmES256,
	}

	_, err := client.ValidateSignatureHeaders(ctx, []byte("payload"), headers)
	require.Error(t, err)
}

func TestValidateSignatureHeadersRequiresHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			resp := tokenResponse{AccessToken: newToken("did:example:receiver"), TokenType: "Bearer", ExpiresIn: 3600}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	client, cleanup := newTestClient(t, handler, operon.Config{})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := client.ValidateSignatureHeaders(ctx, []byte("payload"), nil)
	require.Error(t, err)
}

func newTokenWithClaims(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		panic(fmt.Sprintf("marshal claims: %v", err))
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return header + "." + payload + ".signature"
}

func newToken(participantDID string) string {
	return newTokenWithClaims(map[string]any{"participant_did": participantDID})
}

func newTokenWithoutParticipantDID() string {
	return newTokenWithClaims(map[string]any{"client_id": "demo"})
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
						"workstreamId":        "channel-abc",
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

func TestReferenceFetchFailsWhenParticipantsFail(t *testing.T) {
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
						"workstreamId":        "channel-abc",
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

	require.NoError(t, client.Init(ctx))

	_, err := client.Participants(ctx)
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
						"workstreamId":        "channel-abc",
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
				"workstreamId":  body.WorkstreamID,
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

func TestReferenceFetchFailsWhenInteractionDecodeFails(t *testing.T) {
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

	require.NoError(t, client.Init(ctx))
	_, err := client.Interactions(ctx)
	require.Error(t, err)
}

func TestReferenceFetchFailsWhenParticipantDecodeFails(t *testing.T) {
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
						"workstreamId":        "channel-abc",
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

	require.NoError(t, client.Init(ctx))
	_, err := client.Participants(ctx)
	require.Error(t, err)
}

func TestReferenceFetchFailsWhenInteractionsFail(t *testing.T) {
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

	require.NoError(t, client.Init(ctx))
	_, err := client.Interactions(ctx)
	require.Error(t, err)
}
