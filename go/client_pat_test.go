package operon_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	operon "github.com/operon-cloud/operon-sdk/go"
)

func TestSignHashWithPATSuccess(t *testing.T) {
	pat := newTokenWithClaims(map[string]any{
		"participant_did": "did:example:source",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/dids/self/sign", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer "+pat, r.Header.Get("Authorization"))

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "SHA-256", body["hashAlgorithm"])
		require.Equal(t, "hAsnFFCtdjc0TjjQWL0LyKHwnz5rZsschA1YWUVUcB4", body["payloadHash"])
		require.Equal(t, "EdDSA", body["algorithm"])

		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"signature": map[string]any{
				"algorithm": "EdDSA",
				"value":     "signed",
				"keyId":     "did:example:source#keys-1",
			},
		}))
	}))
	defer server.Close()

	ctx := context.Background()
	sig, err := operon.SignHashWithPAT(ctx, operon.ClientAPIConfig{BaseURL: server.URL}, pat, "hAsnFFCtdjc0TjjQWL0LyKHwnz5rZsschA1YWUVUcB4", "EdDSA")
	require.NoError(t, err)
	require.Equal(t, "EdDSA", sig.Algorithm)
	require.Equal(t, "signed", sig.Value)
	require.Equal(t, "did:example:source#keys-1", sig.KeyID)
}

func TestSignHashWithPATAPIFailure(t *testing.T) {
	pat := newToken("did:example:source")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "UNAUTHORIZED", "message": "unauthorized"})
	}))
	defer server.Close()

	_, err := operon.SignHashWithPAT(context.Background(), operon.ClientAPIConfig{BaseURL: server.URL}, pat, "hAsnFFCtdjc0TjjQWL0LyKHwnz5rZsschA1YWUVUcB4", "EdDSA")
	require.Error(t, err)
	if apiErr, ok := err.(*operon.APIError); ok {
		require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
		require.Equal(t, "UNAUTHORIZED", apiErr.Code)
	} else {
		t.Fatalf("expected APIError, got %T", err)
	}
}

func TestSubmitTransactionWithPATSuccess(t *testing.T) {
	pat := newTokenWithClaims(map[string]any{
		"participant_did": "did:example:source",
		"channel_id":      "channel-123",
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/transactions", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer "+pat, r.Header.Get("Authorization"))

		payloadBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var body map[string]any
		require.NoError(t, json.Unmarshal(payloadBytes, &body))
		_, hasPayloadData := body["payloadData"]
		require.False(t, hasPayloadData, "payloadData must not be transmitted")
		require.Equal(t, "channel-123", body["channelId"])
		require.Equal(t, "interaction-xyz", body["interactionId"])
		require.Equal(t, "did:example:source", body["sourceDid"])
		require.Equal(t, "did:example:target", body["targetDid"])
		require.Equal(t, "signed", body["signature"].(map[string]any)["value"])

		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"id":            "txn-123",
			"correlationId": "corr-1",
			"channelId":     "channel-123",
			"interactionId": "interaction-xyz",
			"timestamp":     time.Now().UTC(),
			"sourceDid":     "did:example:source",
			"targetDid":     "did:example:target",
			"signature": map[string]any{
				"algorithm": "EdDSA",
				"value":     "signed",
				"keyId":     "did:example:source#keys-1",
			},
			"payloadHash": "hAsnFFCtdjc0TjjQWL0LyKHwnz5rZsschA1YWUVUcB4",
			"status":      "received",
		}))
	}))
	defer server.Close()

	req := operon.TransactionRequest{
		CorrelationID: "corr-1",
		ChannelID:     "channel-123",
		InteractionID: "interaction-xyz",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Signature: operon.Signature{
			Algorithm: "EdDSA",
			Value:     "signed",
			KeyID:     "did:example:source#keys-1",
		},
		PayloadHash: "hAsnFFCtdjc0TjjQWL0LyKHwnz5rZsschA1YWUVUcB4",
	}

	txn, err := operon.SubmitTransactionWithPAT(context.Background(), operon.ClientAPIConfig{BaseURL: server.URL}, pat, req)
	require.NoError(t, err)
	require.Equal(t, "txn-123", txn.ID)
	require.Equal(t, "corr-1", txn.CorrelationID)
}

func TestSubmitTransactionWithPATAPIFailure(t *testing.T) {
	pat := newToken("did:example:source")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "FORBIDDEN", "message": "forbidden"})
	}))
	defer server.Close()

	req := operon.TransactionRequest{
		CorrelationID: "corr-1",
		ChannelID:     "channel-123",
		InteractionID: "interaction-xyz",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Signature: operon.Signature{
			Algorithm: "EdDSA",
			Value:     "signed",
		},
		PayloadHash: "hAsnFFCtdjc0TjjQWL0LyKHwnz5rZsschA1YWUVUcB4",
	}

	_, err := operon.SubmitTransactionWithPAT(context.Background(), operon.ClientAPIConfig{BaseURL: server.URL}, pat, req)
	require.Error(t, err)
	if apiErr, ok := err.(*operon.APIError); ok {
		require.Equal(t, http.StatusForbidden, apiErr.StatusCode)
		require.Equal(t, "FORBIDDEN", apiErr.Code)
	} else {
		t.Fatalf("expected APIError, got %T", err)
	}
}

func TestValidateSignatureWithPATSuccess(t *testing.T) {
	pat := newToken("did:example:source")
	payload := []byte(`{"message":"hello"}`)
	hash := sha256.Sum256(payload)
	payloadHash := base64.RawURLEncoding.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/dids/did:example:source/signature/verify", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer "+pat, r.Header.Get("Authorization"))
		require.Equal(t, payloadHash, r.Header.Get(operon.HeaderOperonPayloadHash))
		require.Equal(t, "did:example:source", r.Header.Get(operon.HeaderOperonDID))
		require.Equal(t, "signed-value", r.Header.Get(operon.HeaderOperonSignature))
		require.Equal(t, "did:example:source#key-1", r.Header.Get(operon.HeaderOperonSignatureKey))
		require.Equal(t, "EdDSA", r.Header.Get(operon.HeaderOperonSignatureAlgo))

		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"status":      "VALID",
			"message":     "Signature valid",
			"did":         "did:example:source",
			"payloadHash": payloadHash,
			"algorithm":   "EdDSA",
			"keyId":       "did:example:source#key-1",
		}))
	}))
	defer server.Close()

	headers := operon.OperonHeaders{
		operon.HeaderOperonDID:           "did:example:source",
		operon.HeaderOperonPayloadHash:   payloadHash,
		operon.HeaderOperonSignature:     "signed-value",
		operon.HeaderOperonSignatureKey:  "did:example:source#key-1",
		operon.HeaderOperonSignatureAlgo: "EdDSA",
	}

	result, err := operon.ValidateSignatureWithPAT(context.Background(), operon.ClientAPIConfig{BaseURL: server.URL}, pat, payload, headers)
	require.NoError(t, err)
	require.Equal(t, "VALID", result.Status)
	require.Equal(t, "Signature valid", result.Message)
	require.Equal(t, "did:example:source", result.DID)
	require.Equal(t, payloadHash, result.PayloadHash)
	require.Equal(t, "EdDSA", result.Algorithm)
	require.Equal(t, "did:example:source#key-1", result.KeyID)
}

func TestValidateSignatureWithPATHashMismatch(t *testing.T) {
	pat := newToken("did:example:source")
	payload := []byte(`{"message":"hello"}`)
	headers := operon.OperonHeaders{
		operon.HeaderOperonDID:           "did:example:source",
		operon.HeaderOperonPayloadHash:   "invalid-hash",
		operon.HeaderOperonSignature:     "signed-value",
		operon.HeaderOperonSignatureKey:  "did:example:source#key-1",
		operon.HeaderOperonSignatureAlgo: "EdDSA",
	}

	_, err := operon.ValidateSignatureWithPAT(context.Background(), operon.ClientAPIConfig{BaseURL: "https://example.com"}, pat, payload, headers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "payload hash mismatch")
}

func TestValidateSignatureWithPATAPIFailure(t *testing.T) {
	pat := newToken("did:example:source")
	payload := []byte(`{"message":"hello"}`)
	hash := sha256.Sum256(payload)
	payloadHash := base64.RawURLEncoding.EncodeToString(hash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "UNAUTHORIZED", "message": "invalid"})
	}))
	defer server.Close()

	headers := operon.OperonHeaders{
		operon.HeaderOperonDID:           "did:example:source",
		operon.HeaderOperonPayloadHash:   payloadHash,
		operon.HeaderOperonSignature:     "signed-value",
		operon.HeaderOperonSignatureKey:  "did:example:source#key-1",
		operon.HeaderOperonSignatureAlgo: "EdDSA",
	}

	_, err := operon.ValidateSignatureWithPAT(context.Background(), operon.ClientAPIConfig{BaseURL: server.URL}, pat, payload, headers)
	require.Error(t, err)
	if apiErr, ok := err.(*operon.APIError); ok {
		require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
		require.Equal(t, "UNAUTHORIZED", apiErr.Code)
	} else {
		t.Fatalf("expected APIError, got %T", err)
	}
}

func TestDecodePayloadBase64(t *testing.T) {
	decoded, err := operon.DecodePayloadBase64("aGVsbG8=")
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), decoded)

	empty, err := operon.DecodePayloadBase64("  ")
	require.NoError(t, err)
	require.Nil(t, empty)
}
