package signing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSelfSignerSign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer token", r.Header.Get("Authorization"))

		payload := map[string]any{
			"signature": map[string]any{
				"algorithm": "EdDSA",
				"value":     "c2ln",
				"keyId":     "did:example:source#keys-1",
			},
		}
		require.NoError(t, json.NewEncoder(w).Encode(payload))
	}))
	defer srv.Close()

	signer, err := NewSelfSigner(Config{BaseURL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result, err := signer.Sign(ctx, "token", "hash", "EdDSA")
	require.NoError(t, err)
	require.Equal(t, "c2ln", result.Value)
}

func TestDisabledSigner(t *testing.T) {
	signer := DisabledSigner{}
	_, err := signer.Sign(context.Background(), "token", "hash", "EdDSA")
	require.ErrorIs(t, err, ErrSigningDisabled)
}

func TestNewSelfSignerValidation(t *testing.T) {
	_, err := NewSelfSigner(Config{})
	require.Error(t, err)

	_, err = NewSelfSigner(Config{BaseURL: "https://example.com", HTTPClient: nil})
	require.Error(t, err)
}

func TestSelfSignerErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("{\"message\":\"invalid\"}"))
	}))
	defer srv.Close()

	signer, err := NewSelfSigner(Config{BaseURL: srv.URL, HTTPClient: srv.Client()})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = signer.Sign(ctx, "token", "hash", "EdDSA")
	require.Error(t, err)
}
