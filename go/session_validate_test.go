package operon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateSessionSuccess(t *testing.T) {
	exp := time.Now().Add(15 * time.Minute).Unix()
	pat := makeTestPAT(map[string]interface{}{
		"participant_did": "did:operon:demo",
		"participant_id":  "prtp-123",
		"client_id":       "client-123",
		"azp":             "app-123",
		"channel_id":      "chnl-123",
		"customer_id":     "cust-123",
		"workspace_id":    "wksp-123",
		"session_id":      "sess-123",
		"exp":             exp,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+pat {
			t.Fatalf("expected Authorization header, got %q", got)
		}
		if r.URL.Path != "/v1/session/validate" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"user_id":       "user-123",
			"email":         "demo@operon.cloud",
			"name":          "Demo User",
			"customer_id":   "cust-123",
			"roles":         []string{"sandbox"},
			"feature_flags": map[string]interface{}{"demo": true},
		})
	}))
	defer server.Close()

	info, err := ValidateSession(context.Background(), SessionValidationConfig{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	}, pat)
	if err != nil {
		t.Fatalf("ValidateSession returned error: %v", err)
	}

	if info.UserID != "user-123" || info.CustomerID != "cust-123" {
		t.Fatalf("unexpected session info: %#v", info)
	}
	if info.ChannelID != "chnl-123" || info.ParticipantDID != "did:operon:demo" {
		t.Fatalf("expected channel and DID from claims, got %#v", info)
	}
	if info.SessionID != "sess-123" || info.ParticipantID != "prtp-123" {
		t.Fatalf("unexpected session id: %s", info.SessionID)
	}
	if info.ClientID != "client-123" {
		t.Fatalf("expected client id, got %s", info.ClientID)
	}
	if info.ExpiresAt.IsZero() {
		t.Fatalf("expected expiry to be populated")
	}
	if info.ExpiresInSeconds <= 0 {
		t.Fatalf("expected positive expiresIn, got %d", info.ExpiresInSeconds)
	}
}

func TestValidateSessionUnauthorized(t *testing.T) {
	pat := makeTestPAT(map[string]interface{}{"exp": time.Now().Add(time.Hour).Unix()})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":    "SESSION_EXPIRED",
			"message": "session expired",
		})
	}))
	defer server.Close()

	_, err := ValidateSession(context.Background(), SessionValidationConfig{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	}, pat)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateSessionRequiresPAT(t *testing.T) {
	_, err := ValidateSession(context.Background(), SessionValidationConfig{}, " ")
	if err == nil {
		t.Fatalf("expected error for empty PAT")
	}
}

func makeTestPAT(payload map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	bodyBytes, _ := json.Marshal(payload)
	body := base64.RawURLEncoding.EncodeToString(bodyBytes)
	return header + "." + body + ".signature"
}
