package operon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/auth"
)

// SessionValidationConfig controls how PAT validation requests are issued.
type SessionValidationConfig struct {
	BaseURL    string
	HTTPClient HTTPClient
}

// SessionInfo represents session metadata derived from a PAT plus server-side validation.
type SessionInfo struct {
	UserID           string
	Email            string
	Name             string
	CustomerID       string
	Roles            []string
	FeatureFlags     map[string]interface{}
	ChannelID        string
	WorkspaceID      string
	ParticipantDID   string
	ParticipantID    string
	ClientID         string
	SessionID        string
	ExpiresAt        time.Time
	ExpiresInSeconds int
}

// ValidateSession verifies the provided PAT against the Operon client API and returns
// normalized session metadata used by sandbox-api.
func ValidateSession(ctx context.Context, cfg SessionValidationConfig, pat string) (SessionInfo, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return SessionInfo{}, errors.New("pat is required")
	}

	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/session/validate", nil)
	if err != nil {
		return SessionInfo{}, fmt.Errorf("build validation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pat)

	resp, err := httpClient.Do(req)
	if err != nil {
		return SessionInfo{}, fmt.Errorf("perform validation request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return SessionInfo{}, decodeErr
		}
		return SessionInfo{}, apiErr
	}

	var payload struct {
		UserID       string                 `json:"user_id"`
		Email        string                 `json:"email"`
		Name         string                 `json:"name"`
		CustomerID   string                 `json:"customer_id"`
		Roles        []string               `json:"roles"`
		FeatureFlags map[string]interface{} `json:"feature_flags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return SessionInfo{}, fmt.Errorf("decode validation response: %w", err)
	}

	claims := auth.DecodeTokenClaims(pat)

	var expiresAt time.Time
	if claims.ExpiresAt > 0 {
		expiresAt = time.Unix(claims.ExpiresAt, 0).UTC()
	}

	expiresIn := 0
	if !expiresAt.IsZero() {
		remaining := time.Until(expiresAt).Round(time.Second)
		if remaining > 0 {
			expiresIn = int(remaining / time.Second)
		}
	}

	result := SessionInfo{
		UserID:           payload.UserID,
		Email:            payload.Email,
		Name:             payload.Name,
		CustomerID:       payload.CustomerID,
		Roles:            append([]string(nil), payload.Roles...),
		FeatureFlags:     payload.FeatureFlags,
		ChannelID:        claims.ChannelID,
		WorkspaceID:      claims.WorkspaceID,
		ParticipantDID:   claims.ParticipantDID,
		ParticipantID:    claims.ParticipantID,
		ClientID:         firstNonEmpty(claims.ClientID, claims.AuthorizedParty),
		SessionID:        claims.SessionID,
		ExpiresAt:        expiresAt,
		ExpiresInSeconds: expiresIn,
	}

	if result.FeatureFlags == nil {
		result.FeatureFlags = map[string]interface{}{}
	}

	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
