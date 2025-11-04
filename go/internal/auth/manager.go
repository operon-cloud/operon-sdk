package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/httpx"
)

const defaultLeeway = 30 * time.Second

// Token captures an access token together with the derived participant DID (if
// available) and expiry metadata for proactive refresh decisions.
type Token struct {
	AccessToken    string
	ParticipantDID string
	ChannelID      string
	CustomerID     string
	WorkspaceID    string
	Email          string
	Name           string
	TenantIDs      []string
	Roles          []string
	MemberID       string
	SessionID      string
	OrgID          string
	Expiry         time.Time
}

// Provider exposes the contract for retrieving access tokens.
type Provider interface {
	Token(ctx context.Context) (Token, error)
}

// ClientCredentialsConfig defines the inputs required to mint tokens using the
// OAuth client credentials grant.
type ClientCredentialsConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scope        string
	Audience     []string
	HTTPClient   httpx.Doer
	Leeway       time.Duration
}

// ClientCredentialsManager implements Provider by minting and caching client
// credential tokens via the Operon identity broker.
type ClientCredentialsManager struct {
	tokenURL string
	body     tokenRequest
	clientID string
	secret   string
	scope    string
	audience []string
	http     httpx.Doer
	leeway   time.Duration
	legacy   bool

	mu     sync.Mutex
	cached *Token
}

// NewClientCredentialsManager builds a Provider that caches access tokens and
// refreshes them proactively before expiry.
func NewClientCredentialsManager(cfg ClientCredentialsConfig) (*ClientCredentialsManager, error) {
	if cfg.HTTPClient == nil {
		return nil, errors.New("HTTPClient is required")
	}
	if strings.TrimSpace(cfg.TokenURL) == "" {
		return nil, errors.New("TokenURL is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("ClientID is required")
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, errors.New("ClientSecret is required")
	}

	leeway := cfg.Leeway
	if leeway <= 0 {
		leeway = defaultLeeway
	}

	tokenURL := strings.TrimRight(cfg.TokenURL, "/")
	legacy := strings.Contains(tokenURL, "/v1/session/m2m")

	manager := &ClientCredentialsManager{
		tokenURL: tokenURL,
		body: tokenRequest{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			GrantType:    "client_credentials",
			Scope:        cfg.Scope,
			Audience:     cfg.Audience,
		},
		clientID: cfg.ClientID,
		secret:   cfg.ClientSecret,
		scope:    strings.TrimSpace(cfg.Scope),
		audience: cfg.Audience,
		http:     cfg.HTTPClient,
		leeway:   leeway,
		legacy:   legacy,
	}
	return manager, nil
}

// Token returns a cached access token, refreshing it as needed using the
// configured OAuth credentials.
func (m *ClientCredentialsManager) Token(ctx context.Context) (Token, error) {
	m.mu.Lock()
	if m.cached != nil && time.Until(m.cached.Expiry) > m.leeway {
		token := *m.cached
		m.mu.Unlock()
		return token, nil
	}
	m.mu.Unlock()

	fresh, err := m.fetchToken(ctx)
	if err != nil {
		return Token{}, err
	}

	m.mu.Lock()
	m.cached = &fresh
	m.mu.Unlock()
	return fresh, nil
}

func (m *ClientCredentialsManager) fetchToken(ctx context.Context) (Token, error) {
	var (
		req *http.Request
		err error
	)

	if m.legacy {
		req, err = httpx.NewJSONRequest(ctx, http.MethodPost, m.tokenURL, m.body)
		if err != nil {
			return Token{}, fmt.Errorf("build token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		if m.scope != "" {
			form.Set("scope", m.scope)
		}
		for _, aud := range m.audience {
			if trimmed := strings.TrimSpace(aud); trimmed != "" {
				form.Add("audience", trimmed)
			}
		}

		req, err = http.NewRequestWithContext(ctx, http.MethodPost, m.tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return Token{}, fmt.Errorf("build token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		credentials := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", m.clientID, m.secret)))
		req.Header.Set("Authorization", "Basic "+credentials)
	}

	resp, err := m.http.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return Token{}, decodeErr
		}
		return Token{}, apiErr
	}

	var payload tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return Token{}, fmt.Errorf("decode token response: %w", err)
	}

	accessToken := strings.TrimSpace(payload.AccessToken)
	if accessToken == "" {
		return Token{}, errors.New("token response missing access_token")
	}

	expiresIn := time.Duration(payload.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Minute
	}

	claims := DecodeTokenClaims(accessToken)

	token := Token{
		AccessToken:    accessToken,
		ParticipantDID: claims.ParticipantDID,
		ChannelID:      claims.ChannelID,
		CustomerID:     claims.CustomerID,
		WorkspaceID:    claims.WorkspaceID,
		Email:          claims.Email,
		Name:           claims.Name,
		TenantIDs:      append([]string(nil), claims.TenantIDs...),
		Roles:          append([]string(nil), claims.Roles...),
		MemberID:       claims.MemberID,
		SessionID:      claims.SessionID,
		OrgID:          claims.OrgID,
		Expiry:         time.Now().Add(expiresIn),
	}
	return token, nil
}

// tokenRequest mirrors the JSON payload expected by the identity broker for M2M token issuance.
type tokenRequest struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	GrantType    string   `json:"grant_type"`
	Scope        string   `json:"scope,omitempty"`
	Audience     []string `json:"audience,omitempty"`
}

// tokenResponse represents the JSON body returned by the identity broker.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Claims captures token fields used across the SDK.
type Claims struct {
	ParticipantDID  string   `json:"participant_did"`
	ChannelID       string   `json:"channel_id"`
	CustomerID      string   `json:"customer_id"`
	WorkspaceID     string   `json:"workspace_id"`
	Email           string   `json:"email"`
	Name            string   `json:"name"`
	TenantIDs       []string `json:"tenant_ids"`
	Roles           []string `json:"roles"`
	MemberID        string   `json:"member_id"`
	SessionID       string   `json:"session_id"`
	OrgID           string   `json:"org_id"`
	ParticipantID   string   `json:"participant_id"`
	ClientID        string   `json:"client_id"`
	AuthorizedParty string   `json:"azp"`
	ExpiresAt       int64    `json:"exp"`
}

// DecodeTokenClaims decodes the JWT payload and returns known Operon claims.
func DecodeTokenClaims(token string) Claims {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return Claims{}
	}

	decode := func(seg string) ([]byte, error) {
		if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
			return b, nil
		}
		return base64.StdEncoding.DecodeString(seg)
	}

	payload, err := decode(parts[1])
	if err != nil {
		return Claims{}
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}
	}
	return claims
}

func extractParticipantDID(token string) string {
	return DecodeTokenClaims(token).ParticipantDID
}
