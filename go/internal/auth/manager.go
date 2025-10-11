package auth

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/operonmaster/operon-sdk/go/internal/apierrors"
    "github.com/operonmaster/operon-sdk/go/internal/httpx"
)

const defaultLeeway = 30 * time.Second

// Token captures an access token together with the derived participant DID (if
// available) and expiry metadata for proactive refresh decisions.
type Token struct {
    AccessToken   string
    ParticipantDID string
    Expiry        time.Time
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
    http     httpx.Doer
    leeway   time.Duration

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

    manager := &ClientCredentialsManager{
        tokenURL: strings.TrimRight(cfg.TokenURL, "/"),
        body: tokenRequest{
            ClientID:     cfg.ClientID,
            ClientSecret: cfg.ClientSecret,
            GrantType:    "client_credentials",
            Scope:        cfg.Scope,
            Audience:     cfg.Audience,
        },
        http:   cfg.HTTPClient,
        leeway: leeway,
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
    req, err := httpx.NewJSONRequest(ctx, http.MethodPost, m.tokenURL, m.body)
    if err != nil {
        return Token{}, fmt.Errorf("build token request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

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

    token := Token{
        AccessToken:   accessToken,
        ParticipantDID: extractParticipantDID(accessToken),
        Expiry:        time.Now().Add(expiresIn),
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

func extractParticipantDID(token string) string {
    parts := strings.Split(token, ".")
    if len(parts) < 2 {
        return ""
    }

    decode := func(seg string) ([]byte, error) {
        if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
            return b, nil
        }
        return base64.StdEncoding.DecodeString(seg)
    }

    payload, err := decode(parts[1])
    if err != nil {
        return ""
    }

    var claims struct {
        ParticipantDID string `json:"participant_did"`
    }
    if err := json.Unmarshal(payload, &claims); err != nil {
        return ""
    }
    return claims.ParticipantDID
}
