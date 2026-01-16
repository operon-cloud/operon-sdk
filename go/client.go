package operon

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/operon-cloud/operon-sdk/go/internal/auth"
	"github.com/operon-cloud/operon-sdk/go/internal/catalog"
	"github.com/operon-cloud/operon-sdk/go/internal/signing"
)

// HTTPClient captures the subset of http.Client behaviour consumed by the SDK.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Client exposes a higher-level, token-aware wrapper over the Operon Platform APIs.
type Client struct {
	baseURL string
	http    HTTPClient
	tokens  auth.Provider
	signer  signing.Signer

	registry         *catalog.Registry
	signingAlgorithm string
	selfSigning      bool

	initOnce sync.Once
	initErr  error

	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
	heartbeatURL      string
	heartbeatOnce     sync.Once
	heartbeatCancel   context.CancelFunc
	heartbeatWG       sync.WaitGroup

	referenceMu     sync.Mutex
	referenceLoaded bool

	participantMu  sync.RWMutex
	participantDID string
	workstreamID   string
	customerID     string
	workspaceID    string
	email          string
	name           string
	tenantIDs      []string
	roles          []string
	memberID       string
	sessionID      string
	orgID          string
}

// NewClient constructs a new Client instance using the supplied configuration.
func NewClient(cfg Config) (*Client, error) {
	cfgCopy := cfg
	if err := cfgCopy.Validate(); err != nil {
		return nil, err
	}

	httpClient := cfgCopy.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	tokenProvider, err := auth.NewClientCredentialsManager(auth.ClientCredentialsConfig{
		TokenURL:     cfgCopy.TokenURL,
		ClientID:     cfgCopy.ClientID,
		ClientSecret: cfgCopy.ClientSecret,
		Scope:        cfgCopy.Scope,
		Audience:     cfgCopy.Audience,
		HTTPClient:   httpClient,
		Leeway:       cfgCopy.TokenLeeway,
	})
	if err != nil {
		return nil, err
	}

	var signer signing.Signer = signing.DisabledSigner{}
	selfSigning := !cfgCopy.DisableSelfSign
	if selfSigning {
		signer, err = signing.NewSelfSigner(signing.Config{
			BaseURL:    cfgCopy.BaseURL,
			HTTPClient: httpClient,
		})
		if err != nil {
			return nil, err
		}
	}

	return &Client{
		baseURL:           cfgCopy.BaseURL,
		http:              httpClient,
		tokens:            tokenProvider,
		signer:            signer,
		registry:          catalog.NewRegistry(),
		signingAlgorithm:  cfgCopy.SigningAlgorithm,
		selfSigning:       selfSigning,
		heartbeatInterval: cfgCopy.SessionHeartbeatInterval,
		heartbeatTimeout:  cfgCopy.SessionHeartbeatTimeout,
		heartbeatURL:      cfgCopy.SessionHeartbeatURL,
	}, nil
}

// Init eagerly acquires an access token and loads reference data required for
// convenience helpers. It is safe to call multiple times; subsequent invocations
// are no-ops unless the initial attempt failed.
func (c *Client) Init(ctx context.Context) error {
	c.initOnce.Do(func() {
		if _, err := c.tokenValue(ctx); err != nil {
			c.initErr = err
			return
		}
		c.startHeartbeat()
	})
	return c.initErr
}

// Close releases resources held by the client. For now the HTTP client does not
// require explicit closure, but the method exists to preserve forward
// compatibility with future transport options.
func (c *Client) Close() error {
	c.stopHeartbeat()
	return nil
}

func (c *Client) ensureInitialized(ctx context.Context) error {
	if err := c.Init(ctx); err != nil {
		return err
	}
	return nil
}

func (c *Client) tokenValue(ctx context.Context) (string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return "", err
	}

	c.participantMu.Lock()
	if did := strings.TrimSpace(token.ParticipantDID); did != "" {
		c.participantDID = did
	}
	if workstream := strings.TrimSpace(token.WorkstreamID); workstream != "" {
		c.workstreamID = workstream
	}
	if customer := strings.TrimSpace(token.CustomerID); customer != "" {
		c.customerID = customer
	}
	if workspace := strings.TrimSpace(token.WorkspaceID); workspace != "" {
		c.workspaceID = workspace
	}
	if email := strings.TrimSpace(token.Email); email != "" {
		c.email = email
	}
	if name := strings.TrimSpace(token.Name); name != "" {
		c.name = name
	}
	if token.TenantIDs != nil {
		c.tenantIDs = append([]string(nil), token.TenantIDs...)
	} else {
		c.tenantIDs = nil
	}
	if token.Roles != nil {
		c.roles = append([]string(nil), token.Roles...)
	} else {
		c.roles = nil
	}
	if member := strings.TrimSpace(token.MemberID); member != "" {
		c.memberID = member
	}
	if session := strings.TrimSpace(token.SessionID); session != "" {
		c.sessionID = session
	}
	if org := strings.TrimSpace(token.OrgID); org != "" {
		c.orgID = org
	}
	c.participantMu.Unlock()

	return token.AccessToken, nil
}

func (c *Client) cachedParticipantDID() string {
	c.participantMu.RLock()
	defer c.participantMu.RUnlock()
	return c.participantDID
}

func (c *Client) cachedWorkstreamID() string {
	c.participantMu.RLock()
	defer c.participantMu.RUnlock()
	return c.workstreamID
}
