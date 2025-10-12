package operon

import (
	"context"
	"net/http"
	"strings"
	"sync"

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

	referenceMu     sync.Mutex
	referenceLoaded bool

	participantMu  sync.RWMutex
	participantDID string
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
		baseURL:          cfgCopy.BaseURL,
		http:             httpClient,
		tokens:           tokenProvider,
		signer:           signer,
		registry:         catalog.NewRegistry(),
		signingAlgorithm: cfgCopy.SigningAlgorithm,
		selfSigning:      selfSigning,
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
	})
	return c.initErr
}

// Close releases resources held by the client. For now the HTTP client does not
// require explicit closure, but the method exists to preserve forward
// compatibility with future transport options.
func (c *Client) Close() error {
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

	if did := strings.TrimSpace(token.ParticipantDID); did != "" {
		c.participantMu.Lock()
		c.participantDID = did
		c.participantMu.Unlock()
	}

	return token.AccessToken, nil
}

func (c *Client) cachedParticipantDID() string {
	c.participantMu.RLock()
	defer c.participantMu.RUnlock()
	return c.participantDID
}
