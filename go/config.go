package operon

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is used when Config.BaseURL is unset.
	DefaultBaseURL = "https://api.operon.cloud/client-api"
	// DefaultTokenURL is used when Config.TokenURL is unset.
	DefaultTokenURL = "https://auth.operon.cloud/oauth2/token"
	// DefaultHTTPTimeout controls the default HTTP client timeout if none is provided.
	DefaultHTTPTimeout = 30 * time.Second
	// defaultTokenLeeway subtracts this duration from expires_in to refresh tokens proactively.
	defaultTokenLeeway = 30 * time.Second
	defaultKeyIDSuffix = "#keys-1"
	// defaultHeartbeatTimeout caps how long heartbeat calls may run.
	defaultHeartbeatTimeout = 10 * time.Second
)

// Config encapsulates the options required to instantiate a Client.
type Config struct {
	BaseURL          string
	TokenURL         string
	ClientID         string
	ClientSecret     string
	Scope            string
	Audience         []string
	HTTPClient       HTTPClient
	TokenLeeway      time.Duration
	DisableSelfSign  bool
	SigningAlgorithm string
	// SessionHeartbeatInterval enables background keep-alive checks when greater than zero.
	SessionHeartbeatInterval time.Duration
	// SessionHeartbeatTimeout overrides the timeout per heartbeat call.
	SessionHeartbeatTimeout time.Duration
	// SessionHeartbeatURL customizes the heartbeat endpoint; defaults to BaseURL + /v1/session/heartbeat.
	SessionHeartbeatURL string
}

// Validate performs basic sanity checks on the configuration and fills defaults for optional fields.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config cannot be nil")
	}

	baseURL := strings.TrimSpace(c.BaseURL)
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return fmt.Errorf("invalid BaseURL: %w", err)
	}
	c.BaseURL = strings.TrimRight(baseURL, "/")

	tokenURL := strings.TrimSpace(c.TokenURL)
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	if _, err := url.ParseRequestURI(tokenURL); err != nil {
		return fmt.Errorf("invalid TokenURL: %w", err)
	}
	c.TokenURL = strings.TrimRight(tokenURL, "/")

	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("ClientID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("ClientSecret is required")
	}

	if c.TokenLeeway <= 0 {
		c.TokenLeeway = defaultTokenLeeway
	}

	alg := strings.TrimSpace(c.SigningAlgorithm)
	if alg == "" {
		alg = AlgorithmEd25519
	}
	if canonical, ok := canonicalSigningAlgorithm(alg); ok {
		c.SigningAlgorithm = canonical
	} else {
		return fmt.Errorf("unsupported SigningAlgorithm %s", alg)
	}

	if c.SessionHeartbeatInterval < 0 {
		return errors.New("SessionHeartbeatInterval cannot be negative")
	}
	if c.SessionHeartbeatInterval > 0 {
		timeout := c.SessionHeartbeatTimeout
		if timeout <= 0 {
			timeout = defaultHeartbeatTimeout
		}
		c.SessionHeartbeatTimeout = timeout

		heartbeatURL := strings.TrimSpace(c.SessionHeartbeatURL)
		if heartbeatURL == "" {
			heartbeatURL = c.BaseURL + "/v1/session/heartbeat"
		}
		if _, err := url.ParseRequestURI(heartbeatURL); err != nil {
			return fmt.Errorf("invalid SessionHeartbeatURL: %w", err)
		}
		c.SessionHeartbeatURL = strings.TrimRight(heartbeatURL, "/")
	} else {
		c.SessionHeartbeatTimeout = 0
		c.SessionHeartbeatURL = ""
	}

	return nil
}
