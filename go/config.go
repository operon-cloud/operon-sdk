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

	if strings.TrimSpace(c.SigningAlgorithm) == "" {
		c.SigningAlgorithm = AlgorithmEd25519
	}

	return nil
}
