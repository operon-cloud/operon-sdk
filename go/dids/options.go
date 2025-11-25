package dids

import (
	"net/http"
)

// Option configures the resolver client.
type Option func(*options)

type options struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

func defaultOptions() options {
	return options{
		baseURL:    "https://did.operon.cloud",
		httpClient: http.DefaultClient,
		userAgent:  "operon-sdk-go/dids",
	}
}

// WithBaseURL overrides the resolver base URL (e.g., https://did.dev.operon.cloud).
func WithBaseURL(baseURL string) Option {
	return func(o *options) {
		if baseURL != "" {
			o.baseURL = baseURL
		}
	}
}

// WithHTTPClient overrides the HTTP client used for requests.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		if c != nil {
			o.httpClient = c
		}
	}
}

// WithUserAgent sets a custom User-Agent header.
func WithUserAgent(ua string) Option {
	return func(o *options) {
		if ua != "" {
			o.userAgent = ua
		}
	}
}
