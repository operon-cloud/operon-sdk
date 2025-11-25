package dids

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Resolve fetches the DID Document for the given did:operon identifier.
func Resolve(ctx context.Context, did string, opts ...Option) (*Document, error) {
	if !strings.HasPrefix(did, "did:operon:") {
		return nil, ErrUnsupported
	}
	did = strings.TrimSpace(did)
	if did == "" {
		return nil, ErrInvalidDID
	}

	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	target, err := url.JoinPath(o.baseURL, "/1.0/identifiers", did)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDID, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/did+json")
	if o.userAgent != "" {
		req.Header.Set("user-agent", o.userAgent)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var doc Document
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDecode, err)
		}
		return &doc, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusBadRequest:
		return nil, ErrInvalidDID
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status=%d body=%s", ErrUpstream, resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
