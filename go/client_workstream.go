package operon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/httpx"
)

// GetWorkstream returns the workstream associated with the authenticated PAT. The optional workstreamID
// allows overriding the token-bound workstream when working with broader credentials.
func (c *Client) GetWorkstream(ctx context.Context, workstreamID ...string) (*Workstream, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	token, err := c.tokenValue(ctx)
	if err != nil {
		return nil, err
	}

	targetWorkstream, err := c.resolveWorkstreamID(workstreamID...)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/v1/workstreams/%s", targetWorkstream)
	resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, path, token, nil)
	if err != nil {
		return nil, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var payload Workstream
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

// FetchWorkstream retrieves workstream details using a PAT directly. The optional workstreamID override allows
// callers with multi-workstream tokens to target a specific workstream.
func FetchWorkstream(ctx context.Context, cfg WorkstreamDataConfig, pat string, workstreamID ...string) (*Workstream, error) {
	resp, err := fetchWorkstream(ctx, cfg, pat, workstreamID...)
	if err != nil {
		return nil, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var payload Workstream
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func fetchWorkstream(ctx context.Context, cfg WorkstreamDataConfig, pat string, override ...string) (*http.Response, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil, errors.New("pat is required")
	}

	normalized, httpClient := normalizeWorkstreamConfig(cfg)

	workstream, err := resolveWorkstreamIDFromPAT(pat, override...)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/v1/workstreams/%s", normalized.BaseURL, url.PathEscape(workstream))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pat)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	return resp, nil
}
