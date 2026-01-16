package operon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/auth"
	"github.com/operon-cloud/operon-sdk/go/internal/httpx"
)

// WorkstreamInteraction represents a detailed interaction record associated with the authenticated workstream.
type WorkstreamInteraction struct {
	ID                  string            `json:"id"`
	WorkstreamID        string            `json:"channelId"`
	Name                string            `json:"name,omitempty"`
	Description         string            `json:"description,omitempty"`
	Status              string            `json:"status,omitempty"`
	SourceParticipantID string            `json:"sourceParticipantId,omitempty"`
	TargetParticipantID string            `json:"targetParticipantId,omitempty"`
	Workstreams         []string          `json:"channels,omitempty"`
	Type                InteractionType   `json:"type,omitempty"`
	Actor               InteractionActor  `json:"actor,omitempty"`
	States              []string          `json:"states,omitempty"`
	ROIClassification   ROIClassification `json:"roiClassification,omitempty"`
	ROICost             int               `json:"roiCost,omitempty"`
	ROITime             int               `json:"roiTime,omitempty"`
	Tags                []string          `json:"tags,omitempty"`
	CreatedAt           time.Time         `json:"createdAt"`
	UpdatedAt           time.Time         `json:"updatedAt"`
	Version             int               `json:"version,omitempty"`
}

// WorkstreamInteractionsResponse mirrors the Client API payload for /v1/channels/{channelId}/interactions.
type WorkstreamInteractionsResponse struct {
	Interactions []WorkstreamInteraction `json:"interactions"`
	TotalCount   int                     `json:"totalCount"`
	Page         int                     `json:"page"`
	PageSize     int                     `json:"pageSize"`
	HasMore      bool                    `json:"hasMore"`
}

// WorkstreamParticipant represents a participant linked to the authenticated workstream.
type WorkstreamParticipant struct {
	ID           string    `json:"id"`
	DID          string    `json:"did"`
	Name         string    `json:"name,omitempty"`
	Description  string    `json:"description,omitempty"`
	URL          string    `json:"url,omitempty"`
	Status       string    `json:"status,omitempty"`
	Type         string    `json:"type,omitempty"`
	CustomerID   string    `json:"customerId,omitempty"`
	WorkstreamID string    `json:"channelId,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Version      int       `json:"version,omitempty"`
}

// WorkstreamParticipantsResponse mirrors the Client API payload for /v1/channels/{channelId}/participants.
type WorkstreamParticipantsResponse struct {
	Participants []WorkstreamParticipant `json:"participants"`
	TotalCount   int                     `json:"totalCount"`
	Page         int                     `json:"page"`
	PageSize     int                     `json:"pageSize"`
	HasMore      bool                    `json:"hasMore"`
}

// GetWorkstreamInteractions returns the interactions available to the authenticated workstream. The optional workstreamID argument
// allows overriding the token-bound workstream when working with broader credentials.
func (c *Client) GetWorkstreamInteractions(ctx context.Context, workstreamID ...string) (WorkstreamInteractionsResponse, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return WorkstreamInteractionsResponse{}, err
	}

	token, err := c.tokenValue(ctx)
	if err != nil {
		return WorkstreamInteractionsResponse{}, err
	}

	targetWorkstream, err := c.resolveWorkstreamID(workstreamID...)
	if err != nil {
		return WorkstreamInteractionsResponse{}, err
	}

	path := fmt.Sprintf("/v1/channels/%s/interactions", targetWorkstream)
	resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, path, token, nil)
	if err != nil {
		return WorkstreamInteractionsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return WorkstreamInteractionsResponse{}, decodeErr
		}
		return WorkstreamInteractionsResponse{}, apiErr
	}

	var payload WorkstreamInteractionsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return WorkstreamInteractionsResponse{}, err
	}

	return payload, nil
}

// GetWorkstreamParticipants returns the participants associated with the authenticated workstream. The optional workstreamID argument
// allows overriding the token-bound workstream when working with broader credentials.
func (c *Client) GetWorkstreamParticipants(ctx context.Context, workstreamID ...string) (WorkstreamParticipantsResponse, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return WorkstreamParticipantsResponse{}, err
	}

	token, err := c.tokenValue(ctx)
	if err != nil {
		return WorkstreamParticipantsResponse{}, err
	}

	targetWorkstream, err := c.resolveWorkstreamID(workstreamID...)
	if err != nil {
		return WorkstreamParticipantsResponse{}, err
	}

	path := fmt.Sprintf("/v1/channels/%s/participants", targetWorkstream)
	resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, path, token, nil)
	if err != nil {
		return WorkstreamParticipantsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return WorkstreamParticipantsResponse{}, decodeErr
		}
		return WorkstreamParticipantsResponse{}, apiErr
	}

	var payload WorkstreamParticipantsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return WorkstreamParticipantsResponse{}, err
	}

	return payload, nil
}

// FetchWorkstreamInteractions retrieves workstream interactions using a PAT directly. The optional workstreamID override allows
// callers with multi-workstream tokens to target a specific workstream.
func FetchWorkstreamInteractions(ctx context.Context, cfg WorkstreamDataConfig, pat string, workstreamID ...string) (WorkstreamInteractionsResponse, error) {
	resp, err := fetchWorkstreamDataset(ctx, cfg, pat, "interactions", workstreamID...)
	if err != nil {
		return WorkstreamInteractionsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return WorkstreamInteractionsResponse{}, decodeErr
		}
		return WorkstreamInteractionsResponse{}, apiErr
	}

	var payload WorkstreamInteractionsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return WorkstreamInteractionsResponse{}, err
	}
	return payload, nil
}

// FetchWorkstreamParticipants retrieves workstream participants using a PAT directly. The optional workstreamID override allows
// callers with multi-workstream tokens to target a specific workstream.
func FetchWorkstreamParticipants(ctx context.Context, cfg WorkstreamDataConfig, pat string, workstreamID ...string) (WorkstreamParticipantsResponse, error) {
	resp, err := fetchWorkstreamDataset(ctx, cfg, pat, "participants", workstreamID...)
	if err != nil {
		return WorkstreamParticipantsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return WorkstreamParticipantsResponse{}, decodeErr
		}
		return WorkstreamParticipantsResponse{}, apiErr
	}

	var payload WorkstreamParticipantsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return WorkstreamParticipantsResponse{}, err
	}
	return payload, nil
}

func fetchWorkstreamDataset(ctx context.Context, cfg WorkstreamDataConfig, pat string, resource string, override ...string) (*http.Response, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil, errors.New("pat is required")
	}

	normalized, httpClient := normalizeWorkstreamConfig(cfg)

	workstream, err := resolveWorkstreamIDFromPAT(pat, override...)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/v1/channels/%s/%s", normalized.BaseURL, url.PathEscape(workstream), resource)
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

func (c *Client) resolveWorkstreamID(override ...string) (string, error) {
	for _, candidate := range override {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed, nil
		}
	}

	if workstream := strings.TrimSpace(c.cachedWorkstreamID()); workstream != "" {
		return workstream, nil
	}

	return "", errors.New("workstream ID is required: token not scoped to a workstream and no override provided")
}

func resolveWorkstreamIDFromPAT(pat string, override ...string) (string, error) {
	for _, candidate := range override {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed, nil
		}
	}

	claims := auth.DecodeTokenClaims(pat)
	if workstream := strings.TrimSpace(claims.WorkstreamID); workstream != "" {
		return workstream, nil
	}

	return "", errors.New("workstream ID is required: token not scoped to a workstream and no override provided")
}
