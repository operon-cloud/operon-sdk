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

// ChannelInteraction represents a detailed interaction record associated with the authenticated channel.
type ChannelInteraction struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name,omitempty"`
	Description         string    `json:"description,omitempty"`
	Status              string    `json:"status,omitempty"`
	SourceParticipantID string    `json:"sourceParticipantId,omitempty"`
	TargetParticipantID string    `json:"targetParticipantId,omitempty"`
	Channels            []string  `json:"channels,omitempty"`
	Tags                []string  `json:"tags,omitempty"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
	Version             int       `json:"version,omitempty"`
}

// ChannelInteractionsResponse mirrors the Client API payload for /v1/channels/{channelId}/interactions.
type ChannelInteractionsResponse struct {
	Interactions []ChannelInteraction `json:"interactions"`
	TotalCount   int                  `json:"totalCount"`
	Page         int                  `json:"page"`
	PageSize     int                  `json:"pageSize"`
	HasMore      bool                 `json:"hasMore"`
}

// ChannelParticipant represents a participant linked to the authenticated channel.
type ChannelParticipant struct {
	ID          string    `json:"id"`
	DID         string    `json:"did"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	URL         string    `json:"url,omitempty"`
	Status      string    `json:"status,omitempty"`
	Type        string    `json:"type,omitempty"`
	CustomerID  string    `json:"customerId,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Version     int       `json:"version,omitempty"`
}

// ChannelParticipantsResponse mirrors the Client API payload for /v1/channels/{channelId}/participants.
type ChannelParticipantsResponse struct {
	Participants []ChannelParticipant `json:"participants"`
	TotalCount   int                  `json:"totalCount"`
	Page         int                  `json:"page"`
	PageSize     int                  `json:"pageSize"`
	HasMore      bool                 `json:"hasMore"`
}

// ChannelDataConfig configures direct channel discovery helpers that operate on a PAT without instantiating a Client.
type ChannelDataConfig struct {
	BaseURL    string
	HTTPClient HTTPClient
}

// GetChannelInteractions returns the interactions available to the authenticated channel. The optional channelID argument
// allows overriding the token-bound channel when working with broader credentials.
func (c *Client) GetChannelInteractions(ctx context.Context, channelID ...string) (ChannelInteractionsResponse, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return ChannelInteractionsResponse{}, err
	}

	token, err := c.tokenValue(ctx)
	if err != nil {
		return ChannelInteractionsResponse{}, err
	}

	targetChannel, err := c.resolveChannelID(channelID...)
	if err != nil {
		return ChannelInteractionsResponse{}, err
	}

	path := fmt.Sprintf("/v1/channels/%s/interactions", targetChannel)
	resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, path, token, nil)
	if err != nil {
		return ChannelInteractionsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return ChannelInteractionsResponse{}, decodeErr
		}
		return ChannelInteractionsResponse{}, apiErr
	}

	var payload ChannelInteractionsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return ChannelInteractionsResponse{}, err
	}

	return payload, nil
}

// GetChannelParticipants returns the participants associated with the authenticated channel. The optional channelID argument
// allows overriding the token-bound channel when working with broader credentials.
func (c *Client) GetChannelParticipants(ctx context.Context, channelID ...string) (ChannelParticipantsResponse, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return ChannelParticipantsResponse{}, err
	}

	token, err := c.tokenValue(ctx)
	if err != nil {
		return ChannelParticipantsResponse{}, err
	}

	targetChannel, err := c.resolveChannelID(channelID...)
	if err != nil {
		return ChannelParticipantsResponse{}, err
	}

	path := fmt.Sprintf("/v1/channels/%s/participants", targetChannel)
	resp, err := c.authorizedJSONRequest(ctx, http.MethodGet, path, token, nil)
	if err != nil {
		return ChannelParticipantsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return ChannelParticipantsResponse{}, decodeErr
		}
		return ChannelParticipantsResponse{}, apiErr
	}

	var payload ChannelParticipantsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return ChannelParticipantsResponse{}, err
	}

	return payload, nil
}

// FetchChannelInteractions retrieves channel interactions using a PAT directly. The optional channelID override allows
// callers with multi-channel tokens to target a specific channel.
func FetchChannelInteractions(ctx context.Context, cfg ChannelDataConfig, pat string, channelID ...string) (ChannelInteractionsResponse, error) {
	resp, err := fetchChannelDataset(ctx, cfg, pat, "interactions", channelID...)
	if err != nil {
		return ChannelInteractionsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return ChannelInteractionsResponse{}, decodeErr
		}
		return ChannelInteractionsResponse{}, apiErr
	}

	var payload ChannelInteractionsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return ChannelInteractionsResponse{}, err
	}
	return payload, nil
}

// FetchChannelParticipants retrieves channel participants using a PAT directly. The optional channelID override allows
// callers with multi-channel tokens to target a specific channel.
func FetchChannelParticipants(ctx context.Context, cfg ChannelDataConfig, pat string, channelID ...string) (ChannelParticipantsResponse, error) {
	resp, err := fetchChannelDataset(ctx, cfg, pat, "participants", channelID...)
	if err != nil {
		return ChannelParticipantsResponse{}, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return ChannelParticipantsResponse{}, decodeErr
		}
		return ChannelParticipantsResponse{}, apiErr
	}

	var payload ChannelParticipantsResponse
	if err := httpx.DecodeJSON(resp, &payload); err != nil {
		return ChannelParticipantsResponse{}, err
	}
	return payload, nil
}

func fetchChannelDataset(ctx context.Context, cfg ChannelDataConfig, pat string, resource string, override ...string) (*http.Response, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil, errors.New("pat is required")
	}

	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	channel, err := resolveChannelIDFromPAT(pat, override...)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/v1/channels/%s/%s", baseURL, url.PathEscape(channel), resource)
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

func (c *Client) resolveChannelID(override ...string) (string, error) {
	for _, candidate := range override {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed, nil
		}
	}

	if channel := strings.TrimSpace(c.cachedChannelID()); channel != "" {
		return channel, nil
	}

	return "", errors.New("channel ID is required: token not scoped to a channel and no override provided")
}

func resolveChannelIDFromPAT(pat string, override ...string) (string, error) {
	for _, candidate := range override {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed, nil
		}
	}

	claims := auth.DecodeTokenClaims(pat)
	if channel := strings.TrimSpace(claims.ChannelID); channel != "" {
		return channel, nil
	}

	return "", errors.New("channel ID is required: token not scoped to a channel and no override provided")
}
