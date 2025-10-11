package operon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultKeyIDSuffix = "#keys-1"

// DefaultBaseURL is used when Config.BaseURL is unset.
const DefaultBaseURL = "https://api.operon.cloud/client-api"

// DefaultTokenURL is used when Config.TokenURL is unset.
const DefaultTokenURL = "https://auth.operon.cloud/v1/session/m2m"

// DefaultHTTPTimeout controls the default HTTP client timeout if none is provided.
const DefaultHTTPTimeout = 30 * time.Second

// defaultTokenLeeway subtracts this duration from the expires_in value to refresh tokens proactively.
const defaultTokenLeeway = 30 * time.Second

// Config encapsulates the options required to instantiate a Client.
type Config struct {
	BaseURL         string
	TokenURL        string
	ClientID        string
	ClientSecret    string
	Scope           string
	Audience        []string
	HTTPClient      *http.Client
	TokenLeeway     time.Duration
	DisableSelfSign bool
}

// Validate performs basic sanity checks on the configuration and fills defaults for optional fields.
func (c *Config) Validate() error {
	baseURL := strings.TrimSpace(c.BaseURL)
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return fmt.Errorf("invalid BaseURL: %w", err)
	}
	baseURL = strings.TrimRight(baseURL, "/")

	tokenURL := strings.TrimSpace(c.TokenURL)
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	if _, err := url.ParseRequestURI(tokenURL); err != nil {
		return fmt.Errorf("invalid TokenURL: %w", err)
	}

	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("ClientID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("ClientSecret is required")
	}

	c.BaseURL = baseURL
	c.TokenURL = tokenURL

	return nil
}

// Client exposes a higher level, token-aware wrapper over the Operon Platform APIs.
type Client struct {
	baseURL      string
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	audience     []string

	httpClient  *http.Client
	tokenLeeway time.Duration

	tokenMu     sync.Mutex
	cachedToken *tokenInfo

	initOnce sync.Once
	initErr  error

	interactionMu sync.RWMutex
	interactions  map[string]interactionMeta

	participantMu    sync.RWMutex
	participants     map[string]string
	participantDID   string
	selfSign         bool
	signingAlgorithm string
}

type tokenInfo struct {
	value  string
	expiry time.Time
}

type interactionMeta struct {
	interactionID       string
	channelID           string
	sourceParticipantID string
	targetParticipantID string
	sourceDID           string
	targetDID           string
}

// NewClient constructs a new Client instance using the supplied configuration.
func NewClient(cfg Config) (*Client, error) {
	cfgCopy := cfg
	if err := (&cfgCopy).Validate(); err != nil {
		return nil, err
	}

	httpClient := cfgCopy.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	leeway := cfgCopy.TokenLeeway
	if leeway <= 0 {
		leeway = defaultTokenLeeway
	}

	return &Client{
		baseURL:          cfgCopy.BaseURL,
		tokenURL:         cfgCopy.TokenURL,
		clientID:         cfgCopy.ClientID,
		clientSecret:     cfgCopy.ClientSecret,
		scope:            cfgCopy.Scope,
		audience:         cfgCopy.Audience,
		httpClient:       httpClient,
		tokenLeeway:      leeway,
		interactions:     make(map[string]interactionMeta),
		participants:     make(map[string]string),
		selfSign:         !cfgCopy.DisableSelfSign,
		signingAlgorithm: AlgorithmEd25519,
	}, nil
}

// Init eagerly acquires an access token and loads reference data required for
// convenience helpers (such as resolving interaction participants). It is safe
// to call multiple times; subsequent invocations are no-ops unless the initial
// attempt failed.
func (c *Client) Init(ctx context.Context) error {
	c.initOnce.Do(func() {
		if _, err := c.getToken(ctx); err != nil {
			c.initErr = err
			return
		}
		c.initErr = c.loadReferenceData(ctx)
	})
	return c.initErr
}

// SubmitTransaction submits a transaction payload to the Operon client API and returns the persisted record.
func (c *Client) SubmitTransaction(ctx context.Context, req TransactionRequest) (*Transaction, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	if err := c.populateInteractionFields(ctx, &req); err != nil {
		return nil, err
	}

	payloadData, payloadHash, err := req.resolvePayload()
	if err != nil {
		return nil, err
	}
	req.PayloadHash = payloadHash

	sanitizedLabel := strings.TrimSpace(req.Label)
	var sanitizedTags []string
	if len(req.Tags) > 0 {
		sanitizedTags = make([]string, 0, len(req.Tags))
		for _, tag := range req.Tags {
			trimmed := strings.TrimSpace(tag)
			if trimmed == "" {
				continue
			}
			sanitizedTags = append(sanitizedTags, trimmed)
		}
	}

	if c.selfSign && strings.TrimSpace(req.Signature.Value) == "" {
		signature, err := c.signWithDID(ctx, payloadHash)
		if err != nil {
			return nil, err
		}
		req.Signature = signature
	}

	if err := req.ValidateForSubmit(); err != nil {
		return nil, err
	}

	timestamp := req.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	apiReq := transactionSubmission{
		CorrelationID: req.CorrelationID,
		ChannelID:     req.ChannelID,
		InteractionID: req.InteractionID,
		Timestamp:     timestamp.Format(time.RFC3339Nano),
		SourceDID:     req.SourceDID,
		TargetDID:     req.TargetDID,
		Signature:     req.Signature,
		PayloadData:   payloadData,
		PayloadHash:   payloadHash,
	}

	if sanitizedLabel != "" {
		apiReq.Label = sanitizedLabel
	}
	if len(sanitizedTags) > 0 {
		apiReq.Tags = sanitizedTags
	}

	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/transactions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("submit transaction: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		apiErr, decodeErr := decodeAPIError(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var txn Transaction
	if err := json.NewDecoder(resp.Body).Decode(&txn); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &txn, nil
}

// Close releases resources held by the client. For now the HTTP client does not require explicit closure,
// but the method exists to preserve forward compatibility with future transport options.
func (c *Client) Close() error {
	// no-op placeholder for future extensions (e.g., custom transport shutdown)
	return nil
}

func (c *Client) ensureInitialized(ctx context.Context) error {
	if err := c.Init(ctx); err != nil {
		return err
	}
	return nil
}

// Interactions returns the cached interaction catalogue. It performs lazy
// initialisation if required and returns a copy so callers can mutate safely.
func (c *Client) Interactions(ctx context.Context) ([]InteractionSummary, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	c.interactionMu.RLock()
	defer c.interactionMu.RUnlock()

	result := make([]InteractionSummary, 0, len(c.interactions))
	for _, meta := range c.interactions {
		result = append(result, InteractionSummary{
			ID:                  meta.interactionID,
			ChannelID:           meta.channelID,
			SourceParticipantID: meta.sourceParticipantID,
			TargetParticipantID: meta.targetParticipantID,
			SourceDID:           meta.sourceDID,
			TargetDID:           meta.targetDID,
		})
	}

	return result, nil
}

// Participants returns the cached participant directory (ID -> DID).
func (c *Client) Participants(ctx context.Context) ([]ParticipantSummary, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	c.participantMu.RLock()
	defer c.participantMu.RUnlock()

	result := make([]ParticipantSummary, 0, len(c.participants))
	for id, did := range c.participants {
		result = append(result, ParticipantSummary{ID: id, DID: did})
	}

	return result, nil
}

func (c *Client) populateInteractionFields(ctx context.Context, req *TransactionRequest) error {
	if strings.TrimSpace(req.InteractionID) == "" {
		if strings.TrimSpace(req.SourceDID) == "" && c.participantDID != "" {
			req.SourceDID = c.participantDID
		}
		return nil
	}

	meta, ok := c.lookupInteraction(req.InteractionID)
	if !ok {
		if err := c.loadReferenceData(ctx); err != nil {
			return fmt.Errorf("refresh interaction cache: %w", err)
		}
		meta, ok = c.lookupInteraction(req.InteractionID)
		if !ok {
			return fmt.Errorf("interaction %s not found", req.InteractionID)
		}
	}

	if strings.TrimSpace(req.ChannelID) == "" {
		req.ChannelID = meta.channelID
	}
	if strings.TrimSpace(req.SourceDID) == "" {
		if meta.sourceDID == "" {
			return fmt.Errorf("interaction %s missing source DID", req.InteractionID)
		}
		req.SourceDID = meta.sourceDID
	}
	if strings.TrimSpace(req.TargetDID) == "" {
		if meta.targetDID == "" {
			return fmt.Errorf("interaction %s missing target DID", req.InteractionID)
		}
		req.TargetDID = meta.targetDID
	}

	if strings.TrimSpace(req.SourceDID) == "" && c.participantDID != "" {
		req.SourceDID = c.participantDID
	}

	return nil
}

func (c *Client) lookupInteraction(id string) (interactionMeta, bool) {
	c.interactionMu.RLock()
	defer c.interactionMu.RUnlock()
	meta, ok := c.interactions[id]
	return meta, ok
}

func (c *Client) signWithDID(ctx context.Context, payloadHash string) (Signature, error) {
	reqBody := map[string]string{
		"payloadHash":   payloadHash,
		"hashAlgorithm": "SHA-256",
		"algorithm":     c.signingAlgorithm,
	}

	token, err := c.getToken(ctx)
	if err != nil {
		return Signature{}, err
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return Signature{}, fmt.Errorf("marshal sign request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/dids/self/sign", bytes.NewReader(body))
	if err != nil {
		return Signature{}, fmt.Errorf("build sign request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(request)
	if err != nil {
		return Signature{}, fmt.Errorf("self sign request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		apiErr, decodeErr := decodeAPIError(resp)
		if decodeErr != nil {
			return Signature{}, decodeErr
		}
		return Signature{}, apiErr
	}

	var result struct {
		Signature Signature `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Signature{}, fmt.Errorf("decode sign response: %w", err)
	}

	if strings.TrimSpace(result.Signature.Algorithm) == "" || strings.TrimSpace(result.Signature.Value) == "" {
		return Signature{}, errors.New("sign response missing signature")
	}

	if strings.TrimSpace(result.Signature.KeyID) == "" {
		source := c.participantDID
		if source == "" {
			c.interactionMu.RLock()
			for _, meta := range c.interactions {
				if meta.sourceDID != "" {
					source = meta.sourceDID
					break
				}
			}
			c.interactionMu.RUnlock()
		}
		if source != "" {
			result.Signature.KeyID = source + defaultKeyIDSuffix
		}
	}

	return result.Signature, nil
}

func (c *Client) loadReferenceData(ctx context.Context) error {
	interactions, err := c.fetchInteractions(ctx)
	if err != nil {
		return err
	}
	participantDIDs, err := c.fetchParticipants(ctx)
	if err != nil {
		return err
	}

	updated := make(map[string]interactionMeta, len(interactions))
	for _, intr := range interactions {
		meta := intr
		if did, ok := participantDIDs[intr.sourceParticipantID]; ok {
			meta.sourceDID = did
		}
		if did, ok := participantDIDs[intr.targetParticipantID]; ok {
			meta.targetDID = did
		}
		updated[intr.interactionID] = meta

		if c.participantDID == "" && meta.sourceDID != "" {
			c.participantDID = meta.sourceDID
		}
	}

	c.interactionMu.Lock()
	c.interactions = updated
	c.interactionMu.Unlock()

	c.participantMu.Lock()
	c.participants = participantDIDs
	c.participantMu.Unlock()

	if c.participantDID == "" {
		for _, did := range participantDIDs {
			c.participantDID = did
			break
		}
	}

	return nil
}

func (c *Client) fetchInteractions(ctx context.Context) ([]interactionMeta, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/interactions", nil)
	if err != nil {
		return nil, fmt.Errorf("build interactions request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch interactions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, decodeErr := decodeAPIError(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, errBody
	}

	var payload struct {
		Data []struct {
			ID                  string `json:"id"`
			ChannelID           string `json:"channelId"`
			SourceParticipantID string `json:"sourceParticipantId"`
			TargetParticipantID string `json:"targetParticipantId"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode interactions response: %w", err)
	}

	result := make([]interactionMeta, 0, len(payload.Data))
	for _, item := range payload.Data {
		result = append(result, interactionMeta{
			interactionID:       item.ID,
			channelID:           item.ChannelID,
			sourceParticipantID: item.SourceParticipantID,
			targetParticipantID: item.TargetParticipantID,
		})
	}

	return result, nil
}

func (c *Client) fetchParticipants(ctx context.Context) (map[string]string, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/participants", nil)
	if err != nil {
		return nil, fmt.Errorf("build participants request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch participants: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errBody, decodeErr := decodeAPIError(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, errBody
	}

	var payload struct {
		Data []struct {
			ID  string `json:"id"`
			DID string `json:"did"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode participants response: %w", err)
	}

	result := make(map[string]string, len(payload.Data))
	for _, item := range payload.Data {
		if item.ID != "" && item.DID != "" {
			result[item.ID] = item.DID
		}
	}

	return result, nil
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

func (c *Client) getToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	if c.cachedToken != nil && time.Until(c.cachedToken.expiry) > c.tokenLeeway {
		token := c.cachedToken.value
		c.tokenMu.Unlock()
		return token, nil
	}
	c.tokenMu.Unlock()

	// Acquire new token outside unlocked to avoid blocking.
	newToken, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}

	c.tokenMu.Lock()
	c.cachedToken = newToken
	c.tokenMu.Unlock()

	return newToken.value, nil
}

func (c *Client) fetchToken(ctx context.Context) (*tokenInfo, error) {
	payload := tokenRequest{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		GrantType:    "client_credentials",
		Scope:        c.scope,
		Audience:     c.audience,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		apiErr, decodeErr := decodeAPIError(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return nil, errors.New("token response missing access_token")
	}

	if participantDID := extractParticipantDID(tokenResp.AccessToken); participantDID != "" {
		c.participantDID = participantDID
	}

	expiresIn := time.Duration(tokenResp.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Minute
	}

	return &tokenInfo{
		value:  tokenResp.AccessToken,
		expiry: time.Now().Add(expiresIn),
	}, nil
}
