package operon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/auth"
	"github.com/operon-cloud/operon-sdk/go/internal/httpx"
	"github.com/operon-cloud/operon-sdk/go/internal/signing"
)

// ClientAPIConfig describes the base configuration required for PAT-scoped client API calls.
type ClientAPIConfig struct {
	BaseURL    string
	HTTPClient HTTPClient
}

// WorkstreamDataConfig describes the base configuration required for workstream catalogue calls.
type WorkstreamDataConfig struct {
	BaseURL    string
	HTTPClient HTTPClient
}

func normalizeClientAPIConfig(cfg ClientAPIConfig) (ClientAPIConfig, HTTPClient) {
	baseURL := strings.TrimSpace(cfg.BaseURL)
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}

	return ClientAPIConfig{
		BaseURL: strings.TrimRight(baseURL, "/"),
	}, httpClient
}

func normalizeWorkstreamConfig(cfg WorkstreamDataConfig) (ClientAPIConfig, HTTPClient) {
	return normalizeClientAPIConfig(ClientAPIConfig{
		BaseURL:    cfg.BaseURL,
		HTTPClient: cfg.HTTPClient,
	})
}

// SignHashWithPAT requests a managed signature for the supplied payload hash by calling the Operon client API
// with the provided Personal Access Token (PAT).
func SignHashWithPAT(ctx context.Context, cfg ClientAPIConfig, pat string, payloadHash string, algorithm string) (Signature, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return Signature{}, errors.New("pat is required")
	}

	hash := strings.TrimSpace(payloadHash)
	if hash == "" {
		return Signature{}, errors.New("payload hash is required")
	}

	if err := validatePayloadHashFormat(hash); err != nil {
		return Signature{}, err
	}

	selectedAlg, ok := canonicalSigningAlgorithm(algorithm)
	if !ok {
		return Signature{}, fmt.Errorf("unsupported signing algorithm %s", algorithm)
	}

	normalized, httpClient := normalizeClientAPIConfig(cfg)
	signer, err := signing.NewSelfSigner(signing.Config{
		BaseURL:    normalized.BaseURL,
		HTTPClient: httpClient,
	})
	if err != nil {
		return Signature{}, fmt.Errorf("create signer: %w", err)
	}

	result, err := signer.Sign(ctx, pat, hash, selectedAlg)
	if err != nil {
		return Signature{}, err
	}

	signature := Signature{
		Algorithm: result.Algorithm,
		Value:     result.Value,
		KeyID:     result.KeyID,
	}

	if strings.TrimSpace(signature.KeyID) == "" {
		if claims := auth.DecodeTokenClaims(pat); strings.TrimSpace(claims.ParticipantDID) != "" {
			signature.KeyID = strings.TrimSpace(claims.ParticipantDID) + defaultKeyIDSuffix
		}
	}

	return signature, nil
}

// SubmitTransactionWithPAT submits a signed transaction using the supplied Personal Access Token (PAT) and returns
// the persisted transaction record from the Operon client API.
func SubmitTransactionWithPAT(ctx context.Context, cfg ClientAPIConfig, pat string, req TransactionRequest) (*Transaction, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil, errors.New("pat is required")
	}

	normalized, httpClient := normalizeClientAPIConfig(cfg)

	if strings.TrimSpace(req.WorkstreamID) == "" {
		if claims := auth.DecodeTokenClaims(pat); strings.TrimSpace(claims.WorkstreamID) != "" {
			req.WorkstreamID = strings.TrimSpace(claims.WorkstreamID)
		}
	}

	if strings.TrimSpace(req.SourceDID) == "" {
		if claims := auth.DecodeTokenClaims(pat); strings.TrimSpace(claims.ParticipantDID) != "" {
			req.SourceDID = strings.TrimSpace(claims.ParticipantDID)
		}
	}

	_, payloadHash, err := req.resolvePayload()
	if err != nil {
		return nil, err
	}
	req.PayloadHash = payloadHash

	sanitizedLabel := strings.TrimSpace(req.Label)
	sanitizedTags := make([]string, 0, len(req.Tags))
	for _, tag := range req.Tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}
		sanitizedTags = append(sanitizedTags, trimmed)
	}

	if err := req.ValidateForSubmit(); err != nil {
		return nil, err
	}

	timestamp := req.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	submission := transactionSubmission{
		CorrelationID:     req.CorrelationID,
		WorkstreamID:      req.WorkstreamID,
		InteractionID:     req.InteractionID,
		Timestamp:         timestamp.Format(time.RFC3339Nano),
		SourceDID:         req.SourceDID,
		TargetDID:         req.TargetDID,
		Actor:             req.Actor,
		ROIClassification: req.ROIClassification,
		ROICost:           req.ROICost,
		ROITime:           req.ROITime,
		State:             req.State,
		StateID:           req.StateID,
		StateLabel:        req.StateLabel,
		Signature:         req.Signature,
		PayloadHash:       payloadHash,
	}
	if sanitizedLabel != "" {
		submission.Label = sanitizedLabel
	}
	if len(sanitizedTags) > 0 {
		submission.Tags = sanitizedTags
	}

	httpReq, err := httpx.NewJSONRequest(ctx, http.MethodPost, normalized.BaseURL+"/v1/transactions", submission)
	if err != nil {
		return nil, fmt.Errorf("build transaction request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+pat)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("perform transaction request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var txn Transaction
	if err := httpx.DecodeJSON(resp, &txn); err != nil {
		return nil, err
	}

	return &txn, nil
}

// ValidateSignatureWithPAT verifies Operon signature headers against the provided payload using the caller's PAT.
func ValidateSignatureWithPAT(ctx context.Context, cfg ClientAPIConfig, pat string, payload []byte, headers OperonHeaders) (*SignatureValidationResult, error) {
	pat = strings.TrimSpace(pat)
	if pat == "" {
		return nil, errors.New("pat is required")
	}

	sanitized, err := sanitizeOperonHeaders(headers)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(payload)
	computedHash := base64.RawURLEncoding.EncodeToString(hash[:])
	expectedHash := sanitized[HeaderOperonPayloadHash]
	if !strings.EqualFold(computedHash, expectedHash) {
		return nil, fmt.Errorf("payload hash mismatch: expected %s, got %s", computedHash, expectedHash)
	}

	normalized, httpClient := normalizeClientAPIConfig(cfg)

	did := sanitized[HeaderOperonDID]
	path := fmt.Sprintf("%s/v1/dids/%s/signature/verify", normalized.BaseURL, url.PathEscape(did))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+pat)
	for key, value := range sanitized {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform signature validation request: %w", err)
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	return decodeValidationResponse(resp)
}

// ValidateSignatureWithPATFromString accepts a string payload for convenience.
func ValidateSignatureWithPATFromString(ctx context.Context, cfg ClientAPIConfig, pat string, payload string, headers OperonHeaders) (*SignatureValidationResult, error) {
	return ValidateSignatureWithPAT(ctx, cfg, pat, []byte(payload), headers)
}

// DecodePayloadBase64 decodes a standard base64-encoded payload string so callers can populate TransactionRequest.Payload.
func DecodePayloadBase64(encoded string) ([]byte, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(trimmed)
}
