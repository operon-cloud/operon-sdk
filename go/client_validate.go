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

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/httpx"
)

// SignatureValidationResult captures the response returned by the Operon signature validation endpoint.
type SignatureValidationResult struct {
	Status      string
	Message     string
	DID         string
	PayloadHash string
	Algorithm   string
	KeyID       string
}

// ValidateSignatureHeaders confirms that the supplied signature headers match the payload.
func (c *Client) ValidateSignatureHeaders(ctx context.Context, payload []byte, headers OperonHeaders) (*SignatureValidationResult, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	sanitized, err := sanitizeOperonHeaders(headers)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(payload)
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	expected := sanitized[HeaderOperonPayloadHash]
	if !strings.EqualFold(computed, expected) {
		return nil, fmt.Errorf("payload hash mismatch: expected %s, got %s", computed, expected)
	}

	token, err := c.tokenValue(ctx)
	if err != nil {
		return nil, err
	}

	did := sanitized[HeaderOperonDID]
	path := fmt.Sprintf("%s/v1/dids/%s/signature/verify", c.baseURL, url.PathEscape(did))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for key, value := range sanitized {
		req.Header.Set(key, value)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /v1/dids/{did}/signature/verify: %w", err)
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

// ValidateSignatureHeadersFromString is a convenience wrapper accepting string payloads.
func (c *Client) ValidateSignatureHeadersFromString(ctx context.Context, payload string, headers OperonHeaders) (*SignatureValidationResult, error) {
	return c.ValidateSignatureHeaders(ctx, []byte(payload), headers)
}

func sanitizeOperonHeaders(headers OperonHeaders) (map[string]string, error) {
	if headers == nil {
		return nil, errors.New("operon headers cannot be nil")
	}

	required := []string{
		HeaderOperonDID,
		HeaderOperonPayloadHash,
		HeaderOperonSignature,
		HeaderOperonSignatureKey,
		HeaderOperonSignatureAlgo,
	}

	result := make(map[string]string, len(required))
	for _, key := range required {
		value := strings.TrimSpace(headers[key])
		if value == "" {
			return nil, fmt.Errorf("header %s is required", key)
		}
		result[key] = value
	}

	return result, nil
}

func decodeValidationResponse(resp *http.Response) (*SignatureValidationResult, error) {
	var payloadResp struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		DID         string `json:"did"`
		PayloadHash string `json:"payloadHash"`
		Algorithm   string `json:"algorithm"`
		KeyID       string `json:"keyId"`
	}
	if err := httpx.DecodeJSON(resp, &payloadResp); err != nil {
		return nil, err
	}

	return &SignatureValidationResult{
		Status:      payloadResp.Status,
		Message:     payloadResp.Message,
		DID:         payloadResp.DID,
		PayloadHash: payloadResp.PayloadHash,
		Algorithm:   payloadResp.Algorithm,
		KeyID:       payloadResp.KeyID,
	}, nil
}
