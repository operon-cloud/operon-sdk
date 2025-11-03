package operon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/operon-cloud/operon-sdk/go/internal/signing"
)

const (
	HeaderOperonDID           = "X-Operon-DID"
	HeaderOperonPayloadHash   = "X-Operon-Payload-Hash"
	HeaderOperonSignature     = "X-Operon-Signature"
	HeaderOperonSignatureKey  = "X-Operon-Signature-KeyId"
	HeaderOperonSignatureAlgo = "X-Operon-Signature-Alg"
)

// OperonHeaders captures the HTTP headers required to convey a signed payload across Operon participants.
type OperonHeaders map[string]string

// GenerateSignatureHeaders signs the supplied payload using the participant's managed keys and returns Operon header values.
func (c *Client) GenerateSignatureHeaders(ctx context.Context, payload []byte, algorithm string) (OperonHeaders, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	selectedAlgorithm := strings.TrimSpace(algorithm)
	if selectedAlgorithm == "" {
		selectedAlgorithm = c.signingAlgorithm
	} else {
		var ok bool
		if selectedAlgorithm, ok = canonicalSigningAlgorithm(selectedAlgorithm); !ok {
			return nil, fmt.Errorf("unsupported signing algorithm %s", algorithm)
		}
	}

	digest := sha256.Sum256(payload)
	payloadHash := base64.RawURLEncoding.EncodeToString(digest[:])

	token, err := c.tokenValue(ctx)
	if err != nil {
		return nil, err
	}

	if !c.selfSigning {
		return nil, errors.New("automatic signing disabled: enable self signing to generate headers")
	}

	signature, err := c.signer.Sign(ctx, token, payloadHash, selectedAlgorithm)
	if err != nil {
		if errors.Is(err, signing.ErrSigningDisabled) {
			return nil, errors.New("automatic signing disabled: enable self signing to generate headers")
		}
		return nil, err
	}

	did := strings.TrimSpace(c.cachedParticipantDID())
	if did == "" {
		return nil, errors.New("participant DID unavailable on access token")
	}

	keyID := strings.TrimSpace(signature.KeyID)
	if keyID == "" {
		keyID = did + defaultKeyIDSuffix
	}

	headers := OperonHeaders{
		HeaderOperonDID:           did,
		HeaderOperonPayloadHash:   payloadHash,
		HeaderOperonSignature:     strings.TrimSpace(signature.Value),
		HeaderOperonSignatureKey:  keyID,
		HeaderOperonSignatureAlgo: strings.TrimSpace(signature.Algorithm),
	}

	if headers[HeaderOperonSignature] == "" {
		return nil, errors.New("signature value missing from signing response")
	}
	if headers[HeaderOperonSignatureAlgo] == "" {
		headers[HeaderOperonSignatureAlgo] = selectedAlgorithm
	}

	return headers, nil
}

// GenerateSignatureHeadersFromString is a convenience wrapper accepting payloads as strings.
func (c *Client) GenerateSignatureHeadersFromString(ctx context.Context, payload string, algorithm string) (OperonHeaders, error) {
	return c.GenerateSignatureHeaders(ctx, []byte(payload), algorithm)
}
