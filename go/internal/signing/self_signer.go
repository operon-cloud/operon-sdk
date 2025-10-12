package signing

import (
    "context"
    "errors"
    "fmt"
    "net/http"
    "strings"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
	"github.com/operon-cloud/operon-sdk/go/internal/httpx"
)

// Result represents the structure returned by the signing endpoint.
type Result struct {
    Algorithm string
    Value     string
    KeyID     string
}

// Signer defines the behaviour required to obtain a digital signature for a
// pre-hashed payload.
type Signer interface {
    Sign(ctx context.Context, bearerToken string, payloadHash string, algorithm string) (Result, error)
}

// ErrSigningDisabled signals that the caller requested an operation while
// self-signing has been explicitly disabled in configuration.
var ErrSigningDisabled = errors.New("operon: self-signing disabled")

// DisabledSigner is a no-op implementation used when automatic self-signing is
// turned off.
type DisabledSigner struct{}

// Sign always returns ErrSigningDisabled. Callers should treat this as a cue to
// provide their own signature material.
func (DisabledSigner) Sign(ctx context.Context, bearerToken string, payloadHash string, algorithm string) (Result, error) {
    return Result{}, ErrSigningDisabled
}

// Config captures the inputs required to perform self-signing requests.
type Config struct {
    BaseURL    string
    HTTPClient httpx.Doer
}

// SelfSigner calls the Operon DID service to mint signatures on behalf of the
// authenticated participant.
type SelfSigner struct {
    baseURL string
    http    httpx.Doer
}

// NewSelfSigner creates an operational signer using the provided configuration.
func NewSelfSigner(cfg Config) (*SelfSigner, error) {
    if cfg.HTTPClient == nil {
        return nil, errors.New("HTTPClient is required")
    }
    baseURL := strings.TrimRight(cfg.BaseURL, "/")
    if baseURL == "" {
        return nil, errors.New("BaseURL is required")
    }

    return &SelfSigner{
        baseURL: baseURL,
        http:    cfg.HTTPClient,
    }, nil
}

// Sign invokes the platform DID endpoint to sign the provided hash using the
// caller's default signing key.
func (s *SelfSigner) Sign(ctx context.Context, bearerToken string, payloadHash string, algorithm string) (Result, error) {
    requestBody := map[string]string{
        "payloadHash":   payloadHash,
        "hashAlgorithm": "SHA-256",
        "algorithm":     algorithm,
    }

    req, err := httpx.NewJSONRequest(ctx, http.MethodPost, s.baseURL+"/v1/dids/self/sign", requestBody)
    if err != nil {
        return Result{}, fmt.Errorf("build sign request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+bearerToken)

    resp, err := s.http.Do(req)
    if err != nil {
        return Result{}, fmt.Errorf("self sign request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= http.StatusBadRequest {
        apiErr, decodeErr := apierrors.Decode(resp)
        if decodeErr != nil {
            return Result{}, decodeErr
        }
        return Result{}, apiErr
    }

    var payload struct {
        Signature struct {
            Algorithm string `json:"algorithm"`
            Value     string `json:"value"`
            KeyID     string `json:"keyId"`
        } `json:"signature"`
    }
    if err := httpx.DecodeJSON(resp, &payload); err != nil {
        return Result{}, err
    }

    result := Result{
        Algorithm: strings.TrimSpace(payload.Signature.Algorithm),
        Value:     strings.TrimSpace(payload.Signature.Value),
        KeyID:     strings.TrimSpace(payload.Signature.KeyID),
    }
    if result.Algorithm == "" || result.Value == "" {
        return Result{}, errors.New("sign response missing signature")
    }

    return result, nil
}
