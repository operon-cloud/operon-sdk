package httpx

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
)

// Doer represents the subset of http.Client used across the SDK. It is
// intentionally small so callers can supply custom transports (for example to
// inject tracing, retries, or record fixtures in tests).
type Doer interface {
    Do(*http.Request) (*http.Response, error)
}

// NewJSONRequest serialises the given payload as JSON (if non-nil) and creates
// an HTTP request bound to the supplied context.
func NewJSONRequest(ctx context.Context, method, url string, payload any) (*http.Request, error) {
    var body io.Reader
    if payload != nil {
        raw, err := json.Marshal(payload)
        if err != nil {
            return nil, fmt.Errorf("marshal payload: %w", err)
        }
        body = bytes.NewReader(raw)
    }

    req, err := http.NewRequestWithContext(ctx, method, url, body)
    if err != nil {
        return nil, err
    }

    if payload != nil {
        req.Header.Set("Content-Type", "application/json")
    }

    return req, nil
}

// DecodeJSON unmarshals the provided HTTP response body into the supplied
// target. It expects the caller to close resp.Body when finished.
func DecodeJSON(resp *http.Response, target any) error {
    if target == nil {
        return fmt.Errorf("decode target must be non-nil")
    }
    dec := json.NewDecoder(resp.Body)
    if err := dec.Decode(target); err != nil {
        return fmt.Errorf("decode response: %w", err)
    }
    return nil
}
