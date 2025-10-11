package operon

import (
    "context"
    "fmt"
    "net/http"

    "github.com/operonmaster/operon-sdk/go/internal/httpx"
)

func (c *Client) authorizedJSONRequest(ctx context.Context, method, path, token string, payload any) (*http.Response, error) {
    req, err := httpx.NewJSONRequest(ctx, method, c.baseURL+path, payload)
    if err != nil {
        return nil, err
    }
    if token != "" {
        req.Header.Set("Authorization", "Bearer "+token)
    }

    resp, err := c.http.Do(req)
    if err != nil {
        return nil, fmt.Errorf("%s %s: %w", method, path, err)
    }
    return resp, nil
}

func closeSilently(resp *http.Response) {
    if resp == nil {
        return
    }
    _ = resp.Body.Close()
}
