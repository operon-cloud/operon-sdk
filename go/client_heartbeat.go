package operon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/operon-cloud/operon-sdk/go/internal/apierrors"
)

var errHeartbeatUnauthorized = errors.New("session heartbeat unauthorized")

func (c *Client) startHeartbeat() {
	if c.heartbeatInterval <= 0 || c.heartbeatURL == "" {
		return
	}

	c.heartbeatOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		c.heartbeatCancel = cancel
		c.heartbeatWG.Add(1)
		go func() {
			defer c.heartbeatWG.Done()
			c.runHeartbeat(ctx)
		}()
	})
}

func (c *Client) stopHeartbeat() {
	cancel := c.heartbeatCancel
	if cancel == nil {
		return
	}
	cancel()
	c.heartbeatWG.Wait()
	c.heartbeatCancel = nil
}

func (c *Client) runHeartbeat(ctx context.Context) {
	c.performHeartbeat(ctx)

	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.performHeartbeat(ctx)
		}
	}
}

func (c *Client) performHeartbeat(parent context.Context) {
	ctx := parent
	var cancel context.CancelFunc
	if c.heartbeatTimeout > 0 {
		ctx, cancel = context.WithTimeout(parent, c.heartbeatTimeout)
		defer cancel()
	}

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return
	}

	if err := c.sendHeartbeat(ctx, token.AccessToken); err != nil {
		if errors.Is(err, errHeartbeatUnauthorized) {
			// Force minting of a new PAT immediately.
			_, _ = c.tokens.ForceRefresh(context.Background())
		}
	}
}

func (c *Client) sendHeartbeat(ctx context.Context, pat string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.heartbeatURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+pat)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		return errHeartbeatUnauthorized
	}
	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return decodeErr
		}
		return apiErr
	}
	return nil
}
