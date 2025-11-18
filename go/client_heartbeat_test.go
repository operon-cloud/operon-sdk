package operon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClientHeartbeatSendsRequests(t *testing.T) {
	t.Parallel()

	var tokenCount atomic.Int32
	var heartbeatCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			count := tokenCount.Add(1)
			fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, count)
		case "/client-api/v1/session/heartbeat":
			heartbeatCount.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		BaseURL:                  server.URL + "/client-api",
		TokenURL:                 server.URL + "/oauth2/token",
		ClientID:                 "client",
		ClientSecret:             "secret",
		SessionHeartbeatInterval: 10 * time.Millisecond,
		SessionHeartbeatTimeout:  2 * time.Second,
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, client.Init(context.Background()))
	time.Sleep(40 * time.Millisecond)

	require.GreaterOrEqual(t, heartbeatCount.Load(), int32(3), "expected multiple heartbeat calls")
}

func TestClientHeartbeatForcesRefreshOnUnauthorized(t *testing.T) {
	t.Parallel()

	var tokenCount atomic.Int32
	var heartbeatCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			count := tokenCount.Add(1)
			fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, count)
		case "/client-api/v1/session/heartbeat":
			call := heartbeatCount.Add(1)
			if call == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	cfg := Config{
		BaseURL:                  server.URL + "/client-api",
		TokenURL:                 server.URL + "/oauth2/token",
		ClientID:                 "client",
		ClientSecret:             "secret",
		SessionHeartbeatInterval: 10 * time.Millisecond,
		SessionHeartbeatTimeout:  time.Second,
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, client.Init(context.Background()))
	time.Sleep(60 * time.Millisecond)

	require.GreaterOrEqual(t, heartbeatCount.Load(), int32(2))
	require.GreaterOrEqual(t, tokenCount.Load(), int32(2), "force refresh should mint another token")
}
