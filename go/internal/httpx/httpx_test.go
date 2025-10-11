package httpx

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type badJSON struct{}

func (badJSON) MarshalJSON() ([]byte, error) {
	return nil, io.EOF
}

func TestNewJSONRequestWithPayload(t *testing.T) {
	payload := map[string]string{"foo": "bar"}
	req, err := NewJSONRequest(context.Background(), http.MethodPost, "https://example.com", payload)
	require.NoError(t, err)
	require.Equal(t, http.MethodPost, req.Method)
	require.Equal(t, "https://example.com", req.URL.String())
	require.Equal(t, "application/json", req.Header.Get("Content-Type"))

	var decoded map[string]string
	require.NoError(t, json.NewDecoder(req.Body).Decode(&decoded))
	require.Equal(t, payload, decoded)
}

func TestNewJSONRequestWithoutPayload(t *testing.T) {
	req, err := NewJSONRequest(context.Background(), http.MethodGet, "https://example.com/path", nil)
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, req.Method)
	require.Empty(t, req.Header.Get("Content-Type"))
	require.Nil(t, req.Body)
}

func TestNewJSONRequestMarshalError(t *testing.T) {
	_, err := NewJSONRequest(context.Background(), http.MethodPost, "https://example.com", badJSON{})
	require.Error(t, err)
}

func TestDecodeJSON(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("{\"value\":42}"))}
	var target struct{ Value int }
	require.NoError(t, DecodeJSON(resp, &target))
	require.Equal(t, 42, target.Value)
}

func TestDecodeJSONRequiresTarget(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("{}"))}
	require.Error(t, DecodeJSON(resp, nil))
}
