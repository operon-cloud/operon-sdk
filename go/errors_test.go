package operon

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeAPIErrorJSON(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Status:     "400 Bad Request",
		Body:       io.NopCloser(strings.NewReader("{\"code\":\"INVALID\",\"message\":\"invalid request\"}")),
	}

	err, decodeErr := decodeAPIError(resp)
	require.NoError(t, decodeErr)
	require.Equal(t, http.StatusBadRequest, err.StatusCode)
	require.Equal(t, "INVALID", err.Code)
	require.Equal(t, "invalid request", err.Message)
}

func TestDecodeAPIErrorEmptyBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Status:     "500 Internal Server Error",
		Body:       io.NopCloser(strings.NewReader("")),
	}

	err, decodeErr := decodeAPIError(resp)
	require.NoError(t, decodeErr)
	require.Equal(t, "500 Internal Server Error", err.Message)
}

func TestDecodeAPIErrorInvalidJSON(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Status:     "503 Service Unavailable",
		Body:       io.NopCloser(strings.NewReader("<!doctype html>")),
	}

	err, decodeErr := decodeAPIError(resp)
	require.NoError(t, decodeErr)
	require.Equal(t, "<!doctype html>", err.Message)
}
