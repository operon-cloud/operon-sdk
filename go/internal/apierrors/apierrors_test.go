package apierrors

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorString(t *testing.T) {
	err := &APIError{Code: "INVALID", Message: "bad"}
	require.Equal(t, "operon: bad (INVALID)", err.Error())

	err = &APIError{Message: "oops"}
	require.Equal(t, "operon: oops", err.Error())
}

func TestDecodeJSON(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Status:     "403 Forbidden",
		Body:       io.NopCloser(strings.NewReader("{\"code\":\"DENIED\",\"message\":\"nope\"}")),
	}
	err, decodeErr := Decode(resp)
	require.NoError(t, decodeErr)
	require.Equal(t, 403, err.StatusCode)
	require.Equal(t, "DENIED", err.Code)
	require.Equal(t, "nope", err.Message)
}

func TestDecodeFallbacks(t *testing.T) {
	resp := &http.Response{StatusCode: 500, Status: "500 Internal Server Error", Body: io.NopCloser(strings.NewReader(""))}
	err, decodeErr := Decode(resp)
	require.NoError(t, decodeErr)
	require.Equal(t, "500 Internal Server Error", err.Message)

	resp = &http.Response{StatusCode: 502, Status: "502 Bad Gateway", Body: io.NopCloser(strings.NewReader("<html>"))}
	err, decodeErr = Decode(resp)
	require.NoError(t, decodeErr)
	require.Equal(t, "<html>", err.Message)
}
