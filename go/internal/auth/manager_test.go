package auth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mockDoer struct {
	responses []*http.Response
	calls     int
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	if m.calls >= len(m.responses) {
		return nil, io.EOF
	}
	resp := m.responses[m.calls]
	m.calls++
	return resp, nil
}

func newResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestClientCredentialsManagerCachesTokens(t *testing.T) {
	body := `{"access_token":"header.eyJwYXJ0aWNpcGFudF9kaWQiOiAiZGlkOmV4YW1wbGU6c291cmNlIn0.signature","token_type":"Bearer","expires_in":3600}`
	mock := &mockDoer{responses: []*http.Response{newResponse(http.StatusOK, body)}}

	manager, err := NewClientCredentialsManager(ClientCredentialsConfig{
		TokenURL:     "https://example/token",
		ClientID:     "client",
		ClientSecret: "secret",
		HTTPClient:   mock,
		Leeway:       time.Minute,
	})
	require.NoError(t, err)

	ctx := context.Background()

	token, err := manager.Token(ctx)
	require.NoError(t, err)
	require.Equal(t, "header.eyJwYXJ0aWNpcGFudF9kaWQiOiAiZGlkOmV4YW1wbGU6c291cmNlIn0.signature", token.AccessToken)
	require.Equal(t, "did:example:source", token.ParticipantDID)

	token2, err := manager.Token(ctx)
	require.NoError(t, err)
	require.Equal(t, token.AccessToken, token2.AccessToken)
	require.Equal(t, 1, mock.calls)
}

func TestClientCredentialsManagerHandlesErrorResponses(t *testing.T) {
	mock := &mockDoer{responses: []*http.Response{newResponse(http.StatusUnauthorized, `{"message":"unauthorised"}`)}}

	manager, err := NewClientCredentialsManager(ClientCredentialsConfig{
		TokenURL:     "https://example/token",
		ClientID:     "client",
		ClientSecret: "secret",
		HTTPClient:   mock,
	})
	require.NoError(t, err)

	_, err = manager.Token(context.Background())
	require.Error(t, err)
}

func TestNewClientCredentialsManagerValidation(t *testing.T) {
	_, err := NewClientCredentialsManager(ClientCredentialsConfig{})
	require.Error(t, err)

	_, err = NewClientCredentialsManager(ClientCredentialsConfig{TokenURL: "https://example", ClientID: "", ClientSecret: "secret", HTTPClient: &mockDoer{}})
	require.Error(t, err)
}

func TestExtractParticipantDIDHandlesInvalidToken(t *testing.T) {
	require.Equal(t, "", extractParticipantDID("invalid"))
}
