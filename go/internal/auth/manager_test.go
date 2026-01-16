package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mockDoer struct {
	responses []*http.Response
	requests  []*http.Request
	calls     int
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	if m.calls >= len(m.responses) {
		return nil, io.EOF
	}
	m.requests = append(m.requests, req)
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
	claims := `{"participant_did":"did:example:source","channel_id":"chnl-123","customer_id":"cust-456","workspace_id":"wksp-789","email":"user@example.com","name":"Example User","tenant_ids":["tenant-1","tenant-2"],"roles":["role-admin"],"member_id":"member-1","session_id":"session-1","org_id":"org-1"}`
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	body := fmt.Sprintf(`{"access_token":"header.%s.signature","token_type":"Bearer","expires_in":3600}`, payload)
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
	require.Equal(t, fmt.Sprintf("header.%s.signature", payload), token.AccessToken)
	require.Equal(t, "did:example:source", token.ParticipantDID)
	require.Equal(t, "chnl-123", token.WorkstreamID)
	require.Equal(t, "cust-456", token.CustomerID)
	require.Equal(t, "wksp-789", token.WorkspaceID)
	require.Equal(t, "user@example.com", token.Email)
	require.Equal(t, "Example User", token.Name)
	require.Equal(t, []string{"tenant-1", "tenant-2"}, token.TenantIDs)
	require.Equal(t, []string{"role-admin"}, token.Roles)
	require.Equal(t, "member-1", token.MemberID)
	require.Equal(t, "session-1", token.SessionID)
	require.Equal(t, "org-1", token.OrgID)

	require.Len(t, mock.requests, 1)
	req := mock.requests[0]
	require.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
	require.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("client:secret")), req.Header.Get("Authorization"))
	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	_ = req.Body.Close()
	require.Contains(t, string(bodyBytes), "grant_type=client_credentials")

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
