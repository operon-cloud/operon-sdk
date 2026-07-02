package operon

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/operon-cloud/operon-sdk/go/internal/auth"
)

// TokenProvider supplies short-lived bearer tokens for SDK requests.
type TokenProvider interface {
	Token(ctx context.Context) (Token, error)
}

// Token captures an access token and known Operon claims supplied by a caller-owned provider.
type Token struct {
	AccessToken     string
	ExpiresAt       time.Time
	ParticipantDID  string
	ParticipantID   string
	ParticipantName string
	WorkstreamID    string
	WorkspaceID     string
	CustomerID      string
	Email           string
	Name            string
	TenantIDs       []string
	Roles           []string
	MemberID        string
	SessionID       string
	OrgID           string
}

type forceRefreshTokenProvider interface {
	ForceRefresh(ctx context.Context) (Token, error)
}

type tokenProviderAdapter struct {
	provider TokenProvider
}

func (a tokenProviderAdapter) Token(ctx context.Context) (auth.Token, error) {
	token, err := a.provider.Token(ctx)
	if err != nil {
		return auth.Token{}, err
	}
	return publicTokenToInternal(token)
}

func (a tokenProviderAdapter) ForceRefresh(ctx context.Context) (auth.Token, error) {
	if refresher, ok := a.provider.(forceRefreshTokenProvider); ok {
		token, err := refresher.ForceRefresh(ctx)
		if err != nil {
			return auth.Token{}, err
		}
		return publicTokenToInternal(token)
	}
	return a.Token(ctx)
}

func publicTokenToInternal(token Token) (auth.Token, error) {
	accessToken := strings.TrimSpace(token.AccessToken)
	if accessToken == "" {
		return auth.Token{}, errors.New("token provider returned empty access token")
	}

	claims := auth.DecodeTokenClaims(accessToken)
	expiresAt := token.ExpiresAt
	if expiresAt.IsZero() && claims.ExpiresAt > 0 {
		expiresAt = time.Unix(claims.ExpiresAt, 0).UTC()
	}

	return auth.Token{
		AccessToken:     accessToken,
		ParticipantDID:  firstNonEmpty(token.ParticipantDID, claims.ParticipantDID),
		ParticipantID:   firstNonEmpty(token.ParticipantID, claims.ParticipantID),
		ParticipantName: firstNonEmpty(token.ParticipantName, claims.ParticipantName),
		WorkstreamID:    firstNonEmpty(token.WorkstreamID, claims.WorkstreamID),
		CustomerID:      firstNonEmpty(token.CustomerID, claims.CustomerID),
		WorkspaceID:     firstNonEmpty(token.WorkspaceID, claims.WorkspaceID),
		Email:           firstNonEmpty(token.Email, claims.Email),
		Name:            firstNonEmpty(token.Name, claims.Name),
		TenantIDs:       firstNonEmptyStringSlice(token.TenantIDs, claims.TenantIDs),
		Roles:           firstNonEmptyStringSlice(token.Roles, claims.Roles),
		MemberID:        firstNonEmpty(token.MemberID, claims.MemberID),
		SessionID:       firstNonEmpty(token.SessionID, claims.SessionID),
		OrgID:           firstNonEmpty(token.OrgID, claims.OrgID),
		Expiry:          expiresAt,
	}, nil
}

func firstNonEmptyStringSlice(primary, fallback []string) []string {
	if primary != nil {
		return normalizeStringSlice(primary)
	}
	return normalizeStringSlice(fallback)
}

func normalizeStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
