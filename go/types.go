package operon

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AlgorithmEd25519 = "EdDSA"
	AlgorithmES256   = "ES256"
	AlgorithmES256K  = "ES256K"
)

// Signature captures the digital signature metadata required by the Operon client API.
type Signature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	KeyID     string `json:"keyId,omitempty"`
}

// Transaction mirrors the persisted domain entity returned by TrustOperon services.
type Transaction struct {
	ID                    string    `json:"id"`
	CorrelationID         string    `json:"correlationId"`
	ChannelID             string    `json:"channelId"`
	CustomerID            string    `json:"customerId,omitempty"`
	WorkspaceID           string    `json:"workspaceId,omitempty"`
	InteractionID         string    `json:"interactionId"`
	Timestamp             time.Time `json:"timestamp"`
	SourceDID             string    `json:"sourceDid"`
	TargetDID             string    `json:"targetDid"`
	Signature             Signature `json:"signature"`
	Label                 string    `json:"label,omitempty"`
	Tags                  []string  `json:"tags,omitempty"`
	PayloadHash           string    `json:"payloadHash"`
	Status                string    `json:"status"`
	HCSTopicID            string    `json:"hcsTopicId,omitempty"`
	HCSSequenceNumber     int64     `json:"hcsSequenceNumber,omitempty"`
	HCSConsensusTimestamp string    `json:"hcsConsensusTimestamp,omitempty"`
	HCSTransactionID      string    `json:"hcsTransactionId,omitempty"`
	HCSRunningHash        string    `json:"hcsRunningHash,omitempty"`
	CreatedAt             time.Time `json:"createdAt"`
	UpdatedAt             time.Time `json:"updatedAt"`
	CreatedBy             string    `json:"createdBy,omitempty"`
	UpdatedBy             string    `json:"updatedBy,omitempty"`
	Version               int       `json:"version,omitempty"`
}

// TransactionRequest captures the payload submitted by SDK callers.
type TransactionRequest struct {
	CorrelationID string    `json:"correlationId"`
	ChannelID     string    `json:"channelId,omitempty"`
	InteractionID string    `json:"interactionId"`
	Timestamp     time.Time `json:"timestamp,omitempty"`
	SourceDID     string    `json:"sourceDid,omitempty"`
	TargetDID     string    `json:"targetDid,omitempty"`
	Signature     Signature `json:"signature"`
	Label         string    `json:"label,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	Payload       []byte    `json:"-"`
	PayloadHash   string    `json:"payloadHash,omitempty"`
}

type InteractionSummary struct {
	ID                  string
	ChannelID           string
	SourceParticipantID string
	TargetParticipantID string
	SourceDID           string
	TargetDID           string
}

type ParticipantSummary struct {
	ID  string
	DID string
}

// tokenRequest mirrors the JSON payload expected by the identity broker for M2M token issuance.
type transactionSubmission struct {
	CorrelationID string    `json:"correlationId"`
	ChannelID     string    `json:"channelId"`
	InteractionID string    `json:"interactionId"`
	Timestamp     string    `json:"timestamp"`
	SourceDID     string    `json:"sourceDid"`
	TargetDID     string    `json:"targetDid"`
	Signature     Signature `json:"signature"`
	PayloadHash   string    `json:"payloadHash"`
	Label         string    `json:"label,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
}

// ValidateForSubmit verifies the client-side invariants for a TransactionRequest prior to submission.
func (r TransactionRequest) ValidateForSubmit() error {
	if strings.TrimSpace(r.CorrelationID) == "" {
		return errors.New("CorrelationID is required")
	}
	if strings.TrimSpace(r.ChannelID) == "" {
		return errors.New("ChannelID is required")
	}
	if strings.TrimSpace(r.InteractionID) == "" {
		return errors.New("InteractionID is required")
	}
	if strings.TrimSpace(r.SourceDID) == "" {
		return errors.New("SourceDID is required")
	}
	if !strings.HasPrefix(strings.TrimSpace(r.SourceDID), "did:") {
		return errors.New("SourceDID must be a valid DID")
	}
	if strings.TrimSpace(r.TargetDID) == "" {
		return errors.New("TargetDID is required")
	}
	if !strings.HasPrefix(strings.TrimSpace(r.TargetDID), "did:") {
		return errors.New("TargetDID must be a valid DID")
	}
	if len(r.Payload) == 0 && strings.TrimSpace(r.PayloadHash) == "" {
		return errors.New("payload bytes or payload hash is required")
	}
	if strings.TrimSpace(r.Signature.Algorithm) == "" {
		return errors.New("Signature algorithm is required")
	}
	if strings.TrimSpace(r.Signature.Value) == "" {
		return errors.New("Signature value is required")
	}
	return nil
}

func (r *TransactionRequest) resolvePayload() (encoded string, hash string, err error) {
	if len(r.Payload) > 0 {
		encoded = base64.StdEncoding.EncodeToString(r.Payload)
		sum := sha256.Sum256(r.Payload)
		hash = base64.RawURLEncoding.EncodeToString(sum[:])
		if strings.TrimSpace(r.PayloadHash) != "" && !strings.EqualFold(r.PayloadHash, hash) {
			return "", "", fmt.Errorf("provided payload hash does not match payload content: expected %s got %s", hash, r.PayloadHash)
		}
		return encoded, hash, nil
	}

	hash = strings.TrimSpace(r.PayloadHash)
	if hash == "" {
		return "", "", errors.New("payload bytes or payload hash is required")
	}
	if err := validatePayloadHashFormat(hash); err != nil {
		return "", "", err
	}
	return "", hash, nil
}

func validatePayloadHashFormat(hash string) error {
	if len(hash) != 43 {
		return fmt.Errorf("payload hash must be 43 characters, got %d", len(hash))
	}
	if _, err := base64.RawURLEncoding.DecodeString(hash); err != nil {
		return fmt.Errorf("payload hash must be base64url encoded: %w", err)
	}
	return nil
}

var signingAlgorithms = []string{
	AlgorithmEd25519,
	AlgorithmES256,
	AlgorithmES256K,
}

func canonicalSigningAlgorithm(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}
	for _, candidate := range signingAlgorithms {
		if strings.EqualFold(trimmed, candidate) {
			return candidate, true
		}
	}
	return "", false
}

// MarshalJSON ensures timestamp zero values are omitted when serialising TransactionRequest (useful for tests/examples).
func (r TransactionRequest) MarshalJSON() ([]byte, error) {
	type Alias TransactionRequest
	aux := struct {
		Alias
		Timestamp string `json:"timestamp,omitempty"`
	}{Alias: Alias(r)}
	if !r.Timestamp.IsZero() {
		aux.Timestamp = r.Timestamp.Format(time.RFC3339Nano)
	}
	return json.Marshal(aux)
}
