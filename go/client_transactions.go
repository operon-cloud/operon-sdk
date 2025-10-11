package operon

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/operonmaster/operon-sdk/go/internal/apierrors"
	"github.com/operonmaster/operon-sdk/go/internal/httpx"
	"github.com/operonmaster/operon-sdk/go/internal/signing"
)

// SubmitTransaction submits a transaction payload to the Operon client API and returns the persisted record.
func (c *Client) SubmitTransaction(ctx context.Context, req TransactionRequest) (*Transaction, error) {
	if err := c.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	if err := c.populateInteractionFields(ctx, &req); err != nil {
		return nil, err
	}

	payloadData, payloadHash, err := req.resolvePayload()
	if err != nil {
		return nil, err
	}
	req.PayloadHash = payloadHash

	sanitizedLabel := strings.TrimSpace(req.Label)
	sanitizedTags := make([]string, 0, len(req.Tags))
	for _, tag := range req.Tags {
		trimmed := strings.TrimSpace(tag)
		if trimmed == "" {
			continue
		}
		sanitizedTags = append(sanitizedTags, trimmed)
	}

	token, err := c.tokenValue(ctx)
	if err != nil {
		return nil, err
	}

	signature := req.Signature
	if c.selfSigning && strings.TrimSpace(signature.Value) == "" {
		signed, signErr := c.signer.Sign(ctx, token, payloadHash, c.signingAlgorithm)
		if signErr != nil {
			if errors.Is(signErr, signing.ErrSigningDisabled) {
				return nil, errors.New("automatic signing disabled: provide signature manually or enable self signing")
			}
			return nil, signErr
		}
		signature = Signature{
			Algorithm: signed.Algorithm,
			Value:     signed.Value,
			KeyID:     signed.KeyID,
		}
	}

	if strings.TrimSpace(signature.KeyID) == "" {
		source := strings.TrimSpace(req.SourceDID)
		if source == "" {
			if did := c.cachedParticipantDID(); did != "" {
				source = did
			}
		}
		if source != "" {
			signature.KeyID = source + defaultKeyIDSuffix
		}
	}

	req.Signature = signature
	if err := req.ValidateForSubmit(); err != nil {
		return nil, err
	}

	timestamp := req.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	apiReq := transactionSubmission{
		CorrelationID: req.CorrelationID,
		ChannelID:     req.ChannelID,
		InteractionID: req.InteractionID,
		Timestamp:     timestamp.Format(time.RFC3339Nano),
		SourceDID:     req.SourceDID,
		TargetDID:     req.TargetDID,
		Signature:     signature,
		PayloadData:   payloadData,
		PayloadHash:   payloadHash,
	}
	if sanitizedLabel != "" {
		apiReq.Label = sanitizedLabel
	}
	if len(sanitizedTags) > 0 {
		apiReq.Tags = sanitizedTags
	}

	resp, err := c.authorizedJSONRequest(ctx, http.MethodPost, "/v1/transactions", token, apiReq)
	if err != nil {
		return nil, err
	}
	defer closeSilently(resp)

	if resp.StatusCode >= http.StatusBadRequest {
		apiErr, decodeErr := apierrors.Decode(resp)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, apiErr
	}

	var txn Transaction
	if err := httpx.DecodeJSON(resp, &txn); err != nil {
		return nil, err
	}

	return &txn, nil
}
