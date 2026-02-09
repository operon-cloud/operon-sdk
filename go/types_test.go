package operon

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTransactionRequestResolvePayloadBytes(t *testing.T) {
	req := TransactionRequest{Payload: []byte("hello")}
	encoded, hash, err := req.resolvePayload()
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), encoded)
	require.Len(t, hash, 43)
}

func TestTransactionRequestResolvePayloadMismatch(t *testing.T) {
	req := TransactionRequest{Payload: []byte("hello"), PayloadHash: base64.RawURLEncoding.EncodeToString([]byte("different"))}
	_, _, err := req.resolvePayload()
	require.Error(t, err)
}

func TestTransactionRequestValidateForSubmit(t *testing.T) {
	req := TransactionRequest{
		CorrelationID: "123",
		WorkstreamID:  "workstream",
		InteractionID: "interaction",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Signature:     Signature{Algorithm: AlgorithmEd25519, Value: "sig"},
		PayloadHash:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	require.NoError(t, req.ValidateForSubmit())

	req.TargetDID = "example"
	require.Error(t, req.ValidateForSubmit())
}

func TestTransactionRequestMarshalJSONOmitsZeroTimestamp(t *testing.T) {
	req := TransactionRequest{CorrelationID: "123", WorkstreamID: "workstream", InteractionID: "interaction", SourceDID: "did:example:source", TargetDID: "did:example:target", Signature: Signature{Algorithm: AlgorithmEd25519, Value: "sig"}, PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	raw, err := req.MarshalJSON()
	require.NoError(t, err)
	require.NotContains(t, string(raw), "timestamp")

	req.Timestamp = time.Unix(0, 0).UTC()
	raw, err = req.MarshalJSON()
	require.NoError(t, err)
	require.Contains(t, string(raw), "timestamp")
}

func TestTransactionRequestResolvePayloadInvalidHashLength(t *testing.T) {
	req := TransactionRequest{PayloadHash: "short"}
	_, _, err := req.resolvePayload()
	require.Error(t, err)
}

func TestTransactionRequestResolvePayloadInvalidHashEncoding(t *testing.T) {
	req := TransactionRequest{PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#"}
	_, _, err := req.resolvePayload()
	require.Error(t, err)
}

func TestTransactionRequestValidateForSubmitMissingFields(t *testing.T) {
	req := TransactionRequest{}
	require.Error(t, req.ValidateForSubmit())
}

func TestValidatePayloadHashFormatSuccess(t *testing.T) {
	hash := base64.RawURLEncoding.EncodeToString(make([]byte, 32))[:43]
	require.NoError(t, validatePayloadHashFormat(hash))
}

func TestTransactionRequestValidateForSubmitErrors(t *testing.T) {
	base := TransactionRequest{
		CorrelationID: "corr",
		WorkstreamID:  "workstream",
		InteractionID: "interaction",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Signature:     Signature{Algorithm: AlgorithmEd25519, Value: "sig"},
		PayloadHash:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	cases := map[string]func(*TransactionRequest){
		"missing source":  func(r *TransactionRequest) { r.SourceDID = "" },
		"invalid source":  func(r *TransactionRequest) { r.SourceDID = "source" },
		"missing target":  func(r *TransactionRequest) { r.TargetDID = "" },
		"invalid target":  func(r *TransactionRequest) { r.TargetDID = "target" },
		"missing payload": func(r *TransactionRequest) { r.PayloadHash = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := base
			mutate(&req)
			require.Error(t, req.ValidateForSubmit())
		})
	}
}

func TestTransactionRequestValidateForSubmitRequiresExternalSources(t *testing.T) {
	base := TransactionRequest{
		CorrelationID: "corr",
		WorkstreamID:  "workstream",
		InteractionID: "interaction",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Signature:     Signature{Algorithm: AlgorithmEd25519, Value: "sig"},
		PayloadHash:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	actorMissingSource := base
	actorMissingSource.ActorExternalID = "actor-1"
	require.ErrorContains(t, actorMissingSource.ValidateForSubmit(), "ActorExternalSource")

	assigneeMissingSource := base
	assigneeMissingSource.AssigneeExternalDisplayName = "Owner"
	require.ErrorContains(t, assigneeMissingSource.ValidateForSubmit(), "AssigneeExternalSource")
}

func TestTransactionRequestValidateForSubmitRejectsNegativeLegacyROI(t *testing.T) {
	base := TransactionRequest{
		CorrelationID: "corr",
		WorkstreamID:  "workstream",
		InteractionID: "interaction",
		SourceDID:     "did:example:source",
		TargetDID:     "did:example:target",
		Signature:     Signature{Algorithm: AlgorithmEd25519, Value: "sig"},
		PayloadHash:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	req := base
	req.ROIBaseCost = -1
	require.ErrorContains(t, req.ValidateForSubmit(), "ROIBaseCost")

	req = base
	req.ROIBaseTime = -1
	require.ErrorContains(t, req.ValidateForSubmit(), "ROIBaseTime")

	req = base
	req.ROICostSaving = -1
	require.ErrorContains(t, req.ValidateForSubmit(), "ROICostSaving")

	req = base
	req.ROITimeSaving = -1
	require.ErrorContains(t, req.ValidateForSubmit(), "ROITimeSaving")
}

func TestTransactionUnmarshalIncludesExternalAndLegacyROIFields(t *testing.T) {
	raw := []byte(`{
		"id":"txn-1",
		"correlationId":"corr-1",
		"workstreamId":"wstr-1",
		"interactionId":"intr-1",
		"timestamp":"2026-01-01T00:00:00Z",
		"sourceDid":"did:example:source",
		"targetDid":"did:example:target",
		"roiBaseCost":13,
		"roiBaseTime":21,
		"roiCostSaving":8,
		"roiTimeSaving":5,
		"actorExternalId":"actor-1",
		"actorExternalDisplayName":"Actor One",
		"actorExternalSource":"crm",
		"assigneeExternalId":"assignee-1",
		"assigneeExternalDisplayName":"Assignee One",
		"assigneeExternalSource":"crm",
		"payloadHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"signature":{"algorithm":"EdDSA","value":"sig"},
		"status":"received",
		"createdAt":"2026-01-01T00:00:00Z",
		"updatedAt":"2026-01-01T00:00:00Z"
	}`)

	var txn Transaction
	require.NoError(t, json.Unmarshal(raw, &txn))
	require.Equal(t, 13, txn.ROIBaseCost)
	require.Equal(t, 21, txn.ROIBaseTime)
	require.Equal(t, 8, txn.ROICostSaving)
	require.Equal(t, 5, txn.ROITimeSaving)
	require.Equal(t, "actor-1", txn.ActorExternalID)
	require.Equal(t, "Actor One", txn.ActorExternalDisplayName)
	require.Equal(t, "crm", txn.ActorExternalSource)
	require.Equal(t, "assignee-1", txn.AssigneeExternalID)
	require.Equal(t, "Assignee One", txn.AssigneeExternalDisplayName)
	require.Equal(t, "crm", txn.AssigneeExternalSource)
}
