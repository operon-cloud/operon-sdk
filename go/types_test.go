package operon

import (
	"encoding/base64"
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
		ChannelID:     "channel",
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
	req := TransactionRequest{CorrelationID: "123", ChannelID: "channel", InteractionID: "interaction", SourceDID: "did:example:source", TargetDID: "did:example:target", Signature: Signature{Algorithm: AlgorithmEd25519, Value: "sig"}, PayloadHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
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
		ChannelID:     "channel",
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
