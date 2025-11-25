package dids

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestVerifyJWS_EdDSA(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kid := "did:operon:root#k-ed25519"
	header := jwsHeader{Alg: "EdDSA", Kid: kid}
	hb, _ := json.Marshal(header)
	payload := []byte(`{"ok":true}`)
	jws, err := signEdDSA(hb, payload, priv)
	if err != nil {
		t.Fatalf("sign eddsa: %v", err)
	}

	vm := VM{
		ID:   kid,
		Type: "JsonWebKey2020",
		PublicKeyJWK: &JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(pub),
		},
	}
	doc := &Document{VerificationMethod: []VM{vm}}

	if err := VerifyJWS(context.Background(), jws, doc, ""); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyJWS_ES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kid := "did:operon:root#k-es256"
	payload := []byte(`{"ok":true}`)
	jws, err := signES256(payload, key, kid)
	if err != nil {
		t.Fatalf("sign es256: %v", err)
	}

	vm := VM{
		ID:   kid,
		Type: "JsonWebKey2020",
		PublicKeyJWK: &JWK{
			Kty: "EC",
			Crv: "P-256",
			Kid: kid,
			X:   base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		},
	}
	doc := &Document{VerificationMethod: []VM{vm}}

	if err := VerifyJWS(context.Background(), jws, doc, ""); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyJWS_UnsupportedAlg(t *testing.T) {
	jws := "eyJhbGciOiJFUzI1NksifQ.e30.AQID" // bogus ES256K
	doc := &Document{}
	err := VerifyJWS(context.Background(), jws, doc, "")
	if err == nil || !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("expected unsupported alg error, got %v", err)
	}
}

// signEdDSA builds a compact JWS for EdDSA (Ed25519).
func signEdDSA(headerJSON, payload []byte, key ed25519.PrivateKey) (string, error) {
	encodedHeader := encodeSegment(headerJSON)
	encodedPayload := encodeSegment(payload)
	signing := string(encodedHeader) + "." + string(encodedPayload)
	sig := ed25519.Sign(key, []byte(signing))
	encodedSig := encodeSegment(sig)
	return signing + "." + string(encodedSig), nil
}
