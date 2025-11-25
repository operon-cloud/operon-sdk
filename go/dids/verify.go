package dids

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// VerifyJWS verifies a compact JWS using keys from the provided DID Document or by resolving the DID.
// Supported algorithms: EdDSA (Ed25519), ES256 (P-256). ES256K is not supported in stdlib.
func VerifyJWS(ctx context.Context, jws string, doc *Document, did string, opts ...Option) error {
	if doc == nil {
		if did == "" {
			return errors.New("either doc or did must be provided")
		}
		resolved, err := Resolve(ctx, did, opts...)
		if err != nil {
			return err
		}
		doc = resolved
	}

	protected, sig, headerB64, payloadB64, err := splitJWS(jws)
	if err != nil {
		return err
	}

	var header jwsHeader
	if err := json.Unmarshal(protected, &header); err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}

	switch header.Alg {
	case "EdDSA":
		return verifyEdDSA(header, doc, headerB64, payloadB64, sig)
	case "ES256":
		return verifyES256(header, doc, headerB64, payloadB64, sig)
	case "ES256K":
		return fmt.Errorf("%w: ES256K not supported by stdlib", ErrUnsupportedAlg)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAlg, header.Alg)
	}
}

type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func splitJWS(jws string) ([]byte, []byte, string, string, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, nil, "", "", fmt.Errorf("%w: expected 3 parts", ErrDecode)
	}

	dec := base64.RawURLEncoding
	protected, err := dec.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("%w: %v", ErrDecode, err)
	}
	sig, err := dec.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("%w: %v", ErrDecode, err)
	}
	return protected, sig, parts[0], parts[1], nil
}

func findVM(doc *Document, kid string) (*VM, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.ID == kid {
			return &vm, nil
		}
		if vm.PublicKeyJWK != nil && vm.PublicKeyJWK.Kid != "" && vm.PublicKeyJWK.Kid == kid {
			return &vm, nil
		}
	}
	return nil, ErrKeyNotFound
}

func verifyEdDSA(header jwsHeader, doc *Document, headerB64, payloadB64 string, sig []byte) error {
	vm, err := findVM(doc, header.Kid)
	if err != nil {
		return err
	}
	if vm.PublicKeyJWK == nil || vm.PublicKeyJWK.Kty != "OKP" || vm.PublicKeyJWK.Crv != "Ed25519" || vm.PublicKeyJWK.X == "" {
		return fmt.Errorf("%w: missing or invalid Ed25519 key", ErrKeyNotFound)
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(vm.PublicKeyJWK.X)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: unexpected key length", ErrDecode)
	}
	pub := ed25519.PublicKey(pubKeyBytes)

	signing := headerB64 + "." + payloadB64
	if !ed25519.Verify(pub, []byte(signing), sig) {
		return ErrVerifyFailed
	}
	return nil
}

func verifyES256(header jwsHeader, doc *Document, headerB64, payloadB64 string, sig []byte) error {
	vm, err := findVM(doc, header.Kid)
	if err != nil {
		return err
	}
	if vm.PublicKeyJWK == nil || vm.PublicKeyJWK.Kty != "EC" || vm.PublicKeyJWK.Crv != "P-256" || vm.PublicKeyJWK.X == "" || vm.PublicKeyJWK.Y == "" {
		return fmt.Errorf("%w: missing or invalid P-256 key", ErrKeyNotFound)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(vm.PublicKeyJWK.X)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(vm.PublicKeyJWK.Y)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	// ES256 signature is r||s, 32 bytes each.
	if len(sig) != 64 {
		return fmt.Errorf("%w: expected 64-byte signature", ErrDecode)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	signing := headerB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signing))
	if !ecdsa.Verify(&pub, digest[:], r, s) {
		return ErrVerifyFailed
	}
	return nil
}

func encodeSegment(b []byte) []byte {
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
	base64.RawURLEncoding.Encode(dst, b)
	return dst
}

// signES256 is used only in tests to build compact JWS with ES256.
func signES256(payload []byte, key *ecdsa.PrivateKey, kid string) (string, error) {
	header := jwsHeader{Alg: "ES256", Kid: kid}
	hb, _ := json.Marshal(header)
	encodedHeader := encodeSegment(hb)
	encodedPayload := encodeSegment(payload)
	signing := string(encodedHeader) + "." + string(encodedPayload)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	rb := r.FillBytes(make([]byte, 32))
	sb := s.FillBytes(make([]byte, 32))
	sig := make([]byte, 64)
	copy(sig[:32], rb)
	copy(sig[32:], sb)
	encodedSig := encodeSegment(sig)
	return signing + "." + string(encodedSig), nil
}
