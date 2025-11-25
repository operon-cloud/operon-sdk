package dids

// Document models a minimal DID Document needed for verification.
type Document struct {
	Context            []any  `json:"@context,omitempty"`
	ID                 string `json:"id,omitempty"`
	VerificationMethod []VM   `json:"verificationMethod,omitempty"`
	Authentication     []any  `json:"authentication,omitempty"`
	AssertionMethod    []any  `json:"assertionMethod,omitempty"`
	Service            []any  `json:"service,omitempty"`
}

// VM represents a verification method entry.
type VM struct {
	ID            string `json:"id,omitempty"`
	Type          string `json:"type,omitempty"`
	Controller    string `json:"controller,omitempty"`
	PublicKeyJWK  *JWK   `json:"publicKeyJwk,omitempty"`
	PublicKeyMult string `json:"publicKeyMultibase,omitempty"`
}

// JWK captures the subset of fields needed for signature verification.
type JWK struct {
	Kty string `json:"kty,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// ResolutionError categorises resolver failures.
type ResolutionError string

const (
	ErrInvalidDID     ResolutionError = "invalid_did"
	ErrUnsupported    ResolutionError = "unsupported_method"
	ErrNotFound       ResolutionError = "not_found"
	ErrUpstream       ResolutionError = "upstream_error"
	ErrDecode         ResolutionError = "decode_error"
	ErrUnsupportedAlg ResolutionError = "unsupported_alg"
	ErrKeyNotFound    ResolutionError = "key_not_found"
	ErrVerifyFailed   ResolutionError = "verify_failed"
)

func (e ResolutionError) Error() string { return string(e) }
