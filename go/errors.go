package operon

import (
	"net/http"

	"github.com/operonmaster/operon-sdk/go/internal/apierrors"
)

// APIError represents a structured error returned by the Operon platform.
type APIError = apierrors.APIError

// decodeAPIError reads an HTTP error response and converts it into an APIError.
func decodeAPIError(resp *http.Response) (*APIError, error) {
	return apierrors.Decode(resp)
}
