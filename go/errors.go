package operon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// APIError represents a structured error returned by the Operon platform.
type APIError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Code != "" {
		return fmt.Sprintf("operon: %s (%s)", e.Message, e.Code)
	}
	return fmt.Sprintf("operon: %s", e.Message)
}

// decodeAPIError reads an HTTP error response and converts it into an APIError.
func decodeAPIError(resp *http.Response) (*APIError, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read error response: %w", err)
	}

	apiErr := &APIError{StatusCode: resp.StatusCode}
	if len(body) == 0 {
		apiErr.Message = resp.Status
		return apiErr, nil
	}

	if err := json.Unmarshal(body, apiErr); err != nil {
		apiErr.Message = string(body)
		return apiErr, nil
	}

	if apiErr.Message == "" {
		apiErr.Message = resp.Status
	}
	return apiErr, nil
}
