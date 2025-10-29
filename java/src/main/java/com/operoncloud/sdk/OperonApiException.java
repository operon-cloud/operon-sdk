package com.operoncloud.sdk;

/**
 * Exception representing an error returned by Operon services. When the backend responds with a non-2xx status
 * the SDK hydrates this type so callers can inspect both the HTTP status and the structured Operon error code.
 */
public final class OperonApiException extends OperonException {

    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final String code;

    public OperonApiException(int statusCode, String code, String message) {
        super(message == null || message.isBlank() ? defaultMessage(statusCode, code) : message);
        this.statusCode = statusCode;
        this.code = code;
    }

    /**
     * @return HTTP status code returned by the Operon API.
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * @return Operon-specific error code (nullable when the response body did not include one).
     */
    public String getCode() {
        return code;
    }

    private static String defaultMessage(int status, String code) {
        if (code == null || code.isBlank()) {
            return "Operon request failed with status " + status;
        }
        return "Operon request failed with status " + status + " (" + code + ")";
    }
}
