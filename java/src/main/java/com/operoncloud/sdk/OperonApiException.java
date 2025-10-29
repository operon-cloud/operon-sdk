package com.operoncloud.sdk;

/**
 * Exception representing an error returned by Operon services.
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

    public int getStatusCode() {
        return statusCode;
    }

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
