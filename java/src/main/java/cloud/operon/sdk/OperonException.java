package cloud.operon.sdk;

/**
 * Base exception thrown by the Operon Java SDK.
 */
public class OperonException extends Exception {

    private static final long serialVersionUID = 1L;

    public OperonException(String message) {
        super(message);
    }

    public OperonException(String message, Throwable cause) {
        super(message, cause);
    }
}
