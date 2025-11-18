package cloud.operon.sdk.auth;

import cloud.operon.sdk.OperonException;

/**
 * Contract for obtaining access tokens.
 */
public interface TokenProvider {

    Token token() throws OperonException;

    default void invalidate() {
        // default no-op
    }

    default Token forceRefresh() throws OperonException {
        invalidate();
        return token();
    }
}
