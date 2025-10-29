package com.operoncloud.sdk.auth;

import com.operoncloud.sdk.OperonException;

/**
 * Contract for obtaining access tokens.
 */
public interface TokenProvider {

    Token token() throws OperonException;

    default void invalidate() {
        // default no-op
    }
}
