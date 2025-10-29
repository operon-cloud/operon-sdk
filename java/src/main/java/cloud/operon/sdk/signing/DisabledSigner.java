package cloud.operon.sdk.signing;

import cloud.operon.sdk.OperonException;

/**
 * Signer implementation used when automatic signing is disabled.
 */
public final class DisabledSigner implements Signer {

    public static final String ERROR_MESSAGE = "automatic signing disabled: provide signature manually or enable self signing";

    @Override
    public SigningResult sign(String bearerToken, String payloadHash, String algorithm) throws OperonException {
        throw new OperonException(ERROR_MESSAGE);
    }
}
