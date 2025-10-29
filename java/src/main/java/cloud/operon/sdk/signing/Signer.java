package cloud.operon.sdk.signing;

import cloud.operon.sdk.OperonException;

public interface Signer {

    SigningResult sign(String bearerToken, String payloadHash, String algorithm) throws OperonException;
}
