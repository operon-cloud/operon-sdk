package com.operoncloud.sdk.signing;

import com.operoncloud.sdk.OperonException;

public interface Signer {

    SigningResult sign(String bearerToken, String payloadHash, String algorithm) throws OperonException;
}
