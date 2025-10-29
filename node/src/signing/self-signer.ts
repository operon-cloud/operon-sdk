import type { OperonConfig } from '../config.js';

import { decodeApiError } from '../errors.js';
import { jsonRequest } from '../http/json.js';

import type { Signer, SigningResult } from './types.js';

interface SignResponse {
  signature: {
    algorithm: string;
    value: string;
    keyId?: string;
  };
}

/**
 * Uses the Operon self-sign endpoint to produce digital signatures.
 */
export class SelfSigner implements Signer {
  /**
   * @param config Resolved configuration used to call the signing endpoint.
   */
  constructor(private readonly config: OperonConfig) {}

  async sign(
    token: string,
    payloadHash: string,
    algorithm: string,
    signal?: AbortSignal
  ): Promise<SigningResult> {
    const response = await jsonRequest(this.config, {
      method: 'POST',
      path: '/v1/dids/self/sign',
      token,
      body: {
        payloadHash,
        hashAlgorithm: 'SHA-256',
        algorithm
      },
      signal
    });

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const payload = (await response.json()) as SignResponse;
    const signature = payload.signature ?? {};
    if (!signature.algorithm || !signature.value) {
      throw new Error('sign response missing signature');
    }

    return {
      algorithm: signature.algorithm,
      value: signature.value,
      keyId: signature.keyId?.trim() || undefined
    };
  }
}
