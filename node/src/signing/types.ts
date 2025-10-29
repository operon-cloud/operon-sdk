export interface SigningResult {
  algorithm: string;
  value: string;
  keyId?: string;
}

export interface Signer {
  sign(
    token: string,
    payloadHash: string,
    algorithm: string,
    signal?: AbortSignal
  ): Promise<SigningResult>;
}

export class DisabledSigner implements Signer {
  async sign(): Promise<SigningResult> {
    throw new Error('automatic signing disabled');
  }
}
