import { createHash } from 'node:crypto';

import { ClientCredentialsManager, type TokenManager } from './auth/token-manager.js';
import { Registry } from './catalog/registry.js';
import { createConfig, type OperonConfig, type OperonConfigInput } from './config.js';
import { decodeApiError, ValidationError } from './errors.js';
import { jsonRequest } from './http/json.js';
import { SelfSigner } from './signing/self-signer.js';
import { DisabledSigner, type Signer } from './signing/types.js';
import type {
  OperonHeaders,
  ChannelInteractionsResponse,
  ChannelParticipantsResponse,
  InteractionSummary,
  ParticipantSummary,
  Signature,
  SignatureValidationResult,
  Transaction,
  TransactionRequest,
  TransactionPayload
} from './types.js';

interface TransactionSubmission {
  correlationId: string;
  channelId: string;
  interactionId: string;
  timestamp: string;
  sourceDid: string;
  targetDid: string;
  signature: Signature;
  payloadHash: string;
  label?: string;
  tags?: string[];
}

interface TransactionResponse {
  id: string;
  correlationId: string;
  channelId: string;
  customerId?: string;
  workspaceId?: string;
  interactionId: string;
  timestamp: string;
  sourceDid: string;
  targetDid: string;
  signature: Signature;
  label?: string;
  tags?: string[];
  payloadHash: string;
  status: string;
  hcsTopicId?: string;
  hcsSequenceNumber?: number;
  hcsConsensusTimestamp?: string;
  hcsTransactionId?: string;
  hcsRunningHash?: string;
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
  updatedBy?: string;
  version?: number;
}

interface InteractionsResponse {
  data: Array<{
    id: string;
    channelId: string;
    sourceParticipantId: string;
    targetParticipantId: string;
  }>;
}

interface ParticipantsResponse {
  data: Array<{
    id: string;
    did: string;
  }>;
}

export interface SubmitTransactionOptions {
  signal?: AbortSignal;
}

/**
 * High-level Operon client handling authentication, signing, and reference data caching.
 */
export class OperonClient {
  private readonly config: OperonConfig;
  private readonly tokens: TokenManager;
  private readonly registry = new Registry();
  private readonly signer: Signer;
  private readonly selfSigning: boolean;

  private referenceLoaded = false;
  private referencePromise?: Promise<void>;

  private participantDid?: string;
  private channelId?: string;
  private heartbeatTimer?: ReturnType<typeof setInterval>;
  private heartbeatRunning = false;

  /**
   * Constructs a new client; accepts either raw input or a pre-normalised config.
   *
   * @param input Either raw {@link OperonConfigInput} or a pre-built {@link OperonConfig}.
   */
  constructor(input: OperonConfig | OperonConfigInput) {
    this.config = isOperonConfig(input) ? input : createConfig(input);
    this.tokens = new ClientCredentialsManager(this.config);
    if (this.config.disableSelfSign) {
      this.signer = new DisabledSigner();
      this.selfSigning = false;
    } else {
      this.signer = new SelfSigner(this.config);
      this.selfSigning = true;
    }
  }

  /**
   * Eagerly obtains an access token so subsequent requests can reuse it.
   *
   * @param signal Optional abort signal controlling the underlying token fetch.
   */
  async init(signal?: AbortSignal): Promise<void> {
    await this.tokenValue(signal);
    this.startHeartbeat();
  }

  /**
   * Clears cached credentials; currently a no-op beyond token eviction.
   */
  async close(): Promise<void> {
    this.stopHeartbeat();
    this.tokens.clear();
  }

  /**
   * Submits a transaction payload to Operon, applying signing and validation semantics.
   *
   * @param request Transaction details provided by the caller.
   * @param options Optional request controls (e.g., abort signal).
   */
  async submitTransaction(
    request: TransactionRequest,
    options: SubmitTransactionOptions = {}
  ): Promise<Transaction> {
    const token = await this.tokenValue(options.signal);
    const req = { ...request };

    await this.populateInteractionFields(req, options.signal);

    const { payloadHash } = await resolvePayload(req.payload, req.payloadHash);
    req.payloadHash = payloadHash;

    const signature = await this.resolveSignature(token.accessToken, req, options.signal);
    req.signature = signature;

    validateRequest(req);

    const timestamp = (req.timestamp ?? new Date()).toISOString();
    const sanitizedTags = (req.tags ?? []).map((tag) => tag.trim()).filter(Boolean);
    const payload: TransactionSubmission = {
      correlationId: req.correlationId.trim(),
      channelId: req.channelId!.trim(),
      interactionId: req.interactionId.trim(),
      timestamp,
      sourceDid: req.sourceDid!.trim(),
      targetDid: req.targetDid!.trim(),
      signature,
      payloadHash,
      label: req.label?.trim() || undefined,
      tags: sanitizedTags.length > 0 ? sanitizedTags : undefined
    };

    const response = await jsonRequest(this.config, {
      method: 'POST',
      path: '/v1/transactions',
      token: token.accessToken,
      body: payload,
      signal: options.signal
    });

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const body = (await response.json()) as TransactionResponse;
    return deserializeTransaction(body);
  }

  /**
   * Generates Operon signature headers for the provided payload using managed signing keys.
   *
   * @param payload Raw payload to sign (string, bytes, or JSON-serialisable object).
   * @param algorithm Optional signing algorithm override; defaults to the client configuration.
   * @param options Optional request controls (e.g., abort signal).
   */
  async generateSignatureHeaders(
    payload: TransactionPayload,
    algorithm?: string,
    options: { signal?: AbortSignal } = {}
  ): Promise<OperonHeaders> {
    if (!this.selfSigning) {
      throw new ValidationError('automatic signing disabled; enable self signing to generate headers');
    }

    const payloadInput = await resolvePayload(payload, undefined);
    if (!payloadInput.payloadBytes) {
      throw new ValidationError('payload bytes are required to generate Operon headers');
    }

    const token = await this.tokenValue(options.signal);
    const sourceDid = this.participantDid?.trim();
    if (!sourceDid) {
      throw new ValidationError('participant DID unavailable on access token');
    }

    const selectedAlgorithm = algorithm?.trim() || this.config.signingAlgorithm;
    const signingResult = await this.signer.sign(
      token.accessToken,
      payloadInput.payloadHash,
      selectedAlgorithm,
      options.signal
    );

    const signatureValue = signingResult.value?.trim();
    if (!signatureValue) {
      throw new ValidationError('signature response missing value');
    }

    const keyId = signingResult.keyId?.trim() || `${sourceDid}#keys-1`;
    const algorithmValue = signingResult.algorithm?.trim() || selectedAlgorithm;

    return {
      [HEADER_OPERON_DID]: sourceDid,
      [HEADER_OPERON_PAYLOAD_HASH]: payloadInput.payloadHash,
      [HEADER_OPERON_SIGNATURE]: signatureValue,
      [HEADER_OPERON_SIGNATURE_KEY]: keyId,
      [HEADER_OPERON_SIGNATURE_ALG]: algorithmValue
    };
  }

  /**
   * Returns cached interaction metadata, hydrating the cache on first use.
   *
   * @param options Optional request controls (e.g., abort signal).
   */
  async interactions(options: { signal?: AbortSignal } = {}): Promise<InteractionSummary[]> {
    await this.ensureReferenceData(options.signal);
    return this.registry.interactionsList();
  }

  /**
   * Returns cached participant metadata, hydrating the cache on first use.
   *
   * @param options Optional request controls (e.g., abort signal).
   */
  async participants(options: { signal?: AbortSignal } = {}): Promise<ParticipantSummary[]> {
    await this.ensureReferenceData(options.signal);
    return this.registry.participantsList();
  }

  private async tokenValue(signal?: AbortSignal) {
    const token = await this.tokens.token(signal);
    if (token.participantDid) {
      this.participantDid = token.participantDid;
    }
    if (token.channelId) {
      this.channelId = token.channelId;
    }
    return token;
  }

  private startHeartbeat(): void {
    if (
      this.config.sessionHeartbeatIntervalMs <= 0 ||
      !this.config.sessionHeartbeatUrl ||
      this.heartbeatTimer
    ) {
      return;
    }

    const run = () => {
      if (this.heartbeatRunning) {
        return;
      }
      this.heartbeatRunning = true;
      this.performHeartbeat()
        .catch((error) => {
          this.config.logger.warn?.('session heartbeat failed', { error });
        })
        .finally(() => {
          this.heartbeatRunning = false;
        });
    };

    run();
    this.heartbeatTimer = setInterval(run, this.config.sessionHeartbeatIntervalMs);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
    this.heartbeatRunning = false;
  }

  private async performHeartbeat(): Promise<void> {
    if (!this.config.sessionHeartbeatUrl) {
      return;
    }

    const token = await this.tokens.token();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.sessionHeartbeatTimeoutMs);

    try {
      const response = await this.config.fetchImpl(this.config.sessionHeartbeatUrl, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token.accessToken}`
        },
        signal: controller.signal
      });

      if (response.status === 401) {
        this.config.logger.warn?.('session heartbeat unauthorized; forcing token refresh');
        await this.tokens.forceRefresh();
        return;
      }

      if (response.status >= 400) {
        this.config.logger.warn?.('session heartbeat returned unexpected status', {
          status: response.status
        });
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        this.config.logger.warn?.('session heartbeat timed out');
      } else {
        this.config.logger.warn?.('session heartbeat error', { error });
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  private async populateInteractionFields(
    request: TransactionRequest,
    signal?: AbortSignal
  ): Promise<void> {
    const explicitChannel = request.channelId?.trim();
    if (explicitChannel) {
      this.channelId = explicitChannel;
    }

    if (!request.channelId?.trim() && this.channelId) {
      request.channelId = this.channelId;
    }

    if (!request.interactionId?.trim()) {
      if (!request.sourceDid?.trim() && this.participantDid) {
        request.sourceDid = this.participantDid;
      }
      if (!request.channelId?.trim() && this.channelId) {
        request.channelId = this.channelId;
      }
      return;
    }

    await this.ensureReferenceData(signal);
    const metadata = this.registry.interaction(request.interactionId.trim());
    if (!metadata) {
      throw new ValidationError(`interaction ${request.interactionId} not found`);
    }

    if (!request.channelId?.trim()) {
      request.channelId = metadata.channelId || this.channelId;
    }
    if (!request.sourceDid?.trim()) {
      if (!metadata.sourceDid) {
        throw new ValidationError(`interaction ${metadata.id} missing source DID`);
      }
      request.sourceDid = metadata.sourceDid;
    }
    if (!request.targetDid?.trim()) {
      if (!metadata.targetDid) {
        throw new ValidationError(`interaction ${metadata.id} missing target DID`);
      }
      request.targetDid = metadata.targetDid;
    }
  }

  private async resolveSignature(
    token: string,
    request: TransactionRequest,
    signal?: AbortSignal
  ): Promise<Signature> {
    if (request.signature?.value?.trim()) {
      return {
        algorithm: request.signature.algorithm?.trim() || 'EdDSA',
        value: request.signature.value.trim(),
        keyId: request.signature.keyId?.trim() || this.deriveKeyId(request)
      };
    }

    if (!this.selfSigning) {
      throw new ValidationError('signature value is required when self signing disabled');
    }

    const signingResult = await this.signer.sign(
      token,
      request.payloadHash!,
      request.signature?.algorithm?.trim() || 'EdDSA',
      signal
    );

    return {
      algorithm: signingResult.algorithm,
      value: signingResult.value,
      keyId: signingResult.keyId ?? this.deriveKeyId(request)
    };
  }

  private deriveKeyId(request: TransactionRequest): string | undefined {
    const source = request.sourceDid?.trim() || this.participantDid;
    if (!source) {
      return undefined;
    }
    return `${source}#keys-1`;
  }

  private async ensureReferenceData(signal?: AbortSignal): Promise<void> {
    if (this.referenceLoaded) {
      return;
    }
    if (!this.referencePromise) {
      this.referencePromise = this.reloadReferenceData(signal).finally(() => {
        this.referencePromise = undefined;
      });
    }
    await this.referencePromise;
  }

  private async reloadReferenceData(signal?: AbortSignal): Promise<void> {
    const token = await this.tokenValue(signal);
    const channel = this.channelId?.trim();
    if (!channel) {
      throw new ValidationError('channelId unavailable on access token; provide channelId explicitly');
    }

    const [interactionsResp, participantsResp] = await Promise.all([
      this.fetchInteractions(token.accessToken, channel, signal),
      this.fetchParticipants(token.accessToken, channel, signal)
    ]);

    const participantsMap = new Map<string, string>();
    for (const participant of participantsResp.participants) {
      if (participant.id && participant.did) {
        participantsMap.set(participant.id, participant.did);
      }
    }

    const interactions = interactionsResp.interactions.map((item) => ({
      id: item.id,
      channelId: item.channelId ?? channel,
      sourceParticipantId: item.sourceParticipantId,
      targetParticipantId: item.targetParticipantId,
      sourceDid: participantsMap.get(item.sourceParticipantId),
      targetDid: participantsMap.get(item.targetParticipantId)
    }));

    const participantMetadata = participantsResp.participants.map((participant) => ({
      id: participant.id,
      did: participant.did
    }));

    this.registry.replaceParticipants(participantMetadata);
    this.registry.replaceInteractions(interactions);
    this.referenceLoaded = true;
  }

  private async fetchInteractions(
    token: string,
    channelId: string,
    signal?: AbortSignal
  ): Promise<ChannelInteractionsResponse> {
    const response = await jsonRequest(this.config, {
      method: 'GET',
      path: `/v1/channels/${encodeURIComponent(channelId)}/interactions`,
      token,
      signal
    });
    if (response.status >= 400) {
      throw await decodeApiError(response);
    }
    const payload = (await response.json()) as ChannelInteractionsResponse;
    return {
      interactions: payload.interactions ?? [],
      totalCount: payload.totalCount ?? 0,
      page: payload.page ?? 0,
      pageSize: payload.pageSize ?? 0,
      hasMore: payload.hasMore ?? false
    };
  }

  private async fetchParticipants(
    token: string,
    channelId: string,
    signal?: AbortSignal
  ): Promise<ChannelParticipantsResponse> {
    const response = await jsonRequest(this.config, {
      method: 'GET',
      path: `/v1/channels/${encodeURIComponent(channelId)}/participants`,
      token,
      signal
    });
    if (response.status >= 400) {
      throw await decodeApiError(response);
    }
    const payload = (await response.json()) as ChannelParticipantsResponse;
    return {
      participants: payload.participants ?? [],
      totalCount: payload.totalCount ?? 0,
      page: payload.page ?? 0,
      pageSize: payload.pageSize ?? 0,
      hasMore: payload.hasMore ?? false
    };
  }
}

function isOperonConfig(value: OperonConfig | OperonConfigInput): value is OperonConfig {
  return (value as OperonConfig).fetchImpl !== undefined;
}

async function resolvePayload(
  payload: TransactionPayload | undefined,
  hash?: string
): Promise<{ payloadHash: string; payloadBytes?: Buffer }> {
  if (payload === undefined || payload === null) {
    if (!hash?.trim()) {
      throw new ValidationError('payload or payloadHash is required');
    }
    return { payloadHash: hash.trim(), payloadBytes: undefined };
  }

  let bytes: Uint8Array;
  if (typeof payload === 'string') {
    bytes = Buffer.from(payload, 'utf-8');
  } else if (payload instanceof Buffer || payload instanceof Uint8Array) {
    bytes = payload;
  } else {
    bytes = Buffer.from(JSON.stringify(payload));
  }

  const digest = createHash('sha256').update(bytes).digest();
  const payloadHash = base64UrlEncode(digest);

  if (hash?.trim() && hash.trim() !== payloadHash) {
    throw new ValidationError('provided payloadHash does not match payload content');
  }

  return { payloadHash, payloadBytes: Buffer.from(bytes) };
}

function validateRequest(request: TransactionRequest): void {
  if (!request.correlationId?.trim()) {
    throw new ValidationError('correlationId is required');
  }
  if (!request.channelId?.trim()) {
    throw new ValidationError('channelId is required');
  }
  if (!request.interactionId?.trim()) {
    throw new ValidationError('interactionId is required');
  }
  if (!request.sourceDid?.trim()) {
    throw new ValidationError('sourceDid is required');
  }
  if (!request.targetDid?.trim()) {
    throw new ValidationError('targetDid is required');
  }
  if (!request.payloadHash?.trim()) {
    throw new ValidationError('payloadHash is required');
  }
  if (!request.signature?.algorithm?.trim()) {
    throw new ValidationError('signature.algorithm is required');
  }
  if (!request.signature.value?.trim()) {
    throw new ValidationError('signature.value is required');
  }
}

function deserializeTransaction(response: TransactionResponse): Transaction {
  return {
    ...response,
    timestamp: new Date(response.timestamp),
    createdAt: new Date(response.createdAt),
    updatedAt: new Date(response.updatedAt)
  };
}

function base64UrlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
const HEADER_OPERON_DID = 'X-Operon-DID';
const HEADER_OPERON_PAYLOAD_HASH = 'X-Operon-Payload-Hash';
const HEADER_OPERON_SIGNATURE = 'X-Operon-Signature';
const HEADER_OPERON_SIGNATURE_KEY = 'X-Operon-Signature-KeyId';
const HEADER_OPERON_SIGNATURE_ALG = 'X-Operon-Signature-Alg';
