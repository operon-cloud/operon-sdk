import { ClientCredentialsManager, type TokenManager } from './auth/token-manager.js';
import { Registry } from './catalog/registry.js';
import { createConfig, type OperonConfig, type OperonConfigInput } from './config.js';
import { decodeApiError, TransportError, ValidationError } from './errors.js';
import { jsonRequest } from './http/json.js';
import { SelfSigner } from './signing/self-signer.js';
import { DisabledSigner, type Signer } from './signing/types.js';
import {
  HEADER_OPERON_DID,
  HEADER_OPERON_PAYLOAD_HASH,
  buildTransactionSubmission,
  normalizeTransactionRequestAliases,
  resolvePayload,
  sanitizeOperonHeaders,
  validateTransactionRequestForSubmit
} from './transactions.js';
import {
  buildKeyId,
  canonicalSigningAlgorithm,
  type InteractionSummary,
  type OperonHeaders,
  type ParticipantSummary,
  type Signature,
  type SignatureValidationResult,
  type Transaction,
  type TransactionPayload,
  type TransactionRequest,
  type Workstream,
  type WorkstreamInteraction,
  type WorkstreamInteractionsResponse,
  type WorkstreamParticipant,
  type WorkstreamParticipantsResponse
} from './types.js';

interface TransactionResponse {
  id: string;
  correlationId: string;
  workstreamId?: string;
  channelId?: string;
  workstreamName?: string;
  customerId?: string;
  workspaceId?: string;
  interactionId: string;
  timestamp: string;
  sourceDid: string;
  targetDid: string;
  state?: string;
  stateId?: string;
  stateLabel?: string;
  roiClassification?: string;
  roiCostIncrement?: number;
  roiTimeIncrement?: number;
  roiCostSavings?: number;
  roiTimeSavings?: number;
  roiBaseCost?: number;
  roiBaseTime?: number;
  roiCostSaving?: number;
  roiTimeSaving?: number;
  signature: Signature;
  label?: string;
  tags?: string[];
  payloadHash: string;
  actorExternalId?: string;
  actorExternalDisplayName?: string;
  actorExternalSource?: string;
  assigneeExternalId?: string;
  assigneeExternalDisplayName?: string;
  assigneeExternalSource?: string;
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
  data?: Array<{
    id: string;
    workstreamId?: string;
    channelId?: string;
    workstreamName?: string;
    name?: string;
    description?: string;
    status?: string;
    sourceParticipantId: string;
    targetParticipantId: string;
    type?: string;
    actor?: string;
    states?: string[];
    roiClassification?: string;
    roiCost?: number;
    roiTime?: number;
  }>;
}

interface ParticipantsResponse {
  data?: Array<{
    id: string;
    did: string;
    name?: string;
    status?: string;
    customerId?: string;
    workstreamId?: string;
    channelId?: string;
    workstreamName?: string;
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

  private initPromise?: Promise<void>;
  private referenceLoaded = false;
  private referencePromise?: Promise<void>;

  private participantDid?: string;
  private workstreamId?: string;

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
    if (!this.initPromise) {
      this.initPromise = this.initialize(signal).catch((error) => {
        this.initPromise = undefined;
        throw error;
      });
    }
    await this.initPromise;
  }

  /**
   * Clears cached credentials; currently a no-op beyond token eviction.
   */
  async close(): Promise<void> {
    this.stopHeartbeat();
    this.tokens.clear();
    this.initPromise = undefined;
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
    await this.init(options.signal);

    const req: TransactionRequest = {
      ...request,
      tags: request.tags ? [...request.tags] : undefined,
      signature: request.signature ? { ...request.signature } : undefined
    };

    normalizeTransactionRequestAliases(req);
    await this.populateInteractionFields(req, options.signal);

    const { payloadHash } = resolvePayload(req.payload, req.payloadHash);
    req.payloadHash = payloadHash;

    const token = await this.tokenValue(options.signal);
    const signature = await this.resolveSignature(token.accessToken, req, options.signal);
    req.signature = signature;

    validateTransactionRequestForSubmit(req);

    const submission = buildTransactionSubmission(req, signature, payloadHash, req.timestamp ?? new Date());

    const response = await jsonRequest(this.config, {
      method: 'POST',
      path: '/v1/transactions',
      token: token.accessToken,
      body: submission,
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
   */
  async generateSignatureHeaders(
    payload: TransactionPayload,
    algorithm?: string,
    options: { signal?: AbortSignal } = {}
  ): Promise<OperonHeaders> {
    await this.init(options.signal);

    const selectedAlgorithm =
      algorithm?.trim().length
        ? canonicalSigningAlgorithm(algorithm)
        : canonicalSigningAlgorithm(this.config.signingAlgorithm);
    if (!selectedAlgorithm) {
      throw new ValidationError(`unsupported signing algorithm ${algorithm ?? this.config.signingAlgorithm}`);
    }

    const payloadInput = resolvePayload(payload, undefined);
    if (!payloadInput.payloadBytes) {
      throw new ValidationError('payload bytes are required to generate Operon headers');
    }

    const token = await this.tokenValue(options.signal);
    if (!this.selfSigning) {
      throw new ValidationError('automatic signing disabled: enable self signing to generate headers');
    }

    const did = this.participantDid?.trim();
    if (!did) {
      throw new ValidationError('participant DID unavailable on access token');
    }

    const signingResult = await this.signer.sign(
      token.accessToken,
      payloadInput.payloadHash,
      selectedAlgorithm,
      options.signal
    );

    const signatureValue = signingResult.value?.trim();
    if (!signatureValue) {
      throw new ValidationError('signature value missing from signing response');
    }

    const keyId = signingResult.keyId?.trim() || buildKeyId(did);
    const algorithmValue = signingResult.algorithm?.trim() || selectedAlgorithm;

    return {
      'X-Operon-DID': did,
      'X-Operon-Payload-Hash': payloadInput.payloadHash,
      'X-Operon-Signature': signatureValue,
      'X-Operon-Signature-KeyId': keyId,
      'X-Operon-Signature-Alg': algorithmValue
    };
  }

  /**
   * Convenience wrapper around generateSignatureHeaders for string payloads.
   */
  async generateSignatureHeadersFromString(
    payload: string,
    algorithm?: string,
    options: { signal?: AbortSignal } = {}
  ): Promise<OperonHeaders> {
    return this.generateSignatureHeaders(payload, algorithm, options);
  }

  /**
   * Validates Operon signature headers against the supplied payload.
   */
  async validateSignatureHeaders(
    payload: TransactionPayload,
    headers: OperonHeaders,
    options: { signal?: AbortSignal } = {}
  ): Promise<SignatureValidationResult> {
    await this.init(options.signal);

    const payloadInput = resolvePayload(payload, undefined);
    if (!payloadInput.payloadBytes) {
      throw new ValidationError('payload bytes are required to validate Operon headers');
    }

    const sanitized = sanitizeOperonHeaders(headers);
    const computedHash = payloadInput.payloadHash;
    const expectedHash = sanitized[HEADER_OPERON_PAYLOAD_HASH];
    if (computedHash.toLowerCase() !== expectedHash.toLowerCase()) {
      throw new ValidationError(`payload hash mismatch: expected ${computedHash}, got ${expectedHash}`);
    }

    const token = await this.tokenValue(options.signal);
    const did = sanitized[HEADER_OPERON_DID];
    const response = await this.rawRequest(
      `/v1/dids/${encodeURIComponent(did)}/signature/verify`,
      token.accessToken,
      payloadInput.payloadBytes,
      sanitized,
      options.signal
    );

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const body = (await response.json()) as SignatureValidationResult;
    return {
      status: body.status,
      message: body.message,
      did: body.did,
      payloadHash: body.payloadHash,
      algorithm: body.algorithm,
      keyId: body.keyId
    };
  }

  /**
   * Convenience wrapper around validateSignatureHeaders for string payloads.
   */
  async validateSignatureHeadersFromString(
    payload: string,
    headers: OperonHeaders,
    options: { signal?: AbortSignal } = {}
  ): Promise<SignatureValidationResult> {
    return this.validateSignatureHeaders(payload, headers, options);
  }

  /**
   * Returns cached interaction metadata, hydrating the cache on first use.
   */
  async interactions(options: { signal?: AbortSignal } = {}): Promise<InteractionSummary[]> {
    await this.init(options.signal);
    await this.ensureReferenceData(options.signal);
    return this.registry.interactionsList();
  }

  /**
   * Returns cached participant metadata, hydrating the cache on first use.
   */
  async participants(options: { signal?: AbortSignal } = {}): Promise<ParticipantSummary[]> {
    await this.init(options.signal);
    await this.ensureReferenceData(options.signal);
    return this.registry.participantsList();
  }

  /**
   * Fetches workstream details from the client API.
   */
  async getWorkstream(
    workstreamId?: string,
    options: { signal?: AbortSignal } = {}
  ): Promise<Workstream> {
    await this.init(options.signal);
    const token = await this.tokenValue(options.signal);
    const targetWorkstream = this.resolveWorkstreamId(workstreamId);

    const response = await jsonRequest(this.config, {
      method: 'GET',
      path: `/v1/workstreams/${encodeURIComponent(targetWorkstream)}`,
      token: token.accessToken,
      signal: options.signal
    });

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const body = (await response.json()) as Record<string, unknown>;
    return deserializeWorkstream(body);
  }

  /**
   * Fetches workstream interactions from the client API.
   */
  async getWorkstreamInteractions(
    workstreamId?: string,
    options: { signal?: AbortSignal } = {}
  ): Promise<WorkstreamInteractionsResponse> {
    await this.init(options.signal);
    const token = await this.tokenValue(options.signal);
    const targetWorkstream = this.resolveWorkstreamId(workstreamId);

    const response = await jsonRequest(this.config, {
      method: 'GET',
      path: `/v1/workstreams/${encodeURIComponent(targetWorkstream)}/interactions`,
      token: token.accessToken,
      signal: options.signal
    });

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const body = (await response.json()) as {
      interactions?: Array<Record<string, unknown>>;
      totalCount?: number;
      page?: number;
      pageSize?: number;
      hasMore?: boolean;
    };

    return {
      interactions: (body.interactions ?? []).map(deserializeWorkstreamInteraction),
      totalCount: body.totalCount ?? 0,
      page: body.page ?? 0,
      pageSize: body.pageSize ?? 0,
      hasMore: body.hasMore ?? false
    };
  }

  /**
   * Fetches workstream participants from the client API.
   */
  async getWorkstreamParticipants(
    workstreamId?: string,
    options: { signal?: AbortSignal } = {}
  ): Promise<WorkstreamParticipantsResponse> {
    await this.init(options.signal);
    const token = await this.tokenValue(options.signal);
    const targetWorkstream = this.resolveWorkstreamId(workstreamId);

    const response = await jsonRequest(this.config, {
      method: 'GET',
      path: `/v1/workstreams/${encodeURIComponent(targetWorkstream)}/participants`,
      token: token.accessToken,
      signal: options.signal
    });

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const body = (await response.json()) as {
      participants?: Array<Record<string, unknown>>;
      totalCount?: number;
      page?: number;
      pageSize?: number;
      hasMore?: boolean;
    };

    return {
      participants: (body.participants ?? []).map(deserializeWorkstreamParticipant),
      totalCount: body.totalCount ?? 0,
      page: body.page ?? 0,
      pageSize: body.pageSize ?? 0,
      hasMore: body.hasMore ?? false
    };
  }

  private async initialize(signal?: AbortSignal): Promise<void> {
    await this.tokenValue(signal);
    this.startHeartbeat();
  }

  private async tokenValue(signal?: AbortSignal) {
    const token = await this.tokens.token(signal);
    if (token.participantDid?.trim()) {
      this.participantDid = token.participantDid.trim();
    }
    if (token.workstreamId?.trim()) {
      this.workstreamId = token.workstreamId.trim();
    }
    return token;
  }

  private resolveWorkstreamId(override?: string): string {
    if (override?.trim()) {
      return override.trim();
    }
    if (this.workstreamId?.trim()) {
      return this.workstreamId.trim();
    }
    throw new ValidationError(
      'workstream ID is required: token not scoped to a workstream and no override provided'
    );
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
      void this.performHeartbeat()
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
    normalizeTransactionRequestAliases(request);

    if (request.workstreamId?.trim()) {
      this.workstreamId = request.workstreamId.trim();
    } else if (this.workstreamId?.trim()) {
      request.workstreamId = this.workstreamId;
    }

    if (!request.interactionId?.trim()) {
      if (!request.sourceDid?.trim() && this.participantDid?.trim()) {
        request.sourceDid = this.participantDid;
      }
      if (!request.workstreamId?.trim() && this.workstreamId?.trim()) {
        request.workstreamId = this.workstreamId;
      }
      normalizeTransactionRequestAliases(request);
      return;
    }

    await this.ensureReferenceData(signal);

    let metadata = this.registry.interaction(request.interactionId.trim());
    if (!metadata) {
      await this.reloadReferenceData(signal);
      metadata = this.registry.interaction(request.interactionId.trim());
    }
    if (!metadata) {
      throw new ValidationError(`interaction ${request.interactionId} not found`);
    }

    if (!request.workstreamId?.trim()) {
      request.workstreamId = metadata.workstreamId || this.workstreamId;
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

    if (!request.sourceDid?.trim() && this.participantDid?.trim()) {
      request.sourceDid = this.participantDid;
    }

    normalizeTransactionRequestAliases(request);
  }

  private async resolveSignature(
    token: string,
    request: TransactionRequest,
    signal?: AbortSignal
  ): Promise<Signature> {
    if (request.signature?.value?.trim()) {
      return {
        algorithm: request.signature.algorithm?.trim() || this.config.signingAlgorithm,
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
      request.signature?.algorithm?.trim() || this.config.signingAlgorithm,
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
    return buildKeyId(source);
  }

  private async ensureReferenceData(signal?: AbortSignal): Promise<void> {
    if (this.referenceLoaded) {
      return;
    }
    await this.reloadReferenceData(signal);
  }

  private async reloadReferenceData(signal?: AbortSignal): Promise<void> {
    if (!this.referencePromise) {
      this.referencePromise = this.loadReferenceData(signal).finally(() => {
        this.referencePromise = undefined;
      });
    }
    await this.referencePromise;
  }

  private async loadReferenceData(signal?: AbortSignal): Promise<void> {
    const token = await this.tokenValue(signal);

    const [interactions, participants] = await Promise.all([
      this.fetchInteractions(token.accessToken, signal),
      this.fetchParticipants(token.accessToken, signal)
    ]);

    const participantsMap = new Map<string, string>();
    for (const participant of participants) {
      if (participant.id && participant.did) {
        participantsMap.set(participant.id, participant.did);
      }
    }

    const hydratedInteractions = interactions.map((item) => ({
      ...item,
      sourceDid: item.sourceDid ?? participantsMap.get(item.sourceParticipantId),
      targetDid: item.targetDid ?? participantsMap.get(item.targetParticipantId)
    }));

    this.registry.replaceInteractions(hydratedInteractions);
    this.registry.replaceParticipants(participants);
    this.referenceLoaded = true;
  }

  private async fetchInteractions(token: string, signal?: AbortSignal) {
    const response = await jsonRequest(this.config, {
      method: 'GET',
      path: '/v1/interactions',
      token,
      signal
    });

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const payload = (await response.json()) as InteractionsResponse;
    const data = Array.isArray(payload.data) ? payload.data : [];

    return data.map((item) => {
      const workstreamId = firstNonEmpty(item.workstreamId, item.channelId, '');
      return {
        id: item.id,
        workstreamId,
        workstreamName: item.workstreamName,
        name: item.name,
        description: item.description,
        status: item.status,
        sourceParticipantId: item.sourceParticipantId,
        targetParticipantId: item.targetParticipantId,
        sourceDid: undefined,
        targetDid: undefined,
        type: item.type,
        actor: item.actor,
        states: Array.isArray(item.states) ? item.states.filter((entry) => !!entry) : undefined,
        roiClassification: item.roiClassification,
        roiCost: item.roiCost,
        roiTime: item.roiTime
      };
    });
  }

  private async fetchParticipants(token: string, signal?: AbortSignal) {
    const response = await jsonRequest(this.config, {
      method: 'GET',
      path: '/v1/participants',
      token,
      signal
    });

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const payload = (await response.json()) as ParticipantsResponse;
    const data = Array.isArray(payload.data) ? payload.data : [];

    return data
      .filter((item) => item.id && item.did)
      .map((item) => ({
        id: item.id,
        did: item.did,
        name: item.name,
        status: item.status,
        customerId: item.customerId,
        workstreamId: firstNonEmpty(item.workstreamId, item.channelId),
        workstreamName: item.workstreamName
      }));
  }

  private async rawRequest(
    path: string,
    token: string,
    body: Buffer,
    headers: Record<string, string>,
    signal?: AbortSignal
  ): Promise<Response> {
    const url = `${this.config.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.httpTimeoutMs);

    try {
      return await this.config.fetchImpl(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          ...headers
        },
        body: Uint8Array.from(body),
        signal: mergeSignals(controller.signal, signal)
      });
    } catch (error) {
      throw new TransportError(`request POST ${url} failed`, error);
    } finally {
      clearTimeout(timeout);
    }
  }
}

function isOperonConfig(value: OperonConfig | OperonConfigInput): value is OperonConfig {
  return (value as OperonConfig).fetchImpl !== undefined;
}

function deserializeTransaction(response: TransactionResponse): Transaction {
  const workstreamId = firstNonEmpty(response.workstreamId, response.channelId, '');
  return {
    ...response,
    workstreamId,
    channelId: workstreamId,
    timestamp: toDate(response.timestamp),
    createdAt: toDate(response.createdAt),
    updatedAt: toDate(response.updatedAt)
  };
}

function deserializeWorkstream(payload: Record<string, unknown>): Workstream {
  const createdAt = toDateOrUndefined(payload.createdAt);
  const updatedAt = toDateOrUndefined(payload.updatedAt);

  const states = Array.isArray(payload.states)
    ? payload.states
        .map((state) => {
          if (!state || typeof state !== 'object') {
            return undefined;
          }
          const value = state as Record<string, unknown>;
          if (!value.id || !value.name) {
            return undefined;
          }
          return {
            id: String(value.id),
            name: String(value.name),
            status: asString(value.status)
          };
        })
        .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry))
    : undefined;

  return {
    id: String(payload.id ?? ''),
    createdAt,
    updatedAt,
    createdBy: asString(payload.createdBy),
    updatedBy: asString(payload.updatedBy),
    version: asNumber(payload.version),
    customerId: asString(payload.customerId),
    workspaceId: asString(payload.workspaceId),
    name: asString(payload.name),
    description: asString(payload.description),
    mode: asString(payload.mode),
    type: asString(payload.type),
    status: asString(payload.status),
    states,
    defaultStateId: asString(payload.defaultStateId),
    interactionIds: asStringArray(payload.interactionIds),
    hcsTestTopicId: asString(payload.hcsTestTopicId),
    hcsLiveTopicId: asString(payload.hcsLiveTopicId)
  };
}

function deserializeWorkstreamInteraction(payload: Record<string, unknown>): WorkstreamInteraction {
  const workstreamId = firstNonEmpty(asString(payload.workstreamId), asString(payload.channelId), '');
  return {
    id: String(payload.id ?? ''),
    workstreamId,
    workstreamName: asString(payload.workstreamName),
    name: asString(payload.name),
    description: asString(payload.description),
    status: asString(payload.status),
    sourceParticipantId: asString(payload.sourceParticipantId),
    targetParticipantId: asString(payload.targetParticipantId),
    workstreams: asStringArray(payload.workstreams),
    type: asString(payload.type),
    actor: asString(payload.actor),
    states: asStringArray(payload.states),
    roiClassification: asString(payload.roiClassification),
    roiCost: asNumber(payload.roiCost),
    roiTime: asNumber(payload.roiTime),
    tags: asStringArray(payload.tags),
    createdAt: toDateOrUndefined(payload.createdAt),
    updatedAt: toDateOrUndefined(payload.updatedAt),
    version: asNumber(payload.version)
  };
}

function deserializeWorkstreamParticipant(payload: Record<string, unknown>): WorkstreamParticipant {
  return {
    id: String(payload.id ?? ''),
    did: String(payload.did ?? ''),
    name: asString(payload.name),
    description: asString(payload.description),
    url: asString(payload.url),
    status: asString(payload.status),
    type: asString(payload.type),
    customerId: asString(payload.customerId),
    workstreamId: firstNonEmpty(asString(payload.workstreamId), asString(payload.channelId)),
    workstreamName: asString(payload.workstreamName),
    tags: asStringArray(payload.tags),
    createdAt: toDateOrUndefined(payload.createdAt),
    updatedAt: toDateOrUndefined(payload.updatedAt),
    version: asNumber(payload.version)
  };
}

function toDate(value: string): Date {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new ValidationError(`invalid timestamp ${value}`);
  }
  return date;
}

function toDateOrUndefined(value: unknown): Date | undefined {
  if (typeof value !== 'string' || !value.trim()) {
    return undefined;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function asString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const items = value
    .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
    .filter((entry) => entry.length > 0);
  return items.length > 0 ? items : undefined;
}

function firstNonEmpty(...values: Array<string | undefined>): string {
  for (const value of values) {
    if (value && value.trim()) {
      return value.trim();
    }
  }
  return '';
}

function mergeSignals(primary: AbortSignal, secondary?: AbortSignal): AbortSignal {
  if (!secondary) {
    return primary;
  }
  if (secondary.aborted) {
    return secondary;
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  primary.addEventListener('abort', abort, { once: true });
  secondary.addEventListener('abort', abort, { once: true });
  return controller.signal;
}
