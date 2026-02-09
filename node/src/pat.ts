import {
  DEFAULT_BASE_URL,
  DEFAULT_HTTP_TIMEOUT_MS
} from './config.js';
import { decodeTokenClaims } from './auth/claims.js';
import { decodeApiError, TransportError, ValidationError } from './errors.js';
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
  type FetchFunction,
  type OperonHeaders,
  type Signature,
  type SignatureValidationResult,
  type Transaction,
  type TransactionPayload,
  type TransactionRequest,
  type Workstream,
  type WorkstreamInteractionsResponse,
  type WorkstreamParticipantsResponse
} from './types.js';

export interface ClientAPIConfig {
  baseUrl?: string;
  httpTimeoutMs?: number;
  fetchImpl?: FetchFunction;
}

export interface WorkstreamDataConfig {
  baseUrl?: string;
  httpTimeoutMs?: number;
  fetchImpl?: FetchFunction;
}

interface NormalizedConfig {
  baseUrl: string;
  httpTimeoutMs: number;
  fetchImpl: FetchFunction;
}

/**
 * Signs a payload hash using managed Operon keys with PAT authentication.
 */
export async function signHashWithPAT(
  cfg: ClientAPIConfig,
  pat: string,
  payloadHash: string,
  algorithm: string,
  options: { signal?: AbortSignal } = {}
): Promise<Signature> {
  const token = pat.trim();
  if (!token) {
    throw new ValidationError('pat is required');
  }

  const hash = payloadHash.trim();
  if (!hash) {
    throw new ValidationError('payload hash is required');
  }

  const selectedAlgorithm = canonicalSigningAlgorithm(algorithm);
  if (!selectedAlgorithm) {
    throw new ValidationError(`unsupported signing algorithm ${algorithm}`);
  }

  const normalized = normalizeConfig(cfg);
  const response = await requestJSON(normalized, {
    method: 'POST',
    path: '/v1/dids/self/sign',
    token,
    body: {
      payloadHash: hash,
      hashAlgorithm: 'SHA-256',
      algorithm: selectedAlgorithm
    },
    signal: options.signal
  });

  if (response.status >= 400) {
    throw await decodeApiError(response);
  }

  const body = (await response.json()) as { signature?: Signature };
  if (!body.signature) {
    throw new ValidationError('self sign response missing signature');
  }

  const signature: Signature = {
    algorithm: body.signature.algorithm,
    value: body.signature.value,
    keyId: body.signature.keyId
  };

  if (!signature.keyId?.trim()) {
    const claims = decodeTokenClaims(token);
    if (claims.participantDid?.trim()) {
      signature.keyId = buildKeyId(claims.participantDid);
    }
  }

  return signature;
}

/**
 * Submits a signed transaction with PAT authentication.
 */
export async function submitTransactionWithPAT(
  cfg: ClientAPIConfig,
  pat: string,
  request: TransactionRequest,
  options: { signal?: AbortSignal } = {}
): Promise<Transaction> {
  const token = pat.trim();
  if (!token) {
    throw new ValidationError('pat is required');
  }

  const req: TransactionRequest = {
    ...request,
    tags: request.tags ? [...request.tags] : undefined,
    signature: request.signature ? { ...request.signature } : undefined
  };

  normalizeTransactionRequestAliases(req);

  const claims = decodeTokenClaims(token);
  if (!req.workstreamId?.trim() && claims.workstreamId?.trim()) {
    req.workstreamId = claims.workstreamId.trim();
  }
  if (!req.sourceDid?.trim() && claims.participantDid?.trim()) {
    req.sourceDid = claims.participantDid.trim();
  }

  const { payloadHash } = resolvePayload(req.payload, req.payloadHash);
  req.payloadHash = payloadHash;

  normalizeTransactionRequestAliases(req);
  validateTransactionRequestForSubmit(req);

  const signature = {
    algorithm: req.signature!.algorithm.trim(),
    value: req.signature!.value.trim(),
    keyId: req.signature!.keyId?.trim() || undefined
  };
  const submission = buildTransactionSubmission(req, signature, payloadHash, req.timestamp ?? new Date());

  const normalized = normalizeConfig(cfg);
  const response = await requestJSON(normalized, {
    method: 'POST',
    path: '/v1/transactions',
    token,
    body: submission,
    signal: options.signal
  });

  if (response.status >= 400) {
    throw await decodeApiError(response);
  }

  const body = (await response.json()) as Record<string, unknown>;
  return deserializeTransaction(body);
}

/**
 * Validates Operon signature headers against a payload with PAT authentication.
 */
export async function validateSignatureWithPAT(
  cfg: ClientAPIConfig,
  pat: string,
  payload: TransactionPayload,
  headers: OperonHeaders,
  options: { signal?: AbortSignal } = {}
): Promise<SignatureValidationResult> {
  const token = pat.trim();
  if (!token) {
    throw new ValidationError('pat is required');
  }

  const payloadInput = resolvePayload(payload, undefined);
  if (!payloadInput.payloadBytes) {
    throw new ValidationError('payload bytes are required to validate Operon headers');
  }

  const sanitized = sanitizeOperonHeaders(headers);
  const expectedHash = sanitized[HEADER_OPERON_PAYLOAD_HASH];
  if (payloadInput.payloadHash.toLowerCase() !== expectedHash.toLowerCase()) {
    throw new ValidationError(
      `payload hash mismatch: expected ${payloadInput.payloadHash}, got ${expectedHash}`
    );
  }

  const normalized = normalizeConfig(cfg);
  const did = sanitized[HEADER_OPERON_DID];
  const response = await requestRaw(normalized, {
    method: 'POST',
    path: `/v1/dids/${encodeURIComponent(did)}/signature/verify`,
    token,
    body: payloadInput.payloadBytes,
    headers: sanitized,
    signal: options.signal
  });

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
 * Convenience wrapper around validateSignatureWithPAT for string payloads.
 */
export async function validateSignatureWithPATFromString(
  cfg: ClientAPIConfig,
  pat: string,
  payload: string,
  headers: OperonHeaders,
  options: { signal?: AbortSignal } = {}
): Promise<SignatureValidationResult> {
  return validateSignatureWithPAT(cfg, pat, payload, headers, options);
}

/**
 * Fetches workstream metadata with PAT authentication.
 */
export async function fetchWorkstream(
  cfg: WorkstreamDataConfig,
  pat: string,
  workstreamId?: string,
  options: { signal?: AbortSignal } = {}
): Promise<Workstream> {
  const token = pat.trim();
  if (!token) {
    throw new ValidationError('pat is required');
  }

  const targetWorkstream = resolveWorkstreamIdFromPAT(token, workstreamId);
  const normalized = normalizeConfig(cfg);
  const response = await requestJSON(normalized, {
    method: 'GET',
    path: `/v1/workstreams/${encodeURIComponent(targetWorkstream)}`,
    token,
    signal: options.signal
  });

  if (response.status >= 400) {
    throw await decodeApiError(response);
  }

  const body = (await response.json()) as Record<string, unknown>;
  return deserializeWorkstream(body);
}

/**
 * Fetches workstream interactions with PAT authentication.
 */
export async function fetchWorkstreamInteractions(
  cfg: WorkstreamDataConfig,
  pat: string,
  workstreamId?: string,
  options: { signal?: AbortSignal } = {}
): Promise<WorkstreamInteractionsResponse> {
  return (await fetchWorkstreamDataset(
    cfg,
    pat,
    'interactions',
    workstreamId,
    options
  )) as WorkstreamInteractionsResponse;
}

/**
 * Fetches workstream participants with PAT authentication.
 */
export async function fetchWorkstreamParticipants(
  cfg: WorkstreamDataConfig,
  pat: string,
  workstreamId?: string,
  options: { signal?: AbortSignal } = {}
): Promise<WorkstreamParticipantsResponse> {
  return (await fetchWorkstreamDataset(
    cfg,
    pat,
    'participants',
    workstreamId,
    options
  )) as WorkstreamParticipantsResponse;
}

async function fetchWorkstreamDataset(
  cfg: WorkstreamDataConfig,
  pat: string,
  resource: 'interactions' | 'participants',
  workstreamId?: string,
  options: { signal?: AbortSignal } = {}
): Promise<WorkstreamInteractionsResponse | WorkstreamParticipantsResponse> {
  const token = pat.trim();
  if (!token) {
    throw new ValidationError('pat is required');
  }

  const targetWorkstream = resolveWorkstreamIdFromPAT(token, workstreamId);
  const normalized = normalizeConfig(cfg);

  const response = await requestJSON(normalized, {
    method: 'GET',
    path: `/v1/workstreams/${encodeURIComponent(targetWorkstream)}/${resource}`,
    token,
    signal: options.signal
  });

  if (response.status >= 400) {
    throw await decodeApiError(response);
  }

  const body = (await response.json()) as {
    interactions?: Array<Record<string, unknown>>;
    participants?: Array<Record<string, unknown>>;
    totalCount?: number;
    page?: number;
    pageSize?: number;
    hasMore?: boolean;
  };

  if (resource === 'interactions') {
    return {
      interactions: (body.interactions ?? []).map((item) => ({
        id: String(item.id ?? ''),
        workstreamId: firstNonEmpty(asString(item.workstreamId), asString(item.channelId), ''),
        workstreamName: asString(item.workstreamName),
        name: asString(item.name),
        description: asString(item.description),
        status: asString(item.status),
        sourceParticipantId: asString(item.sourceParticipantId),
        targetParticipantId: asString(item.targetParticipantId),
        workstreams: asStringArray(item.workstreams),
        type: asString(item.type),
        actor: asString(item.actor),
        states: asStringArray(item.states),
        roiClassification: asString(item.roiClassification),
        roiCost: asNumber(item.roiCost),
        roiTime: asNumber(item.roiTime),
        tags: asStringArray(item.tags),
        createdAt: toDateOrUndefined(item.createdAt),
        updatedAt: toDateOrUndefined(item.updatedAt),
        version: asNumber(item.version)
      })),
      totalCount: body.totalCount ?? 0,
      page: body.page ?? 0,
      pageSize: body.pageSize ?? 0,
      hasMore: body.hasMore ?? false
    };
  }

  return {
    participants: (body.participants ?? []).map((item) => ({
      id: String(item.id ?? ''),
      did: String(item.did ?? ''),
      name: asString(item.name),
      description: asString(item.description),
      url: asString(item.url),
      status: asString(item.status),
      type: asString(item.type),
      customerId: asString(item.customerId),
      workstreamId: firstNonEmpty(asString(item.workstreamId), asString(item.channelId)),
      workstreamName: asString(item.workstreamName),
      tags: asStringArray(item.tags),
      createdAt: toDateOrUndefined(item.createdAt),
      updatedAt: toDateOrUndefined(item.updatedAt),
      version: asNumber(item.version)
    })),
    totalCount: body.totalCount ?? 0,
    page: body.page ?? 0,
    pageSize: body.pageSize ?? 0,
    hasMore: body.hasMore ?? false
  };
}

function resolveWorkstreamIdFromPAT(pat: string, override?: string): string {
  if (override?.trim()) {
    return override.trim();
  }

  const claims = decodeTokenClaims(pat);
  if (claims.workstreamId?.trim()) {
    return claims.workstreamId.trim();
  }

  throw new ValidationError(
    'workstream ID is required: token not scoped to a workstream and no override provided'
  );
}

function normalizeConfig(input: ClientAPIConfig | WorkstreamDataConfig): NormalizedConfig {
  const baseUrl = (input.baseUrl ?? DEFAULT_BASE_URL).trim();
  if (!baseUrl) {
    throw new ValidationError('baseUrl is required');
  }

  let normalizedURL: string;
  try {
    normalizedURL = new URL(baseUrl).toString().replace(/\/$/, '');
  } catch (error) {
    throw new ValidationError(
      `invalid baseUrl: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  const fetchImpl =
    input.fetchImpl ??
    (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined);
  if (!fetchImpl) {
    throw new ValidationError(
      'fetch implementation is required; supply fetchImpl when global fetch is unavailable'
    );
  }

  return {
    baseUrl: normalizedURL,
    httpTimeoutMs:
      input.httpTimeoutMs && input.httpTimeoutMs > 0 ? input.httpTimeoutMs : DEFAULT_HTTP_TIMEOUT_MS,
    fetchImpl
  };
}

interface RequestOptions {
  method: string;
  path: string;
  token: string;
  body?: unknown;
  signal?: AbortSignal;
}

async function requestJSON(cfg: NormalizedConfig, options: RequestOptions): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), cfg.httpTimeoutMs);
  const url = `${cfg.baseUrl}${options.path.startsWith('/') ? options.path : `/${options.path}`}`;

  try {
    const response = await cfg.fetchImpl(url, {
      method: options.method,
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${options.token}`,
        ...(options.body !== undefined && options.body !== null
          ? { 'Content-Type': 'application/json' }
          : undefined)
      },
      body: options.body !== undefined && options.body !== null ? JSON.stringify(options.body) : undefined,
      signal: mergeSignals(controller.signal, options.signal)
    });
    return response;
  } catch (error) {
    throw new TransportError(`request ${options.method} ${url} failed`, error);
  } finally {
    clearTimeout(timeout);
  }
}

interface RawRequestOptions {
  method: string;
  path: string;
  token: string;
  body: Buffer;
  headers: Record<string, string>;
  signal?: AbortSignal;
}

async function requestRaw(cfg: NormalizedConfig, options: RawRequestOptions): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), cfg.httpTimeoutMs);
  const url = `${cfg.baseUrl}${options.path.startsWith('/') ? options.path : `/${options.path}`}`;

  try {
    const response = await cfg.fetchImpl(url, {
      method: options.method,
      headers: {
        Authorization: `Bearer ${options.token}`,
        ...options.headers
      },
      body: Uint8Array.from(options.body),
      signal: mergeSignals(controller.signal, options.signal)
    });
    return response;
  } catch (error) {
    throw new TransportError(`request ${options.method} ${url} failed`, error);
  } finally {
    clearTimeout(timeout);
  }
}

function deserializeTransaction(payload: Record<string, unknown>): Transaction {
  const workstreamId = firstNonEmpty(asString(payload.workstreamId), asString(payload.channelId), '');
  return {
    id: String(payload.id ?? ''),
    correlationId: String(payload.correlationId ?? ''),
    workstreamId,
    channelId: workstreamId,
    workstreamName: asString(payload.workstreamName),
    customerId: asString(payload.customerId),
    workspaceId: asString(payload.workspaceId),
    interactionId: String(payload.interactionId ?? ''),
    timestamp: toDate(String(payload.timestamp ?? '')),
    sourceDid: String(payload.sourceDid ?? ''),
    targetDid: String(payload.targetDid ?? ''),
    state: asString(payload.state),
    stateId: asString(payload.stateId),
    stateLabel: asString(payload.stateLabel),
    roiClassification: asString(payload.roiClassification),
    roiCostIncrement: asNumber(payload.roiCostIncrement),
    roiTimeIncrement: asNumber(payload.roiTimeIncrement),
    roiCostSavings: asNumber(payload.roiCostSavings),
    roiTimeSavings: asNumber(payload.roiTimeSavings),
    roiBaseCost: asNumber(payload.roiBaseCost),
    roiBaseTime: asNumber(payload.roiBaseTime),
    roiCostSaving: asNumber(payload.roiCostSaving),
    roiTimeSaving: asNumber(payload.roiTimeSaving),
    signature: (payload.signature as Signature) ?? { algorithm: '', value: '' },
    label: asString(payload.label),
    tags: asStringArray(payload.tags),
    payloadHash: String(payload.payloadHash ?? ''),
    actorExternalId: asString(payload.actorExternalId),
    actorExternalDisplayName: asString(payload.actorExternalDisplayName),
    actorExternalSource: asString(payload.actorExternalSource),
    assigneeExternalId: asString(payload.assigneeExternalId),
    assigneeExternalDisplayName: asString(payload.assigneeExternalDisplayName),
    assigneeExternalSource: asString(payload.assigneeExternalSource),
    status: String(payload.status ?? ''),
    hcsTopicId: asString(payload.hcsTopicId),
    hcsSequenceNumber: asNumber(payload.hcsSequenceNumber),
    hcsConsensusTimestamp: asString(payload.hcsConsensusTimestamp),
    hcsTransactionId: asString(payload.hcsTransactionId),
    hcsRunningHash: asString(payload.hcsRunningHash),
    createdAt: toDate(String(payload.createdAt ?? '')),
    updatedAt: toDate(String(payload.updatedAt ?? '')),
    createdBy: asString(payload.createdBy),
    updatedBy: asString(payload.updatedBy),
    version: asNumber(payload.version)
  };
}

function deserializeWorkstream(payload: Record<string, unknown>): Workstream {
  return {
    id: String(payload.id ?? ''),
    createdAt: toDateOrUndefined(payload.createdAt),
    updatedAt: toDateOrUndefined(payload.updatedAt),
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
    states: Array.isArray(payload.states)
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
      : undefined,
    defaultStateId: asString(payload.defaultStateId),
    interactionIds: asStringArray(payload.interactionIds),
    hcsTestTopicId: asString(payload.hcsTestTopicId),
    hcsLiveTopicId: asString(payload.hcsLiveTopicId)
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
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
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
    if (value?.trim()) {
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
