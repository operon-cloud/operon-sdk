import { createHash } from 'node:crypto';

import { ValidationError } from './errors.js';
import {
  buildKeyId,
  isROIClassification,
  type OperonHeaders,
  type Signature,
  type TransactionPayload,
  type TransactionRequest,
  validatePayloadHashFormat
} from './types.js';

export const HEADER_OPERON_DID = 'X-Operon-DID';
export const HEADER_OPERON_PAYLOAD_HASH = 'X-Operon-Payload-Hash';
export const HEADER_OPERON_SIGNATURE = 'X-Operon-Signature';
export const HEADER_OPERON_SIGNATURE_KEY = 'X-Operon-Signature-KeyId';
export const HEADER_OPERON_SIGNATURE_ALGO = 'X-Operon-Signature-Alg';

export interface TransactionSubmission {
  correlationId: string;
  workstreamId: string;
  interactionId: string;
  timestamp: string;
  sourceDid: string;
  targetDid: string;
  roiClassification?: string;
  roiCost?: number;
  roiTime?: number;
  state?: string;
  stateId?: string;
  stateLabel?: string;
  roiBaseCost?: number;
  roiBaseTime?: number;
  roiCostSaving?: number;
  roiTimeSaving?: number;
  signature: Signature;
  payloadHash: string;
  label?: string;
  tags?: string[];
  actorExternalId?: string;
  actorExternalDisplayName?: string;
  actorExternalSource?: string;
  assigneeExternalId?: string;
  assigneeExternalDisplayName?: string;
  assigneeExternalSource?: string;
  customerId?: string;
  workspaceId?: string;
  createdBy?: string;
}

export function normalizeTransactionRequestAliases(request: TransactionRequest): void {
  const workstream = request.workstreamId?.trim();
  const channel = request.channelId?.trim();

  if (!workstream && channel) {
    request.workstreamId = channel;
  }
  if (!channel && workstream) {
    request.channelId = workstream;
  }
}

export function resolvePayload(
  payload: TransactionPayload | undefined,
  hash?: string
): { payloadHash: string; payloadBytes?: Buffer } {
  if (payload === undefined || payload === null) {
    const providedHash = hash?.trim() ?? '';
    if (!providedHash) {
      throw new ValidationError('payload or payloadHash is required');
    }
    try {
      validatePayloadHashFormat(providedHash);
    } catch (error) {
      throw new ValidationError(error instanceof Error ? error.message : String(error));
    }
    return { payloadHash: providedHash, payloadBytes: undefined };
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

  if (hash?.trim() && hash.trim().toLowerCase() !== payloadHash.toLowerCase()) {
    throw new ValidationError('provided payloadHash does not match payload content');
  }

  return { payloadHash, payloadBytes: Buffer.from(bytes) };
}

export function validateTransactionRequestForSubmit(request: TransactionRequest): void {
  if (!request.correlationId?.trim()) {
    throw new ValidationError('CorrelationID is required');
  }
  if (!request.workstreamId?.trim()) {
    throw new ValidationError('WorkstreamID is required');
  }
  if (!request.interactionId?.trim()) {
    throw new ValidationError('InteractionID is required');
  }
  if (!request.sourceDid?.trim()) {
    throw new ValidationError('SourceDID is required');
  }
  if (!request.sourceDid.trim().startsWith('did:')) {
    throw new ValidationError('SourceDID must be a valid DID');
  }
  if (!request.targetDid?.trim()) {
    throw new ValidationError('TargetDID is required');
  }
  if (!request.targetDid.trim().startsWith('did:')) {
    throw new ValidationError('TargetDID must be a valid DID');
  }
  if (!request.payloadHash?.trim()) {
    throw new ValidationError('payload bytes or payload hash is required');
  }

  const signature = request.signature;
  if (!signature?.algorithm?.trim()) {
    throw new ValidationError('Signature algorithm is required');
  }
  if (!signature.value?.trim()) {
    throw new ValidationError('Signature value is required');
  }

  if (request.roiClassification && !isROIClassification(request.roiClassification)) {
    throw new ValidationError('ROIClassification must be one of baseline, increment, savings');
  }

  if ((request.roiBaseCost ?? 0) < 0) {
    throw new ValidationError('ROIBaseCost cannot be negative');
  }
  if ((request.roiBaseTime ?? 0) < 0) {
    throw new ValidationError('ROIBaseTime cannot be negative');
  }
  if ((request.roiCostSaving ?? 0) < 0) {
    throw new ValidationError('ROICostSaving cannot be negative');
  }
  if ((request.roiTimeSaving ?? 0) < 0) {
    throw new ValidationError('ROITimeSaving cannot be negative');
  }

  if (
    !request.actorExternalSource?.trim() &&
    (request.actorExternalId?.trim() || request.actorExternalDisplayName?.trim())
  ) {
    throw new ValidationError(
      'ActorExternalSource is required when ActorExternalID or ActorExternalDisplayName is set'
    );
  }

  if (
    !request.assigneeExternalSource?.trim() &&
    (request.assigneeExternalId?.trim() || request.assigneeExternalDisplayName?.trim())
  ) {
    throw new ValidationError(
      'AssigneeExternalSource is required when AssigneeExternalID or AssigneeExternalDisplayName is set'
    );
  }
}

export function buildTransactionSubmission(
  request: TransactionRequest,
  signature: Signature,
  payloadHash: string,
  timestamp: Date
): TransactionSubmission {
  const sanitizedTags = (request.tags ?? []).map((tag) => tag.trim()).filter(Boolean);

  return {
    correlationId: request.correlationId.trim(),
    workstreamId: request.workstreamId!.trim(),
    interactionId: request.interactionId.trim(),
    timestamp: timestamp.toISOString(),
    sourceDid: request.sourceDid!.trim(),
    targetDid: request.targetDid!.trim(),
    roiClassification: request.roiClassification?.trim() || undefined,
    roiCost: request.roiCost,
    roiTime: request.roiTime,
    state: request.state?.trim() || undefined,
    stateId: request.stateId?.trim() || undefined,
    stateLabel: request.stateLabel?.trim() || undefined,
    roiBaseCost: request.roiBaseCost,
    roiBaseTime: request.roiBaseTime,
    roiCostSaving: request.roiCostSaving,
    roiTimeSaving: request.roiTimeSaving,
    signature,
    payloadHash,
    label: request.label?.trim() || undefined,
    tags: sanitizedTags.length > 0 ? sanitizedTags : undefined,
    actorExternalId: request.actorExternalId?.trim() || undefined,
    actorExternalDisplayName: request.actorExternalDisplayName?.trim() || undefined,
    actorExternalSource: request.actorExternalSource?.trim() || undefined,
    assigneeExternalId: request.assigneeExternalId?.trim() || undefined,
    assigneeExternalDisplayName: request.assigneeExternalDisplayName?.trim() || undefined,
    assigneeExternalSource: request.assigneeExternalSource?.trim() || undefined,
    customerId: request.customerId?.trim() || undefined,
    workspaceId: request.workspaceId?.trim() || undefined,
    createdBy: request.createdBy?.trim() || undefined
  };
}

export function sanitizeOperonHeaders(headers: OperonHeaders): Record<string, string> {
  if (!headers) {
    throw new ValidationError('operon headers cannot be nil');
  }

  const required = [
    HEADER_OPERON_DID,
    HEADER_OPERON_PAYLOAD_HASH,
    HEADER_OPERON_SIGNATURE,
    HEADER_OPERON_SIGNATURE_KEY,
    HEADER_OPERON_SIGNATURE_ALGO
  ];

  const sanitized: Record<string, string> = {};
  for (const key of required) {
    const value = headers[key]?.trim() ?? '';
    if (!value) {
      throw new ValidationError(`header ${key} is required`);
    }
    sanitized[key] = value;
  }

  return sanitized;
}

export function base64UrlEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export function defaultKeyId(sourceDid: string): string {
  return buildKeyId(sourceDid);
}
