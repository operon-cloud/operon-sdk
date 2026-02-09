/**
 * Default algorithm used when signing transaction hashes.
 */
export const DEFAULT_SIGNING_ALGORITHM = 'EdDSA';
export const ALGORITHM_ES256 = 'ES256';
export const ALGORITHM_ES256K = 'ES256K';

export const SIGNING_ALGORITHMS = [
  DEFAULT_SIGNING_ALGORITHM,
  ALGORITHM_ES256,
  ALGORITHM_ES256K
] as const;

export type SigningAlgorithm = (typeof SIGNING_ALGORITHMS)[number];

export const ROI_CLASSIFICATION_BASELINE = 'baseline';
export const ROI_CLASSIFICATION_INCREMENT = 'increment';
export const ROI_CLASSIFICATION_SAVINGS = 'savings';

export const ROI_CLASSIFICATIONS = [
  ROI_CLASSIFICATION_BASELINE,
  ROI_CLASSIFICATION_INCREMENT,
  ROI_CLASSIFICATION_SAVINGS
] as const;

export type ROIClassification = (typeof ROI_CLASSIFICATIONS)[number];

export const INTERACTION_TYPE_TOUCH = 'touch';
export const INTERACTION_TYPE_TRANSITION = 'transition';
export const INTERACTION_TYPE_TRANSFER = 'transfer';

export const INTERACTION_ACTOR_HUMAN = 'human';
export const INTERACTION_ACTOR_AI = 'ai';
export const INTERACTION_ACTOR_HYBRID = 'hybrid';
export const INTERACTION_ACTOR_NON_AI = 'non-ai';

export const WORKSTREAM_STATUS_DRAFT = 'draft';
export const WORKSTREAM_STATUS_ACTIVE = 'active';
export const WORKSTREAM_STATUS_INACTIVE = 'inactive';
export const WORKSTREAM_STATUS_ARCHIVED = 'archived';

export const WORKSTREAM_MODE_OFF = 'off';
export const WORKSTREAM_MODE_ON = 'on';

export const WORKSTREAM_TYPE_INTERNAL = 'internal';
export const WORKSTREAM_TYPE_PRODUCTION = 'production';

export const WORKSTREAM_STATE_STATUS_ACTIVE = 'active';
export const WORKSTREAM_STATE_STATUS_INACTIVE = 'inactive';

export type TransactionPayload = string | Uint8Array | Buffer | Record<string, unknown>;

/**
 * Signature metadata associated with submitted transactions.
 */
export interface Signature {
  algorithm: string;
  value: string;
  keyId?: string;
}

/**
 * HTTP headers required when exchanging Operon-signed payloads.
 */
export interface OperonHeaders {
  [key: string]: string;
}

/**
 * Result returned by the Operon signature validation endpoint.
 */
export interface SignatureValidationResult {
  status: string;
  message?: string;
  did: string;
  payloadHash: string;
  algorithm: string;
  keyId: string;
}

/**
 * Client-facing shape for submitting transactions to Operon.
 */
export interface TransactionRequest {
  correlationId: string;
  workstreamId?: string;
  channelId?: string;
  interactionId: string;
  timestamp?: Date;
  sourceDid?: string;
  targetDid?: string;
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
  signature?: Signature;
  label?: string;
  tags?: string[];
  payload?: TransactionPayload;
  payloadHash?: string;
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

/**
 * Transaction record returned by Operon APIs.
 */
export interface Transaction {
  id: string;
  correlationId: string;
  workstreamId: string;
  channelId?: string;
  workstreamName?: string;
  customerId?: string;
  workspaceId?: string;
  interactionId: string;
  timestamp: Date;
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
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  updatedBy?: string;
  version?: number;
}

/**
 * Lightweight description of an interaction in the Operon catalogue.
 */
export interface InteractionSummary {
  id: string;
  workstreamId: string;
  channelId?: string;
  workstreamName?: string;
  name?: string;
  description?: string;
  status?: string;
  sourceParticipantId: string;
  targetParticipantId: string;
  sourceDid?: string;
  targetDid?: string;
  type?: string;
  actor?: string;
  states?: string[];
  roiClassification?: string;
  roiCost?: number;
  roiTime?: number;
}

/**
 * Minimal participant record.
 */
export interface ParticipantSummary {
  id: string;
  did: string;
  name?: string;
  status?: string;
  customerId?: string;
  workstreamId?: string;
  channelId?: string;
  workstreamName?: string;
}

export interface WorkstreamState {
  id: string;
  name: string;
  status?: string;
}

export interface Workstream {
  id: string;
  createdAt?: Date;
  updatedAt?: Date;
  createdBy?: string;
  updatedBy?: string;
  version?: number;
  customerId?: string;
  workspaceId?: string;
  name?: string;
  description?: string;
  mode?: string;
  type?: string;
  status?: string;
  states?: WorkstreamState[];
  defaultStateId?: string;
  interactionIds?: string[];
  hcsTestTopicId?: string;
  hcsLiveTopicId?: string;
}

export interface WorkstreamInteraction {
  id: string;
  workstreamId: string;
  workstreamName?: string;
  name?: string;
  description?: string;
  status?: string;
  sourceParticipantId?: string;
  targetParticipantId?: string;
  workstreams?: string[];
  type?: string;
  actor?: string;
  states?: string[];
  roiClassification?: string;
  roiCost?: number;
  roiTime?: number;
  tags?: string[];
  createdAt?: Date;
  updatedAt?: Date;
  version?: number;
}

export interface WorkstreamInteractionsResponse {
  interactions: WorkstreamInteraction[];
  totalCount: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

export interface WorkstreamParticipant {
  id: string;
  did: string;
  name?: string;
  description?: string;
  url?: string;
  status?: string;
  type?: string;
  customerId?: string;
  workstreamId?: string;
  workstreamName?: string;
  tags?: string[];
  createdAt?: Date;
  updatedAt?: Date;
  version?: number;
}

export interface WorkstreamParticipantsResponse {
  participants: WorkstreamParticipant[];
  totalCount: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

// Legacy aliases retained for backward compatibility.
export type ChannelInteraction = WorkstreamInteraction;
export type ChannelInteractionsResponse = WorkstreamInteractionsResponse;
export type ChannelParticipant = WorkstreamParticipant;
export type ChannelParticipantsResponse = WorkstreamParticipantsResponse;

export interface SessionInfo {
  userId?: string;
  email?: string;
  name?: string;
  customerId?: string;
  roles: string[];
  featureFlags: Record<string, unknown>;
  workstreamId?: string;
  channelId?: string;
  workspaceId?: string;
  participantDid?: string;
  participantId?: string;
  clientId?: string;
  sessionId?: string;
  expiresAt?: Date;
  expiresInSeconds?: number;
}

export interface TokenClaims {
  participantDid?: string;
  workstreamId?: string;
  channelId?: string;
  customerId?: string;
  workspaceId?: string;
  email?: string;
  name?: string;
  tenantIds?: string[];
  roles?: string[];
  memberId?: string;
  sessionId?: string;
  orgId?: string;
  participantId?: string;
  clientId?: string;
  authorizedParty?: string;
  expiresAtUnix?: number;
}

export interface TokenContext extends TokenClaims {}

export interface AccessToken extends TokenContext {
  accessToken: string;
  expiresAt: Date;
}

export type FetchFunction = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export function canonicalSigningAlgorithm(value: string): SigningAlgorithm | undefined {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  return SIGNING_ALGORITHMS.find((candidate) => candidate.toLowerCase() === trimmed.toLowerCase());
}

export function isROIClassification(value: string): value is ROIClassification {
  return ROI_CLASSIFICATIONS.some((candidate) => candidate === value);
}

export function validatePayloadHashFormat(payloadHash: string): void {
  if (payloadHash.length !== 43) {
    throw new Error(`payload hash must be 43 characters, got ${payloadHash.length}`);
  }

  if (!/^[A-Za-z0-9_-]{43}$/.test(payloadHash)) {
    throw new Error('payload hash must be base64url encoded: invalid characters');
  }

  const normalized = payloadHash.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  const decoded = Buffer.from(normalized + padding, 'base64');
  if (decoded.length === 0) {
    throw new Error('payload hash must be base64url encoded');
  }
}

export function decodePayloadBase64(payloadData: string): Buffer {
  const encoded = payloadData.trim();
  if (!encoded) {
    return Buffer.alloc(0);
  }

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
    throw new Error('payloadData must be valid base64');
  }

  return Buffer.from(encoded, 'base64');
}

export function buildKeyId(did: string): string {
  const trimmed = did.trim();
  if (!trimmed) {
    return '';
  }
  return `${trimmed}#keys-1`;
}
