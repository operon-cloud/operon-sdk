/**
 * Default algorithm used when signing transaction hashes.
 */
export const DEFAULT_SIGNING_ALGORITHM = 'EdDSA';

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
 * Client-facing shape for submitting transactions to Operon.
 */
export interface TransactionRequest {
  correlationId: string;
  channelId?: string;
  interactionId: string;
  timestamp?: Date;
  sourceDid?: string;
  targetDid?: string;
  signature?: Signature;
  label?: string;
  tags?: string[];
  payload?: TransactionPayload;
  payloadHash?: string;
}

/**
 * Transaction record returned by Operon APIs.
 */
export interface Transaction {
  id: string;
  correlationId: string;
  channelId: string;
  customerId?: string;
  workspaceId?: string;
  interactionId: string;
  timestamp: Date;
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
  channelId: string;
  sourceParticipantId: string;
  targetParticipantId: string;
  sourceDid?: string;
  targetDid?: string;
}

/**
 * Minimal participant record (ID -> DID mapping).
 */
export interface ParticipantSummary {
  id: string;
  did: string;
}

export interface TokenContext {
  participantDid?: string;
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
}

export interface AccessToken extends TokenContext {
  accessToken: string;
  expiresAt: Date;
}

export type FetchFunction = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
