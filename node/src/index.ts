export { OperonClient, type SubmitTransactionOptions } from './client.js';
export {
  createConfig,
  type OperonConfig,
  type OperonConfigInput,
  DEFAULT_BASE_URL,
  DEFAULT_TOKEN_URL,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_TOKEN_LEEWAY_MS,
  DEFAULT_HEARTBEAT_TIMEOUT_MS
} from './config.js';
export {
  validateSession,
  type SessionValidationConfig
} from './session.js';
export {
  signHashWithPAT,
  submitTransactionWithPAT,
  validateSignatureWithPAT,
  validateSignatureWithPATFromString,
  fetchWorkstream,
  fetchWorkstreamInteractions,
  fetchWorkstreamParticipants,
  type ClientAPIConfig,
  type WorkstreamDataConfig
} from './pat.js';
export {
  HEADER_OPERON_DID,
  HEADER_OPERON_PAYLOAD_HASH,
  HEADER_OPERON_SIGNATURE,
  HEADER_OPERON_SIGNATURE_KEY,
  HEADER_OPERON_SIGNATURE_ALGO
} from './transactions.js';
export { decodeTokenClaims } from './auth/claims.js';
export type {
  AccessToken,
  TransactionRequest,
  Transaction,
  Signature,
  OperonHeaders,
  SignatureValidationResult,
  InteractionSummary,
  ParticipantSummary,
  Workstream,
  WorkstreamState,
  WorkstreamInteraction,
  WorkstreamInteractionsResponse,
  WorkstreamParticipant,
  WorkstreamParticipantsResponse,
  ChannelInteraction,
  ChannelInteractionsResponse,
  ChannelParticipant,
  ChannelParticipantsResponse,
  SessionInfo,
  TokenClaims,
  TokenContext
} from './types.js';
export {
  DEFAULT_SIGNING_ALGORITHM,
  ALGORITHM_ES256,
  ALGORITHM_ES256K,
  SIGNING_ALGORITHMS,
  ROI_CLASSIFICATION_BASELINE,
  ROI_CLASSIFICATION_INCREMENT,
  ROI_CLASSIFICATION_SAVINGS,
  ROI_CLASSIFICATIONS,
  INTERACTION_TYPE_TOUCH,
  INTERACTION_TYPE_TRANSITION,
  INTERACTION_TYPE_TRANSFER,
  INTERACTION_ACTOR_HUMAN,
  INTERACTION_ACTOR_AI,
  INTERACTION_ACTOR_HYBRID,
  INTERACTION_ACTOR_NON_AI,
  WORKSTREAM_STATUS_DRAFT,
  WORKSTREAM_STATUS_ACTIVE,
  WORKSTREAM_STATUS_INACTIVE,
  WORKSTREAM_STATUS_ARCHIVED,
  WORKSTREAM_MODE_OFF,
  WORKSTREAM_MODE_ON,
  WORKSTREAM_TYPE_INTERNAL,
  WORKSTREAM_TYPE_PRODUCTION,
  WORKSTREAM_STATE_STATUS_ACTIVE,
  WORKSTREAM_STATE_STATUS_INACTIVE,
  canonicalSigningAlgorithm,
  isROIClassification,
  buildKeyId,
  validatePayloadHashFormat,
  decodePayloadBase64
} from './types.js';
export { ValidationError, ApiError, TransportError, OperonSdkError } from './errors.js';
