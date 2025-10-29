import { DEFAULT_SIGNING_ALGORITHM, type FetchFunction } from './types.js';

/**
 * Production API base used when no override is supplied.
 */
export const DEFAULT_BASE_URL = 'https://api.operon.cloud/client-api';
/**
 * Production OAuth token endpoint used when no override is supplied.
 */
export const DEFAULT_TOKEN_URL = 'https://auth.operon.cloud/oauth2/token';
/**
 * Default HTTP timeout applied to outbound requests.
 */
export const DEFAULT_HTTP_TIMEOUT_MS = 30_000;
/**
 * Default buffer applied when refreshing access tokens ahead of expiry.
 */
export const DEFAULT_TOKEN_LEEWAY_MS = 30_000;

export interface Logger {
  debug?(message: string, metadata?: Record<string, unknown>): void;
  info?(message: string, metadata?: Record<string, unknown>): void;
  warn?(message: string, metadata?: Record<string, unknown>): void;
  error?(message: string, metadata?: Record<string, unknown>): void;
}

/**
 * User-supplied configuration before validation and defaulting.
 */
export interface OperonConfigInput {
  baseUrl?: string;
  tokenUrl?: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  audience?: string[];
  httpTimeoutMs?: number;
  fetchImpl?: FetchFunction;
  disableSelfSign?: boolean;
  signingAlgorithm?: string;
  tokenLeewayMs?: number;
  logger?: Logger;
}

/**
 * Fully validated configuration consumed by the SDK runtime.
 */
export interface OperonConfig {
  baseUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  audience: string[];
  httpTimeoutMs: number;
  fetchImpl: FetchFunction;
  disableSelfSign: boolean;
  signingAlgorithm: string;
  tokenLeewayMs: number;
  logger: Logger;
}

const noopLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {}
};

function trimAndRemoveTrailingSlash(url: string | undefined, fallback: string): string {
  const trimmed = (url ?? '').trim();
  if (!trimmed) {
    return fallback;
  }
  return trimmed.endsWith('/') ? trimmed.slice(0, -1) : trimmed;
}

function ensureFetch(fetchImpl?: FetchFunction): FetchFunction {
  if (fetchImpl) {
    return fetchImpl;
  }
  if (typeof globalThis.fetch === 'function') {
    return globalThis.fetch.bind(globalThis);
  }
  throw new Error('fetch implementation is required; supply fetchImpl when global fetch is unavailable');
}

/**
 * Normalises user configuration, fills defaults, and performs basic validation.
 *
 * @param input Raw configuration provided by the SDK consumer.
 * @returns Fully validated configuration.
 */
export function createConfig(input: OperonConfigInput): OperonConfig {
  if (!input) {
    throw new Error('config cannot be null or undefined');
  }

  const clientId = input.clientId?.trim();
  const clientSecret = input.clientSecret?.trim();
  if (!clientId) {
    throw new Error('clientId is required');
  }
  if (!clientSecret) {
    throw new Error('clientSecret is required');
  }

  const baseUrl = trimAndRemoveTrailingSlash(input.baseUrl, DEFAULT_BASE_URL);
  const tokenUrl = trimAndRemoveTrailingSlash(input.tokenUrl, DEFAULT_TOKEN_URL);

  const httpTimeoutMs =
    input.httpTimeoutMs && input.httpTimeoutMs > 0 ? input.httpTimeoutMs : DEFAULT_HTTP_TIMEOUT_MS;
  const tokenLeewayMs =
    input.tokenLeewayMs && input.tokenLeewayMs > 0 ? input.tokenLeewayMs : DEFAULT_TOKEN_LEEWAY_MS;
  const signingAlgorithm = input.signingAlgorithm?.trim() ?? DEFAULT_SIGNING_ALGORITHM;
  const scope = input.scope?.trim() || undefined;
  const audience =
    input.audience?.map((aud) => aud.trim()).filter((aud) => aud.length > 0) ?? [];

  return {
    baseUrl,
    tokenUrl,
    clientId,
    clientSecret,
    scope,
    audience,
    httpTimeoutMs,
    fetchImpl: ensureFetch(input.fetchImpl),
    disableSelfSign: Boolean(input.disableSelfSign),
    signingAlgorithm,
    tokenLeewayMs,
    logger: input.logger ?? noopLogger
  };
}
