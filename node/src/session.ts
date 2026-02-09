import { decodeTokenClaims } from './auth/claims.js';
import { DEFAULT_BASE_URL, DEFAULT_HTTP_TIMEOUT_MS } from './config.js';
import { decodeApiError, TransportError, ValidationError } from './errors.js';
import type { FetchFunction, SessionInfo } from './types.js';

export interface SessionValidationConfig {
  baseUrl?: string;
  httpTimeoutMs?: number;
  fetchImpl?: FetchFunction;
}

/**
 * Validates a PAT and returns normalized session metadata.
 */
export async function validateSession(
  cfg: SessionValidationConfig,
  pat: string,
  options: { signal?: AbortSignal } = {}
): Promise<SessionInfo> {
  const token = pat.trim();
  if (!token) {
    throw new ValidationError('pat is required');
  }

  const normalized = normalizeConfig(cfg);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), normalized.httpTimeoutMs);

  try {
    let response: Response;
    try {
      response = await normalized.fetchImpl(`${normalized.baseUrl}/v1/session/validate`, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: `Bearer ${token}`
        },
        signal: mergeSignals(controller.signal, options.signal)
      });
    } catch (error) {
      throw new TransportError('perform validation request', error);
    }

    if (response.status >= 400) {
      throw await decodeApiError(response);
    }

    const payload = (await response.json()) as Record<string, unknown>;
    const claims = decodeTokenClaims(token);

    const expiresAt =
      typeof claims.expiresAtUnix === 'number' && claims.expiresAtUnix > 0
        ? new Date(claims.expiresAtUnix * 1000)
        : undefined;

    const expiresInSeconds =
      expiresAt && Number.isFinite(expiresAt.getTime())
        ? Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000))
        : 0;

    const roles = Array.isArray(payload.roles)
      ? payload.roles
          .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
          .filter((entry) => entry.length > 0)
      : [];

    const featureFlags =
      payload.feature_flags && typeof payload.feature_flags === 'object' && !Array.isArray(payload.feature_flags)
        ? (payload.feature_flags as Record<string, unknown>)
        : {};

    return {
      userId: asString(payload.user_id),
      email: asString(payload.email),
      name: asString(payload.name),
      customerId: asString(payload.customer_id),
      roles,
      featureFlags,
      workstreamId: claims.workstreamId,
      channelId: claims.workstreamId,
      workspaceId: claims.workspaceId,
      participantDid: claims.participantDid,
      participantId: claims.participantId,
      clientId: claims.clientId || claims.authorizedParty,
      sessionId: claims.sessionId,
      expiresAt,
      expiresInSeconds
    };
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeConfig(cfg: SessionValidationConfig): {
  baseUrl: string;
  httpTimeoutMs: number;
  fetchImpl: FetchFunction;
} {
  const baseUrl = (cfg.baseUrl ?? DEFAULT_BASE_URL).trim();
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
    cfg.fetchImpl ??
    (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined);
  if (!fetchImpl) {
    throw new ValidationError(
      'fetch implementation is required; supply fetchImpl when global fetch is unavailable'
    );
  }

  return {
    baseUrl: normalizedURL,
    httpTimeoutMs:
      cfg.httpTimeoutMs && cfg.httpTimeoutMs > 0 ? cfg.httpTimeoutMs : DEFAULT_HTTP_TIMEOUT_MS,
    fetchImpl
  };
}

function asString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
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
