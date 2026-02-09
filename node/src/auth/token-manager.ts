import type { OperonConfig } from '../config.js';
import { decodeApiError } from '../errors.js';
import type { AccessToken } from '../types.js';

import { decodeTokenClaims } from './claims.js';

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

/**
 * Retrieves and caches access tokens for downstream requests.
 */
export interface TokenManager {
  /**
   * Returns a valid access token, refreshing if the cached token is nearing expiry.
   */
  token(signal?: AbortSignal): Promise<AccessToken>;
  /**
   * Forces minting of a new token, replacing the cached entry.
   */
  forceRefresh(signal?: AbortSignal): Promise<AccessToken>;
  /**
   * Clears any cached token forcing the next call to mint a fresh one.
   */
  clear(): void;
}

/**
 * Client-credentials token manager backed by the Operon identity service.
 */
export class ClientCredentialsManager implements TokenManager {
  private cached?: AccessToken;

  /**
   * @param config Normalised Operon configuration containing OAuth metadata.
   */
  constructor(private readonly config: OperonConfig) {}

  async token(signal?: AbortSignal): Promise<AccessToken> {
    if (this.cached && this.shouldReuseToken(this.cached)) {
      return this.cached;
    }

    const fresh = await this.fetchToken(signal);
    this.cached = fresh;
    return fresh;
  }

  async forceRefresh(signal?: AbortSignal): Promise<AccessToken> {
    const fresh = await this.fetchToken(signal);
    this.cached = fresh;
    return fresh;
  }

  clear(): void {
    this.cached = undefined;
  }

  private shouldReuseToken(token: AccessToken): boolean {
    const now = Date.now();
    return token.expiresAt.getTime() - now > this.config.tokenLeewayMs;
  }

  private async fetchToken(signal?: AbortSignal): Promise<AccessToken> {
    const legacy = this.isLegacyEndpoint();
    const url = this.config.tokenUrl;

    const headers = new Headers({
      Accept: 'application/json'
    });

    let body: BodyInit;
    if (legacy) {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify({
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        grant_type: 'client_credentials',
        scope: this.config.scope,
        audience: this.config.audience
      });
    } else {
      headers.set('Content-Type', 'application/x-www-form-urlencoded');
      const credentials = Buffer.from(
        `${this.config.clientId}:${this.config.clientSecret}`,
        'utf-8'
      ).toString('base64');
      headers.set('Authorization', `Basic ${credentials}`);
      const form = new URLSearchParams();
      form.set('grant_type', 'client_credentials');
      if (this.config.scope) {
        form.set('scope', this.config.scope);
      }
      for (const aud of this.config.audience) {
        form.append('audience', aud);
      }
      body = form.toString();
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.httpTimeoutMs);
    try {
      const response = await this.config.fetchImpl(url, {
        method: 'POST',
        headers,
        body,
        signal: mergeSignals(controller.signal, signal)
      });

      if (response.status >= 400) {
        throw await decodeApiError(response);
      }

      const payload = (await response.json()) as TokenResponse;
      if (!payload.access_token?.trim()) {
        throw new Error('token response missing access_token');
      }

      const expiresIn = Math.max(1, payload.expires_in ?? 60);
      const claims = decodeTokenClaims(payload.access_token);
      const accessToken: AccessToken = {
        accessToken: payload.access_token.trim(),
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        participantDid: claims.participantDid,
        workstreamId: claims.workstreamId,
        channelId: claims.workstreamId,
        customerId: claims.customerId,
        workspaceId: claims.workspaceId,
        email: claims.email,
        name: claims.name,
        tenantIds: claims.tenantIds,
        roles: claims.roles,
        memberId: claims.memberId,
        sessionId: claims.sessionId,
        orgId: claims.orgId,
        participantId: claims.participantId,
        clientId: claims.clientId,
        authorizedParty: claims.authorizedParty,
        expiresAtUnix: claims.expiresAtUnix
      };
      return accessToken;
    } finally {
      clearTimeout(timeout);
    }
  }

  private isLegacyEndpoint(): boolean {
    return this.config.tokenUrl.includes('/v1/session/m2m');
  }
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
