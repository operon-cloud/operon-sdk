import type { OperonConfig } from '../config.js';
import { decodeApiError } from '../errors.js';
import type { AccessToken } from '../types.js';

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
      const accessToken: AccessToken = {
        accessToken: payload.access_token.trim(),
        expiresAt: new Date(Date.now() + expiresIn * 1000),
        ...this.extractClaims(payload.access_token)
      };
      return accessToken;
    } finally {
      clearTimeout(timeout);
    }
  }

  private isLegacyEndpoint(): boolean {
    return this.config.tokenUrl.includes('/v1/session/m2m');
  }

  private extractClaims(token: string) {
    const parts = token.split('.');
    if (parts.length < 2) {
      return {};
    }

    try {
      const payloadSegment = base64UrlDecode(parts[1]);
      const payload = JSON.parse(payloadSegment.toString('utf-8')) as Record<string, unknown>;
      return {
        participantDid: readString(payload, 'participant_did'),
        channelId: readString(payload, 'channel_id'),
        customerId: readString(payload, 'customer_id'),
        workspaceId: readString(payload, 'workspace_id'),
        email: readString(payload, 'email'),
        name: readString(payload, 'name'),
        tenantIds: readStringArray(payload, 'tenant_ids'),
        roles: readStringArray(payload, 'roles'),
        memberId: readString(payload, 'member_id'),
        sessionId: readString(payload, 'session_id'),
        orgId: readString(payload, 'org_id')
      };
    } catch {
      return {};
    }
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
  primary.addEventListener('abort', abort);
  secondary.addEventListener('abort', abort);
  return controller.signal;
}

function base64UrlDecode(segment: string): Buffer {
  let input = segment.replace(/-/g, '+').replace(/_/g, '/');
  const padding = input.length % 4;
  if (padding === 2) {
    input += '==';
  } else if (padding === 3) {
    input += '=';
  } else if (padding !== 0) {
    input += '==='.slice(0, (4 - padding) % 4);
  }
  return Buffer.from(input, 'base64');
}

function readString(source: Record<string, unknown>, key: string): string | undefined {
  const value = source[key];
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function readStringArray(source: Record<string, unknown>, key: string): string[] | undefined {
  const value = source[key];
  if (!Array.isArray(value)) {
    return undefined;
  }
  const items = value
    .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
    .filter((entry) => entry.length > 0);
  return items.length > 0 ? items : undefined;
}
