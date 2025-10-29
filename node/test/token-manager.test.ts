import { afterEach, describe, expect, test, vi } from 'vitest';

import { createConfig } from '../src/config.js';
import { ClientCredentialsManager } from '../src/auth/token-manager.js';

const TOKEN_URL = 'https://auth.example.com/oauth/token';

describe('ClientCredentialsManager', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('fetches and caches tokens until leeway threshold', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      calls.push({ url, init });
      const body = JSON.stringify({
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
          Buffer.from(
            JSON.stringify({ participant_did: 'did:example:123', channel_id: 'chnl-1' })
          ).toString('base64url') +
          '.sig',
        token_type: 'Bearer',
        expires_in: 120
      });
      return new Response(body, {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    });

    const config = createConfig({
      clientId: 'client',
      clientSecret: 'secret',
      tokenUrl: TOKEN_URL,
      fetchImpl
    });

    const manager = new ClientCredentialsManager(config);
    const first = await manager.token();
    const second = await manager.token();

    expect(first.accessToken).toBe(second.accessToken);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(first.participantDid).toBe('did:example:123');
    expect(first.channelId).toBe('chnl-1');

    manager.clear();
    await manager.token();
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(calls[0].url).toBe(TOKEN_URL);
    expect(calls[0].init?.method).toBe('POST');
  });

  test('refreshes token when expired', async () => {
    let counter = 0;
    const fetchImpl = vi.fn(async () => {
      counter += 1;
      const payload = {
        access_token: `header.${Buffer.from(
          JSON.stringify({})
        ).toString('base64url')}.${counter}`,
        token_type: 'Bearer',
        expires_in: 1
      };
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    });

    const config = createConfig({
      clientId: 'client',
      clientSecret: 'secret',
      tokenUrl: TOKEN_URL,
      fetchImpl,
      tokenLeewayMs: 2_000
    });

    const manager = new ClientCredentialsManager(config);
    const first = await manager.token();
    await new Promise((resolve) => setTimeout(resolve, 5));
    const second = await manager.token();

    expect(first.accessToken).not.toBe(second.accessToken);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });
});
