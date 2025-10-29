import { describe, expect, test } from 'vitest';

import {
  DEFAULT_BASE_URL,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_TOKEN_LEEWAY_MS,
  DEFAULT_TOKEN_URL,
  createConfig
} from '../src/config.js';
import { DEFAULT_SIGNING_ALGORITHM } from '../src/types.js';

describe('createConfig', () => {
  test('fills defaults and preserves optional overrides', () => {
    const config = createConfig({
      clientId: 'm2mc-123',
      clientSecret: 'secret'
    });

    expect(config.baseUrl).toBe(DEFAULT_BASE_URL);
    expect(config.tokenUrl).toBe(DEFAULT_TOKEN_URL);
    expect(config.httpTimeoutMs).toBe(DEFAULT_HTTP_TIMEOUT_MS);
    expect(config.signingAlgorithm).toBe(DEFAULT_SIGNING_ALGORITHM);
    expect(config.tokenLeewayMs).toBe(DEFAULT_TOKEN_LEEWAY_MS);
    expect(config.disableSelfSign).toBe(false);
    expect(typeof config.fetchImpl).toBe('function');
    expect(config.logger).toBeDefined();
  });

  test('trims URLs and applies overrides', () => {
    const fetchImpl = async () => new Response('', { status: 200 });
    const config = createConfig({
      baseUrl: 'https://example.com/client-api/',
      tokenUrl: ' https://example.com/oauth/token ',
      clientId: 'client',
      clientSecret: 'secret',
      scope: 'transactions:write',
      audience: [' https://api.example.com '],
      httpTimeoutMs: 10_000,
      signingAlgorithm: 'ES256',
      disableSelfSign: true,
      tokenLeewayMs: 5_000,
      fetchImpl
    });

    expect(config.baseUrl).toBe('https://example.com/client-api');
    expect(config.tokenUrl).toBe('https://example.com/oauth/token');
    expect(config.scope).toBe('transactions:write');
    expect(config.audience).toEqual(['https://api.example.com']);
    expect(config.httpTimeoutMs).toBe(10_000);
    expect(config.signingAlgorithm).toBe('ES256');
    expect(config.disableSelfSign).toBe(true);
    expect(config.tokenLeewayMs).toBe(5_000);
    expect(config.fetchImpl).toBe(fetchImpl);
  });

  test('requires client credentials', () => {
    expect(() => createConfig({ clientId: '', clientSecret: '' })).toThrow('clientId is required');
    expect(() => createConfig({ clientId: 'id', clientSecret: '' })).toThrow('clientSecret is required');
  });
});
