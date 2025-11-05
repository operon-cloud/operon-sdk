import { afterEach, describe, expect, test, vi } from 'vitest';

import { OperonClient } from '../src/client.js';
import { createConfig } from '../src/config.js';

const BASE_URL = 'https://api.example.com/client-api';
const TOKEN_URL = 'https://auth.example.com/oauth/token';

function buildResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

describe('OperonClient', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('submits transaction with self-signing and reference hydration', async () => {
    const fetchCalls: Array<{ url: string; init?: RequestInit }> = [];
    const interactions = [
      {
        id: 'int-123',
        channelId: 'chnl-1',
        sourceParticipantId: 'part-1',
        targetParticipantId: 'part-2'
      }
    ];
    const participants = [
      { id: 'part-1', did: 'did:example:source' },
      { id: 'part-2', did: 'did:example:target' }
    ];

    const tokenPayload = {
      participant_did: 'did:example:cached',
      channel_id: 'chnl-cached'
    };

    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      fetchCalls.push({ url, init });

      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: `header.${Buffer.from(JSON.stringify(tokenPayload)).toString('base64url')}.sig`,
          token_type: 'Bearer',
          expires_in: 300
        });
      }

      if (url === `${BASE_URL}/v1/channels/chnl-cached/interactions`) {
        return buildResponse({ interactions, totalCount: interactions.length, page: 1, pageSize: 50, hasMore: false });
      }

      if (url === `${BASE_URL}/v1/channels/chnl-cached/participants`) {
        return buildResponse({
          participants,
          totalCount: participants.length,
          page: 1,
          pageSize: 50,
          hasMore: false
        });
      }

      if (url === `${BASE_URL}/v1/dids/self/sign`) {
        return buildResponse({
          signature: {
            algorithm: 'EdDSA',
            value: 'signed-value',
            keyId: 'did:example:source#keys-1'
          }
        });
      }

      if (url === `${BASE_URL}/v1/transactions`) {
        const body = init?.body ? JSON.parse(init.body as string) : {};
        return buildResponse({
          ...body,
          id: 'txn-123',
          status: 'PENDING',
          createdAt: '2025-01-01T00:00:00Z',
          updatedAt: '2025-01-01T00:00:00Z',
          timestamp: body.timestamp
        });
      }

      throw new Error(`unexpected fetch call to ${url}`);
    });

    const client = new OperonClient(
      createConfig({
        baseUrl: BASE_URL,
        tokenUrl: TOKEN_URL,
        clientId: 'client',
        clientSecret: 'secret',
        fetchImpl
      })
    );

    const result = await client.submitTransaction({
      correlationId: 'corr-1',
      interactionId: 'int-123',
      payload: { foo: 'bar' }
    });

    expect(result.id).toBe('txn-123');
    expect(result.signature.value).toBe('signed-value');
    expect(fetchImpl).toHaveBeenCalledTimes(5);

    const transactionCall = fetchCalls.find((call) => call.url.endsWith('/v1/transactions'));
    expect(transactionCall).toBeDefined();
    const requestBody = JSON.parse(transactionCall!.init!.body as string) as Record<string, unknown>;
    expect(requestBody.payloadData).toBeUndefined();
    expect(requestBody.payloadHash).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test('generates Operon signature headers using managed keys', async () => {
    const tokenPayload = {
      participant_did: 'did:example:signer',
      channel_id: 'chnl-sign'
    };

    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: `header.${Buffer.from(JSON.stringify(tokenPayload)).toString('base64url')}.sig`,
          token_type: 'Bearer',
          expires_in: 300
        });
      }

      if (url === `${BASE_URL}/v1/dids/self/sign`) {
        const body = init?.body ? JSON.parse(init.body as string) : {};
        expect(body.payloadHash).toBeDefined();
        return buildResponse({
          signature: {
            algorithm: 'EdDSA',
            value: 'signed-value',
            keyId: 'did:example:signer#keys-1'
          }
        });
      }

      throw new Error(`unexpected fetch call to ${url}`);
    });

    const client = new OperonClient(
      createConfig({
        baseUrl: BASE_URL,
        tokenUrl: TOKEN_URL,
        clientId: 'client',
        clientSecret: 'secret',
        fetchImpl
      })
    );

    const headers = await client.generateSignatureHeaders({ foo: 'bar' });
    expect(headers['X-Operon-DID']).toBe('did:example:signer');
    expect(headers['X-Operon-Payload-Hash']).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(headers['X-Operon-Signature']).toBe('signed-value');
    expect(headers['X-Operon-Signature-KeyId']).toBe('did:example:signer#keys-1');
    expect(headers['X-Operon-Signature-Alg']).toBe('EdDSA');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  test('uses provided signature when self signing disabled', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: `header.${Buffer.from(JSON.stringify({})).toString('base64url')}.sig`,
          token_type: 'Bearer',
          expires_in: 300
        });
      }
      if (url === `${BASE_URL}/v1/channels/chnl-override/interactions`) {
        return buildResponse({
          interactions: [
            {
              id: 'int-manual',
              channelId: 'chnl-override',
              sourceParticipantId: 'part-1',
              targetParticipantId: 'part-2'
            }
          ],
          totalCount: 1,
          page: 1,
          pageSize: 50,
          hasMore: false
        });
      }
      if (url === `${BASE_URL}/v1/channels/chnl-override/participants`) {
        return buildResponse({
          participants: [
            { id: 'part-1', did: 'did:example:src' },
            { id: 'part-2', did: 'did:example:dst' }
          ],
          totalCount: 2,
          page: 1,
          pageSize: 50,
          hasMore: false
        });
      }
      if (url === `${BASE_URL}/v1/transactions`) {
        return buildResponse({
          id: 'txn-456',
          correlationId: 'corr-2',
          channelId: 'chnl-override',
          interactionId: 'int-manual',
          sourceDid: 'did:example:src',
          targetDid: 'did:example:dst',
          signature: { algorithm: 'EdDSA', value: 'manual', keyId: 'did:example:src#keys-1' },
          payloadHash: 'hash',
          status: 'PENDING',
          timestamp: '2025-01-01T00:00:00Z',
          createdAt: '2025-01-01T00:00:00Z',
          updatedAt: '2025-01-01T00:00:00Z'
        });
      }
      throw new Error(`unexpected fetch call to ${url}`);
    });

    const client = new OperonClient(
      createConfig({
        baseUrl: BASE_URL,
        tokenUrl: TOKEN_URL,
        clientId: 'client',
        clientSecret: 'secret',
        disableSelfSign: true,
        fetchImpl
      })
    );

    const result = await client.submitTransaction({
      correlationId: 'corr-2',
      channelId: 'chnl-override',
      interactionId: 'int-manual',
      sourceDid: 'did:example:src',
      targetDid: 'did:example:dst',
      payloadHash: 'existing-hash',
      signature: { algorithm: 'EdDSA', value: 'manual' }
    });

    expect(result.signature.value).toBe('manual');
    expect(fetchImpl).toHaveBeenCalledTimes(4);
  });
});
