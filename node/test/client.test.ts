import { afterEach, describe, expect, test, vi } from 'vitest';

import { OperonClient } from '../src/client.js';
import { createConfig } from '../src/config.js';
import {
  HEADER_OPERON_DID,
  HEADER_OPERON_PAYLOAD_HASH,
  HEADER_OPERON_SIGNATURE,
  HEADER_OPERON_SIGNATURE_ALGO,
  HEADER_OPERON_SIGNATURE_KEY
} from '../src/transactions.js';

const BASE_URL = 'https://api.example.com/client-api';
const TOKEN_URL = 'https://auth.example.com/oauth/token';

function buildResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function buildToken(claims: Record<string, unknown>): string {
  return `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;
}

describe('OperonClient', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('submits transaction with self-signing and actor/assignee fields', async () => {
    const fetchCalls: Array<{ url: string; init?: RequestInit }> = [];
    const interactions = [
      {
        id: 'int-123',
        workstreamId: 'wstr-1',
        sourceParticipantId: 'part-1',
        targetParticipantId: 'part-2'
      }
    ];
    const participants = [
      { id: 'part-1', did: 'did:example:source' },
      { id: 'part-2', did: 'did:example:target' }
    ];

    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      fetchCalls.push({ url, init });

      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: buildToken({ participant_did: 'did:example:cached', workstream_id: 'wstr-1' }),
          token_type: 'Bearer',
          expires_in: 300
        });
      }

      if (url === `${BASE_URL}/v1/interactions`) {
        return buildResponse({ data: interactions });
      }

      if (url === `${BASE_URL}/v1/participants`) {
        return buildResponse({ data: participants });
      }

      if (url === `${BASE_URL}/v1/dids/self/sign`) {
        return buildResponse({
          signature: {
            algorithm: 'EdDSA',
            value: 'signed-value',
            keyId: ''
          }
        });
      }

      if (url === `${BASE_URL}/v1/transactions`) {
        const body = init?.body ? JSON.parse(init.body as string) : {};
        expect(body.workstreamId).toBe('wstr-1');
        expect(body.sourceDid).toBe('did:example:source');
        expect(body.targetDid).toBe('did:example:target');
        expect(body.actorExternalId).toBe('agent-1');
        expect(body.actorExternalDisplayName).toBe('Agent One');
        expect(body.actorExternalSource).toBe('crm');
        expect(body.assigneeExternalId).toBe('owner-2');
        expect(body.assigneeExternalDisplayName).toBe('Owner Two');
        expect(body.assigneeExternalSource).toBe('crm');

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
      payload: { foo: 'bar' },
      actorExternalId: 'agent-1',
      actorExternalDisplayName: 'Agent One',
      actorExternalSource: 'crm',
      assigneeExternalId: 'owner-2',
      assigneeExternalDisplayName: 'Owner Two',
      assigneeExternalSource: 'crm'
    });

    expect(result.id).toBe('txn-123');
    expect(result.signature.value).toBe('signed-value');
    expect(result.signature.keyId).toBe('did:example:source#keys-1');
    expect(fetchImpl).toHaveBeenCalledTimes(5);

    const transactionCall = fetchCalls.find((call) => call.url.endsWith('/v1/transactions'));
    expect(transactionCall).toBeDefined();
    const requestBody = JSON.parse(transactionCall!.init!.body as string) as Record<string, unknown>;
    expect(requestBody.payloadData).toBeUndefined();
    expect(requestBody.payloadHash).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test('uses provided signature when self signing disabled with channel alias', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: buildToken({}),
          token_type: 'Bearer',
          expires_in: 300
        });
      }
      if (url === `${BASE_URL}/v1/interactions`) {
        return buildResponse({
          data: [
            {
              id: 'int-manual',
              workstreamId: 'wstr-override',
              sourceParticipantId: 'part-1',
              targetParticipantId: 'part-2'
            }
          ]
        });
      }
      if (url === `${BASE_URL}/v1/participants`) {
        return buildResponse({
          data: [
            { id: 'part-1', did: 'did:example:src' },
            { id: 'part-2', did: 'did:example:dst' }
          ]
        });
      }
      if (url === `${BASE_URL}/v1/transactions`) {
        const body = JSON.parse((init?.body as string) || '{}');
        expect(body.workstreamId).toBe('wstr-override');
        return buildResponse({
          id: 'txn-456',
          correlationId: 'corr-2',
          workstreamId: 'wstr-override',
          interactionId: 'int-manual',
          sourceDid: 'did:example:src',
          targetDid: 'did:example:dst',
          signature: { algorithm: 'EdDSA', value: 'manual', keyId: 'did:example:src#keys-1' },
          payloadHash: body.payloadHash,
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
      channelId: 'wstr-override',
      interactionId: 'int-manual',
      sourceDid: 'did:example:src',
      targetDid: 'did:example:dst',
      payloadHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      signature: { algorithm: 'EdDSA', value: 'manual' }
    });

    expect(result.signature.value).toBe('manual');
    expect(result.workstreamId).toBe('wstr-override');
    expect(result.channelId).toBe('wstr-override');
    expect(fetchImpl).toHaveBeenCalledTimes(4);
  });

  test('generates and validates Operon signature headers', async () => {
    const payload = Buffer.from('{"demo":true}', 'utf-8');

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: buildToken({ participant_did: 'did:example:signer', workstream_id: 'wstr-sign' }),
          token_type: 'Bearer',
          expires_in: 300
        });
      }

      if (url === `${BASE_URL}/v1/dids/self/sign`) {
        return buildResponse({
          signature: {
            algorithm: 'ES256',
            value: 'signed-value',
            keyId: 'did:example:signer#keys-1'
          }
        });
      }

      if (url === `${BASE_URL}/v1/dids/did%3Aexample%3Asigner/signature/verify`) {
        return buildResponse({
          status: 'VALID',
          message: 'ok',
          did: 'did:example:signer',
          payloadHash: 'placeholder',
          algorithm: 'ES256',
          keyId: 'did:example:signer#keys-1'
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
        signingAlgorithm: 'ES256',
        fetchImpl
      })
    );

    const headers = await client.generateSignatureHeaders(payload);
    expect(headers[HEADER_OPERON_DID]).toBe('did:example:signer');
    expect(headers[HEADER_OPERON_PAYLOAD_HASH]).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(headers[HEADER_OPERON_SIGNATURE]).toBe('signed-value');
    expect(headers[HEADER_OPERON_SIGNATURE_KEY]).toBe('did:example:signer#keys-1');
    expect(headers[HEADER_OPERON_SIGNATURE_ALGO]).toBe('ES256');

    const result = await client.validateSignatureHeaders(payload, headers);
    expect(result.status).toBe('VALID');
  });

  test('validateSignatureHeaders rejects payload hash mismatch', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: buildToken({ participant_did: 'did:example:signer' }),
          token_type: 'Bearer',
          expires_in: 300
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

    await expect(
      client.validateSignatureHeaders(Buffer.from('payload', 'utf-8'), {
        [HEADER_OPERON_DID]: 'did:example:signer',
        [HEADER_OPERON_PAYLOAD_HASH]: 'mismatch',
        [HEADER_OPERON_SIGNATURE]: 'sig',
        [HEADER_OPERON_SIGNATURE_KEY]: 'did:example:signer#keys-1',
        [HEADER_OPERON_SIGNATURE_ALGO]: 'EdDSA'
      })
    ).rejects.toThrow('payload hash mismatch');
  });

  test('getWorkstreamInteractions uses token-scoped workstream by default', async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === TOKEN_URL) {
        return buildResponse({
          access_token: buildToken({ participant_did: 'did:example:source', workstream_id: 'wstr-abc' }),
          token_type: 'Bearer',
          expires_in: 300
        });
      }
      if (url === `${BASE_URL}/v1/workstreams/wstr-abc/interactions`) {
        return buildResponse({
          interactions: [{ id: 'int-1', workstreamId: 'wstr-abc' }],
          totalCount: 1,
          page: 1,
          pageSize: 1000,
          hasMore: false
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

    const response = await client.getWorkstreamInteractions();
    expect(response.interactions).toHaveLength(1);
    expect(response.interactions[0].id).toBe('int-1');
  });

  test('heartbeat forces token refresh when unauthorized', async () => {
    const heartbeatUrl = `${BASE_URL}/v1/session/heartbeat`;
    let tokenCounter = 0;
    let heartbeatCalls = 0;

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url === TOKEN_URL) {
        tokenCounter += 1;
        return buildResponse({
          access_token: `header.${Buffer.from(JSON.stringify({})).toString('base64url')}.${tokenCounter}`,
          token_type: 'Bearer',
          expires_in: 60
        });
      }

      if (url === heartbeatUrl) {
        heartbeatCalls += 1;
        const status = heartbeatCalls === 1 ? 401 : 200;
        return new Response('{}', { status, headers: { 'Content-Type': 'application/json' } });
      }

      return buildResponse({});
    });

    const client = new OperonClient(
      createConfig({
        baseUrl: BASE_URL,
        tokenUrl: TOKEN_URL,
        clientId: 'client',
        clientSecret: 'secret',
        fetchImpl,
        sessionHeartbeatIntervalMs: 25,
        sessionHeartbeatTimeoutMs: 200
      })
    );

    await client.init();
    await new Promise((resolve) => setTimeout(resolve, 60));
    await client.close();

    const heartbeatHits = fetchImpl.mock.calls.filter(
      ([input]) =>
        (typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url) ===
        heartbeatUrl
    );
    expect(heartbeatHits.length).toBeGreaterThanOrEqual(1);

    const tokenHits = fetchImpl.mock.calls.filter(
      ([input]) =>
        (typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url) ===
        TOKEN_URL
    );
    expect(tokenHits.length).toBeGreaterThanOrEqual(2);
  });
});
