import { describe, expect, test, vi } from 'vitest';

import {
  fetchWorkstreamInteractions,
  signHashWithPAT,
  submitTransactionWithPAT,
  validateSignatureWithPAT,
  validateSession
} from '../src/index.js';
import {
  HEADER_OPERON_DID,
  HEADER_OPERON_PAYLOAD_HASH,
  HEADER_OPERON_SIGNATURE,
  HEADER_OPERON_SIGNATURE_ALGO,
  HEADER_OPERON_SIGNATURE_KEY
} from '../src/transactions.js';

const BASE_URL = 'https://api.example.com/client-api';

function buildResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function buildToken(claims: Record<string, unknown>): string {
  return `header.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;
}

describe('PAT and Session helpers', () => {
  test('signHashWithPAT sets default keyId from claims', async () => {
    const pat = buildToken({ participant_did: 'did:test:source' });

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === `${BASE_URL}/v1/dids/self/sign`) {
        return buildResponse({
          signature: {
            algorithm: 'EdDSA',
            value: 'signed',
            keyId: ''
          }
        });
      }
      throw new Error(`unexpected fetch call to ${url}`);
    });

    const signature = await signHashWithPAT(
      { baseUrl: BASE_URL, fetchImpl },
      pat,
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'EdDSA'
    );

    expect(signature.keyId).toBe('did:test:source#keys-1');
  });

  test('submitTransactionWithPAT uses claim defaults', async () => {
    const pat = buildToken({ participant_did: 'did:test:source', workstream_id: 'wstr-123' });

    const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === `${BASE_URL}/v1/transactions`) {
        const body = JSON.parse((init?.body as string) || '{}');
        expect(body.workstreamId).toBe('wstr-123');
        expect(body.sourceDid).toBe('did:test:source');

        return buildResponse({
          id: 'txn-1',
          correlationId: body.correlationId,
          workstreamId: body.workstreamId,
          interactionId: body.interactionId,
          sourceDid: body.sourceDid,
          targetDid: body.targetDid,
          signature: body.signature,
          payloadHash: body.payloadHash,
          status: 'received',
          timestamp: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        });
      }
      throw new Error(`unexpected fetch call to ${url}`);
    });

    const txn = await submitTransactionWithPAT(
      { baseUrl: BASE_URL, fetchImpl },
      pat,
      {
        correlationId: 'corr-1',
        interactionId: 'int-1',
        payload: 'hello',
        targetDid: 'did:test:target',
        signature: { algorithm: 'EdDSA', value: 'manual', keyId: 'did:test:source#keys-1' }
      }
    );

    expect(txn.id).toBe('txn-1');
  });

  test('fetchWorkstreamInteractions supports explicit override', async () => {
    const pat = buildToken({ participant_did: 'did:test:source' });

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === `${BASE_URL}/v1/workstreams/wstr-override/interactions`) {
        return buildResponse({
          interactions: [{ id: 'int-1', workstreamId: 'wstr-override' }],
          totalCount: 1,
          page: 1,
          pageSize: 1000,
          hasMore: false
        });
      }
      throw new Error(`unexpected fetch call to ${url}`);
    });

    const response = await fetchWorkstreamInteractions(
      { baseUrl: BASE_URL, fetchImpl },
      pat,
      'wstr-override'
    );

    expect(response.interactions).toHaveLength(1);
    expect(response.interactions[0].id).toBe('int-1');
  });

  test('validateSignatureWithPAT rejects payload hash mismatch', async () => {
    const pat = buildToken({ participant_did: 'did:test:source' });

    await expect(
      validateSignatureWithPAT(
        { baseUrl: BASE_URL, fetchImpl: vi.fn() },
        pat,
        Buffer.from('payload', 'utf-8'),
        {
          [HEADER_OPERON_DID]: 'did:test:source',
          [HEADER_OPERON_PAYLOAD_HASH]: 'mismatch',
          [HEADER_OPERON_SIGNATURE]: 'sig',
          [HEADER_OPERON_SIGNATURE_KEY]: 'did:test:source#keys-1',
          [HEADER_OPERON_SIGNATURE_ALGO]: 'EdDSA'
        }
      )
    ).rejects.toThrow('payload hash mismatch');
  });

  test('validateSession returns normalized session info', async () => {
    const exp = Math.floor(Date.now() / 1000) + 600;
    const pat = buildToken({
      participant_did: 'did:test:source',
      participant_id: 'part-1',
      workstream_id: 'wstr-1',
      workspace_id: 'wksp-1',
      session_id: 'sess-1',
      client_id: 'client-1',
      exp
    });

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url === `${BASE_URL}/v1/session/validate`) {
        return buildResponse({
          user_id: 'user-1',
          email: 'user@example.com',
          name: 'User',
          customer_id: 'cust-1',
          roles: ['sandbox'],
          feature_flags: { demo: true }
        });
      }
      throw new Error(`unexpected fetch call to ${url}`);
    });

    const info = await validateSession({ baseUrl: BASE_URL, fetchImpl }, pat);

    expect(info.userId).toBe('user-1');
    expect(info.workstreamId).toBe('wstr-1');
    expect(info.channelId).toBe('wstr-1');
    expect(info.participantDid).toBe('did:test:source');
    expect(info.clientId).toBe('client-1');
    expect((info.expiresInSeconds ?? 0) > 0).toBe(true);
  });
});
