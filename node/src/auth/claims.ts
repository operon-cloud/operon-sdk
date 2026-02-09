import type { TokenClaims } from '../types.js';

export function decodeTokenClaims(token: string): TokenClaims {
  const parts = token.split('.');
  if (parts.length < 2) {
    return {};
  }

  try {
    const payloadSegment = base64UrlDecode(parts[1]);
    const payload = JSON.parse(payloadSegment.toString('utf-8')) as Record<string, unknown>;

    const workstream = readString(payload, 'workstream_id') ?? readString(payload, 'channel_id');
    const expiresAtUnix = readNumber(payload, 'exp');

    return {
      participantDid: readString(payload, 'participant_did'),
      workstreamId: workstream,
      channelId: workstream,
      customerId: readString(payload, 'customer_id'),
      workspaceId: readString(payload, 'workspace_id'),
      email: readString(payload, 'email'),
      name: readString(payload, 'name'),
      tenantIds: readStringArray(payload, 'tenant_ids'),
      roles: readStringArray(payload, 'roles'),
      memberId: readString(payload, 'member_id'),
      sessionId: readString(payload, 'session_id'),
      orgId: readString(payload, 'org_id'),
      participantId: readString(payload, 'participant_id'),
      clientId: readString(payload, 'client_id'),
      authorizedParty: readString(payload, 'azp'),
      expiresAtUnix
    };
  } catch {
    return {};
  }
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

  try {
    return Buffer.from(input, 'base64');
  } catch {
    return Buffer.from(segment, 'base64');
  }
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

function readNumber(source: Record<string, unknown>, key: string): number | undefined {
  const value = source[key];
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  return undefined;
}
