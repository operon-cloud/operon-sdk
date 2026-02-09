# Operon Node.js SDK

Enterprise-ready JavaScript/TypeScript client for the [Operon.Cloud](https://www.operon.cloud) platform.

## Compatibility

- Node.js: 20.x or 22.x LTS
- TypeScript: 5.8+

## Installation

```bash
npm install @operoncloud/operon-sdk@1.3.0
```

## Quick Start

```ts
import { OperonClient, createConfig } from '@operoncloud/operon-sdk';

const client = new OperonClient(
  createConfig({
    clientId: process.env.OPERON_CLIENT_ID!,
    clientSecret: process.env.OPERON_CLIENT_SECRET!
  })
);

await client.init();

const txn = await client.submitTransaction({
  correlationId: 'lead-abc',
  interactionId: 'int-123',
  payload: { leadId: 'lead-abc' },
  state: 'Qualified',
  actorExternalId: 'agent-12',
  actorExternalDisplayName: 'Agent 12',
  actorExternalSource: 'crm',
  assigneeExternalId: 'owner-2',
  assigneeExternalDisplayName: 'Owner Two',
  assigneeExternalSource: 'crm'
});

console.log(txn.id, txn.status, txn.workstreamId);
await client.close();
```

`payload` is hashed client-side (`SHA-256`) and only `payloadHash` is sent to Operon.

## Workstream Data APIs

```ts
const workstream = await client.getWorkstream();
const interactions = await client.getWorkstreamInteractions();
const participants = await client.getWorkstreamParticipants();
```

## Signature APIs

```ts
const headers = await client.generateSignatureHeaders(JSON.stringify(body), 'ES256');

const result = await client.validateSignatureHeaders(
  JSON.stringify(body),
  headers
);
```

## PAT and Session Helpers

The SDK includes PAT-only utilities when you already have a Personal Access Token.

```ts
import {
  signHashWithPAT,
  submitTransactionWithPAT,
  fetchWorkstreamInteractions,
  validateSignatureWithPAT,
  validateSession
} from '@operoncloud/operon-sdk';
```

These helpers match the Go/Python/Java v1.3.0 surface for signing, submission, workstream fetches, signature validation, and PAT session validation.

## Legacy Channel Compatibility

`channelId` is retained as a compatibility alias for `workstreamId` in request/response models and token claims.

## Scripts

```bash
npm run lint
npm test
npm run build
```

## License

Apache-2.0 — see [LICENSE](../LICENSE).
