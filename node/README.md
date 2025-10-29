# Operon Node.js SDK

Enterprise-ready JavaScript/TypeScript client for the Operon platform. This SDK mirrors the ergonomics of the Go and Java packages while embracing modern Node.js conventions (ES modules, strict TypeScript typings, fetch-based networking).

## Compatibility

- **Node.js**: 20.x or 22.x LTS (uses the built-in Fetch API and `AbortController`)
- **TypeScript**: 5.8+

## Installation

```bash
npm install @operoncloud/operon-sdk
```

## Quick Start

```ts
import { OperonClient, createConfig } from '@operoncloud/operon-sdk';

const client = new OperonClient(createConfig({
  clientId: process.env.OPERON_CLIENT_ID!,
  clientSecret: process.env.OPERON_CLIENT_SECRET!,
  // Base URL / Token URL fall back to production endpoints; override for dev/qa when needed.
}));

await client.init();

const txn = await client.submitTransaction({
  correlationId: 'lead-abc',
  interactionId: 'int-123',
  payload: { leadId: 'lead-abc' },
});

console.log(txn.id, txn.status);
await client.close();
```

## Scripts

```bash
npm run lint   # ESLint (TypeScript aware)
npm test       # vitest unit tests
npm run build  # Type declarations + transpiled ESM output in dist/
```

## Folder Structure

```
node/
├── src/
│   ├── auth/           # Client credentials manager
│   ├── catalog/        # Reference data registry (interactions/participants)
│   ├── http/           # Fetch helpers with timeouts
│   ├── signing/        # Self-signing client
│   ├── config.ts       # Config validation + defaults
│   ├── client.ts       # High-level Operon client
│   ├── errors.ts       # SDK error hierarchy + API error decoder
│   ├── types.ts        # Shared interfaces (transactions, signatures, etc.)
│   └── index.ts        # Public exports
├── test/               # Vitest suites
├── package.json
├── tsconfig.json
└── README.md
```

## License

Apache-2.0 — see [LICENSE](../LICENSE).
