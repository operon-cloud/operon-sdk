# Operon Go SDK (Preview)

The Operon Go SDK provides a lightweight client for machine-to-machine (M2M)
workloads that need to interact with the Operon Platform. This initial preview
focuses on four core capabilities:

1. Obtaining a Platform Access Token (PAT) using client-credentials (M2M).
2. Submitting transactions through the public Client API and receiving the
   resulting transaction record.
3. Discovering channel interactions and participants without leaving the SDK.
4. Generating and validating Operon signature headers for outbound and inbound
   API calls (ID.Operon flows).

> **Status:** Preview – APIs are subject to change while the platform’s public
> surface stabilises. Please pin explicit versions and share feedback.

## Architecture Overview

The SDK is intentionally modular so that transport, authentication, and domain
expansions can evolve independently:

- `operon`: public entry point exposing `Client`, domain models, and helpers.
- `internal/auth`: client-credential token minting with proactive refresh and
  participant DID extraction.
- `internal/catalog`: thread-safe caches for interactions and participants.
- `internal/httpx`: minimal HTTP utility helpers to keep the transport swappable.
- `internal/signing`: pluggable self-signing implementation with a disabled
  variant when callers supply their own signatures.
- `version`: exposes the SDK semantic version via `version.String()`, which can
  be overridden at build time with Go ldflags for CI-driven releases.

This layout keeps the surface area easy to reason about while giving room for
future features such as retries, tracing, or additional resource clients.

## Installation

```bash
go get github.com/operon-cloud/operon-sdk/go@v1.0.0
```

## Quick Start

```go
ctx := context.Background()

client, err := operon.NewClient(operon.Config{
    ClientID:     os.Getenv("OPERON_CLIENT_ID"),
    ClientSecret: os.Getenv("OPERON_CLIENT_SECRET"),
})
if err != nil {
    log.Fatalf("build client: %v", err)
}
defer client.Close()

if err := client.Init(ctx); err != nil {
    log.Fatalf("initialise client: %v", err)
}
```

With an initialised client you can choose the scenario that matches your workload:

- [Submit a transaction to the Client API](../docs/go/transactions.md)
  - Learn how to construct a `TransactionRequest`, leverage interaction discovery, and handle common response codes.
- [Discover channel interactions and participants](../docs/go/discovery.md)
  - Load the authenticated channel’s catalogue via the SDK client or call helper functions that operate directly on the PAT you already have.
- [Sign outgoing API calls](../docs/go/signing.md)
  - Shows how to request managed signatures, assemble the required Operon headers, and attach them to any HTTP request.
- [Validate incoming API call signatures](../docs/go/validation.md)
  - Walks through capturing headers, verifying the payload hash, and invoking the verification endpoint (with automatic fallback).

Both guides include full code samples, error-handling tips, and troubleshooting checklists.

## Error handling

The SDK returns `*operon.APIError` for structured API failures:

```go
if err != nil {
    if apiErr, ok := err.(*operon.APIError); ok {
        log.Printf("operon error (%d / %s): %s", apiErr.StatusCode, apiErr.Code, apiErr.Message)
    }
}
```

## Testing

```bash
go test ./...
```

## Roadmap

- Idiomatic helpers for signing payloads (Ed25519 and ECDSA).
- Channel + interaction discovery helpers.
- Richer transaction lifecycle APIs (status polling, history).

Feedback and pull requests are welcome while we shape the public SDK surface.

—

Part of the [Operon.Cloud](https://www.operon.cloud) developer platform. Explore more SDKs and resources at https://www.operon.cloud/developers
