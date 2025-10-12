# Operon Go SDK (Preview)

The Operon Go SDK provides a lightweight client for machine-to-machine (M2M)
workloads that need to interact with the Operon Platform. This initial preview
focuses on two core capabilities:

1. Obtaining a Platform Access Token (PAT) using client-credentials (M2M).
2. Submitting transactions through the public Client API and receiving the
   resulting transaction record.

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
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"

    operon "github.com/operon-cloud/operon-sdk/go"
    "github.com/operon-cloud/operon-sdk/go/version"
)

func main() {
    client, err := operon.NewClient(operon.Config{
        ClientID:         mustEnv("OPERON_CLIENT_ID"),
        ClientSecret:     mustEnv("OPERON_CLIENT_SECRET"),
        SigningAlgorithm: operon.AlgorithmEd25519, // optional override
        // BaseURL and TokenURL are optional. Override if you target non-production environments:
        // BaseURL:  "https://api.dev.trustoperon.com/client-api",
        // TokenURL: "https://auth.dev.trustoperon.com/v1/session/m2m",
    })
    if err != nil {
        log.Fatalf("build client: %v", err)
    }
    defer client.Close()

    ctx := context.Background()

    // Optional but recommended: warm credentials and catalogues.
    if err := client.Init(ctx); err != nil {
        log.Fatalf("initialise client: %v", err)
    }

    // Inspect warmed interactions (optional helper).
    interactions, err := client.Interactions(ctx)
    if err != nil {
        log.Fatalf("list interactions: %v", err)
    }
    for _, intr := range interactions {
        log.Printf("interaction=%s channel=%s source=%s target=%s", intr.ID, intr.ChannelID, intr.SourceDID, intr.TargetDID)
    }

    req := operon.TransactionRequest{
        CorrelationID: "ext-123",         // client defined idempotency key
        InteractionID: "interaction-xyz", // workflow binding
        Label:         "Demo payload",
        Tags:          []string{"source:demo"},
        Payload:       []byte("... raw payload ..."),
        Timestamp:     time.Now().UTC(),
    }

    txn, err := client.SubmitTransaction(ctx, req)
    if err != nil {
        log.Fatalf("submit transaction: %v", err)
    }

    fmt.Println("transaction ID:", txn.ID)
    fmt.Println("sdk version:", version.String())
}

func mustEnv(key string) string {
    v := os.Getenv(key)
    if v == "" {
        log.Fatalf("missing environment variable %s", key)
    }
    return v
}
```


### Notes

- `SubmitTransaction` automatically base64-encodes payload bytes, calculates the
  SHA-256 digest (base64url), and injects an RFC3339 timestamp when one is not
  supplied.
- Prefer `Payload` for convenience; set `PayloadHash` (and leave `Payload` empty)
  when you want to keep raw data off-platform.
- BaseURL and TokenURL default to the production endpoints; override them if you
  need to target dev/QA hosts.
- Tokens are cached and refreshed automatically using the `expires_in` value
  returned by the identity broker.
- Set `Label` and `Tags` to describe the transaction payload (tags are sent verbatim and remain queryable through Operon analytics tooling).
- If you omit `SourceDID`, `TargetDID`, or `ChannelID`, call `client.Init(ctx)`
  (or rely on the lazy initialisation performed on first submission) so the SDK
  can fetch the interaction catalogue and fill those fields automatically.
- Use `client.Interactions(ctx)` and `client.Participants(ctx)` to retrieve the
  warmed catalogues; the SDK returns copies so you can safely iterate or log
  them without mutating internal cache.
- With self-signing enabled (default), the SDK calls Operon’s DID service to produce signatures and derive key IDs automatically. Set `DisableSelfSign` when providing your own signatures.
- Override `SigningAlgorithm` if you need to request alternate signature
  algorithms once additional options are available.
- Inject a custom `HTTPClient` (implementing the `Do(*http.Request)` contract)
  when you need advanced behaviours such as retries, circuit-breaking, or
  observability instrumentation.
- The exported `version.String()` helper reports the embedded semantic version;
  override it during builds with `-ldflags "-X github.com/operon-cloud/operon-sdk/go/version.buildVersion=v1.0.0"` to keep binaries aligned with release tags.

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
