# Workstream Discovery Helpers (Preview)

> **Prerequisite:** Complete the [Quick Start](../../go/README.md#quick-start) to configure the Go SDK client.

Many Operon workloads, including sandbox-api, need to understand which interactions and participants are available to the authenticated workstream. The Go SDK now exposes convenience helpers that wrap the client API so your service does not have to craft raw HTTP requests.

## Fetch workstream interactions

```go
ctx := context.Background()

// Uses the workstream bound to the PAT by default.
resp, err := client.GetWorkstreamInteractions(ctx)
if err != nil {
    log.Fatalf("load interactions: %v", err)
}

for _, interaction := range resp.Interactions {
    log.Printf("%s (%s ➜ %s)", interaction.ID, interaction.SourceParticipantID, interaction.TargetParticipantID)
}
```

Interactions may include workstream analytics metadata like `states`, `roiClassification`, `roiCost`, and `roiTime`. These fields surface in `WorkstreamInteraction` and are passed through when caching catalog data.

If your credentials are scoped to multiple workstreams, provide an override:

```go
resp, err := client.GetWorkstreamInteractions(ctx, "wstr-123")
```

The response mirrors `GET /v1/workstreams/{workstreamId}/interactions` from the client API and includes pagination fields should you need them (`totalCount`, `page`, `pageSize`, `hasMore`).

Server-side components that already hold a PAT (for example, sandbox-api after login) can stay SDK-only as well:

```go
cfg := operon.WorkstreamDataConfig{
    BaseURL:    "https://api.operon.cloud/client-api",
    HTTPClient: http.DefaultClient,
}

resp, err := operon.FetchWorkstreamInteractions(ctx, cfg, patFromCookie)
```

## Fetch workstream details

```go
workstream, err := client.GetWorkstream(ctx)
if err != nil {
    log.Fatalf("load workstream: %v", err)
}

log.Printf("%s (%s)", workstream.ID, workstream.Status)
```

The response includes status, mode, and state configuration so you can validate
transaction state values before submitting new payloads.

The PAT-based helper mirrors the same flow:

```go
workstream, err := operon.FetchWorkstream(ctx, cfg, patFromCookie)
if err != nil {
    log.Fatalf("load workstream: %v", err)
}
```

## Fetch workstream participants

```go
resp, err := client.GetWorkstreamParticipants(ctx)
if err != nil {
    log.Fatalf("load participants: %v", err)
}

for _, participant := range resp.Participants {
    log.Printf("%s (%s)", participant.ID, participant.DID)
}
```

As with interactions, optional overrides let you query a different workstream:

```go
resp, err := client.GetWorkstreamParticipants(ctx, "wstr-123")
```

Both helpers infer the PAT to send on the request, handle API error decoding, and keep the SDK’s workstream cache consistent. This keeps your service fully SDK-driven while aligning with Operon’s auth standards.

And the PAT-centric helper mirrors the interactions example:

```go
resp, err := operon.FetchWorkstreamParticipants(ctx, cfg, patFromCookie)
```

## Sign payload hashes with a PAT

```go
cfg := operon.ClientAPIConfig{
    BaseURL:    "https://api.operon.cloud/client-api",
    HTTPClient: http.DefaultClient,
}

signature, err := operon.SignHashWithPAT(ctx, cfg, patFromCookie, payloadHash, "ES256")
if err != nil {
    log.Fatalf("sign payload: %v", err)
}

log.Printf("signature %s via %s", signature.Value, signature.Algorithm)
```

## Submit transactions with a PAT

```go
bytes, err := operon.DecodePayloadBase64(payloadDataB64)
if err != nil {
    log.Fatalf("decode payload: %v", err)
}

req := operon.TransactionRequest{
    CorrelationID: correlationID,
    WorkstreamID:  workstreamID,
    InteractionID: interactionID,
    Timestamp:     time.Now().UTC(),
    SourceDID:     sourceDID,
    TargetDID:     targetDID,
    Signature:     signature,
    Payload:       bytes,
    PayloadHash:   payloadHash,
}

transaction, err := operon.SubmitTransactionWithPAT(ctx, cfg, patFromCookie, req)
if err != nil {
    log.Fatalf("submit transaction: %v", err)
}

log.Printf("transaction stored as %s", transaction.ID)
```
