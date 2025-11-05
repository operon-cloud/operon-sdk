# Submit a Transaction (Go SDK)

This guide walks through the end-to-end flow for submitting a signed transaction to the Operon Client API using the Go SDK. The same pattern underpins audit/event submissions for channel participants.

## Prerequisites

- Operon client credentials (Client ID + Client Secret) with permission to access the target channel.
- An interaction ID that binds the source and target participants for the transaction you want to post.
- Go 1.21+ installed locally.

## 1. Install the SDK

```bash
go get github.com/operon-cloud/operon-sdk/go@v1.0.0
```

## 2. Instantiate the client

```go
ctx := context.Background()

client, err := operon.NewClient(operon.Config{
    ClientID:         mustEnv("OPERON_CLIENT_ID"),
    ClientSecret:     mustEnv("OPERON_CLIENT_SECRET"),
    // Optional overrides:
    // BaseURL:  os.Getenv("OPERON_CLIENT_API_URL"),
    // TokenURL: os.Getenv("OPERON_TOKEN_URL"),
    // SigningAlgorithm: operon.AlgorithmES256,
})
if err != nil {
    log.Fatalf("build client: %v", err)
}
defer client.Close()

// Optional but recommended: warm catalogues and verify credentials.
if err := client.Init(ctx); err != nil {
    log.Fatalf("initialise client: %v", err)
}
```

`client.Init` proactively mints a Platform Access Token (PAT) and hydrates interaction/participant caches so later calls avoid extra round trips.

## 3. Prepare the transaction request

```go
req := operon.TransactionRequest{
    CorrelationID: "ext-123",         // caller-defined idempotency key
    InteractionID: "interaction-xyz", // binds channel + participants
    Label:         "Demo payload",
    Tags:          []string{"source:demo"},
    Payload:       []byte("... raw payload ..."),
    Timestamp:     time.Now().UTC(),  // optional; defaults to current UTC time
}
```

Key points:

- Provide either `Payload` (bytes) or `PayloadHash` (base64url SHA-256). The SDK calculates the hash locally when `Payload` is supplied and **only** transmits the hash to Operon; raw payload bytes never leave your service.
- When interaction metadata is cached, the SDK fills `ChannelID`, `SourceDID`, and `TargetDID` automatically. Provide them explicitly if you disable cache usage.
- `CorrelationID` enforces idempotency. Choose a deterministic value per logical transaction.

## 4. Submit the transaction

```go
txn, err := client.SubmitTransaction(ctx, req)
if err != nil {
    log.Fatalf("submit transaction: %v", err)
}

fmt.Printf("transaction ID: %s\n", txn.ID)
fmt.Printf("status: %s\n", txn.Status)
```

The SDK will:

1. Compute the payload’s SHA-256 hash locally (without sending the raw payload to Operon).
2. Call the managed signing endpoint (unless `DisableSelfSign` is set and you supply your own signature).
3. Populate missing interaction metadata using the warmed registry.
4. Submit the request to `/v1/transactions`.

The returned `Transaction` struct includes consensus metadata, timestamps, and signature details echoed from the platform.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `CorrelationID is required` | Request omitted `CorrelationID` | Provide a non-empty value |
| `interaction xyz not found` | Local cache stale | Call `client.Init` or re-run after `client.reloadReferenceData` logs refresh |
| `automatic signing disabled` | `DisableSelfSign` enabled without `Signature` provided | Either supply `Signature` manually or remove the flag |
| 401/403 responses | PAT missing scope or channel inactive | Verify credentials, channel status, and ensure PAT header is fresh |

## Next steps

- Use `client.Interactions(ctx)` to inspect available interactions and confirm the correct IDs.
- Call `client.Participants(ctx)` to correlate participant IDs with DIDs for advanced routing logic.
- Review the [Signing guide](signing.md) if you need to sign payloads for non-transaction requests.
