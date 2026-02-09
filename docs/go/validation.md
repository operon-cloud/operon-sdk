# Validate Incoming API Call Signatures

Use this guide when you receive an Operon-signed request and need to confirm the headers match the payload before processing it. The SDK delegates validation to the Operon Client API so you never handle private signing keys.

## Prerequisites

- Your service authenticates to Operon with its own client credentials (Client ID/Secret).
- The incoming request includes the Operon headers `X-Operon-*` alongside the payload.
- You can read the payload body as bytes for revalidation.

## 1. Capture the payload and headers

```go
payload, err := io.ReadAll(r.Body)
if err != nil {
    return fmt.Errorf("read body: %w", err)
}

defer r.Body.Close()

headers := operon.OperonHeaders{
    operon.HeaderOperonDID:           r.Header.Get(operon.HeaderOperonDID),
    operon.HeaderOperonPayloadHash:   r.Header.Get(operon.HeaderOperonPayloadHash),
    operon.HeaderOperonSignature:     r.Header.Get(operon.HeaderOperonSignature),
    operon.HeaderOperonSignatureKey:  r.Header.Get(operon.HeaderOperonSignatureKey),
    operon.HeaderOperonSignatureAlgo: r.Header.Get(operon.HeaderOperonSignatureAlgo),
}
```

## 2. Initialise the SDK client (if not already)

```go
client, err := operon.NewClient(operon.Config{
    ClientID:     os.Getenv("OPERON_CLIENT_ID"),
    ClientSecret: os.Getenv("OPERON_CLIENT_SECRET"),
})
if err != nil {
    return fmt.Errorf("build client: %w", err)
}

defer client.Close()

if err := client.Init(r.Context()); err != nil {
    return fmt.Errorf("init client: %w", err)
}
```

## 3. Validate the signature

```go
result, err := client.ValidateSignatureHeaders(r.Context(), payload, headers)
if err != nil {
    return fmt.Errorf("validate signature: %w", err)
}

log.Printf("signature status=%s did=%s key=%s", result.Status, result.DID, result.KeyID)
```

On success the method returns details about the signing DID, algorithm, and key. If the payload hash or signature values are incorrect, you receive an error and the request should be rejected.

## Convenience helpers

For textual bodies use `ValidateSignatureHeadersFromString(ctx, stringBody, headers)`, which delegates to `ValidateSignatureHeaders` using UTF-8 bytes from the provided string.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `header X-Operon-... is required` | A header was missing or empty | Ensure you forward all five Operon headers exactly as received |
| `payload hash mismatch` | Payload mutated after signing | Do not modify the body before calling validation |
| 401/403 responses | PAT missing scope or expired | Confirm the receiving service has the correct client credentials |

## Related scenarios

- [Sign outgoing API calls](signing.md) — use this when you need to originate Operon-signed requests.
- [Submit a transaction](transactions.md) — batch or audit submissions that also leverage managed signing.
