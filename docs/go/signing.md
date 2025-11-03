# Sign Outgoing API Calls

Some Operon endpoints require callers to include signed headers that prove payload integrity (`ID.Operon` flows, partner integrations, etc.). The Go SDK exposes helpers that delegate signing to the platform so secrets never leave the service boundary.

## Prerequisites

- The Operon client must be allowed to sign using its participant DID.
- Self-signing must be enabled (default). If you set `DisableSelfSign`, re-enable it or provide your own signatures.
- The request body you plan to send to the downstream API.

## 1. Create and initialise the client

```go
ctx := context.Background()

client, err := operon.NewClient(operon.Config{
    ClientID:     os.Getenv("OPERON_CLIENT_ID"),
    ClientSecret: os.Getenv("OPERON_CLIENT_SECRET"),
    // Optional: default algorithm for signing helpers.
    SigningAlgorithm: operon.AlgorithmES256,
})
if err != nil {
    log.Fatalf("build client: %v", err)
}
defer client.Close()

if err := client.Init(ctx); err != nil {
    log.Fatalf("initialise client: %v", err)
}
```

`client.Init` ensures the Platform Access Token on the SDK instance carries the participant DID needed for header generation.

## 2. Generate headers from bytes

```go
payload := []byte(`{"op":"demo"}`)

headers, err := client.GenerateSignatureHeaders(ctx, payload, "")
if err != nil {
    log.Fatalf("sign payload: %v", err)
}
```

Passing an empty algorithm string uses the default configured in `Config.SigningAlgorithm`. Provide `operon.AlgorithmEd25519`, `operon.AlgorithmES256`, or `operon.AlgorithmES256K` to override per-call.

The helper returns a `map[string]string` with these keys:

- `operon.HeaderOperonDID`
- `operon.HeaderOperonPayloadHash`
- `operon.HeaderOperonSignature`
- `operon.HeaderOperonSignatureKey`
- `operon.HeaderOperonSignatureAlgo`

## 3. Attach headers to your outbound request

```go
req, err := http.NewRequest(http.MethodPost, downstreamURL, bytes.NewReader(payload))
if err != nil {
    log.Fatalf("build request: %v", err)
}

for key, value := range headers {
    req.Header.Set(key, value)
}

// Example: call the API using your own http.Client implementation.
resp, err := http.DefaultClient.Do(req)
if err != nil {
    log.Fatalf("call API: %v", err)
}
defer resp.Body.Close()
```

With these headers the receiving participant (or any Operon-compatible verifier) can validate the signature via the DID service.

## Working with strings

Use `GenerateSignatureHeadersFromString` when you already have a UTF-8 payload:

```go
headers, err := client.GenerateSignatureHeadersFromString(ctx, `{"geo":"us"}`, operon.AlgorithmES256K)
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `automatic signing disabled` | `DisableSelfSign` set in config | Enable self-signing or call your own signing service |
| `participant DID unavailable on access token` | PAT does not include participant claims (Init not called, or credentials missing DID) | Call `client.Init` and verify the client’s role |
| 401 from `/v1/dids/self/sign` | Token expired or lacks scope | Ensure the SDK can refresh tokens; check IAM bindings |

## Related docs

- [Submit a transaction](transactions.md) — automatically signs and posts to `/v1/transactions`.
- [Operon platform docs](https://www.operon.cloud/developers) — broader API references.
