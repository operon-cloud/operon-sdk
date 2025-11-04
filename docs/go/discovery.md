# Channel Discovery Helpers (Preview)

> **Prerequisite:** Complete the [Quick Start](../../go/README.md#quick-start) to configure the Go SDK client.

Many Operon workloads, including sandbox-api, need to understand which interactions and participants are available to the authenticated channel. The Go SDK now exposes convenience helpers that wrap the client API so your service does not have to craft raw HTTP requests.

## Fetch channel interactions

```go
ctx := context.Background()

// Uses the channel bound to the PAT by default.
resp, err := client.GetChannelInteractions(ctx)
if err != nil {
    log.Fatalf("load interactions: %v", err)
}

for _, interaction := range resp.Interactions {
    log.Printf("%s (%s ➜ %s)", interaction.ID, interaction.SourceParticipantID, interaction.TargetParticipantID)
}
```

If your credentials are scoped to multiple channels, provide an override:

```go
resp, err := client.GetChannelInteractions(ctx, "chnl-123")
```

The response mirrors `GET /v1/channels/{channelId}/interactions` from the client API and includes pagination fields should you need them (`totalCount`, `page`, `pageSize`, `hasMore`).

## Fetch channel participants

```go
resp, err := client.GetChannelParticipants(ctx)
if err != nil {
    log.Fatalf("load participants: %v", err)
}

for _, participant := range resp.Participants {
    log.Printf("%s (%s)", participant.ID, participant.DID)
}
```

As with interactions, optional overrides let you query a different channel:

```go
resp, err := client.GetChannelParticipants(ctx, "chnl-123")
```

Both helpers infer the PAT to send on the request, handle API error decoding, and keep the SDK’s channel cache consistent. This keeps your service fully SDK-driven while aligning with Operon’s auth standards.
