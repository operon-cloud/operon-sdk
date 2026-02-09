# Operon .NET SDK

Modern .NET client (targeting **.NET 8**) for interacting with [Operon.Cloud](https://www.operon.cloud) services.

## Installation

```bash
dotnet add package Operon.Sdk --version 1.3.0
```

## Quick Start

```csharp
using Operon.Sdk;
using Operon.Sdk.Models;
using System.Text.Json;

var config = new OperonConfig(
    clientId: Environment.GetEnvironmentVariable("OPERON_CLIENT_ID")!,
    clientSecret: Environment.GetEnvironmentVariable("OPERON_CLIENT_SECRET")!
);

await using var client = new OperonClient(config);
await client.InitAsync();

var transaction = await client.SubmitTransactionAsync(new TransactionRequest
{
    CorrelationId = "corr-123",
    InteractionId = "int-abc",
    PayloadBytes = JsonSerializer.SerializeToUtf8Bytes(new { foo = "bar" }),
    State = "Qualified",
    ActorExternalId = "agent-12",
    ActorExternalDisplayName = "Agent 12",
    ActorExternalSource = "crm",
    AssigneeExternalId = "owner-2",
    AssigneeExternalDisplayName = "Owner Two",
    AssigneeExternalSource = "crm"
});

Console.WriteLine($"Transaction {transaction.Id} status={transaction.Status} workstream={transaction.WorkstreamId}");
```

The SDK hashes payload bytes locally (`SHA-256`) and submits only `payloadHash` to Operon.

## Workstream APIs

```csharp
var workstream = await client.GetWorkstreamAsync();
var interactions = await client.GetWorkstreamInteractionsAsync();
var participants = await client.GetWorkstreamParticipantsAsync();
```

## Signature APIs

```csharp
var headers = await client.GenerateSignatureHeadersFromStringAsync(
    payload: JsonSerializer.Serialize(new { demo = true }),
    algorithm: "ES256"
);

var validation = await client.ValidateSignatureHeadersFromStringAsync(
    payload: JsonSerializer.Serialize(new { demo = true }),
    headers: headers
);
```

## PAT and Session Helpers

PAT-scoped operations are available via static helpers:

```csharp
using Operon.Sdk;

var signature = await PatHelpers.SignHashWithPatAsync(...);
var txn = await PatHelpers.SubmitTransactionWithPatAsync(...);
var ws = await PatHelpers.FetchWorkstreamAsync(...);
var info = await SessionValidator.ValidateSessionAsync(...);
```

Included helpers:
- `PatHelpers.SignHashWithPatAsync`
- `PatHelpers.SubmitTransactionWithPatAsync`
- `PatHelpers.ValidateSignatureWithPatAsync`
- `PatHelpers.FetchWorkstream*`
- `SessionValidator.ValidateSessionAsync`

## Compatibility

`ChannelId` remains supported as a compatibility alias for `WorkstreamId` in token claims and transaction/reference models.

## Build and Test

```bash
cd dotnet
dotnet restore
DOTNET_ROLL_FORWARD=Major dotnet test ../operon-sdk.sln
```

## Project Layout

```
dotnet/
├── Operon.Sdk/             # Core library (net8.0)
└── Operon.Sdk.Tests/       # xUnit test suite
```

## License

Apache-2.0 — see [LICENSE](../LICENSE).
