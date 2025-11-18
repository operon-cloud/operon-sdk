# Operon .NET SDK

Modern .NET client (targeting **.NET 8**) for interacting with [Operon.Cloud](https://www.operon.cloud) services. The package mirrors the features offered by the Go, Java, and Node SDKs while embracing idiomatic .NET patterns such as dependency injection, `HttpClient`, and `System.Text.Json`.

## Project Structure

```
dotnet/
├── Operon.Sdk/             # Core library (net8.0)
└── Operon.Sdk.Tests/       # xUnit test suite covering configuration, token flow, and transactions
```

### Library (`Operon.Sdk`)
- `OperonConfig` – configuration defaults & validation.
- `OperonClient` – token-aware API client with optional self-signing support.
- `ClientCredentialsTokenProvider` – OAuth2 client-credentials manager with proactive refresh.
- `Models` namespace – transaction, interaction, participant, and signature DTOs.
- `CatalogRegistry` – in-memory cache for interaction/participant metadata.
- Rich XML docs that surface in IntelliSense for enterprise consumers.

### Tests (`Operon.Sdk.Tests`)
- Uses xUnit and stub `HttpMessageHandler` implementations to simulate authentication & API endpoints.
- Validates configuration defaults, token caching semantics, and transaction submission (manual + self-sign).

## Getting Started

```bash
# Restore packages and run the test suite
cd dotnet
dotnet restore
dotnet test
```

To build and publish locally:

```bash
dotnet build Operon.Sdk/Operon.Sdk.csproj -c Release
dotnet pack Operon.Sdk/Operon.Sdk.csproj -c Release -o ./nupkg
```

Add the package to your application (once published to NuGet):

```xml
<ItemGroup>
  <PackageReference Include="Operon.Sdk" Version="1.0.2" />
</ItemGroup>
```

## Quick Start

```csharp
using Operon.Sdk;

var config = new OperonConfig(
    clientId: Environment.GetEnvironmentVariable("OPERON_CLIENT_ID")!,
    clientSecret: Environment.GetEnvironmentVariable("OPERON_CLIENT_SECRET")!
);

await using var client = new OperonClient(config);
await client.InitAsync();

var response = await client.SubmitTransactionAsync(new TransactionRequest
{
    CorrelationId = "corr-123",
    InteractionId = "int-abc",
    PayloadBytes = JsonSerializer.SerializeToUtf8Bytes(new { foo = "bar" })
}, CancellationToken.None);

Console.WriteLine($"Transaction {response.Id} status={response.Status}");
```

> **Security note**
> The .NET SDK mirrors the Go implementation: it hashes payload bytes locally and only transmits the hash (`payloadHash`) to Operon. Raw payloads stay within your application boundary.

### Keep sessions warm

Set `sessionHeartbeatInterval` on `OperonConfig` to enable a background heartbeat that pings `/v1/session/heartbeat` and forces a token refresh whenever Operon returns 401:

```csharp
var config = new OperonConfig(
    clientId: "...",
    clientSecret: "...",
    sessionHeartbeatInterval: TimeSpan.FromMinutes(2)
);
```

## Versioning & Packaging

- Target runtime: **.NET 8 (LTS)**
- Nullable reference types & implicit usings enabled by default.
- `GenerateDocumentationFile` ensures XML docs are emitted for downstream tooling.

## Next Steps

- Wire into CI for automated `dotnet test` and `dotnet pack` runs.
- Publish pre-release builds to a private NuGet feed for early adopters.

—

Find SDKs for other languages and developer resources at https://www.operon.cloud/developers
