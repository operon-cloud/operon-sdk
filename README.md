# Operon SDK

Modern companies rely on verifiable, event-driven data flows. Operon SDK gives platform teams a secure, production-ready client library for integrating with [Operon Cloud](https://operon.cloud) services. This repository hosts the official SDKs that power transaction submission, catalog lookups, and operational telemetry across customer, partner, and internal workloads.

## Overview

- **Enterprise-first**: Designed for regulated industries, with first-class support for service accounts, PATs, and multi-tenant isolation.
- **Unified abstractions**: Common models and request/response contracts across regions, services, and runtimes.
- **Deployment-ready**: Built-in observability, retry, and signing utilities to accelerate production integrations.
- **Secure by default**: Consistent client initialization (timeouts, TLS, mTLS-ready) and guardrails for credential handling.

> **SDK Coverage**  
> ✅ Go (1.3.0)  
> ✅ Java (1.0.1)  
> ✅ Node.js (1.0.1)  
> ✅ .NET (1.0.1)  
> ✅ Rust (1.0.1)  
> ✅ Python (1.0.1)

---

## Go SDK (`github.com/operon-cloud/operon-sdk/go`)

The Go package provides direct access to Operon’s transaction APIs, interaction catalog, and signature utilities.

Transactions support optional workstream analytics metadata such as state/queue labels and ROI classifications so value metrics can be tracked alongside audit records.

### Installation

```bash
go get github.com/operon-cloud/operon-sdk/go@latest
```

Ensure your Go toolchain is at least **Go 1.25** (matching the module’s `go.mod` requirement).

### Quick Start

```go
package main

import (
	"context"
	"log"
	"time"

	operon "github.com/operon-cloud/operon-sdk/go"
)

func main() {
	client, err := operon.NewClient(operon.Config{
		ClientID:     "<CLIENT_ID>",
		ClientSecret: "<CLIENT_SECRET>",
		// Optional: override defaults when targeting non-production environments.
		// BaseURL:  "https://api.dev.operon.cloud/client-api",
		// TokenURL: "https://auth.dev.operon.cloud/oauth2/token",
	})
	if err != nil {
		log.Fatalf("init client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := client.Init(ctx); err != nil {
		log.Fatalf("bootstrap session: %v", err)
	}

	txn, err := client.SubmitTransaction(ctx, operon.TransactionRequest{
		InteractionID: "int-123",
		CorrelationID: "lead-abc",
		Label:         "Sales lead ingestion",
		Payload:       []byte(`{"leadId":"lead-abc","useCase":"B2B onboarding"}`),
		Tags:          []string{"workstream:corporate-api", "priority:high"},
	})
	if err != nil {
		log.Fatalf("submit transaction: %v", err)
	}

	log.Printf("transaction accepted (id=%s status=%s)", txn.ID, txn.Status)
}
```

> **Security Note**  
> The Go SDK computes a SHA-256 hash of any `Payload` you supply and submits only the hash to Operon. Raw payload bytes remain inside your service boundary.

### Configuration Reference

| Field                     | Description                                                                 | Example                                          |
|---------------------------|-----------------------------------------------------------------------------|--------------------------------------------------|
| `BaseURL`                 | Optional; defaults to Operon production API base. Override for dev/QA environments. | `https://api.dev.operon.cloud/client-api`        |
| `TokenURL`                | Optional; defaults to the production OAuth2 token issuer. Override for dev/QA environments. | `https://auth.dev.operon.cloud/oauth2/token` |
| `ClientID`                | Issued client identifier                                                    | `m2mc-xxxxx`                                    |
| `ClientSecret`            | One-time secret accompanying the client ID                                  | `super-secret-value`                            |
| `Scope`                   | Optional OAuth2 scope override                                              | `transactions:write`                            |
| `Audience`                | Optional OAuth2 audience override                                           | `[]string{"https://api.operon.cloud"}`          |
| `HTTPClient`              | Custom HTTP client; defaults to `http.Client{Timeout: 30s}`                 | `&http.Client{Timeout: 10 * time.Second}`       |
| `TokenLeeway`             | Refresh tokens before expiry                                                | `30 * time.Second`                              |
| `DisableSelfSign`         | Disable managed signing (requires manual signature)                         | `true`                                          |
| `SigningAlgorithm`        | Default signing algorithm                                                   | `operon.AlgorithmES256`                         |
| `SessionHeartbeatInterval`| Enable PAT keep-alive pings                                                  | `2 * time.Minute`                               |

See the Go package’s [README](./go/README.md) for API-by-API details, advanced configuration, and testing utilities.

### Testing Locally

```bash
cd go
go test ./...
```

Tests rely on Go’s standard tooling and include lightweight HTTP fixtures to validate signing logic and error handling. Set `OPERON_SDK_DEBUG=true` to enable verbose logs when needed.

---

## Java SDK (`cloud.operon:operon-sdk`)

The Java client brings the same ergonomics to JVM services targeting JDK 17 or 21.

### Installation

Add the dependency to your Maven project:

```xml
<dependency>
  <groupId>cloud.operon</groupId>
  <artifactId>operon-sdk</artifactId>
  <version>1.0.0</version>
</dependency>
```

Or with Gradle (Kotlin DSL):

```kotlin
dependencies {
    implementation("cloud.operon:operon-sdk:1.0.0")
}
```

### Quick Start

```java
import cloud.operon.sdk.*;
import java.time.Duration;

public class Example {
    public static void main(String[] args) throws Exception {
        Config config = Config.builder()
            .clientId(System.getenv("OPERON_CLIENT_ID"))
            .clientSecret(System.getenv("OPERON_CLIENT_SECRET"))
            // Optional overrides for non-production environments
            // .baseUrl("https://api.dev.operon.cloud/client-api")
            // .tokenUrl("https://auth.dev.operon.cloud/oauth2/token")
            .httpTimeout(Duration.ofSeconds(10))
            .build();

        try (OperonClient client = new OperonClient(config)) {
            client.init();

            TransactionRequest request = TransactionRequest.builder()
                .correlationId("lead-abc")
                .interactionId("int-123")
                .signature(new Signature("EdDSA", "BASE64_SIGNATURE", null))
                .payload("{\"leadId\":\"lead-abc\"}")
                .build();

            Transaction txn = client.submitTransaction(request);
            System.out.printf("Transaction %s status=%s%n", txn.id(), txn.status());
        }
    }
}
```

### Building & Testing

```bash
# Run unit tests (HTTP flows are mocked via embedded servers)
mvn -f java/pom.xml test
```

The Maven build targets `--release 17`, ensuring compatibility with both JDK 17 and JDK 21 runtimes and ships with coverage across token management, interaction caching, and transaction submission failure paths.

---

## Node.js SDK (`@operoncloud/operon-sdk`)

The Node package delivers a modern, ESM-first client tailored for Node.js 20+ and TypeScript projects.

### Installation

```bash
npm install @operoncloud/operon-sdk
```

### Quick Start

```ts
import { OperonClient, createConfig } from '@operoncloud/operon-sdk';

const client = new OperonClient(
  createConfig({
    clientId: process.env.OPERON_CLIENT_ID!,
    clientSecret: process.env.OPERON_CLIENT_SECRET!
    // BaseURL and TokenURL default to production; override for dev/qa as needed.
  })
);

await client.init();

const txn = await client.submitTransaction({
  correlationId: 'corr-123',
  interactionId: 'int-abc',
  payload: { foo: 'bar' }
});

console.log(`transaction ${txn.id} status=${txn.status}`);
await client.close();
```

### Building & Testing

```bash
cd node
npm install
npm run lint
npm test
npm run build
```

The build emits ESM output with bundled type declarations, and the Vitest suite covers configuration validation, token lifecycle management, and transaction submission (including automatic signing and manual signature paths).

---

## .NET SDK (`Operon.Sdk`)

The .NET library targets **.NET 8** and mirrors the functionality available in the Go, Java, and Node packages. It embraces modern .NET conventions (nullable reference types, `HttpClient`, `System.Text.Json`) and ships with XML documentation for IntelliSense.

### Installation

```bash
dotnet add package Operon.Sdk --version 1.0.0
```

### Quick Start

```csharp
using Operon.Sdk;
using Operon.Sdk.Models;

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
});

Console.WriteLine($"Transaction {response.Id} status={response.Status}");
```

### Building & Testing

```bash
cd dotnet
dotnet restore
dotnet test
```

The solution includes `Operon.Sdk.Tests`, an xUnit project that exercises configuration defaults, token lifecycle behaviour, and transaction submission (including automatic self-signing).

---

## Rust SDK (`operon-sdk`)

The Rust crate targets **Rust 1.75+** and ships with async APIs built on `reqwest`, `tokio`, and `serde`. Automatic token refresh and optional self-signing mirror other SDKs while staying idiomatic to Rust.

### Installation

```toml
[dependencies]
operon-sdk = { path = "rust/operon-sdk" }
```

### Quick Start

```rust
use operon_sdk::{OperonClient, OperonConfig};
use operon_sdk::models::TransactionRequest;

#[tokio::main]
async fn main() -> Result<(), operon_sdk::errors::OperonError> {
    let config = OperonConfig::builder()
        .client_id(std::env::var("OPERON_CLIENT_ID")?)
        .client_secret(std::env::var("OPERON_CLIENT_SECRET")?)
        .build()?;

    let client = OperonClient::new(config)?;
    client.init().await?;

    let request = TransactionRequest::new("corr-123", "int-abc")?
        .with_payload_bytes(br"{"foo":"bar"}");

    let transaction = client.submit_transaction(request).await?;
    println!("transaction {} status={}", transaction.id, transaction.status);
    Ok(())
}
```

### Building & Testing

```bash
cd rust/operon-sdk
cargo fmt
cargo test
```

The crate includes integration tests powered by `wiremock` covering token refresh, self-signing, and manual signature flows.

---

## Python SDK (`operon-sdk`)

The Python package targets **Python 3.10+** and provides async APIs built on `httpx` and Pydantic. Automatic token refresh, catalog caching, and optional self-signing mirror the other SDKs.

### Installation

```bash
pip install operon-sdk
```

### Quick Start

```python
import asyncio
from operon_sdk import OperonClient, OperonConfig
from operon_sdk.models import TransactionRequest

async def main() -> None:
    config = OperonConfig(client_id="client", client_secret="secret")
    client = OperonClient(config)
    await client.init()

    request = TransactionRequest.new("corr-123", "int-abc").with_payload_bytes(b"{}")
    txn = await client.submit_transaction(request)
    print("Transaction", txn.id)

asyncio.run(main())
```

### Building & Testing

```bash
cd python/operon_sdk
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

The test suite uses `pytest` + `respx` to verify token refresh, self-signing, and manual signature flows.

---

---

## Versioning & Releases

- Semantic versioning (`MAJOR.MINOR.PATCH`) with Go module-aware tags (`go/vX.Y.Z`).
- Change logs are published per release in [`CHANGELOG.md`](./CHANGELOG.md); breaking changes are documented in detail.
- Adds compatibility tests before each release to ensure downstream services remain stable.

To consume a specific version in Go, pin the tag:

```bash
go get github.com/operon-cloud/operon-sdk/go@v1.3.0
```

---

## Contributing

We welcome contributions from customers and partners. To propose changes:

1. Open an issue describing the enhancement or bug.
2. Fork the repository, create a feature branch (`feat/my-improvement`).
3. Run tests (`go test ./...`).
4. Submit a pull request referencing the issue.

All contributions are reviewed for security, backwards compatibility, and documentation impact.

---

## Security

If you discover a vulnerability, **do not** open a public GitHub issue. Instead:

- Email [security@operon.cloud](mailto:security@operon.cloud) with details.
- Include reproduction steps, affected versions, and mitigation ideas if available.

Our security team will acknowledge receipt within 24 hours and follow established disclosure timelines.

---

## Support

- **Documentation**: [Operon Docs](https://docs.operon.cloud)
- **Questions**: [GitHub Discussions](https://github.com/operon-cloud/operon-sdk/discussions)
- **Enterprise Support**: Reach out via your customer success manager or [support@operon.cloud](mailto:support@operon.cloud).

---

## License

This project is licensed under the [Apache License 2.0](./LICENSE), unless otherwise noted. By contributing, you agree that your contributions will be licensed under the same terms.

---

© 2025 Operon, LLC. All rights reserved.
