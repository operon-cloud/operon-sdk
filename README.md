# Operon SDK

Modern companies rely on verifiable, event-driven data flows. Operon SDK gives platform teams a secure, production-ready client library for integrating with [Operon Cloud](https://operon.cloud) services. This repository hosts the official SDKs that power transaction submission, catalog lookups, and operational telemetry across customer, partner, and internal workloads.

## Overview

- **Enterprise-first**: Designed for regulated industries, with first-class support for service accounts, PATs, and multi-tenant isolation.
- **Unified abstractions**: Common models and request/response contracts across regions, services, and runtimes.
- **Deployment-ready**: Built-in observability, retry, and signing utilities to accelerate production integrations.
- **Secure by default**: Consistent client initialization (timeouts, TLS, mTLS-ready) and guardrails for credential handling.

> **SDK Coverage**  
> ✅ Go (primary)  
> ⏳ Java (coming soon)  
> ⏳ Node.js (coming soon)  
> ⏳ .NET (coming soon)

---

## Go SDK (`github.com/operon-cloud/operon-sdk/go`)

The Go package provides direct access to Operon’s transaction APIs, interaction catalog, and signature utilities.

### Installation

```bash
go get github.com/operon-cloud/operon-sdk/go@latest
```

Ensure your Go toolchain is at least **Go 1.21** (matching the module’s `go.mod` requirement).

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
		BaseURL:      "https://api.dev.operon.cloud/client-api",
		TokenURL:     "https://auth.dev.operon.cloud/oauth2/token",
		ClientID:     "<CLIENT_ID>",
		ClientSecret: "<CLIENT_SECRET>",
		HTTPTimeout:  10 * time.Second,
	})
	if err != nil {
		log.Fatalf("init client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := client.Init(ctx); err != nil {
		log.Fatalf("bootstrap session: %v", err)
	}

	txn, err := client.SubmitTransaction(ctx, operon.TransactionRequest{
		InteractionID:  "int-123",
		CorrelationID:  "lead-abc",
		Label:          "Sales lead ingestion",
		Payload:        []byte(`{"leadId":"lead-abc","useCase":"B2B onboarding"}`),
		Tags:           []string{"channel:corporate-api", "priority:high"},
	})
	if err != nil {
		log.Fatalf("submit transaction: %v", err)
	}

	log.Printf("transaction accepted (id=%s status=%s)", txn.ID, txn.Status)
}
```

### Configuration Reference

| Field            | Description                                              | Example                                          |
|------------------|----------------------------------------------------------|--------------------------------------------------|
| `BaseURL`        | Operon API base endpoint                                 | `https://api.dev.operon.cloud/client-api`                  |
| `TokenURL`       | OAuth2 token endpoint for service account credentials    | `https://auth.dev.operon.cloud/oauth2/token`     |
| `ClientID`       | Issued client identifier                                 | `m2mc-xxxxx`                                    |
| `ClientSecret`   | One-time secret accompanying the client ID               | `super-secret-value`                            |
| `HTTPTimeout`    | Global timeout applied to outbound HTTP calls            | `10 * time.Second`                              |
| `Scopes`         | Optional scopes override (defaults to Operon defaults)   | `[]string{"transactions:write"}`                |
| `Logger`         | Custom `*zap.Logger`; falls back to `zap.NewNop()`       | `zap.NewExample()`                              |

See the Go package’s [README](./go/README.md) for API-by-API details, advanced configuration, and testing utilities.

### Testing Locally

```bash
cd go
go test ./...
```

Tests rely on Go’s standard tooling and include lightweight HTTP fixtures to validate signing logic and error handling. Set `OPERON_SDK_DEBUG=true` to enable verbose logs when needed.

---

## Roadmap: Additional Languages

We are actively expanding the SDK surface area. Track progress or contribute feedback via the issues board.

| Language | Status        | Tracking Issue                                         | Notes                              |
|----------|---------------|--------------------------------------------------------|------------------------------------|
| Java     | Planned       | [#12](https://github.com/operon-cloud/operon-sdk/issues/12) | Targeting Spring Boot & Jakarta EE |
| Node.js  | Planned       | [#13](https://github.com/operon-cloud/operon-sdk/issues/13) | Targeting ESM + TypeScript users   |
| .NET     | Planned       | [#14](https://github.com/operon-cloud/operon-sdk/issues/14) | Targeting .NET 8 minimal APIs      |

Interested in early access or partnership on these runtimes? [Contact us](mailto:sdk@operon.cloud).

---

## Versioning & Releases

- Semantic versioning (`MAJOR.MINOR.PATCH`) with Go module-aware tags (`go/vX.Y.Z`).
- Change logs are published per release; breaking changes are documented in detail.
- Adds compatibility tests before each release to ensure downstream services remain stable.

To consume a specific version in Go, pin the tag:

```bash
go get github.com/operon-cloud/operon-sdk/go@v1.0.0
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
