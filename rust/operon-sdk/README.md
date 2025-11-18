# Operon Rust SDK

Idiomatic Rust client for the [Operon.Cloud](https://www.operon.cloud) platform targeting **Rust 1.75+**. The crate mirrors features available in the Go, Java, Node, and .NET SDKs while embracing async/await, `reqwest`, and serde for ergonomic usage.

## Usage

```toml
[dependencies]
operon-sdk = "1.0.2"
```

```rust
use operon_sdk::{OperonClient, OperonConfig};
use operon_sdk::models::TransactionRequest;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = OperonConfig::builder()
        .client_id(std::env::var("OPERON_CLIENT_ID")?)
        .client_secret(std::env::var("OPERON_CLIENT_SECRET")?)
        .build()?;

    let client = OperonClient::new(config)?;
    client.init().await?;

    let txn = client
        .submit_transaction(TransactionRequest::new("corr-123", "int-abc")?
            .with_payload_bytes(br"{\"foo\":\"bar\"}"))
        .await?;

println!("transaction {} status={}", txn.id, txn.status);
    Ok(())
}
```

> **Security note**
> The Rust SDK mirrors the Go implementation: it computes a SHA-256 hash locally and only sends the hash (`payloadHash`) to Operon. Raw payload bytes never leave your service.

### Optional session keep-alive

Long-lived daemons can configure a heartbeat so the SDK pings `/v1/session/heartbeat` and forces a token refresh when Operon responds with 401:

```rust
let config = OperonConfig::builder()
    .client_id("client")
    .client_secret("secret")
    .session_heartbeat_interval(std::time::Duration::from_secs(120))
    .build()?;
```

## Development

```bash
cd rust/operon-sdk
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

## Features

- Client-credentials token provider with proactive refresh
- Interaction/participant catalogue cache
- Optional self-sign flow for payload hashes
- Comprehensive error types (`OperonError`, `ApiError`, `TransportError`)
- Unit tests powered by `wiremock`

## Minimum Supported Rust Version (MSRV)

Rust 1.75.0 (locked via package metadata). The crate is tested against the latest stable release.

---

Licensed under Apache-2.0.

—

Find other language SDKs and onboarding guides at https://www.operon.cloud/developers
