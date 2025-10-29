# Operon Rust SDK

Idiomatic Rust client for the [Operon.Cloud](https://www.operon.cloud) platform targeting **Rust 1.75+**. The crate mirrors features available in the Go, Java, Node, and .NET SDKs while embracing async/await, `reqwest`, and serde for ergonomic usage.

## Usage

```toml
[dependencies]
operon-sdk = { path = "../operon-sdk" }
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
