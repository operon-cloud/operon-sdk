# Operon Rust SDK

Idiomatic Rust client for the [Operon.Cloud](https://www.operon.cloud) platform targeting **Rust 1.75+**.

## Installation

```toml
[dependencies]
operon-sdk = "1.3.0"
```

## Quick Start

```rust
use operon_sdk::{OperonClient, OperonConfig};
use operon_sdk::models::{Signature, TransactionRequest};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = OperonConfig::builder()
        .client_id(std::env::var("OPERON_CLIENT_ID")?)
        .client_secret(std::env::var("OPERON_CLIENT_SECRET")?)
        .build()?;

    let client = OperonClient::new(config)?;
    client.init().await?;

    let mut request = TransactionRequest::new("corr-123", "int-abc")?
        .with_payload_bytes(br#"{"foo":"bar"}"#)
        .with_state("triage")
        .with_state_id("state-1")
        .with_state_label("Triage")
        .with_actor_external("zendesk", "agent-1", "Ops Agent")
        .with_assignee_external("jira", "owner-1", "Case Owner")
        .with_customer_id("cust-1")
        .with_workspace_id("ws-1")
        .with_created_by("ingestion-service");

    request.roi_base_cost = Some(100);
    request.roi_base_time = Some(20);
    request.roi_cost_saving = Some(15);
    request.roi_time_saving = Some(3);

    let transaction = client.submit_transaction(request).await?;
    println!("transaction {} status={}", transaction.id, transaction.status);

    Ok(())
}
```

## Functional Parity (Go v1.3.0)

- Workstream-first transaction/catalog APIs with channel compatibility aliases.
- Expanded transaction request/response model:
  - actor/assignee attribution (`actorExternal*`, `assigneeExternal*`)
  - state fields (`state`, `stateId`, `stateLabel`)
  - ROI compatibility fields (`roiBaseCost`, `roiBaseTime`, `roiCostSaving`, `roiTimeSaving`)
  - context fields (`customerId`, `workspaceId`, `createdBy`)
- Client methods:
  - `interactions`, `participants`
  - `get_workstream`, `get_workstream_interactions`, `get_workstream_participants`
  - `generate_signature_headers`, `validate_signature_headers`
- PAT helpers:
  - `sign_hash_with_pat`, `submit_transaction_with_pat`, `validate_signature_with_pat`
  - `fetch_workstream`, `fetch_workstream_interactions`, `fetch_workstream_participants`
  - `decode_payload_base64`
- Session helper:
  - `validate_session`

## Optional Session Keep-Alive

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

---

Licensed under Apache-2.0.
