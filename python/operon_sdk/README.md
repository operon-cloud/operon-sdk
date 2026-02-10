# Operon Python SDK

Asynchronous Python client for [Operon.Cloud](https://www.operon.cloud) services.
Targets Python **3.10+** and now aligns functionally with the Go SDK `v1.3.0`.

## Installation

```bash
pip install operon-sdk==1.3.0
```

For local development:

```bash
pip install -e python/operon_sdk
```

## Quick Start

```python
import asyncio
from operon_sdk import OperonClient, OperonConfig
from operon_sdk.models import TransactionRequest


async def main() -> None:
    client = OperonClient(
        OperonConfig(
            client_id="your-client-id",
            client_secret="your-client-secret",
        )
    )

    await client.init()

    request = (
        TransactionRequest.new("corr-123", "int-abc")
        .with_payload_bytes(b'{"foo":"bar"}')
    )
    request.actor_external_id = "agent-7"
    request.actor_external_display_name = "Agent Seven"
    request.actor_external_source = "crm"
    request.assignee_external_id = "owner-8"
    request.assignee_external_display_name = "Owner Eight"
    request.assignee_external_source = "crm"

    txn = await client.submit_transaction(request)
    print(txn.id, txn.status)

    await client.aclose()


asyncio.run(main())
```

Security note: the SDK computes SHA-256 for payload bytes and sends only `payloadHash`.

## Included Surfaces

- Transaction submit with self-sign or manual-sign paths
- Interaction/participant reference cache via `/v1/interactions` and `/v1/participants`
- Workstream APIs:
  - `get_workstream`
  - `get_workstream_interactions`
  - `get_workstream_participants`
- Signature helpers:
  - `generate_signature_headers`
  - `validate_signature_headers`
- PAT helpers:
  - `sign_hash_with_pat`
  - `submit_transaction_with_pat`
  - `validate_signature_with_pat`
  - `fetch_workstream`, `fetch_workstream_interactions`, `fetch_workstream_participants`
- Session validation helper:
  - `validate_session`

## Optional Session Heartbeat

```python
config = OperonConfig(
    client_id="your-client-id",
    client_secret="your-client-secret",
    session_heartbeat_interval=120.0,
)
```

When enabled, the client pings `/v1/session/heartbeat` and forces a token refresh on `401`.

## Development

```bash
cd python/operon_sdk
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
black .
```

---

Licensed under Apache-2.0.
