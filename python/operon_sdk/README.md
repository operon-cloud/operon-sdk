# Operon Python SDK

Asynchronous Python client for [Operon.Cloud](https://www.operon.cloud) services. Targets Python **3.10+** and mirrors the feature set provided in the Go, Java, Node, .NET, and Rust SDKs.

## Installation

```bash
pip install operon-sdk
```

(For now the package lives in this repository; install with `pip install -e python/operon_sdk` during development.)

## Quick Start

```python
import asyncio
from operon_sdk import OperonClient, OperonConfig
from operon_sdk.models import TransactionRequest

async def main() -> None:
    config = OperonConfig(
        client_id="your-client-id",
        client_secret="your-client-secret",
    )

    client = OperonClient(config)
    await client.init()

    request = TransactionRequest.new(
        correlation_id="corr-123",
        interaction_id="int-abc",
    ).with_payload_bytes(b'{"foo":"bar"}')

    transaction = await client.submit_transaction(request)
    print("Transaction", transaction.id)

asyncio.run(main())
```

> **Security note**
> The Python SDK mirrors the Go implementation: it computes a SHA-256 hash of any payload bytes you provide and only transmits the hash (`payloadHash`) to Operon. Raw payloads never leave your application boundary.

## Development

```bash
cd python/operon_sdk
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
black .
```

## Features

- Async client built on `httpx`
- Client-credentials token provider with proactive refresh
- Interaction/participant catalogue caching
- Optional self-sign workflow for payload hashes
- Strongly typed request/response models via Pydantic v2
- Comprehensive unit tests powered by `pytest` + `respx`

## Minimum Supported Python Version

Python 3.10+.

---

Licensed under Apache-2.0.

—

Discover more SDKs and guides at the Operon.Cloud Developers hub: https://www.operon.cloud/developers
