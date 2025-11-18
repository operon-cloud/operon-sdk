from __future__ import annotations

import asyncio
import base64
import json

import pytest
import respx
from httpx import Response

from operon_sdk import OperonClient, OperonConfig
from operon_sdk.models import Signature, TransactionRequest


def build_token(claims: dict[str, str]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


@pytest.mark.asyncio
async def test_submit_transaction_self_sign():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api/",
        token_url="https://example.com/oauth/token",
    )

    client = OperonClient(config)

    with respx.mock(base_url="https://example.com") as mock:
        mock.post("/oauth/token").return_value = Response(
            200,
            json={
                "access_token": build_token(
                    {"participant_did": "did:test:123", "channel_id": "chnl"}
                ),
                "expires_in": 300,
            },
        )
        mock.get("/api/v1/channels/chnl/interactions").return_value = Response(
            200,
            json={
                "interactions": [
                    {
                        "id": "int-123",
                        "channelId": "chnl",
                        "sourceParticipantId": "part-1",
                        "targetParticipantId": "part-2",
                    }
                ],
                "totalCount": 1,
                "page": 1,
                "pageSize": 50,
                "hasMore": False,
            },
        )
        mock.get("/api/v1/channels/chnl/participants").return_value = Response(
            200,
            json={
                "participants": [
                    {"id": "part-1", "did": "did:test:123"},
                    {"id": "part-2", "did": "did:test:456"},
                ],
                "totalCount": 2,
                "page": 1,
                "pageSize": 50,
                "hasMore": False,
            },
        )
        mock.post("/api/v1/dids/self/sign").return_value = Response(
            200,
            json={
                "signature": {
                    "algorithm": "EdDSA",
                    "value": "signed-value",
                    "keyId": "did:test:123#keys-1",
                }
            },
        )
        mock.post("/api/v1/transactions").return_value = Response(
            200,
            json={
                "id": "txn-1",
                "correlationId": "corr-1",
                "channelId": "chnl",
                "interactionId": "int-123",
                "timestamp": "2025-01-01T00:00:00Z",
                "sourceDid": "did:test:123",
                "targetDid": "did:test:456",
                "signature": {
                    "algorithm": "EdDSA",
                    "value": "signed-value",
                    "keyId": "did:test:123#keys-1",
                },
                "payloadHash": "hash",
                "status": "PENDING",
            },
        )

        await client.init()
        request = TransactionRequest.new("corr-1", "int-123").with_payload_bytes(b"{}")
        txn = await client.submit_transaction(request)
        assert txn.id == "txn-1"
        assert txn.signature.value == "signed-value"


@pytest.mark.asyncio
async def test_submit_transaction_manual_signature():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api/",
        token_url="https://example.com/oauth/token",
        disable_self_sign=True,
    )

    client = OperonClient(config)

    with respx.mock(base_url="https://example.com") as mock:
        mock.post("/oauth/token").return_value = Response(
            200,
            json={
                "access_token": build_token(
                    {"participant_did": "did:test:999", "channel_id": "chnl"}
                ),
                "expires_in": 300,
            },
        )
        mock.get("/api/v1/channels/chnl/interactions").return_value = Response(
            200,
            json={"interactions": [], "totalCount": 0, "page": 1, "pageSize": 50, "hasMore": False},
        )
        mock.get("/api/v1/channels/chnl/participants").return_value = Response(
            200,
            json={"participants": [], "totalCount": 0, "page": 1, "pageSize": 50, "hasMore": False},
        )
        mock.post("/api/v1/transactions").return_value = Response(
            200,
            json={
                "id": "txn-2",
                "correlationId": "corr-2",
                "channelId": "chnl",
                "interactionId": "int-999",
                "timestamp": "2025-01-01T00:00:00Z",
                "sourceDid": "did:test:999",
                "targetDid": "did:test:888",
                "signature": {
                    "algorithm": "EdDSA",
                    "value": "manual",
                    "keyId": "did:test:999#keys-1",
                },
                "payloadHash": "hash",
                "status": "PENDING",
            },
        )

        await client.init()
        request = (
            TransactionRequest.new("corr-2", "int-999")
            .with_channel_id("chnl")
            .with_source_did("did:test:999")
            .with_target_did("did:test:888")
            .with_payload_hash("hash")
            .with_signature(Signature(algorithm="EdDSA", value="manual"))
        )
        txn = await client.submit_transaction(request)
        assert txn.signature.value == "manual"


@pytest.mark.asyncio
async def test_heartbeat_forces_token_refresh_when_unauthorised():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api/",
        token_url="https://example.com/oauth/token",
        session_heartbeat_interval=0.05,
        session_heartbeat_timeout=0.1,
    )

    client = OperonClient(config)

    with respx.mock(base_url="https://example.com") as mock:
        token_route = mock.post("/oauth/token")
        token_route.side_effect = [
            Response(
                200,
                json={
                    "access_token": build_token({"participant_did": "did:test:heartbeat"}),
                    "expires_in": 300,
                },
            ),
            Response(
                200,
                json={
                    "access_token": build_token({"participant_did": "did:test:refresh"}),
                    "expires_in": 300,
                },
            ),
        ]
        heartbeat_route = mock.get("/api/v1/session/heartbeat")

        async def heartbeat_side_effect(request):
            if heartbeat_route.call_count == 0:
                return Response(401, json={"code": "SESSION_EXPIRED"})
            return Response(200, json={"status": "ok"})

        heartbeat_route.side_effect = heartbeat_side_effect

        await client.init()
        await asyncio.sleep(0.2)
        await client.aclose()

    assert token_route.call_count >= 2
    assert heartbeat_route.call_count >= 1
