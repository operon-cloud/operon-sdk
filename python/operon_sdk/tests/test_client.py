from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime, timezone

import pytest
import respx
from httpx import Response

from operon_sdk import (
    HEADER_OPERON_DID,
    HEADER_OPERON_PAYLOAD_HASH,
    HEADER_OPERON_SIGNATURE,
    HEADER_OPERON_SIGNATURE_ALGO,
    HEADER_OPERON_SIGNATURE_KEY,
    OperonClient,
    OperonConfig,
)
from operon_sdk.errors import ValidationError
from operon_sdk.models import Signature, TransactionRequest


def build_token(claims: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


@pytest.mark.asyncio
async def test_submit_transaction_self_sign_with_actor_assignee_fields():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api",
        token_url="https://example.com/oauth/token",
    )
    client = OperonClient(config)

    with respx.mock(base_url="https://example.com") as mock:
        token_value = build_token({"participant_did": "did:test:source", "workstream_id": "wstr-123"})
        mock.post("/oauth/token").return_value = Response(
            200,
            json={"access_token": token_value, "expires_in": 300},
        )

        mock.get("/api/v1/interactions").return_value = Response(
            200,
            json={
                "data": [
                    {
                        "id": "int-123",
                        "workstreamId": "wstr-123",
                        "sourceParticipantId": "p-src",
                        "targetParticipantId": "p-dst",
                    }
                ]
            },
        )
        mock.get("/api/v1/participants").return_value = Response(
            200,
            json={
                "data": [
                    {"id": "p-src", "did": "did:test:source"},
                    {"id": "p-dst", "did": "did:test:target"},
                ]
            },
        )

        mock.post("/api/v1/dids/self/sign").return_value = Response(
            200,
            json={
                "signature": {
                    "algorithm": "EdDSA",
                    "value": "signed-value",
                    "keyId": "",
                }
            },
        )

        def txn_callback(request):
            body = json.loads(request.content.decode())
            assert body["workstreamId"] == "wstr-123"
            assert body["sourceDid"] == "did:test:source"
            assert body["targetDid"] == "did:test:target"
            assert body["actorExternalId"] == "agent-1"
            assert body["actorExternalDisplayName"] == "Agent One"
            assert body["actorExternalSource"] == "crm"
            assert body["assigneeExternalId"] == "owner-2"
            assert body["assigneeExternalDisplayName"] == "Owner Two"
            assert body["assigneeExternalSource"] == "crm"
            assert body["signature"]["keyId"] == "did:test:source#keys-1"

            return Response(
                200,
                json={
                    "id": "txn-1",
                    "correlationId": "corr-1",
                    "workstreamId": "wstr-123",
                    "interactionId": "int-123",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "sourceDid": "did:test:source",
                    "targetDid": "did:test:target",
                    "signature": {
                        "algorithm": "EdDSA",
                        "value": "signed-value",
                        "keyId": "did:test:source#keys-1",
                    },
                    "payloadHash": body["payloadHash"],
                    "status": "received",
                },
            )

        txn_route = mock.post("/api/v1/transactions")
        txn_route.side_effect = txn_callback

        await client.init()

        req = TransactionRequest.new("corr-1", "int-123").with_payload_bytes(b'{"x":1}')
        req.actor_external_id = "agent-1"
        req.actor_external_display_name = "Agent One"
        req.actor_external_source = "crm"
        req.assignee_external_id = "owner-2"
        req.assignee_external_display_name = "Owner Two"
        req.assignee_external_source = "crm"

        txn = await client.submit_transaction(req)
        assert txn.id == "txn-1"
        assert txn.status == "received"


@pytest.mark.asyncio
async def test_submit_transaction_manual_signature_when_self_sign_disabled():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api",
        token_url="https://example.com/oauth/token",
        disable_self_sign=True,
    )
    client = OperonClient(config)

    with respx.mock(base_url="https://example.com") as mock:
        token_value = build_token({"participant_did": "did:test:source", "workstream_id": "wstr-123"})
        mock.post("/oauth/token").return_value = Response(
            200,
            json={"access_token": token_value, "expires_in": 300},
        )
        mock.get("/api/v1/interactions").return_value = Response(
            200,
            json={"data": [{"id": "int-123", "workstreamId": "wstr-123", "sourceParticipantId": "p-src", "targetParticipantId": "p-dst"}]},
        )
        mock.get("/api/v1/participants").return_value = Response(
            200,
            json={"data": [{"id": "p-src", "did": "did:test:source"}, {"id": "p-dst", "did": "did:test:target"}]},
        )

        mock.post("/api/v1/transactions").return_value = Response(
            200,
            json={
                "id": "txn-2",
                "correlationId": "corr-2",
                "workstreamId": "wstr-123",
                "interactionId": "int-123",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sourceDid": "did:test:source",
                "targetDid": "did:test:target",
                "signature": {
                    "algorithm": "EdDSA",
                    "value": "manual",
                    "keyId": "did:test:source#keys-1",
                },
                "payloadHash": "hash",
                "status": "received",
            },
        )

        req = (
            TransactionRequest.new("corr-2", "int-123")
            .with_payload_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .with_signature(
                Signature(
                    algorithm="EdDSA",
                    value="manual",
                    keyId="did:test:source#keys-1",
                )
            )
        )
        req.source_did = "did:test:source"
        req.target_did = "did:test:target"

        txn = await client.submit_transaction(req)
        assert txn.id == "txn-2"


@pytest.mark.asyncio
async def test_generate_signature_headers_and_validate_signature_headers():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api",
        token_url="https://example.com/oauth/token",
        signing_algorithm="ES256",
    )
    client = OperonClient(config)

    payload = b'{"demo":true}'

    with respx.mock(base_url="https://example.com") as mock:
        token_value = build_token({"participant_did": "did:test:source"})
        mock.post("/oauth/token").return_value = Response(
            200,
            json={"access_token": token_value, "expires_in": 300},
        )

        mock.post("/api/v1/dids/self/sign").return_value = Response(
            200,
            json={
                "signature": {
                    "algorithm": "ES256",
                    "value": "sig-value",
                    "keyId": "did:test:source#keys-1",
                }
            },
        )

        mock.post("/api/v1/dids/did%3Atest%3Asource/signature/verify").return_value = Response(
            200,
            json={
                "status": "VALID",
                "message": "ok",
                "did": "did:test:source",
                "payloadHash": "placeholder",
                "algorithm": "ES256",
                "keyId": "did:test:source#keys-1",
            },
        )

        headers = await client.generate_signature_headers(payload)
        assert headers[HEADER_OPERON_DID] == "did:test:source"
        assert headers[HEADER_OPERON_SIGNATURE_ALGO] == "ES256"

        result = await client.validate_signature_headers(payload, headers)
        assert result.status == "VALID"


@pytest.mark.asyncio
async def test_validate_signature_headers_hash_mismatch():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api",
        token_url="https://example.com/oauth/token",
    )
    client = OperonClient(config)

    with respx.mock(base_url="https://example.com") as mock:
        token_value = build_token({"participant_did": "did:test:source"})
        mock.post("/oauth/token").return_value = Response(
            200,
            json={"access_token": token_value, "expires_in": 300},
        )

        with pytest.raises(ValidationError):
            await client.validate_signature_headers(
                b"payload",
                {
                    HEADER_OPERON_DID: "did:test:source",
                    HEADER_OPERON_PAYLOAD_HASH: "mismatch",
                    HEADER_OPERON_SIGNATURE: "sig",
                    HEADER_OPERON_SIGNATURE_KEY: "did:test:source#keys-1",
                    HEADER_OPERON_SIGNATURE_ALGO: "EdDSA",
                },
            )


@pytest.mark.asyncio
async def test_get_workstream_interactions_uses_token_workstream():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api",
        token_url="https://example.com/oauth/token",
    )
    client = OperonClient(config)

    with respx.mock(base_url="https://example.com") as mock:
        token_value = build_token({"participant_did": "did:test:source", "workstream_id": "wstr-abc"})
        mock.post("/oauth/token").return_value = Response(
            200,
            json={"access_token": token_value, "expires_in": 300},
        )
        mock.get("/api/v1/workstreams/wstr-abc/interactions").return_value = Response(
            200,
            json={
                "interactions": [{"id": "int-1", "workstreamId": "wstr-abc"}],
                "totalCount": 1,
                "page": 1,
                "pageSize": 1000,
                "hasMore": False,
            },
        )

        response = await client.get_workstream_interactions()
        assert len(response.interactions) == 1
        assert response.interactions[0].id == "int-1"


@pytest.mark.asyncio
async def test_heartbeat_forces_token_refresh_on_401():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api",
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
                json={"access_token": build_token({"participant_did": "did:test:heartbeat"}), "expires_in": 300},
            ),
            Response(
                200,
                json={"access_token": build_token({"participant_did": "did:test:refresh"}), "expires_in": 300},
            ),
        ]

        heartbeat_route = mock.get("/api/v1/session/heartbeat")

        async def heartbeat_side_effect(_request):
            if heartbeat_route.call_count == 0:
                return Response(401, json={"code": "SESSION_EXPIRED"})
            return Response(200, json={"status": "ok"})

        heartbeat_route.side_effect = heartbeat_side_effect

        await client.init()
        await asyncio.sleep(0.2)
        await client.aclose()

    assert token_route.call_count >= 2
