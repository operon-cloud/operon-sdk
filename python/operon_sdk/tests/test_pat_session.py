from __future__ import annotations

import base64
import json
import time

import pytest
import respx
from httpx import Response

from operon_sdk import (
    HEADER_OPERON_DID,
    HEADER_OPERON_PAYLOAD_HASH,
    HEADER_OPERON_SIGNATURE,
    HEADER_OPERON_SIGNATURE_ALGO,
    HEADER_OPERON_SIGNATURE_KEY,
    ClientAPIConfig,
    SessionValidationConfig,
    WorkstreamDataConfig,
    fetch_workstream_interactions,
    sign_hash_with_pat,
    submit_transaction_with_pat,
    validate_session,
    validate_signature_with_pat,
)
from operon_sdk.errors import ValidationError
from operon_sdk.models import Signature, TransactionRequest


def build_token(claims: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


@pytest.mark.asyncio
async def test_sign_hash_with_pat_sets_default_key_id_from_claims():
    pat = build_token({"participant_did": "did:test:source"})

    with respx.mock(base_url="https://example.com") as mock:
        mock.post("/api/v1/dids/self/sign").return_value = Response(
            200,
            json={
                "signature": {
                    "algorithm": "EdDSA",
                    "value": "signed",
                    "keyId": "",
                }
            },
        )

        signature = await sign_hash_with_pat(
            ClientAPIConfig(base_url="https://example.com/api"),
            pat,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "EdDSA",
        )

    assert signature.key_id == "did:test:source#keys-1"


@pytest.mark.asyncio
async def test_submit_transaction_with_pat_uses_claim_defaults():
    pat = build_token({"participant_did": "did:test:source", "workstream_id": "wstr-123"})

    with respx.mock(base_url="https://example.com") as mock:
        def txn_callback(request):
            body = json.loads(request.content.decode())
            assert body["workstreamId"] == "wstr-123"
            assert body["sourceDid"] == "did:test:source"
            return Response(
                200,
                json={
                    "id": "txn-1",
                    "correlationId": body["correlationId"],
                    "workstreamId": body["workstreamId"],
                    "interactionId": body["interactionId"],
                    "sourceDid": body["sourceDid"],
                    "targetDid": body["targetDid"],
                    "signature": body["signature"],
                    "payloadHash": body["payloadHash"],
                    "status": "received",
                },
            )

        txn_route = mock.post("/api/v1/transactions")
        txn_route.side_effect = txn_callback

        request = TransactionRequest.new("corr-1", "int-1").with_payload_bytes(b"hello")
        request.target_did = "did:test:target"
        request.signature = Signature(algorithm="EdDSA", value="manual", keyId="did:test:source#keys-1")

        txn = await submit_transaction_with_pat(
            ClientAPIConfig(base_url="https://example.com/api"),
            pat,
            request,
        )

    assert txn.id == "txn-1"


@pytest.mark.asyncio
async def test_fetch_workstream_interactions_with_override():
    pat = build_token({"participant_did": "did:test:source"})

    with respx.mock(base_url="https://example.com") as mock:
        mock.get("/api/v1/workstreams/wstr-override/interactions").return_value = Response(
            200,
            json={
                "interactions": [{"id": "int-1", "workstreamId": "wstr-override"}],
                "totalCount": 1,
                "page": 1,
                "pageSize": 1000,
                "hasMore": False,
            },
        )

        response = await fetch_workstream_interactions(
            WorkstreamDataConfig(base_url="https://example.com/api"),
            pat,
            "wstr-override",
        )

    assert len(response.interactions) == 1
    assert response.interactions[0].id == "int-1"


@pytest.mark.asyncio
async def test_validate_signature_with_pat_hash_mismatch():
    pat = build_token({"participant_did": "did:test:source"})

    with pytest.raises(ValidationError):
        await validate_signature_with_pat(
            ClientAPIConfig(base_url="https://example.com/api"),
            pat,
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
async def test_validate_session_success():
    exp = int(time.time()) + 600
    pat = build_token(
        {
            "participant_did": "did:test:source",
            "participant_id": "part-1",
            "workstream_id": "wstr-1",
            "workspace_id": "wksp-1",
            "session_id": "sess-1",
            "client_id": "client-1",
            "exp": exp,
        }
    )

    with respx.mock(base_url="https://example.com") as mock:
        mock.get("/api/v1/session/validate").return_value = Response(
            200,
            json={
                "user_id": "user-1",
                "email": "user@example.com",
                "name": "User",
                "customer_id": "cust-1",
                "roles": ["sandbox"],
                "feature_flags": {"demo": True},
            },
        )

        info = await validate_session(
            SessionValidationConfig(base_url="https://example.com/api"),
            pat,
        )

    assert info.user_id == "user-1"
    assert info.workstream_id == "wstr-1"
    assert info.participant_did == "did:test:source"
    assert info.client_id == "client-1"
    assert info.expires_in_seconds > 0
