from __future__ import annotations

import base64
import json

import pytest
import respx
from httpx import Response

from operon_sdk import OperonConfig
from operon_sdk.auth.token_provider import ClientCredentialsTokenProvider, decode_token_claims


def build_token(claims: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


@pytest.mark.asyncio
async def test_token_cached_until_expiry():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        token_url="https://example.com/token",
    )

    provider = ClientCredentialsTokenProvider(config)
    with respx.mock(base_url="https://example.com") as mock:
        route = mock.post("/token")
        route.return_value = Response(
            200,
            json={
                "access_token": build_token(
                    {
                        "participant_did": "did:test:123",
                        "workstream_id": "wstr-1",
                        "customer_id": "cust-1",
                        "workspace_id": "wksp-1",
                    }
                ),
                "expires_in": 300,
            },
        )

        token1 = await provider.get_token()
        token2 = await provider.get_token()

    assert route.call_count == 1
    assert token1.value == token2.value
    assert token1.participant_did == "did:test:123"
    assert token1.workstream_id == "wstr-1"
    assert token1.customer_id == "cust-1"
    assert token1.workspace_id == "wksp-1"


@pytest.mark.asyncio
async def test_force_refresh_replaces_cached_token():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        token_url="https://example.com/token",
    )

    provider = ClientCredentialsTokenProvider(config)
    with respx.mock(base_url="https://example.com") as mock:
        route = mock.post("/token")
        route.side_effect = [
            Response(200, json={"access_token": build_token({"participant_did": "did:one"}), "expires_in": 300}),
            Response(200, json={"access_token": build_token({"participant_did": "did:two"}), "expires_in": 300}),
        ]

        token1 = await provider.get_token()
        token2 = await provider.force_refresh()

    assert route.call_count == 2
    assert token1.value != token2.value
    assert token2.participant_did == "did:two"


def test_decode_token_claims_falls_back_to_channel_id():
    token = build_token({"channel_id": "legacy-channel"})
    claims = decode_token_claims(token)
    assert claims.workstream_id == "legacy-channel"


def test_decode_token_claims_invalid_token():
    claims = decode_token_claims("invalid")
    assert claims.participant_did == ""
    assert claims.workstream_id == ""
