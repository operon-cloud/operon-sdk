from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
import respx
from httpx import Response

from operon_sdk import OperonConfig
from operon_sdk.auth.token_provider import AccessToken, ClientCredentialsTokenProvider


def build_token(claims: dict[str, str]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


@pytest.mark.asyncio
async def test_token_cached_until_expiry():
    config = OperonConfig(
        client_id="client", client_secret="secret", token_url="https://example.com/token"
    )

    provider = ClientCredentialsTokenProvider(config)
    with respx.mock(base_url="https://example.com") as mock:
        mock.post("/token").return_value = Response(
            200,
            json={
                "access_token": build_token({"participant_did": "did:test:123"}),
                "expires_in": 120,
            },
        )
        token1 = await provider.get_token()
        token2 = await provider.get_token()

    assert token1.value == token2.value
    assert token1.participant_did == "did:test:123"


@pytest.mark.asyncio
async def test_token_refreshes_when_expiring():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        token_url="https://example.com/token",
        token_leeway=10,
    )

    provider = ClientCredentialsTokenProvider(config)
    with respx.mock(base_url="https://example.com") as mock:
        route = mock.post("/token")
        route.side_effect = [
            Response(
                200,
                json={
                    "access_token": build_token({}),
                    "expires_in": 5,
                },
            ),
            Response(
                200,
                json={
                    "access_token": build_token({"channel_id": "chnl"}),
                    "expires_in": 120,
                },
            ),
        ]

        token1 = await provider.get_token()
        provider._cached = AccessToken(
            value=token1.value,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            participant_did=token1.participant_did,
            channel_id=token1.channel_id,
        )
        token2 = await provider.get_token()

    assert token1.value != token2.value
    assert token2.channel_id == "chnl"


@pytest.mark.asyncio
async def test_force_refresh_replaces_cached_token():
    config = OperonConfig(
        client_id="client", client_secret="secret", token_url="https://example.com/token"
    )
    provider = ClientCredentialsTokenProvider(config)
    with respx.mock(base_url="https://example.com") as mock:
        route = mock.post("/token")
        route.side_effect = [
            Response(
                200,
                json={
                    "access_token": build_token({"participant_did": "did:one"}),
                    "expires_in": 300,
                },
            ),
            Response(
                200,
                json={
                    "access_token": build_token({"participant_did": "did:two"}),
                    "expires_in": 300,
                },
            ),
        ]
        token1 = await provider.get_token()
        token2 = await provider.force_refresh()

    assert token1.value != token2.value
    assert token2.participant_did == "did:two"
