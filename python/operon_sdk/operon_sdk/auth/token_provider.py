from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from ..config import OperonConfig
from ..errors import ApiError, OperonError, TransportError, ValidationError


@dataclass(slots=True)
class AccessToken:
    value: str
    expires_at: datetime
    participant_did: Optional[str]
    channel_id: Optional[str]


class ClientCredentialsTokenProvider:
    def __init__(self, config: OperonConfig, *, client: Optional[httpx.AsyncClient] = None) -> None:
        self._config = config
        self._client = client or httpx.AsyncClient(timeout=config.http_timeout)
        self._lock = asyncio.Lock()
        self._cached: Optional[AccessToken] = None

    async def get_token(self) -> AccessToken:
        async with self._lock:
            if self._cached and self._cached.expires_at - timedelta(seconds=self._config.token_leeway) > datetime.now(timezone.utc):
                return self._cached
            token = await self._fetch_token()
            self._cached = token
            return token

    async def clear(self) -> None:
        async with self._lock:
            self._cached = None

    async def _fetch_token(self) -> AccessToken:
        request = self._build_request()
        try:
            response = await self._client.send(request)
        except httpx.HTTPError as exc:
            raise TransportError("failed to request access token", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError(response.status_code, await self._decode_error_message(response))

        payload = response.json()
        token_value = payload.get("access_token")
        if not token_value:
            raise ValidationError("token response missing access_token")
        expires_in = payload.get("expires_in", 60)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        claims = self._decode_claims(token_value) or {}
        return AccessToken(
            value=token_value,
            expires_at=expires_at,
            participant_did=claims.get("participant_did"),
            channel_id=claims.get("channel_id"),
        )

    def _build_request(self) -> httpx.Request:
        token_url = self._config.token_url
        is_legacy = "/v1/session/m2m" in token_url
        headers = {"Accept": "application/json"}

        if is_legacy:
            body = {
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "grant_type": "client_credentials",
            }
            if self._config.scope:
                body["scope"] = self._config.scope
            if self._config.audience:
                body["audience"] = self._config.audience
            return httpx.Request("POST", token_url, headers=headers, json=body)

        form: List[tuple[str, str]] = [("grant_type", "client_credentials")]
        if self._config.scope:
            form.append(("scope", self._config.scope))
        for audience in self._config.audience:
            form.append(("audience", audience))
        credentials = f"{self._config.client_id}:{self._config.client_secret}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode()
        return httpx.Request("POST", token_url, headers=headers, data=form)

    async def _decode_error_message(self, response: httpx.Response) -> str:
        try:
            payload = response.json()
            message = payload.get("message") if isinstance(payload, dict) else None
            if message:
                return message
            return json.dumps(payload)
        except json.JSONDecodeError:
            body = await response.aread()
            return body.decode()

    @staticmethod
    def _decode_claims(token: str) -> Optional[Dict[str, str]]:
        segments = token.split(".")
        if len(segments) < 2:
            return None
        payload_segment = segments[1]
        padding = "=" * (-len(payload_segment) % 4)
        decoded = base64.urlsafe_b64decode(payload_segment + padding)
        data = json.loads(decoded.decode())
        if not isinstance(data, dict):
            return None
        return {k: str(v) for k, v in data.items() if isinstance(k, str)}


__all__ = ["ClientCredentialsTokenProvider", "AccessToken"]
