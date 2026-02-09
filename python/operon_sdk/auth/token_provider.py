from __future__ import annotations

"""Authentication helpers for the Operon Python SDK."""

import asyncio
import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

from ..config import OperonConfig
from ..errors import ApiError, TransportError, ValidationError


@dataclass(slots=True)
class TokenClaims:
    """Known Operon claims extracted from a JWT payload."""

    participant_did: str = ""
    workstream_id: str = ""
    customer_id: str = ""
    workspace_id: str = ""
    email: str = ""
    name: str = ""
    tenant_ids: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    member_id: str = ""
    session_id: str = ""
    org_id: str = ""
    participant_id: str = ""
    client_id: str = ""
    authorized_party: str = ""
    expires_at_unix: int = 0


@dataclass(slots=True)
class AccessToken:
    """Container for issued OAuth tokens and key claims."""

    value: str
    expires_at: datetime
    participant_did: str = ""
    workstream_id: str = ""
    customer_id: str = ""
    workspace_id: str = ""
    email: str = ""
    name: str = ""
    tenant_ids: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    member_id: str = ""
    session_id: str = ""
    org_id: str = ""
    participant_id: str = ""
    client_id: str = ""
    authorized_party: str = ""
    expires_at_unix: int = 0


def _as_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def _as_str_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value:
        text = _as_str(item).strip()
        if text:
            out.append(text)
    return out


def decode_token_claims(token: str) -> TokenClaims:
    """Decode a JWT payload and return known Operon claims."""

    parts = token.split(".")
    if len(parts) < 2:
        return TokenClaims()

    payload_segment = parts[1]
    padding = "=" * (-len(payload_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_segment + padding)
    except Exception:  # noqa: BLE001
        try:
            decoded = base64.b64decode(payload_segment)
        except Exception:  # noqa: BLE001
            return TokenClaims()

    try:
        data = json.loads(decoded.decode())
    except Exception:  # noqa: BLE001
        return TokenClaims()

    if not isinstance(data, dict):
        return TokenClaims()

    workstream = _as_str(data.get("workstream_id"))
    if not workstream:
        workstream = _as_str(data.get("channel_id"))

    exp_raw = data.get("exp")
    expires_at_unix = 0
    if isinstance(exp_raw, (int, float)):
        expires_at_unix = int(exp_raw)

    return TokenClaims(
        participant_did=_as_str(data.get("participant_did")).strip(),
        workstream_id=workstream.strip(),
        customer_id=_as_str(data.get("customer_id")).strip(),
        workspace_id=_as_str(data.get("workspace_id")).strip(),
        email=_as_str(data.get("email")).strip(),
        name=_as_str(data.get("name")).strip(),
        tenant_ids=_as_str_list(data.get("tenant_ids")),
        roles=_as_str_list(data.get("roles")),
        member_id=_as_str(data.get("member_id")).strip(),
        session_id=_as_str(data.get("session_id")).strip(),
        org_id=_as_str(data.get("org_id")).strip(),
        participant_id=_as_str(data.get("participant_id")).strip(),
        client_id=_as_str(data.get("client_id")).strip(),
        authorized_party=_as_str(data.get("azp")).strip(),
        expires_at_unix=expires_at_unix,
    )


class ClientCredentialsTokenProvider:
    """Fetches and caches access tokens using the client credentials flow."""

    def __init__(self, config: OperonConfig, *, client: Optional[httpx.AsyncClient] = None) -> None:
        self._config = config
        self._client = client or httpx.AsyncClient(timeout=config.http_timeout)
        self._lock = asyncio.Lock()
        self._cached: Optional[AccessToken] = None

    async def get_token(self) -> AccessToken:
        """Return a valid access token, refreshing near expiry."""

        async with self._lock:
            if self._cached and self._cached.expires_at - timedelta(
                seconds=self._config.token_leeway
            ) > datetime.now(timezone.utc):
                return self._cached

            token = await self._fetch_token()
            self._cached = token
            return token

    async def clear(self) -> None:
        """Purge cached token; next request forces refresh."""

        async with self._lock:
            self._cached = None

    async def force_refresh(self) -> AccessToken:
        """Mint a new token and replace cache regardless of current token expiry."""

        async with self._lock:
            token = await self._fetch_token()
            self._cached = token
            return token

    async def _fetch_token(self) -> AccessToken:
        params = self._build_request_params()
        try:
            response = await self._client.post(self._config.token_url, **params)
        except httpx.HTTPError as exc:
            raise TransportError("failed to request access token", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError.from_response(response)

        payload = response.json()
        token_value = payload.get("access_token")
        if not token_value:
            raise ValidationError("token response missing access_token")

        expires_in = payload.get("expires_in", 60)
        if not isinstance(expires_in, (int, float)):
            expires_in = 60

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=max(int(expires_in), 1))
        claims = decode_token_claims(token_value)

        return AccessToken(
            value=token_value,
            expires_at=expires_at,
            participant_did=claims.participant_did,
            workstream_id=claims.workstream_id,
            customer_id=claims.customer_id,
            workspace_id=claims.workspace_id,
            email=claims.email,
            name=claims.name,
            tenant_ids=list(claims.tenant_ids),
            roles=list(claims.roles),
            member_id=claims.member_id,
            session_id=claims.session_id,
            org_id=claims.org_id,
            participant_id=claims.participant_id,
            client_id=claims.client_id,
            authorized_party=claims.authorized_party,
            expires_at_unix=claims.expires_at_unix,
        )

    def _build_request_params(self) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        token_url = self._config.token_url
        is_legacy = "/v1/session/m2m" in token_url

        if is_legacy:
            body: Dict[str, Any] = {
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "grant_type": "client_credentials",
            }
            if self._config.scope:
                body["scope"] = self._config.scope
            if self._config.audience:
                body["audience"] = self._config.audience
            return {"json": body, "headers": headers}

        form: List[tuple[str, str]] = [("grant_type", "client_credentials")]
        if self._config.scope:
            form.append(("scope", self._config.scope))
        for audience in self._config.audience:
            form.append(("audience", audience))

        encoded = urlencode(form, doseq=True)
        credentials = f"{self._config.client_id}:{self._config.client_secret}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        return {"content": encoded.encode(), "headers": headers}


__all__ = [
    "AccessToken",
    "ClientCredentialsTokenProvider",
    "TokenClaims",
    "decode_token_claims",
]
