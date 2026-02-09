from __future__ import annotations

"""PAT session validation helper for Operon client API."""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from .auth.token_provider import decode_token_claims
from .config import DEFAULT_BASE_URL, DEFAULT_HTTP_TIMEOUT
from .errors import ApiError, TransportError, ValidationError
from .models import SessionInfo


@dataclass(slots=True)
class SessionValidationConfig:
    """Controls how PAT validation requests are issued."""

    base_url: str = DEFAULT_BASE_URL
    http_timeout: float = DEFAULT_HTTP_TIMEOUT
    http_client: Optional[httpx.AsyncClient] = None


async def validate_session(cfg: SessionValidationConfig, pat: str) -> SessionInfo:
    """Validate a PAT and return normalized session metadata."""

    pat = pat.strip()
    if not pat:
        raise ValidationError("pat is required")

    base_url = (cfg.base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        raise ValidationError(f"invalid base URL: {cfg.base_url}")

    client = cfg.http_client or httpx.AsyncClient(timeout=cfg.http_timeout)
    owns = cfg.http_client is None

    try:
        try:
            response = await client.get(
                f"{base_url}/v1/session/validate",
                headers={"Authorization": f"Bearer {pat}", "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise TransportError("perform validation request", original=exc) from exc

        if response.status_code >= 400:
            raise ApiError.from_response(response)

        raw_payload = response.json()
        payload: Dict[str, Any] = raw_payload if isinstance(raw_payload, dict) else {}
        claims = decode_token_claims(pat)

        expires_at = None
        if claims.expires_at_unix > 0:
            expires_at = datetime.fromtimestamp(claims.expires_at_unix, tz=timezone.utc)

        expires_in_seconds = 0
        if expires_at is not None:
            remaining = int((expires_at - datetime.now(timezone.utc)).total_seconds())
            expires_in_seconds = max(remaining, 0)

        feature_flags = payload.get("feature_flags")
        if not isinstance(feature_flags, dict):
            feature_flags = {}

        roles = payload.get("roles")
        if not isinstance(roles, list):
            roles = []

        return SessionInfo(
            user_id=str(payload.get("user_id") or ""),
            email=str(payload.get("email") or ""),
            name=str(payload.get("name") or ""),
            customer_id=str(payload.get("customer_id") or ""),
            roles=[str(role) for role in roles],
            feature_flags=feature_flags,
            workstream_id=claims.workstream_id,
            workspace_id=claims.workspace_id,
            participant_did=claims.participant_did,
            participant_id=claims.participant_id,
            client_id=claims.client_id or claims.authorized_party,
            session_id=claims.session_id,
            expires_at=expires_at,
            expires_in_seconds=expires_in_seconds,
        )
    finally:
        if owns:
            await client.aclose()


__all__ = ["SessionValidationConfig", "validate_session"]
