from __future__ import annotations

"""Configuration helpers for the Operon Python SDK."""

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin, urlparse

DEFAULT_BASE_URL = "https://api.operon.cloud/client-api/"
DEFAULT_TOKEN_URL = "https://auth.operon.cloud/oauth2/token"
DEFAULT_HTTP_TIMEOUT = 30.0
DEFAULT_TOKEN_LEEWAY = 30.0


def _normalise_base(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"invalid base URL: {url}")
    if not url.endswith("/"):
        return url + "/"
    return url


def _normalise_token(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"invalid token URL: {url}")
    return url


def _trim_scope(scope: Optional[str]) -> Optional[str]:
    if scope is None:
        return None
    scope = scope.strip()
    return scope or None


def _trim_audience(audience: Optional[List[str]]) -> List[str]:
    if not audience:
        return []
    return [value.strip() for value in audience if value.strip()]


@dataclass(slots=True)
class OperonConfig:
    """Holds configuration required to talk to Operon services."""

    client_id: str
    client_secret: str
    base_url: str = DEFAULT_BASE_URL
    token_url: str = DEFAULT_TOKEN_URL
    scope: Optional[str] = None
    audience: List[str] = field(default_factory=list)
    http_timeout: float = DEFAULT_HTTP_TIMEOUT
    token_leeway: float = DEFAULT_TOKEN_LEEWAY
    disable_self_sign: bool = False

    def __post_init__(self) -> None:
        if not self.client_id.strip():
            raise ValueError("client_id is required")
        if not self.client_secret.strip():
            raise ValueError("client_secret is required")

        self.base_url = _normalise_base(self.base_url)
        self.token_url = _normalise_token(self.token_url)
        self.scope = _trim_scope(self.scope)
        self.audience = _trim_audience(self.audience)

        if self.http_timeout <= 0:
            raise ValueError("http_timeout must be > 0")
        if self.token_leeway < 0:
            raise ValueError("token_leeway cannot be negative")

    def api_url(self, path: str) -> str:
        """Resolve an absolute API URL for the provided path."""
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(self.base_url, path)

    @classmethod
    def from_env(
        cls,
        *,
        client_id_env: str = "OPERON_CLIENT_ID",
        client_secret_env: str = "OPERON_CLIENT_SECRET",
    ) -> "OperonConfig":
        """Build a configuration from environment variables."""
        import os

        client_id = os.environ.get(client_id_env)
        client_secret = os.environ.get(client_secret_env)
        if not client_id or not client_secret:
            missing = []
            if not client_id:
                missing.append(client_id_env)
            if not client_secret:
                missing.append(client_secret_env)
            raise ValueError(f"missing environment variables: {', '.join(missing)}")
        return cls(client_id=client_id, client_secret=client_secret)
