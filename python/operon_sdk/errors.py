"""Error hierarchy used by the Operon Python SDK."""

from __future__ import annotations

import json
from typing import Any

import httpx


class OperonError(Exception):
    """Base error for the Operon SDK."""


class ValidationError(OperonError):
    """Raised when client-side validation fails."""


class TransportError(OperonError):
    """Wraps transport-level failures when calling Operon services."""

    def __init__(self, message: str, *, original: Exception | None = None) -> None:
        super().__init__(message)
        self.original = original


class ApiError(OperonError):
    """Represents an error returned by Operon APIs."""

    def __init__(self, status_code: int, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code

    @classmethod
    def from_response(cls, response: httpx.Response) -> "ApiError":
        status = response.status_code
        code: str | None = None
        message: str = response.reason_phrase or f"HTTP {status}"

        try:
            payload: Any = response.json()
        except json.JSONDecodeError:
            payload = None

        if isinstance(payload, dict):
            if payload.get("code") is not None:
                code = str(payload.get("code"))
            payload_message = payload.get("message")
            if payload_message:
                message = str(payload_message)
            elif not message:
                message = response.text or f"HTTP {status}"
        elif payload is not None:
            message = json.dumps(payload)
        elif response.text:
            message = response.text

        return cls(status, message, code=code)
