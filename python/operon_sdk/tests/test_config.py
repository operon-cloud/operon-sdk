from __future__ import annotations

import pytest

from operon_sdk import OperonConfig
from operon_sdk.config import (
    DEFAULT_BASE_URL,
    DEFAULT_HEARTBEAT_TIMEOUT,
    DEFAULT_TOKEN_LEEWAY,
    DEFAULT_TOKEN_URL,
)


def test_defaults():
    config = OperonConfig(client_id="client", client_secret="secret")
    assert config.base_url == DEFAULT_BASE_URL
    assert config.token_url == DEFAULT_TOKEN_URL
    assert config.token_leeway == DEFAULT_TOKEN_LEEWAY
    assert config.signing_algorithm == "EdDSA"
    assert config.session_heartbeat_interval == 0.0
    assert config.session_heartbeat_timeout == 0.0
    assert config.session_heartbeat_url == ""


def test_requires_credentials():
    with pytest.raises(ValueError):
        OperonConfig(client_id="", client_secret="secret")
    with pytest.raises(ValueError):
        OperonConfig(client_id="client", client_secret=" ")


def test_rejects_unsupported_signing_algorithm():
    with pytest.raises(ValueError):
        OperonConfig(client_id="client", client_secret="secret", signing_algorithm="rsa")


def test_heartbeat_defaults_to_base_url_when_enabled():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api/",
        session_heartbeat_interval=60.0,
    )
    assert config.base_url == "https://example.com/api"
    assert config.session_heartbeat_timeout == DEFAULT_HEARTBEAT_TIMEOUT
    assert config.session_heartbeat_url == "https://example.com/api/v1/session/heartbeat"


def test_token_leeway_defaults_when_non_positive():
    config = OperonConfig(client_id="client", client_secret="secret", token_leeway=0)
    assert config.token_leeway == DEFAULT_TOKEN_LEEWAY
