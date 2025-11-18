import pytest

from operon_sdk import OperonConfig


def test_defaults():
    config = OperonConfig(client_id="client", client_secret="secret")
    assert config.base_url.endswith("/")
    assert config.token_url.startswith("https://")
    assert config.http_timeout == 30.0
    assert config.token_leeway == 30.0
    assert config.session_heartbeat_interval == 0.0
    assert config.session_heartbeat_timeout == 10.0
    assert config.session_heartbeat_url is None


def test_requires_credentials():
    with pytest.raises(ValueError):
        OperonConfig(client_id="", client_secret="secret")
    with pytest.raises(ValueError):
        OperonConfig(client_id="client", client_secret=" ")


def test_heartbeat_defaults_to_base_url():
    config = OperonConfig(
        client_id="client",
        client_secret="secret",
        base_url="https://example.com/api/",
        session_heartbeat_interval=60.0,
    )
    assert config.session_heartbeat_url == "https://example.com/api/v1/session/heartbeat"
