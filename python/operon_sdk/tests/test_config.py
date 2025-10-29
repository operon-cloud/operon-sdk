import pytest

from operon_sdk import OperonConfig


def test_defaults():
    config = OperonConfig(client_id="client", client_secret="secret")
    assert config.base_url.endswith("/")
    assert config.token_url.startswith("https://")
    assert config.http_timeout == 30.0
    assert config.token_leeway == 30.0


def test_requires_credentials():
    with pytest.raises(ValueError):
        OperonConfig(client_id="", client_secret="secret")
    with pytest.raises(ValueError):
        OperonConfig(client_id="client", client_secret=" ")
