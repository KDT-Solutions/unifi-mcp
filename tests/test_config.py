"""Konsolen-Datei: Validierung, Platzhalter-Beispiel, Fingerprint-Format."""

import json
import os

import pytest

from unifi_mcp import config
from unifi_mcp.errors import ConfigError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse(*consoles):
    return config.parse_consoles(json.dumps({"consoles": list(consoles)}))


def test_example_config_is_valid_and_read_only_by_default():
    with open(os.path.join(ROOT, "config", "consoles.example.json"), encoding="utf-8") as f:
        consoles = config.parse_consoles(f.read())
    assert consoles
    assert not any(c.writes_enabled for c in consoles)
    assert not any(c.legacy_enabled for c in consoles)


def test_defaults_are_read_only():
    (c,) = parse({"name": "Kunde A", "console_id": "A" * 20 + ":1"})
    assert c.mode == "cloud" and c.writes_enabled is False and c.legacy_enabled is False


@pytest.mark.parametrize("entry, message", [
    ({"name": "X", "console_id": "A" * 20, "foo": 1}, "unbekannte Felder"),
    ({"name": "X"}, "console_id"),
    ({"name": "X", "mode": "direct", "api_key_env": "K"}, "base_url"),
    ({"name": "X", "mode": "direct", "base_url": "https://unifi.example.com"}, "api_key_env"),
    ({"name": "X", "mode": "direct", "base_url": "http://unifi.example.com", "api_key_env": "K"}, "https"),
    ({"name": "X", "mode": "direct", "base_url": "https://unifi.example.com/x", "api_key_env": "K"}, "ohne Pfad"),
    ({"name": "X", "console_id": "A" * 20, "api_key_env": "lower-case"}, "Variablenname"),
    ({"name": "X", "console_id": "A" * 20, "writes_enabled": "true"}, "true oder false"),
    ({"name": "X", "console_id": "A" * 20, "legacy_enabled": True}, "base_url"),
    ({"name": "X", "console_id": "A" * 20, "base_url": "https://unifi.example.com", "legacy_enabled": True}, "legacy_username_env"),
    ({"name": "X", "console_id": "A" * 20, "tls_fingerprint": "ab" * 32}, "base_url"),
    ({"name": "X", "mode": "direct", "base_url": "https://192.0.2.1", "api_key_env": "K", "tls_fingerprint": "zz"}, "64 Hex"),
])
def test_invalid_entries(entry, message):
    with pytest.raises(ConfigError, match=message):
        parse(entry)


def test_names_unique_case_insensitive():
    with pytest.raises(ConfigError, match="eindeutig"):
        parse({"name": "Kunde A", "console_id": "A" * 20}, {"name": "kunde a", "console_id": "B" * 20})


def test_fingerprint_normalized():
    raw = ":".join(["AB"] * 32)
    (c,) = parse({"name": "X", "mode": "direct", "base_url": "https://192.0.2.1:8443", "api_key_env": "K",
                  "tls_fingerprint": "sha256:" + raw})
    assert c.tls_fingerprint == "ab" * 32


def test_secrets_never_in_public_view():
    (c,) = parse({"name": "X", "mode": "direct", "base_url": "https://192.0.2.1", "api_key_env": "SECRET_ENV"})
    assert "SECRET_ENV" not in json.dumps(c.public())


def test_missing_file_message(tmp_path):
    with pytest.raises(ConfigError, match="nicht gefunden"):
        config.load_consoles(str(tmp_path / "fehlt.json"))


def test_console_secrets_json(monkeypatch):
    monkeypatch.setenv("UNIFI_CONSOLE_SECRETS", '{"UNIFI_KEY_KUNDE_C": "wert-aus-json-123"}')
    config.reset()
    cfg = config.settings()
    assert cfg.secret("UNIFI_KEY_KUNDE_C") == "wert-aus-json-123"
    assert "wert-aus-json-123" in cfg.secret_values()
    monkeypatch.setenv("UNIFI_KEY_KUNDE_C", "wert-aus-env-456")
    assert cfg.secret("UNIFI_KEY_KUNDE_C") == "wert-aus-env-456"


@pytest.mark.parametrize("raw", ["{kein json", '["a"]', '{"klein": "x"}', '{"A": 1}'])
def test_console_secrets_invalid(monkeypatch, raw):
    monkeypatch.setenv("UNIFI_CONSOLE_SECRETS", raw)
    config.reset()
    with pytest.raises(ConfigError, match="UNIFI_CONSOLE_SECRETS") as exc:
        config.settings()
    assert raw not in str(exc.value)


def test_consoles_json_takes_precedence(tmp_path):
    text = json.dumps({"consoles": [{"name": "Kunde C", "console_id": "C" * 20}]})
    (c,) = config.load_consoles(str(tmp_path / "fehlt.json"), text)
    assert c.name == "Kunde C"
