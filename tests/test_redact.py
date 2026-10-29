"""Schwärzung von Secrets in Daten, Freitext und Fehlermeldungen."""

import httpx
from conftest import DIRECT_KEY, SM_KEY

from unifi_mcp import redact, transport


def test_mask_nested_secret_fields():
    data = {"name": "Gast", "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": "geheim-123",
                                                       "presharedKeys": [{"network": {"type": "NATIVE"}, "passphrase": "ppsk-1"}]},
            "radius": {"sharedSecret": "radius-geheim"}, "x_password": "pw", "privateKey": "wg-key", "empty": {"passphrase": ""}}
    masked = redact.mask_secrets(data)
    assert masked["securityConfiguration"]["passphrase"] == "***"
    assert masked["securityConfiguration"]["presharedKeys"][0]["passphrase"] == "***"
    assert masked["radius"]["sharedSecret"] == "***" and masked["x_password"] == "***" and masked["privateKey"] == "***"
    assert masked["empty"]["passphrase"] == "" and masked["name"] == "Gast"
    assert redact.mask_secrets(data, reveal=True) == data


def test_redact_known_secret_values_and_headers():
    text = f"X-API-Key: {SM_KEY} key={DIRECT_KEY} Authorization: Bearer abcdefghijklmnop"
    out = redact.redact_text(text)
    assert SM_KEY not in out and DIRECT_KEY not in out and "abcdefghijklmnop" not in out


def test_error_message_without_body_secrets():
    resp = httpx.Response(401, json={"statusCode": 401, "statusName": "UNAUTHORIZED", "code": "api.authentication.missing-credentials",
                                     "message": f"bad key {DIRECT_KEY}"})
    msg = transport.error_message(resp, "Network API 'Kunde B'")
    assert "HTTP 401" in msg and "UNAUTHORIZED" in msg and DIRECT_KEY not in msg


def test_clean_removes_control_and_bidi_characters():
    assert redact.clean({"name": "AP\x1b[2J‮Empfang\x00"}) == {"name": "AP[2JEmpfang"}
