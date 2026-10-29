"""Gemeinsame Fixtures. Alle HTTP-Requests laufen gegen respx-Mocks, nie gegen echte APIs.
Nur Platzhalterdaten: example.com, 192.0.2.0/24, 'Kunde A'."""

import json
import os
import sys

import pytest
import respx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unifi_mcp.server  # noqa: E402,F401 - registriert alle Tools

SM = "https://api.ui.com"
CLOUD_ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1000000001"
DIRECT_ID = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:1000000002"
CLOUD_NET = f"{SM}/v1/connector/consoles/{CLOUD_ID}/proxy/network/integration"
DIRECT_URL = "https://unifi.example.com"
DIRECT_NET = f"{DIRECT_URL}/proxy/network/integration"
SITE_ID = "11111111-1111-4111-8111-111111111111"
SITE_ID_B = "22222222-2222-4222-8222-222222222222"
SM_KEY = "test-site-manager-key-value"
DIRECT_KEY = "test-integration-key-value"
LEGACY_PASSWORD = "test-legacy-password-value"
MCP_KEY = "test-mcp-api-key"

CONSOLES = {
    "consoles": [
        {"name": "Kunde A", "console_id": CLOUD_ID, "mode": "cloud"},
        {"name": "Kunde B", "console_id": DIRECT_ID, "mode": "direct", "base_url": DIRECT_URL,
         "api_key_env": "UNIFI_KEY_KUNDE_B", "writes_enabled": True, "legacy_enabled": True,
         "legacy_username_env": "UNIFI_LEGACY_USER_KUNDE_B", "legacy_password_env": "UNIFI_LEGACY_PASSWORD_KUNDE_B"},
    ]
}


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    path = tmp_path / "consoles.json"
    path.write_text(json.dumps(CONSOLES), encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    values = {
        "MCP_API_KEY": MCP_KEY,
        "SITE_MANAGER_API_KEY": SM_KEY,
        "UNIFI_KEY_KUNDE_B": DIRECT_KEY,
        "UNIFI_LEGACY_USER_KUNDE_B": "mcp-readonly",
        "UNIFI_LEGACY_PASSWORD_KUNDE_B": LEGACY_PASSWORD,
        "CONSOLES_FILE": str(path),
        "DATA_DIR": str(data),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    for key in ("APP_VERSION", "GIT_SHA", "BUILD_TIME", "SITE_MANAGER_URL", "CACHE_TTL_SECONDS", "CONSOLES_JSON"):
        monkeypatch.delenv(key, raising=False)
    from unifi_mcp import app, config, transport

    monkeypatch.setattr(transport, "MAX_RETRY_WAIT", 0)
    config.reset()
    app.set_runtime(None)
    yield {"consoles_file": path, "data_dir": data, **values}
    config.reset()
    app.set_runtime(None)


@pytest.fixture
def mock():
    """respx-Router: jeder nicht gemockte Request schlägt fehl."""
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        yield router


def page(items):
    return {"offset": 0, "limit": 200, "count": len(items), "totalCount": len(items), "data": items}


def written(router):
    """Alle schreibenden Requests ausser dem Legacy-Login."""
    return [c.request for c in router.calls
            if c.request.method in ("POST", "PUT", "PATCH", "DELETE") and not str(c.request.url).endswith("/api/auth/login")]


DEVICE_SW = {
    "id": "33333333-3333-4333-8333-333333333333", "name": "Switch Buero", "model": "USW-Lite-8-PoE",
    "macAddress": "aa:bb:cc:00:00:01", "ipAddress": "192.0.2.11", "state": "ONLINE", "supported": True,
    "firmwareVersion": "7.1.26", "firmwareUpdatable": True, "features": ["switching"], "interfaces": ["ports"],
}
DEVICE_AP = {
    "id": "44444444-4444-4444-8444-444444444444", "name": "AP Empfang", "model": "U6-Lite",
    "macAddress": "aa:bb:cc:00:00:02", "ipAddress": "192.0.2.12", "state": "OFFLINE", "supported": True,
    "firmwareVersion": "6.6.77", "firmwareUpdatable": False, "features": ["accessPoint"], "interfaces": ["radios"],
}
DEVICE_SW_DETAIL = {
    **{k: v for k, v in DEVICE_SW.items() if k not in ("features", "interfaces")},
    "configurationId": "cfg", "features": {"switching": {"lags": []}},
    "interfaces": {"ports": [
        {"idx": 1, "state": "UP", "connector": "RJ45", "maxSpeedMbps": 1000, "speedMbps": 1000,
         "poe": {"enabled": True, "standard": "802.3at", "state": "UP", "type": 2}},
        {"idx": 2, "state": "DOWN", "connector": "RJ45", "maxSpeedMbps": 1000},
    ]},
    "uplink": {"deviceId": "55555555-5555-4555-8555-555555555555"},
}
CLIENT_WIFI = {
    "id": "66666666-6666-4666-8666-666666666666", "name": "Laptop-01", "type": "WIRELESS",
    "ipAddress": "192.0.2.50", "macAddress": "aa:bb:cc:00:00:50", "connectedAt": "2026-01-01T08:00:00Z",
    "uplinkDeviceId": DEVICE_AP["id"], "access": {"type": "DEFAULT"},
}
CLIENT_WIRED = {
    "id": "77777777-7777-4777-8777-777777777777", "name": "Drucker", "type": "WIRED",
    "ipAddress": "192.0.2.60", "macAddress": "aa:bb:cc:00:00:60", "uplinkDeviceId": DEVICE_SW["id"],
    "access": {"type": "DEFAULT"},
}
WLAN = {
    "id": "88888888-8888-4888-8888-888888888888", "name": "Gast", "type": "STANDARD", "enabled": True,
    "metadata": {"origin": "USER_DEFINED"}, "network": {"type": "SPECIFIC", "networkId": "99999999-9999-4999-8999-999999999999"},
    "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": "geheimes-wlan-passwort", "pmfMode": "OPTIONAL"},
    "broadcastingFrequenciesGHz": [2.4, 5], "hideName": False, "clientIsolationEnabled": True,
    "channel2gLockedTo6": False, "dtimPeriod2gLockedTo3": False, "multicastToUnicastConversionEnabled": False,
    "uapsdEnabled": False,
}
NETWORK = {
    "id": "99999999-9999-4999-8999-999999999999", "name": "Gaeste", "management": "GATEWAY", "enabled": True,
    "vlanId": 20, "default": False, "metadata": {"origin": "USER_DEFINED"},
    "ipv4Configuration": {"autoScaleEnabled": False, "hostIpAddress": "192.0.2.129", "prefixLength": 25,
                          "dhcpConfiguration": {"mode": "SERVER", "ipAddressRange": {"start": "192.0.2.150", "stop": "192.0.2.250"},
                                                "leaseTimeSeconds": 86400}},
    "isolationEnabled": True, "internetAccessEnabled": True,
}


@pytest.fixture
def cloud_site(mock):
    mock.get(f"{CLOUD_NET}/v1/sites").respond(200, json=page([{"id": SITE_ID, "internalReference": "default", "name": "Default"}]))
    return mock


@pytest.fixture
def direct_site(mock):
    mock.get(f"{DIRECT_NET}/v1/sites").respond(200, json=page([{"id": SITE_ID_B, "internalReference": "default", "name": "Hauptsitz"}]))
    return mock


@pytest.fixture
def legacy_login(mock):
    mock.post(f"{DIRECT_URL}/api/auth/login").respond(
        200, json={"username": "mcp-readonly"}, headers={"Set-Cookie": "TOKEN=jwt-test; Path=/; Secure; HttpOnly",
                                                          "X-CSRF-Token": "csrf-test"})
    return mock
