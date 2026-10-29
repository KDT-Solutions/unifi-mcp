"""Mehrere Site-Manager-Keys (UI-Konten): jede Konsole nutzt den Key ihres Kontos."""

import json

import httpx
import pytest
from conftest import CLOUD_ID, SM, SM_KEY

from unifi_mcp import app, config
from unifi_mcp.app import mcp
from unifi_mcp.errors import ConfigError

OTHER_ID = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:1000000003"
OTHER_KEY = "test-site-manager-key-konto-b"


@pytest.fixture
def two_accounts(env, monkeypatch):
    consoles = {"consoles": [
        {"name": "Kunde A", "console_id": CLOUD_ID, "mode": "cloud"},
        {"name": "Kunde C", "console_id": OTHER_ID, "mode": "cloud", "site_manager_key_env": "SITE_MANAGER_API_KEY_B"},
    ]}
    env["consoles_file"].write_text(json.dumps(consoles), encoding="utf-8")
    monkeypatch.setenv("SITE_MANAGER_API_KEY_B", OTHER_KEY)
    config.reset()
    app.set_runtime(None)


async def call(name, **args):
    result = await mcp.call_tool(name, args)
    return json.loads(result.content[0].text)


def device(host_id, name, version):
    return {"hostId": host_id, "devices": [{"mac": "AABBCC0000" + name[-2:], "name": name, "status": "online",
                                            "version": version, "isConsole": True, "firmwareStatus": "upToDate"}]}


async def test_each_account_queried_with_own_key_and_hosts(two_accounts, mock):
    def reply(request):
        key = request.headers["X-API-Key"]
        if key == SM_KEY:
            # Konto A sieht nur die eigene Konsole; ein fremder Eintrag würde verworfen.
            return httpx.Response(200, json={"data": [device(CLOUD_ID, "GW-A1", "4.1.13"), device(OTHER_ID, "Fremd-99", "0")]})
        return httpx.Response(200, json={"data": [device(OTHER_ID, "GW-C3", "4.2.0")]})

    route = mock.get(f"{SM}/v1/devices").mock(side_effect=reply)
    out = await call("list_consoles")
    by_name = {c["name"]: c for c in out["consoles"]}
    assert by_name["Kunde A"]["firmware"] == "4.1.13" and by_name["Kunde C"]["firmware"] == "4.2.0"
    requests = {c.request.headers["X-API-Key"]: c.request.url.params.get_list("hostIds[]") for c in route.calls}
    assert requests == {SM_KEY: [CLOUD_ID], OTHER_KEY: [OTHER_ID]}


async def test_connector_uses_console_account_key(two_accounts, mock):
    base = f"{SM}/v1/connector/consoles/{OTHER_ID}/proxy/network/integration"
    route = mock.get(f"{base}/v1/sites").respond(200, json={"offset": 0, "limit": 200, "count": 0, "totalCount": 0, "data": []})
    await call("list_sites", console="Kunde C")
    assert route.calls[0].request.headers["X-API-Key"] == OTHER_KEY


async def test_one_account_failing_keeps_the_other(two_accounts, mock):
    mock.get(f"{SM}/v1/devices").mock(side_effect=lambda r: httpx.Response(200, json={"data": [device(CLOUD_ID, "GW-A1", "4.1.13")]})
                                      if r.headers["X-API-Key"] == SM_KEY else httpx.Response(401, json={"code": "unauthorized"}))
    out = await call("list_consoles")
    by_name = {c["name"]: c for c in out["consoles"]}
    assert by_name["Kunde A"]["status"] == "online" and by_name["Kunde C"]["status"] == "unbekannt"
    assert "SITE_MANAGER_API_KEY_B" in out["site_manager_error"] and OTHER_KEY not in json.dumps(out)


def test_cloud_with_api_key_env_is_rejected():
    with pytest.raises(ConfigError, match="site_manager_key_env"):
        config.parse_consoles(json.dumps([{"name": "X", "console_id": "A" * 20, "api_key_env": "K"}]))
