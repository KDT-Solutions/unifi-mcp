"""Legacy-API über den Cloud-Connector: Konfiguration, Präfix-Erkennung, hotspot_settings und
Plan guest_access.update. Nur Platzhalterdaten."""

import json

import httpx
import pytest
from conftest import CLOUD_ID, SITE_ID, SM, SM_KEY, page, written
from mcp.server.mcpserver.exceptions import ToolError

from unifi_mcp import app, config
from unifi_mcp.app import mcp
from unifi_mcp.errors import ConfigError

CONNECTOR = f"{SM}/v1/connector/consoles/{CLOUD_ID}"
CLOUD_NET = f"{CONNECTOR}/proxy/network/integration"
GUEST = {
    "_id": "aaaaaaaaaaaaaaaaaaaaaaaa", "key": "guest_access", "site_id": "bbbbbbbbbbbbbbbbbbbbbbbb",
    "portal_enabled": True, "auth": "none", "expire": 480,
    "x_password": "portal-passwort-geheim", "x_stripe_api_key": "sk_test_platzhalter",
    "allowed_subnet_1": "", "restricted_subnet_1": "192.0.2.0/24",
}
OTHER = {"_id": "cccccccccccccccccccccccc", "key": "mgmt", "site_id": "bbbbbbbbbbbbbbbbbbbbbbbb"}


async def call(name, **args):
    result = await mcp.call_tool(name, args)
    return json.loads(result.content[0].text)


@pytest.fixture
def connector_console(monkeypatch):
    consoles = {"consoles": [{"name": "Kunde A", "console_id": CLOUD_ID, "mode": "cloud",
                              "legacy_enabled": True, "writes_enabled": True}]}
    monkeypatch.setenv("CONSOLES_JSON", json.dumps(consoles))
    config.reset()
    app.set_runtime(None)


@pytest.fixture
def connector(mock, connector_console):
    """Site, Präfix /proxy/network liefert 404, /network antwortet (wie beim Art-of-WiFi-Client)."""
    mock.get(f"{CLOUD_NET}/v1/sites").respond(200, json=page([{"id": SITE_ID, "internalReference": "default", "name": "Default"}]))
    mock.get(f"{CONNECTOR}/proxy/network/api/s/default/self").respond(404, json={"code": "not_found"})
    mock.get(f"{CONNECTOR}/network/api/s/default/self").respond(200, json={"meta": {"rc": "ok"}, "data": [{}]})
    state = {"guest": dict(GUEST)}
    mock.get(f"{CONNECTOR}/network/api/s/default/rest/setting").mock(
        side_effect=lambda req: httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [OTHER, state["guest"]]}))

    def put(req):
        state["guest"] = {**json.loads(req.content), "_id": GUEST["_id"], "site_id": GUEST["site_id"]}
        return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [state["guest"]]})

    route = mock.put(f"{CONNECTOR}/network/api/s/default/rest/setting/guest_access/{GUEST['_id']}").mock(side_effect=put)
    return state, route


def test_config_connector_legacy_without_credentials():
    consoles = config.parse_consoles(json.dumps([{"name": "A", "console_id": CLOUD_ID, "legacy_enabled": True}]))
    assert consoles[0].legacy_via_connector is True
    assert consoles[0].public()["legacy_via"] == "connector"


@pytest.mark.parametrize("raw, message", [
    ({"name": "A", "console_id": CLOUD_ID, "legacy_enabled": True, "legacy_username_env": "U", "legacy_password_env": "P"},
     "nur zusammen mit 'base_url'"),
    ({"name": "A", "console_id": CLOUD_ID, "legacy_enabled": True, "base_url": "https://unifi.example.com"},
     "legacy_username_env"),
])
def test_config_connector_legacy_errors(raw, message):
    with pytest.raises(ConfigError, match=message):
        config.parse_consoles(json.dumps([raw]))


async def test_hotspot_settings_via_connector(connector, mock):
    out = await call("hotspot_settings", console="Kunde A")
    text = json.dumps(out)
    assert "portal-passwort-geheim" not in text and "sk_test_platzhalter" not in text
    assert out["settings"]["x_password"] == "***"
    assert out["pre_authorization_fields"] == {"allowed_subnet_1": ""}
    assert out["post_authorization_fields"] == {"restricted_subnet_1": "192.0.2.0/24"}
    legacy_calls = [c.request for c in mock.calls if "/api/s/" in str(c.request.url)]
    assert legacy_calls and all(r.headers["x-api-key"] == SM_KEY for r in legacy_calls)
    assert not any("/api/auth/login" in str(c.request.url) for c in mock.calls)


async def test_hotspot_settings_requires_legacy(mock):
    with pytest.raises(ToolError, match="legacy_enabled"):
        await call("hotspot_settings", console="Kunde A")


async def test_guest_access_plan_executes_and_rolls_back(connector, mock):
    state, put = connector
    plan = await call("prepare_change", console="Kunde A", kind="guest_access.update",
                      changes={"allowed_subnet_1": "192.0.2.81/32"})
    assert plan["diff"] == [{"path": "allowed_subnet_1", "before": "", "after": "192.0.2.81/32"}]
    assert "portal-passwort-geheim" not in json.dumps(plan)
    assert any("Pre-Authorization" in w for w in plan["warnings"])
    assert written(mock) == []
    out = await call("execute_plan", console="Kunde A", plan_id=plan["plan_id"], confirm=True)
    assert out["executed"] is True
    body = json.loads(put.calls[0].request.content)
    assert body["allowed_subnet_1"] == "192.0.2.81/32" and body["key"] == "guest_access"
    assert "_id" not in body and "site_id" not in body
    assert body["x_password"] == "portal-passwort-geheim"  # unverändert mitgeschickt
    back = await call("rollback_change", console="Kunde A", plan_id=plan["plan_id"], confirm=True)
    assert back["executed"] is True and state["guest"]["allowed_subnet_1"] == ""


async def test_guest_access_key_not_changeable(connector):
    with pytest.raises(ToolError, match="'key'"):
        await call("prepare_change", console="Kunde A", kind="guest_access.update", changes={"key": "mgmt"})


async def test_connector_unreachable(mock, connector_console):
    mock.get(f"{CLOUD_NET}/v1/sites").respond(200, json=page([{"id": SITE_ID, "internalReference": "default", "name": "Default"}]))
    mock.get(f"{CONNECTOR}/proxy/network/api/s/default/self").respond(404)
    mock.get(f"{CONNECTOR}/network/api/s/default/self").respond(200, text="<html></html>",
                                                                  headers={"content-type": "text/html"})
    with pytest.raises(ToolError, match="nicht erreichbar"):
        await call("hotspot_settings", console="Kunde A")
