"""Schreibende Aktionen: Schreibrechte, confirm-Vorschau, Ausführung, Audit-Log, Legacy-Pflicht."""

import json

import pytest
from conftest import (
    CLIENT_WIFI, CLOUD_NET, DEVICE_SW, DEVICE_SW_DETAIL, DIRECT_NET, DIRECT_URL, SITE_ID, SITE_ID_B, WLAN, page, written,
)
from mcp.server.mcpserver.exceptions import ToolError

from unifi_mcp.app import mcp


async def call(name, **args):
    result = await mcp.call_tool(name, args)
    return json.loads(result.content[0].text)


async def audit(console):
    return (await call("get_audit_log", console=console))["entries"]


async def test_writes_disabled_blocks_even_preview(mock):
    with pytest.raises(ToolError, match="writes_enabled=false"):
        await call("device_restart", console="Kunde A", device="Switch Buero")
    assert written(mock) == []


async def test_device_restart_preview_then_execute(direct_site, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices").respond(200, json=page([DEVICE_SW]))
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}").respond(200, json=DEVICE_SW_DETAIL)
    action = mock.post(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}/actions").respond(200, json={})
    out = await call("device_restart", console="Kunde B", device="switch buero")
    assert out["preview"] is True and out["target"]["name"] == "Switch Buero" and written(mock) == []
    for value in ("true", 1):
        with pytest.raises(ToolError):
            await call("device_restart", console="Kunde B", device="Switch Buero", confirm=value)
    out = await call("device_restart", console="Kunde B", device="Switch Buero", confirm=True)
    assert out["executed"] is True
    assert json.loads(action.calls[0].request.content) == {"action": "RESTART"}
    entry = (await audit("Kunde B"))[0]
    assert entry["action"] == "device_restart" and entry["result"] == "succeeded" and "Switch Buero" in entry["target"]


async def test_failed_action_is_audited(direct_site, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}").respond(200, json=DEVICE_SW_DETAIL)
    mock.post(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}/actions").respond(
        400, json={"statusCode": 400, "statusName": "BAD_REQUEST", "message": "Device is offline"})
    with pytest.raises(ToolError, match="HTTP 400"):
        await call("device_restart", console="Kunde B", device=DEVICE_SW["id"], confirm=True)
    assert (await audit("Kunde B"))[0]["result"] == "failed"


async def test_port_power_cycle_checks_poe(direct_site, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}").respond(200, json=DEVICE_SW_DETAIL)
    action = mock.post(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}/interfaces/ports/1/actions").respond(200, json={})
    with pytest.raises(ToolError, match="kein PoE"):
        await call("port_power_cycle", console="Kunde B", device=DEVICE_SW["id"], port=2, confirm=True)
    with pytest.raises(ToolError, match="gibt es"):
        await call("port_power_cycle", console="Kunde B", device=DEVICE_SW["id"], port=9, confirm=True)
    await call("port_power_cycle", console="Kunde B", device=DEVICE_SW["id"], port=1, confirm=True)
    assert json.loads(action.calls[0].request.content) == {"action": "POWER_CYCLE"}


async def test_client_block_via_legacy(direct_site, legacy_login, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/clients/{CLIENT_WIFI['id']}").respond(200, json=CLIENT_WIFI)
    cmd = mock.post(f"{DIRECT_URL}/proxy/network/api/s/default/cmd/stamgr").respond(200, json={"meta": {"rc": "ok"}, "data": []})
    await call("client_block", console="Kunde B", client=CLIENT_WIFI["id"], confirm=True)
    await call("client_reconnect", console="Kunde B", client=CLIENT_WIFI["id"], confirm=True)
    await call("client_unblock", console="Kunde B", client="AA:BB:CC:00:00:50", confirm=True)
    bodies = [json.loads(c.request.content) for c in cmd.calls]
    assert bodies == [{"cmd": "block-sta", "mac": "aa:bb:cc:00:00:50"}, {"cmd": "kick-sta", "mac": "aa:bb:cc:00:00:50"},
                      {"cmd": "unblock-sta", "mac": "aa:bb:cc:00:00:50"}]
    assert cmd.calls[0].request.headers["X-CSRF-Token"] == "csrf-test"


async def test_legacy_error_rc_is_reported(direct_site, legacy_login, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/clients/{CLIENT_WIFI['id']}").respond(200, json=CLIENT_WIFI)
    mock.post(f"{DIRECT_URL}/proxy/network/api/s/default/cmd/stamgr").respond(
        200, json={"meta": {"rc": "error", "msg": "api.err.NoPermission"}, "data": []})
    with pytest.raises(ToolError, match="NoPermission"):
        await call("client_block", console="Kunde B", client=CLIENT_WIFI["id"], confirm=True)


async def test_legacy_relogin_once_on_401(direct_site, legacy_login, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/clients/{CLIENT_WIFI['id']}").respond(200, json=CLIENT_WIFI)
    responses = iter([(401, {}), (200, {"meta": {"rc": "ok"}, "data": []})])

    def reply(request):
        import httpx

        status, body = next(responses)
        return httpx.Response(status, json=body)

    mock.post(f"{DIRECT_URL}/proxy/network/api/s/default/cmd/stamgr").mock(side_effect=reply)
    await call("client_reconnect", console="Kunde B", client=CLIENT_WIFI["id"], confirm=True)
    logins = [c for c in mock.calls if str(c.request.url).endswith("/api/auth/login")]
    assert len(logins) == 2


async def test_legacy_disabled_message(cloud_site, mock):
    from unifi_mcp import app

    app.runtime().store.set_writes("Kunde A", True)
    with pytest.raises(ToolError, match="legacy_enabled"):
        await call("client_block", console="Kunde A", client=CLIENT_WIFI["id"], confirm=True)
    assert written(mock) == []


async def test_wlan_set_enabled_sends_full_object(direct_site, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/wifi/broadcasts").respond(200, json=page([WLAN]))
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/wifi/broadcasts/{WLAN['id']}").respond(200, json=WLAN)
    put = mock.put(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/wifi/broadcasts/{WLAN['id']}").respond(200, json=WLAN)
    same = await call("wlan_set_enabled", console="Kunde B", wlan="Gast", enabled=True, confirm=True)
    assert same["executed"] is False and put.calls.call_count == 0
    await call("wlan_set_enabled", console="Kunde B", wlan="Gast", enabled=False, confirm=True)
    body = json.loads(put.calls[0].request.content)
    assert body["enabled"] is False and "id" not in body and "metadata" not in body
    assert body["securityConfiguration"]["passphrase"] == WLAN["securityConfiguration"]["passphrase"]


async def test_create_guest_voucher(direct_site, mock):
    route = mock.post(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/hotspot/vouchers").respond(201, json={"vouchers": [
        {"id": "v1", "code": "1234567890", "timeLimitMinutes": 480, "authorizedGuestLimit": 1, "name": "Event",
         "createdAt": "2026-01-01T00:00:00Z", "authorizedGuestCount": 0, "expired": False}]})
    with pytest.raises(ToolError, match="download_kbps"):
        await call("create_guest_voucher", console="Kunde B", duration_minutes=480, download_kbps=1, confirm=True)
    out = await call("create_guest_voucher", console="Kunde B", duration_minutes=480, uses=1, note="Event",
                     download_kbps=5000, confirm=True)
    assert out["vouchers"][0]["code"] == "1234567890"
    assert json.loads(route.calls[0].request.content) == {"name": "Event", "count": 1, "timeLimitMinutes": 480,
                                                          "authorizedGuestLimit": 1, "rxRateLimitKbps": 5000}


async def test_device_upgrade_only_when_updatable(direct_site, legacy_login, mock):
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}").respond(200, json=DEVICE_SW_DETAIL)
    cmd = mock.post(f"{DIRECT_URL}/proxy/network/api/s/default/cmd/devmgr").respond(200, json={"meta": {"rc": "ok"}, "data": []})
    await call("device_upgrade", console="Kunde B", device=DEVICE_SW["id"], confirm=True)
    assert json.loads(cmd.calls[0].request.content) == {"cmd": "upgrade", "mac": "aa:bb:cc:00:00:01"}
    mock.get(f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/devices/{DEVICE_SW['id']}").respond(
        200, json={**DEVICE_SW_DETAIL, "firmwareUpdatable": False})
    from unifi_mcp import app

    app.runtime().cache.clear()
    with pytest.raises(ToolError, match="kein Firmware-Update"):
        await call("device_upgrade", console="Kunde B", device=DEVICE_SW["id"], confirm=True)


async def test_set_console_writes_needs_confirm_and_is_audited(cloud_site, mock):
    preview = await call("set_console_writes", console="Kunde A", enabled=True)
    assert preview["preview"] is True
    out = await call("set_console_writes", console="Kunde A", enabled=True, confirm=True)
    assert out["writes_enabled"] is True
    entry = (await audit("Kunde A"))[0]
    assert entry["action"] == "set_console_writes" and entry["target"] == "enabled"
    mock.get(f"{CLOUD_NET}/v1/sites/{SITE_ID}/devices/{DEVICE_SW['id']}").respond(200, json=DEVICE_SW_DETAIL)
    preview = await call("device_restart", console="Kunde A", device=DEVICE_SW["id"])
    assert preview["preview"] is True
    await call("set_console_writes", console="Kunde A", enabled=False, confirm=True)
    with pytest.raises(ToolError, match="writes_enabled=false"):
        await call("device_restart", console="Kunde A", device=DEVICE_SW["id"])
