"""prepare_change / execute_plan / rollback_change: Diff, Maskierung, Sicherung, Ablauf, Einmaligkeit."""

import copy
import json
import os
import time

import pytest
from conftest import CLOUD_NET, DIRECT_NET, DIRECT_URL, NETWORK, SITE_ID, SITE_ID_B, WLAN, page, written
from mcp.server.mcpserver.exceptions import ToolError

from unifi_mcp import app
from unifi_mcp.app import mcp

WLAN_URL = f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/wifi/broadcasts"
NET_URL = f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/networks"


async def call(name, **args):
    result = await mcp.call_tool(name, args)
    return json.loads(result.content[0].text)


@pytest.fixture
def wlan(direct_site, mock):
    state = {"current": copy.deepcopy(WLAN)}
    mock.get(WLAN_URL).respond(200, json=page([WLAN]))
    mock.get(f"{WLAN_URL}/{WLAN['id']}").mock(side_effect=lambda req: __import__("httpx").Response(200, json=state["current"]))

    def put(req):
        import httpx

        state["current"] = {**json.loads(req.content), "id": WLAN["id"], "metadata": WLAN["metadata"]}
        return httpx.Response(200, json=state["current"])

    route = mock.put(f"{WLAN_URL}/{WLAN['id']}").mock(side_effect=put)
    return state, route


async def test_requires_writes(mock):
    with pytest.raises(ToolError, match="writes_enabled=false"):
        await call("prepare_change", console="Kunde A", kind="wlan.update", target="Gast", changes={"hideName": True})


async def test_set_passphrase_plan_masks_and_executes(wlan, env, mock):
    state, put = wlan
    plan = await call("prepare_change", console="Kunde B", kind="wlan.set_passphrase", target="Gast",
                      changes={"passphrase": "neues-passwort-2026"})
    text = json.dumps(plan)
    assert "neues-passwort-2026" not in text and WLAN["securityConfiguration"]["passphrase"] not in text
    assert plan["diff"] == [{"path": "securityConfiguration.passphrase", "before": "***", "after": "*** (geändert)"}]
    assert written(mock) == []
    preview = await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"])
    assert preview["preview"] is True and written(mock) == []
    out = await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    assert out["executed"] is True
    body = json.loads(put.calls[0].request.content)
    assert body["securityConfiguration"]["passphrase"] == "neues-passwort-2026" and "id" not in body
    backup = os.path.join(env["DATA_DIR"], "backups", f"{plan['plan_id']}.json")
    assert oct(os.stat(backup).st_mode & 0o777) == "0o600"
    with open(backup, encoding="utf-8") as f:
        assert json.load(f)["before"]["securityConfiguration"]["passphrase"] == WLAN["securityConfiguration"]["passphrase"]
    with pytest.raises(ToolError, match="bereits verwendet"):
        await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    # Nach der Ausführung liegt die neue Passphrase nicht mehr im Plan-Speicher.
    stored = app.runtime().store.get_plan(plan["plan_id"])
    assert stored["payload"] is None


@pytest.mark.parametrize("changes, message", [
    ({"passphrase": "kurz"}, "8-63"),
    ({"passphrase": "x" * 64}, "8-63"),
    ({"passphrase": "gültig-aber-ä-umlaut"}, "ASCII"),
    ({"passphrase": "gut-genug-123", "hideName": True}, "changes ="),
])
async def test_passphrase_validation(wlan, changes, message):
    with pytest.raises(ToolError, match=message):
        await call("prepare_change", console="Kunde B", kind="wlan.set_passphrase", target="Gast", changes=changes)


async def test_wlan_update_rejects_passphrase_and_readonly(wlan):
    with pytest.raises(ToolError, match="wlan.set_passphrase"):
        await call("prepare_change", console="Kunde B", kind="wlan.update", target="Gast",
                   changes={"securityConfiguration": {"passphrase": "neues-passwort-2026"}})
    with pytest.raises(ToolError, match="nicht änderbar"):
        await call("prepare_change", console="Kunde B", kind="wlan.update", target="Gast", changes={"id": "x"})
    with pytest.raises(ToolError, match="Keine Änderung"):
        await call("prepare_change", console="Kunde B", kind="wlan.update", target="Gast", changes={"hideName": False})


async def test_execute_aborts_when_state_changed(wlan, mock):
    state, put = wlan
    plan = await call("prepare_change", console="Kunde B", kind="wlan.update", target="Gast", changes={"hideName": True})
    state["current"] = {**state["current"], "clientIsolationEnabled": False}
    with pytest.raises(ToolError, match="seit prepare_change geändert"):
        await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    assert put.calls.call_count == 0
    entries = (await call("get_audit_log", console="Kunde B"))["entries"]
    assert entries[0]["result"] == "aborted_changed"


async def test_plan_expires(wlan, monkeypatch):
    plan = await call("prepare_change", console="Kunde B", kind="wlan.update", target="Gast", changes={"hideName": True})
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 901)
    with pytest.raises(ToolError, match="abgelaufen"):
        await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)


async def test_plan_bound_to_console(wlan):
    plan = await call("prepare_change", console="Kunde B", kind="wlan.update", target="Gast", changes={"hideName": True})
    app.runtime().store.set_writes("Kunde A", True)
    with pytest.raises(ToolError, match="anderen Konsole"):
        await call("execute_plan", console="Kunde A", plan_id=plan["plan_id"], confirm=True)


async def test_rollback_restores_before_state(wlan):
    state, put = wlan
    plan = await call("prepare_change", console="Kunde B", kind="wlan.update", target="Gast",
                      changes={"hideName": True, "broadcastingFrequenciesGHz": [5]})
    await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    assert state["current"]["hideName"] is True
    preview = await call("rollback_change", console="Kunde B", plan_id=plan["plan_id"])
    assert preview["preview"] is True and {d["path"] for d in preview["diff"]} == {"hideName", "broadcastingFrequenciesGHz"}
    await call("rollback_change", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    assert state["current"]["hideName"] is False and state["current"]["broadcastingFrequenciesGHz"] == [2.4, 5]
    with pytest.raises(ToolError, match="rolled_back"):
        await call("rollback_change", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    actions = [e["action"] for e in (await call("get_audit_log", console="Kunde B"))["entries"]]
    assert actions[:3] == ["rollback_change:wlan.update", "execute_plan:wlan.update", "wlan.update"]


async def test_network_create_checks_vlan_and_rolls_back_by_delete(direct_site, mock):
    mock.get(NET_URL).respond(200, json=page([NETWORK]))
    new = {"name": "Kameras", "management": "GATEWAY", "enabled": True, "vlanId": 30,
           "ipv4Configuration": {"autoScaleEnabled": False, "hostIpAddress": "192.0.2.65", "prefixLength": 27}}
    with pytest.raises(ToolError, match="VLAN 20"):
        await call("prepare_change", console="Kunde B", kind="network.create", changes={**new, "vlanId": 20})
    with pytest.raises(ToolError, match="Pflichtfelder"):
        await call("prepare_change", console="Kunde B", kind="network.create", changes={"name": "X"})
    plan = await call("prepare_change", console="Kunde B", kind="network.create", changes=new)
    assert all(d["before"] == "(neu)" for d in plan["diff"])
    created = {**new, "id": "aaaaaaaa-0000-4000-8000-000000000030", "default": False}
    post = mock.post(NET_URL).respond(201, json=created)
    out = await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    assert out["target"]["id"] == created["id"] and json.loads(post.calls[0].request.content) == new
    mock.get(f"{NET_URL}/{created['id']}").respond(200, json=created)
    delete = mock.delete(f"{NET_URL}/{created['id']}").respond(204)
    preview = await call("rollback_change", console="Kunde B", plan_id=plan["plan_id"])
    assert preview["action"] == "Objekt löschen"
    await call("rollback_change", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    assert delete.calls.call_count == 1


async def test_firewall_policy_update_merges_nested(direct_site, mock):
    policy = {"id": "p1", "index": 3, "name": "Block Gast", "enabled": True, "action": {"type": "BLOCK"},
              "source": {"zoneId": "z1", "trafficFilter": None}, "destination": {"zoneId": "z2"},
              "ipProtocolScope": {"ipVersion": "IPV4"}, "loggingEnabled": False, "metadata": {"origin": "USER_DEFINED"}}
    base = f"{DIRECT_NET}/v1/sites/{SITE_ID_B}/firewall/policies"
    mock.get(base).respond(200, json=page([policy]))
    mock.get(f"{base}/p1").respond(200, json=policy)
    put = mock.put(f"{base}/p1").respond(200, json=policy)
    plan = await call("prepare_change", console="Kunde B", kind="firewall_policy.update", target="Block Gast",
                      changes={"loggingEnabled": True, "destination": {"zoneId": "z3"}})
    assert {d["path"] for d in plan["diff"]} == {"loggingEnabled", "destination.zoneId"}
    await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    body = json.loads(put.calls[0].request.content)
    assert body["destination"] == {"zoneId": "z3"} and body["source"] == {"zoneId": "z1", "trafficFilter": None}
    assert "index" not in body and "metadata" not in body and "id" not in body


async def test_port_forward_requires_legacy(cloud_site, mock):
    app.runtime().store.set_writes("Kunde A", True)
    with pytest.raises(ToolError, match="legacy_enabled"):
        await call("prepare_change", console="Kunde A", kind="port_forward.create",
                   changes={"name": "Web", "dst_port": "443", "fwd": "192.0.2.20", "fwd_port": "443", "proto": "tcp"})


async def test_port_forward_create_via_legacy(direct_site, legacy_login, mock):
    mock.get(f"{DIRECT_URL}/proxy/network/api/s/default/list/portforward").respond(200, json={"meta": {"rc": "ok"}, "data": []})
    body = {"name": "Web", "enabled": True, "dst_port": "443", "fwd": "192.0.2.20", "fwd_port": "443", "proto": "tcp", "src": "any"}
    plan = await call("prepare_change", console="Kunde B", kind="port_forward.create", changes=body)
    assert any("ganzen Internet" in w for w in plan["warnings"])
    post = mock.post(f"{DIRECT_URL}/proxy/network/api/s/default/rest/portforward").respond(
        200, json={"meta": {"rc": "ok"}, "data": [{**body, "_id": "pf1"}]})
    out = await call("execute_plan", console="Kunde B", plan_id=plan["plan_id"], confirm=True)
    assert out["target"]["id"] == "pf1" and json.loads(post.calls[0].request.content) == body


async def test_unknown_kind_and_bad_plan_id(direct_site):
    with pytest.raises(ToolError, match="kind:"):
        await call("prepare_change", console="Kunde B", kind="firewall_policy.delete", changes={"x": 1})
    with pytest.raises(ToolError, match="Ungültige Plan-ID"):
        await call("execute_plan", console="Kunde B", plan_id="../etc/passwd", confirm=True)


async def test_cloud_console_plan_uses_connector(cloud_site, mock):
    app.runtime().store.set_writes("Kunde A", True)
    base = f"{CLOUD_NET}/v1/sites/{SITE_ID}/wifi/broadcasts"
    mock.get(base).respond(200, json=page([WLAN]))
    mock.get(f"{base}/{WLAN['id']}").respond(200, json=WLAN)
    plan = await call("prepare_change", console="Kunde A", kind="wlan.update", target=WLAN["id"], changes={"hideName": True})
    assert plan["target"]["id"] == WLAN["id"]
