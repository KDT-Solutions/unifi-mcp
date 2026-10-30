"""Schutz des MCP-HTTP-Endpunkts (Bearer-Token, Rate-Limit, fail-safe Start, CORS) und Protokollierung."""

import json
import os
import re

import pytest
from conftest import MCP_KEY
from starlette.testclient import TestClient

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def server():
    from unifi_mcp import server as srv

    return srv


@pytest.fixture
def http_client(server):
    app = server._build_http_app(MCP_KEY)
    with TestClient(app, base_url="https://mcp.example.com") as client:
        yield client


def init_request():
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}


def test_refuses_start_without_api_key(server, monkeypatch):
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="MCP_API_KEY"):
        server.main()
    with pytest.raises(RuntimeError, match="MCP_API_KEY"):
        server._build_http_app("")


def test_request_without_token_is_401(http_client):
    resp = http_client.post("/unifi", json=init_request(), headers=HEADERS)
    assert resp.status_code == 401 and resp.json() == {"error": "unauthorized"}


@pytest.mark.parametrize("auth", ["Bearer wrong", f"bearer {MCP_KEY}", MCP_KEY, f"Bearer {MCP_KEY}x", "Basic abc"])
def test_wrong_token_is_401(http_client, auth):
    assert http_client.post("/unifi", json=init_request(), headers={**HEADERS, "Authorization": auth}).status_code == 401


def test_valid_token_passes_on_mcp_path(http_client):
    resp = http_client.post("/unifi", json=init_request(), headers={**HEADERS, "Authorization": f"Bearer {MCP_KEY}"})
    assert resp.status_code == 200
    assert resp.json()["result"]["serverInfo"]["name"] == "unifi-mcp"


def test_healthz_also_needs_token(http_client):
    assert http_client.get("/healthz").status_code == 401
    ok = http_client.get("/healthz", headers={"Authorization": f"Bearer {MCP_KEY}"})
    assert ok.status_code == 200 and ok.json()["status"] == "ok"


def test_rate_limit_for_valid_token(server, monkeypatch):
    monkeypatch.setenv("MCP_RATE_LIMIT_PER_MINUTE", "3")
    from unifi_mcp import config

    config.reset()
    with TestClient(server._build_http_app(MCP_KEY), base_url="https://mcp.example.com") as client:
        codes = [client.get("/healthz", headers={"Authorization": f"Bearer {MCP_KEY}"}).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_rate_limit_for_failed_auth(server, monkeypatch):
    monkeypatch.setenv("MCP_AUTH_FAIL_LIMIT_PER_MINUTE", "2")
    from unifi_mcp import config

    config.reset()
    with TestClient(server._build_http_app(MCP_KEY), base_url="https://mcp.example.com") as client:
        codes = [client.get("/healthz", headers={"Authorization": "Bearer falsch"}).status_code for _ in range(4)]
        # Ein gültiges Token wird vom Fehl-Limit nicht blockiert.
        good = client.get("/healthz", headers={"Authorization": f"Bearer {MCP_KEY}"}).status_code
    assert codes == [401, 401, 429, 429] and good == 200


def test_cors_preflight_without_token(http_client):
    resp = http_client.options("/unifi", headers={"Origin": "https://client.example.com",
                                                  "Access-Control-Request-Method": "POST",
                                                  "Access-Control-Request-Headers": "authorization,content-type"})
    assert resp.status_code == 200 and "access-control-allow-origin" in resp.headers


async def test_tool_call_is_logged_without_secrets(server, capsys):
    from mcp.server.mcpserver.exceptions import ToolError

    from unifi_mcp.app import mcp

    with pytest.raises(ToolError, match="nicht konfiguriert"):
        await mcp.call_tool("prepare_change", {"console": "Unbekannt", "kind": "wlan.set_passphrase",
                                               "target": "Gast", "changes": {"passphrase": "geheim-123456"}})
    lines = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.startswith("{")]
    entry = [e for e in lines if e.get("tool") == "prepare_change"][-1]
    assert entry["status"] == "error" and entry["params"]["changes"] == {"passphrase": "***"}
    assert "geheim-123456" not in json.dumps(lines)


async def test_tool_list(server):
    from unifi_mcp.app import mcp

    names = {t.name for t in await mcp.list_tools()}
    expected = {
        "get_version", "list_consoles", "list_sites", "site_health", "list_devices", "device_info", "list_clients",
        "client_info", "list_networks", "list_wlans", "list_firewall_rules", "list_vpn", "wan_status", "list_events",
        "firmware_overview", "get_audit_log", "discover_consoles", "device_restart", "port_power_cycle", "client_block", "client_unblock",
        "client_reconnect", "wlan_set_enabled", "create_guest_voucher", "device_upgrade", "set_console_writes",
        "prepare_change", "execute_plan", "rollback_change", "hotspot_settings",
    }
    assert names == expected


async def test_get_version_uses_build_args(server, monkeypatch):
    from unifi_mcp import tools_read

    monkeypatch.setenv("APP_VERSION", "1.2.3")
    monkeypatch.setenv("GIT_SHA", "abcdef1234567890")
    info = await tools_read.get_version()
    assert info["version"] == "1.2.3" and info["commit"] == "abcdef1234567890"


def test_version_file_format():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VERSION")
    with open(path, encoding="utf-8") as f:
        assert re.fullmatch(r"\d+\.\d+\.\d+", f.read().strip())
