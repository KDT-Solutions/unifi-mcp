"""Einfache schreibende Aktionen. Gemeinsame Regeln:

- nur bei Konsolen mit freigeschalteten Schreibrechten (sonst Fehler, auch ohne confirm),
- ohne confirm=true nur Vorschau mit dem aufgelösten Ziel, nichts wird ausgeführt,
- jede Ausführung landet im Audit-Log (Zeitpunkt, Konsole, Aktion, Ziel, Ergebnis).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from pydantic import StrictBool

from . import resolve
from .app import runtime, tool
from .config import Console
from .errors import GuardError, UnclearStateError, UnifiError
from .redact import clean_text

WRITE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
DISRUPTIVE = {**WRITE, "destructiveHint": True}


def is_confirmed(confirm: Any) -> bool:
    return confirm is True


def preview(action: str, console: Console, target: dict[str, Any], **details: Any) -> dict[str, Any]:
    return {
        "executed": False, "preview": True, "action": action, "console": console.name, "target": target, **details,
        "hint": "Nichts ausgeführt. Zum Ausführen denselben Aufruf mit confirm=true wiederholen.",
    }


async def execute(console: Console, action: str, target: str, call: Callable[[], Awaitable[Any]]) -> Any:
    """Remote-Aufruf ausführen und das Ergebnis immer ins Audit-Log schreiben."""
    store = runtime().store
    try:
        result = await call()
    except UnclearStateError as exc:
        store.audit(console.name, action, target, "unknown_verify_state", clean_text(str(exc), 300))
        raise
    except UnifiError as exc:
        store.audit(console.name, action, target, "failed", clean_text(str(exc), 300))
        raise
    except BaseException as exc:
        store.audit(console.name, action, target, "unknown_verify_state", type(exc).__name__)
        raise
    store.audit(console.name, action, target, "succeeded")
    return result


def describe_device(d: dict[str, Any]) -> dict[str, Any]:
    return {"id": d.get("id"), "name": d.get("name"), "model": d.get("model"), "mac": d.get("macAddress"),
            "ip": d.get("ipAddress"), "state": d.get("state"), "firmware": d.get("firmwareVersion")}


def describe_client(cl: dict[str, Any]) -> dict[str, Any]:
    return {"id": cl.get("id"), "name": cl.get("name"), "type": cl.get("type"), "mac": cl.get("macAddress"),
            "ip": cl.get("ipAddress")}


async def _prepare(console: str, site: str | None):
    rt = runtime()
    c = rt.find(console)
    rt.require_writes(c)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    return rt, c, net, s


@tool(annotations=DISRUPTIVE)
async def device_restart(console: str, device: str, site: str | None = None, confirm: StrictBool = False) -> dict[str, Any]:
    """Gerät (ID, Name, MAC oder IP) neu starten. Verbundene Clients bzw. nachgelagerte Geräte verlieren kurz
    die Verbindung. Nur mit Schreibrechten der Konsole und confirm=true."""
    rt, c, net, s = await _prepare(console, site)
    d = await resolve.device(net, s["id"], device)
    target = describe_device(d)
    if not is_confirmed(confirm):
        return preview("device_restart", c, target, site=s.get("name"))
    await execute(c, "device_restart", f"{d.get('name')} ({d.get('macAddress')})",
                  lambda: net.request("POST", f"/v1/sites/{s['id']}/devices/{d['id']}/actions", json={"action": "RESTART"}))
    return {"executed": True, "action": "device_restart", "console": c.name, "target": target}


@tool(annotations=DISRUPTIVE)
async def port_power_cycle(console: str, device: str, port: int, site: str | None = None,
                           confirm: StrictBool = False) -> dict[str, Any]:
    """PoE-Port eines Switches neu starten (Strom kurz aus und wieder ein), z.B. für einen hängenden AP oder
    eine Kamera. port: Port-Nummer (idx). Nur mit Schreibrechten der Konsole und confirm=true."""
    if type(port) is not int or port < 1:
        raise GuardError("port: Port-Nummer ab 1")
    rt, c, net, s = await _prepare(console, site)
    d = await resolve.device(net, s["id"], device)
    ports = {p.get("idx"): p for p in ((d.get("interfaces") or {}).get("ports") or [])}
    if port not in ports:
        raise GuardError(f"Port {port} gibt es auf '{clean_text(str(d.get('name')), 60)}' nicht")
    if not ports[port].get("poe"):
        raise GuardError(f"Port {port} unterstützt laut API kein PoE")
    target = {**describe_device(d), "port": port, "port_poe": ports[port].get("poe")}
    if not is_confirmed(confirm):
        return preview("port_power_cycle", c, target, site=s.get("name"))
    await execute(c, "port_power_cycle", f"{d.get('name')} Port {port}",
                  lambda: net.request("POST", f"/v1/sites/{s['id']}/devices/{d['id']}/interfaces/ports/{port}/actions",
                                      json={"action": "POWER_CYCLE"}))
    return {"executed": True, "action": "port_power_cycle", "console": c.name, "target": target}


async def _legacy_client_cmd(action: str, cmd: str, console: str, client: str, site: str | None, confirm: Any,
                             note: str) -> dict[str, Any]:
    rt, c, net, s = await _prepare(console, site)
    legacy = rt.legacy(c)
    cl = await resolve.client(net, s["id"], client)
    mac = resolve.normalize_mac(cl.get("macAddress"))
    if not mac:
        raise GuardError("Client hat keine MAC-Adresse (z.B. VPN-Verbindung) - Aktion nicht möglich")
    target = describe_client(cl)
    if not is_confirmed(confirm):
        return preview(action, c, target, site=s.get("name"), note=note)
    await execute(c, action, f"{cl.get('name')} ({mac})",
                  lambda: legacy.request("POST", s["internalReference"], "cmd/stamgr", json={"cmd": cmd, "mac": mac}))
    return {"executed": True, "action": action, "console": c.name, "target": target}


@tool(annotations=DISRUPTIVE)
async def client_block(console: str, client: str, site: str | None = None, confirm: StrictBool = False) -> dict[str, Any]:
    """Client (ID, MAC, IP oder Name) sperren: er kann sich nicht mehr verbinden, bis er entsperrt wird.
    Läuft über die Legacy-API (legacy_enabled nötig). Nur mit Schreibrechten und confirm=true."""
    return await _legacy_client_cmd("client_block", "block-sta", console, client, site, confirm,
                                    "Gesperrte Clients bleiben gesperrt, bis client_unblock ausgeführt wird.")


@tool(annotations=WRITE)
async def client_unblock(console: str, client: str, site: str | None = None, confirm: StrictBool = False) -> dict[str, Any]:
    """Gesperrten Client wieder zulassen. Gesperrte Clients sind nicht verbunden: client am besten als MAC
    angeben. Läuft über die Legacy-API (legacy_enabled nötig). Nur mit Schreibrechten und confirm=true."""
    rt, c, net, s = await _prepare(console, site)
    legacy = rt.legacy(c)
    mac = resolve.normalize_mac(client)
    if mac:
        target: dict[str, Any] = {"mac": mac}
    else:
        cl = await resolve.client(net, s["id"], client)
        mac = resolve.normalize_mac(cl.get("macAddress"))
        target = describe_client(cl)
    if not mac:
        raise GuardError("MAC-Adresse des Clients nicht ermittelbar")
    if not is_confirmed(confirm):
        return preview("client_unblock", c, target, site=s.get("name"))
    await execute(c, "client_unblock", mac,
                  lambda: legacy.request("POST", s["internalReference"], "cmd/stamgr", json={"cmd": "unblock-sta", "mac": mac}))
    return {"executed": True, "action": "client_unblock", "console": c.name, "target": target}


@tool(annotations=WRITE)
async def client_reconnect(console: str, client: str, site: str | None = None, confirm: StrictBool = False) -> dict[str, Any]:
    """WLAN-Client trennen; er verbindet sich in der Regel sofort neu (z.B. um einen anderen AP zu wählen).
    Läuft über die Legacy-API (legacy_enabled nötig). Nur mit Schreibrechten und confirm=true."""
    return await _legacy_client_cmd("client_reconnect", "kick-sta", console, client, site, confirm,
                                    "Der Client wird getrennt und kann sich danach wieder verbinden.")


@tool(annotations=DISRUPTIVE)
async def wlan_set_enabled(console: str, wlan: str, enabled: StrictBool, site: str | None = None,
                           confirm: StrictBool = False) -> dict[str, Any]:
    """SSID ein- oder ausschalten. wlan: ID oder SSID-Name. Beim Ausschalten verlieren alle Clients dieses
    WLANs die Verbindung. Nur mit Schreibrechten der Konsole und confirm=true."""
    if type(enabled) is not bool:
        raise GuardError("enabled muss true oder false sein")
    rt, c, net, s = await _prepare(console, site)
    items, _ = await net.list_all(f"/v1/sites/{s['id']}/wifi/broadcasts")
    w = resolve.pick(items, wlan, "WLAN")
    details = await net.get(f"/v1/sites/{s['id']}/wifi/broadcasts/{w['id']}", cache=False)
    target = {"id": w.get("id"), "ssid": w.get("name"), "enabled_now": details.get("enabled"), "enabled_new": enabled}
    if details.get("enabled") == enabled:
        return {"executed": False, "action": "wlan_set_enabled", "console": c.name, "target": target,
                "notice": "Keine Änderung nötig - das WLAN hat bereits diesen Zustand."}
    if not is_confirmed(confirm):
        return preview("wlan_set_enabled", c, target, site=s.get("name"))
    body = {k: v for k, v in details.items() if k not in ("id", "metadata")}
    body["enabled"] = enabled
    await execute(c, "wlan_set_enabled", f"{w.get('name')} -> {'an' if enabled else 'aus'}",
                  lambda: net.request("PUT", f"/v1/sites/{s['id']}/wifi/broadcasts/{w['id']}", json=body))
    return {"executed": True, "action": "wlan_set_enabled", "console": c.name, "target": target}


@tool(annotations=WRITE)
async def create_guest_voucher(console: str, duration_minutes: int, count: int = 1, uses: int | None = None,
                               note: str = "unifi-mcp", data_limit_mb: int | None = None,
                               download_kbps: int | None = None, upload_kbps: int | None = None,
                               site: str | None = None, confirm: StrictBool = False) -> dict[str, Any]:
    """Hotspot-Voucher erzeugen. duration_minutes: Gültigkeit ab erster Nutzung (1-1000000), count: Anzahl
    Voucher (1-1000), uses: wie viele Geräte denselben Voucher nutzen dürfen (leer = unbegrenzt), optional
    Datenlimit (MB) und Bandbreite (kbit/s, 2-100000). Liefert die Voucher-Codes. Nur mit Schreibrechten
    und confirm=true."""
    def check(name: str, value: Any, low: int, high: int | None, optional: bool) -> None:
        if value is None and optional:
            return
        if type(value) is not int or value < low or (high is not None and value > high):
            raise GuardError(f"{name}: ganze Zahl {low}{f'-{high}' if high else '+'}")

    check("duration_minutes", duration_minutes, 1, 1000000, False)
    check("count", count, 1, 1000, False)
    check("uses", uses, 1, None, True)
    check("data_limit_mb", data_limit_mb, 1, 1048576, True)
    check("download_kbps", download_kbps, 2, 100000, True)
    check("upload_kbps", upload_kbps, 2, 100000, True)
    if not isinstance(note, str) or not note.strip() or len(note) > 100:
        raise GuardError("note: 1-100 Zeichen")
    rt, c, net, s = await _prepare(console, site)
    body: dict[str, Any] = {"name": note.strip(), "count": count, "timeLimitMinutes": duration_minutes}
    optional = {"authorizedGuestLimit": uses, "dataUsageLimitMBytes": data_limit_mb,
                "rxRateLimitKbps": download_kbps, "txRateLimitKbps": upload_kbps}
    body.update({k: v for k, v in optional.items() if v is not None})
    if not is_confirmed(confirm):
        return preview("create_guest_voucher", c, {"site": s.get("name")}, request=body)
    result = await execute(c, "create_guest_voucher", f"{count} x {duration_minutes} min ({s.get('name')})",
                           lambda: net.request("POST", f"/v1/sites/{s['id']}/hotspot/vouchers", json=body))
    vouchers = [{"code": v.get("code"), "id": v.get("id"), "minutes": v.get("timeLimitMinutes"),
                 "uses": v.get("authorizedGuestLimit"), "expires_at": v.get("expiresAt")}
                for v in (result or {}).get("vouchers") or [] if isinstance(v, dict)]
    return {"executed": True, "action": "create_guest_voucher", "console": c.name, "site": s.get("name"),
            "vouchers": vouchers, "count": len(vouchers)}


@tool(annotations=DISRUPTIVE)
async def device_upgrade(console: str, device: str, site: str | None = None, confirm: StrictBool = False) -> dict[str, Any]:
    """Firmware-Update eines einzelnen Geräts auf die von der Konsole angebotene Version starten. Das Gerät
    startet dabei neu. Läuft über die Legacy-API (die offizielle API bietet kein Update; legacy_enabled
    nötig). Nur wenn die API ein Update meldet, mit Schreibrechten und confirm=true."""
    rt, c, net, s = await _prepare(console, site)
    legacy = rt.legacy(c)
    d = await resolve.device(net, s["id"], device)
    if not d.get("firmwareUpdatable"):
        raise GuardError(f"Für '{clean_text(str(d.get('name')), 60)}' ist laut API kein Firmware-Update verfügbar")
    mac = resolve.normalize_mac(d.get("macAddress"))
    target = describe_device(d)
    if not is_confirmed(confirm):
        return preview("device_upgrade", c, target, site=s.get("name"),
                       note="Das Gerät lädt die Firmware und startet neu; nachgelagerte Geräte/Clients sind kurz offline.")
    await execute(c, "device_upgrade", f"{d.get('name')} ({mac}) von {d.get('firmwareVersion')}",
                  lambda: legacy.request("POST", s["internalReference"], "cmd/devmgr", json={"cmd": "upgrade", "mac": mac}))
    return {"executed": True, "action": "device_upgrade", "console": c.name, "target": target,
            "notice": "Update gestartet. Fortschritt mit device_info oder list_devices prüfen (state UPDATING)."}


@tool(annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False})
async def set_console_writes(console: str, enabled: StrictBool, confirm: StrictBool = False) -> dict[str, Any]:
    """Schreibrechte einer Konsole ein- oder ausschalten (übersteuert writes_enabled aus der Konsolen-Datei,
    gespeichert im Volume). Nur mit confirm=true, wird auditiert."""
    if type(enabled) is not bool:
        raise GuardError("enabled muss true oder false sein")
    rt = runtime()
    c = rt.find(console)
    current = rt.writes_enabled(c)
    if not is_confirmed(confirm):
        return preview("set_console_writes", c, {"writes_enabled_now": current, "writes_enabled_new": enabled})
    rt.store.set_writes(c.name, enabled)
    rt.store.audit(c.name, "set_console_writes", "enabled" if enabled else "disabled", "succeeded")
    return {"executed": True, "action": "set_console_writes", "console": c.name, "writes_enabled": enabled}
