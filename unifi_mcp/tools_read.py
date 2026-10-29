"""Lesende Tools."""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import time
from typing import Any

from pydantic import StrictBool

from . import resolve
from .app import runtime, tool
from .config import DEFAULT_SITE_MANAGER_KEY_ENV as DEFAULT_KEY, Console
from .errors import GuardError, UnifiError
from .redact import mask_secrets
from .version import version_info

READ_ONLY = {"readOnlyHint": True, "openWorldHint": True}
DETAIL_CONCURRENCY = 5
STATS_MAX_DEVICES = 50
CONNECTIONS = {"wired": "WIRED", "wireless": "WIRELESS", "vpn": "VPN", "teleport": "TELEPORT"}
DEVICE_TYPES = {"gateway": "gateway", "switch": "switching", "ap": "accessPoint"}
PERSONAL_SECURITY = ("WPA2_PERSONAL", "WPA3_PERSONAL", "WPA2_WPA3_PERSONAL")


# ---------------------------------------------------------------------------
# Hilfsfunktionen (auch von den schreibenden Tools genutzt)
# ---------------------------------------------------------------------------


def error_text(exc: Exception) -> str:
    return str(exc) if isinstance(exc, UnifiError) else f"Fehler ({type(exc).__name__})"


async def gather_limited(calls: list, limit: int = DETAIL_CONCURRENCY) -> list:
    semaphore = asyncio.Semaphore(limit)

    async def run(call):
        async with semaphore:
            try:
                return await call()
            except Exception as exc:  # noqa: BLE001 - Fehler pro Eintrag melden statt alles abzubrechen
                return exc

    return await asyncio.gather(*(run(c) for c in calls))


def device_type(features: list[str] | None) -> str:
    names = {v: k for k, v in DEVICE_TYPES.items()}
    found = [names[f] for f in features or [] if f in names]
    return "+".join(found) if found else "other"


def selected_consoles(console: str | None) -> list[Console]:
    rt = runtime()
    return [rt.find(console)] if console else list(rt.consoles)


async def sm_collect(call: str, *args: Any, consoles: list[Console] | None = None,
                     host_field: str = "hostId") -> tuple[list[dict[str, Any]], str | None]:
    """Eine Site-Manager-Abfrage pro Key (UI-Konto) und nur die Einträge der eigenen Konsolen behalten.
    Fehler eines Kontos verhindern die Daten der anderen nicht."""
    rt = runtime()
    out: list[dict[str, Any]] = []
    errors: list[str] = []
    for key_env, group in rt.sitemanager_groups(consoles).items():
        ids = {c.console_id for c in group}
        client = rt.sitemanager(key_env)
        try:
            items = await (client.devices(sorted(ids)) if call == "devices" else getattr(client, call)(*args))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{key_env} ({', '.join(c.name for c in group)}): {error_text(exc)}")
            continue
        out.extend(i for i in items if i.get(host_field) in ids)
    return out, ("; ".join(errors) or None)


async def sm_console_devices(consoles: list[Console] | None = None) -> tuple[dict[str, list[dict]], str | None]:
    """Geräte aus der Site Manager API je Host-ID (eine Abfrage pro Key)."""
    hosts, error = await sm_collect("devices", consoles=consoles)
    return {h.get("hostId"): [d for d in h.get("devices") or [] if isinstance(d, dict)] for h in hosts}, error


async def sm_site(console: Console, site: dict[str, Any] | None) -> tuple[dict | None, str | None]:
    """Passende Site aus der Site Manager API (hostId = console_id, meta.name = internalReference)."""
    if not console.console_id:
        return None, "Konsole ohne console_id - keine Site-Manager-Daten"
    try:
        items = await runtime().sitemanager(console.site_manager_key_env).sites()
    except Exception as exc:  # noqa: BLE001
        return None, error_text(exc)
    own = [s for s in items if s.get("hostId") == console.console_id]
    if site is not None:
        own = [s for s in own if (s.get("meta") or {}).get("name") == site.get("internalReference")]
    return (own[0] if own else None), (None if own else "Site in der Site Manager API nicht gefunden")


def sm_site_summary(entry: dict[str, Any]) -> dict[str, Any]:
    meta = entry.get("meta") or {}
    stats = entry.get("statistics") or {}
    counts = stats.get("counts") or {}
    issues = stats.get("internetIssues") or []
    return {
        "site": meta.get("desc") or meta.get("name"),
        "site_internal_name": meta.get("name"),
        "gateway_model": (stats.get("gateway") or {}).get("shortname"),
        "isp": (stats.get("ispInfo") or {}).get("name"),
        "wan_uptime_pct": (stats.get("percentages") or {}).get("wanUptime"),
        "devices_total": counts.get("totalDevice"),
        "devices_offline": counts.get("offlineDevice"),
        "gateway_offline": counts.get("offlineGatewayDevice"),
        "devices_pending_update": counts.get("pendingUpdateDevice"),
        "clients_wifi": counts.get("wifiClient"),
        "clients_wired": counts.get("wiredClient"),
        "clients_guest": counts.get("guestClient"),
        "critical_notifications": counts.get("criticalNotification"),
        "internet_issues": len(issues) if isinstance(issues, list) else None,
    }


async def legacy_by_mac(console: Console, site: dict[str, Any], path: str) -> tuple[dict[str, dict], str | None]:
    """Legacy-Daten (stat/sta, stat/device) nach MAC, nur wenn legacy_enabled."""
    if not console.legacy_enabled:
        return {}, None
    try:
        rows = await runtime().legacy(console).request("GET", site["internalReference"], path)
    except Exception as exc:  # noqa: BLE001
        return {}, error_text(exc)
    return {resolve.normalize_mac(r.get("mac")): r for r in rows or [] if isinstance(r, dict)}, None


def uptime_from(startup: str | None) -> int | None:
    if not startup:
        return None
    try:
        started = datetime.datetime.fromisoformat(str(startup).replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((datetime.datetime.now(datetime.timezone.utc) - started).total_seconds()))


def subnet_of(host_ip: str | None, prefix: int | None) -> str | None:
    if not host_ip or prefix is None:
        return None
    try:
        return str(ipaddress.ip_interface(f"{host_ip}/{prefix}").network)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool(annotations={"readOnlyHint": True, "openWorldHint": False})
async def get_version() -> dict[str, str]:
    """Version, Commit-Hash und Build-Zeit des laufenden unifi-mcp."""
    return version_info()


def site_manager_key_names() -> list[str]:
    """Alle eingetragenen Site-Manager-Keys: SITE_MANAGER_API_KEY, SITE_MANAGER_API_KEY_* aus der Umgebung
    oder UNIFI_CONSOLE_SECRETS und alle site_manager_key_env der Konsolen - nur Namen mit Wert."""
    import os
    import re

    rt = runtime()
    pattern = re.compile(r"^SITE_MANAGER_API_KEY(_[A-Z0-9_]+)?$")
    names = {DEFAULT_KEY} | {c.site_manager_key_env for c in rt.consoles}
    names |= {k for k in os.environ if pattern.fullmatch(k)} | {k for k in rt.settings.console_secrets if pattern.fullmatch(k)}
    return sorted(n for n in names if rt.settings.secret(n))


async def discover() -> list[dict[str, Any]]:
    """Konsolen, die jeder Site-Manager-Key sieht, mit Hinweis, ob sie schon konfiguriert sind."""
    rt = runtime()
    configured = {c.console_id: c.name for c in rt.consoles if c.console_id}
    out = []
    for key_env in site_manager_key_names():
        client = rt.sitemanager(key_env)
        entry: dict[str, Any] = {"site_manager_key_env": key_env}
        try:
            hosts = await client.hosts()
            devices = {h.get("hostId"): h for h in await client.devices()}
        except Exception as exc:  # noqa: BLE001
            entry["error"] = error_text(exc)
            out.append(entry)
            continue
        consoles = []
        for h in hosts:
            dev = devices.get(h.get("id")) or {}
            own = next((d for d in dev.get("devices") or [] if isinstance(d, dict) and d.get("isConsole")), {})
            consoles.append({
                "console_id": h.get("id"), "name": dev.get("hostName") or own.get("name"), "type": h.get("type"),
                "model": own.get("model"), "firmware": own.get("version"), "status": own.get("status"),
                "owner": h.get("owner"), "configured_as": configured.get(h.get("id")),
            })
        entry.update({"consoles": consoles, "count": len(consoles)})
        out.append(entry)
    return out


@tool(annotations=READ_ONLY)
async def discover_consoles() -> dict[str, Any]:
    """Alle Konsolen, die die eingetragenen Site-Manager-Keys sehen (pro Key), mit console_id, Name, Modell,
    Firmware und Status sowie ob sie schon in der Konsolen-Liste stehen. Hilft beim Erstellen von
    CONSOLES_JSON. Keys: SITE_MANAGER_API_KEY und SITE_MANAGER_API_KEY_* (Umgebung oder UNIFI_CONSOLE_SECRETS)."""
    return {"keys": await discover()}


@tool(annotations=READ_ONLY)
async def list_consoles() -> dict[str, Any]:
    """Alle konfigurierten Konsolen mit Status (online/offline laut Site Manager), Modell, Firmware,
    Firmware-Update, Modus (cloud/direct) und ob Schreiben bzw. die Legacy-API aktiv ist."""
    rt = runtime()
    by_host, error = await sm_console_devices()
    out = []
    for c in rt.consoles:
        entry: dict[str, Any] = {**c.public(), "writes_enabled": rt.writes_enabled(c)}
        own = next((d for d in by_host.get(c.console_id, []) if d.get("isConsole")), None)
        if own:
            entry.update({
                "status": own.get("status"), "model": own.get("model"), "firmware": own.get("version"),
                "firmware_status": own.get("firmwareStatus"), "update_available": own.get("updateAvailable"),
                "ip": own.get("ip"), "devices_reported": len(by_host.get(c.console_id, [])),
            })
        else:
            entry["status"] = "unbekannt"
        out.append(entry)
    result: dict[str, Any] = {"consoles": out, "count": len(out)}
    if error:
        result["site_manager_error"] = error
    return result


@tool(annotations=READ_ONLY)
async def list_sites(console: str | None = None) -> dict[str, Any]:
    """Sites der Network-App, optional nur einer Konsole (Name oder console_id). Die Site-ID oder der
    interne Name ('default') dient als Parameter site in den übrigen Tools."""
    out, errors = [], []
    for c in selected_consoles(console):
        try:
            items = await resolve.sites(runtime().network(c))
        except Exception as exc:  # noqa: BLE001
            errors.append({"console": c.name, "error": error_text(exc)})
            continue
        out.extend({"console": c.name, "site_id": s.get("id"), "internal_name": s.get("internalReference"),
                    "name": s.get("name")} for s in items)
    return {"sites": out, "count": len(out), **({"errors": errors} if errors else {})}


@tool(annotations=READ_ONLY)
async def site_health(console: str | None = None, site: str | None = None) -> dict[str, Any]:
    """Zusammenfassung pro Site: WAN-Verfügbarkeit, ISP, Gateway, Geräte online/offline, Clients und
    offene Meldungen. Ohne console: Übersicht aller Konsolen aus der Site Manager API (eine Abfrage pro Key).
    Mit console: zusätzlich Live-Zählung über die Network API (Geräte nach Status, Clients nach Typ)
    und bei aktivierter Legacy-API die Anzahl offener Alarme."""
    rt = runtime()
    if not console:
        entries, error = await sm_collect("sites")
        if error and not entries:
            raise GuardError(f"Site Manager nicht erreichbar: {error}")
        names = {c.console_id: c.name for c in rt.consoles if c.console_id}
        out = [{"console": names[e.get("hostId")], **sm_site_summary(e)} for e in entries if e.get("hostId") in names]
        return {"sites": out, "count": len(out), "source": "site_manager",
                **({"site_manager_error": error} if error else {})}

    c = rt.find(console)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    base = f"/v1/sites/{s['id']}"
    result: dict[str, Any] = {"console": c.name, "site": s.get("name"), "site_id": s.get("id")}

    entry, sm_error = await sm_site(c, s)
    if entry:
        result["site_manager"] = sm_site_summary(entry)
        issues = (entry.get("statistics") or {}).get("internetIssues") or []
        if issues:
            result["internet_issues"] = issues[:10]
    elif sm_error:
        result["site_manager_error"] = sm_error

    devices, truncated = await net.list_all(f"{base}/devices")
    states: dict[str, int] = {}
    for d in devices:
        states[d.get("state", "UNKNOWN")] = states.get(d.get("state", "UNKNOWN"), 0) + 1
    gateways = [d for d in devices if "gateway" in (d.get("features") or [])]
    result["devices"] = {
        "total": len(devices), "online": states.get("ONLINE", 0),
        "offline": sum(v for k, v in states.items() if k != "ONLINE"), "by_state": states,
        "firmware_updatable": sum(1 for d in devices if d.get("firmwareUpdatable")),
        **({"truncated": True} if truncated else {}),
    }
    result["gateway"] = [{"name": g.get("name"), "model": g.get("model"), "state": g.get("state"),
                          "ip": g.get("ipAddress"), "firmware": g.get("firmwareVersion")} for g in gateways]

    async def count(flt: str | None) -> int | None:
        params: dict[str, Any] = {"offset": 0, "limit": 1}
        if flt:
            params["filter"] = flt
        body = await net.get(f"{base}/clients", params)
        return (body or {}).get("totalCount")

    totals = await gather_limited([lambda: count(None), lambda: count("type.eq('WIRED')"),
                                   lambda: count("type.eq('WIRELESS')")])
    result["clients"] = {k: (v if not isinstance(v, Exception) else None)
                         for k, v in zip(("total", "wired", "wireless"), totals)}

    if c.legacy_enabled:
        try:
            alarms = await rt.legacy(c).request("GET", s["internalReference"], "list/alarm")
            result["open_alarms"] = sum(1 for a in alarms or [] if isinstance(a, dict) and not a.get("archived"))
        except Exception as exc:  # noqa: BLE001
            result["open_alarms_error"] = error_text(exc)
    else:
        result["open_alarms"] = None
        result["open_alarms_note"] = ("Alarme liefert die offizielle API nicht (Legacy-API nicht aktiv). "
                                      "Hinweis: site_manager.critical_notifications.")
    return result


@tool(annotations=READ_ONLY)
async def list_devices(console: str, site: str | None = None, type: str | None = None,
                       include_stats: bool = False) -> dict[str, Any]:
    """Geräte einer Site mit Typ (gateway/switch/ap), Modell, IP, MAC, Status, Firmware und ob ein Update
    verfügbar ist (inkl. Zielversion und Uptime aus der Site Manager API, falls vorhanden).
    type: gateway, switch oder ap. include_stats=true lädt zusätzlich CPU, RAM und Uptime je Gerät
    (eine Abfrage pro Gerät, höchstens 50)."""
    rt = runtime()
    c = rt.find(console)
    if type is not None and type not in DEVICE_TYPES:
        raise GuardError("type: gateway, switch oder ap")
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    flt = f"features.contains({resolve.quote_filter(DEVICE_TYPES[type])})" if type else None
    devices, truncated = await net.list_all(f"/v1/sites/{s['id']}/devices", flt)
    by_host, sm_error = await sm_console_devices()
    sm = {resolve.normalize_mac(d.get("mac")): d for d in by_host.get(c.console_id, [])}
    out = []
    for d in devices:
        extra = sm.get(resolve.normalize_mac(d.get("macAddress")), {})
        out.append({
            "id": d.get("id"), "name": d.get("name"), "type": device_type(d.get("features")),
            "model": d.get("model"), "ip": d.get("ipAddress"), "mac": d.get("macAddress"), "state": d.get("state"),
            "firmware": d.get("firmwareVersion"), "firmware_updatable": d.get("firmwareUpdatable"),
            "update_available": extra.get("updateAvailable"), "uptime_s": uptime_from(extra.get("startupTime")),
        })
    if include_stats:
        selected = out[:STATS_MAX_DEVICES]
        stats = await gather_limited([
            (lambda i=d["id"]: net.get(f"/v1/sites/{s['id']}/devices/{i}/statistics/latest")) for d in selected
        ])
        for entry, st in zip(selected, stats):
            if isinstance(st, Exception):
                entry["stats_error"] = error_text(st)
                continue
            entry.update({"uptime_s": (st or {}).get("uptimeSec", entry["uptime_s"]),
                          "cpu_pct": (st or {}).get("cpuUtilizationPct"),
                          "memory_pct": (st or {}).get("memoryUtilizationPct")})
    result: dict[str, Any] = {"console": c.name, "site": s.get("name"), "devices": out, "count": len(out)}
    if truncated:
        result["truncated"] = True
    if sm_error:
        result["site_manager_error"] = sm_error
    return result


@tool(annotations=READ_ONLY)
async def device_info(console: str, device: str, site: str | None = None) -> dict[str, Any]:
    """Details zu einem Gerät (ID, Name, MAC oder IP): Firmware, Uplink, CPU/RAM/Uptime, bei Switches die
    Ports (Link, Geschwindigkeit, PoE), bei APs die Funkmodule (Band, Kanal, Breite, Sendeleistung,
    Wiederholungsrate). PoE-Verbrauch, Port-Fehler und Kanalauslastung nur mit aktivierter Legacy-API."""
    rt = runtime()
    c = rt.find(console)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    d = await resolve.device(net, s["id"], device)
    try:
        stats = await net.get(f"/v1/sites/{s['id']}/devices/{d['id']}/statistics/latest")
    except UnifiError as exc:
        stats = {"error": str(exc)}
    interfaces = d.get("interfaces") or {}
    ports = [{
        "idx": p.get("idx"), "state": p.get("state"), "speed_mbps": p.get("speedMbps"),
        "max_speed_mbps": p.get("maxSpeedMbps"), "connector": p.get("connector"),
        "poe": p.get("poe"),
    } for p in interfaces.get("ports") or []]
    radio_stats = {r.get("frequencyGHz"): r for r in ((stats or {}).get("interfaces") or {}).get("radios") or []}
    radios = [{
        "band_ghz": r.get("frequencyGHz"), "channel": r.get("channel"), "width_mhz": r.get("channelWidthMHz"),
        "tx_power": r.get("txPowerMode"), "standard": r.get("wlanStandard"),
        "tx_retries_pct": (radio_stats.get(r.get("frequencyGHz")) or {}).get("txRetriesPct"),
    } for r in interfaces.get("radios") or []]

    result: dict[str, Any] = {
        "console": c.name, "site": s.get("name"), "id": d.get("id"), "name": d.get("name"),
        "type": device_type(list((d.get("features") or {}).keys())), "model": d.get("model"),
        "ip": d.get("ipAddress"), "mac": d.get("macAddress"), "state": d.get("state"),
        "firmware": d.get("firmwareVersion"), "firmware_updatable": d.get("firmwareUpdatable"),
        "adopted_at": d.get("adoptedAt"), "uplink_device_id": (d.get("uplink") or {}).get("deviceId"),
        "stats": {k: v for k, v in (stats or {}).items() if k != "interfaces"},
        "ports": ports, "radios": radios,
    }
    legacy, legacy_error = await legacy_by_mac(c, s, f"stat/device/{resolve.normalize_mac(d.get('macAddress'))}")
    raw = legacy.get(resolve.normalize_mac(d.get("macAddress")))
    if raw:
        by_idx = {p.get("port_idx"): p for p in raw.get("port_table") or [] if isinstance(p, dict)}
        for port in ports:
            lp = by_idx.get(port["idx"]) or {}
            port.update({"name": lp.get("name"), "poe_power_w": lp.get("poe_power"),
                         "rx_errors": lp.get("rx_errors"), "tx_errors": lp.get("tx_errors"),
                         "rx_dropped": lp.get("rx_dropped"), "tx_dropped": lp.get("tx_dropped"),
                         "full_duplex": lp.get("full_duplex")})
        result["radio_utilization"] = [{
            "radio": r.get("radio"), "channel": r.get("channel"), "utilization_pct": r.get("cu_total"),
            "clients": r.get("num_sta"), "satisfaction": r.get("satisfaction"),
        } for r in raw.get("radio_table_stats") or [] if isinstance(r, dict)]
        result["upgrade_to_firmware"] = raw.get("upgrade_to_firmware")
    elif legacy_error:
        result["legacy_error"] = legacy_error
    elif not c.legacy_enabled:
        result["note"] = "PoE-Verbrauch, Port-Fehler und Kanalauslastung nur mit legacy_enabled."
    return result


def _client_entry(cl: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    access = cl.get("access") or {}
    return {
        "id": cl.get("id"), "name": cl.get("name"), "type": cl.get("type"), "ip": cl.get("ipAddress"),
        "mac": cl.get("macAddress"), "connected_at": cl.get("connectedAt"),
        "uplink_device": names.get(cl.get("uplinkDeviceId")) or cl.get("uplinkDeviceId"),
        "access": access.get("type"),
    }


def _merge_legacy_client(entry: dict[str, Any], raw: dict[str, Any] | None) -> None:
    if not raw:
        return
    entry.update({
        "hostname": raw.get("hostname"), "ssid": raw.get("essid"), "signal_dbm": raw.get("signal"),
        "rssi": raw.get("rssi"), "switch_port": raw.get("sw_port"), "network": raw.get("network"),
        "vlan": raw.get("vlan"), "tx_bytes": raw.get("tx_bytes"), "rx_bytes": raw.get("rx_bytes"),
        "uptime_s": raw.get("uptime"), "blocked": raw.get("blocked"),
    })


@tool(annotations=READ_ONLY)
async def list_clients(console: str, site: str | None = None, connection: str | None = None,
                       search: str | None = None, limit: int = 200) -> dict[str, Any]:
    """Verbundene Clients einer Site. connection: wired, wireless oder vpn. search: MAC, IP oder Teil des
    Namens/Hostnamens. Mit verbundenem AP/Switch; Signal, SSID, Switch-Port und Datenvolumen nur mit
    aktivierter Legacy-API. limit 1-2000."""
    rt = runtime()
    c = rt.find(console)
    if connection is not None and connection not in CONNECTIONS:
        raise GuardError("connection: wired, wireless oder vpn")
    if type(limit) is not int or not 1 <= limit <= 2000:
        raise GuardError("limit: 1 bis 2000")
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    filters = []
    if connection:
        filters.append(f"type.eq({resolve.quote_filter(CONNECTIONS[connection])})")
    needle = (search or "").strip()
    if needle and resolve.is_ip(needle):
        filters.append(f"ipAddress.eq({resolve.quote_filter(needle)})")
    flt = filters[0] if len(filters) == 1 else (f"and({', '.join(filters)})" if filters else None)
    clients, truncated = await net.list_all(f"/v1/sites/{s['id']}/clients", flt)
    devices, _ = await net.list_all(f"/v1/sites/{s['id']}/devices")
    names = {d.get("id"): d.get("name") for d in devices}
    legacy, legacy_error = await legacy_by_mac(c, s, "stat/sta")
    out = []
    mac = resolve.normalize_mac(needle)
    for cl in clients:
        entry = _client_entry(cl, names)
        _merge_legacy_client(entry, legacy.get(resolve.normalize_mac(cl.get("macAddress"))))
        if needle and not resolve.is_ip(needle):
            if mac:
                if resolve.normalize_mac(entry.get("mac")) != mac:
                    continue
            elif not any(needle.casefold() in str(entry.get(k) or "").casefold() for k in ("name", "hostname")):
                continue
        out.append(entry)
    result: dict[str, Any] = {"console": c.name, "site": s.get("name"), "clients": out[:limit], "count": len(out)}
    if truncated or len(out) > limit:
        result["truncated"] = True
    if legacy_error:
        result["legacy_error"] = legacy_error
    return result


@tool(annotations=READ_ONLY)
async def client_info(console: str, client: str, site: str | None = None) -> dict[str, Any]:
    """Details zu einem Client (ID, MAC, IP oder Name): Typ, IP, MAC, Verbindungszeit, Uplink-Gerät,
    Gastzugang; mit Legacy-API zusätzlich Signal, SSID, Switch-Port, Datenvolumen und ob gesperrt."""
    rt = runtime()
    c = rt.find(console)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    cl = await resolve.client(net, s["id"], client)
    names: dict[str, str] = {}
    if cl.get("uplinkDeviceId"):
        try:
            up = await net.get(f"/v1/sites/{s['id']}/devices/{cl['uplinkDeviceId']}")
            names[cl["uplinkDeviceId"]] = up.get("name")
        except UnifiError:
            pass
    entry = _client_entry(cl, names)
    entry["access_details"] = cl.get("access")
    legacy, legacy_error = await legacy_by_mac(c, s, "stat/sta")
    _merge_legacy_client(entry, legacy.get(resolve.normalize_mac(cl.get("macAddress"))))
    if legacy_error:
        entry["legacy_error"] = legacy_error
    return {"console": c.name, "site": s.get("name"), **entry}


@tool(annotations=READ_ONLY)
async def list_networks(console: str, site: str | None = None) -> dict[str, Any]:
    """Netze/VLANs einer Site mit VLAN-ID, Subnetz, Gateway-IP, DHCP (Modus, Bereich, Lease, DNS),
    Isolation, Internetzugang und Firewall-Zone."""
    rt = runtime()
    c = rt.find(console)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    items, truncated = await net.list_all(f"/v1/sites/{s['id']}/networks")
    details = await gather_limited([(lambda i=n["id"]: net.get(f"/v1/sites/{s['id']}/networks/{i}")) for n in items])
    out = []
    for n, d in zip(items, details):
        entry: dict[str, Any] = {"id": n.get("id"), "name": n.get("name"), "vlan_id": n.get("vlanId"),
                                 "management": n.get("management"), "enabled": n.get("enabled"),
                                 "default": n.get("default")}
        if isinstance(d, Exception):
            entry["details_error"] = error_text(d)
        else:
            v4 = (d or {}).get("ipv4Configuration") or {}
            dhcp = v4.get("dhcpConfiguration") or {}
            rng = dhcp.get("ipAddressRange") or {}
            entry.update({
                "gateway_ip": v4.get("hostIpAddress"), "prefix_length": v4.get("prefixLength"),
                "subnet": subnet_of(v4.get("hostIpAddress"), v4.get("prefixLength")),
                "dhcp_mode": dhcp.get("mode"), "dhcp_range": f"{rng['start']} - {rng['stop']}" if rng.get("start") else None,
                "dhcp_lease_s": dhcp.get("leaseTimeSeconds"), "dhcp_dns": dhcp.get("dnsServerIpAddressesOverride"),
                "dhcp_relay_servers": dhcp.get("dhcpServerIpAddresses"),
                "isolation": d.get("isolationEnabled"), "internet_access": d.get("internetAccessEnabled"),
                "zone_id": d.get("zoneId"),
                "ipv6": ((d.get("ipv6Configuration") or {}).get("interfaceType")),
            })
        out.append(entry)
    return {"console": c.name, "site": s.get("name"), "networks": out, "count": len(out),
            **({"truncated": True} if truncated else {})}


@tool(annotations=READ_ONLY)
async def list_wlans(console: str, site: str | None = None, show_passphrase: StrictBool = False) -> dict[str, Any]:
    """WLANs (SSIDs) einer Site mit Status, Sicherheitsmodus, zugeordnetem Netz, Frequenzbändern und
    Sichtbarkeit. WLAN-Passwörter sind maskiert; Klartext nur mit show_passphrase=true (wird im
    Audit-Log vermerkt)."""
    rt = runtime()
    c = rt.find(console)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    items, truncated = await net.list_all(f"/v1/sites/{s['id']}/wifi/broadcasts")
    details = await gather_limited([(lambda i=w["id"]: net.get(f"/v1/sites/{s['id']}/wifi/broadcasts/{i}"))
                                    for w in items])
    networks, _ = await net.list_all(f"/v1/sites/{s['id']}/networks")
    net_names = {n.get("id"): n.get("name") for n in networks}
    out = []
    for w, d in zip(items, details):
        src = w if isinstance(d, Exception) else d
        sec = src.get("securityConfiguration") or {}
        ref = src.get("network") or {}
        entry = {
            "id": w.get("id"), "ssid": w.get("name"), "enabled": w.get("enabled"), "type": w.get("type"),
            "security": sec.get("type"),
            "network": "native" if ref.get("type") == "NATIVE" else net_names.get(ref.get("networkId"), ref.get("networkId")),
            "bands_ghz": src.get("broadcastingFrequenciesGHz"), "hidden": src.get("hideName"),
            "client_isolation": src.get("clientIsolationEnabled"),
            "hotspot": (src.get("hotspotConfiguration") or {}).get("type"),
            "security_details": mask_secrets(sec, reveal=show_passphrase),
        }
        if isinstance(d, Exception):
            entry["details_error"] = error_text(d)
        out.append(entry)
    if show_passphrase:
        rt.store.audit(c.name, "show_passphrase", s.get("name") or s.get("id"), "succeeded")
    return {"console": c.name, "site": s.get("name"), "wlans": out, "count": len(out),
            "passphrases": "Klartext" if show_passphrase else "maskiert",
            **({"truncated": True} if truncated else {})}


def _zone_name(zones: dict[str, str], zone_id: str | None) -> str | None:
    return zones.get(zone_id, zone_id) if zone_id else None


@tool(annotations=READ_ONLY)
async def list_firewall_rules(console: str, site: str | None = None, include_predefined: bool = False) -> dict[str, Any]:
    """Firewall-Policies (zonenbasiert) mit Reihenfolge, Aktion, Quell-/Zielzone, Filter und Logging sowie
    die Firewall-Zonen. include_predefined=true zeigt auch die vom System angelegten Policies.
    Portweiterleitungen nur mit aktivierter Legacy-API (die offizielle API bietet sie nicht). Nur lesen."""
    rt = runtime()
    c = rt.find(console)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    zones_raw, _ = await net.list_all(f"/v1/sites/{s['id']}/firewall/zones")
    zones = {z.get("id"): z.get("name") for z in zones_raw}
    flt = None if include_predefined else "metadata.origin.eq('USER_DEFINED')"
    policies, truncated = await net.list_all(f"/v1/sites/{s['id']}/firewall/policies", flt)
    out = [{
        "id": p.get("id"), "index": p.get("index"), "name": p.get("name"), "enabled": p.get("enabled"),
        "action": (p.get("action") or {}).get("type"),
        "source_zone": _zone_name(zones, (p.get("source") or {}).get("zoneId")),
        "destination_zone": _zone_name(zones, (p.get("destination") or {}).get("zoneId")),
        "source_filter": (p.get("source") or {}).get("trafficFilter"),
        "destination_filter": (p.get("destination") or {}).get("trafficFilter"),
        "ip_version": (p.get("ipProtocolScope") or {}).get("ipVersion"),
        "protocol": p.get("ipProtocolScope"), "connection_states": p.get("connectionStateFilter"),
        "schedule": p.get("schedule"), "logging": p.get("loggingEnabled"),
        "origin": (p.get("metadata") or {}).get("origin"), "description": p.get("description"),
    } for p in sorted(policies, key=lambda p: p.get("index") or 0)]
    result: dict[str, Any] = {
        "console": c.name, "site": s.get("name"), "policies": out, "count": len(out),
        "zones": [{"id": z.get("id"), "name": z.get("name"), "networks": len(z.get("networkIds") or [])} for z in zones_raw],
    }
    if truncated:
        result["truncated"] = True
    if c.legacy_enabled:
        try:
            forwards = await rt.legacy(c).request("GET", s["internalReference"], "list/portforward")
            result["port_forwards"] = [{
                "id": f.get("_id"), "name": f.get("name"), "enabled": f.get("enabled"), "protocol": f.get("proto"),
                "source": f.get("src"), "wan_port": f.get("dst_port"), "forward_ip": f.get("fwd"),
                "forward_port": f.get("fwd_port"), "interface": f.get("pfwd_interface"), "logging": f.get("log"),
            } for f in forwards or [] if isinstance(f, dict)]
        except Exception as exc:  # noqa: BLE001
            result["port_forwards_error"] = error_text(exc)
    else:
        result["port_forwards"] = None
        result["port_forwards_note"] = "Portweiterleitungen bietet die offizielle API nicht (legacy_enabled nötig)."
    return result


@tool(annotations=READ_ONLY)
async def list_vpn(console: str, site: str | None = None) -> dict[str, Any]:
    """VPN-Server (WireGuard, OpenVPN, L2TP, ...) und Site-to-Site-Tunnel einer Site mit Typ und ob aktiviert.
    Einen Verbindungsstatus der Tunnel liefert die offizielle API nicht."""
    rt = runtime()
    c = rt.find(console)
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    servers, _ = await net.list_all(f"/v1/sites/{s['id']}/vpn/servers")
    tunnels, _ = await net.list_all(f"/v1/sites/{s['id']}/vpn/site-to-site-tunnels")
    return {
        "console": c.name, "site": s.get("name"),
        "servers": [mask_secrets({k: v for k, v in x.items() if k != "metadata"}) for x in servers],
        "site_to_site": [mask_secrets({k: v for k, v in x.items() if k != "metadata"}) for x in tunnels],
        "note": "Status (verbunden/getrennt) ist in der offiziellen API nicht enthalten.",
    }


def _isp_summary(metric: dict[str, Any]) -> dict[str, Any]:
    periods = [p for p in metric.get("periods") or [] if isinstance(p, dict)]
    wans = [((p.get("data") or {}).get("wan") or {}) for p in periods]
    wans = [w for w in wans if w]
    if not wans:
        return {"periods": 0}

    def values(key):
        return [w[key] for w in wans if isinstance(w.get(key), (int, float))]

    latency, peak, loss, down = values("avgLatency"), values("maxLatency"), values("packetLoss"), values("downtime")
    last = wans[-1]
    return {
        "periods": len(wans), "from": periods[0].get("metricTime"), "to": periods[-1].get("metricTime"),
        "isp": last.get("ispName"), "isp_asn": last.get("ispAsn"),
        "avg_latency_ms": round(sum(latency) / len(latency), 1) if latency else None,
        "max_latency_ms": max(peak) if peak else None,
        "avg_packet_loss": round(sum(loss) / len(loss), 2) if loss else None,
        "downtime_total": sum(down) if down else None,
        "periods_with_downtime": sum(1 for d in down if d),
        "last": {k: last.get(k) for k in ("avgLatency", "maxLatency", "packetLoss", "download_kbps", "upload_kbps",
                                          "uptime", "downtime")},
    }


@tool(annotations=READ_ONLY)
async def wan_status(console: str | None = None, site: str | None = None, period: str = "24h") -> dict[str, Any]:
    """WAN-Status: WAN-Schnittstellen (Network API), von der Site Manager API gemeldete IP der Konsole,
    ISP, WAN-Verfügbarkeit, Internet-Probleme und ISP-Metriken (Latenz, Paketverlust, Ausfallzeit).
    period: 24h (5-Minuten-Werte), 7d oder 30d (Stundenwerte). Ohne console: alle Konsolen."""
    if period not in ("24h", "7d", "30d"):
        raise GuardError("period: 24h, 7d oder 30d")
    rt = runtime()
    interval = "5m" if period == "24h" else "1h"
    errors: list[dict[str, str]] = []
    consoles = selected_consoles(console)
    host_list, e1 = await sm_collect("hosts", consoles=consoles, host_field="id")
    sm_sites, e2 = await sm_collect("sites", consoles=consoles)
    metrics, e3 = await sm_collect("isp_metrics", interval, period, consoles=consoles)
    hosts = {h.get("id"): h for h in host_list}
    for err in dict.fromkeys(e for e in (e1, e2, e3) if e):
        errors.append({"console": "*", "error": f"Site Manager: {err}"})
    out = []
    for c in consoles:
        own_sites = [x for x in sm_sites if x.get("hostId") == c.console_id] if c.console_id else []
        wans: Any = None
        selected_ref = None
        if console:
            try:
                net = rt.network(c)
                s = await resolve.site(net, c, site)
                selected_ref = s.get("internalReference")
                items, _ = await net.list_all(f"/v1/sites/{s['id']}/wans")
                wans = [{"id": w.get("id"), "name": w.get("name")} for w in items]
            except Exception as exc:  # noqa: BLE001
                errors.append({"console": c.name, "error": error_text(exc)})
        if selected_ref:
            own_sites = [x for x in own_sites if (x.get("meta") or {}).get("name") == selected_ref]
        for entry in own_sites or [None]:
            row: dict[str, Any] = {"console": c.name,
                                   "public_ip_reported": (hosts.get(c.console_id) or {}).get("ipAddress")}
            if entry:
                stats = entry.get("statistics") or {}
                row.update({
                    "site": (entry.get("meta") or {}).get("desc") or (entry.get("meta") or {}).get("name"),
                    "isp": (stats.get("ispInfo") or {}).get("name"),
                    "wan_uptime_pct": (stats.get("percentages") or {}).get("wanUptime"),
                    "internet_issues": (stats.get("internetIssues") or [])[:10],
                })
                metric = next((m for m in metrics if m.get("hostId") == c.console_id
                               and m.get("siteId") == entry.get("siteId")), None)
                row["isp_metrics"] = _isp_summary(metric) if metric else None
            if wans is not None:
                row["wan_interfaces"] = wans
            out.append(row)
    return {"period": period, "wan": out, **({"errors": errors} if errors else {})}


@tool(annotations=READ_ONLY)
async def list_events(console: str, site: str | None = None, hours: int = 24, limit: int = 100,
                      include_alarms: bool = True) -> dict[str, Any]:
    """Ereignisse und Alarme einer Site, neueste zuerst, Zeitraum in Stunden (1-720), limit 1-1000.
    Ereignisse und Alarme kommen aus der Legacy-API (die offizielle API bietet sie nicht); ohne
    legacy_enabled nur die Internet-Probleme und kritischen Meldungen aus der Site Manager API."""
    rt = runtime()
    c = rt.find(console)
    if type(hours) is not int or not 1 <= hours <= 720:
        raise GuardError("hours: 1 bis 720")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise GuardError("limit: 1 bis 1000")
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    result: dict[str, Any] = {"console": c.name, "site": s.get("name"), "hours": hours}
    entry, sm_error = await sm_site(c, s)
    if entry:
        stats = entry.get("statistics") or {}
        result["internet_issues"] = (stats.get("internetIssues") or [])[:limit]
        result["critical_notifications"] = (stats.get("counts") or {}).get("criticalNotification")
    elif sm_error:
        result["site_manager_error"] = sm_error
    if not c.legacy_enabled:
        result["events"] = None
        result["note"] = "Ereignisse und Alarme nur mit legacy_enabled (nicht in der offiziellen API)."
        return result
    legacy = rt.legacy(c)
    since_ms = (time.time() - hours * 3600) * 1000
    try:
        rows = await legacy.request("POST", s["internalReference"], "stat/event",
                                    json={"_sort": "-time", "within": hours, "_start": 0, "_limit": limit}, read=True)
        events = [r for r in rows or [] if isinstance(r, dict) and (r.get("time") or 0) >= since_ms]
        result["events"] = [{"time": r.get("datetime"), "key": r.get("key"), "subsystem": r.get("subsystem"),
                             "message": r.get("msg")} for r in events[:limit]]
    except Exception as exc:  # noqa: BLE001
        result["events_error"] = error_text(exc)
    if include_alarms:
        try:
            alarms = await legacy.request("GET", s["internalReference"], "list/alarm")
            open_alarms = [a for a in alarms or [] if isinstance(a, dict) and not a.get("archived")]
            result["alarms"] = [{"time": a.get("datetime"), "key": a.get("key"), "message": a.get("msg")}
                                for a in open_alarms[:limit]]
        except Exception as exc:  # noqa: BLE001
            result["alarms_error"] = error_text(exc)
    return result


@tool(annotations=READ_ONLY)
async def firmware_overview(console: str | None = None) -> dict[str, Any]:
    """Alle Geräte über alle Konsolen (oder eine Konsole), für die ein Firmware-Update verfügbar ist,
    mit aktueller und verfügbarer Version. Quelle: Site Manager API; Konsolen ohne console_id über die
    Network API (dort nur 'Update verfügbar' ohne Zielversion)."""
    rt = runtime()
    consoles = selected_consoles(console)
    by_host, sm_error = await sm_console_devices(consoles)
    out, errors = [], []
    for c in consoles:
        if c.console_id and c.console_id in by_host:
            for d in by_host[c.console_id]:
                if d.get("updateAvailable") or (d.get("firmwareStatus") not in (None, "upToDate")):
                    out.append({"console": c.name, "name": d.get("name"), "model": d.get("model"), "mac": d.get("mac"),
                                "status": d.get("status"), "firmware": d.get("version"),
                                "firmware_status": d.get("firmwareStatus"), "update_available": d.get("updateAvailable")})
            continue
        try:
            net = rt.network(c)
            for s in await resolve.sites(net):
                items, _ = await net.list_all(f"/v1/sites/{s['id']}/devices", "firmwareUpdatable.eq(true)")
                out.extend({"console": c.name, "site": s.get("name"), "name": d.get("name"), "model": d.get("model"),
                            "mac": d.get("macAddress"), "status": d.get("state"), "firmware": d.get("firmwareVersion"),
                            "firmware_status": "updateAvailable", "update_available": None} for d in items)
        except Exception as exc:  # noqa: BLE001
            errors.append({"console": c.name, "error": error_text(exc)})
    result: dict[str, Any] = {"devices": out, "count": len(out)}
    if sm_error:
        errors.append({"console": "*", "error": f"Site Manager: {sm_error}"})
    if errors:
        result["errors"] = errors
    return result


@tool(annotations={"readOnlyHint": True, "openWorldHint": False})
async def get_audit_log(console: str | None = None, action: str | None = None, hours: int | None = None,
                        limit: int = 100) -> dict[str, Any]:
    """Audit-Log der schreibenden Aktionen (neueste zuerst): Zeitpunkt, Konsole, Aktion, Ziel, Ergebnis.
    Filter: Konsole, Aktion (z.B. device_restart, execute_plan), letzte N Stunden. limit 1-1000."""
    rt = runtime()
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise GuardError("limit: 1 bis 1000")
    if hours is not None and (type(hours) is not int or hours < 1):
        raise GuardError("hours: ganze Zahl ab 1")
    consoles = [rt.find(console).name] if console else None
    since = time.time() - hours * 3600 if hours else None
    entries = rt.store.audit_log(consoles, action, since, limit)
    return {"entries": entries, "count": len(entries)}

