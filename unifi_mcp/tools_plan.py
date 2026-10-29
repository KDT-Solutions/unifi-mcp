"""Heikle Änderungen nach dem Muster vorbereiten -> prüfen -> ausführen -> ggf. zurücknehmen.

prepare_change ändert nichts: es liest den aktuellen Stand, berechnet den neuen Stand und liefert ein
Vorher/Nachher-Diff mit Plan-ID. execute_plan prüft, dass sich der Stand seit der Planung nicht geändert
hat, sichert ihn als JSON im Volume und führt den Plan genau einmal aus. rollback_change stellt den
gesicherten Stand wieder her (bzw. löscht ein neu angelegtes Objekt).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from pydantic import StrictBool

from . import resolve
from .app import runtime, tool
from .config import Console
from .errors import GuardError, UnclearStateError, UnifiError
from .redact import MASK, clean_text, is_secret_key, mask_secrets
from .tools_read import PERSONAL_SECURITY
from .tools_write import is_confirmed

READONLY_FIELDS = {"id", "metadata", "default", "index", "_id", "site_id", "attr_hidden_id", "attr_no_delete"}
PASSPHRASE_RE = re.compile(r"^[\x20-\x7e]{8,63}$")


@dataclass(frozen=True)
class Kind:
    api: str            # network | legacy
    collection: str     # Pfad unterhalb der Site
    op: str             # create | update
    label: str
    required: tuple[str, ...] = ()


KINDS: dict[str, Kind] = {
    "firewall_policy.create": Kind("network", "firewall/policies", "create", "Firewall-Policy anlegen",
                                   ("action", "destination", "enabled", "ipProtocolScope", "loggingEnabled", "name", "source")),
    "firewall_policy.update": Kind("network", "firewall/policies", "update", "Firewall-Policy ändern"),
    "network.create": Kind("network", "networks", "create", "Netz/VLAN anlegen", ("enabled", "management", "name", "vlanId")),
    "network.update": Kind("network", "networks", "update", "Netz/VLAN ändern"),
    "wlan.update": Kind("network", "wifi/broadcasts", "update", "WLAN ändern"),
    "wlan.set_passphrase": Kind("network", "wifi/broadcasts", "update", "WLAN-Passwort ändern"),
    "port_forward.create": Kind("legacy", "rest/portforward", "create", "Portweiterleitung anlegen",
                                ("name", "dst_port", "fwd", "fwd_port", "proto")),
    "port_forward.update": Kind("legacy", "rest/portforward", "update", "Portweiterleitung ändern"),
}
LIST_PATHS = {"rest/portforward": "list/portforward"}


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def digest(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def strip_readonly(data: dict[str, Any]) -> dict[str, Any]:
    return {k: copy.deepcopy(v) for k, v in data.items() if k not in READONLY_FIELDS}


def deep_merge(base: Any, changes: Any) -> Any:
    """Objekte rekursiv zusammenführen; Listen und Werte werden ersetzt; null setzt das Feld auf null."""
    if isinstance(base, dict) and isinstance(changes, dict):
        out = copy.deepcopy(base)
        for key, value in changes.items():
            out[key] = deep_merge(out.get(key), value) if key in out else copy.deepcopy(value)
        return out
    return copy.deepcopy(changes)


def diff(before: Any, after: Any, path: str = "") -> list[dict[str, Any]]:
    """Flaches Vorher/Nachher-Diff. Werte unter Secret-Feldern werden nur als *** gezeigt."""
    secret = is_secret_key(path.rsplit(".", 1)[-1].split("[")[0]) if path else False
    if isinstance(before, dict) and isinstance(after, dict):
        out: list[dict[str, Any]] = []
        for key in sorted(set(before) | set(after), key=str):
            sub = f"{path}.{key}" if path else str(key)
            if key not in after:
                out.append({"path": sub, "before": _shown(before[key], sub), "after": "(entfernt)"})
            elif key not in before:
                out.append({"path": sub, "before": "(neu)", "after": _shown(after[key], sub)})
            else:
                out.extend(diff(before[key], after[key], sub))
        return out
    if before == after:
        return []
    if secret:
        return [{"path": path, "before": MASK if before not in (None, "") else before, "after": f"{MASK} (geändert)"}]
    return [{"path": path, "before": mask_secrets(before), "after": mask_secrets(after)}]


def _shown(value: Any, path: str) -> Any:
    if is_secret_key(path.rsplit(".", 1)[-1]) and value not in (None, ""):
        return MASK
    return mask_secrets(value)


def check_changes(changes: Any) -> dict[str, Any]:
    if not isinstance(changes, dict) or not changes:
        raise GuardError("changes: JSON-Objekt mit den gewünschten Feldern")
    bad = sorted(READONLY_FIELDS & set(changes))
    if bad:
        raise GuardError(f"changes: Felder {bad} sind nicht änderbar")
    if len(json.dumps(changes, default=str)) > 20000:
        raise GuardError("changes: zu gross (max. 20000 Zeichen)")
    return changes


async def load_items(rt, c: Console, site: dict[str, Any], kind: Kind) -> list[dict[str, Any]]:
    if kind.api == "network":
        items, _ = await rt.network(c).list_all(f"/v1/sites/{site['id']}/{kind.collection}")
        return items
    rows = await rt.legacy(c).request("GET", site["internalReference"], LIST_PATHS[kind.collection], cache=False)
    return [r for r in rows or [] if isinstance(r, dict)]


async def load_current(rt, c: Console, site: dict[str, Any], kind: Kind, target_id: str) -> dict[str, Any]:
    if kind.api == "network":
        return await rt.network(c).get(f"/v1/sites/{site['id']}/{kind.collection}/{target_id}", cache=False)
    rows = await load_items(rt, c, site, kind)
    found = [r for r in rows if r.get("_id") == target_id]
    if not found:
        raise GuardError("Objekt existiert nicht mehr")
    return found[0]


async def apply(rt, c: Console, site: dict[str, Any], kind: Kind, method: str, target_id: str | None,
                body: dict[str, Any] | None) -> Any:
    if kind.api == "network":
        path = f"/v1/sites/{site['id']}/{kind.collection}" + (f"/{target_id}" if target_id else "")
        return await rt.network(c).request(method, path, json=body)
    path = kind.collection + (f"/{target_id}" if target_id else "")
    return await rt.legacy(c).request(method, site["internalReference"], path, json=body)


def created_id(kind: Kind, response: Any) -> str | None:
    if kind.api == "network":
        return (response or {}).get("id") if isinstance(response, dict) else None
    rows = response if isinstance(response, list) else []
    return rows[0].get("_id") if rows and isinstance(rows[0], dict) else None


def validate_create(kind_name: str, kind: Kind, body: dict[str, Any], items: list[dict[str, Any]]) -> list[str]:
    missing = [k for k in kind.required if k not in body]
    if missing:
        raise GuardError(f"changes: Pflichtfelder fehlen: {missing}")
    warnings = []
    name = str(body.get("name", "")).casefold()
    if name and any(str(i.get("name", "")).casefold() == name for i in items):
        raise GuardError("Ein Objekt mit diesem Namen existiert bereits")
    if kind_name == "network.create":
        vlan = body.get("vlanId")
        if type(vlan) is not int or not 2 <= vlan <= 4009:
            raise GuardError("vlanId: 2 bis 4009 (1 ist das Standardnetz)")
        if any(i.get("vlanId") == vlan for i in items):
            raise GuardError(f"VLAN {vlan} wird bereits verwendet")
    if kind_name == "port_forward.create":
        warnings.append("Portweiterleitungen öffnen Dienste ins Internet. Quelle (src) möglichst einschränken.")
        if str(body.get("src", "any")) in ("any", ""):
            warnings.append("Quelle ist 'any': die Weiterleitung ist aus dem ganzen Internet erreichbar.")
    if kind_name == "firewall_policy.create" and (body.get("action") or {}).get("type") == "ALLOW":
        warnings.append("ALLOW-Policy: Quelle und Ziel genau prüfen.")
    return warnings


def apply_passphrase(before: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    if set(changes) != {"passphrase"}:
        raise GuardError("wlan.set_passphrase: changes = {\"passphrase\": \"...\"}")
    passphrase = changes["passphrase"]
    if not isinstance(passphrase, str) or not PASSPHRASE_RE.fullmatch(passphrase):
        raise GuardError("Passphrase: 8-63 druckbare ASCII-Zeichen")
    security = before.get("securityConfiguration") or {}
    if security.get("type") not in PERSONAL_SECURITY:
        raise GuardError(f"WLAN nutzt {security.get('type')} - Passphrase nur bei WPA2/WPA3 Personal")
    after = copy.deepcopy(before)
    after["securityConfiguration"]["passphrase"] = passphrase
    return after


def plan_view(plan: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"plan_id": plan["id"], "kind": plan["kind"], "status": plan["status"],
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(plan["expires"])), **extra}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@tool(annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True})
async def prepare_change(console: str, kind: str, changes: dict[str, Any], target: str | None = None,
                         site: str | None = None) -> dict[str, Any]:
    """Heikle Änderung vorbereiten, ohne etwas zu ändern. Liefert Vorher/Nachher-Diff und eine Plan-ID
    (gültig 15 Minuten), ausführen mit execute_plan.
    kind: firewall_policy.create, firewall_policy.update, network.create (VLAN anlegen), network.update,
    wlan.update, wlan.set_passphrase, port_forward.create, port_forward.update (Portweiterleitungen nur
    mit Legacy-API).
    target: ID oder Name des bestehenden Objekts (bei *.update), bei WLANs die SSID.
    changes: bei *.create das vollständige Objekt im Format der API; bei *.update nur die zu ändernden
    Felder (verschachtelte Objekte werden zusammengeführt, Listen ersetzt); bei wlan.set_passphrase
    {"passphrase": "..."}. Passwörter erscheinen im Diff nur als ***."""
    rt = runtime()
    c = rt.find(console)
    rt.require_writes(c)
    spec = KINDS.get(kind)
    if spec is None:
        raise GuardError(f"kind: {', '.join(KINDS)}")
    changes = check_changes(changes)
    if spec.api == "legacy":
        rt.legacy(c)  # Fehler, falls legacy_enabled fehlt
    net = rt.network(c)
    s = await resolve.site(net, c, site)
    items = await load_items(rt, c, s, spec)
    warnings: list[str] = []
    if spec.op == "create":
        if target:
            raise GuardError("target gilt nur für *.update")
        before: dict[str, Any] = {}
        after = copy.deepcopy(changes)
        warnings = validate_create(kind, spec, after, items)
        target_id, target_name = "", str(after.get("name", ""))
    else:
        if not target:
            raise GuardError("target: ID oder Name des Objekts angeben")
        found = resolve.pick(items, target, spec.label.split()[0])
        target_id = found.get("id") or found.get("_id")
        current = await load_current(rt, c, s, spec, target_id)
        before = strip_readonly(current)
        after = apply_passphrase(before, changes) if kind == "wlan.set_passphrase" else deep_merge(before, changes)
        target_name = str(current.get("name", target_id))
        if kind == "wlan.update" and "passphrase" in json.dumps(changes):
            raise GuardError("Passphrase bitte mit kind wlan.set_passphrase ändern")
        if kind == "network.update" and current.get("default") and "vlanId" in changes:
            raise GuardError("VLAN-ID des Standardnetzes ist nicht änderbar")
    changes_list = diff(before, after)
    if not changes_list:
        raise GuardError("Keine Änderung gegenüber dem aktuellen Stand")
    payload = {"site_id": s["id"], "site_ref": s.get("internalReference"), "target_id": target_id,
               "target_name": target_name, "before_hash": digest(before), "body": after}
    plan_id, expires = rt.store.create_plan(c.name, kind, target_id or target_name, payload, rt.settings.plan_ttl)
    rt.store.audit(c.name, kind, target_name or target_id, "planned", f"plan {plan_id}")
    return {
        "plan_id": plan_id, "console": c.name, "site": s.get("name"), "kind": kind, "description": spec.label,
        "target": {"id": target_id or None, "name": target_name},
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires)),
        "diff": changes_list, "before": mask_secrets(before) if before else None, "after": mask_secrets(after),
        "warnings": warnings,
        "notice": "Nichts geändert. Nach Prüfung execute_plan(console, plan_id, confirm=true) aufrufen.",
    }


@tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
async def execute_plan(console: str, plan_id: str, confirm: StrictBool = False) -> dict[str, Any]:
    """Geprüften Plan einmalig ausführen. Vorher wird der aktuelle Stand als JSON im Volume gesichert
    (rollback_change). Bricht ab, wenn sich der Stand seit prepare_change geändert hat oder der Plan
    abgelaufen ist. Nur mit Schreibrechten der Konsole und confirm=true."""
    rt = runtime()
    c = rt.find(console)
    rt.require_writes(c)
    plan = rt.store.get_plan(plan_id)
    if plan["console"] != c.name:
        raise GuardError("Plan gehört zu einer anderen Konsole")
    spec = KINDS[plan["kind"]]
    payload = plan["payload"] or {}
    if not is_confirmed(confirm):
        return {"executed": False, "preview": True, **plan_view(plan, console=c.name, target=payload.get("target_name")),
                "hint": "Nichts ausgeführt. Zum Ausführen mit confirm=true wiederholen."}
    plan = rt.store.claim_plan(plan_id, c.name)
    site = {"id": payload["site_id"], "internalReference": payload["site_ref"]}
    target_id = payload.get("target_id") or None
    label = payload.get("target_name") or target_id or ""
    try:
        before = strip_readonly(await load_current(rt, c, site, spec, target_id)) if target_id else {}
    except UnifiError as exc:
        rt.store.finish_plan(plan_id, "aborted")
        rt.store.audit(c.name, f"execute_plan:{plan['kind']}", label, "aborted", clean_text(str(exc), 200))
        raise GuardError(f"Aktueller Stand nicht lesbar - nichts geändert ({exc})") from None
    if digest(before) != payload["before_hash"]:
        rt.store.finish_plan(plan_id, "aborted_changed")
        rt.store.audit(c.name, f"execute_plan:{plan['kind']}", label, "aborted_changed", f"plan {plan_id}")
        raise GuardError("Der Stand hat sich seit prepare_change geändert - nichts ausgeführt. Bitte neu planen.")
    backup = rt.store.write_backup(plan_id, {
        "plan_id": plan_id, "console": c.name, "kind": plan["kind"], "site_id": site["id"],
        "site_ref": site["internalReference"], "target_id": target_id, "target_name": label,
        "before": before, "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    method = "POST" if spec.op == "create" else "PUT"
    try:
        response = await apply(rt, c, site, spec, method, target_id, payload["body"])
    except UnclearStateError:
        rt.store.finish_plan(plan_id, "unknown")
        rt.store.audit(c.name, f"execute_plan:{plan['kind']}", label, "unknown_verify_state", f"plan {plan_id}")
        raise
    except UnifiError as exc:
        rt.store.finish_plan(plan_id, "failed")
        rt.store.audit(c.name, f"execute_plan:{plan['kind']}", label, "failed", clean_text(str(exc), 300))
        raise
    except BaseException as exc:
        rt.store.finish_plan(plan_id, "unknown")
        rt.store.audit(c.name, f"execute_plan:{plan['kind']}", label, "unknown_verify_state", type(exc).__name__)
        raise
    new_id = created_id(spec, response) if spec.op == "create" else target_id
    rt.store.update_backup(plan_id, created_id=new_id if spec.op == "create" else None)
    rt.store.finish_plan(plan_id, "succeeded")
    rt.store.audit(c.name, f"execute_plan:{plan['kind']}", label, "succeeded", f"plan {plan_id}")
    result = {"executed": True, "plan_id": plan_id, "console": c.name, "kind": plan["kind"],
              "target": {"id": new_id, "name": label}, "backup": backup.rsplit("/", 1)[-1],
              "rollback": "rollback_change(console, plan_id, confirm=true) stellt den vorherigen Stand wieder her."}
    if spec.op == "create" and not new_id:
        result["warning"] = "ID des neuen Objekts nicht in der Antwort - rollback_change kann es nicht löschen."
    return result


@tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
async def rollback_change(console: str, plan_id: str, confirm: StrictBool = False) -> dict[str, Any]:
    """Ausgeführten Plan zurücknehmen: bei Änderungen den gesicherten Stand wiederherstellen, bei neu
    angelegten Objekten das Objekt löschen. Ohne confirm Vorschau mit Diff (aktuell -> gesichert).
    Nur mit Schreibrechten der Konsole und confirm=true."""
    rt = runtime()
    c = rt.find(console)
    rt.require_writes(c)
    plan = rt.store.get_plan(plan_id)
    if plan["console"] != c.name:
        raise GuardError("Plan gehört zu einer anderen Konsole")
    if plan["status"] != "succeeded":
        raise GuardError(f"Nur erfolgreich ausgeführte Pläne lassen sich zurücknehmen (Status {plan['status']})")
    spec = KINDS[plan["kind"]]
    saved = rt.store.read_backup(plan_id)
    site = {"id": saved["site_id"], "internalReference": saved["site_ref"]}
    label = saved.get("target_name") or ""
    if spec.op == "create":
        target_id = saved.get("created_id")
        if not target_id:
            raise GuardError("ID des angelegten Objekts unbekannt - bitte von Hand entfernen")
        action, method, body = "Objekt löschen", "DELETE", None
        current = strip_readonly(await load_current(rt, c, site, spec, target_id))
        changes = diff(current, {})
    else:
        target_id = saved["target_id"]
        current = strip_readonly(await load_current(rt, c, site, spec, target_id))
        action, method, body = "gesicherten Stand wiederherstellen", "PUT", saved["before"]
        changes = diff(current, body)
    if not is_confirmed(confirm):
        return {"executed": False, "preview": True, "plan_id": plan_id, "console": c.name, "kind": plan["kind"],
                "action": action, "target": {"id": target_id, "name": label}, "diff": changes,
                "hint": "Nichts ausgeführt. Zum Zurücknehmen mit confirm=true wiederholen."}
    if not rt.store.set_plan_status(plan_id, "succeeded", "rolling_back"):
        raise GuardError("Plan wird bereits zurückgenommen")
    rt.store.update_backup(plan_id, before_rollback=current)
    try:
        await apply(rt, c, site, spec, method, target_id, body)
    except UnclearStateError:
        rt.store.set_plan_status(plan_id, "rolling_back", "rollback_unknown")
        rt.store.audit(c.name, f"rollback_change:{plan['kind']}", label, "unknown_verify_state", f"plan {plan_id}")
        raise
    except BaseException as exc:
        rt.store.set_plan_status(plan_id, "rolling_back", "succeeded")
        rt.store.audit(c.name, f"rollback_change:{plan['kind']}", label, "failed",
                       clean_text(str(exc), 300) if isinstance(exc, UnifiError) else type(exc).__name__)
        raise
    rt.store.set_plan_status(plan_id, "rolling_back", "rolled_back")
    rt.store.audit(c.name, f"rollback_change:{plan['kind']}", label, "succeeded", f"plan {plan_id}")
    return {"executed": True, "plan_id": plan_id, "console": c.name, "kind": plan["kind"], "action": action,
            "target": {"id": target_id, "name": label}}
