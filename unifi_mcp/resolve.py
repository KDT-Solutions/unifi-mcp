"""Auflösen von Sites, Geräten, Clients und Objekten über ID, Name, MAC oder IP."""

from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Any

from .clients import NetworkClient
from .config import Console
from .errors import GuardError
from .redact import clean_text

MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$|^[0-9a-f]{12}$", re.IGNORECASE)


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def normalize_mac(value: str | None) -> str:
    """'AA-BB-CC-DD-EE-FF' / 'aabbccddeeff' -> 'aa:bb:cc:dd:ee:ff'; ungültig -> ''."""
    text = str(value or "").strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", text):
        text = ":".join(text[i:i + 2] for i in range(0, 12, 2))
    return text if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text) else ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def quote_filter(value: str) -> str:
    """STRING-Wert für den filter-Parameter: in einfachen Anführungszeichen, ' verdoppelt."""
    return "'" + str(value).replace("'", "''") + "'"


async def sites(net: NetworkClient) -> list[dict[str, Any]]:
    items, _ = await net.list_all("/v1/sites")
    return items


async def site(net: NetworkClient, console: Console, ref: str | None) -> dict[str, Any]:
    """Site über UUID, internen Namen (z.B. 'default') oder Anzeigenamen; ohne Angabe die einzige Site."""
    items = await sites(net)
    if not items:
        raise GuardError(f"Konsole '{console.name}': keine Site gefunden")
    if not ref:
        if len(items) == 1:
            return items[0]
        names = ", ".join(clean_text(str(s.get("name")), 60) for s in items[:20])
        raise GuardError(f"Konsole '{console.name}' hat mehrere Sites, bitte site angeben: {names}")
    needle = ref.strip()
    for s in items:
        if s.get("id") == needle or s.get("internalReference") == needle:
            return s
    matches = [s for s in items if str(s.get("name", "")).casefold() == needle.casefold()]
    if len(matches) == 1:
        return matches[0]
    raise GuardError(f"Site '{clean_text(needle, 80)}' auf Konsole '{console.name}' nicht gefunden")


def pick(items: list[dict[str, Any]], ref: str, label: str, keys: tuple[str, ...] = ("name",)) -> dict[str, Any]:
    """Eintrag über id oder exakten Namen (ohne Gross-/Kleinschreibung) wählen; mehrdeutig = Fehler."""
    needle = str(ref or "").strip()
    if not needle:
        raise GuardError(f"{label} angeben")
    for item in items:
        if item.get("id") == needle or item.get("_id") == needle:
            return item
    mac = normalize_mac(needle)
    if mac:
        found = [i for i in items if normalize_mac(i.get("macAddress") or i.get("mac")) == mac]
        if len(found) == 1:
            return found[0]
    if is_ip(needle):
        found = [i for i in items if i.get("ipAddress") == needle or i.get("ip") == needle]
        if len(found) == 1:
            return found[0]
    found = [i for i in items if any(str(i.get(k, "")).casefold() == needle.casefold() for k in keys)]
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        raise GuardError(f"{label} '{clean_text(needle, 80)}' ist mehrdeutig ({len(found)} Treffer) - bitte die ID verwenden")
    raise GuardError(f"{label} '{clean_text(needle, 80)}' nicht gefunden")


async def device(net: NetworkClient, site_id: str, ref: str) -> dict[str, Any]:
    if is_uuid(ref):
        return await net.get(f"/v1/sites/{site_id}/devices/{ref}")
    items, _ = await net.list_all(f"/v1/sites/{site_id}/devices")
    found = pick(items, ref, "Gerät")
    return await net.get(f"/v1/sites/{site_id}/devices/{found['id']}")


async def client(net: NetworkClient, site_id: str, ref: str) -> dict[str, Any]:
    if is_uuid(ref):
        return await net.get(f"/v1/sites/{site_id}/clients/{ref}")
    mac = normalize_mac(ref)
    if mac:
        items, _ = await net.list_all(f"/v1/sites/{site_id}/clients", f"macAddress.eq({quote_filter(mac)})")
        if not items:
            # MAC-Format der API ist nicht festgelegt: zusätzlich ohne Filter suchen.
            items, _ = await net.list_all(f"/v1/sites/{site_id}/clients")
    elif is_ip(ref):
        items, _ = await net.list_all(f"/v1/sites/{site_id}/clients", f"ipAddress.eq({quote_filter(ref.strip())})")
    else:
        items, _ = await net.list_all(f"/v1/sites/{site_id}/clients")
    found = pick(items, ref, "Client")
    return await net.get(f"/v1/sites/{site_id}/clients/{found['id']}")
