"""Konfiguration: Umgebungsvariablen für den Dienst, Konsolen-Liste als JSON-Datei.

Secrets (Site-Manager-Key, Integration-Keys, Legacy-Passwörter, Bearer-Token) kommen
nur aus der Umgebung bzw. den Portainer-Stack-Variablen. Die Konsolen-Datei enthält
nur die *Namen* der Umgebungsvariablen, nie die Werte.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

from .errors import ConfigError

logger = logging.getLogger("unifi_mcp.config")

MODES = ("cloud", "direct")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
# Site-Manager-Host-ID, z.B. "0000AAAA...:123456789" (Hex, Doppelpunkt, Ziffern).
CONSOLE_ID_RE = re.compile(r"^[A-Za-z0-9]{8,128}(:[0-9]{1,20})?$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
CONSOLE_KEYS = {
    "name", "console_id", "mode", "base_url", "api_key_env", "tls_fingerprint",
    "writes_enabled", "legacy_enabled", "legacy_username_env", "legacy_password_env",
}
DEFAULT_SITE_MANAGER_URL = "https://api.ui.com"


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(value: str | None, default: int, minimum: int = 0) -> int:
    try:
        number = int(value) if value not in (None, "") else default
    except ValueError:
        number = default
    return max(minimum, number)


def normalize_fingerprint(value: str) -> str:
    """'sha256:AB:CD:..', 'AB:CD:..' oder 'abcd..' -> 64 Hex-Zeichen klein."""
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    text = text.replace(":", "").replace(" ", "")
    if not FINGERPRINT_RE.fullmatch(text):
        raise ConfigError("tls_fingerprint: SHA-256-Fingerabdruck des Zertifikats (64 Hex-Zeichen, optional mit ':')")
    return text


@dataclass(frozen=True)
class Console:
    name: str
    console_id: str
    mode: str
    base_url: str = ""
    api_key_env: str = ""
    tls_fingerprint: str = ""
    writes_enabled: bool = False
    legacy_enabled: bool = False
    legacy_username_env: str = ""
    legacy_password_env: str = ""

    def public(self) -> dict:
        """Darstellung ohne Secrets (Variablennamen sind keine Secrets, werden aber nicht ausgegeben)."""
        return {
            "name": self.name,
            "console_id": self.console_id or None,
            "mode": self.mode,
            "base_url": self.base_url or None,
            "tls_pinned": bool(self.tls_fingerprint),
            "legacy_enabled": self.legacy_enabled,
        }


def _parse_console(raw: object, index: int) -> Console:
    where = f"Konsole #{index + 1}"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: muss ein JSON-Objekt sein")
    unknown = sorted(set(raw) - CONSOLE_KEYS)
    if unknown:
        raise ConfigError(f"{where}: unbekannte Felder {unknown}")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 100:
        raise ConfigError(f"{where}: 'name' fehlt oder ist länger als 100 Zeichen")
    where = f"Konsole '{name}'"
    mode = raw.get("mode", "cloud")
    if mode not in MODES:
        raise ConfigError(f"{where}: 'mode' muss 'cloud' oder 'direct' sein")
    console_id = raw.get("console_id") or ""
    if not isinstance(console_id, str) or (console_id and not CONSOLE_ID_RE.fullmatch(console_id)):
        raise ConfigError(f"{where}: 'console_id' ist keine gültige Site-Manager-ID")
    if mode == "cloud" and not console_id:
        raise ConfigError(f"{where}: 'console_id' ist im Modus cloud Pflicht")
    base_url = raw.get("base_url") or ""
    if not isinstance(base_url, str):
        raise ConfigError(f"{where}: 'base_url' muss ein Text sein")
    base_url = base_url.strip().rstrip("/")
    if base_url:
        if not re.fullmatch(r"https://[A-Za-z0-9.\-\[\]:]+", base_url):
            raise ConfigError(f"{where}: 'base_url' nur als https://host[:port] ohne Pfad")
    if mode == "direct" and not base_url:
        raise ConfigError(f"{where}: 'base_url' ist im Modus direct Pflicht")
    for key in ("api_key_env", "legacy_username_env", "legacy_password_env"):
        value = raw.get(key) or ""
        if not isinstance(value, str) or (value and not ENV_NAME_RE.fullmatch(value)):
            raise ConfigError(f"{where}: '{key}' muss ein Variablenname aus A-Z, 0-9 und _ sein")
    if mode == "direct" and not raw.get("api_key_env"):
        raise ConfigError(f"{where}: 'api_key_env' ist im Modus direct Pflicht")
    for key in ("writes_enabled", "legacy_enabled"):
        if key in raw and type(raw[key]) is not bool:
            raise ConfigError(f"{where}: '{key}' muss true oder false sein")
    legacy = raw.get("legacy_enabled", False)
    if legacy:
        if not base_url:
            raise ConfigError(f"{where}: Legacy-API braucht 'base_url' (direkter Zugriff auf die Konsole)")
        if not raw.get("legacy_username_env") or not raw.get("legacy_password_env"):
            raise ConfigError(f"{where}: Legacy-API braucht 'legacy_username_env' und 'legacy_password_env'")
    fingerprint = raw.get("tls_fingerprint") or ""
    if not isinstance(fingerprint, str):
        raise ConfigError(f"{where}: 'tls_fingerprint' muss ein Text sein")
    if fingerprint:
        if not base_url:
            raise ConfigError(f"{where}: 'tls_fingerprint' gilt nur zusammen mit 'base_url'")
        fingerprint = normalize_fingerprint(fingerprint)
    return Console(
        name=name.strip(),
        console_id=console_id,
        mode=mode,
        base_url=base_url,
        api_key_env=raw.get("api_key_env") or "",
        tls_fingerprint=fingerprint,
        writes_enabled=raw.get("writes_enabled", False),
        legacy_enabled=legacy,
        legacy_username_env=raw.get("legacy_username_env") or "",
        legacy_password_env=raw.get("legacy_password_env") or "",
    )


def parse_consoles(text: str) -> tuple[Console, ...]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ConfigError(f"Konsolen-Datei ist kein gültiges JSON (Zeile {getattr(exc, 'lineno', '?')})") from None
    items = data.get("consoles") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ConfigError("Konsolen-Datei: erwartet {\"consoles\": [...]} oder eine Liste")
    consoles = tuple(_parse_console(raw, i) for i, raw in enumerate(items))
    names = [c.name.casefold() for c in consoles]
    if len(names) != len(set(names)):
        raise ConfigError("Konsolen-Datei: Namen müssen eindeutig sein (Gross-/Kleinschreibung zählt nicht)")
    ids = [c.console_id for c in consoles if c.console_id]
    if len(ids) != len(set(ids)):
        raise ConfigError("Konsolen-Datei: console_id doppelt")
    return consoles


@dataclass(frozen=True)
class Settings:
    mcp_api_key: str
    site_manager_api_key: str
    site_manager_url: str = DEFAULT_SITE_MANAGER_URL
    consoles_file: str = "/config/consoles.json"
    consoles_json: str = field(default="", repr=False)
    data_dir: str = "/data"
    cache_ttl: int = 30
    plan_ttl: int = 900
    audit_retention_days: int = 365
    rate_limit_per_minute: int = 120
    auth_fail_limit_per_minute: int = 10
    max_items: int = 2000
    secrets: tuple[str, ...] = field(default=(), repr=False)
    console_secrets: dict[str, str] = field(default_factory=dict, repr=False)

    def secret(self, name: str) -> str:
        """Wert einer Variablen aus api_key_env / legacy_*_env: zuerst die Umgebung,
        dann UNIFI_CONSOLE_SECRETS (JSON-Objekt, eine Stack-Variable für alle Konsolen)."""
        return os.environ.get(name, "").strip() or self.console_secrets.get(name, "")

    def secret_values(self) -> tuple[str, ...]:
        """Werte, die in keiner Ausgabe und keinem Log auftauchen dürfen."""
        return tuple(v for v in (self.mcp_api_key, self.site_manager_api_key, *self.secrets) if v and len(v) >= 4)


def _console_secrets(text: str | None) -> dict[str, str]:
    if not text or not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        raise ConfigError("UNIFI_CONSOLE_SECRETS ist kein gültiges JSON") from None
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and ENV_NAME_RE.fullmatch(k) and isinstance(v, str) for k, v in data.items()
    ):
        raise ConfigError("UNIFI_CONSOLE_SECRETS: JSON-Objekt {\"VARIABLENNAME\": \"Wert\"} mit Namen aus A-Z, 0-9, _")
    return {k: v.strip() for k, v in data.items() if v.strip()}


def load_settings() -> Settings:
    env = os.environ
    console_secrets = _console_secrets(env.get("UNIFI_CONSOLE_SECRETS"))
    url = env.get("SITE_MANAGER_URL", "").strip().rstrip("/") or DEFAULT_SITE_MANAGER_URL
    # Alle Werte, deren Name nach Secret aussieht, zusätzlich schwärzen (z.B. die
    # Integration-Keys und Legacy-Passwörter, deren Namen in der Konsolen-Datei stehen).
    secret_like = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASS)", re.IGNORECASE)
    secrets = tuple(v for k, v in env.items() if secret_like.search(k) and v and len(v) >= 8)
    secrets += tuple(v for v in console_secrets.values() if len(v) >= 4)
    return Settings(
        mcp_api_key=env.get("MCP_API_KEY", ""),
        site_manager_api_key=env.get("SITE_MANAGER_API_KEY", "").strip(),
        site_manager_url=url,
        consoles_file=env.get("CONSOLES_FILE", "/config/consoles.json").strip(),
        consoles_json=env.get("CONSOLES_JSON", "").strip(),
        data_dir=env.get("DATA_DIR", "/data").strip() or "/data",
        cache_ttl=_int(env.get("CACHE_TTL_SECONDS"), 30),
        plan_ttl=_int(env.get("PLAN_TTL_SECONDS"), 900, minimum=60),
        audit_retention_days=_int(env.get("AUDIT_RETENTION_DAYS"), 365),
        rate_limit_per_minute=_int(env.get("MCP_RATE_LIMIT_PER_MINUTE"), 120, minimum=1),
        auth_fail_limit_per_minute=_int(env.get("MCP_AUTH_FAIL_LIMIT_PER_MINUTE"), 10, minimum=1),
        max_items=_int(env.get("MAX_ITEMS"), 2000, minimum=1),
        secrets=secrets,
        console_secrets=console_secrets,
    )


def load_consoles(path: str, text: str = "") -> tuple[Console, ...]:
    """Konsolen aus CONSOLES_JSON (Stack-Variable), sonst aus der Datei."""
    if text:
        return parse_consoles(text)
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        raise ConfigError(f"Konsolen-Datei {path} nicht gefunden (Volume eingebunden?)") from None
    except OSError as exc:
        raise ConfigError(f"Konsolen-Datei {path} nicht lesbar ({type(exc).__name__})") from None
    return parse_consoles(text)


_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset() -> None:
    """Nur für Tests: Konfiguration beim nächsten Zugriff neu aus der Umgebung lesen."""
    global _settings
    _settings = None
