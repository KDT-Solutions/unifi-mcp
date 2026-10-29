"""API-Clients.

Site Manager API (https://developer.ui.com/site-manager/v1.0.0), Header X-API-Key:
- GET /v1/hosts, /v1/devices, /v1/sites, /v1/isp-metrics/{type}  (Paginierung über nextToken)

Network Integration API (https://developer.ui.com/network/v11.0.97), Header X-API-Key:
- cloud:  https://api.ui.com/v1/connector/consoles/{consoleId}/proxy/network/integration
          (Connector der Site Manager API: Site-Manager-Key, 100 Requests/Minute pro Konsole,
          25 s Timeout und 10 MB Antwortgrösse pro Request)
- direct: https://{konsole}/proxy/network/integration  (Key aus der Network-App der Konsole)
- Listen: offset/limit (max. 200) und filter, Antwort {offset, limit, count, totalCount, data}

Legacy-API (nicht offiziell dokumentiert, nur Fallback, nur direkt zur Konsole):
- POST /api/auth/login, danach Cookie + X-CSRF-Token
- /proxy/network/api/s/{site}/...  Antwort {"meta": {"rc": "ok"}, "data": [...]}
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import quote

import httpx

from . import transport
from .config import Console, Settings, settings
from .errors import ApiError, ConfigError
from .transport import TtlCache, decode, send

logger = logging.getLogger("unifi_mcp.clients")

PAGE_LIMIT = 200
# Connector: Requests werden nach 25 s abgebrochen, etwas Reserve für den Rückweg.
CONNECTOR_TIMEOUT = 28.0
WRITE_TIMEOUT = 30.0


def _env(name: str, label: str) -> str:
    value = settings().secret(name)
    if not value:
        raise ConfigError(f"{label}: {name} ist weder als Umgebungsvariable noch in UNIFI_CONSOLE_SECRETS gesetzt")
    return value


class SiteManagerClient:
    def __init__(self, settings: Settings, cache: TtlCache):
        self.settings = settings
        self.cache = cache
        self._client: httpx.AsyncClient | None = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.settings.site_manager_url, verify=True, trust_env=True)
        return self._client

    def _headers(self) -> dict[str, str]:
        if not self.settings.site_manager_api_key:
            raise ConfigError("SITE_MANAGER_API_KEY ist nicht gesetzt")
        return {"X-API-Key": self.settings.site_manager_api_key, "Accept": "application/json"}

    async def _get(self, path: str, params: Any = None, ttl: float | None = None) -> Any:
        key = ("sitemanager", path, repr(params))
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        resp = await send(self._http(), "GET", path, label="Site Manager", headers=self._headers(), params=params)
        data = decode(resp, "Site Manager")
        self.cache.put(key, data, ttl)
        return data

    async def _paged(self, path: str, params: list[tuple[str, str]] | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        token = ""
        for _ in range(100):
            query = list(params or [])
            if token:
                query.append(("nextToken", token))
            body = await self._get(path, query or None)
            data = (body or {}).get("data") or []
            items.extend(d for d in data if isinstance(d, dict))
            token = (body or {}).get("nextToken") or ""
            if not token or len(items) >= self.settings.max_items:
                break
        return items

    async def hosts(self) -> list[dict[str, Any]]:
        return await self._paged("/v1/hosts")

    async def devices(self, host_ids: list[str] | None = None) -> list[dict[str, Any]]:
        return await self._paged("/v1/devices", [("hostIds[]", h) for h in host_ids or []])

    async def sites(self) -> list[dict[str, Any]]:
        return await self._paged("/v1/sites")

    async def isp_metrics(self, interval: str = "5m", duration: str = "24h") -> list[dict[str, Any]]:
        body = await self._get(f"/v1/isp-metrics/{interval}", {"duration": duration}, ttl=60)
        return [d for d in (body or {}).get("data") or [] if isinstance(d, dict)]

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class NetworkClient:
    """Network Integration API einer Konsole, über Cloud-Connector oder direkt."""

    def __init__(self, console: Console, settings: Settings, cache: TtlCache):
        self.console = console
        self.settings = settings
        self.cache = cache
        self._client: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    @property
    def scope(self) -> str:
        return f"network:{self.console.name}"

    @property
    def base(self) -> str:
        if self.console.mode == "cloud":
            return (
                f"{self.settings.site_manager_url}/v1/connector/consoles/"
                f"{quote(self.console.console_id, safe=':')}/proxy/network/integration"
            )
        return f"{self.console.base_url}/proxy/network/integration"

    def _key(self) -> str:
        label = f"Konsole '{self.console.name}'"
        if self.console.api_key_env:
            return _env(self.console.api_key_env, label)
        if self.console.mode == "cloud":
            if not self.settings.site_manager_api_key:
                raise ConfigError("SITE_MANAGER_API_KEY ist nicht gesetzt")
            return self.settings.site_manager_api_key
        raise ConfigError(f"{label}: api_key_env fehlt")

    async def _http(self) -> httpx.AsyncClient:
        async with self._lock:
            if self._client is None:
                verify: Any = True
                if self.console.mode == "direct" and self.console.tls_fingerprint:
                    verify = await asyncio.to_thread(
                        transport.build_pinned_context, self.console.base_url, self.console.tls_fingerprint
                    )
                self._client = httpx.AsyncClient(verify=verify, trust_env=self.console.mode == "cloud")
            return self._client

    def _label(self) -> str:
        return f"Network API '{self.console.name}'"

    async def request(self, method: str, path: str, *, params: Any = None, json: Any = None, cache: bool = True) -> Any:
        key = (self.scope, path, repr(params))
        if method == "GET" and cache:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
        headers = {"X-API-Key": self._key(), "Accept": "application/json"}
        timeout = CONNECTOR_TIMEOUT if self.console.mode == "cloud" else (WRITE_TIMEOUT if method != "GET" else None)
        resp = await send(await self._http(), method, self.base + path, label=self._label(),
                          headers=headers, params=params, json=json, timeout=timeout)
        data = decode(resp, self._label())
        if method == "GET":
            if cache:
                self.cache.put(key, data)
        else:
            self.cache.invalidate(self.scope)
        return data

    async def get(self, path: str, params: Any = None, cache: bool = True) -> Any:
        return await self.request("GET", path, params=params, cache=cache)

    async def list_all(self, path: str, filter: str | None = None) -> tuple[list[dict[str, Any]], bool]:
        """Alle Seiten einer Liste, höchstens MAX_ITEMS. Liefert (Einträge, gekürzt)."""
        items: list[dict[str, Any]] = []
        offset = 0
        while True:
            params: dict[str, Any] = {"offset": offset, "limit": PAGE_LIMIT}
            if filter:
                params["filter"] = filter
            body = await self.get(path, params)
            if isinstance(body, list):
                return body[: self.settings.max_items], len(body) > self.settings.max_items
            data = [d for d in (body or {}).get("data") or [] if isinstance(d, dict)]
            items.extend(data)
            total = (body or {}).get("totalCount")
            offset += len(data)
            if not data or not isinstance(total, int) or offset >= total:
                return items, False
            if len(items) >= self.settings.max_items:
                return items[: self.settings.max_items], True

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class LegacyClient:
    """Alte, nicht offiziell dokumentierte API der Network-App (Benutzername/Passwort).
    Nur für Funktionen, die die Integration API nicht bietet, nur mit legacy_enabled."""

    def __init__(self, console: Console, cache: TtlCache):
        self.console = console
        self.cache = cache
        self._client: httpx.AsyncClient | None = None
        self._csrf = ""
        self._lock = asyncio.Lock()

    @property
    def scope(self) -> str:
        return f"legacy:{self.console.name}"

    def _label(self) -> str:
        return f"Legacy-API '{self.console.name}'"

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            verify: Any = True
            if self.console.tls_fingerprint:
                verify = await asyncio.to_thread(
                    transport.build_pinned_context, self.console.base_url, self.console.tls_fingerprint
                )
            self._client = httpx.AsyncClient(base_url=self.console.base_url, verify=verify, trust_env=False)
        return self._client

    async def _login(self) -> None:
        label = f"Konsole '{self.console.name}'"
        payload = {
            "username": _env(self.console.legacy_username_env, label),
            "password": _env(self.console.legacy_password_env, label),
            "remember": False,
        }
        client = await self._http()
        client.cookies.clear()
        # Anmeldung ändert nichts an der Konsole: Timeouts wie bei lesenden Aufrufen behandeln.
        resp = await send(client, "POST", "/api/auth/login", label=self._label(), json=payload,
                          headers={"Accept": "application/json"}, read=True)
        if resp.status_code >= 400:
            raise ApiError(f"{self._label()}: Anmeldung fehlgeschlagen (HTTP {resp.status_code})", resp.status_code)
        self._csrf = resp.headers.get("x-csrf-token", "")

    async def request(self, method: str, site: str, path: str, *, json: Any = None, cache: bool = True,
                      read: bool | None = None) -> Any:
        """read=True: lesender Aufruf trotz POST (z.B. stat/event mit Filter im Body)."""
        is_read = method == "GET" if read is None else read
        url = f"/proxy/network/api/s/{quote(site, safe='')}/{path.lstrip('/')}"
        key = (self.scope, method, url, repr(json))
        if is_read and cache:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
        async with self._lock:
            client = await self._http()
            if not client.cookies:
                await self._login()
            for attempt in range(2):
                headers = {"Accept": "application/json"}
                if self._csrf:
                    headers["X-CSRF-Token"] = self._csrf
                resp = await send(client, method, url, label=self._label(), json=json, headers=headers,
                                  timeout=None if is_read else WRITE_TIMEOUT, read=is_read)
                updated = resp.headers.get("x-updated-csrf-token") or resp.headers.get("x-csrf-token")
                if updated:
                    self._csrf = updated
                # 401: Sitzung abgelaufen, nichts ausgeführt -> genau einmal neu anmelden.
                if resp.status_code == 401 and attempt == 0:
                    await self._login()
                    continue
                break
        body = decode(resp, self._label())
        meta = (body or {}).get("meta") if isinstance(body, dict) else None
        if isinstance(meta, dict) and meta.get("rc") not in (None, "ok"):
            raise ApiError(f"{self._label()}: {transport.clean_text(str(meta.get('msg') or 'Fehler'), 200)}")
        data = (body or {}).get("data") if isinstance(body, dict) else body
        if is_read:
            if cache:
                self.cache.put(key, data)
        else:
            self.cache.invalidate(self.scope)
        return data

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
