"""HTTP-Transport (Streamable HTTP) mit Bearer-Auth und Rate-Limit - gleiches Muster wie infra-mcp.

Läuft ausschliesslich als Docker-Container hinter einem Reverse-Proxy und wird als Custom Connector
genutzt. Ohne MCP_API_KEY startet der Server nicht; jeder Request ohne gültiges
"Authorization: Bearer <MCP_API_KEY>" bekommt 401 (auch /healthz).
"""

from __future__ import annotations

import asyncio
import collections
import hmac
import json
import logging
import os
import sys
import time

# Registrierung der Tools passiert beim Import der Module.
from . import tools_plan, tools_read, tools_write  # noqa: F401
from .app import mcp, runtime
from .config import settings
from .version import __version__

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
# httpx loggt sonst jede URL auf INFO.
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("unifi_mcp")


class RateLimiter:
    """Gleitendes Fenster über 60 s."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, collections.deque] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        if len(self._hits) > 1000:
            # Quellen ohne Treffer in der letzten Minute vergessen, damit die Tabelle nicht wächst.
            self._hits = {k: v for k, v in self._hits.items() if v and v[-1] >= now - 60}
        hits = self._hits.setdefault(key, collections.deque())
        while hits and hits[0] < now - 60:
            hits.popleft()
        if len(hits) >= self.per_minute:
            return False
        hits.append(now)
        return True


class _BearerAuthMiddleware:
    """Prüft 'Authorization: Bearer <token>' in konstanter Zeit und begrenzt die Request-Rate:
    gültige Requests insgesamt (Schutz bei geleaktem Token), fehlgeschlagene Anmeldungen je Quelle."""

    def __init__(self, app, token: str, per_minute: int, auth_fail_per_minute: int):
        self.app = app
        self.expected = f"Bearer {token}".encode("latin-1")
        self.ok_limit = RateLimiter(per_minute)
        self.fail_limit = RateLimiter(auth_fail_per_minute)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        from starlette.responses import JSONResponse

        headers = dict(scope.get("headers", []))
        source = (scope.get("client") or ("unbekannt", 0))[0]
        auth_header = headers.get(b"authorization", b"")
        # Konstantzeit-Vergleich, damit das Token nicht über Antwortzeiten erratbar ist.
        if not hmac.compare_digest(auth_header, self.expected):
            if not self.fail_limit.allow(source):
                await JSONResponse({"error": "too many requests"}, status_code=429, headers={"Retry-After": "60"})(
                    scope, receive, send)
                return
            await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
            return
        if not self.ok_limit.allow("token"):
            logger.warning("Rate-Limit des MCP-Endpunkts erreicht")
            await JSONResponse({"error": "too many requests"}, status_code=429, headers={"Retry-After": "60"})(
                scope, receive, send)
            return
        await self.app(scope, receive, send)


def _with_healthz(app):
    """/healthz für den Docker-Healthcheck (liegt hinter der Bearer-Prüfung)."""
    from starlette.responses import JSONResponse

    async def router(scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/healthz":
            await JSONResponse({"status": "ok", "version": __version__})(scope, receive, send)
            return
        await app(scope, receive, send)

    return router


def _build_http_app(api_key: str, host: str = "0.0.0.0"):
    if not api_key:
        raise RuntimeError("MCP_API_KEY (statisches Bearer-Token) fehlt - aus Sicherheitsgründen kein Start ohne Token.")
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.middleware.cors import CORSMiddleware

    cfg = settings()
    # DNS-Rebinding-Schutz aus wie bei infra-mcp: der Dienst ist bewusst unter einer echten Domain
    # erreichbar, die Absicherung übernimmt das Bearer-Token. json_response=True: einfache
    # JSON-Antworten statt SSE-Stream - robuster hinter Reverse-Proxies.
    starlette_app = mcp.streamable_http_app(
        streamable_http_path=os.environ.get("MCP_PATH", "/unifi"),
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host=host,
    )
    secured = _BearerAuthMiddleware(_with_healthz(starlette_app), api_key, cfg.rate_limit_per_minute,
                                    cfg.auth_fail_limit_per_minute)
    # CORS aussen um die Auth-Middleware: Preflight-Requests (ohne Authorization) beantwortet
    # CORSMiddleware direkt.
    return CORSMiddleware(secured, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
                          expose_headers=["mcp-session-id"])


async def _run_http_server(api_key: str, host: str, port: int) -> None:
    import uvicorn

    app = _build_http_app(api_key, host)
    rt = runtime()  # Konsolen-Datei beim Start prüfen, nicht erst beim ersten Tool-Aufruf
    logger.info("unifi-mcp %s: %d Konsole(n) geladen", __version__, len(rt.consoles))
    if not rt.consoles:
        await _log_discovery()
    config = uvicorn.Config(app, host=host, port=port, log_level="info", access_log=False, proxy_headers=False)
    try:
        await uvicorn.Server(config).serve()
    finally:
        await rt.aclose()


async def _log_discovery() -> None:
    """Ohne konfigurierte Konsolen: sichtbare Konsolen je Site-Manager-Key ins Log schreiben
    (Hilfe für CONSOLES_JSON). Keine Keys oder Fehler verhindern den Start nicht."""
    try:
        result = await asyncio.wait_for(tools_read.discover(), timeout=60)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Konsolen-Erkennung fehlgeschlagen (%s)", type(exc).__name__)
        return
    if not result:
        logger.info("Konsolen-Erkennung: kein Site-Manager-Key gesetzt")
    for entry in result:
        logger.info("Konsolen-Erkennung: %s", json.dumps(entry, ensure_ascii=False))


def main() -> None:
    api_key = os.environ.get("MCP_API_KEY", "")
    if not api_key:
        raise RuntimeError("MCP_API_KEY (statisches Bearer-Token) fehlt - aus Sicherheitsgründen kein Start ohne Token.")
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8000"))
    asyncio.run(_run_http_server(api_key, host, port))


if __name__ == "__main__":
    main()
