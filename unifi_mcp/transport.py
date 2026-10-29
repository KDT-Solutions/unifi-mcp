"""HTTP-Grundlagen: TLS (inkl. Zertifikats-Pinning), Wiederholung bei HTTP 429,
kurzer Cache für lesende Aufrufe und Fehlermeldungen ohne Secrets."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from .errors import ApiError, UnclearStateError
from .redact import clean_text, redact_text

logger = logging.getLogger("unifi_mcp.transport")

CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 30.0
MAX_RETRIES_429 = 3
MAX_RETRY_WAIT = 30.0
READ_METHODS = ("GET",)


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def fetch_peer_certificate(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> bytes:
    """Zertifikat der Gegenstelle (DER) holen, ohne Daten zu senden. Nur zum Pinnen:
    die eigentlichen Requests laufen danach über einen Kontext, der genau diesem
    Zertifikat vertraut."""
    import socket

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ApiError("Konsole liefert kein TLS-Zertifikat")
    return der


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def pinned_context(der: bytes) -> ssl.SSLContext:
    """SSL-Kontext, der ausschliesslich diesem (selbstsignierten) Zertifikat vertraut.
    Der Hostname wird nicht geprüft - das Pinning ersetzt ihn. Gültigkeit und
    Signatur prüft OpenSSL weiterhin; ein anderes Zertifikat scheitert beim
    Handshake, bevor ein Header (API-Key) gesendet wird."""
    ctx = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(der))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return ctx


def build_pinned_context(base_url: str, expected: str) -> ssl.SSLContext:
    parts = urlsplit(base_url)
    host, port = parts.hostname or "", parts.port or 443
    der = fetch_peer_certificate(host, port)
    actual = fingerprint(der)
    if actual != expected:
        raise ApiError(
            "TLS-Fingerabdruck stimmt nicht mit tls_fingerprint überein - Verbindung abgebrochen. "
            f"Vorgelegt: sha256:{actual}. Nur übernehmen, wenn das neue Zertifikat auf der Konsole "
            "selbst geprüft wurde (z.B. nach einem Zertifikatswechsel)."
        )
    return pinned_context(der)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class TtlCache:
    def __init__(self, ttl: float):
        self.ttl = ttl
        self._data: dict[tuple, tuple[float, Any]] = {}

    def get(self, key: tuple) -> Any:
        hit = self._data.get(key)
        if hit is None:
            return None
        expires, value = hit
        if expires < time.monotonic():
            self._data.pop(key, None)
            return None
        return value

    def put(self, key: tuple, value: Any, ttl: float | None = None) -> None:
        if (ttl if ttl is not None else self.ttl) <= 0:
            return
        self._data[key] = (time.monotonic() + (ttl if ttl is not None else self.ttl), value)

    def invalidate(self, scope: str) -> None:
        for key in [k for k in self._data if k and k[0] == scope]:
            self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def error_message(resp: httpx.Response, label: str) -> str:
    """Kurze Fehlermeldung aus Statuscode und den Feldern code/message der API."""
    detail = ""
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        parts = []
        for key in ("statusName", "code", "message", "msg", "error"):
            value = body.get(key)
            if isinstance(value, (str, int)) and value != "":
                parts.append(str(value))
        meta = body.get("meta")
        if isinstance(meta, dict) and meta.get("msg"):
            parts.append(str(meta["msg"]))
        detail = " - ".join(dict.fromkeys(parts))
    text = f"{label}: HTTP {resp.status_code}" + (f" ({detail})" if detail else "")
    return clean_text(redact_text(text), 400)


def retry_after_seconds(resp: httpx.Response, attempt: int) -> float:
    value = resp.headers.get("retry-after", "")
    try:
        wait = float(value)
    except ValueError:
        wait = float(2 ** attempt)
    return max(0.0, min(wait, MAX_RETRY_WAIT))


async def send(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    label: str,
    headers: dict[str, str] | None = None,
    params: Any = None,
    json: Any = None,
    timeout: float | None = None,
    read: bool | None = None,
) -> httpx.Response:
    """Request mit Wiederholung bei 429 (Retry-After, höchstens 3x, max. 30 s).
    429 heisst: nicht ausgeführt, deshalb auch bei schreibenden Aufrufen wiederholbar.
    Timeouts bei schreibenden Aufrufen ergeben UnclearStateError (nie automatisch wiederholen)."""
    is_read = method in READ_METHODS if read is None else read
    attempt = 0
    request_timeout = httpx.Timeout(timeout or READ_TIMEOUT, connect=CONNECT_TIMEOUT)
    while True:
        try:
            resp = await client.request(method, url, headers=headers, params=params, json=json, timeout=request_timeout)
        except httpx.ConnectError as exc:
            raise ApiError(f"{label}: keine Verbindung ({_reason(exc)})") from None
        except httpx.TimeoutException:
            if is_read:
                raise ApiError(f"{label}: Zeitüberschreitung") from None
            raise UnclearStateError(
                f"{label}: Zeitüberschreitung beim Schreiben. Ob die Aktion ausgeführt wurde, ist unklar - "
                "zuerst den aktuellen Stand lesen, nicht blind wiederholen."
            ) from None
        except httpx.HTTPError as exc:
            if is_read:
                raise ApiError(f"{label}: Verbindungsfehler ({type(exc).__name__})") from None
            raise UnclearStateError(
                f"{label}: Verbindung beim Schreiben abgebrochen ({type(exc).__name__}). Stand zuerst prüfen."
            ) from None
        if resp.status_code == 429 and attempt < MAX_RETRIES_429:
            wait = retry_after_seconds(resp, attempt)
            logger.warning("%s: HTTP 429, neuer Versuch in %.1f s", label, wait)
            await asyncio.sleep(wait)
            attempt += 1
            continue
        return resp


def _reason(exc: Exception) -> str:
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text:
        return "TLS-Zertifikat nicht vertrauenswürdig - bei selbstsigniertem Zertifikat tls_fingerprint setzen"
    if "Name or service not known" in text or "nodename nor servname" in text:
        return "Hostname nicht auflösbar"
    return type(exc).__name__


def decode(resp: httpx.Response, label: str) -> Any:
    if resp.status_code >= 400:
        raise ApiError(error_message(resp, label), status=resp.status_code)
    if resp.status_code == 204 or not resp.content:
        return None
    try:
        return resp.json()
    except ValueError:
        raise ApiError(f"{label}: Antwort ist kein JSON (HTTP {resp.status_code})") from None
