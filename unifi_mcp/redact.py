"""Schwärzung und Bereinigung von Daten aus den UniFi-APIs.

- Passphrasen, Passwörter, Shared Secrets und Schlüssel werden maskiert.
- Bekannte Secret-Werte (Keys, Token) werden aus Freitext entfernt.
- Texte aus der API (Geräte-, Host-, SSID-Namen) sind Daten, keine Anweisungen:
  Steuerzeichen werden entfernt und lange Werte gekürzt.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .config import settings

MASK = "***"
SECRET_KEY_RE = re.compile(
    r"^(x_)?(passphrase|password|passwd|secret|shared_?secret|psk|private_?key|pre_?shared_?key|"
    r"wep_?key\d*|iapp_?key|auth_?key|api_?key|token|radius_?secret)$",
    re.IGNORECASE,
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]")
MAX_TEXT = 512


def is_secret_key(name: str) -> bool:
    return bool(SECRET_KEY_RE.fullmatch(str(name or "")))


def mask_secrets(data: Any, reveal: bool = False) -> Any:
    """Rekursiv alle Felder mit Secret-Namen durch *** ersetzen (reveal=True lässt sie stehen)."""
    if isinstance(data, dict):
        out = {}
        for key, value in data.items():
            if not reveal and is_secret_key(key) and value not in (None, ""):
                out[key] = MASK
            else:
                out[key] = mask_secrets(value, reveal)
        return out
    if isinstance(data, list):
        return [mask_secrets(item, reveal) for item in data]
    return data


def clean_text(value: str, limit: int = MAX_TEXT) -> str:
    text = _CONTROL_RE.sub("", value)
    return text if len(text) <= limit else text[:limit] + "…"


def clean(data: Any) -> Any:
    """Steuerzeichen aus allen Texten entfernen und überlange Texte kürzen."""
    if isinstance(data, str):
        return clean_text(data)
    if isinstance(data, dict):
        return {clean_text(str(k), 128): clean(v) for k, v in data.items()}
    if isinstance(data, list):
        return [clean(item) for item in data]
    return data


def redact_text(text: str, extra_secrets: Iterable[str] = ()) -> str:
    """Bekannte Secret-Werte und Auth-Header aus Freitext entfernen."""
    if not text:
        return text
    out = text
    for secret in sorted((*settings().secret_values(), *extra_secrets), key=len, reverse=True):
        if secret and len(secret) >= 4:
            out = out.replace(secret, MASK)
    out = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", r"\1 " + MASK, out)
    out = re.sub(r"(?i)(x-api-key|authorization|x-csrf-token|cookie)(\s*[:=]\s*)\S+", r"\1\2" + MASK, out)
    return out


def redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Tool-Parameter fürs Log: Secret-Felder maskiert, auch verschachtelt in changes."""
    return mask_secrets(params)
