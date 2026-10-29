"""Protokollierung auf stdout: jeder Tool-Aufruf als eine JSON-Zeile
(Toolname, Parameter ohne Secrets, Resultat-Kurzfassung, Dauer).

Das dauerhafte Audit-Log der schreibenden Aktionen liegt in der SQLite-Datenbank
(siehe store.py) und ist über das Tool get_audit_log abrufbar.
"""

from __future__ import annotations

import datetime
import json
import sys
from typing import Any


def log_event(event: str, **fields: Any) -> None:
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        **fields,
    }
    print(json.dumps(record, ensure_ascii=False, default=str), file=sys.stdout, flush=True)


def summarize_result(result: Any) -> Any:
    """Kurzfassung fürs Log - keine Inhalte wie Client-Listen oder Passphrasen."""
    if isinstance(result, dict):
        summary: dict[str, Any] = {"keys": sorted(result.keys())[:20]}
        for key in ("executed", "preview", "action", "status", "plan_id", "console", "count"):
            if key in result and isinstance(result[key], (str, int, bool, type(None))):
                summary[key] = result[key]
        return summary
    if isinstance(result, list):
        return {"items": len(result)}
    if isinstance(result, str):
        return {"chars": len(result)}
    return {"type": type(result).__name__}
