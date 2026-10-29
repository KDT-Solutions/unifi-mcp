"""Dauerhafter Zustand im Volume /data:

- state.db (SQLite): Audit-Log, Änderungspläne, zur Laufzeit gesetzte Schreibrechte
- backups/<plan_id>.json: Stand vor der Ausführung eines Plans (für rollback_change)

Nur eine Instanz mit diesem Volume betreiben.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any

from .errors import GuardError

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    console TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    console TEXT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    payload TEXT,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS console_writes (
    console TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    changed REAL NOT NULL
);
"""


class Store:
    def __init__(self, data_dir: str, retention_days: int = 365):
        self.data_dir = data_dir
        self.backup_dir = os.path.join(data_dir, "backups")
        os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._db = sqlite3.connect(os.path.join(data_dir, "state.db"), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._last_cleanup = 0.0

    # -- Audit ---------------------------------------------------------------

    def audit(self, console: str, action: str, target: str, result: str, detail: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit(ts, console, action, target, result, detail) VALUES (?,?,?,?,?,?)",
                (time.time(), console, action, str(target)[:300], result, detail[:1000]),
            )
        self._cleanup()

    def audit_log(self, consoles: list[str] | None, action: str | None, since: float | None, limit: int) -> list[dict]:
        query = "SELECT ts, console, action, target, result, detail FROM audit WHERE 1=1"
        args: list[Any] = []
        if consoles is not None:
            query += f" AND console IN ({','.join('?' * len(consoles))})" if consoles else " AND 0"
            args.extend(consoles)
        if action:
            query += " AND action = ?"
            args.append(action)
        if since:
            query += " AND ts >= ?"
            args.append(since)
        query += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        return [
            {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r[0])), "console": r[1], "action": r[2],
             "target": r[3], "result": r[4], **({"detail": r[5]} if r[5] else {})}
            for r in rows
        ]

    def _cleanup(self) -> None:
        now = time.time()
        if now - self._last_cleanup < 3600:
            return
        self._last_cleanup = now
        with self._lock:
            if self.retention_days > 0:
                self._db.execute("DELETE FROM audit WHERE ts < ?", (now - self.retention_days * 86400,))
            # Abgelaufene, nie ausgeführte Pläne samt Payload entfernen.
            self._db.execute("DELETE FROM plans WHERE status = 'planned' AND expires < ?", (now,))

    # -- Schreibrechte zur Laufzeit -----------------------------------------

    def writes_override(self, console: str) -> bool | None:
        with self._lock:
            row = self._db.execute("SELECT enabled FROM console_writes WHERE console = ?", (console,)).fetchone()
        return None if row is None else bool(row[0])

    def set_writes(self, console: str, enabled: bool) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO console_writes(console, enabled, changed) VALUES (?,?,?) "
                "ON CONFLICT(console) DO UPDATE SET enabled = excluded.enabled, changed = excluded.changed",
                (console, int(enabled), time.time()),
            )

    # -- Pläne ---------------------------------------------------------------

    def create_plan(self, console: str, kind: str, target: str, payload: dict, ttl: int) -> tuple[str, float]:
        plan_id = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self._db.execute(
                "INSERT INTO plans(id, console, kind, target, payload, created, expires, status) VALUES (?,?,?,?,?,?,?,?)",
                (plan_id, console, kind, target, json.dumps(payload), now, now + ttl, "planned"),
            )
        return plan_id, now + ttl

    def get_plan(self, plan_id: str) -> dict:
        if not isinstance(plan_id, str) or len(plan_id) != 32 or not all(c in "0123456789abcdef" for c in plan_id):
            raise GuardError("Ungültige Plan-ID")
        with self._lock:
            row = self._db.execute(
                "SELECT id, console, kind, target, payload, created, expires, status FROM plans WHERE id = ?", (plan_id,)
            ).fetchone()
        if row is None:
            raise GuardError("Plan nicht gefunden (abgelaufen oder nie angelegt)")
        return {"id": row[0], "console": row[1], "kind": row[2], "target": row[3],
                "payload": json.loads(row[4]) if row[4] else None, "created": row[5], "expires": row[6], "status": row[7]}

    def claim_plan(self, plan_id: str, console: str) -> dict:
        """Plan atomar verbrauchen: nur einmal, nur für die eigene Konsole, nur vor Ablauf."""
        plan = self.get_plan(plan_id)
        if plan["console"] != console:
            raise GuardError("Plan gehört zu einer anderen Konsole")
        with self._lock:
            cur = self._db.execute(
                "UPDATE plans SET status = 'executing' WHERE id = ? AND status = 'planned' AND expires >= ?",
                (plan_id, time.time()),
            )
        if cur.rowcount != 1:
            if plan["status"] != "planned":
                raise GuardError(f"Plan wurde bereits verwendet (Status {plan['status']})")
            raise GuardError("Plan ist abgelaufen - bitte mit prepare_change neu erstellen")
        return plan

    def finish_plan(self, plan_id: str, status: str, keep_payload: bool = False) -> None:
        with self._lock:
            if keep_payload:
                self._db.execute("UPDATE plans SET status = ? WHERE id = ?", (status, plan_id))
            else:
                # Payload kann Passphrasen enthalten: nach der Ausführung nicht weiter aufbewahren.
                self._db.execute("UPDATE plans SET status = ?, payload = NULL WHERE id = ?", (status, plan_id))

    def set_plan_status(self, plan_id: str, expected: str, status: str) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE plans SET status = ? WHERE id = ? AND status = ?", (status, plan_id, expected))
        return cur.rowcount == 1

    # -- Backups -------------------------------------------------------------

    def backup_path(self, plan_id: str) -> str:
        return os.path.join(self.backup_dir, f"{plan_id}.json")

    def write_backup(self, plan_id: str, content: dict) -> str:
        path = self.backup_path(plan_id)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(content, handle, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
        return path

    def read_backup(self, plan_id: str) -> dict:
        try:
            with open(self.backup_path(plan_id), encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError:
            raise GuardError("Für diesen Plan gibt es keine Sicherung") from None

    def update_backup(self, plan_id: str, **fields: Any) -> None:
        content = self.read_backup(plan_id)
        content.update(fields)
        self.write_backup(plan_id, content)
