"""Persistance du moteur (SQLite sur volume dédié) : incidents, actions, blocages actifs.

Le moteur ne dépend PAS de la base métier qu'il est chargé de réparer.
"""
import json
import sqlite3
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    source TEXT NOT NULL,
    detected_at REAL NOT NULL,
    window_start REAL,
    resolved_at REAL,
    rto_s REAL,
    playbook TEXT,
    proof TEXT,
    events TEXT NOT NULL DEFAULT '[]',
    summary TEXT
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    at REAL NOT NULL,
    action TEXT NOT NULL,
    params TEXT NOT NULL,
    result TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS blocks (
    kind TEXT NOT NULL,          -- ip | fingerprint | strict
    value TEXT NOT NULL,
    expires_at REAL NOT NULL,
    incident_id TEXT,
    PRIMARY KEY (kind, value)
);
"""

OPEN_STATUSES = ("DETECTED", "REMEDIATING", "VERIFYING")


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    # --- incidents ---
    def create_incident(self, type_: str, source: str, event: dict, window_start: float | None) -> dict:
        inc_id = "inc-" + uuid.uuid4().hex[:8]
        self.db.execute(
            "INSERT INTO incidents (id, type, status, source, detected_at, window_start, events) "
            "VALUES (?, ?, 'DETECTED', ?, ?, ?, ?)",
            (inc_id, type_, source, time.time(), window_start, json.dumps([event])),
        )
        return self.get_incident(inc_id)

    def attach_event(self, inc_id: str, event: dict) -> None:
        row = self.db.execute("SELECT events FROM incidents WHERE id = ?", (inc_id,)).fetchone()
        events = json.loads(row["events"])[-49:] + [event]
        self.db.execute("UPDATE incidents SET events = ? WHERE id = ?", (json.dumps(events), inc_id))

    def update_incident(self, inc_id: str, **fields) -> None:
        cols = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(f"UPDATE incidents SET {cols} WHERE id = ?", (*fields.values(), inc_id))

    def get_incident(self, inc_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM incidents WHERE id = ?", (inc_id,)).fetchone()
        return self._incident(row) if row else None

    def find_open(self, type_: str, since: float) -> dict | None:
        row = self.db.execute(
            f"SELECT * FROM incidents WHERE type = ? AND detected_at > ? AND status IN {OPEN_STATUSES} "
            "ORDER BY detected_at DESC LIMIT 1", (type_, since)).fetchone()
        return self._incident(row) if row else None

    def recent_resolved(self, type_: str | None, since: float) -> dict | None:
        """Dernier incident résolu depuis « since » (de ce type, ou de n'importe quel type si None)."""
        row = self.db.execute(
            "SELECT * FROM incidents WHERE (? IS NULL OR type = ?) AND resolved_at > ? "
            "ORDER BY resolved_at DESC LIMIT 1", (type_, type_, since)).fetchone()
        return self._incident(row) if row else None

    def list_incidents(self, limit: int = 20) -> list[dict]:
        rows = self.db.execute("SELECT * FROM incidents ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._incident(r) for r in rows]

    def open_incidents(self) -> list[dict]:
        rows = self.db.execute(f"SELECT * FROM incidents WHERE status IN {OPEN_STATUSES}").fetchall()
        return [self._incident(r) for r in rows]

    def _incident(self, row: sqlite3.Row) -> dict:
        d = dict(row)
        d["events"] = json.loads(d["events"])
        d["proof"] = json.loads(d["proof"]) if d["proof"] else None
        d["actions"] = self.list_actions(incident_id=d["id"])
        return d

    # --- actions (journal d'audit) ---
    def record_action(self, incident_id: str | None, action: str, params: dict, result: str, detail: str = "") -> dict:
        at = time.time()
        cur = self.db.execute(
            "INSERT INTO actions (incident_id, at, action, params, result, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, at, action, json.dumps(params), result, detail[:500]))
        return {"id": cur.lastrowid, "incident_id": incident_id, "at": at, "action": action,
                "params": params, "result": result, "detail": detail[:500]}

    def list_actions(self, incident_id: str | None = None, limit: int = 100) -> list[dict]:
        if incident_id:
            rows = self.db.execute("SELECT * FROM actions WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()
        else:
            rows = self.db.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "params": json.loads(r["params"])} for r in rows]

    def actions_since(self, since: float) -> int:
        return self.db.execute("SELECT COUNT(*) FROM actions WHERE at > ? AND result = 'ok'", (since,)).fetchone()[0]

    # --- blocages actifs (WAF) ---
    def upsert_block(self, kind: str, value: str, ttl_s: float, incident_id: str | None) -> None:
        self.db.execute(
            "INSERT INTO blocks (kind, value, expires_at, incident_id) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(kind, value) DO UPDATE SET expires_at = excluded.expires_at",
            (kind, value, time.time() + ttl_s, incident_id))

    def active_blocks(self) -> list[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM blocks WHERE expires_at > ? ORDER BY expires_at", (time.time(),)).fetchall()]

    def purge_expired_blocks(self) -> int:
        return self.db.execute("DELETE FROM blocks WHERE expires_at <= ?", (time.time(),)).rowcount

    def clear_blocks(self) -> None:
        self.db.execute("DELETE FROM blocks")
