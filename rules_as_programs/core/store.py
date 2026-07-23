"""SQLite-backed verdict store, queryable grouped by project.

The native findings inbox and ``rap status`` both read from here. A *verdict* is one
rule program's judgment about one conversation at one point in time.
"""

from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .. import config


@dataclass
class Verdict:
    rule_id: str
    rule_title: str
    severity: str
    message: str
    conversation_id: str
    project_root: str
    label: str = ""
    evidence: str = ""
    fuzzy: bool = True  # whether a PAW judgment (vs deterministic) produced it
    fingerprint: str = ""
    trigger_event_id: str = ""
    trigger_kind: str = ""
    source_hash: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    id: int | None = None
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "message": self.message,
            "conversation_id": self.conversation_id,
            "project_root": self.project_root,
            "label": self.label,
            "evidence": self.evidence,
            "fuzzy": self.fuzzy,
            "fingerprint": self.fingerprint,
            "trigger_event_id": self.trigger_event_id,
            "trigger_kind": self.trigger_kind,
            "source_hash": self.source_hash,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "id": self.id,
            "ts": self.ts,
        }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_title TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    label TEXT,
    evidence TEXT,
    fuzzy INTEGER DEFAULT 1,
    acknowledged INTEGER DEFAULT 0,
    reviewed_at REAL,
    review_reason TEXT,
    suppressed INTEGER DEFAULT 0,
    suppression_reason TEXT,
    fingerprint TEXT,
    trigger_event_id TEXT,
    trigger_kind TEXT,
    source_hash TEXT,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_project ON verdicts(project_root);
CREATE INDEX IF NOT EXISTS idx_verdicts_ts ON verdicts(ts);
"""

_MIGRATION_COLUMNS = {
    "acknowledged": "INTEGER DEFAULT 0",
    "reviewed_at": "REAL",
    "review_reason": "TEXT",
    "suppressed": "INTEGER DEFAULT 0",
    "suppression_reason": "TEXT",
    "fingerprint": "TEXT",
    "trigger_event_id": "TEXT",
    "trigger_kind": "TEXT",
    "source_hash": "TEXT",
}


def finding_fingerprint(
    project_root: str, rule_id: str, message: str, source_hash: str = ""
) -> str:
    """Stable issue-like identity for repeated occurrences of one problem."""
    normalized = re.sub(r"\s+", " ", (message or "").strip().lower())
    raw = "\x00".join((
        project_root or "", rule_id or "", source_hash or "legacy", normalized))
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]


class VerdictStore:
    def __init__(self, path: str | None = None):
        self.path = str(path or config.db_path())
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(verdicts)")}
            for name, sql_type in _MIGRATION_COLUMNS.items():
                if name not in cols:
                    conn.execute(f"ALTER TABLE verdicts ADD COLUMN {name} {sql_type}")
            # Existing rows predate fingerprints. Populate them once so old
            # findings group and resolve exactly like new occurrences.
            rows = conn.execute(
                """SELECT id, project_root, rule_id, message FROM verdicts
                   WHERE fingerprint IS NULL OR fingerprint = ''"""
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE verdicts SET fingerprint=? WHERE id=?",
                    (
                        finding_fingerprint(
                            row["project_root"], row["rule_id"], row["message"]),
                        row["id"],
                    ),
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_fingerprint "
                "ON verdicts(fingerprint)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_open "
                "ON verdicts(acknowledged, suppressed, ts)")

    def record(self, v: Verdict) -> int:
        fingerprint = v.fingerprint or finding_fingerprint(
            v.project_root, v.rule_id, v.message, v.source_hash)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO verdicts
                   (rule_id, rule_title, severity, message, conversation_id,
                    project_root, label, evidence, fuzzy, fingerprint,
                    trigger_event_id, trigger_kind, suppressed,
                    suppression_reason, source_hash, ts)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    v.rule_id, v.rule_title, v.severity, v.message,
                    v.conversation_id, v.project_root, v.label, v.evidence,
                    1 if v.fuzzy else 0, fingerprint, v.trigger_event_id,
                    v.trigger_kind, 1 if v.suppressed else 0,
                    v.suppression_reason, v.source_hash, v.ts,
                ),
            )
            return int(cur.lastrowid)

    def recent(self, limit: int = 100, project_root: str | None = None,
               include_acknowledged: bool = False,
               include_suppressed: bool = False) -> list[dict[str, Any]]:
        q = "SELECT * FROM verdicts"
        clauses: list[str] = []
        params: list[Any] = []
        if project_root:
            clauses.append("project_root = ?")
            params.append(project_root)
        if not include_acknowledged:
            clauses.append("acknowledged = 0")
        if not include_suppressed:
            clauses.append("suppressed = 0")
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _group_rows(rows: list[dict[str, Any]], limit: int | None = None) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for row in rows:
            fingerprint = row.get("fingerprint") or finding_fingerprint(
                row.get("project_root", ""), row.get("rule_id", ""),
                row.get("message", ""))
            if fingerprint not in grouped:
                grouped[fingerprint] = []
                order.append(fingerprint)
            grouped[fingerprint].append(row)
        out: list[dict[str, Any]] = []
        for fingerprint in order:
            occurrences = grouped[fingerprint]
            latest = dict(occurrences[0])
            latest["latest_severity"] = latest.get("severity", "info")
            rank = {"info": 1, "warn": 2, "warning": 2, "critical": 3}
            highest = max(
                (str(row.get("severity", "info")).lower() for row in occurrences),
                key=lambda value: rank.get(value, 0),
                default="info",
            )
            latest["severity"] = (
                "warn" if highest == "warning" else highest)
            latest["fingerprint"] = fingerprint
            latest["ids"] = [int(row["id"]) for row in occurrences]
            latest["occurrences"] = len(occurrences)
            latest["first_seen"] = min(float(row.get("ts", 0)) for row in occurrences)
            latest["last_seen"] = max(float(row.get("ts", 0)) for row in occurrences)
            out.append(latest)
            if limit is not None and len(out) >= limit:
                break
        return out

    def grouped(
        self,
        project_root: str | None = None,
        include_reviewed: bool = False,
        include_suppressed: bool = False,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        rows = self.recent(
            limit=limit,
            project_root=project_root,
            include_acknowledged=include_reviewed,
            include_suppressed=include_suppressed,
        )
        return self._group_rows(rows)

    def history_grouped(
        self, project_root: str | None = None, limit: int = 1000
    ) -> list[dict[str, Any]]:
        clauses = ["(acknowledged = 1 OR suppressed = 1)"]
        params: list[Any] = []
        if project_root:
            clauses.append("project_root = ?")
            params.append(project_root)
        params.append(limit)
        query = (
            "SELECT * FROM verdicts WHERE " + " AND ".join(clauses)
            + " ORDER BY ts DESC LIMIT ?"
        )
        with self._lock, self._connect() as conn:
            rows = [dict(row) for row in conn.execute(query, params).fetchall()]
        return self._group_rows(rows)

    def by_project(
        self, limit_per_project: int | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        """Actionable finding groups by project (not raw occurrence rows)."""
        out: dict[str, list[dict[str, Any]]] = {}
        with self._lock, self._connect() as conn:
            rows = [
                dict(row) for row in conn.execute(
                    """SELECT * FROM verdicts
                       WHERE acknowledged=0 AND suppressed=0
                       ORDER BY ts DESC"""
                ).fetchall()
            ]
        per_project: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            proj = row["project_root"] or "(unknown)"
            per_project.setdefault(proj, []).append(row)
        for proj, project_rows in per_project.items():
            out[proj] = self._group_rows(project_rows, limit_per_project)
        return out

    def acknowledge(self, ids: list[int] | None = None,
                    project_root: str | None = None,
                    fingerprint: str | None = None,
                    reason: str | None = None) -> int:
        """Mark findings reviewed (hidden from the menu, kept in history)."""
        reviewed_at = time.time()
        with self._lock, self._connect() as conn:
            if ids:
                qs = ",".join("?" for _ in ids)
                cur = conn.execute(
                    f"""UPDATE verdicts SET acknowledged=1, reviewed_at=?,
                        review_reason=? WHERE id IN ({qs})""",
                    [reviewed_at, reason or "reviewed", *list(ids)],
                )
            elif fingerprint:
                cur = conn.execute(
                    """UPDATE verdicts SET acknowledged=1, reviewed_at=?,
                       review_reason=? WHERE fingerprint=? AND acknowledged=0""",
                    (reviewed_at, reason or "reviewed", fingerprint),
                )
            elif project_root:
                cur = conn.execute(
                    """UPDATE verdicts SET acknowledged=1, reviewed_at=?,
                       review_reason=? WHERE project_root=? AND acknowledged=0""",
                    (reviewed_at, reason or "reviewed", project_root),
                )
            else:
                cur = conn.execute(
                    """UPDATE verdicts SET acknowledged=1, reviewed_at=?,
                       review_reason=? WHERE acknowledged=0""",
                    (reviewed_at, reason or "reviewed"),
                )
            return cur.rowcount

    def reopen(self, ids: list[int] | None = None,
               fingerprint: str | None = None) -> int:
        with self._lock, self._connect() as conn:
            if ids:
                qs = ",".join("?" for _ in ids)
                cur = conn.execute(
                    f"""UPDATE verdicts SET acknowledged=0, reviewed_at=NULL,
                        review_reason=NULL WHERE id IN ({qs})""", list(ids))
            elif fingerprint:
                cur = conn.execute(
                    """UPDATE verdicts SET acknowledged=0, reviewed_at=NULL,
                       review_reason=NULL WHERE fingerprint=?""", (fingerprint,))
            else:
                return 0
            return cur.rowcount

    def get(self, finding_id: int) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM verdicts WHERE id=?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def occurrences(self, fingerprint: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM verdicts WHERE fingerprint=?
                   ORDER BY ts DESC LIMIT ?""", (fingerprint, limit)).fetchall()
        return [dict(row) for row in rows]

    def clear(self, project_root: str | None = None) -> None:
        with self._lock, self._connect() as conn:
            if project_root:
                conn.execute("DELETE FROM verdicts WHERE project_root = ?", (project_root,))
            else:
                conn.execute("DELETE FROM verdicts")


def project_label(project_root: str) -> str:
    return os.path.basename(project_root.rstrip("/")) or project_root or "(unknown)"
