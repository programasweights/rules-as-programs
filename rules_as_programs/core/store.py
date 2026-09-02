"""SQLite-backed verdict store, queryable grouped by project.

The native findings inbox and ``rap status`` both read from here. A *verdict* is one
rule program's judgment about one conversation at one point in time.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .. import config
from . import revisions


@dataclass
class Verdict:
    rule_id: str
    rule_title: str
    severity: str
    conversation_id: str
    project_root: str
    evaluation: dict[str, Any]
    fingerprint: str = ""
    trigger_event_id: str = ""
    trigger_kind: str = ""
    source_hash: str = ""
    behavior_hash: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    id: int | None = None
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "conversation_id": self.conversation_id,
            "project_root": self.project_root,
            "evaluation": self.evaluation,
            "fingerprint": self.fingerprint,
            "trigger_event_id": self.trigger_event_id,
            "trigger_kind": self.trigger_kind,
            "source_hash": self.source_hash,
            "behavior_hash": self.behavior_hash,
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
    conversation_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    evaluation_json TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    reviewed_at REAL,
    review_reason TEXT,
    suppressed INTEGER DEFAULT 0,
    suppression_reason TEXT,
    fingerprint TEXT,
    trigger_event_id TEXT,
    trigger_kind TEXT,
    source_hash TEXT,
    behavior_hash TEXT,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_project ON verdicts(project_root);
CREATE INDEX IF NOT EXISTS idx_verdicts_ts ON verdicts(ts);
"""
FINDING_SCHEMA_VERSION = 4
SQLITE_BUSY_RETRIES = 2
SQLITE_BUSY_RETRY_DELAY_SECONDS = 0.05


def finding_fingerprint(
    project_root: str, rule_id: str, severity: str, source_hash: str = ""
) -> str:
    """Stable issue-like identity for repeated occurrences of one problem."""
    raw = "\x00".join(
        (
            project_root or "",
            rule_id or "",
            source_hash or "no-source",
            str(severity or "").lower(),
        )
    )
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:24]


def reset_development_finding_history() -> None:
    """One-time destructive reset for the strict finding schema."""
    marker = config.state_dir() / "finding-schema"
    expected = str(FINDING_SCHEMA_VERSION)
    try:
        if marker.read_text(encoding="utf-8").strip() == expected:
            return
    except OSError:
        pass
    db_path = config.db_path()
    project_roots: list[str] = []
    if db_path.exists():
        try:
            with sqlite3.connect(str(db_path)) as conn:
                project_roots = [
                    str(row[0])
                    for row in conn.execute(
                        "SELECT DISTINCT project_root FROM verdicts"
                    )
                    if row[0]
                ]
        except sqlite3.Error:
            project_roots = []
    for suffix in ("", "-wal", "-shm"):
        try:
            (db_path.parent / f"{db_path.name}{suffix}").unlink()
        except OSError:
            pass
    shutil.rmtree(config.state_dir() / "ledgers", ignore_errors=True)
    for project_root in project_roots:
        for path in (
            config.project_log_file(project_root),
            config.project_evaluation_log_file(project_root),
        ):
            try:
                path.unlink()
            except OSError:
                pass
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(expected + "\n", encoding="utf-8")


class VerdictStore:
    def __init__(self, path: str | None = None):
        self.path = str(path or config.db_path())
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _decode(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        value = dict(row)
        raw = value.pop("evaluation_json", "{}")
        try:
            value["evaluation"] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            value["evaluation"] = {}
        return value

    def _init(self) -> None:
        with self._lock, self._connect() as conn:
            current = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if current != FINDING_SCHEMA_VERSION:
                conn.executescript(
                    "DROP TABLE IF EXISTS verdicts;"
                    "DROP INDEX IF EXISTS idx_verdicts_project;"
                    "DROP INDEX IF EXISTS idx_verdicts_ts;"
                    "DROP INDEX IF EXISTS idx_verdicts_fingerprint;"
                    "DROP INDEX IF EXISTS idx_verdicts_open;"
                )
            conn.executescript(_SCHEMA)
            columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(verdicts)").fetchall()
            }
            if "behavior_hash" not in columns:
                conn.execute("ALTER TABLE verdicts ADD COLUMN behavior_hash TEXT")
            legacy_rows = conn.execute(
                """SELECT id, rule_id, severity, project_root, source_hash,
                          evaluation_json
                   FROM verdicts
                   WHERE behavior_hash IS NULL OR behavior_hash=''"""
            ).fetchall()
            for row in legacy_rows:
                try:
                    evaluation = json.loads(row["evaluation_json"])
                except (json.JSONDecodeError, TypeError):
                    evaluation = {}
                rule = evaluation.get("rule") or {}
                behavior = str(rule.get("behavior_hash") or "")
                if not behavior and rule.get("source"):
                    behavior = revisions.behavior_hash(str(rule["source"]))
                if not behavior:
                    behavior = str(row["source_hash"] or "")
                fingerprint = finding_fingerprint(
                    str(row["project_root"] or ""),
                    str(row["rule_id"] or ""),
                    str(row["severity"] or ""),
                    behavior,
                )
                conn.execute(
                    """UPDATE verdicts
                       SET behavior_hash=?, fingerprint=?
                       WHERE id=?""",
                    (behavior, fingerprint, int(row["id"])),
                )
            conn.execute(f"PRAGMA user_version={FINDING_SCHEMA_VERSION}")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_fingerprint "
                "ON verdicts(fingerprint)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_verdicts_open "
                "ON verdicts(acknowledged, suppressed, ts)"
            )

    def record(self, v: Verdict) -> int:
        fingerprint = v.fingerprint or finding_fingerprint(
            v.project_root, v.rule_id, v.severity, v.source_hash
        )
        with self._lock:
            for attempt in range(SQLITE_BUSY_RETRIES + 1):
                try:
                    with self._connect() as conn:
                        cur = conn.execute(
                            """INSERT INTO verdicts
                               (rule_id, rule_title, severity, conversation_id,
                                project_root, evaluation_json, fingerprint,
                                trigger_event_id, trigger_kind, suppressed,
                                suppression_reason, source_hash, behavior_hash, ts)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (
                                v.rule_id,
                                v.rule_title,
                                v.severity,
                                v.conversation_id,
                                v.project_root,
                                json.dumps(v.evaluation, ensure_ascii=False),
                                fingerprint,
                                v.trigger_event_id,
                                v.trigger_kind,
                                1 if v.suppressed else 0,
                                v.suppression_reason,
                                v.source_hash,
                                v.behavior_hash,
                                v.ts,
                            ),
                        )
                        return int(cur.lastrowid)
                except sqlite3.OperationalError as exc:
                    busy = any(
                        marker in str(exc).lower() for marker in ("locked", "busy")
                    )
                    if not busy or attempt >= SQLITE_BUSY_RETRIES:
                        raise
                    time.sleep(SQLITE_BUSY_RETRY_DELAY_SECONDS)
        raise RuntimeError("unreachable SQLite finding retry state")

    def recent(
        self,
        limit: int = 100,
        project_root: str | None = None,
        include_acknowledged: bool = False,
        include_suppressed: bool = False,
    ) -> list[dict[str, Any]]:
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
        return [self._decode(r) for r in rows]

    @staticmethod
    def _group_rows(
        rows: list[dict[str, Any]], limit: int | None = None
    ) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for row in rows:
            fingerprint = row.get("fingerprint") or finding_fingerprint(
                row.get("project_root", ""),
                row.get("rule_id", ""),
                row.get("severity", ""),
                row.get("source_hash", ""),
            )
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
            latest["severity"] = "warn" if highest == "warning" else highest
            latest["fingerprint"] = fingerprint
            latest["last_seen"] = max(float(row.get("ts", 0)) for row in occurrences)
            latest["occurrence_count"] = len(occurrences)
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
            "SELECT * FROM verdicts WHERE "
            + " AND ".join(clauses)
            + " ORDER BY ts DESC LIMIT ?"
        )
        with self._lock, self._connect() as conn:
            rows = [self._decode(row) for row in conn.execute(query, params).fetchall()]
        return self._group_rows(rows)

    def by_project(
        self, limit_per_project: int | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        """Latest actionable occurrence per fingerprint, grouped by project."""
        out: dict[str, list[dict[str, Any]]] = {}
        with self._lock, self._connect() as conn:
            rows = [
                self._decode(row)
                for row in conn.execute(
                    """SELECT verdicts.*, latest.occurrence_count
                       FROM verdicts
                       JOIN (
                           SELECT fingerprint, MAX(id) AS latest_id,
                                  COUNT(*) AS occurrence_count
                           FROM verdicts
                           WHERE acknowledged=0 AND suppressed=0
                           GROUP BY fingerprint
                       ) latest ON latest.latest_id = verdicts.id
                       ORDER BY verdicts.ts DESC"""
                ).fetchall()
            ]
        per_project: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            proj = row["project_root"] or "(unknown)"
            per_project.setdefault(proj, []).append(row)
        for proj, project_rows in per_project.items():
            out[proj] = (
                project_rows[:limit_per_project]
                if limit_per_project is not None
                else project_rows
            )
        return out

    def acknowledge(
        self,
        ids: list[int] | None = None,
        project_root: str | None = None,
        fingerprint: str | None = None,
        reason: str | None = None,
    ) -> int:
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

    def acknowledge_rule(
        self,
        rule_id: str,
        project_root: str,
        reason: str = "rule_deleted",
    ) -> int:
        """Archive actionable findings for one no-longer-installed rule."""
        reviewed_at = time.time()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """UPDATE verdicts SET acknowledged=1, reviewed_at=?,
                   review_reason=?
                   WHERE rule_id=? AND project_root=?
                     AND acknowledged=0 AND suppressed=0""",
                (reviewed_at, reason, rule_id, project_root),
            )
            return cur.rowcount

    def reopen(
        self, ids: list[int] | None = None, fingerprint: str | None = None
    ) -> int:
        with self._lock, self._connect() as conn:
            if ids:
                qs = ",".join("?" for _ in ids)
                cur = conn.execute(
                    f"""UPDATE verdicts SET acknowledged=0, reviewed_at=NULL,
                        review_reason=NULL WHERE id IN ({qs})""",
                    list(ids),
                )
            elif fingerprint:
                cur = conn.execute(
                    """UPDATE verdicts SET acknowledged=0, reviewed_at=NULL,
                       review_reason=NULL WHERE fingerprint=?""",
                    (fingerprint,),
                )
            else:
                return 0
            return cur.rowcount

    def get(self, finding_id: int) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM verdicts WHERE id=?", (finding_id,)
            ).fetchone()
        return self._decode(row) if row else None

    def occurrences(
        self,
        fingerprint: str,
        limit: int = 100,
        *,
        include_reviewed: bool = True,
    ) -> list[dict[str, Any]]:
        reviewed_clause = (
            "" if include_reviewed else (" AND acknowledged=0 AND suppressed=0")
        )
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"""SELECT * FROM verdicts
                    WHERE fingerprint=?{reviewed_clause}
                    ORDER BY ts DESC LIMIT ?""",
                (fingerprint, limit),
            ).fetchall()
        return [self._decode(row) for row in rows]

    def occurrence_count(self, fingerprint: str) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM verdicts WHERE fingerprint=?",
                (fingerprint,),
            ).fetchone()
        return int(row[0]) if row else 0

    def clear(self, project_root: str | None = None) -> None:
        with self._lock, self._connect() as conn:
            if project_root:
                conn.execute(
                    "DELETE FROM verdicts WHERE project_root = ?", (project_root,)
                )
            else:
                conn.execute("DELETE FROM verdicts")


def project_label(project_root: str) -> str:
    return os.path.basename(project_root.rstrip("/")) or project_root or "(unknown)"
