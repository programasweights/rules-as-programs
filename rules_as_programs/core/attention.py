"""Persisted, auto-clearing project attention that is not a rule violation."""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any

from .. import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attention (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_root TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    generation_id TEXT,
    message TEXT NOT NULL,
    confidence TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at REAL NOT NULL,
    cleared_at REAL,
    clear_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_attention_active
ON attention(cleared_at, created_at);
"""


class AttentionStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = str(path or config.db_path())
        self._lock = threading.Lock()
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        return connection

    def set(
        self,
        *,
        project_root: str,
        conversation_id: str,
        generation_id: str,
        message: str,
        confidence: str,
        source: str,
    ) -> int:
        now = time.time()
        with self._lock, self._connect() as connection:
            connection.execute(
                """UPDATE attention SET cleared_at=?, clear_reason='superseded'
                   WHERE conversation_id=? AND cleared_at IS NULL""",
                (now, conversation_id),
            )
            cursor = connection.execute(
                """INSERT INTO attention
                   (project_root, conversation_id, generation_id, message,
                    confidence, source, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    project_root,
                    conversation_id,
                    generation_id,
                    message[:4000],
                    confidence,
                    source,
                    now,
                ),
            )
            return int(cursor.lastrowid)

    def clear(
        self,
        *,
        attention_id: int | None = None,
        conversation_id: str | None = None,
        project_root: str | None = None,
        reason: str = "answered",
    ) -> int:
        clauses = ["cleared_at IS NULL"]
        params: list[Any] = [time.time(), reason]
        if attention_id is not None:
            clauses.append("id=?")
            params.append(attention_id)
        elif conversation_id:
            clauses.append("conversation_id=?")
            params.append(conversation_id)
        elif project_root:
            clauses.append("project_root=?")
            params.append(project_root)
        else:
            return 0
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                f"""UPDATE attention SET cleared_at=?, clear_reason=?
                    WHERE {' AND '.join(clauses)}""",
                params,
            )
            return cursor.rowcount

    def active(self, ttl_seconds: float = 24 * 3600) -> list[dict[str, Any]]:
        cutoff = time.time() - ttl_seconds
        with self._lock, self._connect() as connection:
            connection.execute(
                """UPDATE attention SET cleared_at=?, clear_reason='expired'
                   WHERE cleared_at IS NULL AND created_at < ?""",
                (time.time(), cutoff),
            )
            rows = connection.execute(
                """SELECT * FROM attention WHERE cleared_at IS NULL
                   ORDER BY created_at DESC"""
            ).fetchall()
        return [dict(row) for row in rows]
