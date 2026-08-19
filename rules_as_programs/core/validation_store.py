"""Persistent, per-case validation results for exact PAW programs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .. import config

EVALUATOR_VERSION = 1
MAX_RUNS = 20_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS validation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_root TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    spec_hash TEXT NOT NULL,
    compiler TEXT NOT NULL,
    compiler_snapshot TEXT NOT NULL,
    program_id TEXT NOT NULL,
    evaluator_version INTEGER NOT NULL,
    case_id TEXT NOT NULL,
    case_hash TEXT NOT NULL,
    input_text TEXT NOT NULL,
    expected TEXT NOT NULL,
    actual TEXT NOT NULL,
    valid_output INTEGER NOT NULL,
    passed INTEGER NOT NULL,
    ran_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_validation_match ON validation_runs(
    project_root, rule_id, spec_hash, compiler, compiler_snapshot,
    evaluator_version, case_hash, ran_at DESC
);
"""


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8", errors="replace")
    return hashlib.sha256(encoded).hexdigest()


def spec_fingerprint(spec: str) -> str:
    return _digest({"spec": str(spec).strip()})


def case_fingerprint(case: dict[str, Any]) -> str:
    return _digest({
        "input": str(case.get("input", "")),
        "expected": str(case.get("expected", "")).strip().upper(),
    })


class ValidationResultStore:
    def __init__(self, path: str | Path | None = None):
        self.path = str(path or config.validation_db_path())
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    def record(
        self,
        *,
        project_root: str,
        rule_id: str,
        spec: str,
        compiler: str,
        compiler_snapshot: str,
        program_id: str,
        results: list[dict[str, Any]],
        ran_at: float | None = None,
    ) -> list[dict[str, Any]]:
        timestamp = float(ran_at or time.time())
        spec_hash = spec_fingerprint(spec)
        enriched = []
        rows = []
        for result in results:
            case_hash = case_fingerprint(result)
            value = {
                **result,
                "spec_hash": spec_hash,
                "compiler": compiler,
                "compiler_snapshot": compiler_snapshot,
                "program_id": program_id,
                "evaluator_version": EVALUATOR_VERSION,
                "case_hash": case_hash,
                "ran_at": timestamp,
            }
            enriched.append(value)
            rows.append((
                project_root,
                rule_id,
                spec_hash,
                compiler,
                compiler_snapshot,
                program_id,
                EVALUATOR_VERSION,
                str(result.get("id", "")),
                case_hash,
                str(result.get("input", "")),
                str(result.get("expected", "")).strip().upper(),
                str(result.get("actual", "")),
                int(bool(result.get("valid_output"))),
                int(bool(result.get("ok"))),
                timestamp,
            ))
        if not rows:
            return enriched
        with self._lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO validation_runs (
                    project_root, rule_id, spec_hash, compiler,
                    compiler_snapshot, program_id, evaluator_version,
                    case_id, case_hash, input_text, expected, actual,
                    valid_output, passed, ran_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM validation_runs"
                ).fetchone()[0]
            )
            if count > MAX_RUNS:
                conn.execute(
                    """
                    DELETE FROM validation_runs
                    WHERE id NOT IN (
                        SELECT id FROM validation_runs
                        ORDER BY ran_at DESC, id DESC LIMIT ?
                    )
                    """,
                    (MAX_RUNS,),
                )
        return enriched

    def matching(
        self,
        *,
        project_root: str,
        rule_id: str,
        spec: str,
        compiler: str,
        compiler_snapshot: str,
        cases: list[dict[str, Any]],
        program_id: str = "",
    ) -> list[dict[str, Any]]:
        by_hash: dict[str, list[dict[str, Any]]] = {}
        for case in cases:
            by_hash.setdefault(case_fingerprint(case), []).append(case)
        if not by_hash:
            return []
        hashes = list(by_hash)
        placeholders = ",".join("?" for _ in hashes)
        params = [
            project_root,
            rule_id,
            spec_fingerprint(spec),
            compiler,
            compiler_snapshot,
            EVALUATOR_VERSION,
        ]
        program_clause = ""
        if program_id:
            program_clause = " AND program_id = ?"
            params.append(program_id)
        params.extend(hashes)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM validation_runs
                WHERE project_root = ?
                  AND rule_id = ?
                  AND spec_hash = ?
                  AND compiler = ?
                  AND compiler_snapshot = ?
                  AND evaluator_version = ?
                  {program_clause}
                  AND case_hash IN ({placeholders})
                ORDER BY ran_at DESC, id DESC
                """,
                params,
            ).fetchall()
        latest: dict[str, dict[str, Any]] = {}
        for row in rows:
            value = dict(row)
            latest.setdefault(str(value["case_hash"]), value)
        results = []
        for case in cases:
            case_hash = case_fingerprint(case)
            value = latest.get(case_hash)
            if not value:
                continue
            results.append({
                **case,
                "actual": str(value["actual"]),
                "valid_output": bool(value["valid_output"]),
                "ok": bool(value["passed"]),
                "spec_hash": str(value["spec_hash"]),
                "compiler": str(value["compiler"]),
                "compiler_snapshot": str(value["compiler_snapshot"]),
                "program_id": str(value["program_id"]),
                "evaluator_version": int(value["evaluator_version"]),
                "case_hash": case_hash,
                "ran_at": float(value["ran_at"]),
            })
        return results
