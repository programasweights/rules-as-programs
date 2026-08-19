"""Append-only, all-outcome rule evaluation journal."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from .. import config

MAX_LOG_BYTES = 10 * 1024 * 1024
MAX_BACKUPS = 5
_lock = threading.Lock()


def _rotate(path: Path) -> None:
    if not path.exists() or path.stat().st_size < MAX_LOG_BYTES:
        return
    oldest = path.with_name(f"{path.name}.{MAX_BACKUPS}")
    oldest.unlink(missing_ok=True)
    for index in range(MAX_BACKUPS - 1, 0, -1):
        source = path.with_name(f"{path.name}.{index}")
        if source.exists():
            os.replace(
                source, path.with_name(f"{path.name}.{index + 1}"))
    os.replace(path, path.with_name(f"{path.name}.1"))


def append(project_root: str, record: dict[str, Any]) -> None:
    if not project_root:
        return
    try:
        log_dir = config.project_log_dir(project_root)
        log_dir.mkdir(parents=True, exist_ok=True)
        gitignore = log_dir / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text("*\n", encoding="utf-8")
        path = config.project_evaluation_log_file(project_root)
        line = json.dumps(record, ensure_ascii=False)
        with _lock:
            _rotate(path)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except OSError:
        pass


def started(project_root: str, record: dict[str, Any]) -> None:
    append(project_root, {"type": "evaluation_started", **record})


def completed(project_root: str, record: dict[str, Any]) -> None:
    append(project_root, {"type": "evaluation_completed", **record})


def failed(project_root: str, record: dict[str, Any]) -> None:
    append(project_root, {"type": "evaluation_failed", **record})


def _paths(project_root: str) -> list[Path]:
    base = config.project_evaluation_log_file(project_root)
    paths = [
        base.with_name(f"{base.name}.{index}")
        for index in range(MAX_BACKUPS, 0, -1)
        if base.with_name(f"{base.name}.{index}").exists()
    ]
    if base.exists():
        paths.append(base)
    return paths


def _records(project_root: str) -> list[dict[str, Any]]:
    records = []
    for path in _paths(project_root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for raw in lines:
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(value, dict):
                records.append(value)
    return records


def history(
    project_root: str,
    *,
    rule_id: str = "",
    limit: int = 500,
) -> list[dict[str, Any]]:
    outcomes: dict[str, dict[str, Any]] = {}
    rows = []
    for record in reversed(_records(project_root)):
        evaluation_id = str(record.get("evaluation_id", ""))
        if not evaluation_id:
            continue
        if record.get("type") in (
            "evaluation_completed", "evaluation_failed"
        ):
            outcomes.setdefault(evaluation_id, record)
            continue
        if record.get("type") != "evaluation_started":
            continue
        if rule_id and str((record.get("rule") or {}).get("id")) != rule_id:
            continue
        outcome = outcomes.get(evaluation_id)
        status = (
            "failed"
            if outcome and outcome.get("type") == "evaluation_failed"
            else "completed" if outcome else "running"
        )
        rows.append({
            **record,
            "status": status,
            "outcome": outcome or {},
            "result": str((outcome or {}).get("result", "")),
            "duration_ms": (outcome or {}).get("duration_ms"),
            "finding_id": (outcome or {}).get("finding_id"),
        })
        if len(rows) >= max(1, min(5000, int(limit))):
            break
    return rows


def get(
    project_root: str, evaluation_id: str
) -> dict[str, Any] | None:
    return next(
        (
            row for row in history(project_root, limit=5000)
            if row.get("evaluation_id") == evaluation_id
        ),
        None,
    )
