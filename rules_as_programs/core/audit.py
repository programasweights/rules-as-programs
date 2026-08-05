"""Per-project, violations-only audit log.

Each violation is one JSON line in ``<project>/.cursor/rules-as-programs/log/
audit.jsonl`` recording its stable finding ID, timestamp, rule, severity,
suppression state, exact mapped trigger input, raw trigger payload, and PAW
decision trace. A ``.gitignore`` (``*``) is dropped in the log folder so
audit logs are never committed.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from .. import config

_lock = threading.Lock()
MAX_FIELD = 4000  # cap any single captured string so files stay sane
MAX_RULE_SOURCE = 30000


def _cap(text: str) -> str:
    text = text if isinstance(text, str) else str(text)
    return text if len(text) <= MAX_FIELD else text[:MAX_FIELD] + " ...[truncated]"


def _cap_value(value: Any) -> Any:
    if isinstance(value, str):
        return _cap(value)
    if isinstance(value, list):
        return [_cap_value(item) for item in value[:100]]
    if isinstance(value, dict):
        return {str(k): _cap_value(v) for k, v in value.items()}
    return value


def _cap_trace(trace: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_cap_value(item) for item in (trace or [])[:100]]


def _cap_evaluation(evaluation: dict[str, Any] | None) -> dict[str, Any]:
    return dict(evaluation or {})


def read_recent(project_root: str, rule_id: str | None = None,
                limit: int = 1) -> list[dict[str, Any]]:
    """Return the most recent audit entries for a project (newest first).

    Optionally filter by ``rule_id``. Used by the tray to show the full trace of
    a specific finding.
    """
    if not project_root:
        return []
    path = config.project_log_file(project_root)
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for raw in reversed(lines):
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if rule_id and entry.get("rule_id") != rule_id:
            continue
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def read_finding(
    project_root: str,
    finding_id: int,
) -> dict[str, Any] | None:
    """Read the exact audit entry associated with a verdict."""
    path = config.project_log_file(project_root)
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for raw in reversed(lines):
        try:
            entry = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if entry.get("finding_id") == finding_id:
            return entry
    return None


def log_violation(
    project_root: str,
    finding_id: int,
    rule_id: str,
    title: str,
    severity: str,
    message: str,
    trace: list[dict[str, Any]],
    *,
    conversation_id: str = "",
    trigger_event_id: str = "",
    trigger_kind: str = "",
    fingerprint: str = "",
    suppressed: bool = False,
    suppression_reason: str = "",
    ts: float | None = None,
    rule_scope: str = "",
    rule_path: str = "",
    rule_source_hash: str = "",
    rule_source: str = "",
    evaluation: dict[str, Any] | None = None,
) -> None:
    if not project_root:
        return
    recorded_at = ts if ts is not None else time.time()
    entry = {
        "type": "finding",
        "finding_id": finding_id,
        "ts": recorded_at,
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(recorded_at)),
        "rule_id": rule_id,
        "id": rule_id,
        "name": title,
        "title": title,
        "severity": severity,
        "message": _cap(message),
        "conversation_id": conversation_id,
        "trigger_event_id": trigger_event_id,
        "trigger_kind": trigger_kind,
        "fingerprint": fingerprint,
        "suppressed": bool(suppressed),
        "suppression_reason": suppression_reason,
        "rule_scope": rule_scope,
        "rule_path": rule_path,
        "rule_source_hash": rule_source_hash,
        "source_hash": rule_source_hash,
        "rule_source": (
            rule_source if len(rule_source) <= MAX_RULE_SOURCE
            else rule_source[:MAX_RULE_SOURCE] + " ...[truncated]"
        ),
        "trace": _cap_trace(trace),
        "evaluation": _cap_evaluation(evaluation),
    }
    try:
        log_dir = config.project_log_dir(project_root)
        log_dir.mkdir(parents=True, exist_ok=True)
        gitignore = log_dir / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text("*\n", encoding="utf-8")
        line = json.dumps(entry, ensure_ascii=False)
        with _lock:
            with config.project_log_file(project_root).open("a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError:
        pass
