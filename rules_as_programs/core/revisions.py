"""Working-source and last-good active revision management."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .. import config

_lock = threading.Lock()
_VERSION = 1
AUTOMATIC_COMPILER_MODE = "automatic"
EXPLICIT_COMPILER_MODE = "explicit"
COMPILER_MODES = {AUTOMATIC_COMPILER_MODE, EXPLICIT_COMPILER_MODE}


def hash_source(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def behavior_hash(source: str) -> str:
    """Hash executable rule behavior while excluding mutable display identity."""
    try:
        tree = ast.parse(source, filename="<rule>")
    except SyntaxError:
        return hash_source(source)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        rule_decorators = [
            decorator for decorator in node.decorator_list
            if (
                isinstance(decorator, ast.Call)
                and (
                    isinstance(decorator.func, ast.Name)
                    and decorator.func.id == "rule"
                    or isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "rule"
                )
            )
        ]
        if not rule_decorators:
            continue
        node.name = "__rule__"
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            node.body[0].value.value = "__doc__"
        for decorator in rule_decorators:
            for keyword in decorator.keywords:
                if keyword.arg in ("name", "title"):
                    keyword.value = ast.Constant(value="__name__")
    canonical = ast.dump(
        tree, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load() -> dict[str, Any]:
    path = config.active_revisions_path()
    if path.exists():
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("version") == _VERSION:
                return value
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
    return {"version": _VERSION, "sources": {}}


def _save(state: dict[str, Any]) -> None:
    path = config.active_revisions_path()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def source_key(source_path: str | os.PathLike[str]) -> str:
    return str(Path(source_path).expanduser().resolve())


def active_info(
    rule_id: str, source_path: str | os.PathLike[str]
) -> dict[str, Any] | None:
    key = source_key(source_path)
    with _lock:
        info = _load()["sources"].get(key)
    if not info or info.get("id") != rule_id:
        return None
    cache_path = Path(info.get("cache_path", ""))
    if not cache_path.exists():
        return None
    normalized = dict(info)
    normalized["compiler_mode"] = _compiler_mode(
        normalized.get("compiler_mode"))
    normalized["artifacts"] = _normalized_artifacts(
        normalized.get("artifacts"),
        str(normalized.get("behavior_hash", "")),
    )
    current = _artifact(
        str(normalized.get("compiler", "")),
        str(normalized.get("program_id", "")),
        str(normalized.get("compiler_snapshot", "")),
        behavior_hash=str(normalized.get("behavior_hash", "")),
        created_at=float(normalized.get("activated_at", 0) or 0),
    )
    if current:
        normalized["artifacts"].setdefault(current["key"], current)
    return normalized


def _compiler_mode(value: Any) -> str:
    mode = str(value or AUTOMATIC_COMPILER_MODE)
    return mode if mode in COMPILER_MODES else AUTOMATIC_COMPILER_MODE


def artifact_key(compiler: str, compiler_snapshot: str = "") -> str:
    return f"{compiler or 'default'}@{compiler_snapshot or 'unknown'}"


def _artifact(
    compiler: str,
    program_id: str,
    compiler_snapshot: str,
    *,
    behavior_hash: str = "",
    created_at: float | None = None,
) -> dict[str, Any] | None:
    if not program_id:
        return None
    return {
        "key": artifact_key(compiler, compiler_snapshot),
        "compiler": compiler,
        "compiler_snapshot": compiler_snapshot,
        "program_id": program_id,
        "behavior_hash": behavior_hash,
        "created_at": float(created_at or time.time()),
    }


def _normalized_artifacts(
    value: Any, behavior_hash: str = ""
) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    normalized = {}
    for key, item in value.items():
        if not isinstance(item, dict) or not item.get("program_id"):
            continue
        artifact = dict(item)
        artifact.setdefault("behavior_hash", behavior_hash)
        normalized[str(key)] = artifact
    return normalized


def activate(
    rule_id: str,
    source_path: str | os.PathLike[str],
    source: str,
    *,
    compiler: str | None = None,
    program_id: str | None = None,
    warnings: list[str] | None = None,
    compiler_snapshot: str | None = None,
    compiler_mode: str | None = None,
) -> dict[str, Any]:
    digest = hash_source(source)
    cache_dir = config.revision_dir() / rule_id
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{digest}.py"
    if not cache_path.exists():
        temporary = cache_dir / f".{digest}.tmp"
        temporary.write_text(
            source if source.endswith("\n") else source + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, cache_path)
    key = source_key(source_path)
    with _lock:
        state = _load()
        previous = state["sources"].get(key) or {}
        source_behavior_hash = behavior_hash(source)
        preserve_artifacts = bool(
            previous.get("id") == rule_id
            and str(previous.get("behavior_hash", "")) == source_behavior_hash
        )
        artifacts = (
            _normalized_artifacts(
                previous.get("artifacts"), source_behavior_hash)
            if preserve_artifacts else {}
        )
        current_artifact = _artifact(
            compiler or "",
            program_id or "",
            compiler_snapshot or "",
            behavior_hash=source_behavior_hash,
        )
        if current_artifact:
            artifacts[current_artifact["key"]] = current_artifact
        info = {
            "id": rule_id,
            "source_path": key,
            "source_hash": digest,
            "behavior_hash": source_behavior_hash,
            "cache_path": str(cache_path),
            "activated_at": time.time(),
            "compiler": compiler or "",
            "program_id": program_id or "",
            "warnings": list(warnings or []),
            "compiler_snapshot": compiler_snapshot or "",
            "compiler_mode": _compiler_mode(
                compiler_mode
                if compiler_mode is not None
                else previous.get("compiler_mode")),
            "artifacts": artifacts,
        }
        state["sources"][key] = info
        _save(state)
    return dict(info)


def activate_artifact(
    rule_id: str,
    source_path: str | os.PathLike[str],
    expected_behavior_hash: str,
    *,
    compiler: str,
    program_id: str,
    compiler_snapshot: str = "",
    compiler_mode: str | None = None,
    expected_compiler_mode: str | None = None,
) -> dict[str, Any] | None:
    """Atomically switch the active compiled artifact for one deployed behavior."""
    key = source_key(source_path)
    with _lock:
        state = _load()
        current = state["sources"].get(key)
        if (
            not current
            or current.get("id") != rule_id
            or str(current.get("behavior_hash", "")) != expected_behavior_hash
        ):
            return None
        current_mode = _compiler_mode(current.get("compiler_mode"))
        if (
            expected_compiler_mode is not None
            and current_mode != _compiler_mode(expected_compiler_mode)
        ):
            return None
        artifact = _artifact(compiler, program_id, compiler_snapshot)
        if artifact is None:
            return None
        behavior = str(current.get("behavior_hash", ""))
        artifact["behavior_hash"] = behavior
        artifacts = _normalized_artifacts(
            current.get("artifacts"), behavior)
        artifacts[artifact["key"]] = artifact
        updated = {
            **current,
            "compiler": compiler,
            "program_id": program_id,
            "compiler_snapshot": compiler_snapshot,
            "compiler_mode": _compiler_mode(
                compiler_mode
                if compiler_mode is not None else current_mode),
            "compiler_activated_at": time.time(),
            "artifacts": artifacts,
        }
        state["sources"][key] = updated
        _save(state)
        return dict(updated)


def restore_active(
    rule_id: str,
    source_path: str | os.PathLike[str],
    previous: dict[str, Any] | None,
) -> None:
    """Restore an exact active pointer after a failed deployment commit."""
    key = source_key(source_path)
    with _lock:
        state = _load()
        if previous and previous.get("id") == rule_id:
            restored = dict(previous)
            restored["source_path"] = key
            state["sources"][key] = restored
        else:
            state["sources"].pop(key, None)
        _save(state)


def working_status(
    rule_id: str, source_path: str | os.PathLike[str], source: str
) -> dict[str, Any]:
    working_hash = hash_source(source)
    working_behavior_hash = behavior_hash(source)
    active = active_info(rule_id, source_path)
    active_behavior_hash = str((active or {}).get("behavior_hash", ""))
    if active and not active_behavior_hash:
        try:
            active_behavior_hash = behavior_hash(
                Path(str(active.get("cache_path", ""))).read_text(
                    encoding="utf-8"))
        except OSError:
            active_behavior_hash = str(active.get("source_hash", ""))
        active["behavior_hash"] = active_behavior_hash
    return {
        "working_hash": working_hash,
        "working_behavior_hash": working_behavior_hash,
        "active_hash": (active or {}).get("source_hash", ""),
        "active_behavior_hash": active_behavior_hash,
        "active": active,
        "has_active": bool(active),
        "draft_changes": bool(
            active and active_behavior_hash != working_behavior_hash),
    }


def migrate_source_path(
    rule_id: str,
    old_path: str | os.PathLike[str],
    new_path: str | os.PathLike[str],
) -> None:
    old_key, new_key = source_key(old_path), source_key(new_path)
    with _lock:
        state = _load()
        info = state["sources"].pop(old_key, None)
        if info and info.get("id") == rule_id:
            info["source_path"] = new_key
            state["sources"][new_key] = info
            _save(state)


def remove_source(source_path: str | os.PathLike[str]) -> None:
    key = source_key(source_path)
    with _lock:
        state = _load()
        if state["sources"].pop(key, None) is not None:
            _save(state)
