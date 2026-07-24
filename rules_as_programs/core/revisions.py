"""Working-source and last-good active revision management."""

from __future__ import annotations

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


def hash_source(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


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
    return dict(info) if cache_path.exists() else None


def activate(
    rule_id: str,
    source_path: str | os.PathLike[str],
    source: str,
    *,
    compiler: str | None = None,
    program_id: str | None = None,
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
    info = {
        "id": rule_id,
        "source_path": key,
        "source_hash": digest,
        "cache_path": str(cache_path),
        "activated_at": time.time(),
        "compiler": compiler or "",
        "program_id": program_id or "",
    }
    with _lock:
        state = _load()
        state["sources"][key] = info
        _save(state)
    return dict(info)


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
    active = active_info(rule_id, source_path)
    return {
        "working_hash": working_hash,
        "active_hash": (active or {}).get("source_hash", ""),
        "active": active,
        "has_active": bool(active),
        "draft_changes": bool(active and active.get("source_hash") != working_hash),
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
