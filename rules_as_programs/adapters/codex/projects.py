"""Discover saved local Codex projects without mutating Codex state."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ... import config


def _state_databases() -> list[Path]:
    home = config.codex_home()
    return sorted(
        home.glob("state_*.sqlite"),
        key=lambda path: path.stat().st_mtime if path.exists() else 0,
        reverse=True,
    )


def _projects_from_db(path: Path) -> list[dict[str, str | float]]:
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=0.1) as connection:
            rows = connection.execute(
                """
                SELECT project_roots.path, projects.name, projects.updated_at_ms
                FROM project_roots
                JOIN projects ON projects.id = project_roots.project_id
                ORDER BY projects.updated_at_ms DESC, project_roots.position ASC
                """
            ).fetchall()
    except (sqlite3.Error, OSError):
        return []
    found = []
    seen: set[str] = set()
    for raw_path, raw_name, updated_at_ms in rows:
        project = Path(str(raw_path)).expanduser()
        if not project.is_dir():
            continue
        resolved = str(project.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append({
            "path": resolved,
            "name": str(raw_name or project.name or resolved),
            "mtime": float(updated_at_ms or 0) / 1000,
        })
    return found


def discover_projects(limit: int = 20) -> list[dict[str, str | float]]:
    """Return recent saved Codex projects from the newest readable state DB."""
    if limit <= 0:
        return []
    for database in _state_databases():
        projects = _projects_from_db(database)
        if projects:
            return projects[:limit]
    return []
