"""Discover the user's real Cursor projects.

Cursor records every opened workspace under
``~/Library/Application Support/Cursor/User/workspaceStorage/<hash>/workspace.json``
(each contains ``{"folder": "file:///abs/path"}``). We read those, keep folders
that still exist, dedupe, and sort by recency (workspace dir mtime). This lets
the tray list real projects even before any agent activity.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse


def _workspace_storage_dir() -> Path | None:
    home = Path.home()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support" / "Cursor"
    elif sys.platform.startswith("win"):
        import os
        base = Path(os.environ.get("APPDATA", home)) / "Cursor"
    else:
        base = home / ".config" / "Cursor"
    d = base / "User" / "workspaceStorage"
    return d if d.exists() else None


def _folder_from_uri(uri: str) -> str | None:
    if not uri:
        return None
    if uri.startswith("file://"):
        return unquote(urlparse(uri).path)
    return uri


def discover_projects(limit: int = 20) -> list[dict[str, str]]:
    """Return [{path, name, mtime}] for recent, still-existing Cursor projects."""
    ws = _workspace_storage_dir()
    if ws is None:
        return []
    found: dict[str, float] = {}
    for wj in ws.glob("*/workspace.json"):
        try:
            data = json.loads(wj.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        folder = _folder_from_uri(data.get("folder", ""))
        if not folder:
            continue
        p = Path(folder)
        if not p.is_dir():
            continue
        try:
            mtime = wj.parent.stat().st_mtime
        except OSError:
            mtime = 0.0
        found[str(p)] = max(found.get(str(p), 0.0), mtime)
    ordered = sorted(found.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"path": path, "name": Path(path).name or path, "mtime": mt}
            for path, mt in ordered]
