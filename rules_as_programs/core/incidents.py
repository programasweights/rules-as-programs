"""Typed, thresholded operational incidents for local rule execution."""

from __future__ import annotations

import threading
import time
from typing import Any


class IncidentStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: dict[tuple[str, str, str], dict[str, Any]] = {}

    def record(
        self,
        code: str,
        *,
        project_root: str = "",
        rule_id: str = "",
        rule_name: str = "",
        summary: str,
        detail: str = "",
        impact: str = "rule skipped",
        threshold: int = 2,
    ) -> dict[str, Any]:
        key = (code, project_root, rule_id)
        now = time.time()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                item = {
                    "code": code,
                    "project_root": project_root,
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "summary": summary,
                    "detail": detail,
                    "impact": impact,
                    "first_seen": now,
                    "count": 0,
                    "threshold": max(1, int(threshold)),
                }
                self._items[key] = item
            item.update({
                "rule_name": rule_name or item.get("rule_name", ""),
                "summary": summary,
                "detail": detail,
                "impact": impact,
                "last_seen": now,
            })
            item["count"] = int(item.get("count", 0)) + 1
            return dict(item)

    def clear(
        self,
        *,
        code: str | None = None,
        project_root: str | None = None,
        rule_id: str | None = None,
    ) -> int:
        with self._lock:
            keys = [
                key for key, item in self._items.items()
                if (code is None or item.get("code") == code)
                and (
                    project_root is None
                    or item.get("project_root") == project_root
                )
                and (rule_id is None or item.get("rule_id") == rule_id)
            ]
            for key in keys:
                self._items.pop(key, None)
            return len(keys)

    def active(self) -> list[dict[str, Any]]:
        with self._lock:
            visible = [
                dict(item) for item in self._items.values()
                if int(item.get("count", 0)) >= int(item.get("threshold", 1))
            ]
        grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
        for item in visible:
            group_key = (
                str(item.get("code", "")),
                str(item.get("rule_id", "")),
                str(item.get("detail", "")),
            )
            group = grouped.get(group_key)
            if group is None:
                group = dict(item)
                group["affected_projects"] = []
                grouped[group_key] = group
            root = str(item.get("project_root", ""))
            if root and root not in group["affected_projects"]:
                group["affected_projects"].append(root)
            group["count"] = max(
                int(group.get("count", 0)), int(item.get("count", 0)))
            group["last_seen"] = max(
                float(group.get("last_seen", 0)),
                float(item.get("last_seen", 0)),
            )
        out = []
        for group in grouped.values():
            affected = len(group.get("affected_projects", []))
            if affected > 1:
                group["summary"] = (
                    f"{group.get('rule_name') or 'Rule check'} failing in "
                    f"{affected} projects"
                )
            out.append(group)
        return sorted(
            out, key=lambda item: float(item.get("last_seen", 0)),
            reverse=True)
