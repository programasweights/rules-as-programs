"""Persistent deployment intents waiting on long-running compiler builds."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .. import config

PENDING_STATUSES = {
    "waiting_for_build", "building", "checking", "validating", "deploying",
}
DEPLOYMENT_KIND = "deployment"
OPTIMIZATION_KIND = "optimization"


def _kind(value: dict[str, Any]) -> str:
    return str(value.get("kind") or DEPLOYMENT_KIND)


class DeploymentQueueStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or config.deployment_queue_path())
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            return {}
        entries = value.get("entries") if isinstance(value, dict) else None
        return {
            str(key): dict(item)
            for key, item in (entries or {}).items()
            if isinstance(item, dict)
        }

    def _save(self, entries: dict[str, dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"entries": entries}, indent=2, default=str),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)

    def put(self, entry: dict[str, Any]) -> dict[str, Any]:
        value = dict(entry)
        value.setdefault("created_at", time.time())
        value["updated_at"] = time.time()
        with self._lock:
            entries = self._load()
            entries[str(value["id"])] = value
            self._save(entries)
        return dict(value)

    def update(self, queue_id: str, **changes: Any) -> dict[str, Any] | None:
        with self._lock:
            entries = self._load()
            value = entries.get(queue_id)
            if not value:
                return None
            value.update(changes)
            value["updated_at"] = time.time()
            entries[queue_id] = value
            self._save(entries)
            return dict(value)

    def get(self, queue_id: str) -> dict[str, Any] | None:
        with self._lock:
            value = self._load().get(queue_id)
        return dict(value) if value else None

    def active_for_rule(
        self, rule_id: str, *, kind: str = DEPLOYMENT_KIND
    ) -> dict[str, Any] | None:
        with self._lock:
            values = [
                value for value in self._load().values()
                if str(value.get("rule_id", "")) == rule_id
                and _kind(value) == kind
                and value.get("status") in PENDING_STATUSES
            ]
        if not values:
            return None
        return dict(max(
            values, key=lambda value: float(value.get("created_at", 0))))

    def latest_for_rule(
        self, rule_id: str, *, kind: str = DEPLOYMENT_KIND
    ) -> dict[str, Any] | None:
        with self._lock:
            values = [
                value for value in self._load().values()
                if str(value.get("rule_id", "")) == rule_id
                and _kind(value) == kind
            ]
        if not values:
            return None
        return dict(max(
            values, key=lambda value: float(value.get("created_at", 0))))

    def pending(self, *, kind: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            values = [
                dict(value) for value in self._load().values()
                if value.get("status") in PENDING_STATUSES
                and (kind is None or _kind(value) == kind)
            ]
        return values

    def cancel(
        self, queue_id: str, reason: str = "Cancelled by user."
    ) -> dict[str, Any] | None:
        return self.update(
            queue_id,
            status="cancelled",
            error=reason,
            finished_at=time.time(),
        )
