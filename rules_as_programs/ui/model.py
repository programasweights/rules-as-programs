"""Threaded, AppKit-agnostic state model for the tray UI.

The UI renders immutable snapshots and never performs socket, filesystem, rule
import, or log work on AppKit's main thread.  This module deliberately knows
nothing about Cocoa so its state transitions and action failures are easy to
test on every platform.
"""

from __future__ import annotations

import copy
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import ipc

SnapshotListener = Callable[["UISnapshot"], None]
ActionCallback = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class UISnapshot:
    """One complete render state returned by the daemon."""

    status: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    fetched_at: float = field(default_factory=time.time)

    @property
    def open_count(self) -> int:
        return int(self.data.get("open_count", 0) or 0)

    @property
    def projects(self) -> list[dict[str, Any]]:
        value = self.data.get("projects", [])
        return value if isinstance(value, list) else []

    @property
    def findings_by_project(self) -> dict[str, list[dict[str, Any]]]:
        value = self.data.get("findings_by_project", {})
        return value if isinstance(value, dict) else {}

    @property
    def daemon(self) -> dict[str, Any]:
        value = self.data.get("daemon", {})
        return value if isinstance(value, dict) else {}

    @property
    def attention(self) -> list[dict[str, Any]]:
        value = self.data.get("attention", [])
        return value if isinstance(value, list) else []

    @classmethod
    def loading(cls, previous: "UISnapshot | None" = None) -> "UISnapshot":
        return cls("loading", copy.deepcopy(previous.data) if previous else {})

    @classmethod
    def unavailable(cls, message: str, previous: "UISnapshot | None" = None) -> "UISnapshot":
        return cls("unavailable", copy.deepcopy(previous.data) if previous else {}, message)


class UIModel:
    """Own daemon polling and command execution away from the UI thread."""

    def __init__(
        self,
        listener: SnapshotListener | None = None,
        poll_seconds: float = 3.0,
        send: Callable[..., dict[str, Any] | None] = ipc.send_request,
        ensure: Callable[..., bool] = ipc.ensure_daemon,
    ) -> None:
        self.poll_seconds = poll_seconds
        self._send = send
        self._ensure = ensure
        self._listeners: list[SnapshotListener] = []
        if listener:
            self._listeners.append(listener)
        self._snapshot = UISnapshot.loading()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._refresh = threading.Event()
        self._thread: threading.Thread | None = None
        self._work = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rap-ui")

    @property
    def snapshot(self) -> UISnapshot:
        with self._lock:
            return self._snapshot

    def add_listener(self, listener: SnapshotListener) -> None:
        self._listeners.append(listener)

    def remove_listener(self, listener: SnapshotListener) -> None:
        try:
            self._listeners.remove(listener)
        except ValueError:
            pass

    def _publish(self, snapshot: UISnapshot) -> None:
        with self._lock:
            self._snapshot = snapshot
        for listener in list(self._listeners):
            try:
                listener(snapshot)
            except Exception:
                continue

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._publish(UISnapshot.loading(self.snapshot))
        self._thread = threading.Thread(
            target=self._poll_loop, name="rap-ui-poller", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._refresh.set()
        self._work.shutdown(wait=False, cancel_futures=True)

    def refresh(self) -> None:
        self._refresh.set()

    def _poll_loop(self) -> None:
        first = True
        while not self._stop.is_set():
            if not first:
                self._refresh.wait(self.poll_seconds)
                self._refresh.clear()
            first = False
            if self._stop.is_set():
                break
            previous = self.snapshot
            try:
                if not self._ensure(
                    wait=6.0, required_protocol=ipc.PROTOCOL_VERSION,
                    restart_stale=True,
                ):
                    self._publish(UISnapshot.unavailable(
                        "The Rules as Programs daemon could not be started.", previous))
                    continue
                response = self._send({"type": "snapshot"}, timeout=4.0)
                if not response or not response.get("ok"):
                    error = (response or {}).get("error", "The daemon did not return a snapshot.")
                    self._publish(UISnapshot.unavailable(str(error), previous))
                    continue
                self._publish(UISnapshot("ready", copy.deepcopy(response)))
            except Exception as exc:
                self._publish(UISnapshot.unavailable(str(exc), previous))

    def perform(
        self,
        request: dict[str, Any],
        callback: ActionCallback | None = None,
        timeout: float = 4.0,
    ) -> None:
        """Execute a command and refresh only after a confirmed success."""

        def work() -> None:
            try:
                response = self._send(request, timeout=timeout)
                if not response:
                    result = {"ok": False, "error": "The daemon did not respond."}
                else:
                    result = response
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}
            if result.get("ok"):
                self.refresh()
            if callback:
                try:
                    callback(result)
                except Exception:
                    pass

        self._work.submit(work)

    def query(
        self,
        request: dict[str, Any],
        callback: ActionCallback | None = None,
        timeout: float = 4.0,
    ) -> None:
        """Execute a read-only request without refreshing the tray snapshot."""

        def work() -> None:
            try:
                response = self._send(request, timeout=timeout)
                result = response or {
                    "ok": False, "error": "The daemon did not respond."}
            except Exception as exc:
                result = {"ok": False, "error": str(exc)}
            if callback:
                try:
                    callback(result)
                except Exception:
                    pass

        self._work.submit(work)

    # Convenience commands keep action semantics consistent across AppKit and
    # the simpler cross-platform tray.
    def done(self, ids: list[int], callback: ActionCallback | None = None) -> None:
        self.perform({"type": "review", "ids": ids}, callback)

    def done_project(self, project_root: str, callback: ActionCallback | None = None) -> None:
        self.perform({"type": "review", "project_root": project_root}, callback)

    def mute_rule(
        self, rule_id: str, project_root: str,
        callback: ActionCallback | None = None,
    ) -> None:
        self.perform({
            "type": "mute",
            "rule_id": rule_id,
            "project_root": project_root,
            "until": None,
        }, callback)

    def set_rule_enabled(
        self, rule_id: str, project_root: str, enabled: bool,
        name: str = "",
        callback: ActionCallback | None = None,
    ) -> None:
        self.perform({
            "type": "set_rule_enabled",
            "rule_id": rule_id,
            "project_root": project_root,
            "enabled": enabled,
            "name": name,
        }, callback)

    def set_project_monitoring(
        self, project_root: str, enabled: bool,
        callback: ActionCallback | None = None,
    ) -> None:
        self.perform({
            "type": "set_project_monitoring",
            "project_root": project_root,
            "enabled": enabled,
        }, callback)


def demo_snapshot() -> UISnapshot:
    """Deterministic fixture for manual AppKit review and smoke tests."""
    now = time.time()
    project = "/Users/developer/Projects/example"
    return UISnapshot("ready", {
        "ok": True,
        "protocol": ipc.PROTOCOL_VERSION,
        "open_count": 2,
        "attention_count": 1,
        "project_count": 1,
        "daemon": {
            "health": "ready",
            "paw_available": True,
            "last_successful_audit": now - 15,
        },
        "projects": [{
            "path": project,
            "name": "example",
            "monitoring": True,
            "hooks_installed": True,
            "status": "ready",
            "active": True,
            "last_event_ts": now - 8,
            "rule_count": 4,
            "enabled_rule_count": 4,
            "open_count": 2,
            "attention_count": 1,
            "warm": {},
        }],
        "attention": [{
            "id": 201,
            "project_root": project,
            "conversation_id": "conversation",
            "generation_id": "generation",
            "message": "Which deployment environment should I use?",
            "confidence": "inferred",
            "source": "agent-needs-reply",
            "created_at": now - 20,
        }],
        "findings_by_project": {
            project: [
                {
                    "id": 101,
                    "ids": [101],
                    "rule_id": "fdg0z9837mz4v0ka",
                    "rule_title": "Verify claims with evidence",
                    "severity": "critical",
                    "message": "The agent claimed a deployment succeeded without a successful check.",
                    "project_root": project,
                    "ts": now - 42,
                    "occurrences": 1,
                    "label": "UNVERIFIED_CLAIM",
                },
                {
                    "id": 102,
                    "ids": [102],
                    "rule_id": "pkgk71nkt3e7xzxn",
                    "rule_title": "Keep work synchronized",
                    "severity": "warn",
                    "message": "Meaningful changes remain uncommitted.",
                    "project_root": project,
                    "ts": now - 300,
                    "occurrences": 2,
                    "label": "UNSYNCED",
                },
            ],
        },
    })
