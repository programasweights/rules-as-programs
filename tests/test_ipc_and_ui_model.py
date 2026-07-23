from __future__ import annotations

import threading

from rules_as_programs import ipc
from rules_as_programs.ui.model import UIModel


def test_ensure_daemon_replaces_protocol_mismatch(monkeypatch):
    state = {"mode": "stale", "shutdowns": 0, "spawns": 0}

    def ping_details(timeout=0.5):
        if state["mode"] == "stale":
            return {"ok": True, "protocol": ipc.PROTOCOL_VERSION - 1}
        if state["mode"] == "current":
            return {"ok": True, "protocol": ipc.PROTOCOL_VERSION}
        return None

    def send(request, timeout=2):
        if request.get("type") == "shutdown":
            state["shutdowns"] += 1
            state["mode"] = "down"
        return {"ok": True}

    def spawn():
        state["spawns"] += 1
        state["mode"] = "current"
        return True

    monkeypatch.setattr(ipc, "ping_details", ping_details)
    monkeypatch.setattr(ipc, "send_request", send)
    monkeypatch.setattr(ipc, "_spawn_daemon", spawn)

    assert ipc.ensure_daemon(wait=0.2, required_protocol=ipc.PROTOCOL_VERSION)
    assert state["shutdowns"] == 1
    assert state["spawns"] == 1


def test_ui_model_publishes_snapshot_off_thread():
    received = threading.Event()
    snapshots = []

    def send(request, timeout=2):
        assert request["type"] == "snapshot"
        return {
            "ok": True,
            "open_count": 2,
            "projects": [],
            "findings_by_project": {},
            "daemon": {"health": "ready"},
        }

    model = UIModel(
        listener=lambda snapshot: (snapshots.append(snapshot), received.set()),
        poll_seconds=60,
        send=send,
        ensure=lambda **_kwargs: True,
    )
    model.start()
    assert received.wait(2)
    # The first publication is loading; wait for the fetched snapshot.
    for _ in range(20):
        if model.snapshot.status == "ready":
            break
        threading.Event().wait(0.02)
    assert model.snapshot.status == "ready"
    assert model.snapshot.open_count == 2
    model.stop()


def test_ui_model_surfaces_action_failure():
    completed = threading.Event()
    result_box = {}
    model = UIModel(
        send=lambda _request, timeout=2: None,
        ensure=lambda **_kwargs: True,
    )
    model.perform(
        {"type": "review", "ids": [1]},
        lambda result: (result_box.update(result), completed.set()),
    )
    assert completed.wait(2)
    assert result_box["ok"] is False
    assert "respond" in result_box["error"]
    model.stop()
