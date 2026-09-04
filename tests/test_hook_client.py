from __future__ import annotations

import io
from types import SimpleNamespace

from rules_as_programs.adapters.codex import hook_client


def test_event_delivery_retries_idempotently_before_spawning(monkeypatch):
    event = SimpleNamespace(to_dict=lambda: {"id": "event-1"})
    responses = iter((None, {"ok": True, "accepted": False}))
    calls = []
    sleeps = []
    spawned = []

    def send(request, timeout):
        calls.append((request, timeout))
        return next(responses)

    monkeypatch.setattr(hook_client, "normalize", lambda _raw: [event])
    monkeypatch.setattr(hook_client.ipc, "send_request", send)
    monkeypatch.setattr(hook_client.time, "sleep", sleeps.append)
    monkeypatch.setattr(hook_client, "_spawn_daemon", lambda: spawned.append(True))
    monkeypatch.setattr(hook_client.sys, "stdin", io.StringIO("{}"))
    stdout = io.StringIO()
    monkeypatch.setattr(hook_client.sys, "stdout", stdout)

    assert hook_client.main() == 0
    assert stdout.getvalue() == "{}"
    assert len(calls) == 2
    assert sleeps == [hook_client.EVENT_DELIVERY_RETRY_DELAY_SECONDS]
    assert calls[0][0] == calls[1][0]
    assert all(
        timeout == hook_client.EVENT_DELIVERY_TIMEOUT_SECONDS
        for _request, timeout in calls
    )
    assert spawned == []


def test_event_delivery_retries_error_responses_and_then_spawns(monkeypatch):
    event = SimpleNamespace(to_dict=lambda: {"id": "event-1"})
    calls = []
    sleeps = []
    spawned = []

    def send(request, timeout):
        calls.append((request, timeout))
        return {"ok": False, "error": "listener overloaded"}

    monkeypatch.setattr(hook_client, "normalize", lambda _raw: [event])
    monkeypatch.setattr(hook_client.ipc, "send_request", send)
    monkeypatch.setattr(hook_client.time, "sleep", sleeps.append)
    monkeypatch.setattr(hook_client, "_spawn_daemon", lambda: spawned.append(True))
    monkeypatch.setattr(hook_client.sys, "stdin", io.StringIO("{}"))
    stdout = io.StringIO()
    monkeypatch.setattr(hook_client.sys, "stdout", stdout)

    assert hook_client.main() == 0
    assert stdout.getvalue() == "{}"
    assert len(calls) == hook_client.EVENT_DELIVERY_ATTEMPTS
    assert sleeps == [
        hook_client.EVENT_DELIVERY_RETRY_DELAY_SECONDS * attempt
        for attempt in range(1, hook_client.EVENT_DELIVERY_ATTEMPTS)
    ]
    assert spawned == [True]
