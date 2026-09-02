"""Fast, observation-only client for Codex lifecycle command hooks."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from ... import ipc
from .adapter import normalize

EVENT_DELIVERY_TIMEOUT_SECONDS = 1.5
EVENT_DELIVERY_ATTEMPTS = 2


def _spawn_daemon() -> None:
    try:
        subprocess.Popen(
            [sys.executable, "-m", "rules_as_programs.daemon"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env={**os.environ},
        )
    except OSError:
        pass


def main() -> int:
    try:
        raw_text = sys.stdin.read()
        raw = json.loads(raw_text) if raw_text.strip() else {}
    except (json.JSONDecodeError, ValueError, OSError):
        raw = {}

    try:
        events = normalize(raw) if isinstance(raw, dict) else []
    except Exception:
        events = []

    daemon_down = False
    for event in events:
        request = {"type": "event", "event": event.to_dict()}
        response = None
        for _attempt in range(EVENT_DELIVERY_ATTEMPTS):
            response = ipc.send_request(request, timeout=EVENT_DELIVERY_TIMEOUT_SECONDS)
            if response is not None:
                break
        if response is None:
            daemon_down = True
            break
    if daemon_down:
        _spawn_daemon()

    # All observed Codex events accept an empty JSON object on successful exit,
    # including Stop and SubagentStop, which require JSON rather than text.
    sys.stdout.write("{}")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
