"""Fast, observation-only client for Codex lifecycle command hooks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from ... import ipc
from .adapter import normalize

EVENT_DELIVERY_TIMEOUT_SECONDS = 0.75
EVENT_DELIVERY_ATTEMPTS = 4
EVENT_DELIVERY_RETRY_DELAY_SECONDS = 0.05


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
        for attempt in range(EVENT_DELIVERY_ATTEMPTS):
            response = ipc.send_request(request, timeout=EVENT_DELIVERY_TIMEOUT_SECONDS)
            # ``accepted=False`` is a successful idempotent duplicate.  An
            # empty or error response is not an acknowledgement and must not
            # silently discard the observed event.
            if response and response.get("ok") is True:
                break
            if attempt + 1 < EVENT_DELIVERY_ATTEMPTS:
                time.sleep(EVENT_DELIVERY_RETRY_DELAY_SECONDS * (attempt + 1))
        if not response or response.get("ok") is not True:
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
