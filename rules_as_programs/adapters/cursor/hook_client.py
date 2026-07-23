"""Thin Cursor hook client (the ``rap-hook`` entry point).

Cursor spawns this once per hook event with the event JSON on stdin. It must be
near-instant and fail-open so the agent is never stalled:

1. read + parse stdin (best-effort),
2. normalize to events and hand them to the daemon over the socket,
3. if the daemon is down, fire-and-forget spawn it (never wait),
4. always print an empty JSON object and exit 0 (observation-only: no
   permission/continue/followup fields -> Cursor just proceeds).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from ... import config, ipc
from .adapter import normalize


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
    # Whatever happens, emit valid JSON and never block the agent.
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
        resp = ipc.send_request({"type": "event", "event": event.to_dict()}, timeout=0.6)
        if resp is None:
            daemon_down = True
            break

    if daemon_down:
        # Start it for next time; do not wait on it now.
        _spawn_daemon()

    sys.stdout.write("{}")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
