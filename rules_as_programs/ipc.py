"""Tiny newline-delimited-JSON protocol over a Unix domain socket.

Used by the thin hook client, the tray UI, and ``rap status`` to talk to the
long-lived daemon. Kept deliberately minimal and fail-open: if the daemon is
down or slow, callers get ``None`` fast and never stall the agent.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from typing import Any

from . import config

PROTOCOL_VERSION = 21


def send_request(obj: dict[str, Any], timeout: float = 2.0) -> dict[str, Any] | None:
    """Send one request, read one JSON response. Returns ``None`` on failure."""
    path = str(config.socket_path())
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(path)
            sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        raw = b"".join(chunks).decode("utf-8").strip()
        if not raw:
            return {}
        return json.loads(raw.splitlines()[0])
    except (OSError, socket.timeout, json.JSONDecodeError):
        return None


def ping_details(timeout: float = 0.5) -> dict[str, Any] | None:
    """Return daemon identity/health without reducing it to a boolean."""
    resp = send_request({"type": "ping"}, timeout=timeout)
    return resp if resp and resp.get("ok") else None


def ping(timeout: float = 0.5, required_protocol: int | None = None) -> bool:
    resp = ping_details(timeout)
    if not resp:
        return False
    if required_protocol is not None:
        return resp.get("protocol") == required_protocol
    return True


def _spawn_daemon() -> bool:
    try:
        log_path = config.daemon_stderr_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.touch(exist_ok=True)
        os.chmod(log_path, 0o600)
        with log_path.open("ab", buffering=0) as diagnostics:
            subprocess.Popen(
                [sys.executable, "-m", "rules_as_programs.daemon"],
                stdout=diagnostics,
                stderr=diagnostics,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env={**os.environ, "PYTHONFAULTHANDLER": "1"},
            )
        return True
    except OSError:
        return False


def ensure_daemon(
    wait: float = 6.0,
    required_protocol: int | None = PROTOCOL_VERSION,
    restart_stale: bool = True,
) -> bool:
    """Ensure a compatible daemon is running.

    A tray process can outlive a package update.  Older implementations merely
    checked that *some* daemon answered, then sent requests that the stale
    process silently ignored.  We now negotiate a tiny protocol version and
    gracefully replace an incompatible daemon before the UI becomes usable.
    """
    details = ping_details()
    if details and (
        required_protocol is None or details.get("protocol") == required_protocol
    ):
        return True

    if details:
        if not restart_stale:
            return False
        send_request({"type": "shutdown"}, timeout=1.0)
        deadline = time.time() + min(wait, 3.0)
        while time.time() < deadline and ping_details(timeout=0.2):
            time.sleep(0.1)
        if ping_details(timeout=0.2):
            return False

    if not _spawn_daemon():
        return False
    deadline = time.time() + wait
    while time.time() < deadline:
        if ping(timeout=0.3, required_protocol=required_protocol):
            return True
        time.sleep(0.15)
    return False
