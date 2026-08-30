#!/usr/bin/env python3
"""Run synthetic, local operational probes for the EACL 2027 evaluation.

The measurements in this module deliberately stop at observable process and
daemon-ingress boundaries.  In particular, hook timing is *not* Codex turn
latency: normal RAP lifecycle hooks run asynchronously in Codex.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import math
import os
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rules_as_programs.adapters.codex import hook_client  # noqa: E402
from rules_as_programs.adapters.codex.adapter import normalize  # noqa: E402
from rules_as_programs.daemon import Daemon  # noqa: E402


class OperationalProbeError(RuntimeError):
    """Raised when a probe violates its expected operational contract."""


def _short_temporary_state(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """Create state below a short POSIX root for ``sockaddr_un`` portability."""
    parent = "/tmp" if os.name == "posix" and Path("/tmp").is_dir() else None
    return tempfile.TemporaryDirectory(prefix=prefix, dir=parent)


def _milliseconds(nanoseconds: int) -> float:
    return round(nanoseconds / 1_000_000.0, 6)


def _nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("cannot summarize an empty sample")
    ordered = sorted(values)
    rank = max(1, math.ceil((percentile / 100.0) * len(ordered)))
    return ordered[rank - 1]


def _summary(values: list[float]) -> dict[str, Any]:
    if not values:
        raise ValueError("cannot summarize an empty sample")
    return {
        "unit": "ms",
        "count": len(values),
        "minimum": round(min(values), 6),
        "mean": round(sum(values) / len(values), 6),
        "p50_nearest_rank": round(_nearest_rank(values, 50.0), 6),
        "p95_nearest_rank": round(_nearest_rank(values, 95.0), 6),
        "maximum": round(max(values), 6),
    }


def _git_state() -> dict[str, Any]:
    scope = ["rules_as_programs", "experiments/eacl2027", "pyproject.toml"]
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
        dirty = bool(
            subprocess.check_output(
                [
                    "git",
                    "status",
                    "--porcelain",
                    "--untracked-files=normal",
                    "--",
                    *scope,
                ],
                cwd=REPO_ROOT,
                text=True,
            ).strip()
        )
        return {"commit": commit, "dirty": dirty, "scope": scope}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "", "dirty": True, "scope": scope}


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def _synthetic_pre_tool(project: Path, tool_use_id: str) -> dict[str, Any]:
    return {
        "session_id": "synthetic-operational-session",
        "turn_id": "synthetic-operational-turn",
        "hook_event_name": "PreToolUse",
        "cwd": str(project),
        "tool_name": "Bash",
        "tool_use_id": tool_use_id,
        "tool_input": {"command": "python -m pytest -q"},
    }


def _synthetic_stop(project: Path) -> dict[str, Any]:
    return {
        "session_id": "synthetic-operational-session",
        "turn_id": "synthetic-operational-stop-turn",
        "hook_event_name": "Stop",
        "cwd": str(project),
        "last_assistant_message": "Synthetic task completed after a test run.",
        "stop_hook_active": False,
    }


class _ImmediateAckServer:
    """Minimal newline-delimited JSON daemon stand-in on an isolated socket."""

    def __init__(self, path: Path):
        self.path = path
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopped = threading.Event()
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._errors: list[str] = []

    def __enter__(self) -> _ImmediateAckServer:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.unlink(missing_ok=True)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.path))
        server.listen(16)
        server.settimeout(0.1)
        self._socket = server
        self._thread = threading.Thread(
            target=self._serve,
            name="eacl-operational-mock-daemon",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stopped.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                raise OperationalProbeError("mock daemon thread did not stop")
        self.path.unlink(missing_ok=True)

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stopped.is_set():
            try:
                connection, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stopped.is_set():
                    with self._lock:
                        self._errors.append(f"accept: {type(exc).__name__}: {exc}")
                return
            try:
                with connection:
                    connection.settimeout(2.0)
                    chunks: list[bytes] = []
                    while not any(b"\n" in chunk for chunk in chunks):
                        data = connection.recv(65536)
                        if not data:
                            break
                        chunks.append(data)
                    received_ns = time.perf_counter_ns()
                    raw = b"".join(chunks).split(b"\n", 1)[0]
                    request = json.loads(raw.decode("utf-8"))
                    connection.sendall(b'{"ok":true,"accepted":true}\n')
                    ack_sent_ns = time.perf_counter_ns()
                    with self._lock:
                        self._records.append(
                            {
                                "request": request,
                                "received_ns": received_ns,
                                "ack_sent_ns": ack_sent_ns,
                            }
                        )
            except (
                OSError,
                socket.timeout,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as exc:
                with self._lock:
                    self._errors.append(f"request: {type(exc).__name__}: {exc}")

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._records)

    def errors(self) -> list[str]:
        with self._lock:
            return list(self._errors)


def _subprocess_environment(state_dir: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["RAP_STATE_DIR"] = str(state_dir)
    current_path = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(REPO_ROOT) + (
        os.pathsep + current_path if current_path else ""
    )
    return environment


def _measure_hook_handoff_at_state_dir(
    work_dir: Path,
    *,
    state_dir: Path,
    repetitions: int,
    warmups: int,
    python_executable: str = sys.executable,
) -> dict[str, Any]:
    """Measure hook subprocess boundaries against an immediate socket mock."""
    if repetitions < 1 or warmups < 0:
        raise ValueError("repetitions must be positive and warmups non-negative")
    project = work_dir / "synthetic-project"
    project.mkdir(parents=True, exist_ok=True)
    environment = _subprocess_environment(state_dir)
    server = _ImmediateAckServer(state_dir / "daemon.sock")
    samples: list[dict[str, Any]] = []
    total = repetitions + warmups

    with server:
        for sequence in range(total):
            tool_use_id = f"synthetic-handoff-{sequence}"
            raw = _synthetic_pre_tool(project, tool_use_id)
            started_ns = time.perf_counter_ns()
            completed = subprocess.run(
                [
                    python_executable,
                    "-m",
                    "rules_as_programs.adapters.codex.hook_client",
                ],
                cwd=REPO_ROOT,
                env=environment,
                input=json.dumps(raw, sort_keys=True),
                text=True,
                capture_output=True,
                timeout=5.0,
                check=False,
            )
            finished_ns = time.perf_counter_ns()
            records = server.records()
            if completed.returncode != 0 or completed.stdout != "{}":
                raise OperationalProbeError(
                    "hook subprocess failed: "
                    f"returncode={completed.returncode}, "
                    f"stdout={completed.stdout!r}, stderr={completed.stderr!r}"
                )
            if len(records) != sequence + 1:
                raise OperationalProbeError(
                    f"mock received {len(records)} requests after invocation "
                    f"{sequence + 1}; expected {sequence + 1}"
                )
            record = records[-1]
            request = record["request"]
            event = request.get("event") if isinstance(request, dict) else None
            raw_payload = event.get("raw_payload") if isinstance(event, dict) else None
            if (
                request.get("type") != "event"
                or not isinstance(raw_payload, dict)
                or raw_payload.get("tool_use_id") != tool_use_id
            ):
                raise OperationalProbeError("mock received an unexpected hook request")
            if sequence >= warmups:
                samples.append(
                    {
                        "sequence": sequence - warmups,
                        "parent_launch_call_to_mock_request_received_ms": _milliseconds(
                            record["received_ns"] - started_ns
                        ),
                        "parent_launch_call_to_hook_exit_ms": _milliseconds(
                            finished_ns - started_ns
                        ),
                        "mock_request_received_to_ack_sent_ms": _milliseconds(
                            record["ack_sent_ns"] - record["received_ns"]
                        ),
                    }
                )

    errors = server.errors()
    if errors:
        raise OperationalProbeError(f"mock daemon errors: {errors}")
    receipt = [
        item["parent_launch_call_to_mock_request_received_ms"] for item in samples
    ]
    wall = [item["parent_launch_call_to_hook_exit_ms"] for item in samples]
    service = [item["mock_request_received_to_ack_sent_ms"] for item in samples]
    return {
        "fixture": "synthetic PreToolUse; one normalized event per invocation",
        "transport": "newline-delimited JSON over an isolated Unix socket",
        "mock_response": {"ok": True, "accepted": True},
        "warmup_invocations_excluded": warmups,
        "measured_invocations": repetitions,
        "validated_mock_requests": total,
        "metric_definitions": {
            "parent_launch_call_to_mock_request_received_ms": (
                "perf_counter timestamp immediately before subprocess.run to "
                "the mock timestamp after reading the complete newline-delimited request"
            ),
            "parent_launch_call_to_hook_exit_ms": (
                "perf_counter timestamp immediately before subprocess.run to "
                "the timestamp immediately after subprocess.run returned"
            ),
            "mock_request_received_to_ack_sent_ms": (
                "mock timestamp after complete request receipt to timestamp "
                "after sending its immediate JSON acknowledgement"
            ),
        },
        "metrics": {
            "parent_launch_call_to_mock_request_received_ms": _summary(receipt),
            "parent_launch_call_to_hook_exit_ms": _summary(wall),
            "mock_request_received_to_ack_sent_ms": _summary(service),
        },
        "samples": samples,
    }


def measure_hook_handoff(
    work_dir: Path,
    *,
    repetitions: int,
    warmups: int,
    python_executable: str = sys.executable,
) -> dict[str, Any]:
    """Measure hook handoff with a short, isolated ``RAP_STATE_DIR`` path."""
    # Darwin limits AF_UNIX paths to roughly 104 bytes. pytest and CI temp
    # roots can be much longer, so use a separately managed short state path.
    with _short_temporary_state("rap-op-handoff-") as temporary:
        return _measure_hook_handoff_at_state_dir(
            work_dir,
            state_dir=Path(temporary),
            repetitions=repetitions,
            warmups=warmups,
            python_executable=python_executable,
        )


def _measure_daemon_unavailable_at_state_dir(
    work_dir: Path,
    *,
    state_dir: Path,
    repetitions: int,
) -> dict[str, Any]:
    """Exercise the real absent-socket branch without launching a daemon."""
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    project = work_dir / "synthetic-project"
    project.mkdir(parents=True, exist_ok=True)
    durations: list[float] = []
    spawn_attempts = 0
    outputs: list[str] = []

    def record_spawn_attempt() -> None:
        nonlocal spawn_attempts
        spawn_attempts += 1

    with mock.patch.dict(os.environ, {"RAP_STATE_DIR": str(state_dir)}):
        for sequence in range(repetitions):
            socket_path = state_dir / "daemon.sock"
            if socket_path.exists():
                raise OperationalProbeError(
                    "unavailable probe unexpectedly has a socket"
                )
            stdin = io.StringIO(
                json.dumps(
                    _synthetic_pre_tool(project, f"synthetic-unavailable-{sequence}"),
                    sort_keys=True,
                )
            )
            stdout = io.StringIO()
            with (
                mock.patch.object(sys, "stdin", stdin),
                mock.patch.object(sys, "stdout", stdout),
                mock.patch.object(
                    hook_client, "_spawn_daemon", side_effect=record_spawn_attempt
                ),
            ):
                started_ns = time.perf_counter_ns()
                return_code = hook_client.main()
                finished_ns = time.perf_counter_ns()
            output = stdout.getvalue()
            if return_code != 0 or output != "{}":
                raise OperationalProbeError(
                    "hook client did not fail open: "
                    f"returncode={return_code}, stdout={output!r}"
                )
            durations.append(_milliseconds(finished_ns - started_ns))
            outputs.append(output)

    if spawn_attempts != repetitions:
        raise OperationalProbeError(
            f"expected {repetitions} daemon spawn attempts, saw {spawn_attempts}"
        )
    return {
        "fault": "daemon Unix socket absent",
        "probe_boundary": (
            "hook_client.main entry to return; interpreter startup and the "
            "intercepted daemon process launch are excluded"
        ),
        "daemon_spawn": "intercepted after the attempt was recorded",
        "repetitions": repetitions,
        "return_codes_all_zero": True,
        "outputs_all_empty_json_objects": all(value == "{}" for value in outputs),
        "daemon_spawn_attempts": spawn_attempts,
        "metric": {"hook_client_main_absent_socket_to_return_ms": _summary(durations)},
    }


def measure_daemon_unavailable(
    work_dir: Path,
    *,
    repetitions: int,
) -> dict[str, Any]:
    """Measure absent-socket behavior with a short, isolated state path."""
    with _short_temporary_state("rap-op-unavailable-") as temporary:
        return _measure_daemon_unavailable_at_state_dir(
            work_dir,
            state_dir=Path(temporary),
            repetitions=repetitions,
        )


def _admission_only_daemon() -> Daemon:
    daemon = Daemon.__new__(Daemon)
    daemon._ingress_seen = OrderedDict()
    daemon._ingress_dedup_lock = threading.Lock()
    daemon._ingress_duplicate_count = 0
    return daemon


def _require_outcomes(name: str, actual: list[bool], expected: list[bool]) -> None:
    if actual != expected:
        raise OperationalProbeError(
            f"{name} produced admission outcomes {actual}; expected {expected}"
        )


def measure_duplicate_admission(
    work_dir: Path,
    *,
    concurrency: int,
    concurrency_trials: int,
) -> dict[str, Any]:
    """Run deterministic ingress-admission scenarios with an injected clock."""
    if concurrency < 2 or concurrency_trials < 1:
        raise ValueError("concurrency must be >= 2 and trials must be positive")
    project = work_dir / "synthetic-project"
    project.mkdir(parents=True, exist_ok=True)
    ttl = float(Daemon.INGRESS_DEDUP_TTL_SECONDS)

    raw = _synthetic_pre_tool(project, "synthetic-duplicate")
    within_daemon = _admission_only_daemon()
    within_outcomes = [
        within_daemon._admit_ingress_event(normalize(dict(raw))[0], now=100.0),
        within_daemon._admit_ingress_event(
            normalize(dict(raw))[0], now=100.0 + ttl / 2.0
        ),
    ]
    _require_outcomes("within-TTL duplicate", within_outcomes, [True, False])

    expiry_daemon = _admission_only_daemon()
    expiry_outcomes = [
        expiry_daemon._admit_ingress_event(normalize(dict(raw))[0], now=200.0),
        expiry_daemon._admit_ingress_event(
            normalize(dict(raw))[0], now=200.0 + ttl + 0.001
        ),
    ]
    _require_outcomes("post-TTL duplicate", expiry_outcomes, [True, True])

    stop_daemon = _admission_only_daemon()
    stop_raw = _synthetic_stop(project)
    first_stop = normalize(dict(stop_raw))
    second_stop = normalize(dict(stop_raw))
    stop_outcomes = [
        stop_daemon._admit_ingress_event(event, now=300.0) for event in first_stop
    ] + [
        stop_daemon._admit_ingress_event(event, now=300.0 + ttl / 2.0)
        for event in second_stop
    ]
    _require_outcomes("Stop dual projection", stop_outcomes, [True, True, False, False])

    distinct_daemon = _admission_only_daemon()
    distinct_outcomes = [
        distinct_daemon._admit_ingress_event(
            normalize(_synthetic_pre_tool(project, "synthetic-tool-one"))[0],
            now=400.0,
        ),
        distinct_daemon._admit_ingress_event(
            normalize(_synthetic_pre_tool(project, "synthetic-tool-two"))[0],
            now=400.0,
        ),
    ]
    _require_outcomes("distinct tool uses", distinct_outcomes, [True, True])

    concurrent_admitted_counts: list[int] = []
    concurrent_duplicate_counts: list[int] = []
    for trial in range(concurrency_trials):
        concurrent_daemon = _admission_only_daemon()
        event = normalize(
            _synthetic_pre_tool(project, f"synthetic-concurrent-{trial}")
        )[0]
        barrier = threading.Barrier(concurrency)
        outcomes: list[bool] = []
        outcomes_lock = threading.Lock()

        def deliver() -> None:
            barrier.wait()
            admitted = concurrent_daemon._admit_ingress_event(event, now=500.0)
            with outcomes_lock:
                outcomes.append(admitted)

        threads = [threading.Thread(target=deliver) for _ in range(concurrency)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
        if any(thread.is_alive() for thread in threads):
            raise OperationalProbeError("concurrent admission thread did not stop")
        admitted_count = sum(outcomes)
        if len(outcomes) != concurrency or admitted_count != 1:
            raise OperationalProbeError(
                "concurrent duplicate admission was not atomic: "
                f"outcomes={len(outcomes)}, admitted={admitted_count}"
            )
        concurrent_admitted_counts.append(admitted_count)
        concurrent_duplicate_counts.append(concurrent_daemon._ingress_duplicate_count)

    return {
        "probe_boundary": (
            "Daemon ingress admission only; excludes ledger writes, rule "
            "evaluation, and user-visible latency"
        ),
        "clock": "injected deterministic logical seconds",
        "configured_ttl_seconds": ttl,
        "scenarios": {
            "identical_global_and_project_delivery_within_ttl": {
                "attempts": 2,
                "admission_outcomes": within_outcomes,
                "admitted": sum(within_outcomes),
                "suppressed_as_duplicate": within_daemon._ingress_duplicate_count,
            },
            "identical_delivery_after_ttl": {
                "attempts": 2,
                "admission_outcomes": expiry_outcomes,
                "admitted": sum(expiry_outcomes),
                "suppressed_as_duplicate": expiry_daemon._ingress_duplicate_count,
            },
            "stop_dual_projection_from_two_hook_layers": {
                "attempts": 4,
                "normalized_kinds": [event.kind for event in first_stop + second_stop],
                "admission_outcomes": stop_outcomes,
                "admitted": sum(stop_outcomes),
                "suppressed_as_duplicate": stop_daemon._ingress_duplicate_count,
            },
            "distinct_tool_use_ids": {
                "attempts": 2,
                "admission_outcomes": distinct_outcomes,
                "admitted": sum(distinct_outcomes),
                "suppressed_as_duplicate": distinct_daemon._ingress_duplicate_count,
            },
            "concurrent_identical_delivery": {
                "trials": concurrency_trials,
                "attempts_per_trial": concurrency,
                "admitted_per_trial": concurrent_admitted_counts,
                "suppressed_per_trial": concurrent_duplicate_counts,
                "all_trials_admitted_exactly_one": True,
            },
        },
    }


def run_operational(
    *,
    repetitions: int,
    warmups: int,
    unavailable_repetitions: int,
    dedup_concurrency: int,
    dedup_trials: int,
    python_executable: str = sys.executable,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rap-eacl-operational-") as temporary:
        work_dir = Path(temporary)
        hook_handoff = measure_hook_handoff(
            work_dir,
            repetitions=repetitions,
            warmups=warmups,
            python_executable=python_executable,
        )
        unavailable = measure_daemon_unavailable(
            work_dir, repetitions=unavailable_repetitions
        )
        duplicate_admission = measure_duplicate_admission(
            work_dir,
            concurrency=dedup_concurrency,
            concurrency_trials=dedup_trials,
        )

    return {
        "schema_version": 1,
        "experiment": "eacl2027-local-operational-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "measurement_scope": {
            "hook_handoff": (
                "Parent timestamp immediately before hook subprocess launch "
                "through complete request receipt by an immediate-ack local "
                "Unix-socket mock; not Codex turn latency"
            ),
            "daemon_unavailable": (
                "In-process hook_client.main absent-socket fail-open path; "
                "interpreter and daemon-startup time excluded"
            ),
            "duplicate_admission": (
                "Deterministic daemon admission decisions only; no PAW inference"
            ),
            "user_visible_latency_measured": False,
        },
        "hook_handoff": hook_handoff,
        "daemon_unavailable": unavailable,
        "duplicate_admission": duplicate_admission,
        "provenance": {
            "script": str(Path(__file__).resolve().relative_to(REPO_ROOT)),
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "git": _git_state(),
            "python": sys.version,
            "python_executable": str(Path(python_executable).resolve()),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "packages": {
                "rules-as-programs": _package_version("rules-as-programs"),
                "programasweights": _package_version("programasweights"),
            },
            "data": "synthetic fixtures only; temporary RAP_STATE_DIR removed",
        },
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run synthetic local RAP operational measurements."
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--warmups", type=int, default=10)
    parser.add_argument("--unavailable-repetitions", type=int, default=100)
    parser.add_argument("--dedup-concurrency", type=int, default=16)
    parser.add_argument("--dedup-trials", type=int, default=20)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()

    report = run_operational(
        repetitions=args.repetitions,
        warmups=args.warmups,
        unavailable_repetitions=args.unavailable_repetitions,
        dedup_concurrency=args.dedup_concurrency,
        dedup_trials=args.dedup_trials,
        python_executable=args.python,
    )
    _write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
