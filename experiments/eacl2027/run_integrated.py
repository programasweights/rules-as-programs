#!/usr/bin/env python3
"""Run the isolated hook-to-finding RAP integration experiment.

Unlike ``run_operational.py``, this runner crosses the production boundaries
from the installed Codex hook wrapper through the Unix socket, daemon, rule
loader, local PAW inference worker, SQLite finding store, and daemon query API.
All inputs and state are synthetic and live in a temporary directory.

The measured endpoint is *query-visible finding*, not rendered menu-bar UI and
not Codex turn latency. Codex normally launches the RAP hook asynchronously.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import psutil
except ImportError as exc:  # pragma: no cover - environment dependency
    raise SystemExit(
        "run_integrated.py requires psutil (python -m pip install psutil)"
    ) from exc


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rules_as_programs import ipc, rules_api  # noqa: E402
from rules_as_programs.adapters.codex.adapter import (  # noqa: E402
    CodexAdapter,
    normalize,
)
from rules_as_programs.core import revisions  # noqa: E402
from rules_as_programs.core.triggers import extract_input  # noqa: E402


RULE_ID = "78v34vpkzm2jp4rx"
RULE_PATH = ROOT / "rules" / RULE_ID / "rule.py"
PAW_MANIFEST = ROOT / "outputs" / "frozen" / "paw-finetuned.jsonl.manifest.json"
PAW_OUTPUT = ROOT / "outputs" / "frozen" / "paw-finetuned.jsonl"
FROZEN_OUTPUT = ROOT / "outputs" / "frozen" / "integrated.json"
COMPILER = "paw-ft-bs48"
COMPILER_SNAPSHOT = "paw-ft-bs48-20260530"
DEFAULT_SEQUENTIAL_REPETITIONS = 30
DEFAULT_BURST_SIZE = 24
DEFAULT_WARMUPS = 3
DEFAULT_TIMEOUT_SECONDS = 20.0
HOOK_TIMEOUT_SECONDS = 5.0
QUERY_POLL_INTERVAL_SECONDS = 0.005
RESOURCE_SAMPLE_INTERVAL_SECONDS = 0.02


class IntegratedExperimentError(RuntimeError):
    """Raised when a required production-path invariant is not satisfied."""


def _nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("cannot summarize an empty sample")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
    return ordered[rank - 1]


def _summary(values: list[float]) -> dict[str, Any]:
    if not values:
        raise ValueError("cannot summarize an empty sample")
    return {
        "unit": "ms",
        "count": len(values),
        "minimum": round(min(values), 3),
        "mean": round(sum(values) / len(values), 3),
        "p50_nearest_rank": round(_nearest_rank(values, 50), 3),
        "p95_nearest_rank": round(_nearest_rank(values, 95), 3),
        "p99_nearest_rank": round(_nearest_rank(values, 99), 3),
        "maximum": round(max(values), 3),
    }


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


@contextmanager
def _isolated_environment(root: Path) -> Iterator[dict[str, str]]:
    names = ("RAP_STATE_DIR", "CODEX_HOME", "PYTHONPATH")
    previous = {name: os.environ.get(name) for name in names}
    os.environ["RAP_STATE_DIR"] = str(root / "state")
    os.environ["CODEX_HOME"] = str(root / "codex-home")
    current_pythonpath = previous["PYTHONPATH"] or ""
    os.environ["PYTHONPATH"] = str(REPO_ROOT) + (
        os.pathsep + current_pythonpath if current_pythonpath else ""
    )
    try:
        yield dict(os.environ)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _program_id() -> str:
    manifest = json.loads(PAW_MANIFEST.read_text(encoding="utf-8"))
    program_id = str((manifest.get("program_ids") or {}).get(RULE_ID, ""))
    if not program_id:
        raise IntegratedExperimentError(
            f"frozen PAW manifest has no program id for {RULE_ID}"
        )
    if str(manifest.get("compiler", "")) != COMPILER:
        raise IntegratedExperimentError("frozen PAW compiler does not match protocol")
    snapshot = str(
        ((manifest.get("compiler_info") or {}).get(RULE_ID) or {}).get(
            "latest_snapshot", ""
        )
    )
    if snapshot != COMPILER_SNAPSHOT:
        raise IntegratedExperimentError(
            "frozen PAW compiler snapshot does not match protocol"
        )
    dataset_value = str(manifest.get("dataset", ""))
    dataset_path = (REPO_ROOT / dataset_value).resolve()
    try:
        dataset_path.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise IntegratedExperimentError(
            "frozen PAW manifest dataset escapes the repository"
        ) from exc
    if not dataset_path.is_file() or _sha256_file(dataset_path) != str(
        manifest.get("dataset_sha256", "")
    ):
        raise IntegratedExperimentError(
            "frozen PAW dataset is missing or does not match its manifest"
        )
    frozen_output = PAW_OUTPUT
    if not frozen_output.is_file() or _sha256_file(frozen_output) != str(
        manifest.get("output_sha256", "")
    ):
        raise IntegratedExperimentError(
            "frozen PAW output is missing or does not match its manifest"
        )
    try:
        matching_cases = [
            json.loads(line)
            for line in dataset_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except json.JSONDecodeError as exc:
        raise IntegratedExperimentError(
            "frozen PAW dataset is not valid JSONL"
        ) from exc
    matching_cases = [
        case for case in matching_cases if str(case.get("rule_id", "")) == RULE_ID
    ]
    source_hashes = {str(case.get("source_hash", "")) for case in matching_cases}
    if source_hashes != {_sha256_file(RULE_PATH)}:
        raise IntegratedExperimentError(
            "frozen PAW program was not compiled for the current rule source"
        )
    try:
        frozen_cases = [
            json.loads(line)
            for line in frozen_output.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except json.JSONDecodeError as exc:
        raise IntegratedExperimentError("frozen PAW output is not valid JSONL") from exc
    frozen_cases = [
        case for case in frozen_cases if str(case.get("rule_id", "")) == RULE_ID
    ]
    frozen_program_ids = {str(case.get("program_id", "")) for case in frozen_cases}
    frozen_source_hashes = {str(case.get("source_hash", "")) for case in frozen_cases}
    if frozen_program_ids != {program_id} or frozen_source_hashes != source_hashes:
        raise IntegratedExperimentError(
            "frozen PAW output does not link the pinned program to the rule source"
        )
    return program_id


def _raw_event(project: Path, case_id: str) -> dict[str, Any]:
    return {
        "session_id": f"integrated-session-{case_id}",
        "turn_id": f"integrated-turn-{case_id}",
        "hook_event_name": "PreToolUse",
        "cwd": str(project),
        "tool_name": "Bash",
        "tool_use_id": f"integrated-tool-{case_id}",
        "tool_input": {
            "command": (
                "scp train.py researcher@example.invalid:~/project/ "
                f"# synthetic-{case_id}"
            )
        },
    }


def _expected_input(raw: dict[str, Any]) -> str:
    events = normalize(raw)
    if len(events) != 1:
        raise IntegratedExperimentError(
            f"expected one normalized PreToolUse event, got {len(events)}"
        )
    text, _pointer, _kind, _overridden = extract_input(
        "PreToolUse", events[0].raw_payload, ""
    )
    return text


def _wait_for_daemon(process: subprocess.Popen, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise IntegratedExperimentError(
                f"daemon exited during startup with code {process.returncode}"
            )
        details = ipc.ping_details(timeout=0.25)
        if details:
            if int(details.get("pid", -1)) != process.pid:
                raise IntegratedExperimentError(
                    "daemon readiness probe reached an unexpected process"
                )
            if int(details.get("protocol", -1)) != ipc.PROTOCOL_VERSION:
                raise IntegratedExperimentError(
                    "daemon IPC protocol does not match the experiment client"
                )
            return details
        time.sleep(0.05)
    raise IntegratedExperimentError("daemon did not become ready before timeout")


def _force_terminate_process(process: subprocess.Popen, timeout: float = 2.0) -> None:
    """Terminate the isolated daemon process group without leaving workers."""
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (AttributeError, OSError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, OSError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise IntegratedExperimentError(
            f"daemon process group {process.pid} did not terminate"
        ) from exc


def _start_daemon(
    environment: dict[str, str], diagnostics: Path, timeout: float
) -> tuple[subprocess.Popen, dict[str, Any]]:
    diagnostics.parent.mkdir(parents=True, exist_ok=True)
    handle = diagnostics.open("ab", buffering=0)
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "rules_as_programs.daemon"],
            cwd=REPO_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=handle,
            start_new_session=True,
        )
    except Exception:
        handle.close()
        raise
    process._rap_diagnostics_handle = handle  # type: ignore[attr-defined]
    try:
        details = _wait_for_daemon(process, timeout)
    except Exception as exc:
        termination_error = ""
        try:
            _force_terminate_process(process)
        except IntegratedExperimentError as stop_exc:
            termination_error = f"; cleanup error: {stop_exc}"
        try:
            tail = diagnostics.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = ""
        handle.close()
        raise IntegratedExperimentError(
            f"{exc}{termination_error}; daemon diagnostics: {tail.strip() or '(empty)'}"
        ) from exc
    return process, details


def _stop_daemon(process: subprocess.Popen, timeout: float = 8.0) -> None:
    try:
        if process.poll() is None:
            ipc.send_request({"type": "shutdown"}, timeout=1.0)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _force_terminate_process(process)
    finally:
        handle = getattr(process, "_rap_diagnostics_handle", None)
        if handle is not None and not handle.closed:
            handle.close()


def _query_findings(
    project: Path, limit: int = 1000, timeout: float = 1.0
) -> list[dict[str, Any]]:
    response = ipc.send_request(
        {
            "type": "verdicts",
            "project_root": str(project),
            "limit": limit,
            "include_acknowledged": True,
            "include_suppressed": True,
        },
        timeout=timeout,
    )
    if not response or not response.get("ok"):
        return []
    return list(response.get("verdicts") or [])


def _finding_for_input(
    project: Path, expected_input: str, timeout: float = 1.0
) -> dict[str, Any] | None:
    for finding in _query_findings(project, timeout=timeout):
        observed = ((finding.get("evaluation") or {}).get("input") or {}).get("text")
        if observed == expected_input:
            return finding
    return None


def _invoke_hook(
    wrapper: Path, raw: dict[str, Any], environment: dict[str, str]
) -> dict[str, Any]:
    started_ns = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            [str(wrapper)],
            cwd=raw["cwd"],
            env=environment,
            input=json.dumps(raw),
            text=True,
            capture_output=True,
            timeout=HOOK_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise IntegratedExperimentError(
            f"installed hook exceeded its {HOOK_TIMEOUT_SECONDS:.1f}s timeout"
        ) from exc
    exited_ns = time.perf_counter_ns()
    return {
        "started_ns": started_ns,
        "exited_ns": exited_ns,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _assert_hook_contract(hook: dict[str, Any], label: str) -> None:
    if hook["returncode"] != 0 or hook["stdout"] != "{}" or hook["stderr"]:
        raise IntegratedExperimentError(
            f"{label} did not preserve the fail-open empty-object contract: "
            f"returncode={hook['returncode']} stdout={hook['stdout']!r} "
            f"stderr={hook['stderr']!r}"
        )


def _wait_for_finding(
    project: Path, expected_input: str, started_ns: int, timeout: float
) -> tuple[dict[str, Any], int]:
    deadline_ns = started_ns + int(timeout * 1_000_000_000)
    while time.perf_counter_ns() < deadline_ns:
        remaining = (deadline_ns - time.perf_counter_ns()) / 1_000_000_000
        finding = _finding_for_input(
            project, expected_input, timeout=max(0.001, min(1.0, remaining))
        )
        visible_ns = time.perf_counter_ns()
        if finding is not None and visible_ns <= deadline_ns:
            return finding, visible_ns
        time.sleep(QUERY_POLL_INTERVAL_SECONDS)
    elapsed = (time.perf_counter_ns() - started_ns) / 1_000_000_000
    raise IntegratedExperimentError(
        f"finding did not become query-visible after {elapsed:.3f}s"
    )


def _run_one(
    wrapper: Path,
    project: Path,
    environment: dict[str, str],
    case_id: str,
    timeout: float,
) -> dict[str, Any]:
    raw = _raw_event(project, case_id)
    expected_input = _expected_input(raw)
    hook = _invoke_hook(wrapper, raw, environment)
    _assert_hook_contract(hook, "installed hook")
    finding, visible_ns = _wait_for_finding(
        project, expected_input, hook["started_ns"], timeout
    )
    evaluation = finding.get("evaluation") or {}
    rule = evaluation.get("rule") or {}
    return {
        "case_id": case_id,
        "hook_exit_ms": round((hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3),
        "event_to_query_visible_finding_ms": round(
            (visible_ns - hook["started_ns"]) / 1_000_000, 3
        ),
        "finding_id": int(finding["id"]),
        "severity": finding.get("severity"),
        "input_sha256": hashlib.sha256(expected_input.encode("utf-8")).hexdigest(),
        "exact_input_preserved": (
            ((evaluation.get("input") or {}).get("text")) == expected_input
        ),
        "input_sha256_matches": (
            ((evaluation.get("input") or {}).get("sha256"))
            == hashlib.sha256(expected_input.encode("utf-8")).hexdigest()
        ),
        "trigger_hook": (evaluation.get("trigger") or {}).get("hook"),
        "evaluation_schema_version": evaluation.get("schema_version"),
        "rule_id": rule.get("id"),
        "rule_source_hash": rule.get("source_hash"),
        "rule_behavior_hash": rule.get("behavior_hash"),
        "rule_compiler": rule.get("compiler"),
        "rule_compiler_snapshot": rule.get("compiler_snapshot"),
        "rule_program_id": rule.get("program_id"),
    }


def _process_tree_resources(pid: int) -> dict[str, Any]:
    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {"processes": 0, "rss_bytes": 0, "cpu_seconds": 0.0}
    rss = 0
    cpu = 0.0
    alive = 0
    for process in processes:
        try:
            rss += int(process.memory_info().rss)
            times = process.cpu_times()
            cpu += float(times.user + times.system)
            alive += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return {
        "processes": alive,
        "rss_bytes": rss,
        "cpu_seconds": round(cpu, 6),
    }


class _ResourceSampler:
    def __init__(self, pid: int, interval: float = RESOURCE_SAMPLE_INTERVAL_SECONDS):
        self.pid = pid
        self.interval = interval
        self.samples: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self._stop.is_set():
            try:
                sample = _process_tree_resources(self.pid)
                if sample["processes"] == 0:
                    return
                self.samples.append(sample)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return
            self._stop.wait(self.interval)

    def __enter__(self) -> "_ResourceSampler":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)


def _inference_workers(daemon_pid: int) -> list[tuple[int, psutil.Process]]:
    try:
        children = psutil.Process(daemon_pid).children(recursive=False)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []
    candidates: list[tuple[int, psutil.Process]] = []
    for child in children:
        try:
            command = " ".join(child.cmdline())
            if "spawn_main" in command:
                candidates.append((int(child.memory_info().rss), child))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return candidates


def _kill_inference_worker(daemon_pid: int) -> dict[str, Any]:
    candidates = _inference_workers(daemon_pid)
    if not candidates:
        raise IntegratedExperimentError("could not identify the PAW inference worker")
    _rss, worker = max(candidates, key=lambda item: item[0])
    old_pid = worker.pid
    try:
        worker.send_signal(signal.SIGTERM)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        raise IntegratedExperimentError(
            "PAW inference worker disappeared before the recovery probe"
        ) from exc
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            if not worker.is_running() or worker.status() == psutil.STATUS_ZOMBIE:
                break
        except psutil.NoSuchProcess:
            break
        time.sleep(0.05)
    else:
        try:
            worker.kill()
            worker.wait(timeout=2.0)
        except psutil.NoSuchProcess:
            pass
        except psutil.TimeoutExpired as exc:
            raise IntegratedExperimentError(
                f"PAW inference worker {old_pid} did not terminate"
            ) from exc
    return {"old_worker_pid": old_pid, "old_worker_rss_bytes": _rss}


def _assert_samples(
    samples: list[dict[str, Any]],
    expected: int,
    *,
    program_id: str,
    source_hash: str,
    behavior_hash: str,
) -> None:
    if len(samples) != expected:
        raise IntegratedExperimentError(
            f"expected {expected} successful samples, observed {len(samples)}"
        )
    for sample in samples:
        if sample["severity"] != "warn":
            raise IntegratedExperimentError(
                f"unexpected severity for {sample['case_id']}: {sample['severity']!r}"
            )
        if not sample["exact_input_preserved"] or not sample["input_sha256_matches"]:
            raise IntegratedExperimentError(
                f"input provenance mismatch for {sample['case_id']}"
            )
        if sample["trigger_hook"] != "PreToolUse":
            raise IntegratedExperimentError(
                f"trigger provenance mismatch for {sample['case_id']}"
            )
        expected_rule = {
            "evaluation_schema_version": 4,
            "rule_id": RULE_ID,
            "rule_source_hash": source_hash,
            "rule_behavior_hash": behavior_hash,
            "rule_compiler": COMPILER,
            "rule_compiler_snapshot": COMPILER_SNAPSHOT,
            "rule_program_id": program_id,
        }
        mismatched = {
            key: {"expected": value, "observed": sample.get(key)}
            for key, value in expected_rule.items()
            if sample.get(key) != value
        }
        if mismatched:
            raise IntegratedExperimentError(
                f"deployed-revision provenance mismatch for {sample['case_id']}: "
                f"{mismatched}"
            )


def _finding_accounting(
    findings: list[dict[str, Any]], expected_inputs: list[str]
) -> dict[str, Any]:
    expected_hashes = {
        hashlib.sha256(value.encode("utf-8")).hexdigest() for value in expected_inputs
    }
    if len(expected_hashes) != len(expected_inputs):
        raise IntegratedExperimentError(
            "synthetic case generator produced duplicate expected inputs"
        )
    counts = {value: 0 for value in expected_hashes}
    unexpected = 0
    for finding in findings:
        observed = ((finding.get("evaluation") or {}).get("input") or {}).get("text")
        observed_hash = hashlib.sha256(str(observed).encode("utf-8")).hexdigest()
        if observed_hash in counts:
            counts[observed_hash] += 1
        else:
            unexpected += 1
    missing = sum(1 for count in counts.values() if count == 0)
    duplicates = sum(max(0, count - 1) for count in counts.values())
    return {
        "findings_expected": len(expected_hashes),
        "findings_observed": len(findings),
        "expected_inputs_observed": len(expected_hashes) - missing,
        "loss_count": missing,
        "duplicate_findings": duplicates,
        "unexpected_findings": unexpected,
    }


def run_experiment(
    *,
    sequential_repetitions: int = DEFAULT_SEQUENTIAL_REPETITIONS,
    burst_size: int = DEFAULT_BURST_SIZE,
    warmups: int = DEFAULT_WARMUPS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if sequential_repetitions < 1 or burst_size < 1 or warmups < 1:
        raise ValueError(
            "sequential repetitions, burst size, and warmups must be positive"
        )
    program_id = _program_id()
    with tempfile.TemporaryDirectory(prefix="rap-integrated-", dir="/tmp") as temporary:
        isolated_root = Path(temporary)
        with _isolated_environment(isolated_root) as environment:
            project = (isolated_root / "synthetic-project").resolve()
            project.mkdir()
            source = RULE_PATH.read_text(encoding="utf-8")
            saved = rules_api.save_rule(RULE_ID, source, "project", str(project))
            if not saved.get("ok"):
                raise IntegratedExperimentError(
                    str(saved.get("error", "could not install synthetic study rule"))
                )
            saved_source = str(saved["source"])
            source_hash = revisions.hash_source(saved_source)
            behavior_hash = revisions.behavior_hash(saved_source)
            revisions.activate(
                RULE_ID,
                str(saved["path"]),
                saved_source,
                compiler=COMPILER,
                program_id=program_id,
                compiler_snapshot=COMPILER_SNAPSHOT,
                compiler_mode=revisions.EXPLICIT_COMPILER_MODE,
            )
            install_notes = CodexAdapter().install("project", str(project))
            wrapper = project / ".codex" / "hooks" / "rap-hook.sh"
            hooks_json = project / ".codex" / "hooks.json"
            if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
                raise IntegratedExperimentError(
                    "project hook wrapper was not installed"
                )
            if "rap-hook.sh" not in hooks_json.read_text(encoding="utf-8"):
                raise IntegratedExperimentError(
                    "project hooks.json does not register RAP"
                )
            normalized_install_notes = [
                str(note).replace(str(project), "<synthetic-project>")
                for note in install_notes
            ]

            diagnostics = isolated_root / "daemon-output.log"
            daemon, first_identity = _start_daemon(environment, diagnostics, timeout)
            daemons = [daemon]
            try:
                warmup_samples = [
                    _run_one(
                        wrapper,
                        project,
                        environment,
                        f"warmup-{index}",
                        timeout,
                    )
                    for index in range(warmups)
                ]
                _assert_samples(
                    warmup_samples,
                    warmups,
                    program_id=program_id,
                    source_hash=source_hash,
                    behavior_hash=behavior_hash,
                )

                resource_before = _process_tree_resources(daemon.pid)
                if resource_before["processes"] == 0:
                    raise IntegratedExperimentError(
                        "daemon process tree disappeared before measurement"
                    )
                sequential = [
                    _run_one(
                        wrapper,
                        project,
                        environment,
                        f"sequential-{index}",
                        timeout,
                    )
                    for index in range(sequential_repetitions)
                ]
                _assert_samples(
                    sequential,
                    sequential_repetitions,
                    program_id=program_id,
                    source_hash=source_hash,
                    behavior_hash=behavior_hash,
                )
                resource_after_sequential = _process_tree_resources(daemon.pid)
                if resource_after_sequential["processes"] == 0:
                    raise IntegratedExperimentError(
                        "daemon process tree disappeared after sequential measurement"
                    )

                with _ResourceSampler(daemon.pid) as resource_sampler:
                    burst_started_ns = time.perf_counter_ns()
                    burst: list[dict[str, Any]] = []
                    with ThreadPoolExecutor(
                        max_workers=min(24, burst_size),
                        thread_name_prefix="rap-integrated-burst",
                    ) as executor:
                        futures = [
                            executor.submit(
                                _run_one,
                                wrapper,
                                project,
                                environment,
                                f"burst-{index}",
                                timeout,
                            )
                            for index in range(burst_size)
                        ]
                        for future in as_completed(futures):
                            burst.append(future.result())
                    burst_finished_ns = time.perf_counter_ns()
                burst.sort(key=lambda sample: sample["case_id"])
                _assert_samples(
                    burst,
                    burst_size,
                    program_id=program_id,
                    source_hash=source_hash,
                    behavior_hash=behavior_hash,
                )
                resource_after_burst = _process_tree_resources(daemon.pid)
                if resource_after_burst["processes"] == 0:
                    raise IntegratedExperimentError(
                        "daemon process tree disappeared after burst measurement"
                    )

                duplicate_raw = _raw_event(project, "duplicate")
                duplicate_input = _expected_input(duplicate_raw)
                duplicate_sample = _run_one(
                    wrapper, project, environment, "duplicate", timeout
                )
                _assert_samples(
                    [duplicate_sample],
                    1,
                    program_id=program_id,
                    source_hash=source_hash,
                    behavior_hash=behavior_hash,
                )
                duplicate_before = ipc.send_request({"type": "snapshot"}, timeout=2.0)
                if not duplicate_before:
                    raise IntegratedExperimentError(
                        "snapshot failed before duplicate redelivery"
                    )
                duplicate_second = _invoke_hook(wrapper, duplicate_raw, environment)
                _assert_hook_contract(duplicate_second, "duplicate redelivery hook")
                duplicate_after = ipc.send_request({"type": "snapshot"}, timeout=2.0)
                if not duplicate_after:
                    raise IntegratedExperimentError(
                        "snapshot failed after duplicate redelivery"
                    )
                duplicate_before_count = int(
                    (
                        (duplicate_before.get("daemon") or {}).get(
                            "ingress_duplicates", 0
                        )
                    )
                )
                duplicate_after_count = int(
                    ((duplicate_after.get("daemon") or {}).get("ingress_duplicates", 0))
                )
                duplicate_count_delta = duplicate_after_count - duplicate_before_count
                duplicate_occurrences = sum(
                    1
                    for finding in _query_findings(project)
                    if ((finding.get("evaluation") or {}).get("input") or {}).get(
                        "text"
                    )
                    == duplicate_input
                )
                if duplicate_count_delta != 1 or duplicate_occurrences != 1:
                    raise IntegratedExperimentError(
                        "identical redelivery did not yield one admission and finding: "
                        f"counter_delta={duplicate_count_delta}, "
                        f"stored_findings={duplicate_occurrences}"
                    )

                worker_restart = _kill_inference_worker(daemon.pid)
                worker_recovery = _run_one(
                    wrapper,
                    project,
                    environment,
                    "worker-recovery",
                    timeout,
                )
                _assert_samples(
                    [worker_recovery],
                    1,
                    program_id=program_id,
                    source_hash=source_hash,
                    behavior_hash=behavior_hash,
                )
                new_worker_candidates = [
                    child.pid for _rss, child in _inference_workers(daemon.pid)
                ]
                worker_restart["new_worker_pids"] = new_worker_candidates
                worker_restart["replaced"] = worker_restart[
                    "old_worker_pid"
                ] not in new_worker_candidates and bool(new_worker_candidates)
                if not worker_restart["replaced"]:
                    raise IntegratedExperimentError(
                        "PAW worker recovery did not produce a distinct live worker"
                    )

                _stop_daemon(daemon)
                second_daemon, second_identity = _start_daemon(
                    environment, diagnostics, timeout
                )
                daemons.append(second_daemon)
                daemon_recovery = _run_one(
                    wrapper,
                    project,
                    environment,
                    "daemon-recovery",
                    timeout,
                )
                _assert_samples(
                    [daemon_recovery],
                    1,
                    program_id=program_id,
                    source_hash=source_hash,
                    behavior_hash=behavior_hash,
                )
                daemon_pid_changed = int(first_identity["pid"]) != int(
                    second_identity["pid"]
                )
                daemon_started_at_changed = first_identity.get(
                    "started_at"
                ) != second_identity.get("started_at")
                daemon_replaced = daemon_started_at_changed
                if not daemon_replaced:
                    raise IntegratedExperimentError(
                        "daemon recovery did not produce a distinct daemon identity"
                    )

                expected_case_ids = [
                    *[f"warmup-{index}" for index in range(warmups)],
                    *[f"sequential-{index}" for index in range(sequential_repetitions)],
                    *[f"burst-{index}" for index in range(burst_size)],
                    "duplicate",
                    "worker-recovery",
                    "daemon-recovery",
                ]
                expected_inputs = [
                    _expected_input(_raw_event(project, case_id))
                    for case_id in expected_case_ids
                ]
                all_findings = _query_findings(project, limit=len(expected_inputs) + 20)
                accounting = _finding_accounting(all_findings, expected_inputs)
                if any(
                    accounting[key]
                    for key in (
                        "loss_count",
                        "duplicate_findings",
                        "unexpected_findings",
                    )
                ):
                    raise IntegratedExperimentError(
                        f"end-to-end finding accounting failed: {accounting}"
                    )

                sequential_latency = [
                    sample["event_to_query_visible_finding_ms"] for sample in sequential
                ]
                sequential_hook = [sample["hook_exit_ms"] for sample in sequential]
                burst_latency = [
                    sample["event_to_query_visible_finding_ms"] for sample in burst
                ]
                burst_hook = [sample["hook_exit_ms"] for sample in burst]
                resource_samples = resource_sampler.samples
                peak_rss = max(
                    [
                        resource_before["rss_bytes"],
                        resource_after_sequential["rss_bytes"],
                        resource_after_burst["rss_bytes"],
                    ]
                    + [sample["rss_bytes"] for sample in resource_samples]
                )
                cpu_delta = max(
                    0.0,
                    resource_after_burst["cpu_seconds"]
                    - resource_before["cpu_seconds"],
                )
                burst_seconds = (burst_finished_ns - burst_started_ns) / 1_000_000_000
                return {
                    "schema_version": 2,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "measurement_boundary": {
                        "start": "parent immediately before installed hook process launch",
                        "end": "first successful daemon verdict query returning the exact input",
                        "included": [
                            "installed project hook wrapper",
                            "Codex adapter normalization",
                            "Unix-socket request and acknowledgement",
                            "daemon ingress and ledger append",
                            "production rule loading and trigger matching",
                            "local PAW inference in supervised subprocess",
                            "SQLite finding persistence",
                            "daemon verdict query",
                        ],
                        "excluded": [
                            "Codex scheduling of its asynchronous hook",
                            "rendering or human perception of the menu-bar UI",
                            "remote PAW compilation (artifact was already frozen)",
                        ],
                        "interpretation": (
                            "query-visible finding latency, not Codex turn latency or "
                            "rendered UI latency"
                        ),
                        "invocation": (
                            "experiment parent synchronously launches the exact installed "
                            "wrapper that Codex normally schedules asynchronously"
                        ),
                        "query_poll_interval_ms": int(
                            QUERY_POLL_INTERVAL_SECONDS * 1000
                        ),
                    },
                    "protocol": {
                        "synthetic_inputs": True,
                        "rule_id": RULE_ID,
                        "compiler": COMPILER,
                        "compiler_snapshot": COMPILER_SNAPSHOT,
                        "program_id": program_id,
                        "warmups_excluded": warmups,
                        "sequential_repetitions": sequential_repetitions,
                        "burst_size": burst_size,
                        "per_finding_timeout_seconds": timeout,
                        "hook_process_timeout_seconds": HOOK_TIMEOUT_SECONDS,
                        "daemon_ipc_protocol": ipc.PROTOCOL_VERSION,
                    },
                    "installation": {
                        "wrapper_present_and_executable": True,
                        "hooks_json_registered": True,
                        "notes": normalized_install_notes,
                    },
                    "provenance": {
                        "runner": {
                            "path": str(
                                Path(__file__).resolve().relative_to(REPO_ROOT)
                            ),
                            "sha256": _sha256_file(Path(__file__).resolve()),
                        },
                        "rule_source": {
                            "path": str(RULE_PATH.relative_to(REPO_ROOT)),
                            "file_sha256": _sha256_file(RULE_PATH),
                            "source_sha256": source_hash,
                            "behavior_sha256": behavior_hash,
                        },
                        "frozen_paw_manifest": {
                            "path": str(PAW_MANIFEST.relative_to(REPO_ROOT)),
                            "sha256": _sha256_file(PAW_MANIFEST),
                        },
                        "frozen_paw_output": {
                            "path": str(PAW_OUTPUT.relative_to(REPO_ROOT)),
                            "sha256": _sha256_file(PAW_OUTPUT),
                        },
                        "study_protocol": {
                            "path": str(
                                (ROOT / "protocol.json").relative_to(REPO_ROOT)
                            ),
                            "sha256": _sha256_file(ROOT / "protocol.json"),
                        },
                        "installed_wrapper_sha256": _sha256_file(wrapper),
                        "installed_hooks_json_sha256": _sha256_file(hooks_json),
                        "daemon_version": first_identity.get("version"),
                    },
                    "sequential": {
                        "findings_expected": sequential_repetitions,
                        "findings_observed": len(sequential),
                        "loss_count": sequential_repetitions - len(sequential),
                        "hook_process_exit": _summary(sequential_hook),
                        "event_to_query_visible_finding": _summary(sequential_latency),
                        "all_exact_inputs_preserved": all(
                            item["exact_input_preserved"] for item in sequential
                        ),
                        "samples": sequential,
                    },
                    "burst": {
                        "findings_expected": burst_size,
                        "findings_observed": len(burst),
                        "loss_count": burst_size - len(burst),
                        "wall_seconds": round(burst_seconds, 3),
                        "throughput_findings_per_second": round(
                            burst_size / burst_seconds, 3
                        ),
                        "hook_process_exit": _summary(burst_hook),
                        "event_to_query_visible_finding": _summary(burst_latency),
                        "all_exact_inputs_preserved": all(
                            item["exact_input_preserved"] for item in burst
                        ),
                        "samples": burst,
                    },
                    "duplicate_delivery": {
                        "deliveries": 2,
                        "stored_findings": duplicate_occurrences,
                        "ingress_duplicate_counter_before": duplicate_before_count,
                        "ingress_duplicate_counter_after": duplicate_after_count,
                        "duplicate_count_delta": duplicate_count_delta,
                        "first_finding_id": duplicate_sample["finding_id"],
                        "first_delivery_sample": duplicate_sample,
                        "one_finding_for_two_identical_deliveries": (
                            duplicate_count_delta == 1 and duplicate_occurrences == 1
                        ),
                    },
                    "recovery": {
                        "worker": {
                            **worker_restart,
                            "finding_observed": True,
                            "event_to_query_visible_finding_ms": worker_recovery[
                                "event_to_query_visible_finding_ms"
                            ],
                            "sample": worker_recovery,
                        },
                        "daemon": {
                            "old_pid": int(first_identity["pid"]),
                            "new_pid": int(second_identity["pid"]),
                            "old_started_at": first_identity.get("started_at"),
                            "new_started_at": second_identity.get("started_at"),
                            "pid_changed": daemon_pid_changed,
                            "started_at_changed": daemon_started_at_changed,
                            "replaced": daemon_replaced,
                            "finding_observed": True,
                            "event_to_query_visible_finding_ms": daemon_recovery[
                                "event_to_query_visible_finding_ms"
                            ],
                            "sample": daemon_recovery,
                        },
                    },
                    "resources": {
                        "scope": "daemon plus recursive child processes",
                        "warm_idle_rss_bytes": resource_before["rss_bytes"],
                        "peak_sampled_rss_bytes": peak_rss,
                        "cpu_seconds_sequential_plus_burst": round(cpu_delta, 3),
                        "sampling_interval_ms": int(
                            RESOURCE_SAMPLE_INTERVAL_SECONDS * 1000
                        ),
                        "burst_samples": len(resource_samples),
                        "warm_idle_processes": resource_before["processes"],
                        "post_sequential_processes": resource_after_sequential[
                            "processes"
                        ],
                        "post_burst_processes": resource_after_burst["processes"],
                    },
                    "end_to_end_accounting": accounting,
                    "machine": {
                        "platform": platform.platform(),
                        "system": platform.system(),
                        "machine": platform.machine(),
                        "python": sys.version,
                        "cpu_count_logical": os.cpu_count(),
                    },
                    "packages": {
                        "rules-as-programs": _package_version("rules-as-programs"),
                        "programasweights": _package_version("programasweights"),
                        "llama-cpp-python": _package_version("llama-cpp-python"),
                        "psutil": _package_version("psutil"),
                    },
                    "git": _git_state(),
                }
            finally:
                for process in reversed(daemons):
                    _stop_daemon(process)


def _require_frozen_configuration(
    sequential_repetitions: int,
    burst_size: int,
    warmups: int,
    timeout: float,
) -> dict[str, Any]:
    observed = {
        "sequential_repetitions": sequential_repetitions,
        "burst_size": burst_size,
        "warmups": warmups,
        "timeout": timeout,
    }
    expected = {
        "sequential_repetitions": DEFAULT_SEQUENTIAL_REPETITIONS,
        "burst_size": DEFAULT_BURST_SIZE,
        "warmups": DEFAULT_WARMUPS,
        "timeout": DEFAULT_TIMEOUT_SECONDS,
    }
    if observed != expected:
        raise IntegratedExperimentError(
            f"frozen run parameters differ from protocol: "
            f"observed={observed} expected={expected}"
        )
    if FROZEN_OUTPUT.exists():
        raise IntegratedExperimentError(
            f"frozen output already exists; protocol amendment required: {FROZEN_OUTPUT}"
        )
    git_state = _git_state()
    if not git_state.get("commit") or git_state.get("dirty") is not False:
        raise IntegratedExperimentError(
            f"frozen run requires a clean scoped Git commit: {git_state}"
        )
    return git_state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sequential-repetitions",
        type=int,
        default=DEFAULT_SEQUENTIAL_REPETITIONS,
    )
    parser.add_argument("--burst-size", type=int, default=DEFAULT_BURST_SIZE)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--output",
        type=Path,
        help="write JSON here; otherwise print to stdout",
    )
    parser.add_argument(
        "--write-frozen",
        action="store_true",
        help="create the canonical output using only frozen protocol parameters",
    )
    args = parser.parse_args()
    if args.write_frozen and args.output:
        parser.error("use either --output or --write-frozen, not both")
    if args.write_frozen:
        _require_frozen_configuration(
            args.sequential_repetitions,
            args.burst_size,
            args.warmups,
            args.timeout,
        )
    result = run_experiment(
        sequential_repetitions=args.sequential_repetitions,
        burst_size=args.burst_size,
        warmups=args.warmups,
        timeout=args.timeout,
    )
    if args.write_frozen and (
        not (result.get("git") or {}).get("commit")
        or (result.get("git") or {}).get("dirty") is not False
    ):
        raise IntegratedExperimentError(
            f"refusing to write frozen output from dirty Git state: {result.get('git')}"
        )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output = FROZEN_OUTPUT if args.write_frozen else args.output
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, output)
        print(output)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
