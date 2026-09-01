#!/usr/bin/env python3
"""Run the RAP multi-rule/multi-project scaling and fault study.

The default formal design implements protocol v3. Candidate and smoke runs are
explicitly labeled and cannot write below ``outputs/frozen``. Each
matrix condition uses a fresh isolated RAP state directory, fresh synthetic
project roots, and a fresh daemon process.  The installed project hook wrapper
is the only event-ingress path.

The primary endpoint is *query-visible completion of every expected rule
evaluation*.  It is not Codex turn latency, rendered UI latency, or human
perception.  Codex normally schedules this fail-open hook asynchronously; the
harness synchronously launches the exact installed wrapper so its boundary can
be measured reproducibly.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import platform
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

try:
    import psutil
except ImportError as exc:  # pragma: no cover - environment dependency
    raise SystemExit(
        "run_scaling_faults.py requires psutil (python -m pip install psutil)"
    ) from exc


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rules_as_programs import config as rap_config  # noqa: E402
from rules_as_programs import ipc, rules_api  # noqa: E402
from rules_as_programs.adapters.codex.adapter import CodexAdapter, normalize  # noqa: E402
from rules_as_programs.core import evaluation_log, revisions  # noqa: E402
from rules_as_programs.core.triggers import extract_input  # noqa: E402

from experiments.eacl2027 import run_integrated as integrated  # noqa: E402
from experiments.eacl2027.scaling_faults_attempts import (  # noqa: E402
    _COMPONENT_CANARY_ARCHIVE_MEMBER_TEMPLATES,
    AttemptRecorder,
    SystemsHarnessError,
    UNIT_STATUSES,
    replacement_launch_binding,
)
from experiments.eacl2027.scaling_faults_runtime import (  # noqa: E402
    RuntimeContractError,
    formal_runtime_receipt,
    retain_cache_end_receipt,
)


class SystemViolationError(RuntimeError):
    """A measured production-path failure, never a rerun-eligible harness error."""


class ExternalInfrastructureError(RuntimeError):
    """A positively observed host/storage failure outside the measured system."""


EXTERNAL_MANIFEST = (
    ROOT / "outputs" / "frozen" / "external-paw-finetuned.jsonl.manifest.json"
)
EXTERNAL_OUTPUT = ROOT / "outputs" / "frozen" / "external-paw-finetuned.jsonl"
EXTERNAL_DATASET = ROOT / "data" / "public" / "external.jsonl"
PROTOCOL_V3 = ROOT / "protocol-v3.json"
FORMAL_PARENT_AMENDMENT = ROOT / "protocol-v3-amendment-006.json"
FORMAL_BASE_AMENDMENT = ROOT / "protocol-v3-amendment-007.json"
FORMAL_BASE_AMENDMENT_SHA256 = (
    "540ee245cd025d3cb5c4146fb36ec30b7d54b40ccc74de78a3a4df9a06f4aa91"
)
FORMAL_AMENDMENT = ROOT / "protocol-v3-amendment-008.json"
FORMAL_CORRECTION_AMENDMENT = ROOT / "protocol-v3-amendment-009.json"
FORMAL_ROUTING_CORRECTION_AMENDMENT = ROOT / "protocol-v3-amendment-010.json"
FORMAL_PREPUBLICATION_CORRECTION_AMENDMENT = (
    ROOT / "protocol-v3-amendment-011.json"
)
FORMAL_HISTORICAL_ROLE_CORRECTION_AMENDMENT = (
    ROOT / "protocol-v3-amendment-012.json"
)
FORMAL_SUPERVISOR_WAIT_CORRECTION_AMENDMENT = (
    ROOT / "protocol-v3-amendment-013.json"
)
FORMAL_STUDY_MODE = "formal_protocol_v3_amendment_008"
FORMAL_STUDY_MODE_OVERRIDE_TEXT = (
    "For exact raw r03, study_mode is exactly "
    "formal_protocol_v3_amendment_008 and is cross-bound without aliasing in "
    "the effective-config receipt, setup receipt, launch identity, every "
    "terminal result, raw result, and analyzer. study_mode is not inserted "
    "into plan rows; r03 plan.json must be byte-for-byte equal to r02 plan.json "
    "and retain the frozen canonical plan hash. The inherited "
    "formal_protocol_v3_amendment_007 value remains exact for r01/r02 only."
)
FORMAL_FULL_PLAN_SHA256 = (
    "4cdf827bf1c07a7bea9cd9d1af5c5ab37086af294583c8a5775643209b3c917c"
)
FORMAL_FULL_PLAN_STORED_SHA256 = (
    "cab6e22893cea6a41f3140ce57a39d34b7a463ba5e7453aa3970d39ff67f5434"
)
FORMAL_FULL_PLAN_MEMBERSHIP_SHA256 = (
    "cd5885dba0bfe7584f4b44efe18e3f1b827a9de0bfef6abcb0127adab1b6b162"
)
FORMAL_COMPONENT_ANALYSIS_ID = "protocol-v3-amendment-008-whole-attempt-replacement-v1"
FORMAL_FAULTS = (
    "daemon_crash",
    "worker_exit",
    "worker_timeout",
    "sqlite_lock",
    "malformed_payload",
    "duplicate_delivery",
    "deployment_failure",
)
FORMAL_FAULT_OVERRIDE_TEXT = (
    "For exact r03, fault_names_in_order remains the complete inherited order "
    "[daemon_crash, worker_exit, worker_timeout, sqlite_lock, malformed_payload, "
    "duplicate_delivery, deployment_failure]. No family is omitted, synthesized, "
    "or sourced from another attempt."
)
FROZEN_OUTPUT_DIR = (ROOT / "outputs" / "frozen").resolve()
EXTERNAL_RULE_ORDER = (
    "3pcxewp5hggr1vsn",
    "98z9wvr031840p4g",
    "e3m4bdwj6gqcwpnn",
    "g3b7damk0b5xgdj6",
    "q88xgdmftag16dq9",
    "qfh0h1cf4wt5aeg4",
    "sr09vpkt60y74r0q",
    "xb24rc14cpcrsf4g",
)
DEFAULT_RULE_COUNTS = (1, 2, 4, 8)
DEFAULT_PROJECT_COUNTS = (1, 4, 8)
DEFAULT_BURST_SIZES = (24, 64)
DEFAULT_REPEATS = 4
DEFAULT_SEQUENTIAL_EVENTS = 20
DEFAULT_WARMUPS_PER_PROJECT = 1
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_DRAIN_TIMEOUT_SECONDS = 1200.0
DEFAULT_MAX_HOOK_WORKERS = 24
DEFAULT_SOAK_BATCH_SIZE = 64
DEFAULT_SOAK_EVENTS = 10_000
DEFAULT_FAULT_REPETITIONS = 20
FINAL_DRAIN_SETTLE_SECONDS = 1.0
TRAFFIC_PATTERNS = ("round_robin_across_projects", "one_project_hotspot")
QUERY_POLL_INTERVAL_SECONDS = 0.25
MATRIX_HISTORY_DUPLICATE_HEADROOM = 64
SOAK_JOURNAL_POLL_INTERVAL_SECONDS = 1.0
SOAK_HISTORY_CHECKPOINT_RETRY_SECONDS = 1.0
SOAK_BATCH_SETTLE_SECONDS = 1.0
RESOURCE_SAMPLE_INTERVAL_SECONDS = 1.0
EVALUATION_HISTORY_LIMIT = 5000
EVALUATION_JOURNAL_ROTATION_BYTES = evaluation_log.MAX_LOG_BYTES
EVALUATION_JOURNAL_ROTATION_BACKUPS = evaluation_log.MAX_BACKUPS
SQLITE_BUSY_TIMEOUT_SECONDS = 5.0
MAX_AF_UNIX_PATHNAME_BYTES = 107
SOCKET_CLEANUP_TIMEOUT_SECONDS = 2.0
FORMAL_RAW_ATTEMPT_ROOT = Path("/u4/yuntian/rap-eacl-systems-formal-v3/attempts")
FORMAL_SUPERVISOR_ROOT = Path(
    "/u4/yuntian/rap-eacl-systems-formal-v3/scheduler/supervisor-closeouts/"
    "formal-v3-20260831t051023z-r05"
)
FORMAL_RAW_ATTEMPT_ID = "formal-v3-20260831t051023z-r05"
_SUPERVISOR_SENSITIVE_ENV_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
    "AUTHORIZATION",
    "PRIVATE_KEY",
)
PYTHON_SOCKET_BOUNDARY_ID = "cpython_socket_api_inet_v1"
ACCOUNTING_FAILURE_KEYS = (
    "loss_count",
    "duplicate_count",
    "unexpected_count",
    "cross_project_contamination_count",
    "failed_count",
    "running_count",
    "provenance_mismatch_count",
)
_SENSITIVE_ENV_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
    "AUTHORIZATION",
    "PRIVATE_KEY",
)


@dataclass(frozen=True)
class RuleArtifact:
    rule_id: str
    source: str
    source_path: str
    source_file_sha256: str
    source_sha256: str
    behavior_sha256: str
    program_id: str = ""
    compiler: str = ""
    compiler_snapshot: str = ""
    probe_tool_input: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ArtifactBundle:
    artifacts: tuple[RuleArtifact, ...]
    provenance: dict[str, Any]


@dataclass(frozen=True)
class MatrixConfig:
    rule_counts: tuple[int, ...] = DEFAULT_RULE_COUNTS
    project_counts: tuple[int, ...] = DEFAULT_PROJECT_COUNTS
    burst_sizes: tuple[int, ...] = DEFAULT_BURST_SIZES
    repeats: int = DEFAULT_REPEATS
    sequential_events: int = DEFAULT_SEQUENTIAL_EVENTS
    warmups_per_project: int = DEFAULT_WARMUPS_PER_PROJECT
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    drain_timeout_seconds: float = DEFAULT_DRAIN_TIMEOUT_SECONDS
    max_hook_workers: int = DEFAULT_MAX_HOOK_WORKERS
    soak_events: int = 0
    soak_rule_count: int = 8
    soak_project_count: int = 8
    soak_batch_size: int = DEFAULT_SOAK_BATCH_SIZE
    fault_repetitions: int = DEFAULT_FAULT_REPETITIONS

    def validate(self, available_rules: int = 8) -> None:
        for label, values in (
            ("rule counts", self.rule_counts),
            ("project counts", self.project_counts),
            ("burst sizes", self.burst_sizes),
        ):
            if not values or any(value < 1 for value in values):
                raise ValueError(f"{label} must contain positive integers")
            if len(set(values)) != len(values):
                raise ValueError(f"{label} must not contain duplicates")
        if max(self.rule_counts) > available_rules:
            raise ValueError(
                f"requested {max(self.rule_counts)} rules, only {available_rules} exist"
            )
        if self.repeats < 1 or self.sequential_events < 1:
            raise ValueError("repeats and sequential events must be positive")
        if self.warmups_per_project < 0:
            raise ValueError("warmups per project must be non-negative")
        if (
            self.timeout_seconds <= 0
            or self.drain_timeout_seconds <= 0
            or self.max_hook_workers < 1
        ):
            raise ValueError("timeout and max hook workers must be positive")
        if self.soak_events < 0 or self.soak_batch_size < 1:
            raise ValueError("soak events must be non-negative and batch size positive")
        if self.fault_repetitions < 1:
            raise ValueError("fault repetitions must be positive")
        if self.soak_events and (
            self.soak_rule_count not in self.rule_counts
            or self.soak_project_count not in self.project_counts
        ):
            raise ValueError(
                "soak rule/project count must be present in the configured matrix"
            )
        if self.soak_batch_size * max(self.rule_counts) >= EVALUATION_HISTORY_LIMIT:
            raise ValueError(
                "soak batch creates too many evaluations for exact history accounting"
            )


@dataclass(frozen=True)
class ExpectedEvaluation:
    case_id: str
    project_root: str
    input_sha256: str
    rule_id: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.project_root, self.input_sha256, self.rule_id)


@dataclass
class InstalledProject:
    index: int
    root: Path
    wrapper: Path
    hooks_json: Path


@dataclass
class RunningFixture:
    isolated_root: Path
    environment: dict[str, str]
    projects: list[InstalledProject]
    artifacts: tuple[RuleArtifact, ...]
    diagnostics: Path
    daemon: subprocess.Popen[Any]
    identity: dict[str, Any]
    retained: bool = False


@contextmanager
def _fixture_directory(retained_root: Path | None) -> Iterator[Path]:
    if retained_root is not None:
        root = retained_root.expanduser().resolve()
        try:
            root.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise SystemsHarnessError(
                f"retained runtime directory already exists: {root}"
            ) from exc
        yield root
        return
    with tempfile.TemporaryDirectory(prefix="rap-systems-", dir="/tmp") as temporary:
        yield Path(temporary)


FAULT_CAPABILITIES: dict[str, dict[str, Any]] = {
    "daemon_crash": {
        "feasible": os.name == "posix",
        "injection": "SIGKILL the isolated daemon before an installed-hook delivery",
        "boundary": "hook fail-open plus first post-respawn exact evaluation",
    },
    "worker_exit": {
        "feasible": True,
        "injection": "terminate the idle supervised PAW inference worker",
        "boundary": "next event to all expected query-visible evaluations",
    },
    "worker_timeout": {
        "feasible": hasattr(signal, "SIGSTOP"),
        "injection": (
            "SIGSTOP the idle PAW worker before dispatch so the production native "
            "timeout kills it"
        ),
        "boundary": "faulting evaluation outcome plus next-event recovery",
        "limitation": "does not claim a kill at a known instruction inside llama.cpp",
    },
    "sqlite_lock": {
        "feasible": True,
        "injection": (
            "hold an external SQLite EXCLUSIVE transaction beyond the production "
            "five-second busy timeout"
        ),
        "boundary": "accepted event, incident/outcome state, and next-event recovery",
    },
    "malformed_payload": {
        "feasible": True,
        "injection": "send invalid JSON and an oversized trigger field to the wrapper",
        "boundary": "hook contract and evaluation-history delta",
    },
    "duplicate_delivery": {
        "feasible": True,
        "injection": "concurrently redeliver byte-identical Codex hook payloads",
        "boundary": "daemon admission counter and exact evaluation/finding counts",
    },
    "deployment_failure": {
        "feasible": True,
        "injection": "change a working draft after prepare and then commit its stale token",
        "boundary": "commit rejection and next evaluation's active-revision hash",
        "limitation": "tests atomic stale-commit failure, not remote compiler transport",
    },
    "remote_compiler_transport_failure": {
        "feasible": False,
        "reason": (
            "the study pins already-compiled public programs; faithfully forcing a remote "
            "compiler outage requires service/network control outside the production API"
        ),
    },
}


DETERMINISTIC_RULE_ID = "systfawtprbe0001"
DETERMINISTIC_RULE_SOURCE = f'''from rules_as_programs import rule


@rule(
    id="{DETERMINISTIC_RULE_ID}",
    name="Synthetic systems fault probe",
    trigger="PreToolUse",
    max_input_bytes=1024,
)
def synthetic_systems_fault_probe(ctx):
    """Synthetic systems fault probe."""
    return ctx.result("WARNING")
'''


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _subprocess_environment(
    environment: dict[str, str], overrides: dict[str, str] | None = None
) -> dict[str, str]:
    """Remove credentials that local inference and the hook never require.

    Besides reducing ambient authority, this prevents a failed subprocess call
    from rendering unrelated API credentials in a Python traceback.
    """
    sanitized = {
        name: value
        for name, value in environment.items()
        if not any(marker in name.upper() for marker in _SENSITIVE_ENV_MARKERS)
        and name not in ("SSH_AUTH_SOCK", "GITHUB_ENV")
    }
    sanitized.update(overrides or {})
    return sanitized


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_private_directory(path: Path, *, label: str) -> os.stat_result:
    """Validate a preclaimed directory without following a symlink."""

    try:
        observed = path.lstat()
    except OSError as exc:
        raise SystemsHarnessError(f"{label} lstat failed: {path}: {exc}") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or int(observed.st_uid) != os.geteuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise SystemsHarnessError(
            f"{label} must be a non-symlink directory owned by the effective "
            "user with mode 0700"
        )
    return observed


def _open_private_directory(path: Path, *, label: str) -> tuple[int, os.stat_result]:
    """Open a directory without symlink following and bind its path identity."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SystemsHarnessError(f"{label} open failed: {path}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        observed = _validate_private_directory(path, label=label)
        if (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino):
            raise SystemsHarnessError(f"{label} changed during preclaim")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _validate_private_child(
    parent_descriptor: int, name: str, path: Path, *, label: str
) -> os.stat_result:
    """Validate a child through its anchored parent and its absolute path."""

    try:
        anchored = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise SystemsHarnessError(f"{label} lstatat failed: {path}: {exc}") from exc
    observed = _validate_private_directory(path, label=label)
    if (anchored.st_dev, anchored.st_ino) != (observed.st_dev, observed.st_ino):
        raise SystemsHarnessError(f"{label} changed during preclaim")
    return anchored


def _ensure_formal_supervisor_parent(parent: Path) -> None:
    """Race-safely create and validate Amendment 011's closeout parent."""

    scheduler_root = parent.parent
    scheduler_descriptor, _ = _open_private_directory(
        scheduler_root, label="formal scheduler root"
    )
    try:
        try:
            os.mkdir(parent.name, 0o700, dir_fd=scheduler_descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SystemsHarnessError(
                f"formal supervisor parent mkdir failed: {parent}: {exc}"
            ) from exc
        else:
            try:
                os.fsync(scheduler_descriptor)
            except OSError as exc:
                raise SystemsHarnessError(
                    f"formal scheduler root fsync failed: {scheduler_root}: {exc}"
                ) from exc
        _validate_private_child(
            scheduler_descriptor,
            parent.name,
            parent,
            label="formal supervisor parent",
        )
    finally:
        os.close(scheduler_descriptor)


def _preclaim_formal_supervisor_root(supervisor_root: Path) -> None:
    """Exclusively create the per-attempt root through an anchored parent."""

    parent = supervisor_root.parent
    _ensure_formal_supervisor_parent(parent)
    parent_descriptor, _ = _open_private_directory(
        parent, label="formal supervisor parent"
    )
    try:
        try:
            os.mkdir(supervisor_root.name, 0o700, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        except OSError as exc:
            raise SystemsHarnessError(
                f"formal supervisor root exclusive preclaim failed: {supervisor_root}: {exc}"
            ) from exc
        _validate_private_child(
            parent_descriptor,
            supervisor_root.name,
            supervisor_root,
            label="formal supervisor root",
        )
    finally:
        os.close(parent_descriptor)


def _formal_attempt_root(retained_runtime_root: Path) -> Path:
    resolved = retained_runtime_root.expanduser().resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / "launch.json").is_file():
            try:
                resolved.relative_to(candidate / "runtime")
            except ValueError:
                continue
            return candidate
    raise SystemsHarnessError(
        "socket endpoint mapping requires a retained runtime root beneath an "
        "immutable attempt containing launch.json"
    )


def _socket_unit_identity(
    retained_runtime_root: Path,
    *,
    component: str | None,
    unit_id: str | None,
) -> tuple[Path, str, str]:
    attempt_root = _formal_attempt_root(retained_runtime_root)
    relative = (
        retained_runtime_root.expanduser()
        .resolve()
        .relative_to(attempt_root / "runtime")
    )
    parts = relative.parts
    derived_component = ""
    derived_unit_id = ""
    if len(parts) == 2 and parts[0] in ("matrix", "faults"):
        derived_component, derived_unit_id = parts
    elif parts == ("offline",):
        derived_component = "offline"
        derived_unit_id = "online-offline-exact-replay"
    elif parts == ("soak",):
        derived_component = "soak"
    else:
        raise SystemsHarnessError(
            f"unrecognized formal retained runtime layout for socket mapping: {relative}"
        )
    observed_component = component or derived_component
    observed_unit_id = unit_id or derived_unit_id
    if observed_component != derived_component or not observed_unit_id:
        raise SystemsHarnessError(
            "socket endpoint component/unit identity does not match its retained "
            "runtime layout"
        )
    if derived_unit_id and observed_unit_id != derived_unit_id:
        raise SystemsHarnessError(
            "socket endpoint unit identity does not match its retained runtime layout"
        )
    return attempt_root, observed_component, observed_unit_id


def _validated_socket_root(
    environment: Mapping[str, str],
) -> tuple[Path, os.stat_result]:
    configured = str(environment.get("RAP_EACL_SOCKET_ROOT", ""))
    job_id = str(environment.get("SLURM_JOB_ID", ""))
    expected = f"/tmp/rf3-{job_id}"
    if not job_id.isdecimal() or configured != expected:
        raise SystemsHarnessError(
            "RAP_EACL_SOCKET_ROOT must be the exact /tmp/rf3-${SLURM_JOB_ID} path"
        )
    root = Path(configured)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise SystemsHarnessError(f"socket root is unavailable: {root}: {exc}") from exc
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(root_stat.st_mode)
        or int(root_stat.st_uid) != os.geteuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise SystemsHarnessError(
            "socket root must be a non-symlink directory owned by the effective "
            "user with mode 0700"
        )
    return root, root_stat


def _require_socket_endpoint_available(
    environment: Mapping[str, str], *, stage: str
) -> None:
    endpoint = str(environment.get("RAP_SOCKET_PATH", ""))
    if endpoint and os.path.lexists(endpoint):
        raise SystemsHarnessError(
            f"socket endpoint collision before {stage}: {endpoint}"
        )


def _socket_entry_receipt(path: Path) -> dict[str, Any] | None:
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return None
    entry_type = (
        "socket"
        if stat.S_ISSOCK(observed.st_mode)
        else "symlink"
        if stat.S_ISLNK(observed.st_mode)
        else "regular_file"
        if stat.S_ISREG(observed.st_mode)
        else "directory"
        if stat.S_ISDIR(observed.st_mode)
        else "other"
    )
    return {
        "path": str(path),
        "type": entry_type,
        "owner_uid": int(observed.st_uid),
        "mode": stat.S_IMODE(observed.st_mode),
        "device": int(observed.st_dev),
        "inode": int(observed.st_ino),
    }


def _enforce_socket_removed_after_shutdown(
    environment: Mapping[str, str],
    retained_runtime_root: Path,
    *,
    stage: str,
    active_exception: BaseException | None = None,
    timeout_seconds: float | None = None,
) -> None:
    """Fail closed on a socket left after a verified daemon shutdown.

    If workload unwinding is already carrying an exception, preserve it and
    retain this independent cleanup defect rather than masking the first cause.
    """
    endpoint_text = str(environment.get("RAP_SOCKET_PATH", ""))
    if not endpoint_text:
        return
    endpoint = Path(endpoint_text)
    timeout_seconds = (
        SOCKET_CLEANUP_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    )
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while os.path.lexists(endpoint) and time.monotonic() < deadline:
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    observed = _socket_entry_receipt(endpoint)
    if observed is None:
        return
    cleanup_error = SystemsHarnessError(
        f"socket endpoint remained after verified {stage}: {endpoint}"
    )
    safe_stage = re.sub(r"[^a-z0-9.-]+", "-", stage.lower()).strip("-.")
    failure_path = (
        retained_runtime_root.expanduser().resolve()
        / f"socket-cleanup-failure-{safe_stage or 'shutdown'}.json"
    )
    failure = {
        "schema_version": 1,
        "status": "socket_endpoint_persisted_after_verified_shutdown",
        "stage": stage,
        "endpoint": observed,
        "active_exception": (
            {
                "present": True,
                "type": type(active_exception).__name__,
            }
            if active_exception is not None
            else {"present": False, "type": None}
        ),
    }
    try:
        _write_immutable_evidence(
            failure_path,
            json.dumps(
                failure,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            + b"\n",
        )
        _fsync_directory(failure_path.parent)
    except BaseException as receipt_error:
        if active_exception is None:
            raise SystemsHarnessError(
                f"{cleanup_error}; cleanup failure receipt could not be retained: "
                f"{type(receipt_error).__name__}: {receipt_error}"
            ) from cleanup_error
        return
    if active_exception is None:
        raise cleanup_error


@contextmanager
def _unit_socket_environment(
    retained_runtime_root: Path,
    environment: Mapping[str, str],
    *,
    component: str | None = None,
    unit_id: str | None = None,
) -> Iterator[dict[str, str]]:
    """Bind one formal top-level unit to its short node-local AF_UNIX path."""
    configured_root = str(environment.get("RAP_EACL_SOCKET_ROOT", ""))
    if not configured_root:
        yield dict(environment)
        return
    retained = retained_runtime_root.expanduser().resolve()
    attempt_root, component, unit_id = _socket_unit_identity(
        retained, component=component, unit_id=unit_id
    )
    socket_root, root_stat = _validated_socket_root(environment)
    state = Path(str(environment.get("RAP_STATE_DIR", ""))).expanduser().resolve()
    expected_state = (retained / "state").resolve()
    if state != expected_state:
        raise SystemsHarnessError(
            "node-local socket override must not move durable RAP_STATE_DIR away "
            "from the retained runtime root"
        )
    digest_input = {
        "schema_version": 1,
        "raw_attempt_id": attempt_root.name,
        "component": component,
        "unit_id": unit_id,
        "retained_runtime_root": str(retained),
    }
    digest = _sha256_bytes(
        json.dumps(
            digest_input,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )
    endpoint = socket_root / f"{digest}.sock"
    encoded_length = len(os.fsencode(endpoint))
    if encoded_length > MAX_AF_UNIX_PATHNAME_BYTES:
        raise SystemsHarnessError(
            f"node-local socket endpoint is {encoded_length} encoded bytes; "
            f"maximum is {MAX_AF_UNIX_PATHNAME_BYTES}"
        )
    socket_environment = dict(environment)
    socket_environment["RAP_SOCKET_PATH"] = str(endpoint)
    _require_socket_endpoint_available(
        socket_environment, stage="per-unit daemon start"
    )
    receipt = {
        "schema_version": 1,
        "digest_input": digest_input,
        "endpoint_digest": digest,
        "endpoint": str(endpoint),
        "encoded_pathname_bytes": encoded_length,
        "maximum_encoded_pathname_bytes": MAX_AF_UNIX_PATHNAME_BYTES,
        "socket_root": {
            "path": str(socket_root),
            "owner_uid": int(root_stat.st_uid),
            "mode": stat.S_IMODE(root_stat.st_mode),
            "device": int(root_stat.st_dev),
        },
        "rap_state_dir": str(state),
        "component": component,
        "unit_id": unit_id,
        "raw_attempt_id": attempt_root.name,
        "slurm": {
            "job_id": str(environment.get("SLURM_JOB_ID", "")),
            "partition": str(environment.get("SLURM_JOB_PARTITION", "")),
            "node_list": str(environment.get("SLURM_JOB_NODELIST", "")),
        },
    }
    receipt_path = retained / "socket-endpoint.json"
    receipt_bytes = (
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        + b"\n"
    )
    try:
        _write_immutable_evidence(receipt_path, receipt_bytes)
    except FileExistsError as exc:
        raise SystemsHarnessError(
            f"socket endpoint receipt collision for {component}/{unit_id}: "
            f"{receipt_path}"
        ) from exc
    _fsync_directory(receipt_path.parent)
    previous = os.environ.get("RAP_SOCKET_PATH")
    os.environ["RAP_SOCKET_PATH"] = str(endpoint)
    try:
        yield socket_environment
    finally:
        if previous is None:
            os.environ.pop("RAP_SOCKET_PATH", None)
        else:
            os.environ["RAP_SOCKET_PATH"] = previous


def _jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemsHarnessError(
            f"could not read validated JSONL {path}: {exc}"
        ) from exc


def _normalized_managed_source(rule_id: str, source: str) -> str:
    """Return the exact source form persisted by ``rules_api.save_rule``."""
    projection = rules_api.source_projection(source)
    if not projection.get("ok"):
        raise SystemsHarnessError(
            f"could not project rule source {rule_id}: {projection.get('error')}"
        )
    name = str(projection.get("name") or projection.get("title") or "Rule")
    ok, normalized, error = rules_api.patch_rule_identity(source, rule_id, name)
    if not ok:
        raise SystemsHarnessError(f"could not normalize {rule_id}: {error}")
    return normalized if normalized.endswith("\n") else normalized + "\n"


def load_external_artifacts() -> ArtifactBundle:
    """Load and cross-check the eight frozen external finetuned programs."""
    try:
        manifest = json.loads(EXTERNAL_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemsHarnessError(f"invalid external PAW manifest: {exc}") from exc
    if _sha256_file(EXTERNAL_DATASET) != str(manifest.get("dataset_sha256", "")):
        raise SystemsHarnessError("external dataset hash does not match its manifest")
    if _sha256_file(EXTERNAL_OUTPUT) != str(manifest.get("output_sha256", "")):
        raise SystemsHarnessError(
            "external PAW output hash does not match its manifest"
        )
    dataset_value = str(manifest.get("dataset", ""))
    if (REPO_ROOT / dataset_value).resolve() != EXTERNAL_DATASET.resolve():
        raise SystemsHarnessError("external manifest points at an unexpected dataset")

    compiler = str(manifest.get("compiler", ""))
    program_ids = dict(manifest.get("program_ids") or {})
    compiler_info = dict(manifest.get("compiler_info") or {})
    if set(program_ids) != set(EXTERNAL_RULE_ORDER):
        raise SystemsHarnessError(
            "external manifest rule set is not the fixed eight-rule set"
        )
    dataset = _jsonl(EXTERNAL_DATASET)
    output = _jsonl(EXTERNAL_OUTPUT)
    artifacts = []
    for rule_id in EXTERNAL_RULE_ORDER:
        source_path = ROOT / "rules" / rule_id / "rule.py"
        compiled_source = source_path.read_text(encoding="utf-8")
        source = _normalized_managed_source(rule_id, compiled_source)
        source_file_hash = _sha256_file(source_path)
        source_hashes = {
            str(row.get("source_hash", ""))
            for row in dataset
            if str(row.get("rule_id", "")) == rule_id
        }
        output_programs = {
            str(row.get("program_id", ""))
            for row in output
            if str(row.get("rule_id", "")) == rule_id
        }
        output_sources = {
            str(row.get("source_hash", ""))
            for row in output
            if str(row.get("rule_id", "")) == rule_id
        }
        program_id = str(program_ids.get(rule_id, ""))
        if source_hashes != {source_file_hash} or output_sources != source_hashes:
            raise SystemsHarnessError(f"source provenance mismatch for {rule_id}")
        if output_programs != {program_id} or not program_id:
            raise SystemsHarnessError(f"program provenance mismatch for {rule_id}")
        if revisions.behavior_hash(compiled_source) != revisions.behavior_hash(source):
            raise SystemsHarnessError(
                f"managed source normalization changed behavior for {rule_id}"
            )
        info = dict(compiler_info.get(rule_id) or {})
        snapshot = str(info.get("latest_snapshot", ""))
        if not compiler or not snapshot:
            raise SystemsHarnessError(f"compiler provenance missing for {rule_id}")
        representative = next(
            (
                dict(row)
                for row in dataset
                if str(row.get("rule_id", "")) == rule_id
                and str(row.get("expected", "")) == "WARNING"
            ),
            None,
        )
        if representative is None:
            raise SystemsHarnessError(f"no positive probe input for {rule_id}")
        try:
            tool_input = json.loads(str(representative["input"]))
        except (KeyError, json.JSONDecodeError) as exc:
            raise SystemsHarnessError(f"invalid probe input for {rule_id}") from exc
        if not isinstance(tool_input, dict):
            raise SystemsHarnessError(f"probe input for {rule_id} is not an object")
        artifacts.append(
            RuleArtifact(
                rule_id=rule_id,
                source=source,
                source_path=str(source_path.relative_to(REPO_ROOT)),
                source_file_sha256=source_file_hash,
                source_sha256=revisions.hash_source(source),
                behavior_sha256=revisions.behavior_hash(source),
                program_id=program_id,
                compiler=compiler,
                compiler_snapshot=snapshot,
                probe_tool_input=tool_input,
            )
        )
    return ArtifactBundle(
        artifacts=tuple(artifacts),
        provenance={
            "manifest": {
                "path": str(EXTERNAL_MANIFEST.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(EXTERNAL_MANIFEST),
            },
            "dataset": {
                "path": str(EXTERNAL_DATASET.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(EXTERNAL_DATASET),
            },
            "output": {
                "path": str(EXTERNAL_OUTPUT.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(EXTERNAL_OUTPUT),
            },
            "rule_order": list(EXTERNAL_RULE_ORDER),
        },
    )


def deterministic_artifact() -> RuleArtifact:
    source = _normalized_managed_source(
        DETERMINISTIC_RULE_ID, DETERMINISTIC_RULE_SOURCE
    )
    return RuleArtifact(
        rule_id=DETERMINISTIC_RULE_ID,
        source=source,
        source_path="<generated deterministic fault fixture>",
        source_file_sha256=_sha256_bytes(DETERMINISTIC_RULE_SOURCE.encode("utf-8")),
        source_sha256=revisions.hash_source(source),
        behavior_sha256=revisions.behavior_hash(source),
        probe_tool_input={"command": "synthetic fault probe"},
    )


def parse_int_tuple(value: str, *, allowed: set[int] | None = None) -> tuple[int, ...]:
    try:
        parsed = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from exc
    if not parsed or any(item < 1 for item in parsed):
        raise argparse.ArgumentTypeError("expected one or more positive integers")
    if len(set(parsed)) != len(parsed):
        raise argparse.ArgumentTypeError("values must not be repeated")
    if allowed is not None and not set(parsed).issubset(allowed):
        raise argparse.ArgumentTypeError(
            f"values must be selected from {','.join(str(item) for item in sorted(allowed))}"
        )
    return parsed


def build_matrix_plan(config: MatrixConfig) -> list[dict[str, Any]]:
    config.validate()
    plan = []
    for rule_count in config.rule_counts:
        for project_count in config.project_counts:
            for repeat in range(config.repeats):
                workloads = [
                    ("sequential", config.sequential_events),
                    *(("burst", size) for size in config.burst_sizes),
                ]
                for traffic in TRAFFIC_PATTERNS:
                    for mode, events in workloads:
                        plan.append(
                            {
                                "condition_id": (
                                    f"r{rule_count}-p{project_count}-{traffic}-"
                                    f"{mode}{events}-rep{repeat}"
                                ),
                                "rule_count": rule_count,
                                "project_count": project_count,
                                "mode": mode,
                                "events": events,
                                "repeat": repeat,
                                "fresh_daemon": True,
                                "fresh_state": True,
                                "schedule": traffic,
                            }
                        )
    return plan


def build_study_plan(
    config: MatrixConfig,
    *,
    fault_names: Sequence[str],
    run_offline_probe: bool,
) -> list[dict[str, Any]]:
    """Return every independently terminal top-level unit in execution order."""
    units = [
        {"component": "matrix", "unit_id": item["condition_id"], **item}
        for item in build_matrix_plan(config)
    ]
    if config.soak_events:
        soak_id = f"soak-r{config.soak_rule_count}-p{config.soak_project_count}"
        units.append(
            {
                "component": "soak",
                "unit_id": soak_id,
                "events": config.soak_events,
                "rule_count": config.soak_rule_count,
                "project_count": config.soak_project_count,
            }
        )
    if run_offline_probe:
        units.append(
            {
                "component": "offline",
                "unit_id": "online-offline-exact-replay",
                "rules": max(config.rule_counts),
            }
        )
    for name in fault_names:
        for repetition in range(config.fault_repetitions):
            units.append(
                {
                    "component": "faults",
                    "unit_id": f"{name}-rep{repetition}",
                    "fault": name,
                    "repetition": repetition,
                }
            )
    return units


def build_full_attempt_plan(config: MatrixConfig) -> dict[str, Any]:
    """Build amendment-008's unchanged 430-row r03 plan and role partition.

    Every primary row is sourced from r03.  The role labels describe why each
    r03 execution occurs; they never select a value from r02 and never inspect
    an observed r03 outcome.
    """

    full_plan = build_study_plan(
        config,
        fault_names=FORMAL_FAULTS,
        run_offline_probe=True,
    )
    plan_keys = [
        {
            "plan_index": index,
            "component": str(item["component"]),
            "unit_id": str(item["unit_id"]),
        }
        for index, item in enumerate(full_plan)
    ]
    return {
        "full_plan": full_plan,
        "unit_count": len(full_plan),
        "canonical_sha256": _sha256_bytes(_canonical_json_bytes(full_plan)),
        "ordered_membership_sha256": _sha256_bytes(_canonical_json_bytes(plan_keys)),
        "primary_source_attempt_id": FORMAL_RAW_ATTEMPT_ID,
        "execution_roles": {
            "provenance_rerun": {"start": 0, "stop": 279, "count": 279},
            "direct_first_completion": {"start": 279, "stop": 350, "count": 71},
            "deterministic_first_execution": {
                "start": 350,
                "stop": 430,
                "count": 80,
            },
        },
    }


def _raw_event(
    project: Path,
    *,
    project_index: int,
    sequence: int,
    condition_id: str,
    tool_input: dict[str, Any],
) -> dict[str, Any]:
    case_id = f"{condition_id}-p{project_index}-e{sequence}"
    marked_input = dict(tool_input)
    marked_input["_rap_systems_probe"] = {
        "case_id": case_id,
        "project_index": project_index,
    }
    return {
        "session_id": f"systems-session-{case_id}",
        "turn_id": f"systems-turn-{case_id}",
        "hook_event_name": "PreToolUse",
        "cwd": str(project),
        "tool_name": "Bash",
        "tool_use_id": f"systems-tool-{case_id}",
        "tool_input": marked_input,
    }


def _expected_input(raw: dict[str, Any]) -> str:
    events = normalize(raw)
    if len(events) != 1:
        raise SystemsHarnessError(
            f"expected one normalized event, observed {len(events)}"
        )
    text, _pointer, _kind, _overridden = extract_input(
        "PreToolUse", events[0].raw_payload, ""
    )
    return text


def _envelope_projection(raw: dict[str, Any]) -> dict[str, Any]:
    """Retain replay identity without conflating it with the declared input bytes."""
    return {
        key: raw.get(key)
        for key in (
            "session_id",
            "turn_id",
            "tool_use_id",
            "hook_event_name",
            "tool_name",
            "cwd",
        )
    }


def _install_projects(
    isolated_root: Path,
    artifacts: Sequence[RuleArtifact],
    project_count: int,
) -> list[InstalledProject]:
    projects = []
    for project_index in range(project_count):
        project = (isolated_root / f"project-{project_index}").resolve()
        project.mkdir(parents=True)
        for artifact in artifacts:
            try:
                saved = rules_api.save_rule(
                    artifact.rule_id, artifact.source, "project", str(project)
                )
            except Exception as exc:
                raise SystemViolationError(
                    f"production rule save failed for {artifact.rule_id} in "
                    f"{project}: {type(exc).__name__}: {exc}"
                ) from None
            if not saved.get("ok"):
                raise SystemViolationError(
                    f"could not install {artifact.rule_id} in {project}: "
                    f"{saved.get('error', 'unknown error')}"
                )
            saved_source = str(saved["source"])
            if revisions.hash_source(saved_source) != artifact.source_sha256:
                raise SystemViolationError(
                    f"installed source hash changed for {artifact.rule_id}"
                )
            try:
                revisions.activate(
                    artifact.rule_id,
                    str(saved["path"]),
                    saved_source,
                    compiler=artifact.compiler or None,
                    program_id=artifact.program_id or None,
                    compiler_snapshot=artifact.compiler_snapshot or None,
                    compiler_mode=(
                        revisions.EXPLICIT_COMPILER_MODE if artifact.compiler else None
                    ),
                )
            except Exception as exc:
                raise SystemViolationError(
                    f"production rule activation failed for {artifact.rule_id} in "
                    f"{project}: {type(exc).__name__}: {exc}"
                ) from None
        try:
            CodexAdapter().install("project", str(project))
        except Exception as exc:
            raise SystemViolationError(
                f"production Codex adapter install failed for {project}: "
                f"{type(exc).__name__}: {exc}"
            ) from None
        wrapper = project / ".codex" / "hooks" / "rap-hook.sh"
        hooks_json = project / ".codex" / "hooks.json"
        if not wrapper.is_file() or not os.access(wrapper, os.X_OK):
            raise SystemViolationError(f"installed wrapper missing for {project}")
        if "rap-hook.sh" not in hooks_json.read_text(encoding="utf-8"):
            raise SystemViolationError(
                f"hooks.json does not register RAP for {project}"
            )
        projects.append(InstalledProject(project_index, project, wrapper, hooks_json))
    return projects


@contextmanager
def _running_fixture(
    artifacts: Sequence[RuleArtifact],
    project_count: int,
    *,
    environment_overrides: dict[str, str] | None = None,
    retained_root: Path | None = None,
    component: str | None = None,
    unit_id: str | None = None,
) -> Iterator[RunningFixture]:
    with _fixture_directory(retained_root) as isolated_root:
        with integrated._isolated_environment(isolated_root) as base_environment:
            initial_environment = _subprocess_environment(
                base_environment, environment_overrides
            )
            with _unit_socket_environment(
                isolated_root,
                initial_environment,
                component=component,
                unit_id=unit_id,
            ) as environment:
                projects = _install_projects(isolated_root, artifacts, project_count)
                diagnostics = isolated_root / "daemon-output.log"
                try:
                    daemon, identity = integrated._start_daemon(
                        environment, diagnostics, DEFAULT_TIMEOUT_SECONDS
                    )
                except Exception as exc:
                    raise SystemViolationError(str(exc)) from None
                fixture = RunningFixture(
                    isolated_root=isolated_root,
                    environment=environment,
                    projects=projects,
                    artifacts=tuple(artifacts),
                    diagnostics=diagnostics,
                    daemon=daemon,
                    identity=identity,
                    retained=retained_root is not None,
                )
                try:
                    yield fixture
                finally:
                    active_exception = sys.exc_info()[1]
                    # This also shuts down an auto-respawned daemon because the
                    # parent process still points at this unit's isolated socket.
                    try:
                        ipc.send_request({"type": "shutdown"}, timeout=1.0)
                    except Exception:
                        pass
                    integrated._stop_daemon(fixture.daemon)
                    _enforce_socket_removed_after_shutdown(
                        fixture.environment,
                        fixture.isolated_root,
                        stage="final-daemon-shutdown",
                        active_exception=active_exception,
                    )


def _invoke_payload(
    wrapper: Path,
    cwd: Path,
    payload: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    started_ns = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            [str(wrapper)],
            cwd=cwd,
            env=environment,
            input=payload,
            text=True,
            capture_output=True,
            timeout=integrated.HOOK_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        exited_ns = time.perf_counter_ns()
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return {
            "started_ns": started_ns,
            "exited_ns": exited_ns,
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
            "contract_preserved": False,
            "contract_error": "installed hook process timed out",
        }
    exited_ns = time.perf_counter_ns()
    result = {
        "started_ns": started_ns,
        "exited_ns": exited_ns,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "timed_out": False,
    }
    try:
        integrated._assert_hook_contract(result, "systems harness hook")
    except integrated.IntegratedExperimentError as exc:
        result["contract_preserved"] = False
        result["contract_error"] = str(exc)
    else:
        result["contract_preserved"] = True
        result["contract_error"] = ""
    return result


def _invoke_raw(
    wrapper: Path,
    raw: dict[str, Any],
    environment: dict[str, str],
) -> dict[str, Any]:
    return _invoke_payload(wrapper, Path(str(raw["cwd"])), json.dumps(raw), environment)


def _evaluation_history(
    project: Path, *, limit: int = EVALUATION_HISTORY_LIMIT
) -> list[dict[str, Any]]:
    response = ipc.send_request(
        {
            "type": "evaluation_history",
            "project_root": str(project),
            "limit": min(EVALUATION_HISTORY_LIMIT, max(1, limit)),
        },
        timeout=1.0,
    )
    if not response or not response.get("ok"):
        return []
    return list(response.get("evaluations") or [])


def _timed_evaluation_history(
    project: Path, *, limit: int = EVALUATION_HISTORY_LIMIT
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    started_ns = time.perf_counter_ns()
    rows = _evaluation_history(project, limit=limit)
    finished_ns = time.perf_counter_ns()
    return rows, {
        "project_root": str(project),
        "started_monotonic_ns": started_ns,
        "finished_monotonic_ns": finished_ns,
        "latency_ns": finished_ns - started_ns,
        "latency_ms": round((finished_ns - started_ns) / 1_000_000, 3),
        "rows": len(rows),
    }


def _full_evaluation_history(project: Path) -> list[dict[str, Any]]:
    """Read every retained evaluation outcome, bypassing the 5,000-row UI cap."""
    base = rap_config.project_evaluation_log_file(str(project))
    paths = [
        base.with_name(f"{base.name}.{index}")
        for index in range(5, 0, -1)
        if base.with_name(f"{base.name}.{index}").exists()
    ]
    if base.exists():
        paths.append(base)
    records: list[dict[str, Any]] = []
    try:
        for path in paths:
            records.extend(_jsonl(path))
    except SystemsHarnessError as exc:
        raise SystemViolationError(
            f"production evaluation journal could not be read: {exc}"
        ) from None
    outcomes: dict[str, dict[str, Any]] = {}
    started: list[dict[str, Any]] = []
    for record in records:
        evaluation_id = str(record.get("evaluation_id", ""))
        if not evaluation_id:
            continue
        if record.get("type") in ("evaluation_completed", "evaluation_failed"):
            outcomes[evaluation_id] = record
        elif record.get("type") == "evaluation_started":
            started.append(record)
    rows = []
    for record in started:
        evaluation_id = str(record["evaluation_id"])
        outcome = outcomes.get(evaluation_id)
        status = (
            "failed"
            if outcome and outcome.get("type") == "evaluation_failed"
            else "completed"
            if outcome
            else "running"
        )
        rows.append(
            {
                **record,
                "status": status,
                "outcome": outcome or {},
                "result": str((outcome or {}).get("result", "")),
                "duration_ms": (outcome or {}).get("duration_ms"),
                "finding_id": (outcome or {}).get("finding_id"),
            }
        )
    return rows


def _full_findings(project: Path) -> list[dict[str, Any]]:
    path = rap_config.project_log_file(str(project))
    try:
        return _jsonl(path) if path.exists() else []
    except SystemsHarnessError as exc:
        raise SystemViolationError(
            f"production finding journal could not be read: {exc}"
        ) from None


def _evaluation_journal_paths(project: Path) -> list[Path]:
    base = rap_config.project_evaluation_log_file(str(project))
    return [
        *[
            base.with_name(f"{base.name}.{index}")
            for index in range(EVALUATION_JOURNAL_ROTATION_BACKUPS, 0, -1)
            if base.with_name(f"{base.name}.{index}").exists()
        ],
        *([base] if base.exists() else []),
    ]


class _IncrementalJsonlWriter:
    def __init__(self, path: Path, *, fsync_every: int = 60):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.handle = path.open("x", encoding="utf-8")
        self.fsync_every = max(1, fsync_every)
        self.count = 0

    def append(self, value: dict[str, Any]) -> None:
        self.handle.write(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.handle.flush()
        self.count += 1
        if self.count % self.fsync_every == 0:
            os.fsync(self.handle.fileno())

    def close(self) -> None:
        if self.handle.closed:
            return
        self.handle.flush()
        os.fsync(self.handle.fileno())
        self.handle.close()

    def receipt(self) -> dict[str, Any]:
        if not self.handle.closed:
            raise SystemsHarnessError(
                "incremental JSONL receipt requested before close"
            )
        receipt = {
            "path": str(self.path),
            "records": self.count,
            "bytes": self.path.stat().st_size,
            "sha256": _sha256_file(self.path),
        }
        # Formal artifacts must remain analyzable after the raw-attempt directory
        # is copied, renamed, or extracted elsewhere.  Preserve the original path
        # as provenance, but make the attempt-relative path authoritative.
        for parent in self.path.parents:
            if (parent / "launch.json").is_file():
                receipt["attempt_relative_path"] = str(self.path.relative_to(parent))
                break
        return receipt

    def __enter__(self) -> "_IncrementalJsonlWriter":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _write_immutable_evidence(path: Path, value: bytes) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    receipt: dict[str, Any] = {
        "path": str(path),
        "bytes": len(value),
        "sha256": _sha256_bytes(value),
    }
    for parent in path.parents:
        if (parent / "launch.json").is_file():
            receipt["attempt_relative_path"] = str(path.relative_to(parent))
            break
    return receipt


class _EvaluationJournalTailer:
    """Rotation-safe incremental terminal-key reader for long soak progress."""

    def __init__(self, projects: Sequence[InstalledProject], journal_path: Path):
        self.projects = tuple(projects)
        self.handles: dict[tuple[int, int], Any] = {}
        self.project_by_inode: dict[tuple[int, int], str] = {}
        self.positions: dict[tuple[int, int], int] = {}
        self.buffers: dict[tuple[int, int], bytes] = {}
        self.started: dict[str, tuple[str, str, str]] = {}
        self.outcomes_before_start: set[str] = set()
        self.terminal_keys: set[tuple[str, str, str]] = set()
        self.writer = _IncrementalJsonlWriter(journal_path)
        for project in self.projects:
            for path in _evaluation_journal_paths(project.root):
                self._discover(path, str(project.root), start_at_end=True)

    def _discover(
        self, path: Path, project_root: str, *, start_at_end: bool = False
    ) -> None:
        """Open first, then identify the inode from that exact descriptor.

        Keeping descriptors open also lets a later poll finish reading a rotated
        inode after its directory entry has been renamed or unlinked.
        """
        try:
            handle = path.open("rb")
        except FileNotFoundError:
            return
        try:
            stat = os.fstat(handle.fileno())
            inode = (int(stat.st_dev), int(stat.st_ino))
            if inode in self.handles:
                handle.close()
                return
            self.handles[inode] = handle
            self.project_by_inode[inode] = project_root
            self.positions[inode] = int(stat.st_size) if start_at_end else 0
        except BaseException:
            handle.close()
            raise

    def _consume(self, project_root: str, record: dict[str, Any]) -> int:
        evaluation_id = str(record.get("evaluation_id", ""))
        if not evaluation_id:
            return 0
        record_type = str(record.get("type", ""))
        if record_type == "evaluation_started":
            key = (
                project_root,
                _input_hash_from_row(record),
                str((record.get("rule") or {}).get("id", "")),
            )
            self.started[evaluation_id] = key
            if evaluation_id in self.outcomes_before_start:
                self.outcomes_before_start.remove(evaluation_id)
                self.started.pop(evaluation_id, None)
                before = len(self.terminal_keys)
                self.terminal_keys.add(key)
                return len(self.terminal_keys) - before
            return 0
        if record_type not in ("evaluation_completed", "evaluation_failed"):
            return 0
        key = self.started.pop(evaluation_id, None)
        if key is None:
            self.outcomes_before_start.add(evaluation_id)
            return 0
        before = len(self.terminal_keys)
        self.terminal_keys.add(key)
        return len(self.terminal_keys) - before

    def poll(self) -> dict[str, Any]:
        new_terminal = 0
        bytes_read = 0
        records_read = 0
        for project in self.projects:
            for path in _evaluation_journal_paths(project.root):
                self._discover(path, str(project.root))
        for inode, handle in list(self.handles.items()):
            project_root = self.project_by_inode[inode]
            try:
                stat = os.fstat(handle.fileno())
                offset = self.positions.get(inode, 0)
                if int(stat.st_size) < offset:
                    raise SystemViolationError(
                        "evaluation journal inode truncated during soak: "
                        f"device={inode[0]} inode={inode[1]}"
                    )
                handle.seek(offset)
                data = handle.read()
                self.positions[inode] = offset + len(data)
                bytes_read += len(data)
                if not data:
                    continue
                pieces = (self.buffers.get(inode, b"") + data).split(b"\n")
                self.buffers[inode] = pieces.pop()
                for raw in pieces:
                    if not raw:
                        continue
                    try:
                        record = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise SystemViolationError(
                            "malformed incremental evaluation journal "
                            f"inode={inode[1]}: {exc}"
                        ) from None
                    if not isinstance(record, dict):
                        raise SystemViolationError(
                            "non-object incremental evaluation record in "
                            f"inode={inode[1]}"
                        )
                    records_read += 1
                    new_terminal += self._consume(project_root, record)
            except OSError as exc:
                raise SystemViolationError(
                    f"could not tail evaluation journal inode={inode[1]}: {exc}"
                ) from None
        observed_ns = time.perf_counter_ns()
        progress = {
            "observed_monotonic_ns": observed_ns,
            "bytes_read": bytes_read,
            "records_read": records_read,
            "new_terminal_keys": new_terminal,
            "terminal_keys_total": len(self.terminal_keys),
            "inflight_evaluations": len(self.started),
            "outcomes_without_observed_start": len(self.outcomes_before_start),
        }
        self.writer.append(progress)
        return progress

    def close(self) -> None:
        try:
            self.writer.close()
        finally:
            for handle in self.handles.values():
                handle.close()
            self.handles.clear()

    def receipt(self) -> dict[str, Any]:
        return self.writer.receipt()

    def named_inode_reachability(self) -> dict[str, Any]:
        named: set[tuple[int, int]] = set()
        paths: list[str] = []
        for project in self.projects:
            for path in _evaluation_journal_paths(project.root):
                try:
                    with path.open("rb") as handle:
                        stat = os.fstat(handle.fileno())
                except FileNotFoundError:
                    continue
                named.add((int(stat.st_dev), int(stat.st_ino)))
                paths.append(str(path))
        held = set(self.handles)
        unreachable = sorted(held - named)
        return {
            "all_discovered_inodes_still_named": not unreachable,
            "held_inode_count": len(held),
            "named_inode_count": len(named),
            "unreachable_inodes": [
                {"device": device, "inode": inode} for device, inode in unreachable
            ],
            "named_paths": sorted(paths),
            "rotation_backups": EVALUATION_JOURNAL_ROTATION_BACKUPS,
        }

    def __enter__(self) -> "_EvaluationJournalTailer":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _evaluation_projection(row: dict[str, Any]) -> dict[str, Any]:
    rule = dict(row.get("rule") or {})
    outcome = dict(row.get("outcome") or {})
    return {
        "evaluation_id": str(row.get("evaluation_id", "")),
        "timestamp": row.get("timestamp"),
        "project_root": str(row.get("project_root", "")),
        "status": str(row.get("status", "")),
        "input_sha256": _input_hash_from_row(row),
        "rule": {
            key: str(rule.get(key, ""))
            for key in (
                "id",
                "source_hash",
                "behavior_hash",
                "compiler",
                "compiler_snapshot",
                "program_id",
            )
        },
        "result": str(row.get("result", "")),
        "outcome": {
            key: outcome.get(key)
            for key in (
                "type",
                "timestamp",
                "duration_ms",
                "result",
                "finding_id",
                "suppressed",
                "deduplicated",
                "error_code",
                "error",
            )
            if key in outcome
        },
    }


def _finding_projection(project: Path, finding: dict[str, Any]) -> dict[str, Any]:
    evaluation = dict(finding.get("evaluation") or {})
    return {
        "finding_id": finding.get("finding_id", finding.get("id")),
        "timestamp": finding.get("ts"),
        "project_root": str(project),
        "rule_id": str(finding.get("rule_id", "")),
        "severity": str(finding.get("severity", "")),
        "evaluation_id": str(evaluation.get("evaluation_id", "")),
        "input_sha256": str((evaluation.get("input") or {}).get("sha256", "")),
    }


def _canonical_projection_order(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Make persistence bytes invariant to database/query row ordering."""
    return sorted(
        (dict(row) for row in rows),
        key=lambda row: _canonical_json_bytes(row),
    )


def _input_hash_from_row(row: dict[str, Any]) -> str:
    value = str((row.get("input") or {}).get("sha256", ""))
    if value:
        return value
    text = (row.get("input") or {}).get("text")
    return _sha256_bytes(str(text).encode("utf-8")) if text is not None else ""


def _row_key(row: dict[str, Any], log_project: Path) -> tuple[str, str, str]:
    return (
        str(log_project),
        _input_hash_from_row(row),
        str((row.get("rule") or {}).get("id", "")),
    )


def _key_json(key: tuple[str, str, str]) -> dict[str, str]:
    return {"project_root": key[0], "input_sha256": key[1], "rule_id": key[2]}


def account_evaluations(
    rows_by_project: dict[str, list[dict[str, Any]]],
    expected: Sequence[ExpectedEvaluation],
    artifacts: Sequence[RuleArtifact],
    *,
    started_wall_time: float,
    baseline_evaluation_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Account exact evaluations and project isolation for one workload."""
    expected_keys = [item.key for item in expected]
    if len(set(expected_keys)) != len(expected_keys):
        raise SystemsHarnessError("expected evaluation generator produced duplicates")
    expected_set = set(expected_keys)
    global_input_projects: dict[str, str] = {}
    for item in expected:
        previous = global_input_projects.setdefault(
            item.input_sha256, item.project_root
        )
        if previous != item.project_root:
            raise SystemsHarnessError(
                "probe input hashes are not globally project-unique"
            )
    expected_artifacts = {item.rule_id: item for item in artifacts}
    relevant_rows: list[tuple[tuple[str, str, str], dict[str, Any]]] = []
    unexpected = []
    cross_project = []
    provenance_mismatches = []
    for project_root, rows in rows_by_project.items():
        project = Path(project_root)
        for row in rows:
            input_hash = _input_hash_from_row(row)
            row_project = str(row.get("project_root", ""))
            if row_project and Path(row_project).resolve() != project.resolve():
                cross_project.append(
                    {
                        "reason": "row project_root differs from containing project log",
                        "log_project": project_root,
                        "row_project": row_project,
                        "evaluation_id": row.get("evaluation_id"),
                    }
                )
            owner = global_input_projects.get(input_hash)
            if owner and Path(owner).resolve() != project.resolve():
                cross_project.append(
                    {
                        "reason": "another project's exact probe input appeared here",
                        "log_project": project_root,
                        "expected_project": owner,
                        "evaluation_id": row.get("evaluation_id"),
                    }
                )
            key = _row_key(row, project)
            if key in expected_set:
                relevant_rows.append((key, row))
                artifact = expected_artifacts.get(key[2])
                rule = row.get("rule") or {}
                if artifact is not None:
                    checks = {
                        "source_hash": artifact.source_sha256,
                        "behavior_hash": artifact.behavior_sha256,
                        "compiler": artifact.compiler,
                        "compiler_snapshot": artifact.compiler_snapshot,
                        "program_id": artifact.program_id,
                    }
                    differences = {
                        name: {"expected": wanted, "observed": str(rule.get(name, ""))}
                        for name, wanted in checks.items()
                        if str(rule.get(name, "")) != wanted
                    }
                    if differences:
                        provenance_mismatches.append(
                            {"key": _key_json(key), "differences": differences}
                        )
            elif (
                str(row.get("evaluation_id", "")) not in baseline_evaluation_ids
                if baseline_evaluation_ids is not None
                else float(row.get("timestamp", 0) or 0) >= started_wall_time
            ):
                unexpected.append(
                    {
                        "project_root": project_root,
                        "input_sha256": input_hash,
                        "rule_id": str((row.get("rule") or {}).get("id", "")),
                        "evaluation_id": row.get("evaluation_id"),
                    }
                )
    counts = Counter(key for key, _row in relevant_rows)
    missing = [key for key in expected_keys if counts[key] == 0]
    duplicates = [
        {"key": _key_json(key), "count": count}
        for key, count in counts.items()
        if count > 1
    ]
    failed = []
    running = []
    result_counts: Counter[str] = Counter()
    for key, row in relevant_rows:
        status = str(row.get("status", ""))
        if status == "failed":
            failed.append(
                {
                    "key": _key_json(key),
                    "error_code": (row.get("outcome") or {}).get("error_code"),
                    "error": (row.get("outcome") or {}).get("error"),
                }
            )
        elif status != "completed":
            running.append({"key": _key_json(key), "status": status or "running"})
        result_counts[str(row.get("result", "")) or status or "unknown"] += 1
    return {
        "evaluations_expected": len(expected_keys),
        "evaluations_observed_for_expected_keys": len(relevant_rows),
        "expected_keys_observed": len(expected_keys) - len(missing),
        "loss_count": len(missing),
        "duplicate_count": sum(item["count"] - 1 for item in duplicates),
        "unexpected_count": len(unexpected),
        "cross_project_contamination_count": len(cross_project),
        "failed_count": len(failed),
        "running_count": len(running),
        "provenance_mismatch_count": len(provenance_mismatches),
        "result_counts": dict(sorted(result_counts.items())),
        "missing": [_key_json(key) for key in missing],
        "duplicates": duplicates,
        "unexpected": unexpected,
        "cross_project_contamination": cross_project,
        "failed": failed,
        "running": running,
        "provenance_mismatches": provenance_mismatches,
    }


def account_findings(
    findings_by_project: dict[str, list[dict[str, Any]]],
    evaluation_rows_by_project: dict[str, list[dict[str, Any]]],
    expected: Sequence[ExpectedEvaluation],
    *,
    baseline_finding_ids: set[int] | None = None,
) -> dict[str, Any]:
    """Reconcile violations-only findings with exact terminal evaluations."""
    expected_keys = [item.key for item in expected]
    expected_set = set(expected_keys)
    input_owner = {item.input_sha256: item.project_root for item in expected}
    expected_findings: dict[tuple[str, str, str], tuple[int, str]] = {}
    for project_root, rows in evaluation_rows_by_project.items():
        project = Path(project_root)
        for row in rows:
            key = _row_key(row, project)
            if key not in expected_set or str(row.get("status", "")) != "completed":
                continue
            finding_id = (row.get("outcome") or {}).get("finding_id")
            if finding_id is None:
                continue
            expected_findings.setdefault(
                key,
                (int(finding_id), str(row.get("evaluation_id", ""))),
            )

    observed: Counter[tuple[str, str, str]] = Counter()
    matched_ids: set[int] = set()
    unexpected = []
    wrong_project = []
    id_mismatches = []
    evaluation_id_mismatches = []
    for project_root, findings in findings_by_project.items():
        project = Path(project_root)
        for finding in findings:
            projected = _finding_projection(project, finding)
            finding_id_value = projected.get("finding_id")
            try:
                finding_id = int(finding_id_value)
            except (TypeError, ValueError):
                finding_id = -1
            if baseline_finding_ids is not None and finding_id in baseline_finding_ids:
                continue
            key = (
                str(project),
                str(projected.get("input_sha256", "")),
                str(projected.get("rule_id", "")),
            )
            owner = input_owner.get(key[1])
            if owner and Path(owner).resolve() != project.resolve():
                wrong_project.append(
                    {
                        "finding_id": finding_id_value,
                        "observed_project": str(project),
                        "expected_project": owner,
                        "input_sha256": key[1],
                    }
                )
            expectation = expected_findings.get(key)
            if expectation is None:
                unexpected.append(projected)
                continue
            observed[key] += 1
            expected_id, expected_evaluation_id = expectation
            if finding_id != expected_id:
                id_mismatches.append(
                    {
                        "key": _key_json(key),
                        "expected": expected_id,
                        "observed": finding_id_value,
                    }
                )
            else:
                matched_ids.add(expected_id)
            if projected["evaluation_id"] != expected_evaluation_id:
                evaluation_id_mismatches.append(
                    {
                        "key": _key_json(key),
                        "expected": expected_evaluation_id,
                        "observed": projected["evaluation_id"],
                    }
                )
    missing = [
        {"key": _key_json(key), "finding_id": finding_id}
        for key, (finding_id, _evaluation_id) in expected_findings.items()
        if finding_id not in matched_ids
    ]
    duplicates = [
        {"key": _key_json(key), "count": count}
        for key, count in observed.items()
        if count > 1
    ]
    return {
        "findings_expected": len(expected_findings),
        "findings_observed_for_expected_keys": sum(observed.values()),
        "loss_count": len(missing),
        "duplicate_count": sum(item["count"] - 1 for item in duplicates),
        "unexpected_count": len(unexpected),
        "wrong_project_count": len(wrong_project),
        "finding_id_mismatch_count": len(id_mismatches),
        "evaluation_id_mismatch_count": len(evaluation_id_mismatches),
        "missing": missing,
        "duplicates": duplicates,
        "unexpected": unexpected,
        "wrong_project": wrong_project,
        "finding_id_mismatches": id_mismatches,
        "evaluation_id_mismatches": evaluation_id_mismatches,
    }


def _terminal_keys(
    rows_by_project: dict[str, list[dict[str, Any]]],
    expected: Sequence[ExpectedEvaluation],
) -> set[tuple[str, str, str]]:
    expected_set = {item.key for item in expected}
    terminal = set()
    for project_root, rows in rows_by_project.items():
        project = Path(project_root)
        for row in rows:
            key = _row_key(row, project)
            if key in expected_set and str(row.get("status", "")) in (
                "completed",
                "failed",
            ):
                terminal.add(key)
    return terminal


def _wait_for_expected(
    projects: Sequence[InstalledProject],
    expected: Sequence[ExpectedEvaluation],
    event_started_ns: dict[str, int],
    timeout: float,
    *,
    deadline_ns: int | None = None,
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, int],
    dict[str, int],
    dict[str, Any],
]:
    expected_by_input: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for item in expected:
        expected_by_input[item.input_sha256].add(item.key)
    first_visible: dict[str, int] = {}
    all_visible: dict[str, int] = {}
    deadline_ns = (
        int(deadline_ns)
        if deadline_ns is not None
        else min(event_started_ns.values()) + int(timeout * 1_000_000_000)
    )
    last_rows: dict[str, list[dict[str, Any]]] = {}
    query_samples: list[dict[str, Any]] = []
    last_observed_ns: int | None = None
    after_deadline_visible: set[str] = set()
    while time.perf_counter_ns() < deadline_ns:
        last_rows = {}
        for project in projects:
            rows, query_sample = _timed_evaluation_history(project.root)
            last_rows[str(project.root)] = rows
            query_samples.append(query_sample)
        observed_ns = time.perf_counter_ns()
        last_observed_ns = observed_ns
        terminal = _terminal_keys(last_rows, expected)
        for input_hash, keys in expected_by_input.items():
            present = terminal.intersection(keys)
            if (
                observed_ns <= deadline_ns
                and present
                and input_hash not in first_visible
            ):
                first_visible[input_hash] = observed_ns
            if keys.issubset(terminal):
                if observed_ns <= deadline_ns and input_hash not in all_visible:
                    all_visible[input_hash] = observed_ns
                elif observed_ns > deadline_ns:
                    after_deadline_visible.add(input_hash)
        if observed_ns > deadline_ns:
            break
        if len(all_visible) == len(expected_by_input):
            # One settle interval catches duplicate evaluations admitted just
            # behind the first complete observation.
            remaining = max(0.0, (deadline_ns - time.perf_counter_ns()) / 1e9)
            time.sleep(min(QUERY_POLL_INTERVAL_SECONDS, remaining))
            last_rows = {}
            for project in projects:
                rows, query_sample = _timed_evaluation_history(project.root)
                last_rows[str(project.root)] = rows
                query_samples.append(query_sample)
            settle_observed_ns = time.perf_counter_ns()
            last_observed_ns = settle_observed_ns
            settle_terminal = _terminal_keys(last_rows, expected)
            settle_complete = all(
                keys.issubset(settle_terminal) for keys in expected_by_input.values()
            )
            if settle_complete and settle_observed_ns <= deadline_ns:
                return (
                    last_rows,
                    first_visible,
                    all_visible,
                    {
                        "timed_out": False,
                        "missing_input_sha256": [],
                        "deadline_monotonic_ns": deadline_ns,
                        "last_observed_monotonic_ns": settle_observed_ns,
                        "settle_seconds": QUERY_POLL_INTERVAL_SECONDS,
                        "query_samples": query_samples,
                    },
                )
            if settle_complete:
                after_deadline_visible.update(expected_by_input)
            break
        time.sleep(QUERY_POLL_INTERVAL_SECONDS)
    missing = sorted(set(expected_by_input) - set(all_visible))
    # A missing/slow system outcome is measured data, not a harness exception.
    # Return the last complete observation so callers can retain exact loss and
    # right-censoring rather than discarding the condition.
    return (
        last_rows,
        first_visible,
        all_visible,
        {
            "timed_out": True,
            "missing_input_sha256": missing,
            "deadline_monotonic_ns": deadline_ns,
            "last_observed_monotonic_ns": last_observed_ns,
            "after_deadline_visible_input_sha256": sorted(after_deadline_visible),
            "query_samples": query_samples,
        },
    )


def _wait_for_expected_incremental(
    projects: Sequence[InstalledProject],
    expected: Sequence[ExpectedEvaluation],
    event_started_ns: dict[str, int],
    timeout: float,
    *,
    tailer: _EvaluationJournalTailer,
    checkpoint_writer: _IncrementalJsonlWriter,
    history_limits: Mapping[str, int],
    deadline_ns: int | None = None,
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, int],
    dict[str, int],
    dict[str, Any],
]:
    """Confirm journal-signalled per-event transitions with bounded History calls."""
    expected_by_input: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    owner_by_input: dict[str, str] = {}
    project_by_root = {str(project.root): project for project in projects}
    for item in expected:
        expected_by_input[item.input_sha256].add(item.key)
        owner_by_input[item.input_sha256] = item.project_root
    deadline_ns = (
        int(deadline_ns)
        if deadline_ns is not None
        else min(event_started_ns.values()) + int(timeout * 1_000_000_000)
    )
    first_visible: dict[str, int] = {}
    all_visible: dict[str, int] = {}
    after_deadline_visible: set[str] = set()
    query_samples: list[dict[str, Any]] = []
    last_rows: dict[str, list[dict[str, Any]]] = {}
    journal_polls = 0
    history_limit_saturated = False
    last_observed_ns: int | None = None
    while time.perf_counter_ns() < deadline_ns:
        progress = tailer.poll()
        journal_polls += 1
        journal_observed_ns = int(progress["observed_monotonic_ns"])
        last_observed_ns = journal_observed_ns
        if journal_observed_ns > deadline_ns:
            for input_hash, keys in expected_by_input.items():
                if keys.issubset(tailer.terminal_keys):
                    after_deadline_visible.add(input_hash)
            break
        pending_by_project: dict[str, set[str]] = defaultdict(set)
        for input_hash, keys in expected_by_input.items():
            terminal = tailer.terminal_keys.intersection(keys)
            if terminal and input_hash not in first_visible:
                pending_by_project[owner_by_input[input_hash]].add(input_hash)
            if keys.issubset(tailer.terminal_keys) and input_hash not in all_visible:
                pending_by_project[owner_by_input[input_hash]].add(input_hash)
        for project_root, pending_inputs in sorted(pending_by_project.items()):
            limit = int(history_limits[project_root])
            if limit > EVALUATION_HISTORY_LIMIT:
                history_limit_saturated = True
                limit = EVALUATION_HISTORY_LIMIT
            rows, query_sample = _timed_evaluation_history(
                project_by_root[project_root].root, limit=limit
            )
            query_sample.update(
                {
                    "limit": limit,
                    "trigger_input_sha256": sorted(pending_inputs),
                    "kind": "journal_transition_confirmation",
                }
            )
            query_samples.append(query_sample)
            last_rows[project_root] = rows
            query_finished_ns = int(query_sample["finished_monotonic_ns"])
            last_observed_ns = query_finished_ns
            terminal = _terminal_keys({project_root: rows}, expected)
            if len(rows) >= limit:
                history_limit_saturated = True
            for input_hash in pending_inputs:
                keys = expected_by_input[input_hash]
                if query_finished_ns > deadline_ns:
                    if keys.issubset(terminal):
                        after_deadline_visible.add(input_hash)
                    continue
                if terminal.intersection(keys) and input_hash not in first_visible:
                    first_visible[input_hash] = query_finished_ns
                if keys.issubset(terminal) and input_hash not in all_visible:
                    all_visible[input_hash] = query_finished_ns
            checkpoint_writer.append(
                {
                    "kind": "journal_transition_confirmation",
                    "project_root": project_root,
                    "observed_monotonic_ns": query_finished_ns,
                    "within_deadline": query_finished_ns <= deadline_ns,
                    "limit": limit,
                    "rows": len(rows),
                    "trigger_input_sha256": sorted(pending_inputs),
                    "first_visible_confirmed": sorted(
                        pending_inputs.intersection(first_visible)
                    ),
                    "all_visible_confirmed": sorted(
                        pending_inputs.intersection(all_visible)
                    ),
                    "query_latency_ns": int(query_sample["latency_ns"]),
                }
            )
        if len(all_visible) == len(expected_by_input):
            break
        remaining = max(0.0, (deadline_ns - time.perf_counter_ns()) / 1e9)
        time.sleep(min(QUERY_POLL_INTERVAL_SECONDS, remaining))

    # Endpoint timestamps above remain valid.  This separate quiescence gate
    # catches late duplicate/in-flight work without retroactively censoring them.
    settle_started_ns = time.perf_counter_ns()
    remaining = max(0.0, (deadline_ns - settle_started_ns) / 1e9)
    time.sleep(min(QUERY_POLL_INTERVAL_SECONDS, remaining))
    settle_progress = tailer.poll()
    journal_polls += 1
    settle_finished_ns = int(settle_progress["observed_monotonic_ns"])
    expected_keys = {item.key for item in expected}
    settle_complete = bool(
        settle_finished_ns <= deadline_ns
        and expected_keys.issubset(tailer.terminal_keys)
        and not tailer.started
        and not tailer.outcomes_before_start
    )
    checkpoint_writer.append(
        {
            "kind": "condition_quiescence",
            "started_monotonic_ns": settle_started_ns,
            "observed_monotonic_ns": settle_finished_ns,
            "within_deadline": settle_finished_ns <= deadline_ns,
            "complete": settle_complete,
            "inflight_evaluations": len(tailer.started),
            "outcomes_without_observed_start": len(tailer.outcomes_before_start),
        }
    )
    missing = sorted(set(expected_by_input) - set(all_visible))
    return (
        last_rows,
        first_visible,
        all_visible,
        {
            "timed_out": bool(missing),
            "integrity_violation": bool(not settle_complete or history_limit_saturated),
            "history_limit_saturated": history_limit_saturated,
            "missing_input_sha256": missing,
            "deadline_monotonic_ns": deadline_ns,
            "last_observed_monotonic_ns": max(
                settle_finished_ns, last_observed_ns or settle_finished_ns
            ),
            "after_deadline_visible_input_sha256": sorted(after_deadline_visible),
            "journal_polls": journal_polls,
            "settle": {
                "seconds": QUERY_POLL_INTERVAL_SECONDS,
                "started_monotonic_ns": settle_started_ns,
                "finished_monotonic_ns": settle_finished_ns,
                "complete": settle_complete,
            },
            "query_samples": query_samples,
            "history_limits": dict(sorted(history_limits.items())),
        },
    )


def _process_tree_snapshot(pid: int) -> dict[str, Any]:
    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {
            "processes": 0,
            "rss_bytes": 0,
            "cpu_seconds": 0.0,
            "file_descriptors": None,
        }
    rss = 0
    cpu = 0.0
    descriptors = 0
    descriptor_supported = True
    alive = 0
    for process in processes:
        try:
            rss += int(process.memory_info().rss)
            times = process.cpu_times()
            cpu += float(times.user + times.system)
            if hasattr(process, "num_fds"):
                descriptors += int(process.num_fds())
            elif hasattr(process, "num_handles"):
                descriptors += int(process.num_handles())
            else:
                descriptor_supported = False
            alive += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except (NotImplementedError, AttributeError):
            descriptor_supported = False
    return {
        "processes": alive,
        "rss_bytes": rss,
        "cpu_seconds": round(cpu, 6),
        "file_descriptors": descriptors if descriptor_supported else None,
    }


class _ResourceSampler:
    def __init__(
        self,
        pid: int,
        interval: float = RESOURCE_SAMPLE_INTERVAL_SECONDS,
        *,
        journal_path: Path | None = None,
        keep_full_samples: bool = True,
    ):
        self.pid = pid
        self.interval = interval
        self.samples: list[dict[str, Any]] = []
        self.rss_points: list[dict[str, int]] = []
        self.sample_count = 0
        self.peak_rss_bytes = 0
        self.peak_file_descriptors: int | None = None
        self.writer = (
            _IncrementalJsonlWriter(journal_path) if journal_path is not None else None
        )
        self.keep_full_samples = keep_full_samples
        self.thread_error: BaseException | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._sample, name="rap-systems-resources", daemon=True
        )

    def _sample(self) -> None:
        try:
            while not self._stop.is_set():
                sample = _process_tree_snapshot(self.pid)
                if sample["processes"] == 0:
                    return
                sample["observed_monotonic_ns"] = time.perf_counter_ns()
                sample["observed_utc"] = datetime.now(timezone.utc).isoformat()
                self.sample_count += 1
                self.peak_rss_bytes = max(self.peak_rss_bytes, int(sample["rss_bytes"]))
                descriptors = sample.get("file_descriptors")
                if descriptors is not None:
                    self.peak_file_descriptors = max(
                        self.peak_file_descriptors or 0, int(descriptors)
                    )
                self.rss_points.append(
                    {
                        "observed_monotonic_ns": int(sample["observed_monotonic_ns"]),
                        "rss_bytes": int(sample["rss_bytes"]),
                    }
                )
                if self.keep_full_samples:
                    self.samples.append(sample)
                if self.writer is not None:
                    self.writer.append(sample)
                self._stop.wait(self.interval)
        except BaseException as exc:
            self.thread_error = exc
            self._stop.set()

    def __enter__(self) -> "_ResourceSampler":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._stop.set()
        self._thread.join(timeout=2.0)
        alive = self._thread.is_alive()
        try:
            if self.writer is not None:
                self.writer.close()
        finally:
            if exc_type is None:
                if alive:
                    raise SystemViolationError(
                        "resource sampler thread did not terminate"
                    )
                if self.thread_error is not None:
                    raise SystemViolationError(
                        f"resource sampler failed: {self.thread_error}"
                    ) from self.thread_error

    def journal_receipt(self) -> dict[str, Any] | None:
        return self.writer.receipt() if self.writer is not None else None


def _tree_size(path: Path) -> dict[str, int]:
    files = 0
    size = 0
    if not path.exists():
        return {"files": 0, "bytes": 0}
    for candidate in path.rglob("*"):
        try:
            if candidate.is_file() and not candidate.is_symlink():
                files += 1
                size += int(candidate.stat().st_size)
        except OSError:
            continue
    return {"files": files, "bytes": size}


def _path_bytes(path: Path) -> int:
    try:
        return int(path.stat().st_size) if path.is_file() else 0
    except OSError:
        return 0


def _evaluation_journal_bytes(project: Path) -> int:
    base = rap_config.project_evaluation_log_file(str(project))
    return sum(
        _path_bytes(path)
        for path in [
            base,
            *(base.with_name(f"{base.name}.{index}") for index in range(1, 6)),
        ]
    )


def _storage_snapshot(fixture: RunningFixture) -> dict[str, Any]:
    state = _tree_size(fixture.isolated_root / "state")
    project_logs = {
        str(project.root): _tree_size(
            project.root / ".codex" / "rules-as-programs" / "log"
        )
        for project in fixture.projects
    }
    project_rap = {
        str(project.root): _tree_size(project.root / ".codex" / "rules-as-programs")
        for project in fixture.projects
    }
    database = rap_config.db_path()
    named_bytes = {
        "ledger_tree": _tree_size(fixture.isolated_root / "state" / "ledgers")["bytes"],
        "finding_database": _path_bytes(database),
        "finding_database_wal": _path_bytes(database.with_name(f"{database.name}-wal")),
        "finding_database_shm": _path_bytes(database.with_name(f"{database.name}-shm")),
        "audit_logs": {
            str(project.root): _path_bytes(
                rap_config.project_log_file(str(project.root))
            )
            for project in fixture.projects
        },
        "evaluation_journals_including_rotations": {
            str(project.root): _evaluation_journal_bytes(project.root)
            for project in fixture.projects
        },
    }
    return {
        "state": state,
        "project_logs": project_logs,
        "project_rap_trees": project_rap,
        "named_bytes": named_bytes,
        "total_runtime_bytes": state["bytes"]
        + sum(item["bytes"] for item in project_logs.values()),
    }


def _storage_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    roots = sorted(set(before["project_logs"]) | set(after["project_logs"]))
    value = {
        "state_bytes": after["state"]["bytes"] - before["state"]["bytes"],
        "project_log_bytes": {
            root: after["project_logs"].get(root, {}).get("bytes", 0)
            - before["project_logs"].get(root, {}).get("bytes", 0)
            for root in roots
        },
        "total_runtime_bytes": after["total_runtime_bytes"]
        - before["total_runtime_bytes"],
    }
    if "named_bytes" in before or "named_bytes" in after:
        before_named = dict(before.get("named_bytes") or {})
        after_named = dict(after.get("named_bytes") or {})
        scalar_names = (
            "ledger_tree",
            "finding_database",
            "finding_database_wal",
            "finding_database_shm",
        )
        named_delta: dict[str, Any] = {
            name: int(after_named.get(name, 0)) - int(before_named.get(name, 0))
            for name in scalar_names
        }
        for name in ("audit_logs", "evaluation_journals_including_rotations"):
            before_map = dict(before_named.get(name) or {})
            after_map = dict(after_named.get(name) or {})
            named_delta[name] = {
                root: int(after_map.get(root, 0)) - int(before_map.get(root, 0))
                for root in sorted(set(before_map) | set(after_map))
            }
        value["named_bytes"] = named_delta
    return value


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


def _summary_ns(values: list[int]) -> dict[str, Any]:
    """Reduce exact integer nanoseconds; rounded milliseconds are display-only."""
    if not values:
        raise ValueError("cannot summarize an empty sample")
    ordered = sorted(int(value) for value in values)

    def select(percentile: float) -> int:
        rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
        return ordered[rank - 1]

    exact = {
        "minimum_ns": ordered[0],
        "mean_ns": sum(ordered) / len(ordered),
        "p50_nearest_rank_ns": select(50),
        "p95_nearest_rank_ns": select(95),
        "p99_nearest_rank_ns": select(99),
        "maximum_ns": ordered[-1],
    }
    return {
        "unit": "ns",
        "count": len(ordered),
        **exact,
        "display_ms": {
            name.removesuffix("_ns"): round(float(value) / 1_000_000, 3)
            for name, value in exact.items()
        },
        # Compatibility display fields; selection never uses these rounded values.
        "minimum": round(ordered[0] / 1_000_000, 3),
        "mean": round((sum(ordered) / len(ordered)) / 1_000_000, 3),
        "p50_nearest_rank": round(select(50) / 1_000_000, 3),
        "p95_nearest_rank": round(select(95) / 1_000_000, 3),
        "p99_nearest_rank": round(select(99) / 1_000_000, 3),
        "maximum": round(ordered[-1] / 1_000_000, 3),
    }


def _latency_summary(samples: Sequence[dict[str, Any]], key: str) -> dict[str, Any]:
    ns_key = key.removesuffix("_ms") + "_ns" if key.endswith("_ms") else key
    observed: list[int] = []
    lower_bounds: list[int] = []
    censored = 0
    for sample in samples:
        value = sample.get(ns_key)
        if value is None and sample.get(key) is not None:
            value = round(float(sample[key]) * 1_000_000)
        if value is None:
            censored += 1
            censor_ns = sample.get("latency_censored_at_ns")
            if censor_ns is None:
                censor_ns = round(
                    float(sample.get("latency_censored_at_ms") or 0.0) * 1_000_000
                )
            lower_bounds.append(int(censor_ns))
        else:
            observed.append(int(value))
            lower_bounds.append(int(value))
    summary = _summary_ns(lower_bounds)
    summary.update(
        {
            "observed_count": len(observed),
            "right_censored_count": censored,
            "percentiles_are_lower_bounds": bool(censored),
        }
    )
    return summary


def _linear_slope(
    samples: Sequence[dict[str, Any]],
    *,
    x_key: str,
    y_key: str,
) -> dict[str, Any]:
    points = [
        (float(item[x_key]), float(item[y_key]))
        for item in samples
        if item.get(x_key) is not None and item.get(y_key) is not None
    ]
    distinct_x = {point[0] for point in points}
    if len(points) < 2 or len(distinct_x) < 2:
        return {
            "available": False,
            "reason": "at least two distinct timestamped samples are required",
            "sample_count": len(points),
        }
    mean_x = sum(point[0] for point in points) / len(points)
    mean_y = sum(point[1] for point in points) / len(points)
    denominator = sum((x - mean_x) ** 2 for x, _y in points)
    slope = sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator
    intercept = mean_y - slope * mean_x
    residual_sum_squares = sum((y - (intercept + slope * x)) ** 2 for x, y in points)
    total_sum_squares = sum((y - mean_y) ** 2 for _x, y in points)
    r_squared = (
        1.0
        if total_sum_squares == 0.0 and residual_sum_squares == 0.0
        else 0.0
        if total_sum_squares == 0.0
        else 1.0 - residual_sum_squares / total_sum_squares
    )
    return {
        "available": True,
        "method": "ordinary_least_squares_with_intercept",
        "sample_count": len(points),
        "slope": round(slope, 6),
        "intercept": round(intercept, 6),
        "r_squared": round(r_squared, 12),
        "x_min": min(distinct_x),
        "x_max": max(distinct_x),
    }


def _rss_slope(samples: Sequence[dict[str, Any]]) -> dict[str, Any]:
    if not samples:
        return _linear_slope(samples, x_key="elapsed_seconds", y_key="rss_bytes")
    origin = min(int(item["observed_monotonic_ns"]) for item in samples)
    normalized = [
        {
            **item,
            "elapsed_seconds": (int(item["observed_monotonic_ns"]) - origin)
            / 1_000_000_000,
        }
        for item in samples
    ]
    value = _linear_slope(normalized, x_key="elapsed_seconds", y_key="rss_bytes")
    if value.get("available"):
        value["unit"] = "bytes_per_second"
    return value


def _fairness_summary(
    schedule: str,
    project_count: int,
    complete_by_project: dict[str, list[int]],
) -> dict[str, Any]:
    active = {key: values for key, values in complete_by_project.items() if values}
    if schedule != "round_robin_across_projects":
        return {
            "applicable": False,
            "range_ms": None,
            "range_ns": None,
            "reason": "hotspot traffic intentionally exercises only one project",
            "active_projects": len(active),
            "idle_projects": max(0, project_count - len(active)),
        }
    if project_count < 2 or len(active) < 2:
        return {
            "applicable": False,
            "range_ms": None,
            "range_ns": None,
            "reason": "fairness requires at least two exercised projects",
            "active_projects": len(active),
            "idle_projects": max(0, project_count - len(active)),
        }
    project_p95_ns = {
        project: int(_nearest_rank(values, 95))
        for project, values in sorted(active.items())
    }
    range_ns = max(project_p95_ns.values()) - min(project_p95_ns.values())
    return {
        "applicable": True,
        "range_ns": range_ns,
        "range_ms": round(range_ns / 1_000_000, 3),
        "project_p95_ns": project_p95_ns,
        "reason": "",
        "active_projects": len(active),
        "idle_projects": max(0, project_count - len(active)),
    }


def _build_events(
    fixture: RunningFixture,
    condition_id: str,
    event_count: int,
    schedule: str = "round_robin_across_projects",
) -> list[tuple[InstalledProject, dict[str, Any], str, str]]:
    if schedule not in TRAFFIC_PATTERNS:
        raise ValueError(f"unsupported traffic schedule {schedule!r}")
    events = []
    for sequence in range(event_count):
        project = (
            fixture.projects[sequence % len(fixture.projects)]
            if schedule == "round_robin_across_projects"
            else fixture.projects[0]
        )
        probe = fixture.artifacts[sequence % len(fixture.artifacts)].probe_tool_input
        raw = _raw_event(
            project.root,
            project_index=project.index,
            sequence=sequence,
            condition_id=condition_id,
            tool_input=probe,
        )
        expected_input = _expected_input(raw)
        input_hash = _sha256_bytes(expected_input.encode("utf-8"))
        events.append((project, raw, expected_input, input_hash))
    hashes = [item[3] for item in events]
    if len(set(hashes)) != len(hashes):
        raise SystemsHarnessError("event generator did not create unique inputs")
    return events


def _expected_for_events(
    events: Sequence[tuple[InstalledProject, dict[str, Any], str, str]],
    artifacts: Sequence[RuleArtifact],
) -> list[ExpectedEvaluation]:
    return [
        ExpectedEvaluation(
            case_id=str((raw["tool_input"]["_rap_systems_probe"])["case_id"]),
            project_root=str(project.root),
            input_sha256=input_hash,
            rule_id=artifact.rule_id,
        )
        for project, raw, _expected_input_text, input_hash in events
        for artifact in artifacts
    ]


def _invoke_event_group(
    fixture: RunningFixture,
    events: Sequence[tuple[InstalledProject, dict[str, Any], str, str]],
    *,
    mode: str,
    timeout: float,
    max_workers: int,
    tailer: _EvaluationJournalTailer | None = None,
    checkpoint_writer: _IncrementalJsonlWriter | None = None,
    baseline_rows_by_project: Mapping[str, int] | None = None,
) -> tuple[
    list[dict[str, Any]],
    list[ExpectedEvaluation],
    dict[str, list[dict[str, Any]]],
    dict[str, Any],
]:
    expected = _expected_for_events(events, fixture.artifacts)
    expected_rows_by_project = Counter(item.project_root for item in expected)
    history_limits = {
        str(project.root): int(
            (baseline_rows_by_project or {}).get(str(project.root), 0)
        )
        + int(expected_rows_by_project[str(project.root)])
        + MATRIX_HISTORY_DUPLICATE_HEADROOM
        for project in fixture.projects
    }

    def wait_for(
        wait_expected: Sequence[ExpectedEvaluation],
        started: dict[str, int],
    ) -> tuple[
        dict[str, list[dict[str, Any]]],
        dict[str, int],
        dict[str, int],
        dict[str, Any],
    ]:
        if tailer is not None and checkpoint_writer is not None:
            return _wait_for_expected_incremental(
                fixture.projects,
                wait_expected,
                started,
                timeout,
                tailer=tailer,
                checkpoint_writer=checkpoint_writer,
                history_limits=history_limits,
            )
        return _wait_for_expected(fixture.projects, wait_expected, started, timeout)

    samples: list[dict[str, Any]] = []

    def sample_for(
        project: InstalledProject,
        raw: dict[str, Any],
        input_hash: str,
        hook: dict[str, Any],
        submitted_ns: int,
        first: dict[str, int],
        complete: dict[str, int],
        deadline_ns: int,
    ) -> dict[str, Any]:
        first_ns = first.get(input_hash)
        complete_ns = complete.get(input_hash)
        executor_queue_ns = int(hook["started_ns"]) - submitted_ns
        hook_exit_ns = int(hook["exited_ns"]) - int(hook["started_ns"])
        submission_to_hook_exit_ns = int(hook["exited_ns"]) - submitted_ns
        first_latency_ns = (
            int(first_ns) - submitted_ns if first_ns is not None else None
        )
        complete_latency_ns = (
            int(complete_ns) - submitted_ns if complete_ns is not None else None
        )
        censor_ns = max(0, int(deadline_ns) - submitted_ns)
        return {
            "case_id": raw["tool_input"]["_rap_systems_probe"]["case_id"],
            "project_root": str(project.root),
            "input_sha256": input_hash,
            "submitted_monotonic_ns": submitted_ns,
            "hook_started_monotonic_ns": hook["started_ns"],
            "hook_exited_monotonic_ns": hook["exited_ns"],
            "first_visible_monotonic_ns": first_ns,
            "all_visible_monotonic_ns": complete_ns,
            "censor_deadline_monotonic_ns": int(deadline_ns),
            "executor_queue_ns": executor_queue_ns,
            "hook_exit_ns": hook_exit_ns,
            "submission_to_hook_exit_ns": submission_to_hook_exit_ns,
            "event_to_first_query_visible_evaluation_ns": first_latency_ns,
            "event_to_all_query_visible_evaluations_ns": complete_latency_ns,
            "latency_censored_at_ns": None if complete_ns is not None else censor_ns,
            "executor_queue_ms": round(executor_queue_ns / 1_000_000, 3),
            "hook_exit_ms": round(hook_exit_ns / 1_000_000, 3),
            "submission_to_hook_exit_ms": round(
                submission_to_hook_exit_ns / 1_000_000, 3
            ),
            "event_to_first_query_visible_evaluation_ms": (
                round(first_latency_ns / 1_000_000, 3)
                if first_latency_ns is not None
                else None
            ),
            "event_to_all_query_visible_evaluations_ms": (
                round(complete_latency_ns / 1_000_000, 3)
                if complete_latency_ns is not None
                else None
            ),
            "latency_censored_at_ms": (
                None if complete_ns is not None else round(censor_ns / 1_000_000, 3)
            ),
            "hook": {
                "returncode": hook.get("returncode"),
                "stdout": hook.get("stdout", ""),
                "stderr": hook.get("stderr", ""),
                "timed_out": bool(hook.get("timed_out")),
                "contract_preserved": bool(hook.get("contract_preserved")),
                "contract_error": str(hook.get("contract_error", "")),
            },
        }

    if mode == "sequential":
        query_samples: list[dict[str, Any]] = []
        timed_out_inputs: list[str] = []
        per_event_wait: list[dict[str, Any]] = []
        integrity_violation = False
        history_limit_saturated = False
        after_deadline_visible: set[str] = set()
        journal_polls = 0
        for project, raw, _text, input_hash in events:
            submitted_ns = time.perf_counter_ns()
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            one_expected = [
                item for item in expected if item.input_sha256 == input_hash
            ]
            rows, first, complete, wait = wait_for(
                one_expected, {input_hash: submitted_ns}
            )
            query_samples.extend(wait["query_samples"])
            timed_out_inputs.extend(wait["missing_input_sha256"])
            integrity_violation = bool(
                integrity_violation or wait.get("integrity_violation")
            )
            history_limit_saturated = bool(
                history_limit_saturated or wait.get("history_limit_saturated")
            )
            after_deadline_visible.update(
                wait.get("after_deadline_visible_input_sha256") or []
            )
            journal_polls += int(wait.get("journal_polls", 0))
            per_event_wait.append(
                {
                    "input_sha256": input_hash,
                    **{
                        key: value
                        for key, value in wait.items()
                        if key != "query_samples"
                    },
                }
            )
            samples.append(
                sample_for(
                    project,
                    raw,
                    input_hash,
                    hook,
                    submitted_ns,
                    first,
                    complete,
                    int(wait["deadline_monotonic_ns"]),
                )
            )
        final_rows = {
            str(project.root): _evaluation_history(project.root)
            for project in fixture.projects
        }
        workload_start_ns = min(int(item["submitted_monotonic_ns"]) for item in samples)
        workload_end_ns = max(
            int(
                item.get("all_visible_monotonic_ns")
                or item["censor_deadline_monotonic_ns"]
            )
            for item in samples
        )
        return (
            samples,
            expected,
            final_rows,
            {
                "timed_out": bool(timed_out_inputs),
                "integrity_violation": integrity_violation,
                "history_limit_saturated": history_limit_saturated,
                "missing_input_sha256": sorted(set(timed_out_inputs)),
                "after_deadline_visible_input_sha256": sorted(after_deadline_visible),
                "journal_polls": journal_polls,
                "per_event_wait": per_event_wait,
                "query_samples": query_samples,
                "burst_queue_drain_ns": None,
                "burst_queue_drain_ms": None,
                "workload_wall_ns": workload_end_ns - workload_start_ns,
            },
        )
    if mode != "burst":
        raise ValueError(f"unsupported event-group mode {mode!r}")
    hooks: dict[str, dict[str, Any]] = {}
    submissions: dict[str, int] = {}
    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(events)),
        thread_name_prefix="rap-systems-hooks",
    ) as executor:
        futures = {}
        for project, raw, _text, input_hash in events:
            submissions[input_hash] = time.perf_counter_ns()
            future = executor.submit(
                _invoke_raw, project.wrapper, raw, fixture.environment
            )
            futures[future] = (project, raw, input_hash)
        for future in as_completed(futures):
            _project, _raw, input_hash = futures[future]
            hooks[input_hash] = future.result()
    rows, first, complete, wait = wait_for(expected, submissions)
    for project, raw, _text, input_hash in events:
        hook = hooks[input_hash]
        samples.append(
            sample_for(
                project,
                raw,
                input_hash,
                hook,
                submissions[input_hash],
                first,
                complete,
                int(wait["deadline_monotonic_ns"]),
            )
        )
    samples.sort(key=lambda item: item["case_id"])
    latest_hook_exit_ns = max(int(hook["exited_ns"]) for hook in hooks.values())
    all_complete_ns = max(complete.values()) if len(complete) == len(events) else None
    queue_drain_ns = (
        max(0, int(all_complete_ns) - latest_hook_exit_ns)
        if all_complete_ns is not None
        else None
    )
    earliest_submission_ns = min(submissions.values())
    workload_end_ns = (
        int(all_complete_ns)
        if all_complete_ns is not None
        else int(wait["deadline_monotonic_ns"])
    )
    wait.update(
        {
            "burst_queue_drain_ns": queue_drain_ns,
            "burst_queue_drain_ms": (
                round(queue_drain_ns / 1_000_000, 3)
                if queue_drain_ns is not None
                else None
            ),
            "burst_queue_drain_censored_at_ns": (
                None
                if queue_drain_ns is not None
                else max(0, int(wait["deadline_monotonic_ns"]) - latest_hook_exit_ns)
            ),
            "workload_wall_ns": max(0, workload_end_ns - earliest_submission_ns),
            "workload_completed_monotonic_ns": all_complete_ns,
        }
    )
    return samples, expected, rows, wait


def _warm_fixture(
    fixture: RunningFixture, warmups_per_project: int, timeout: float
) -> None:
    for project in fixture.projects:
        for warmup in range(warmups_per_project):
            probe = fixture.artifacts[warmup % len(fixture.artifacts)].probe_tool_input
            raw = _raw_event(
                project.root,
                project_index=project.index,
                sequence=warmup,
                condition_id=f"warmup-{project.index}",
                tool_input=probe,
            )
            expected_input = _expected_input(raw)
            input_hash = _sha256_bytes(expected_input.encode("utf-8"))
            started_wall_time = time.time()
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            expected = [
                ExpectedEvaluation(
                    case_id=f"warmup-{project.index}-{warmup}",
                    project_root=str(project.root),
                    input_sha256=input_hash,
                    rule_id=artifact.rule_id,
                )
                for artifact in fixture.artifacts
            ]
            rows, _first, _complete, _wait = _wait_for_expected(
                fixture.projects,
                expected,
                {input_hash: hook["started_ns"]},
                timeout,
            )
            accounting = account_evaluations(
                rows,
                expected,
                fixture.artifacts,
                started_wall_time=started_wall_time,
            )
            _assert_clean_accounting(accounting, "warmup")


def _assert_clean_accounting(accounting: dict[str, Any], label: str) -> None:
    failures = {
        key: accounting.get(key)
        for key in ACCOUNTING_FAILURE_KEYS
        if accounting.get(key)
    }
    finding_accounting = dict(accounting.get("findings") or {})
    for key in (
        "loss_count",
        "duplicate_count",
        "unexpected_count",
        "wrong_project_count",
        "finding_id_mismatch_count",
        "evaluation_id_mismatch_count",
    ):
        if finding_accounting.get(key):
            failures[f"findings.{key}"] = finding_accounting[key]
    if failures:
        raise SystemViolationError(
            f"{label} exact evaluation accounting failed: {failures}"
        )


def _runtime_inventory(root: Path) -> list[dict[str, Any]]:
    inventory = []
    for path in sorted(root.rglob("*")):
        try:
            if not path.is_file() or path.is_symlink():
                continue
            inventory.append(
                {
                    "path": str(path.relative_to(root)),
                    "bytes": int(path.stat().st_size),
                    "sha256": _sha256_file(path),
                }
            )
        except OSError:
            continue
    return inventory


def _fixture_evidence(
    fixture: RunningFixture,
    rows_by_project: dict[str, list[dict[str, Any]]] | None = None,
    findings_by_project: dict[str, list[dict[str, Any]]] | None = None,
    *,
    include_records: bool = True,
) -> dict[str, Any]:
    rows_by_project = rows_by_project or {
        str(project.root): _full_evaluation_history(project.root)
        for project in fixture.projects
    }
    findings_by_project = findings_by_project or {
        str(project.root): _full_findings(project.root) for project in fixture.projects
    }
    try:
        diagnostic_text = fixture.diagnostics.read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        diagnostic_text = ""
    snapshot = ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
    evaluation_projections = {
        root: [_evaluation_projection(row) for row in rows]
        for root, rows in rows_by_project.items()
    }
    finding_projections = {
        root: [_finding_projection(Path(root), finding) for finding in findings]
        for root, findings in findings_by_project.items()
    }

    def retained_projection(
        values: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        if include_records:
            return values
        return {
            root: {
                "count": len(records),
                "canonical_projection_sha256": _sha256_bytes(
                    _canonical_json_bytes(_canonical_projection_order(records))
                ),
                "records": "retained in the immutable project journal",
            }
            for root, records in values.items()
        }

    return {
        "retained_runtime_root": str(fixture.isolated_root)
        if fixture.retained
        else None,
        "daemon_identity": fixture.identity,
        "runtime_inventory": _runtime_inventory(fixture.isolated_root),
        "daemon_diagnostics": {
            "path": str(fixture.diagnostics),
            "bytes": len(diagnostic_text.encode("utf-8")),
            "sha256": _sha256_bytes(diagnostic_text.encode("utf-8")),
            **({"text": diagnostic_text} if include_records else {}),
        },
        "daemon_snapshot": snapshot,
        "evaluations": retained_projection(evaluation_projections),
        "findings": retained_projection(finding_projections),
    }


def run_condition(
    artifacts: Sequence[RuleArtifact],
    *,
    rule_count: int,
    project_count: int,
    mode: str,
    event_count: int,
    repeat: int,
    warmups_per_project: int,
    timeout: float,
    drain_timeout: float | None = None,
    max_hook_workers: int,
    schedule: str = "round_robin_across_projects",
    strict: bool = True,
    retained_root: Path | None = None,
) -> dict[str, Any]:
    selected = tuple(artifacts[:rule_count])
    drain_timeout = drain_timeout or timeout
    if len(selected) != rule_count:
        raise ValueError("not enough rule artifacts for requested condition")
    condition_id = (
        f"r{rule_count}-p{project_count}-{schedule}-{mode}{event_count}-rep{repeat}"
    )
    with _running_fixture(
        selected,
        project_count,
        retained_root=retained_root,
        component="matrix",
        unit_id=condition_id,
    ) as fixture:
        _warm_fixture(fixture, warmups_per_project, timeout)
        baseline_rows = {
            str(project.root): _full_evaluation_history(project.root)
            for project in fixture.projects
        }
        baseline_evaluation_ids = {
            str(row.get("evaluation_id", ""))
            for rows in baseline_rows.values()
            for row in rows
        }
        baseline_finding_ids = {
            int(finding.get("finding_id", finding.get("id")))
            for project in fixture.projects
            for finding in _full_findings(project.root)
            if finding.get("finding_id", finding.get("id")) is not None
        }
        resources_before = _process_tree_snapshot(fixture.daemon.pid)
        storage_before = _storage_snapshot(fixture)
        started_wall_time = time.time()
        events = _build_events(fixture, condition_id, event_count, schedule=schedule)
        workload_started_ns = time.perf_counter_ns()
        with (
            _ResourceSampler(fixture.daemon.pid) as sampler,
            _EvaluationJournalTailer(
                fixture.projects,
                fixture.isolated_root / "matrix-journal-progress.jsonl",
            ) as matrix_tailer,
            _IncrementalJsonlWriter(
                fixture.isolated_root / "matrix-history-checkpoints.jsonl",
                fsync_every=1,
            ) as matrix_checkpoint_writer,
        ):
            samples, expected, rows, wait = _invoke_event_group(
                fixture,
                events,
                mode=mode,
                timeout=(drain_timeout or timeout) if mode == "burst" else timeout,
                max_workers=max_hook_workers,
                tailer=matrix_tailer,
                checkpoint_writer=matrix_checkpoint_writer,
                baseline_rows_by_project={
                    root: len(values) for root, values in baseline_rows.items()
                },
            )
        incremental_evidence = {
            "journal_progress": matrix_tailer.receipt(),
            "history_checkpoints": matrix_checkpoint_writer.receipt(),
        }
        workload_finished_ns = time.perf_counter_ns()
        rows = {
            str(project.root): _full_evaluation_history(project.root)
            for project in fixture.projects
        }
        findings = {
            str(project.root): _full_findings(project.root)
            for project in fixture.projects
        }
        accounting = account_evaluations(
            rows,
            expected,
            selected,
            started_wall_time=started_wall_time,
            baseline_evaluation_ids=baseline_evaluation_ids,
        )
        accounting["findings"] = account_findings(
            findings,
            rows,
            expected,
            baseline_finding_ids=baseline_finding_ids,
        )
        resources_after = _process_tree_snapshot(fixture.daemon.pid)
        storage_after = _storage_snapshot(fixture)
        all_resource_samples = [resources_before, *sampler.samples, resources_after]
        fd_values = [
            int(item["file_descriptors"])
            for item in all_resource_samples
            if item.get("file_descriptors") is not None
        ]
        hook_latencies_ns = [int(item["hook_exit_ns"]) for item in samples]
        complete_by_project: dict[str, list[int]] = defaultdict(list)
        for item in samples:
            value = item.get("event_to_all_query_visible_evaluations_ns")
            if value is not None:
                complete_by_project[str(item["project_root"])].append(int(value))
        project_p95 = {
            project: {
                "p95_nearest_rank_ns": int(_nearest_rank(values, 95)),
                "p95_nearest_rank_ms": round(
                    int(_nearest_rank(values, 95)) / 1_000_000, 3
                ),
            }
            for project, values in sorted(complete_by_project.items())
        }
        fairness = _fairness_summary(schedule, project_count, complete_by_project)
        workload_wall_ns = int(
            wait.get("workload_wall_ns") or (workload_finished_ns - workload_started_ns)
        )
        wall_seconds = workload_wall_ns / 1_000_000_000
        accounting_failure = any(accounting.get(key) for key in ACCOUNTING_FAILURE_KEYS)
        finding_failure = any(
            accounting["findings"].get(key)
            for key in (
                "loss_count",
                "duplicate_count",
                "unexpected_count",
                "wrong_project_count",
                "finding_id_mismatch_count",
                "evaluation_id_mismatch_count",
            )
        )
        hook_failure = any(
            not bool((item.get("hook") or {}).get("contract_preserved"))
            for item in samples
        )
        system_failure = bool(
            wait.get("timed_out")
            or wait.get("integrity_violation")
            or accounting_failure
            or finding_failure
            or hook_failure
        )
        query_latencies_ns = [
            int(item["latency_ns"]) for item in wait.get("query_samples", [])
        ]
        return {
            "status": ("system_violation" if system_failure else "completed"),
            "performance_failures_are_retained": True,
            "condition_id": condition_id,
            "rule_count": rule_count,
            "project_count": project_count,
            "mode": mode,
            "event_count": event_count,
            "repeat": repeat,
            "fresh_daemon": True,
            "fresh_state": True,
            "schedule": schedule,
            "rule_ids": [artifact.rule_id for artifact in selected],
            "daemon_identity": fixture.identity,
            "wall_seconds": round(wall_seconds, 3),
            "workload_wall_ns": workload_wall_ns,
            "event_throughput_per_second": round(event_count / wall_seconds, 3),
            "evaluation_throughput_per_second": round(
                (event_count * rule_count) / wall_seconds, 3
            ),
            "hook_process_exit": _summary_ns(hook_latencies_ns),
            "submission_to_hook_exit": _summary_ns(
                [int(item["submission_to_hook_exit_ns"]) for item in samples]
            ),
            "executor_queue": _summary_ns(
                [int(item["executor_queue_ns"]) for item in samples]
            ),
            "event_to_first_query_visible_evaluation": _latency_summary(
                samples, "event_to_first_query_visible_evaluation_ms"
            ),
            "event_to_all_query_visible_evaluations": _latency_summary(
                samples, "event_to_all_query_visible_evaluations_ms"
            ),
            "evaluation_history_query": _summary_ns(query_latencies_ns)
            if query_latencies_ns
            else {"unit": "ms", "count": 0, "available": False},
            "wait": {
                key: value for key, value in wait.items() if key != "query_samples"
            },
            "incremental_evidence": incremental_evidence,
            "burst_queue_drain": {
                "applicable": mode == "burst",
                "value_ns": wait.get("burst_queue_drain_ns"),
                "display_ms": wait.get("burst_queue_drain_ms"),
                "right_censored_at_ns": wait.get("burst_queue_drain_censored_at_ns"),
            },
            "per_project_event_to_all_p95_ms": project_p95,
            "per_project_p95_fairness_range_ms": fairness["range_ms"],
            "fairness": fairness,
            "accounting": accounting,
            "resources": {
                "scope": "daemon plus recursive child processes",
                "before": resources_before,
                "after": resources_after,
                "cpu_seconds_delta": round(
                    max(
                        0.0,
                        float(resources_after["cpu_seconds"])
                        - float(resources_before["cpu_seconds"]),
                    ),
                    6,
                ),
                "peak_sampled_rss_bytes": max(
                    int(item["rss_bytes"]) for item in all_resource_samples
                ),
                "peak_sampled_file_descriptors": max(fd_values) if fd_values else None,
                "sampling_interval_ms": int(RESOURCE_SAMPLE_INTERVAL_SECONDS * 1000),
                "sample_count": len(sampler.samples),
            },
            "storage": {
                "scope": (
                    "isolated RAP_STATE_DIR plus each synthetic project's RAP log tree; "
                    "installed sources/hooks are reported separately"
                ),
                "before": storage_before,
                "after": storage_after,
                "delta": _storage_delta(storage_before, storage_after),
            },
            "samples": samples,
            "evidence": _fixture_evidence(fixture, rows, findings),
        }


def _soak_history_checkpoint(
    projects: Sequence[InstalledProject],
    expected: Sequence[ExpectedEvaluation],
    *,
    batch_id: str,
    deadline_ns: int,
    writer: _IncrementalJsonlWriter,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    expected_keys = {item.key for item in expected}
    expected_key_set_sha256 = _sha256_bytes(
        _canonical_json_bytes([_key_json(key) for key in sorted(expected_keys)])
    )
    query_samples: list[dict[str, Any]] = []
    attempts = 0
    last_rows: dict[str, list[dict[str, Any]]] = {}
    last_missing = expected_keys
    last_observed_ns: int | None = None
    complete_after_deadline = False
    while True:
        attempts += 1
        last_rows = {}
        attempt_samples = []
        for project in projects:
            rows, sample = _timed_evaluation_history(project.root)
            last_rows[str(project.root)] = rows
            attempt_samples.append(sample)
            query_samples.append(sample)
        observed_ns = time.perf_counter_ns()
        last_observed_ns = observed_ns
        visible = _terminal_keys(last_rows, expected)
        last_missing = expected_keys - visible
        within_deadline = observed_ns <= deadline_ns
        writer.append(
            {
                "batch_id": batch_id,
                "expected_key_set_sha256": expected_key_set_sha256,
                "attempt": attempts,
                "observed_monotonic_ns": observed_ns,
                "expected_terminal_tuples": len(expected_keys),
                "visible_terminal_tuples": len(expected_keys) - len(last_missing),
                "missing_count": len(last_missing),
                "within_deadline": within_deadline,
                "per_project_queries": attempt_samples,
            }
        )
        if not last_missing and within_deadline:
            return last_rows, {
                "batch_id": batch_id,
                "expected_key_set_sha256": expected_key_set_sha256,
                "complete": True,
                "timed_out": False,
                "attempts": attempts,
                "visible_monotonic_ns": observed_ns,
                "missing": [],
                "query_samples": query_samples,
            }
        if not last_missing:
            complete_after_deadline = True
            break
        now_ns = time.perf_counter_ns()
        if now_ns >= deadline_ns:
            break
        time.sleep(
            min(
                SOAK_HISTORY_CHECKPOINT_RETRY_SECONDS,
                max(0.0, (deadline_ns - now_ns) / 1_000_000_000),
            )
        )
    return last_rows, {
        "batch_id": batch_id,
        "expected_key_set_sha256": expected_key_set_sha256,
        "complete": False,
        "timed_out": True,
        "attempts": attempts,
        "visible_monotonic_ns": last_observed_ns if complete_after_deadline else None,
        "complete_after_deadline": complete_after_deadline,
        "missing": [_key_json(key) for key in sorted(last_missing)],
        "query_samples": query_samples,
    }


def _invoke_soak_batch(
    fixture: RunningFixture,
    events: Sequence[tuple[InstalledProject, dict[str, Any], str, str]],
    *,
    batch_id: str,
    tailer: _EvaluationJournalTailer,
    checkpoint_writer: _IncrementalJsonlWriter,
    timeout: float,
    max_workers: int,
) -> tuple[
    list[dict[str, Any]],
    list[ExpectedEvaluation],
    dict[str, list[dict[str, Any]]],
    dict[str, Any],
]:
    expected = _expected_for_events(events, fixture.artifacts)
    expected_key_set_sha256 = _sha256_bytes(
        _canonical_json_bytes(
            [_key_json(key) for key in sorted({item.key for item in expected})]
        )
    )
    expected_by_input: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    for item in expected:
        expected_by_input[item.input_sha256].add(item.key)
    hooks: dict[str, dict[str, Any]] = {}
    submissions: dict[str, int] = {}
    with ThreadPoolExecutor(
        max_workers=min(max_workers, len(events)),
        thread_name_prefix="rap-systems-soak-hooks",
    ) as executor:
        futures = {}
        for project, raw, _text, input_hash in events:
            submissions[input_hash] = time.perf_counter_ns()
            future = executor.submit(
                _invoke_raw, project.wrapper, raw, fixture.environment
            )
            futures[future] = input_hash
        for future in as_completed(futures):
            hooks[futures[future]] = future.result()
    deadline_ns = min(submissions.values()) + int(timeout * 1_000_000_000)
    first_terminal_ns: dict[str, int] = {}
    all_terminal_ns: dict[str, int] = {}
    late_all_terminal_ns: dict[str, int] = {}
    journal_polls = 0
    journal_bytes_read = 0
    journal_records_read = 0
    settle: dict[str, Any] = {
        "attempted": False,
        "complete": False,
        "inflight_evaluations": None,
        "observed_monotonic_ns": None,
    }
    checkpoint_rows: dict[str, list[dict[str, Any]]] = {}
    checkpoint: dict[str, Any] = {
        "batch_id": batch_id,
        "expected_key_set_sha256": expected_key_set_sha256,
        "complete": False,
        "timed_out": True,
        "attempts": 0,
        "visible_monotonic_ns": None,
        "missing": [_key_json(key) for key in sorted({item.key for item in expected})],
        "query_samples": [],
    }
    while True:
        progress = tailer.poll()
        journal_polls += 1
        journal_bytes_read += int(progress["bytes_read"])
        journal_records_read += int(progress["records_read"])
        observed_ns = int(progress["observed_monotonic_ns"])
        within_deadline = observed_ns <= deadline_ns
        for input_hash, keys in expected_by_input.items():
            visible = tailer.terminal_keys.intersection(keys)
            if within_deadline and visible and input_hash not in first_terminal_ns:
                first_terminal_ns[input_hash] = observed_ns
            if keys.issubset(tailer.terminal_keys):
                if within_deadline and input_hash not in all_terminal_ns:
                    all_terminal_ns[input_hash] = observed_ns
                elif not within_deadline:
                    late_all_terminal_ns.setdefault(input_hash, observed_ns)
        if not within_deadline:
            break
        if len(all_terminal_ns) == len(expected_by_input):
            settle["attempted"] = True
            settle["started_monotonic_ns"] = time.perf_counter_ns()
            remaining = max(0.0, (deadline_ns - time.perf_counter_ns()) / 1e9)
            time.sleep(min(SOAK_BATCH_SETTLE_SECONDS, remaining))
            settle_progress = tailer.poll()
            journal_polls += 1
            journal_bytes_read += int(settle_progress["bytes_read"])
            journal_records_read += int(settle_progress["records_read"])
            settle_ns = int(settle_progress["observed_monotonic_ns"])
            settle_complete = bool(
                settle_ns <= deadline_ns
                and {item.key for item in expected}.issubset(tailer.terminal_keys)
                and not tailer.started
                and not tailer.outcomes_before_start
            )
            settle.update(
                {
                    "complete": settle_complete,
                    "observed_monotonic_ns": settle_ns,
                    "inflight_evaluations": int(
                        settle_progress["inflight_evaluations"]
                    ),
                    "within_deadline": settle_ns <= deadline_ns,
                    "settle_seconds": SOAK_BATCH_SETTLE_SECONDS,
                }
            )
            if not settle_complete:
                break
            checkpoint_rows, checkpoint = _soak_history_checkpoint(
                fixture.projects,
                expected,
                batch_id=batch_id,
                deadline_ns=deadline_ns,
                writer=checkpoint_writer,
            )
            break
        now_ns = time.perf_counter_ns()
        if now_ns >= deadline_ns:
            break
        time.sleep(
            min(
                SOAK_JOURNAL_POLL_INTERVAL_SECONDS,
                max(0.0, (deadline_ns - now_ns) / 1_000_000_000),
            )
        )
    checkpoint_ns = checkpoint.get("visible_monotonic_ns")
    checkpoint_within_deadline = bool(
        checkpoint.get("complete")
        and checkpoint_ns is not None
        and int(checkpoint_ns) <= deadline_ns
    )
    single_rotation_volume_exceeded = (
        journal_bytes_read >= EVALUATION_JOURNAL_ROTATION_BYTES
    )
    samples = []
    for project, raw, _text, input_hash in events:
        submitted_ns = submissions[input_hash]
        hook = hooks[input_hash]
        journal_ns = all_terminal_ns.get(input_hash)
        checkpoint_latency_ns = (
            int(checkpoint_ns) - submitted_ns if checkpoint_within_deadline else None
        )
        censor_ns = max(0, deadline_ns - submitted_ns)
        hook_latency_ns = int(hook["exited_ns"]) - int(hook["started_ns"])
        samples.append(
            {
                "batch_id": batch_id,
                "expected_key_set_sha256": expected_key_set_sha256,
                "case_id": raw["tool_input"]["_rap_systems_probe"]["case_id"],
                "project_root": str(project.root),
                "input_sha256": input_hash,
                "submitted_monotonic_ns": submitted_ns,
                "hook_started_monotonic_ns": int(hook["started_ns"]),
                "hook_exited_monotonic_ns": int(hook["exited_ns"]),
                "censor_deadline_monotonic_ns": deadline_ns,
                "hook_exit_ns": hook_latency_ns,
                "soak_journal_terminal_observed_monotonic_ns": journal_ns,
                "soak_journal_terminal_latency_ns": (
                    int(journal_ns) - submitted_ns if journal_ns is not None else None
                ),
                "soak_batch_history_checkpoint_monotonic_ns": (
                    checkpoint_ns if checkpoint_within_deadline else None
                ),
                "soak_batch_history_checkpoint_after_deadline_monotonic_ns": (
                    checkpoint_ns
                    if checkpoint_ns is not None and not checkpoint_within_deadline
                    else None
                ),
                "event_to_all_query_visible_evaluations_ns": checkpoint_latency_ns,
                "latency_censored_at_ns": (
                    None if checkpoint_latency_ns is not None else censor_ns
                ),
                "hook_exit_ms": round(hook_latency_ns / 1_000_000, 3),
                "event_to_all_query_visible_evaluations_ms": (
                    round(checkpoint_latency_ns / 1_000_000, 3)
                    if checkpoint_latency_ns is not None
                    else None
                ),
                "latency_censored_at_ms": (
                    None
                    if checkpoint_latency_ns is not None
                    else round(censor_ns / 1_000_000, 3)
                ),
                "hook": _hook_projection(hook),
            }
        )
    latest_hook_exit_ns = max(int(item["exited_ns"]) for item in hooks.values())
    queue_drain_ns = (
        max(0, int(checkpoint_ns) - latest_hook_exit_ns)
        if checkpoint_within_deadline
        else None
    )
    return (
        samples,
        expected,
        checkpoint_rows,
        {
            "batch_id": batch_id,
            "expected_key_set_sha256": expected_key_set_sha256,
            "timed_out": not checkpoint_within_deadline,
            "deadline_monotonic_ns": deadline_ns,
            "missing_input_sha256": sorted(
                set(expected_by_input) - set(all_terminal_ns)
            ),
            "journal_polls": journal_polls,
            "journal_bytes_read": journal_bytes_read,
            "journal_records_read": journal_records_read,
            "journal_rotation_bytes": EVALUATION_JOURNAL_ROTATION_BYTES,
            "single_rotation_volume_exceeded_diagnostic": (
                single_rotation_volume_exceeded
            ),
            "journal_terminal_inputs": len(all_terminal_ns),
            "journal_terminal_after_deadline_input_sha256": sorted(
                late_all_terminal_ns
            ),
            "settle": settle,
            "history_checkpoint": {
                key: value
                for key, value in checkpoint.items()
                if key != "query_samples"
            },
            "query_samples": list(checkpoint.get("query_samples") or []),
            "burst_queue_drain_ns": queue_drain_ns,
            "burst_queue_drain_ms": (
                round(queue_drain_ns / 1_000_000, 3)
                if queue_drain_ns is not None
                else None
            ),
            "workload_wall_ns": (
                int(checkpoint_ns) - min(submissions.values())
                if checkpoint_within_deadline
                else max(0, deadline_ns - min(submissions.values()))
            ),
        },
    )


def run_soak(
    artifacts: Sequence[RuleArtifact],
    *,
    rule_count: int,
    project_count: int,
    event_count: int,
    batch_size: int,
    warmups_per_project: int,
    timeout: float,
    drain_timeout: float | None = None,
    max_hook_workers: int,
    strict: bool = True,
    retained_root: Path | None = None,
) -> dict[str, Any]:
    selected = tuple(artifacts[:rule_count])
    drain_timeout = drain_timeout or timeout
    if batch_size * rule_count >= EVALUATION_HISTORY_LIMIT:
        raise ValueError("soak batch is too large for exact online accounting")
    with _running_fixture(
        selected,
        project_count,
        retained_root=retained_root,
        component="soak",
        unit_id=f"soak-r{rule_count}-p{project_count}",
    ) as fixture:
        _warm_fixture(fixture, warmups_per_project, timeout)
        baseline_rows = {
            str(project.root): _full_evaluation_history(project.root)
            for project in fixture.projects
        }
        baseline_evaluation_ids = {
            str(row.get("evaluation_id", ""))
            for rows in baseline_rows.values()
            for row in rows
        }
        baseline_finding_ids = {
            int(finding.get("finding_id", finding.get("id")))
            for project in fixture.projects
            for finding in _full_findings(project.root)
            if finding.get("finding_id", finding.get("id")) is not None
        }
        resources_before = _process_tree_snapshot(fixture.daemon.pid)
        storage_before = _storage_snapshot(fixture)
        batches = []
        batch_accounting_sums: Counter[str] = Counter()
        batch_finding_accounting_sums: Counter[str] = Counter()
        all_hook_ns: list[int] = []
        all_samples: list[dict[str, Any]] = []
        all_expected: list[ExpectedEvaluation] = []
        query_samples: list[dict[str, Any]] = []
        resource_checkpoints: list[dict[str, Any]] = []
        unresolved_batch_expected: list[ExpectedEvaluation] = []
        unresolved_batch_id: str | None = None
        batch_drain_failed = False
        started_ns = time.perf_counter_ns()
        started_wall = time.time()
        seen_finding_ids = set(baseline_finding_ids)
        with (
            _ResourceSampler(
                fixture.daemon.pid,
                journal_path=fixture.isolated_root / "soak-resource-samples.jsonl",
                keep_full_samples=not fixture.retained,
            ) as sampler,
            _EvaluationJournalTailer(
                fixture.projects,
                fixture.isolated_root / "soak-journal-progress.jsonl",
            ) as tailer,
            _IncrementalJsonlWriter(
                fixture.isolated_root / "soak-history-checkpoints.jsonl",
                fsync_every=1,
            ) as checkpoint_writer,
            _IncrementalJsonlWriter(
                fixture.isolated_root / "soak-event-samples.jsonl",
            ) as event_writer,
        ):
            offset = 0
            while offset < event_count:
                size = min(batch_size, event_count - offset)
                condition_id = f"soak-r{rule_count}-p{project_count}-offset{offset}"
                events = _build_events(fixture, condition_id, size)
                batch_wall = time.time()
                samples, expected, rows, wait = _invoke_soak_batch(
                    fixture,
                    events,
                    batch_id=condition_id,
                    tailer=tailer,
                    checkpoint_writer=checkpoint_writer,
                    timeout=drain_timeout,
                    max_workers=max_hook_workers,
                )
                findings = {
                    str(project.root): _full_findings(project.root)
                    for project in fixture.projects
                }
                accounting = account_evaluations(
                    rows,
                    expected,
                    selected,
                    started_wall_time=batch_wall,
                )
                accounting["findings"] = account_findings(
                    findings,
                    rows,
                    expected,
                    baseline_finding_ids=seen_finding_ids,
                )
                seen_finding_ids.update(
                    int(finding.get("finding_id", finding.get("id")))
                    for project_findings in findings.values()
                    for finding in project_findings
                    if finding.get("finding_id", finding.get("id")) is not None
                )
                for name in (
                    "evaluations_expected",
                    "evaluations_observed_for_expected_keys",
                    "loss_count",
                    "duplicate_count",
                    "unexpected_count",
                    "cross_project_contamination_count",
                    "failed_count",
                    "running_count",
                    "provenance_mismatch_count",
                ):
                    batch_accounting_sums[name] += int(accounting.get(name, 0))
                for name in (
                    "findings_expected",
                    "findings_observed_for_expected_keys",
                    "loss_count",
                    "duplicate_count",
                    "unexpected_count",
                    "wrong_project_count",
                    "finding_id_mismatch_count",
                    "evaluation_id_mismatch_count",
                ):
                    batch_finding_accounting_sums[name] += int(
                        accounting["findings"].get(name, 0)
                    )
                all_hook_ns.extend(int(item["hook_exit_ns"]) for item in samples)
                all_samples.extend(samples)
                all_expected.extend(expected)
                for sample in samples:
                    event_writer.append(sample)
                query_samples.extend(wait.get("query_samples", []))
                checkpoint = _process_tree_snapshot(fixture.daemon.pid)
                checkpoint.update(
                    {
                        "cumulative_events": offset + size,
                        "observed_monotonic_ns": time.perf_counter_ns(),
                        "observed_utc": datetime.now(timezone.utc).isoformat(),
                    }
                )
                resource_checkpoints.append(checkpoint)
                batches.append(
                    {
                        "batch_id": condition_id,
                        "expected_key_set_sha256": wait["expected_key_set_sha256"],
                        "offset": offset,
                        "events": size,
                        "accounting": accounting,
                        "wait": {
                            key: value
                            for key, value in wait.items()
                            if key != "query_samples"
                        },
                        "evaluation_history_query": _summary_ns(
                            [
                                int(item["latency_ns"])
                                for item in wait.get("query_samples", [])
                            ]
                        )
                        if wait.get("query_samples")
                        else {"unit": "ns", "count": 0, "available": False},
                    }
                )
                offset += size
                if wait.get("timed_out"):
                    # Never submit a later batch while this serialized worker still
                    # has a backlog.  The batch deadline is a retained system result.
                    batch_drain_failed = True
                    unresolved_batch_expected = list(expected)
                    unresolved_batch_id = condition_id
                    break
            final_drain_started_ns = time.perf_counter_ns()
            final_drain_deadline_ns = final_drain_started_ns + int(
                drain_timeout * 1_000_000_000
            )
            if unresolved_batch_expected:
                unresolved_keys = {item.key for item in unresolved_batch_expected}
                final_checkpoint: dict[str, Any] | None = None
                final_checkpoint_rows: dict[str, list[dict[str, Any]]] = {}
                final_journal_polls = 0
                while time.perf_counter_ns() < final_drain_deadline_ns:
                    tailer.poll()
                    final_journal_polls += 1
                    if unresolved_keys.issubset(tailer.terminal_keys):
                        (
                            final_checkpoint_rows,
                            final_checkpoint,
                        ) = _soak_history_checkpoint(
                            fixture.projects,
                            unresolved_batch_expected,
                            batch_id=str(unresolved_batch_id),
                            deadline_ns=final_drain_deadline_ns,
                            writer=checkpoint_writer,
                        )
                        break
                    time.sleep(
                        min(
                            SOAK_JOURNAL_POLL_INTERVAL_SECONDS,
                            max(
                                0.0,
                                (final_drain_deadline_ns - time.perf_counter_ns())
                                / 1_000_000_000,
                            ),
                        )
                    )
                if final_checkpoint is None:
                    final_checkpoint = {
                        "batch_id": str(unresolved_batch_id),
                        "expected_key_set_sha256": _sha256_bytes(
                            _canonical_json_bytes(
                                [_key_json(key) for key in sorted(unresolved_keys)]
                            )
                        ),
                        "complete": False,
                        "timed_out": True,
                        "attempts": 0,
                        "visible_monotonic_ns": None,
                        "missing": [
                            _key_json(key)
                            for key in sorted(unresolved_keys - tailer.terminal_keys)
                        ],
                        "query_samples": [],
                    }
                query_samples.extend(final_checkpoint.get("query_samples", []))
                final_drain_wait = {
                    "timed_out": not bool(final_checkpoint.get("complete")),
                    "missing_input_sha256": sorted(
                        {key[1] for key in unresolved_keys - tailer.terminal_keys}
                    ),
                    "deadline_monotonic_ns": final_drain_deadline_ns,
                    "last_observed_monotonic_ns": (
                        final_checkpoint.get("visible_monotonic_ns")
                        or time.perf_counter_ns()
                    ),
                    "journal_polls": final_journal_polls,
                    "history_checkpoint": {
                        key: value
                        for key, value in final_checkpoint.items()
                        if key != "query_samples"
                    },
                    "checkpoint_rows": sum(
                        len(rows) for rows in final_checkpoint_rows.values()
                    ),
                    "query_samples": list(final_checkpoint.get("query_samples") or []),
                }
            else:
                final_drain_wait = {
                    "timed_out": False,
                    "missing_input_sha256": [],
                    "deadline_monotonic_ns": final_drain_deadline_ns,
                    "last_observed_monotonic_ns": final_drain_started_ns,
                    "query_samples": [],
                    "proof": (
                        "every bounded batch already reached complete query-visible "
                        "terminal status before the next batch was submitted"
                    ),
                }
            settle_started_ns = time.perf_counter_ns()
            settle_quiescent = False
            settle_progress: dict[str, Any] | None = None
            if not final_drain_wait.get("timed_out"):
                time.sleep(FINAL_DRAIN_SETTLE_SECONDS)
                settle_progress = tailer.poll()
                settle_quiescent = bool(
                    not tailer.started and not tailer.outcomes_before_start
                )
            settle_finished_ns = time.perf_counter_ns()
            drain_observation_finished_ns = int(
                (settle_progress or {}).get("observed_monotonic_ns")
                or settle_finished_ns
            )
            post_drain_snapshot_started_ns = time.perf_counter_ns()
            post_drain_resources = _process_tree_snapshot(fixture.daemon.pid)
            post_drain_snapshot_finished_ns = time.perf_counter_ns()
            final_drain_wait["final_settle"] = {
                "seconds": (
                    FINAL_DRAIN_SETTLE_SECONDS
                    if not final_drain_wait.get("timed_out")
                    else None
                ),
                "started_monotonic_ns": settle_started_ns,
                "finished_monotonic_ns": settle_finished_ns,
                "quiescent": settle_quiescent,
                "progress": settle_progress,
                "post_drain_snapshot_started_monotonic_ns": (
                    post_drain_snapshot_started_ns
                ),
                "post_drain_snapshot_finished_monotonic_ns": (
                    post_drain_snapshot_finished_ns
                ),
            }
            journal_reachability = tailer.named_inode_reachability()
            # The tailer's persistent descriptors preserve expected terminal keys
            # even when an old rotated inode is no longer named.  Detailed global
            # counts come from the already retained bounded-batch checkpoints.
            final_journal_rows = {
                str(project.root): _full_evaluation_history(project.root)
                for project in fixture.projects
            }
            expected_union = {item.key for item in all_expected}
            final_journal_terminal = tailer.terminal_keys.intersection(expected_union)
            final_journal_findings = {
                str(project.root): _full_findings(project.root)
                for project in fixture.projects
            }
            if journal_reachability["all_discovered_inodes_still_named"]:
                final_journal_accounting = account_evaluations(
                    final_journal_rows,
                    all_expected,
                    selected,
                    started_wall_time=started_wall,
                    baseline_evaluation_ids=baseline_evaluation_ids,
                )
                final_journal_accounting["findings"] = account_findings(
                    final_journal_findings,
                    final_journal_rows,
                    all_expected,
                    baseline_finding_ids=baseline_finding_ids,
                )
                final_accounting_source = "all_discovered_inodes_still_named"
            else:
                final_journal_accounting = {
                    **dict(batch_accounting_sums),
                    "expected_keys_observed": (
                        len(expected_union)
                        - int(batch_accounting_sums.get("loss_count", 0))
                    ),
                    "result_counts": {},
                    "details": (
                        "exact per-batch detail is retained in batches; an older "
                        "held inode is no longer name-addressable for reprojection"
                    ),
                    "findings": dict(batch_finding_accounting_sums),
                }
                final_accounting_source = (
                    "cumulative_bounded_batch_checkpoints_plus_persistent_terminal_keys"
                )
            final_journal_missing = sorted(
                _key_json(key) for key in expected_union - final_journal_terminal
            )
            journal_union_complete = not final_journal_missing
            final_drain_wait["full_journal_accounting"] = {
                "expected_terminal_tuples": len(expected_union),
                "observed_terminal_tuples": len(
                    final_journal_terminal.intersection(expected_union)
                ),
                "missing": final_journal_missing,
                "complete": journal_union_complete,
                "accounting": final_journal_accounting,
                "accounting_source": final_accounting_source,
                "journal_inode_reachability": journal_reachability,
            }
            true_drain_complete = bool(
                not final_drain_wait.get("timed_out")
                and journal_union_complete
                and settle_quiescent
            )
            journal_scan_finished_ns = time.perf_counter_ns()
            true_drain_finished_ns = drain_observation_finished_ns
            final_drain_wait["full_journal_scan_finished_monotonic_ns"] = (
                journal_scan_finished_ns
            )
            final_drain_wait["journal_scan_excluded_from_rss_window"] = bool(
                journal_scan_finished_ns >= post_drain_snapshot_finished_ns
            )
            restart_eligible = bool(
                true_drain_complete
                and settle_quiescent
                and not batch_drain_failed
                and offset == event_count
                and _accounting_is_clean(final_journal_accounting)
                and journal_reachability["all_discovered_inodes_still_named"]
            )
        incremental_evidence = {
            "event_samples": event_writer.receipt(),
            "journal_progress": tailer.receipt(),
            "history_checkpoints": checkpoint_writer.receipt(),
            "resource_samples": sampler.journal_receipt(),
            "journal_inode_reachability": journal_reachability,
        }
        finished_ns = time.perf_counter_ns()
        post_scan_resources = _process_tree_snapshot(fixture.daemon.pid)
        storage_after = _storage_snapshot(fixture)
        global_rows = final_journal_rows
        global_findings = final_journal_findings
        global_accounting = final_journal_accounting
        projection_available = bool(
            journal_reachability["all_discovered_inodes_still_named"]
        )
        before_restart_bytes: bytes | None = None
        before_restart_receipt: dict[str, Any] | None = None
        if projection_available:
            before_restart_evaluations = {
                root: _canonical_projection_order(
                    [
                        _evaluation_projection(row)
                        for row in rows
                        if str(row.get("evaluation_id", ""))
                        not in baseline_evaluation_ids
                    ]
                )
                for root, rows in global_rows.items()
            }
            before_restart_findings = {
                root: _canonical_projection_order(
                    [
                        _finding_projection(Path(root), finding)
                        for finding in findings
                        if int(finding.get("finding_id", finding.get("id", -1)))
                        not in baseline_finding_ids
                    ]
                )
                for root, findings in global_findings.items()
            }
            before_restart_bytes = json.dumps(
                {
                    "evaluations": before_restart_evaluations,
                    "findings": before_restart_findings,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            before_restart_receipt = _write_immutable_evidence(
                fixture.isolated_root / "soak-persisted-projection-before-restart.json",
                before_restart_bytes,
            )
        old_identity = fixture.identity
        post_restart_query_receipt: dict[str, Any] | None = None
        if restart_eligible:
            if before_restart_bytes is None:
                raise SystemsHarnessError(
                    "restart was marked eligible without a complete projection"
                )
            integrated._stop_daemon(fixture.daemon)
            _enforce_socket_removed_after_shutdown(
                fixture.environment,
                fixture.isolated_root,
                stage="pre-restart-daemon-shutdown",
            )
            try:
                restarted, restarted_identity = integrated._start_daemon(
                    fixture.environment, fixture.diagnostics, timeout
                )
            except Exception as exc:
                raise SystemViolationError(
                    f"post-soak production daemon restart failed: {exc}"
                ) from None
            fixture.daemon = restarted
            fixture.identity = restarted_identity
            after_restart_rows = {
                str(project.root): _full_evaluation_history(project.root)
                for project in fixture.projects
            }
            after_restart_findings = {
                str(project.root): _full_findings(project.root)
                for project in fixture.projects
            }
            after_restart_bytes = json.dumps(
                {
                    "evaluations": {
                        root: _canonical_projection_order(
                            [
                                _evaluation_projection(row)
                                for row in rows
                                if str(row.get("evaluation_id", ""))
                                not in baseline_evaluation_ids
                            ]
                        )
                        for root, rows in after_restart_rows.items()
                    },
                    "findings": {
                        root: _canonical_projection_order(
                            [
                                _finding_projection(Path(root), finding)
                                for finding in findings
                                if int(finding.get("finding_id", finding.get("id", -1)))
                                not in baseline_finding_ids
                            ]
                        )
                        for root, findings in after_restart_findings.items()
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            after_restart_receipt = _write_immutable_evidence(
                fixture.isolated_root / "soak-persisted-projection-after-restart.json",
                after_restart_bytes,
            )
            with _IncrementalJsonlWriter(
                fixture.isolated_root / "soak-post-restart-history-query.jsonl",
                fsync_every=1,
            ) as post_restart_query_writer:
                history_rows, restart_query = _timed_evaluation_history(
                    fixture.projects[0].root
                )
                post_restart_query_writer.append(restart_query)
            post_restart_query_receipt = post_restart_query_writer.receipt()
            query_samples.append(restart_query)
            restart_sample, restart_accounting = _single_event(
                fixture, "soak-post-restart-recovery", timeout=timeout
            )
            restart_persistence = {
                "status": "completed",
                "old_daemon_identity": old_identity,
                "new_daemon_identity": restarted_identity,
                "persisted_projection_sha256_before": _sha256_bytes(
                    before_restart_bytes
                ),
                "persisted_projection_sha256_after": _sha256_bytes(after_restart_bytes),
                "persisted_projection_before_receipt": before_restart_receipt,
                "persisted_projection_after_receipt": after_restart_receipt,
                "exact_projection_bytes_preserved": (
                    before_restart_bytes == after_restart_bytes
                ),
                "first_project_history_rows_query_visible": len(history_rows),
                "history_query": restart_query,
                "post_restart_event": restart_sample,
                "post_restart_accounting": restart_accounting,
            }
        else:
            after_restart_rows = global_rows
            after_restart_findings = global_findings
            restart_persistence = {
                "status": "not_applicable",
                "reason": (
                    "restart persistence is not measured until every planned soak "
                    "event has been submitted and the complete expected tuple set has "
                    "reached a true terminal drain with all journal inodes still named"
                ),
                "old_daemon_identity": old_identity,
                "new_daemon_identity": None,
                "persisted_projection_sha256_before": (
                    _sha256_bytes(before_restart_bytes)
                    if before_restart_bytes is not None
                    else None
                ),
                "persisted_projection_sha256_after": None,
                "persisted_projection_before_receipt": before_restart_receipt,
                "persisted_projection_after_receipt": None,
                "exact_projection_bytes_preserved": None,
                "post_restart_event": None,
                "post_restart_accounting": None,
            }
        if post_restart_query_receipt is not None:
            incremental_evidence["post_restart_history_query"] = (
                post_restart_query_receipt
            )
        failure = any(global_accounting.get(key) for key in ACCOUNTING_FAILURE_KEYS)
        finding_failure = any(
            global_accounting["findings"].get(key)
            for key in (
                "loss_count",
                "duplicate_count",
                "unexpected_count",
                "wrong_project_count",
                "finding_id_mismatch_count",
                "evaluation_id_mismatch_count",
            )
        )
        restart_failure = (
            restart_persistence.get("status") != "completed"
            or not restart_persistence.get("exact_projection_bytes_preserved")
            or not bool(
                (
                    (restart_persistence.get("post_restart_event") or {}).get("hook")
                    or {}
                ).get("contract_preserved")
            )
            or not _accounting_is_clean(
                restart_persistence.get("post_restart_accounting")
            )
        )
        system_violation = bool(
            failure
            or finding_failure
            or batch_drain_failed
            or not true_drain_complete
            or offset != event_count
            or restart_failure
        )
        first_submission_ns = min(
            (int(item["submitted_monotonic_ns"]) for item in all_samples),
            default=started_ns,
        )
        rss_window = [
            item
            for item in sampler.rss_points
            if first_submission_ns
            <= int(item["observed_monotonic_ns"])
            <= true_drain_finished_ns
        ]
        return {
            "status": "system_violation" if system_violation else "completed",
            "rule_count": rule_count,
            "project_count": project_count,
            "events": event_count,
            "events_submitted": offset,
            "events_not_submitted_after_drain_timeout": event_count - offset,
            "batch_size": batch_size,
            "fresh_daemon": True,
            "wall_seconds": round((finished_ns - started_ns) / 1_000_000_000, 3),
            "hook_process_exit": _summary_ns(all_hook_ns),
            "event_to_all_query_visible_evaluations": _latency_summary(
                all_samples, "event_to_all_query_visible_evaluations_ms"
            ),
            "evaluation_history_query": _summary_ns(
                [int(item["latency_ns"]) for item in query_samples]
            ),
            "query_samples": query_samples if not fixture.retained else [],
            "incremental_evidence": incremental_evidence,
            "global_accounting": global_accounting,
            "batch_accounting_diagnostic_sums_not_global": dict(batch_accounting_sums),
            "post_drain": {
                "status": "completed" if true_drain_complete else "not_applicable",
                "final_drain_timeout_seconds": drain_timeout,
                "final_drain_started_monotonic_ns": final_drain_started_ns,
                "true_drain_finished_monotonic_ns": true_drain_finished_ns,
                "final_drain_wait": {
                    key: value
                    for key, value in final_drain_wait.items()
                    if key != "query_samples"
                },
                "settle_seconds": (
                    FINAL_DRAIN_SETTLE_SECONDS
                    if not final_drain_wait.get("timed_out")
                    else None
                ),
                "settle_actual_ns": settle_finished_ns - settle_started_ns,
                "settle_started_monotonic_ns": settle_started_ns,
                "settle_finished_monotonic_ns": settle_finished_ns,
                "snapshot_started_monotonic_ns": post_drain_snapshot_started_ns,
                "snapshot_finished_monotonic_ns": post_drain_snapshot_finished_ns,
                "rss_bytes": int(post_drain_resources["rss_bytes"]),
                "process_tree": post_drain_resources,
            },
            "resources": {
                "before": resources_before,
                "after": post_drain_resources,
                "post_scan_diagnostic_not_used_for_claims": post_scan_resources,
                "peak_sampled_rss_bytes": max(
                    (int(item["rss_bytes"]) for item in rss_window),
                    default=max(
                        int(resources_before["rss_bytes"]),
                        int(sampler.peak_rss_bytes),
                    ),
                ),
                "sample_count": sampler.sample_count,
                "rss_change_bytes": int(post_drain_resources["rss_bytes"])
                - int(resources_before["rss_bytes"]),
                "rss_change_bytes_per_event": (
                    round(
                        (
                            int(post_drain_resources["rss_bytes"])
                            - int(resources_before["rss_bytes"])
                        )
                        / offset,
                        6,
                    )
                    if offset
                    else None
                ),
                "rss_change_bytes_per_event_denominator": {
                    "field": "events_submitted",
                    "value": offset,
                },
                "rss_slope": _rss_slope(rss_window),
                "rss_slope_window": {
                    "start_first_submission_monotonic_ns": first_submission_ns,
                    "end_true_drain_monotonic_ns": true_drain_finished_ns,
                },
                "timestamped_samples": (rss_window if not fixture.retained else []),
                "timestamped_samples_receipt": sampler.journal_receipt(),
                "batch_checkpoints": resource_checkpoints,
                "cpu_seconds_delta": round(
                    max(
                        0.0,
                        float(post_drain_resources["cpu_seconds"])
                        - float(resources_before["cpu_seconds"]),
                    ),
                    6,
                ),
            },
            "restart_persistence": restart_persistence,
            "storage": {
                "before": storage_before,
                "after": storage_after,
                "delta": _storage_delta(storage_before, storage_after),
            },
            "batches": batches,
            "evidence": _fixture_evidence(
                fixture,
                after_restart_rows,
                after_restart_findings,
                include_records=not fixture.retained,
            ),
        }


def _network_blocker_source() -> str:
    return """import json
import os
import socket
import time

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_send = socket.socket.send
_real_sendall = socket.socket.sendall
_real_sendto = socket.socket.sendto
_real_sendmsg = getattr(socket.socket, "sendmsg", None)
_real_create_connection = socket.create_connection

def _append(path, value):
    if path:
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(value) + "\\n")
        except OSError:
            pass

_append(os.environ.get("RAP_OFFLINE_ACTIVATION_LOG", ""), {
    "kind": "sitecustomize_loaded", "pid": os.getpid(), "time": time.time(),
})

def _record(api, family, address):
    path = os.environ.get("RAP_OFFLINE_BLOCK_LOG", "")
    _append(path, {
        "pid": os.getpid(), "time": time.time(), "api": api,
        "family": int(family), "address": repr(address),
    })

def _blocked(sock, address, api):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        _record(api, sock.family, address)
        raise OSError("RAP systems offline probe blocked an Internet socket")

def _connect(sock, address):
    _blocked(sock, address, "socket.socket.connect")
    return _real_connect(sock, address)

def _connect_ex(sock, address):
    _blocked(sock, address, "socket.socket.connect_ex")
    return _real_connect_ex(sock, address)

def _send(sock, data, *args, **kwargs):
    _blocked(sock, None, "socket.socket.send")
    return _real_send(sock, data, *args, **kwargs)

def _sendall(sock, data, *args, **kwargs):
    _blocked(sock, None, "socket.socket.sendall")
    return _real_sendall(sock, data, *args, **kwargs)

def _sendto(sock, data, *args, **kwargs):
    address = args[-1] if args else kwargs.get("address")
    _blocked(sock, address, "socket.socket.sendto")
    return _real_sendto(sock, data, *args, **kwargs)

def _sendmsg(sock, buffers, *args, **kwargs):
    address = args[-1] if args else kwargs.get("address")
    _blocked(sock, address, "socket.socket.sendmsg")
    return _real_sendmsg(sock, buffers, *args, **kwargs)

def _create_connection(address, *args, **kwargs):
    _record("socket.create_connection", socket.AF_UNSPEC, address)
    raise OSError("RAP systems offline probe blocked socket.create_connection")

socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex
socket.socket.send = _send
socket.socket.sendall = _sendall
socket.socket.sendto = _sendto
if _real_sendmsg is not None:
    socket.socket.sendmsg = _sendmsg
socket.create_connection = _create_connection
"""


def _network_blocker(root: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    blocker = root / "offline-python"
    blocker.mkdir()
    log_path = root / "blocked-network.jsonl"
    activation_path = root / "offline-boundary-activation.jsonl"
    source_receipt = _write_immutable_evidence(
        blocker / "sitecustomize.py", _network_blocker_source().encode("utf-8")
    )
    return blocker, log_path, activation_path, source_receipt


def _python_socket_boundary() -> dict[str, Any]:
    return {
        "id": PYTHON_SOCKET_BOUNDARY_ID,
        "mechanism": "CPython sitecustomize monkeypatch inherited by Python children",
        "blocked_families": ["AF_INET", "AF_INET6"],
        "blocked_apis": [
            "socket.socket.connect",
            "socket.socket.connect_ex",
            "socket.socket.send",
            "socket.socket.sendall",
            "socket.socket.sendto",
            "socket.socket.sendmsg when available",
            "socket.create_connection",
        ],
        "allowed": ["AF_UNIX local sockets"],
        "outside_boundary": [
            "native libraries or subprocesses that make socket syscalls without CPython socket APIs",
            "non-Python processes",
        ],
        "advisory_environment_flags": ["HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"],
    }


def _persisted_predictions(
    rows_by_project: dict[str, list[dict[str, Any]]],
    *,
    project: Path,
    input_sha256: str,
    rule_ids: Sequence[str],
) -> dict[str, Any]:
    rows = [
        row
        for row in rows_by_project.get(str(project), [])
        if _input_hash_from_row(row) == input_sha256
        and str((row.get("rule") or {}).get("id", "")) in set(rule_ids)
        and str(row.get("status", "")) in ("completed", "failed")
    ]
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_rule[str((row.get("rule") or {}).get("id", ""))].append(row)
    values = {}
    for rule_id in rule_ids:
        matching = by_rule.get(rule_id, [])
        if len(matching) != 1:
            values[rule_id] = {
                "status": "missing" if not matching else "duplicate",
                "terminal_rows": len(matching),
                "error_code": None,
                "persisted_prediction_utf8_present": False,
                "persisted_prediction_utf8_hex": None,
                "persisted_prediction_utf8_sha256": None,
            }
            continue
        row = matching[0]
        outcome = dict(row.get("outcome") or {})
        prediction_present = "result" in outcome and outcome.get("result") is not None
        persisted = (
            str(outcome["result"]).encode("utf-8") if prediction_present else None
        )
        values[rule_id] = {
            "status": str(row.get("status", "")),
            "terminal_rows": 1,
            "error_code": outcome.get("error_code"),
            "persisted_prediction_utf8_present": prediction_present,
            "persisted_prediction_utf8_hex": (
                persisted.hex() if persisted is not None else None
            ),
            "persisted_prediction_utf8_sha256": (
                _sha256_bytes(persisted) if persisted is not None else None
            ),
        }
    return values


def compare_persisted_predictions(
    online: dict[str, Any], offline: dict[str, Any]
) -> dict[str, Any]:
    rule_ids = sorted(set(online) | set(offline))
    mismatches = []
    for rule_id in rule_ids:
        left = online.get(rule_id)
        right = offline.get(rule_id)
        invalid_fields = []
        for arm, record in (("online", left), ("offline", right)):
            if not isinstance(record, dict):
                invalid_fields.append(f"{arm}.record_missing")
                continue
            if record.get("status") != "completed":
                invalid_fields.append(f"{arm}.status")
            if record.get("terminal_rows") != 1:
                invalid_fields.append(f"{arm}.terminal_rows")
            if record.get("persisted_prediction_utf8_present") is not True:
                invalid_fields.append(f"{arm}.persisted_prediction_utf8_present")
        if left != right or invalid_fields:
            fields = sorted(
                key
                for key in set((left or {}).keys()) | set((right or {}).keys())
                if (left or {}).get(key) != (right or {}).get(key)
            )
            mismatches.append(
                {
                    "rule_id": rule_id,
                    "differing_fields": sorted([*fields, *invalid_fields]),
                    "online": left,
                    "offline": right,
                }
            )
    return {
        "comparison_unit": "persisted_prediction_utf8_and_terminal_status",
        "rule_count": len(rule_ids),
        "exactly_equal": not mismatches,
        "mismatches": mismatches,
        "first_difference": mismatches[0] if mismatches else None,
    }


def _offline_arm_system_violation(
    wait: Mapping[str, Any],
    accounting: Mapping[str, Any],
    sample: Mapping[str, Any] | None,
) -> bool:
    hook_ok = bool(sample and (sample.get("hook") or {}).get("contract_preserved"))
    return bool(
        wait.get("timed_out")
        or wait.get("integrity_violation")
        or not _accounting_is_clean(accounting)
        or not hook_ok
    )


def run_offline_after_prepare(
    artifacts: Sequence[RuleArtifact],
    *,
    rule_count: int,
    timeout: float,
    retained_root: Path | None = None,
) -> dict[str, Any]:
    selected = tuple(artifacts[:rule_count])
    with _fixture_directory(retained_root) as isolated_root:
        socket_base_environment = dict(os.environ)
        socket_base_environment["RAP_STATE_DIR"] = str(isolated_root / "state")
        with (
            _unit_socket_environment(
                isolated_root,
                socket_base_environment,
                component="offline",
                unit_id="online-offline-exact-replay",
            ),
            integrated._isolated_environment(isolated_root) as base_environment,
        ):
            base_environment = _subprocess_environment(base_environment)
            projects = _install_projects(isolated_root, selected, 2)
            online_diagnostics = isolated_root / "online-daemon-output.log"
            try:
                online, online_identity = integrated._start_daemon(
                    base_environment, online_diagnostics, timeout
                )
            except Exception as exc:
                raise SystemViolationError(
                    f"online prepared daemon did not become ready: {exc}"
                ) from None
            online_fixture = RunningFixture(
                isolated_root,
                dict(base_environment),
                [projects[0]],
                selected,
                online_diagnostics,
                online,
                online_identity,
                retained_root is not None,
            )
            try:
                _warm_fixture(online_fixture, 1, timeout)
                online_baseline_evaluation_ids = {
                    str(row.get("evaluation_id", ""))
                    for row in _full_evaluation_history(projects[0].root)
                }
                online_baseline_finding_ids = {
                    int(finding.get("finding_id", finding.get("id")))
                    for finding in _full_findings(projects[0].root)
                    if finding.get("finding_id", finding.get("id")) is not None
                }
                raw_online = _raw_event(
                    projects[0].root,
                    project_index=0,
                    sequence=0,
                    condition_id="offline-exact-replay",
                    tool_input=selected[0].probe_tool_input,
                )
                exact_input = _expected_input(raw_online)
                input_sha256 = _sha256_bytes(exact_input.encode("utf-8"))
                online_event = [(projects[0], raw_online, exact_input, input_sha256)]
                online_wall = time.time()
                online_samples, online_expected, _online_rows, online_wait = (
                    _invoke_event_group(
                        online_fixture,
                        online_event,
                        mode="sequential",
                        timeout=timeout,
                        max_workers=1,
                    )
                )
                online_rows = {
                    str(projects[0].root): _full_evaluation_history(projects[0].root)
                }
                online_findings = {
                    str(projects[0].root): _full_findings(projects[0].root)
                }
                online_accounting = account_evaluations(
                    online_rows,
                    online_expected,
                    selected,
                    started_wall_time=online_wall,
                    baseline_evaluation_ids=online_baseline_evaluation_ids,
                )
                online_accounting["findings"] = account_findings(
                    online_findings,
                    online_rows,
                    online_expected,
                    baseline_finding_ids=online_baseline_finding_ids,
                )
                online_predictions = _persisted_predictions(
                    online_rows,
                    project=projects[0].root,
                    input_sha256=input_sha256,
                    rule_ids=[item.rule_id for item in selected],
                )
                online_evidence = _fixture_evidence(
                    online_fixture, online_rows, online_findings
                )
            finally:
                online_exception = sys.exc_info()[1]
                integrated._stop_daemon(online)
                _enforce_socket_removed_after_shutdown(
                    base_environment,
                    isolated_root,
                    stage="online-daemon-shutdown",
                    active_exception=online_exception,
                )
            blocker, block_log, activation_log, boundary_source_receipt = (
                _network_blocker(isolated_root)
            )
            offline_environment = dict(base_environment)
            offline_environment.update(
                {
                    "PYTHONPATH": str(blocker)
                    + os.pathsep
                    + offline_environment.get("PYTHONPATH", ""),
                    "RAP_OFFLINE_BLOCK_LOG": str(block_log),
                    "RAP_OFFLINE_ACTIVATION_LOG": str(activation_log),
                    "HF_HUB_OFFLINE": "1",
                    "TRANSFORMERS_OFFLINE": "1",
                }
            )
            offline_diagnostics = isolated_root / "offline-daemon-output.log"
            raw_offline = json.loads(json.dumps(raw_online))
            raw_offline["cwd"] = str(projects[1].root)
            # Envelope IDs differ deterministically to avoid duplicate admission;
            # the extracted declared input remains byte-identical.
            raw_offline["session_id"] = f"{raw_online['session_id']}-offline"
            raw_offline["turn_id"] = f"{raw_online['turn_id']}-offline"
            raw_offline["tool_use_id"] = f"{raw_online['tool_use_id']}-offline"
            offline_input = _expected_input(raw_offline)
            offline_hash = _sha256_bytes(offline_input.encode("utf-8"))
            try:
                offline, offline_identity = integrated._start_daemon(
                    offline_environment, offline_diagnostics, timeout
                )
            except Exception as exc:
                blocked_attempts = _jsonl(block_log) if block_log.exists() else []
                activation_records = (
                    _jsonl(activation_log) if activation_log.exists() else []
                )
                try:
                    diagnostic_bytes = offline_diagnostics.read_bytes()
                except OSError:
                    diagnostic_bytes = b""
                offline_predictions = _persisted_predictions(
                    {str(projects[1].root): []},
                    project=projects[1].root,
                    input_sha256=offline_hash,
                    rule_ids=[item.rule_id for item in selected],
                )
                comparison = compare_persisted_predictions(
                    online_predictions, offline_predictions
                )
                input_identity_equal = bool(
                    exact_input.encode("utf-8") == offline_input.encode("utf-8")
                    and input_sha256 == offline_hash
                )
                comparison.update(
                    {
                        "prediction_records_exactly_equal": False,
                        "input_identity_equal": input_identity_equal,
                        "exactly_equal": False,
                    }
                )
                online_hook_ok = bool(
                    online_samples
                    and (online_samples[0].get("hook") or {}).get("contract_preserved")
                )
                return {
                    "status": "system_violation",
                    "prepared_online": True,
                    "fresh_offline_daemon": False,
                    "rule_count": rule_count,
                    "online_daemon_identity": online_identity,
                    "offline_daemon_identity": None,
                    "network_boundary": _python_socket_boundary(),
                    "boundary_source_receipt": boundary_source_receipt,
                    "boundary_activation_records": activation_records,
                    "offline_daemon_boundary_activated": False,
                    "blocked_internet_attempts": len(blocked_attempts),
                    "blocked_attempt_records": blocked_attempts,
                    "exact_declared_input": {
                        "encoding": "UTF-8 rendered as lowercase hexadecimal",
                        "online_utf8_hex": exact_input.encode("utf-8").hex(),
                        "offline_utf8_hex": offline_input.encode("utf-8").hex(),
                        "online_sha256": input_sha256,
                        "offline_sha256": offline_hash,
                        "identical": input_identity_equal,
                    },
                    "online": {
                        "status": (
                            "system_violation"
                            if _offline_arm_system_violation(
                                online_wait,
                                online_accounting,
                                online_samples[0] if online_samples else None,
                            )
                            else "completed"
                        ),
                        "hook_contract_preserved": online_hook_ok,
                        "envelope": _envelope_projection(raw_online),
                        "accounting": online_accounting,
                        "sample": online_samples[0],
                        "wait": {
                            key: value
                            for key, value in online_wait.items()
                            if key != "query_samples"
                        },
                        "persisted_predictions": online_predictions,
                        "evidence": online_evidence,
                    },
                    "offline": {
                        "status": "system_violation",
                        "stage": "daemon_start_under_socket_boundary",
                        "envelope": _envelope_projection(raw_offline),
                        "error": {
                            "type": type(exc).__name__,
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        },
                        "accounting": None,
                        "sample": None,
                        "wait": {"status": "not_applicable"},
                        "persisted_predictions": offline_predictions,
                        "evidence": {
                            "daemon_diagnostics": {
                                "path": str(offline_diagnostics),
                                "bytes": len(diagnostic_bytes),
                                "sha256": _sha256_bytes(diagnostic_bytes),
                                "text": diagnostic_bytes.decode(
                                    "utf-8", errors="replace"
                                ),
                            },
                            "blocked_attempt_records": blocked_attempts,
                            "boundary_activation_records": activation_records,
                        },
                    },
                    "comparison": comparison,
                    "paired_event_to_all_latency": {
                        "online_ns": online_samples[0].get(
                            "event_to_all_query_visible_evaluations_ns"
                        ),
                        "offline_ns": None,
                        "offline_minus_online_ns": None,
                        "descriptive_only": True,
                    },
                    "limitation": (
                        "The offline arm failed at the named CPython socket-boundary "
                        "daemon start; the completed online arm and all available "
                        "offline diagnostics remain part of this measured outcome."
                    ),
                }
            offline_fixture = RunningFixture(
                isolated_root,
                offline_environment,
                [projects[1]],
                selected,
                offline_diagnostics,
                offline,
                offline_identity,
                retained_root is not None,
            )
            try:
                started_wall = time.time()
                events = [(projects[1], raw_offline, offline_input, offline_hash)]
                samples, expected, _rows, offline_wait = _invoke_event_group(
                    offline_fixture,
                    events,
                    mode="sequential",
                    timeout=timeout,
                    max_workers=1,
                )
                rows = {
                    str(projects[1].root): _full_evaluation_history(projects[1].root)
                }
                findings = {str(projects[1].root): _full_findings(projects[1].root)}
                accounting = account_evaluations(
                    rows, expected, selected, started_wall_time=started_wall
                )
                accounting["findings"] = account_findings(findings, rows, expected)
                blocked_attempts = _jsonl(block_log) if block_log.exists() else []
                activation_records = (
                    _jsonl(activation_log) if activation_log.exists() else []
                )
                offline_daemon_boundary_activated = any(
                    record.get("kind") == "sitecustomize_loaded"
                    and record.get("pid") == offline_identity.get("pid")
                    for record in activation_records
                    if isinstance(record, dict)
                )
                offline_predictions = _persisted_predictions(
                    rows,
                    project=projects[1].root,
                    input_sha256=offline_hash,
                    rule_ids=[item.rule_id for item in selected],
                )
                comparison = compare_persisted_predictions(
                    online_predictions, offline_predictions
                )
                online_input_bytes = exact_input.encode("utf-8")
                offline_input_bytes = offline_input.encode("utf-8")
                input_identity_equal = (
                    online_input_bytes == offline_input_bytes
                    and input_sha256 == offline_hash
                )
                comparison["prediction_records_exactly_equal"] = comparison[
                    "exactly_equal"
                ]
                comparison["input_identity_equal"] = input_identity_equal
                comparison["exactly_equal"] = bool(
                    input_identity_equal
                    and comparison["prediction_records_exactly_equal"]
                )
                if not input_identity_equal:
                    comparison["first_difference"] = {
                        "rule_id": None,
                        "differing_fields": ["exact_declared_input_utf8"],
                        "online": {
                            "sha256": input_sha256,
                            "utf8_hex": online_input_bytes.hex(),
                        },
                        "offline": {
                            "sha256": offline_hash,
                            "utf8_hex": offline_input_bytes.hex(),
                        },
                    }
                online_latency_ns = online_samples[0].get(
                    "event_to_all_query_visible_evaluations_ns"
                )
                offline_latency_ns = samples[0].get(
                    "event_to_all_query_visible_evaluations_ns"
                )
                paired_latency = {
                    "online_ns": online_latency_ns,
                    "offline_ns": offline_latency_ns,
                    "offline_minus_online_ns": (
                        int(offline_latency_ns) - int(online_latency_ns)
                        if online_latency_ns is not None
                        and offline_latency_ns is not None
                        else None
                    ),
                    "descriptive_only": True,
                }
                online_hook_ok = bool(
                    online_samples
                    and (online_samples[0].get("hook") or {}).get("contract_preserved")
                )
                offline_hook_ok = bool(
                    samples and (samples[0].get("hook") or {}).get("contract_preserved")
                )
                online_arm_failure = _offline_arm_system_violation(
                    online_wait,
                    online_accounting,
                    online_samples[0] if online_samples else None,
                )
                offline_arm_failure = _offline_arm_system_violation(
                    offline_wait,
                    accounting,
                    samples[0] if samples else None,
                )
                system_failure = bool(
                    online_arm_failure
                    or offline_arm_failure
                    or not offline_daemon_boundary_activated
                    or not input_identity_equal
                    or not comparison["exactly_equal"]
                )
                return {
                    "status": ("system_violation" if system_failure else "completed"),
                    "prepared_online": True,
                    "fresh_offline_daemon": True,
                    "rule_count": rule_count,
                    "online_daemon_identity": online_identity,
                    "offline_daemon_identity": offline_identity,
                    "network_boundary": _python_socket_boundary(),
                    "boundary_source_receipt": boundary_source_receipt,
                    "boundary_activation_records": activation_records,
                    "offline_daemon_boundary_activated": (
                        offline_daemon_boundary_activated
                    ),
                    "blocked_internet_attempts": len(blocked_attempts),
                    "blocked_attempt_records": blocked_attempts,
                    "exact_declared_input": {
                        "encoding": "UTF-8 rendered as lowercase hexadecimal",
                        "online_utf8_hex": online_input_bytes.hex(),
                        "offline_utf8_hex": offline_input_bytes.hex(),
                        "online_sha256": input_sha256,
                        "offline_sha256": offline_hash,
                        "identical": input_identity_equal,
                    },
                    "online": {
                        "status": (
                            "system_violation" if online_arm_failure else "completed"
                        ),
                        "hook_contract_preserved": online_hook_ok,
                        "envelope": _envelope_projection(raw_online),
                        "accounting": online_accounting,
                        "sample": online_samples[0],
                        "wait": {
                            key: value
                            for key, value in online_wait.items()
                            if key != "query_samples"
                        },
                        "persisted_predictions": online_predictions,
                        "evidence": online_evidence,
                    },
                    "offline": {
                        "status": (
                            "system_violation" if offline_arm_failure else "completed"
                        ),
                        "hook_contract_preserved": offline_hook_ok,
                        "envelope": _envelope_projection(raw_offline),
                        "accounting": accounting,
                        "sample": samples[0],
                        "wait": {
                            key: value
                            for key, value in offline_wait.items()
                            if key != "query_samples"
                        },
                        "persisted_predictions": offline_predictions,
                        "evidence": _fixture_evidence(offline_fixture, rows, findings),
                    },
                    "comparison": comparison,
                    "paired_event_to_all_latency": paired_latency,
                    "evidence": {
                        "online": online_evidence,
                        "offline": _fixture_evidence(offline_fixture, rows, findings),
                    },
                    "limitation": (
                        "This is the named CPython socket-API boundary, not an OS "
                        "network namespace. Persisted prediction labels are compared; "
                        "the journal does not expose raw decoder token bytes."
                    ),
                }
            finally:
                offline_exception = sys.exc_info()[1]
                integrated._stop_daemon(offline)
                _enforce_socket_removed_after_shutdown(
                    offline_environment,
                    isolated_root,
                    stage="offline-daemon-shutdown",
                    active_exception=offline_exception,
                )


def _wait_for_any_daemon(timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        details = ipc.ping_details(timeout=0.25)
        if details:
            return details
        time.sleep(0.05)
    raise SystemViolationError("auto-respawned daemon did not become ready")


def _single_event(
    fixture: RunningFixture,
    condition_id: str,
    *,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started_wall = time.time()
    events = _build_events(fixture, condition_id, 1)
    samples, expected, rows, _wait = _invoke_event_group(
        fixture,
        events,
        mode="sequential",
        timeout=timeout,
        max_workers=1,
    )
    accounting = account_evaluations(
        rows, expected, fixture.artifacts, started_wall_time=started_wall
    )
    findings = {
        str(project.root): _full_findings(project.root) for project in fixture.projects
    }
    accounting["findings"] = account_findings(findings, rows, expected)
    return samples[0], accounting


def _hook_projection(hook: dict[str, Any]) -> dict[str, Any]:
    started_ns = int(hook["started_ns"])
    exited_ns = int(hook["exited_ns"])
    latency_ns = exited_ns - started_ns
    return {
        "started_monotonic_ns": started_ns,
        "exited_monotonic_ns": exited_ns,
        "latency_ns": latency_ns,
        "returncode": hook.get("returncode"),
        "stdout": hook.get("stdout", ""),
        "stderr": hook.get("stderr", ""),
        "timed_out": bool(hook.get("timed_out")),
        "contract_preserved": bool(hook.get("contract_preserved")),
        "contract_error": str(hook.get("contract_error", "")),
        "latency_ms": round(latency_ns / 1_000_000, 3),
    }


def _persistent_state_integrity(fixture: RunningFixture) -> dict[str, Any]:
    database = rap_config.db_path()
    database_check: str | None = None
    database_error = ""
    if database.exists():
        try:
            with sqlite3.connect(str(database), timeout=2.0) as connection:
                database_check = str(
                    connection.execute("PRAGMA integrity_check").fetchone()[0]
                )
        except sqlite3.Error as exc:
            database_error = f"{type(exc).__name__}: {exc}"
    journal_errors = []
    for project in fixture.projects:
        for path in (
            rap_config.project_evaluation_log_file(str(project.root)),
            rap_config.project_log_file(str(project.root)),
        ):
            if not path.exists():
                continue
            try:
                _jsonl(path)
            except SystemsHarnessError as exc:
                journal_errors.append(str(exc))
    return {
        "database_present": database.exists(),
        "sqlite_integrity_check": database_check,
        "database_error": database_error,
        "journal_parse_errors": journal_errors,
        "ok": (
            database_check in (None, "ok") and not database_error and not journal_errors
        ),
    }


def _fault_fixture_observations(fixture: RunningFixture) -> dict[str, Any]:
    snapshot = ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
    return {
        "persistent_state_integrity": _persistent_state_integrity(fixture),
        "operator_visible_incidents": list(snapshot.get("health_issues") or []),
        "orphan_process_count": None,
        "orphan_process_count_status": (
            "not_applicable_until_fixture_cleanup; retained process and state evidence "
            "is available for independent inspection"
        ),
        "runtime_evidence": _fixture_evidence(fixture),
    }


def _orphan_processes(retained_root: Path | None) -> dict[str, Any]:
    if retained_root is None:
        return {"processes": None, "scan_errors": [], "race_diagnostics": []}
    expected_state = str(retained_root / "state")
    matches = []
    scan_errors = []
    race_diagnostics = []
    for process in psutil.process_iter(["pid", "uids"]):
        try:
            uids = process.info.get("uids")
            if uids is None:
                uids = process.uids()
            if int(uids.effective) != os.geteuid():
                continue
            if process.environ().get("RAP_STATE_DIR") != expected_state:
                continue
            matches.append(
                {
                    "pid": process.pid,
                    "create_time": process.create_time(),
                    "cmdline": list(process.cmdline() or []),
                }
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess) as exc:
            race_diagnostics.append(
                {
                    "pid": int(getattr(process, "pid", -1)),
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
        except (psutil.AccessDenied, OSError) as exc:
            scan_errors.append(
                {
                    "pid": int(getattr(process, "pid", -1)),
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
    return {
        "processes": sorted(matches, key=lambda item: int(item["pid"])),
        "scan_errors": sorted(
            scan_errors, key=lambda item: (item["pid"], item["type"], item["message"])
        ),
        "race_diagnostics": sorted(
            race_diagnostics,
            key=lambda item: (item["pid"], item["type"], item["message"]),
        ),
    }


def _wait_for_fault_process_cleanup(
    retained_root: Path | None,
    timeout: float,
) -> dict[str, Any]:
    """Retain bounded evidence that every fixture process exited after shutdown."""
    started_ns = time.perf_counter_ns()
    deadline_ns = started_ns + max(0, round(timeout * 1_000_000_000))
    observations: list[dict[str, Any]] = []
    while True:
        query_started_ns = time.perf_counter_ns()
        scan = _orphan_processes(retained_root)
        # Preserve compatibility with focused test doubles while production
        # always emits the complete scan receipt above.
        if isinstance(scan, dict):
            processes = scan.get("processes")
            scan_errors = list(scan.get("scan_errors") or [])
            race_diagnostics = list(scan.get("race_diagnostics") or [])
        else:  # pragma: no cover - compatibility seam for external test doubles
            processes = scan
            scan_errors = []
            race_diagnostics = []
        query_finished_ns = time.perf_counter_ns()
        within_deadline = query_finished_ns <= deadline_ns
        observations.append(
            {
                "query_started_monotonic_ns": query_started_ns,
                "query_finished_monotonic_ns": query_finished_ns,
                "within_deadline": within_deadline,
                "processes": processes,
                "scan_errors": scan_errors,
                "race_diagnostics": race_diagnostics,
            }
        )
        if processes is None:
            return {
                "status": "not_measured_without_retained_runtime_root",
                "started_monotonic_ns": started_ns,
                "deadline_monotonic_ns": deadline_ns,
                "finished_monotonic_ns": query_finished_ns,
                "poll_interval_seconds": QUERY_POLL_INTERVAL_SECONDS,
                "completed_within_deadline": False,
                "observations": observations,
                "final_orphan_processes": None,
                "final_scan_errors": scan_errors,
            }
        if not processes and not scan_errors and within_deadline:
            return {
                "status": "complete",
                "started_monotonic_ns": started_ns,
                "deadline_monotonic_ns": deadline_ns,
                "finished_monotonic_ns": query_finished_ns,
                "poll_interval_seconds": QUERY_POLL_INTERVAL_SECONDS,
                "completed_within_deadline": True,
                "observations": observations,
                "final_orphan_processes": [],
                "final_scan_errors": [],
            }
        if query_finished_ns >= deadline_ns:
            return {
                "status": "timed_out",
                "started_monotonic_ns": started_ns,
                "deadline_monotonic_ns": deadline_ns,
                "finished_monotonic_ns": query_finished_ns,
                "poll_interval_seconds": QUERY_POLL_INTERVAL_SECONDS,
                "completed_within_deadline": False,
                "observations": observations,
                "final_orphan_processes": processes,
                "final_scan_errors": scan_errors,
            }
        remaining = (deadline_ns - query_finished_ns) / 1_000_000_000
        time.sleep(min(QUERY_POLL_INTERVAL_SECONDS, remaining))


def _force_terminate_fault_processes(
    retained_root: Path,
    processes: Sequence[Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """Kill only processes whose retained runtime identity still matches exactly."""
    expected_state_dir = str(retained_root / "state")
    started_ns = time.perf_counter_ns()
    actions: list[dict[str, Any]] = []
    for captured in processes or ():
        pid = int(captured.get("pid", -1))
        captured_create_time = captured.get("create_time")
        action: dict[str, Any] = {
            "pid": pid,
            "captured_create_time": captured_create_time,
            "captured_cmdline": list(captured.get("cmdline") or []),
            "expected_rap_state_dir": expected_state_dir,
            "ownership_confirmed": False,
            "action": "not_sent",
        }
        try:
            process = psutil.Process(pid)
            observed_create_time = process.create_time()
            observed_state_dir = process.environ().get("RAP_STATE_DIR")
            action["observed_create_time"] = observed_create_time
            action["observed_rap_state_dir"] = observed_state_dir
            action["observed_cmdline"] = process.cmdline()
            identity_matches = (
                captured_create_time is not None
                and observed_create_time == captured_create_time
                and observed_state_dir == expected_state_dir
            )
            action["ownership_confirmed"] = identity_matches
            if not identity_matches:
                action["action"] = "skipped_identity_mismatch"
            else:
                process.kill()
                action["action"] = "sigkill_sent"
        except psutil.NoSuchProcess:
            action["action"] = "already_exited"
        except (psutil.AccessDenied, psutil.ZombieProcess, OSError) as exc:
            action["action"] = "kill_error"
            action["error"] = f"{type(exc).__name__}: {exc}"
        actions.append(action)
    finished_ns = time.perf_counter_ns()
    return {
        "status": (
            "completed_with_errors"
            if any(item["action"] == "kill_error" for item in actions)
            else "completed"
        ),
        "started_monotonic_ns": started_ns,
        "finished_monotonic_ns": finished_ns,
        "expected_rap_state_dir": expected_state_dir,
        "actions": actions,
    }


def _fault_cleanup_error(exc: BaseException, stage: str) -> dict[str, Any]:
    now_ns = time.perf_counter_ns()
    return {
        "status": "measurement_error",
        "stage": stage,
        "started_monotonic_ns": now_ns,
        "deadline_monotonic_ns": now_ns,
        "finished_monotonic_ns": now_ns,
        "poll_interval_seconds": QUERY_POLL_INTERVAL_SECONDS,
        "completed_within_deadline": False,
        "observations": [],
        "final_orphan_processes": None,
        "final_scan_errors": [
            {"pid": -1, "type": type(exc).__name__, "message": str(exc)}
        ],
        "error": {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        },
    }


def _settle_and_force_fault_cleanup(
    retained_root: Path | None,
    timeout: float,
) -> dict[str, Any]:
    """Settle, force exact retained processes if needed, and prove isolation."""
    try:
        initial_settle = _wait_for_fault_process_cleanup(retained_root, timeout)
    except BaseException as exc:
        initial_settle = _fault_cleanup_error(exc, "initial_settle")

    force_actions: dict[str, Any] | None = None
    final_settle = initial_settle
    if retained_root is not None and not bool(
        initial_settle.get("completed_within_deadline")
    ):
        force_started_ns = time.perf_counter_ns()
        try:
            force_actions = _force_terminate_fault_processes(
                retained_root,
                initial_settle.get("final_orphan_processes"),
            )
        except BaseException as exc:
            force_finished_ns = time.perf_counter_ns()
            force_actions = {
                "status": "force_error",
                "started_monotonic_ns": force_started_ns,
                "finished_monotonic_ns": force_finished_ns,
                "expected_rap_state_dir": str(retained_root / "state"),
                "actions": [],
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            }
        try:
            final_settle = _wait_for_fault_process_cleanup(retained_root, timeout)
        except BaseException as exc:
            final_settle = _fault_cleanup_error(exc, "post_force_settle")

    final_orphans = final_settle.get("final_orphan_processes")
    final_scan_errors = list(final_settle.get("final_scan_errors") or [])
    measurable = retained_root is not None
    safe_to_continue = not measurable or (
        bool(final_settle.get("completed_within_deadline"))
        and final_orphans == []
        and not final_scan_errors
    )
    return {
        "initial_settle": initial_settle,
        "forced_actions": force_actions,
        "final_settle": final_settle,
        "measurable": measurable,
        "safe_to_continue": safe_to_continue,
        "final_orphan_processes": final_orphans,
        "final_scan_errors": final_scan_errors,
    }


def _attach_fault_cleanup_evidence(
    probe_result: dict[str, Any], cleanup: Mapping[str, Any]
) -> None:
    initial_settle = dict(cleanup["initial_settle"])
    final_settle = dict(cleanup["final_settle"])
    orphan_processes = cleanup.get("final_orphan_processes")
    probe_result["post_shutdown_process_cleanup"] = dict(cleanup)
    probe_result["post_shutdown_process_settle"] = initial_settle
    probe_result["forced_process_cleanup"] = cleanup.get("forced_actions")
    probe_result["post_force_process_settle"] = final_settle
    probe_result["orphan_processes_after_cleanup"] = orphan_processes
    probe_result["orphan_process_count"] = (
        len(orphan_processes) if orphan_processes is not None else None
    )
    probe_result["orphan_process_count_status"] = (
        "measurement incomplete because the final process scan had errors"
        if cleanup.get("final_scan_errors")
        else "measured after bounded post-shutdown fixture cleanup and forced recheck"
        if orphan_processes is not None
        else "not measured without a retained runtime root"
    )


def _fault_daemon_crash(
    artifact: RuleArtifact, timeout: float, retained_root: Path | None = None
) -> dict[str, Any]:
    with _running_fixture((artifact,), 1, retained_root=retained_root) as fixture:
        _warm_fixture(fixture, 1, timeout)
        old_pid = fixture.daemon.pid
        os.killpg(old_pid, signal.SIGKILL)
        fixture.daemon.wait(timeout=3.0)
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="daemon-crash-lost-event",
            tool_input=artifact.probe_tool_input,
        )
        expected_input = _expected_input(raw)
        expected_hash = _sha256_bytes(expected_input.encode("utf-8"))
        hook = _invoke_raw(project.wrapper, raw, fixture.environment)
        respawned = _wait_for_any_daemon(timeout)
        time.sleep(0.2)
        lost_rows = [
            row
            for row in _evaluation_history(project.root)
            if _input_hash_from_row(row) == expected_hash
        ]
        recovery_fixture = RunningFixture(
            fixture.isolated_root,
            fixture.environment,
            fixture.projects,
            fixture.artifacts,
            fixture.diagnostics,
            fixture.daemon,
            respawned,
        )
        recovery_sample, recovery_accounting = _single_event(
            recovery_fixture, "daemon-crash-recovery", timeout=timeout
        )
        return {
            "old_pid": old_pid,
            "new_pid": int(respawned.get("pid", -1)),
            "old_pid_confirmed_dead": not psutil.pid_exists(old_pid),
            "faulting_hook_exit_ms": round(
                (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
            ),
            "faulting_hook_contract_preserved": bool(hook.get("contract_preserved")),
            "faulting_hook": _hook_projection(hook),
            "faulting_event_evaluations": len(lost_rows),
            "faulting_event_expected_loss": len(lost_rows) == 0,
            "interpretation": (
                "An event that cannot reach the daemon is not queued for replay; the "
                "hook fails open and starts a replacement daemon."
            ),
            "recovery": {
                "sample": recovery_sample,
                "accounting": recovery_accounting,
            },
            **_fault_fixture_observations(fixture),
        }


def _fault_worker_exit(
    artifact: RuleArtifact, timeout: float, retained_root: Path | None = None
) -> dict[str, Any]:
    with _running_fixture((artifact,), 1, retained_root=retained_root) as fixture:
        _warm_fixture(fixture, 1, timeout)
        killed = integrated._kill_inference_worker(fixture.daemon.pid)
        sample, accounting = _single_event(
            fixture, "worker-exit-recovery", timeout=timeout
        )
        new_pids = [
            pid
            for _rss, process in integrated._inference_workers(fixture.daemon.pid)
            if (pid := process.pid)
        ]
        return {
            **killed,
            "new_worker_pids": new_pids,
            "old_worker_confirmed_absent": not psutil.pid_exists(
                int(killed["old_worker_pid"])
            ),
            "worker_replaced": killed["old_worker_pid"] not in new_pids
            and bool(new_pids),
            "recovery": {"sample": sample, "accounting": accounting},
            **_fault_fixture_observations(fixture),
        }


def _wait_for_conversation(
    project: Path,
    conversation_id: str,
    timeout: float,
    *,
    require_terminal: bool,
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = next(
            (
                row
                for row in _evaluation_history(project)
                if str(row.get("conversation_id", "")) == conversation_id
            ),
            None,
        )
        if last is not None and (
            not require_terminal
            or str(last.get("status", "")) in ("completed", "failed")
        ):
            return last
        time.sleep(QUERY_POLL_INTERVAL_SECONDS)
    return last


def _wait_for_process_stopped(
    process: psutil.Process,
    *,
    timeout_seconds: float = 2.0,
) -> dict[str, Any]:
    started_ns = time.perf_counter_ns()
    deadline_ns = started_ns + int(timeout_seconds * 1_000_000_000)
    observations: list[dict[str, Any]] = []
    stopped_statuses = {
        psutil.STATUS_STOPPED,
        getattr(psutil, "STATUS_TRACING_STOP", "tracing-stop"),
    }
    while True:
        observed_ns = time.perf_counter_ns()
        try:
            status = process.status()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return {
                "confirmed": False,
                "started_monotonic_ns": started_ns,
                "finished_monotonic_ns": observed_ns,
                "deadline_monotonic_ns": deadline_ns,
                "observations": observations,
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
        observations.append({"observed_monotonic_ns": observed_ns, "status": status})
        if status in stopped_statuses and observed_ns <= deadline_ns:
            return {
                "confirmed": True,
                "started_monotonic_ns": started_ns,
                "finished_monotonic_ns": observed_ns,
                "deadline_monotonic_ns": deadline_ns,
                "observations": observations,
                "error": None,
            }
        if observed_ns >= deadline_ns:
            return {
                "confirmed": False,
                "started_monotonic_ns": started_ns,
                "finished_monotonic_ns": observed_ns,
                "deadline_monotonic_ns": deadline_ns,
                "observations": observations,
                "error": None,
            }
        time.sleep(0.01)


def _fault_worker_timeout(
    artifact: RuleArtifact, timeout: float, retained_root: Path | None = None
) -> dict[str, Any]:
    with _running_fixture((artifact,), 1, retained_root=retained_root) as fixture:
        _warm_fixture(fixture, 1, timeout)
        candidates = integrated._inference_workers(fixture.daemon.pid)
        if not candidates:
            raise SystemViolationError("could not identify worker for timeout probe")
        _rss, worker = max(candidates, key=lambda item: item[0])
        old_pid = worker.pid
        stop_signal_sent_ns = time.perf_counter_ns()
        worker.send_signal(signal.SIGSTOP)
        stopped = _wait_for_process_stopped(worker)
        if not stopped["confirmed"]:
            try:
                if worker.is_running():
                    worker.send_signal(signal.SIGCONT)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            return {
                "old_worker_pid": old_pid,
                "stop_signal_sent_monotonic_ns": stop_signal_sent_ns,
                "old_worker_confirmed_stopped_before_dispatch": False,
                "stop_confirmation": stopped,
                "faulting_hook": None,
                "failed_outcome": {
                    "status": "not_applicable",
                    "error_code": None,
                    "error": "worker stop was not confirmed; no event dispatched",
                },
                "new_worker_pids": [],
                "old_worker_confirmed_absent": False,
                "worker_replaced": False,
                "recovery": {"sample": None, "accounting": None},
                **_fault_fixture_observations(fixture),
            }
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="worker-timeout",
            tool_input=artifact.probe_tool_input,
        )
        started = time.perf_counter_ns()
        try:
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            row = _wait_for_conversation(
                project.root,
                str(raw["session_id"]),
                max(timeout, 12.0),
                require_terminal=True,
            )
        finally:
            try:
                if worker.is_running():
                    worker.send_signal(signal.SIGCONT)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        failed_visible_ns = time.perf_counter_ns()
        recovery_sample, recovery_accounting = _single_event(
            fixture, "worker-timeout-recovery", timeout=max(timeout, 12.0)
        )
        new_pids = [
            process.pid
            for _rss, process in integrated._inference_workers(fixture.daemon.pid)
        ]
        return {
            "old_worker_pid": old_pid,
            "stop_signal_sent_monotonic_ns": stop_signal_sent_ns,
            "old_worker_confirmed_stopped_before_dispatch": True,
            "stop_confirmation": stopped,
            "faulting_hook_exit_ms": round(
                (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
            ),
            "faulting_hook": _hook_projection(hook),
            "time_to_failed_outcome_ms": round(
                (failed_visible_ns - started) / 1_000_000, 3
            ),
            "failed_outcome": {
                "status": (row or {}).get("status", "missing"),
                "error_code": ((row or {}).get("outcome") or {}).get("error_code"),
                "error": ((row or {}).get("outcome") or {}).get("error"),
            },
            "new_worker_pids": new_pids,
            "old_worker_confirmed_absent": not psutil.pid_exists(old_pid),
            "worker_replaced": old_pid not in new_pids and bool(new_pids),
            "recovery": {
                "sample": recovery_sample,
                "accounting": recovery_accounting,
            },
            **_fault_fixture_observations(fixture),
        }


def _fault_sqlite_lock(
    timeout: float, retained_root: Path | None = None
) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1, retained_root=retained_root) as fixture:
        _warm_fixture(fixture, 1, timeout)
        database = rap_config.db_path()
        lock = sqlite3.connect(str(database), timeout=1.0, isolation_level=None)
        lock.execute("BEGIN EXCLUSIVE")
        lock_acquired_ns = time.perf_counter_ns()
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="sqlite-lock",
            tool_input=artifact.probe_tool_input,
        )
        try:
            hook = _invoke_raw(project.wrapper, raw, fixture.environment)
            hold_deadline_ns = lock_acquired_ns + int(
                (SQLITE_BUSY_TIMEOUT_SECONDS + 1.0) * 1_000_000_000
            )
            while time.perf_counter_ns() < hold_deadline_ns:
                time.sleep(0.05)
            snapshot_while_held = (
                ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
            )
        finally:
            lock_release_started_ns = time.perf_counter_ns()
            lock.execute("ROLLBACK")
            lock.close()
            lock_released_ns = time.perf_counter_ns()
        row = _wait_for_conversation(
            project.root, str(raw["session_id"]), 1.0, require_terminal=False
        )
        snapshot_after_release = (
            ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
        )
        recovery_sample, recovery_accounting = _single_event(
            fixture, "sqlite-lock-recovery", timeout=timeout
        )
        return {
            "lock_mode": "BEGIN EXCLUSIVE",
            "lock_acquired_monotonic_ns": lock_acquired_ns,
            "lock_release_started_monotonic_ns": lock_release_started_ns,
            "lock_released_monotonic_ns": lock_released_ns,
            "held_ns": lock_release_started_ns - lock_acquired_ns,
            "held_seconds": round(
                (lock_release_started_ns - lock_acquired_ns) / 1_000_000_000,
                9,
            ),
            "production_sqlite_timeout_seconds": SQLITE_BUSY_TIMEOUT_SECONDS,
            "faulting_hook_exit_ms": round(
                (hook["exited_ns"] - hook["started_ns"]) / 1_000_000, 3
            ),
            "faulting_hook_contract_preserved": bool(hook.get("contract_preserved")),
            "faulting_hook": _hook_projection(hook),
            "faulting_evaluation_status": (row or {}).get("status", "missing"),
            "faulting_evaluation_outcome": (row or {}).get("outcome", {}),
            "health_issues_while_lock_held": list(
                snapshot_while_held.get("health_issues") or []
            ),
            "health_issues_after_lock_release": list(
                snapshot_after_release.get("health_issues") or []
            ),
            "recovery": {"sample": recovery_sample, "accounting": recovery_accounting},
            **_fault_fixture_observations(fixture),
        }


def _fault_malformed_payload(
    timeout: float, retained_root: Path | None = None
) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1, retained_root=retained_root) as fixture:
        project = fixture.projects[0]
        baseline_rows = _full_evaluation_history(project.root)
        baseline_ids = {str(row.get("evaluation_id", "")) for row in baseline_rows}
        before = len(baseline_rows)
        malformed = _invoke_payload(
            project.wrapper, project.root, "{not-json", fixture.environment
        )
        time.sleep(0.2)
        after = len(_evaluation_history(project.root))
        oversized = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="oversized-payload",
            tool_input={"command": "x" * 2048},
        )
        oversized_hook = _invoke_raw(project.wrapper, oversized, fixture.environment)
        oversized_input_sha256 = _sha256_bytes(
            _expected_input(oversized).encode("utf-8")
        )
        oversized_row = _wait_for_conversation(
            project.root,
            str(oversized["session_id"]),
            timeout,
            require_terminal=True,
        )
        recovery_sample, recovery_accounting = _single_event(
            fixture, "malformed-recovery", timeout=timeout
        )
        final_exact_accounting = _fault_evaluation_quiescence(
            project.root,
            baseline_evaluation_ids=baseline_ids,
            expected_input_sha256=(
                oversized_input_sha256,
                str(recovery_sample.get("input_sha256", "")),
            ),
        )
        return {
            "invalid_json": {
                "hook_exit_ms": round(
                    (malformed["exited_ns"] - malformed["started_ns"]) / 1_000_000,
                    3,
                ),
                "hook_contract_preserved": bool(malformed.get("contract_preserved")),
                "hook": _hook_projection(malformed),
                "evaluation_history_delta": after - before,
                "early_history_delta_is_diagnostic_only": True,
            },
            "oversized_trigger_field": {
                "bytes": 2048,
                "rule_max_input_bytes": 1024,
                "hook_exit_ms": round(
                    (oversized_hook["exited_ns"] - oversized_hook["started_ns"])
                    / 1_000_000,
                    3,
                ),
                "hook": _hook_projection(oversized_hook),
                "status": (oversized_row or {}).get("status", "missing"),
                "error_code": ((oversized_row or {}).get("outcome") or {}).get(
                    "error_code"
                ),
            },
            "final_exact_evaluation_accounting": final_exact_accounting,
            "recovery": {"sample": recovery_sample, "accounting": recovery_accounting},
            **_fault_fixture_observations(fixture),
        }


def _fault_evaluation_quiescence(
    project_root: Path,
    *,
    baseline_evaluation_ids: set[str],
    expected_input_sha256: Sequence[str],
    settle_seconds: float = FINAL_DRAIN_SETTLE_SECONDS,
) -> dict[str, Any]:
    """Prove a bounded fault fixture has only its two declared evaluations."""

    def scan() -> dict[str, Any]:
        started_ns = time.perf_counter_ns()
        rows = [
            row
            for row in _full_evaluation_history(project_root)
            if str(row.get("evaluation_id", "")) not in baseline_evaluation_ids
        ]
        projections = _canonical_projection_order(
            [_evaluation_projection(row) for row in rows]
        )
        finished_ns = time.perf_counter_ns()
        return {
            "started_monotonic_ns": started_ns,
            "finished_monotonic_ns": finished_ns,
            "count": len(rows),
            "terminal_count": sum(
                str(row.get("status", "")) in {"completed", "failed"} for row in rows
            ),
            "input_sha256_counts": dict(
                sorted(Counter(_input_hash_from_row(row) for row in rows).items())
            ),
            "canonical_projection_sha256": _sha256_bytes(
                _canonical_json_bytes(projections)
            ),
            "records": projections,
        }

    before_settle = scan()
    settle_started_ns = time.perf_counter_ns()
    time.sleep(settle_seconds)
    settle_finished_ns = time.perf_counter_ns()
    after_settle = scan()
    expected_counts = dict(sorted(Counter(expected_input_sha256).items()))
    stable = (
        before_settle["canonical_projection_sha256"]
        == after_settle["canonical_projection_sha256"]
    )
    exact = (
        after_settle["count"] == len(expected_input_sha256)
        and after_settle["terminal_count"] == len(expected_input_sha256)
        and after_settle["input_sha256_counts"] == expected_counts
    )
    return {
        "complete": stable and exact,
        "stable_across_settle": stable,
        "exact_declared_terminal_records": exact,
        "expected_input_sha256_counts": expected_counts,
        "before_settle": before_settle,
        "after_settle": after_settle,
        "settle_seconds": settle_seconds,
        "settle_started_monotonic_ns": settle_started_ns,
        "settle_finished_monotonic_ns": settle_finished_ns,
        "interpretation": (
            "The early 0.2-second count is diagnostic only; pass/fail uses this "
            "fixed quiescence interval and exact final bounded-fixture projection."
        ),
    }


def _fault_duplicate_delivery(
    timeout: float, retained_root: Path | None = None
) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1, retained_root=retained_root) as fixture:
        project = fixture.projects[0]
        raw = _raw_event(
            project.root,
            project_index=0,
            sequence=0,
            condition_id="duplicate-delivery",
            tool_input=artifact.probe_tool_input,
        )
        expected_input = _expected_input(raw)
        input_hash = _sha256_bytes(expected_input.encode("utf-8"))
        before = ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
        with ThreadPoolExecutor(max_workers=2) as executor:
            hooks = list(
                executor.map(
                    lambda _index: _invoke_raw(
                        project.wrapper, raw, fixture.environment
                    ),
                    range(2),
                )
            )
        expected = [
            ExpectedEvaluation(
                case_id="duplicate-delivery",
                project_root=str(project.root),
                input_sha256=input_hash,
                rule_id=artifact.rule_id,
            )
        ]
        rows, _first, _complete, _wait = _wait_for_expected(
            fixture.projects,
            expected,
            {input_hash: min(item["started_ns"] for item in hooks)},
            timeout,
        )
        relevant = [
            row
            for row in rows.get(str(project.root), [])
            if _input_hash_from_row(row) == input_hash
            and str((row.get("rule") or {}).get("id", "")) == artifact.rule_id
        ]
        findings = integrated._query_findings(project.root)
        finding_count = sum(
            1
            for finding in findings
            if str(
                ((finding.get("evaluation") or {}).get("input") or {}).get("sha256", "")
            )
            == input_hash
        )
        after = ipc.send_request({"type": "snapshot"}, timeout=2.0) or {}
        before_count = int(((before.get("daemon") or {}).get("ingress_duplicates", 0)))
        after_count = int(((after.get("daemon") or {}).get("ingress_duplicates", 0)))
        return {
            "deliveries": 2,
            "hook_contracts_preserved": len(hooks) == 2
            and all(bool(hook.get("contract_preserved")) for hook in hooks),
            "hooks": [_hook_projection(hook) for hook in hooks],
            "evaluations": len(relevant),
            "findings": finding_count,
            "ingress_duplicate_counter_delta": after_count - before_count,
            "exactly_once_within_live_daemon_window": (
                len(relevant) == 1
                and finding_count == 1
                and after_count - before_count == 1
            ),
            "scope": (
                "byte-identical concurrent redelivery while one daemon and its "
                "short-window admission cache remain live"
            ),
            **_fault_fixture_observations(fixture),
        }


def _seed_compiler_catalog() -> None:
    rap_config.compiler_catalog_path().write_text(
        json.dumps(
            {
                "fetched_at": time.time(),
                "compilers": [
                    {
                        "name": "",
                        "description": "synthetic cached default",
                        "default": True,
                        "supports_local_sdk": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _fault_deployment_failure(
    timeout: float, retained_root: Path | None = None
) -> dict[str, Any]:
    artifact = deterministic_artifact()
    with _running_fixture((artifact,), 1, retained_root=retained_root) as fixture:
        _seed_compiler_catalog()
        project = fixture.projects[0]
        prepared = ipc.send_request(
            {
                "type": "prepare_deployment",
                "rule_id": artifact.rule_id,
                "project_root": str(project.root),
                "source": artifact.source,
                "source_changed": False,
                "expected_active_hash": artifact.source_sha256,
                "coverage": {
                    "mode": "selected",
                    "selected_projects": [str(project.root)],
                },
            },
            timeout=5.0,
        )
        if not prepared or not prepared.get("ok"):
            raise SystemViolationError(
                f"deployment prepare failed unexpectedly: {prepared}"
            )
        changed_source = artifact.source.replace(
            'return ctx.result("WARNING")',
            'return ctx.result("CRITICAL")',
        )
        working_behavior_changed = (
            revisions.behavior_hash(changed_source) != artifact.behavior_sha256
        )
        if not working_behavior_changed:
            raise SystemsHarnessError(
                "deployment fault source mutation did not change behavior identity"
            )
        saved = rules_api.save_rule(
            artifact.rule_id, changed_source, "project", str(project.root)
        )
        if not saved.get("ok"):
            raise SystemViolationError(f"could not change prepared draft: {saved}")
        committed = ipc.send_request(
            {"type": "commit_deployment", "token": str(prepared["token"])},
            timeout=5.0,
        )
        sample, accounting = _single_event(
            fixture, "deployment-failure-active-revision", timeout=timeout
        )
        current = rules_api.get_rule(artifact.rule_id, str(project.root)) or {}
        post_failure_active_source_sha256 = str(
            (current.get("active") or {}).get("source_hash", "")
        )
        return {
            "prepare_ok": True,
            "working_source_changed_after_prepare": (
                revisions.hash_source(changed_source) != artifact.source_sha256
            ),
            "working_behavior_changed_after_prepare": working_behavior_changed,
            "commit_ok": bool((committed or {}).get("ok")),
            "commit_error": str((committed or {}).get("error", "")),
            "previous_active_source_sha256": artifact.source_sha256,
            "post_failure_active_source_sha256": post_failure_active_source_sha256,
            "post_failure_accounting": accounting,
            "post_failure_sample": sample,
            "previous_active_revision_remained_effective": (
                accounting["provenance_mismatch_count"] == 0
                and accounting["failed_count"] == 0
                and post_failure_active_source_sha256 == artifact.source_sha256
            ),
            **_fault_fixture_observations(fixture),
        }


def _accounting_is_clean(accounting: dict[str, Any] | None) -> bool:
    accounting = accounting or {}
    if any(accounting.get(key) for key in ACCOUNTING_FAILURE_KEYS):
        return False
    findings = dict(accounting.get("findings") or {})
    return not any(
        findings.get(key)
        for key in (
            "loss_count",
            "duplicate_count",
            "unexpected_count",
            "wrong_project_count",
            "finding_id_mismatch_count",
            "evaluation_id_mismatch_count",
        )
    )


def _fault_passed(name: str, result: dict[str, Any]) -> bool:
    integrity = bool((result.get("persistent_state_integrity") or {}).get("ok"))
    orphan_count = result.get("orphan_process_count")
    cleanup_ok = orphan_count == 0 and bool(
        (result.get("post_shutdown_process_settle") or {}).get(
            "completed_within_deadline"
        )
    )
    recovery = dict(result.get("recovery") or {})
    recovery_accounting = recovery.get("accounting")
    recovery_hook_ok = bool(
        ((recovery.get("sample") or {}).get("hook") or {}).get("contract_preserved")
    )
    if name == "duplicate_delivery":
        return (
            cleanup_ok
            and integrity
            and result.get("hook_contracts_preserved") is True
            and result.get("evaluations") == 1
            and result.get("findings") == 1
            and result.get("ingress_duplicate_counter_delta") == 1
            and result.get("exactly_once_within_live_daemon_window") is True
        )
    if name == "deployment_failure":
        return (
            cleanup_ok
            and integrity
            and result.get("prepare_ok") is True
            and result.get("working_source_changed_after_prepare") is True
            and result.get("working_behavior_changed_after_prepare") is True
            and result.get("commit_ok") is False
            and "working draft changed" in str(result.get("commit_error", ""))
            and result.get("previous_active_revision_remained_effective") is True
            and result.get("post_failure_active_source_sha256")
            == result.get("previous_active_source_sha256")
            and _accounting_is_clean(result.get("post_failure_accounting"))
            and bool(
                ((result.get("post_failure_sample") or {}).get("hook") or {}).get(
                    "contract_preserved"
                )
            )
        )
    if name == "malformed_payload":
        malformed = dict(result.get("invalid_json") or {})
        oversized = dict(result.get("oversized_trigger_field") or {})
        return (
            cleanup_ok
            and integrity
            and bool(malformed.get("hook_contract_preserved"))
            and (result.get("final_exact_evaluation_accounting") or {}).get("complete")
            and bool((oversized.get("hook") or {}).get("contract_preserved"))
            and oversized.get("status") == "failed"
            and oversized.get("error_code") == "input_too_large"
            and _accounting_is_clean(recovery_accounting)
            and recovery_hook_ok
        )
    if name == "worker_exit":
        return (
            cleanup_ok
            and integrity
            and bool(result.get("worker_replaced"))
            and result.get("old_worker_confirmed_absent") is True
            and bool(result.get("new_worker_pids"))
            and _accounting_is_clean(recovery_accounting)
            and recovery_hook_ok
        )
    if name == "worker_timeout":
        return (
            cleanup_ok
            and integrity
            and result.get("old_worker_confirmed_stopped_before_dispatch") is True
            and (result.get("failed_outcome") or {}).get("status") == "failed"
            and (result.get("failed_outcome") or {}).get("error_code")
            == "invalid_output"
            and bool((result.get("faulting_hook") or {}).get("contract_preserved"))
            and bool(result.get("worker_replaced"))
            and result.get("old_worker_confirmed_absent") is True
            and bool(result.get("new_worker_pids"))
            and _accounting_is_clean(recovery_accounting)
            and recovery_hook_ok
        )
    if name == "daemon_crash":
        return (
            cleanup_ok
            and integrity
            and result.get("old_pid_confirmed_dead") is True
            and isinstance(result.get("new_pid"), int)
            and int(result.get("new_pid", -1)) > 0
            and result.get("new_pid") != result.get("old_pid")
            and bool(result.get("faulting_hook_contract_preserved"))
            and _accounting_is_clean(recovery_accounting)
            and recovery_hook_ok
        )
    if name == "sqlite_lock":
        return (
            cleanup_ok
            and integrity
            and result.get("lock_mode") == "BEGIN EXCLUSIVE"
            and float(result.get("held_seconds", 0.0))
            > float(result.get("production_sqlite_timeout_seconds", float("inf")))
            and bool(result.get("faulting_hook_contract_preserved"))
            and _accounting_is_clean(recovery_accounting)
            and recovery_hook_ok
        )
    return cleanup_ok and integrity


def _standardized_fault_outcomes(name: str, result: dict[str, Any]) -> dict[str, Any]:
    recovery = dict(result.get("recovery") or {})
    hook = (
        result.get("faulting_hook")
        or (result.get("invalid_json") or {}).get("hook")
        or result.get("hooks")
    )
    return {
        "schema_version": 1,
        "injected_boundary": FAULT_CAPABILITIES[name].get("boundary", ""),
        "fail_open_hook_contract_and_latency": hook,
        "current_event_survival": {
            key: result.get(key)
            for key in (
                "faulting_event_evaluations",
                "faulting_event_expected_loss",
                "faulting_evaluation_status",
                "faulting_evaluation_outcome",
            )
            if key in result
        },
        "loss_and_duplication": (
            recovery.get("accounting")
            or result.get("post_failure_accounting")
            or {
                "evaluations": result.get("evaluations"),
                "findings": result.get("findings"),
            }
        ),
        "healthy_recovery": recovery
        or {
            "sample": result.get("post_failure_sample"),
            "accounting": result.get("post_failure_accounting"),
        },
        "previous_deployment_continuity": result.get(
            "previous_active_revision_remained_effective"
        ),
        "orphan_process_count": result.get("orphan_process_count"),
        "orphan_process_count_status": result.get("orphan_process_count_status"),
        "post_shutdown_process_cleanup": result.get("post_shutdown_process_cleanup"),
        "persistent_state_integrity": result.get("persistent_state_integrity"),
        "operator_visible_incident_records": result.get(
            "operator_visible_incidents", []
        ),
    }


def _unknown_standardized_fault_outcomes(name: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "injected_boundary": FAULT_CAPABILITIES[name].get("boundary", ""),
        "fail_open_hook_contract_and_latency": None,
        "current_event_survival": None,
        "loss_and_duplication": None,
        "healthy_recovery": None,
        "previous_deployment_continuity": None,
        "orphan_process_count": None,
        "orphan_process_count_status": "unknown_after_caught_exception",
        "post_shutdown_process_cleanup": None,
        "persistent_state_integrity": None,
        "operator_visible_incident_records": [],
    }


def run_fault_suite(
    external_artifacts: Sequence[RuleArtifact],
    fault_names: Sequence[str],
    *,
    timeout: float,
    repetitions: int = DEFAULT_FAULT_REPETITIONS,
    strict: bool = True,
    recorder: AttemptRecorder | None = None,
) -> dict[str, Any]:
    if repetitions < 1:
        raise ValueError("fault repetitions must be positive")
    unknown = sorted(set(fault_names) - set(FAULT_CAPABILITIES))
    if unknown:
        raise ValueError(f"unknown fault probes: {unknown}")
    external = external_artifacts[0]
    runners = {
        "daemon_crash": lambda root: _fault_daemon_crash(external, timeout, root),
        "worker_exit": lambda root: _fault_worker_exit(external, timeout, root),
        "worker_timeout": lambda root: _fault_worker_timeout(external, timeout, root),
        "sqlite_lock": lambda root: _fault_sqlite_lock(timeout, root),
        "malformed_payload": lambda root: _fault_malformed_payload(timeout, root),
        "duplicate_delivery": lambda root: _fault_duplicate_delivery(timeout, root),
        "deployment_failure": lambda root: _fault_deployment_failure(timeout, root),
    }
    results = {}
    for name in fault_names:
        capability = FAULT_CAPABILITIES[name]
        if not capability.get("feasible"):
            results[name] = {"status": "not_run", **capability}
            continue
        attempts = []
        for repetition in range(repetitions):
            attempt_id = f"{name}-rep{repetition}"
            started_utc = datetime.now(timezone.utc).isoformat()
            started_ns = time.perf_counter_ns()
            if recorder:
                recorder.record(
                    "faults",
                    attempt_id,
                    "started",
                    {
                        "fault": name,
                        "repetition": repetition,
                        "phase": "started",
                        "started_utc": started_utc,
                        "started_monotonic_ns": started_ns,
                    },
                )
            retained_root = (
                recorder.root / "runtime" / "faults" / attempt_id if recorder else None
            )
            probe_result: dict[str, Any] | None = None
            retained_exception: dict[str, Any] | None = None
            cleanup: dict[str, Any]
            try:
                probe_result = runners[name](retained_root)
            except Exception as exc:
                retained_exception = _retained_error(exc, retained_root)
            finally:
                cleanup = _settle_and_force_fault_cleanup(retained_root, timeout)
            if probe_result is not None:
                _attach_fault_cleanup_evidence(probe_result, cleanup)
                passed = _fault_passed(name, probe_result)
                finished_ns = time.perf_counter_ns()
                duration_ns = finished_ns - started_ns
                attempt = {
                    "fault": name,
                    "repetition": repetition,
                    "status": "completed" if passed else "system_violation",
                    "passed": passed,
                    "started_utc": started_utc,
                    "finished_utc": datetime.now(timezone.utc).isoformat(),
                    "started_monotonic_ns": started_ns,
                    "finished_monotonic_ns": finished_ns,
                    "duration_ms": round(duration_ns / 1_000_000, 3),
                    "duration_ns": duration_ns,
                    "standardized_outcomes": _standardized_fault_outcomes(
                        name, probe_result
                    ),
                    "probe_specific": probe_result,
                    "error": None,
                }
            else:
                if retained_exception is None:  # pragma: no cover - defensive
                    raise SystemsHarnessError(
                        "fault probe produced neither a result nor an exception"
                    )
                exception_probe = {
                    "probe_exception": retained_exception["error"],
                }
                _attach_fault_cleanup_evidence(exception_probe, cleanup)
                standardized = _unknown_standardized_fault_outcomes(name)
                standardized["orphan_process_count"] = exception_probe[
                    "orphan_process_count"
                ]
                standardized["orphan_process_count_status"] = exception_probe[
                    "orphan_process_count_status"
                ]
                standardized["post_shutdown_process_cleanup"] = cleanup
                finished_ns = time.perf_counter_ns()
                duration_ns = finished_ns - started_ns
                attempt = {
                    "fault": name,
                    "repetition": repetition,
                    "status": retained_exception["status"],
                    "classification_basis": retained_exception["classification_basis"],
                    "passed": False,
                    "started_utc": started_utc,
                    "finished_utc": datetime.now(timezone.utc).isoformat(),
                    "started_monotonic_ns": started_ns,
                    "finished_monotonic_ns": finished_ns,
                    "duration_ms": round(duration_ns / 1_000_000, 3),
                    "duration_ns": duration_ns,
                    "standardized_outcomes": standardized,
                    "probe_specific": exception_probe,
                    "error": retained_exception["error"],
                }
            if not cleanup["safe_to_continue"]:
                attempt["status"] = "system_violation"
                attempt["passed"] = False
                attempt["cleanup_system_violation"] = {
                    "classification_basis": (
                        "post-shutdown retained-runtime processes could not be "
                        "proven absent after exact-owner forced cleanup"
                    ),
                    "cleanup": cleanup,
                }
            if (
                recorder
                and (
                    (getattr(recorder, "manifest", {}).get("identity") or {}).get(
                        "study_mode"
                    )
                )
                == FORMAL_STUDY_MODE
            ):
                attempt["study_mode"] = FORMAL_STUDY_MODE
            attempts.append(attempt)
            if recorder:
                recorder.record("faults", attempt_id, "terminal", attempt)
            if not cleanup["safe_to_continue"]:
                raise SystemViolationError(
                    f"fault cleanup isolation failed after {attempt_id}; "
                    "subsequent units were not started"
                )
        results[name] = {
            "status": (
                "completed"
                if all(item["passed"] for item in attempts)
                else "harness_error"
                if any(item["status"] == "harness_error" for item in attempts)
                else "infrastructure_error"
                if any(item["status"] == "infrastructure_error" for item in attempts)
                else "unclassified_failure"
                if any(item["status"] == "unclassified_failure" for item in attempts)
                else "system_violation"
            ),
            "capability": capability,
            "repetitions_planned": repetitions,
            "repetitions_completed": sum(
                item["status"] in ("completed", "system_violation") for item in attempts
            ),
            "repetitions_passed": sum(item["passed"] for item in attempts),
            "repetitions_system_violation": sum(
                item["status"] == "system_violation" for item in attempts
            ),
            "repetitions_harness_error": sum(
                item["status"] == "harness_error" for item in attempts
            ),
            "repetitions_infrastructure_error": sum(
                item["status"] == "infrastructure_error" for item in attempts
            ),
            "repetitions_unclassified_failure": sum(
                item["status"] == "unclassified_failure" for item in attempts
            ),
            "attempts": attempts,
        }
    for name, capability in FAULT_CAPABILITIES.items():
        if name not in results and not capability.get("feasible"):
            results[name] = {"status": "not_run", **capability}
    return results


def _measurement_boundary() -> dict[str, Any]:
    return {
        "hook_start": "parent immediately before exact installed wrapper process launch",
        "hook_end": "parent immediately after the installed wrapper exits",
        "evaluation_start": (
            "parent time.perf_counter_ns immediately before executor.submit in burst "
            "mode or direct installed-wrapper invocation in sequential mode"
        ),
        "evaluation_first_end": (
            "first successful daemon Evaluation History query containing any terminal "
            "expected rule evaluation for the exact input"
        ),
        "evaluation_all_end": (
            "first successful daemon Evaluation History query containing every terminal "
            "expected (project, exact input hash, rule ID) tuple"
        ),
        "included": [
            "installed project hook wrapper",
            "Codex adapter normalization",
            "Unix-socket request and acknowledgement",
            "daemon ingress and ledger append",
            "production per-project rule loading and trigger matching",
            "serialized local PAW inference in the supervised subprocess",
            "all-outcome evaluation journal persistence",
            "finding SQLite persistence when a rule returns a finding",
            "daemon Evaluation History query and polling",
        ],
        "excluded": [
            "Codex scheduling of its asynchronous hook",
            "rendering or human perception of the menu-bar UI",
            "remote PAW compilation because public program IDs are already frozen",
        ],
        "interpretation": (
            "installed-path, query-visible all-evaluation latency; not Codex turn or UI latency"
        ),
        "query_poll_interval_ms": int(QUERY_POLL_INTERVAL_SECONDS * 1000),
        "single_event_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "burst_and_soak_drain_timeout_seconds": DEFAULT_DRAIN_TIMEOUT_SECONDS,
    }


def reduce_matrix_attempts(
    plan: Sequence[dict[str, Any]], matrix: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    """Apply the preregistered complete-attempt reducer without dropping failures."""
    planned_ids = [str(item["condition_id"]) for item in plan]
    observed_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in matrix:
        observed_by_id[str(item.get("condition_id", ""))].append(dict(item))
    missing = [
        condition_id for condition_id in planned_ids if not observed_by_id[condition_id]
    ]
    duplicate_terminal = {
        condition_id: len(items)
        for condition_id, items in observed_by_id.items()
        if condition_id and len(items) > 1
    }
    unexpected = sorted(set(observed_by_id) - set(planned_ids) - {""})

    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for planned in plan:
        condition_id = str(planned["condition_id"])
        terminal = observed_by_id.get(condition_id, [])
        item = (
            terminal[0]
            if len(terminal) == 1
            else {
                "condition_id": condition_id,
                "status": "missing_or_duplicate_terminal",
                "samples": [],
                "accounting": {},
            }
        )
        key = (
            int(planned["rule_count"]),
            int(planned["project_count"]),
            str(planned["schedule"]),
            str(planned["mode"]),
            int(planned["events"]),
        )
        grouped[key].append(item)

    cells = []
    for key, attempts in sorted(grouped.items()):
        pooled_samples = [
            sample for attempt in attempts for sample in attempt.get("samples", [])
        ]
        statuses = Counter(
            str(attempt.get("status", "missing")) for attempt in attempts
        )
        accounting_totals: Counter[str] = Counter()
        finding_totals: Counter[str] = Counter()
        for attempt in attempts:
            accounting = dict(attempt.get("accounting") or {})
            for name in ACCOUNTING_FAILURE_KEYS:
                accounting_totals[name] += int(accounting.get(name, 0) or 0)
            for name in (
                "loss_count",
                "duplicate_count",
                "unexpected_count",
                "wrong_project_count",
                "finding_id_mismatch_count",
                "evaluation_id_mismatch_count",
            ):
                finding_totals[name] += int(
                    (accounting.get("findings") or {}).get(name, 0) or 0
                )
        latency = (
            _latency_summary(
                pooled_samples, "event_to_all_query_visible_evaluations_ms"
            )
            if pooled_samples
            else {
                "unit": "ns",
                "count": 0,
                "observed_count": 0,
                "right_censored_count": 0,
                "available": False,
            }
        )
        failed_attempts = sum(
            count for status, count in statuses.items() if status != "completed"
        )
        cells.append(
            {
                "cell_id": (f"r{key[0]}-p{key[1]}-{key[2]}-{key[3]}{key[4]}"),
                "rule_count": key[0],
                "project_count": key[1],
                "schedule": key[2],
                "mode": key[3],
                "events": key[4],
                "repetitions_planned": len(attempts),
                "attempt_status_counts": dict(sorted(statuses.items())),
                "failed_or_incomplete_attempts": failed_attempts,
                "event_to_all_query_visible_evaluations": latency,
                "accounting_failure_totals": dict(accounting_totals),
                "finding_failure_totals": dict(finding_totals),
                "condition_ids": [
                    str(attempt.get("condition_id", "")) for attempt in attempts
                ],
            }
        )

    def worst_key(cell: dict[str, Any]) -> tuple[Any, ...]:
        latency = dict(cell["event_to_all_query_visible_evaluations"])
        incomplete = int(cell["failed_or_incomplete_attempts"] > 0)
        violations = sum(cell["accounting_failure_totals"].values()) + sum(
            cell["finding_failure_totals"].values()
        )
        censored = int(latency.get("right_censored_count", 0) or 0)
        p95 = int(latency.get("p95_nearest_rank_ns", -1) or -1)
        maximum = int(latency.get("maximum_ns", -1) or -1)
        return (
            incomplete,
            violations > 0,
            censored > 0,
            censored,
            p95,
            maximum,
            cell["cell_id"],
        )

    worst = max(cells, key=worst_key) if cells else None
    marginals = []
    direct_by_dimensions = {
        (
            int(item.get("rule_count", 0)),
            int(item.get("project_count", 0)),
            str(item.get("schedule", "")),
            str(item.get("mode", "")),
            int(item.get("event_count", 0)),
            int(item.get("repeat", -1)),
        ): item
        for item in matrix
        if item.get("event_to_all_query_visible_evaluations")
    }
    for dimensions, item in sorted(direct_by_dimensions.items()):
        rules, projects, schedule, mode, events, repeat = dimensions
        current_ns = int(
            item["event_to_all_query_visible_evaluations"].get("p95_nearest_rank_ns", 0)
            or 0
        )
        for factor_index, factor_name in ((0, "rule_count"), (1, "project_count")):
            values = sorted({key[factor_index] for key in direct_by_dimensions})
            previous_values = [
                value for value in values if value < dimensions[factor_index]
            ]
            if not previous_values:
                continue
            prior_value = max(previous_values)
            prior_dimensions = list(dimensions)
            prior_dimensions[factor_index] = prior_value
            prior = direct_by_dimensions.get(tuple(prior_dimensions))
            if prior is None:
                continue
            prior_p95_ns = int(
                prior["event_to_all_query_visible_evaluations"].get(
                    "p95_nearest_rank_ns", 0
                )
                or 0
            )
            added_units = dimensions[factor_index] - prior_value
            delta_ns = current_ns - prior_p95_ns
            change_per_unit_ns = delta_ns / added_units
            marginals.append(
                {
                    "factor": factor_name,
                    "from": prior_value,
                    "to": dimensions[factor_index],
                    "otherwise_matched": {
                        "rule_count": rules,
                        "project_count": projects,
                        "schedule": schedule,
                        "mode": mode,
                        "events": events,
                        "repeat": repeat,
                    },
                    "p95_delta_ns": delta_ns,
                    "added_units": added_units,
                    "p95_ns_change_per_added_unit": change_per_unit_ns,
                    "display_p95_ms_change_per_added_unit": round(
                        change_per_unit_ns / 1_000_000, 6
                    ),
                }
            )
    return {
        "contract": {
            "repetition_reducer": "pool event samples across all planned repetitions",
            "censoring": (
                "timeouts remain right-censored and enter percentile lower bounds at "
                "their timeout; missing/error attempts outrank numeric cells as worse"
            ),
            "worst_case_order": (
                "missing/error attempt, any accounting violation, any censoring, "
                "censored count, pooled integer-ns p95 lower bound, integer-ns "
                "maximum, lexical cell ID"
            ),
            "marginals": (
                "adjacent rule/project finite differences selected from integer-ns "
                "p95 within the same repetition, traffic, mode, and event count; "
                "milliseconds are display-only"
            ),
        },
        "plan_accounting": {
            "planned": len(planned_ids),
            "terminal_records": len(matrix),
            "missing": missing,
            "duplicate_terminal": duplicate_terminal,
            "unexpected": unexpected,
        },
        "cells": cells,
        "worst_case": worst,
        "marginal_contrasts": marginals,
    }


def _git_state_allowing_attempt(attempt_root: Path | None) -> dict[str, Any]:
    scope = ["rules_as_programs", "experiments/eacl2027", "pyproject.toml"]
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
        status = subprocess.check_output(
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
        ).splitlines()
        allowed_prefix = ""
        if attempt_root is not None:
            try:
                allowed_prefix = str(attempt_root.resolve().relative_to(REPO_ROOT))
            except ValueError:
                allowed_prefix = ""
        dirty = [
            line
            for line in status
            if not allowed_prefix or not line[3:].strip().startswith(allowed_prefix)
        ]
        return {"commit": commit, "dirty": bool(dirty), "scope": scope}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": "", "dirty": True, "scope": scope}


def _classify_unit_exception(exc: BaseException) -> tuple[str, str]:
    """Classify only from positive cause evidence; unknown is never rerunnable."""
    if isinstance(exc, SystemViolationError):
        return (
            "system_violation",
            "explicit measured daemon/worker/evaluation/accounting/fault-boundary failure",
        )
    if isinstance(exc, ExternalInfrastructureError):
        return (
            "infrastructure_error",
            "positive host/storage durability failure outside measured RAP behavior",
        )
    if isinstance(exc, MemoryError) or (
        isinstance(exc, OSError) and exc.errno == errno.ENOMEM
    ):
        return (
            "system_violation",
            "fixed-resource process memory exhaustion at a measured boundary",
        )
    if isinstance(exc, SystemsHarnessError):
        return (
            "harness_error",
            "explicit runner/plan/schema invariant failure",
        )
    return (
        "unclassified_failure",
        "cause is not positively proven as harness or external infrastructure; not rerun-eligible",
    )


def _retained_error(exc: BaseException, retained_root: Path | None) -> dict[str, Any]:
    status, basis = _classify_unit_exception(exc)
    return {
        "status": status,
        "classification_basis": basis,
        "error": {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
            "retained_runtime_root": str(retained_root) if retained_root else None,
        },
    }


def run_study(
    bundle: ArtifactBundle,
    config: MatrixConfig,
    *,
    fault_names: Sequence[str],
    run_offline_probe: bool,
    strict: bool,
    formal: bool = False,
    recorder: AttemptRecorder | None = None,
) -> dict[str, Any]:
    config.validate(len(bundle.artifacts))
    matrix_plan = build_matrix_plan(config)
    plan = build_study_plan(
        config,
        fault_names=fault_names,
        run_offline_probe=run_offline_probe,
    )
    source_state_at_start = (
        dict((recorder.manifest.get("identity") or {}).get("git") or {})
        if recorder and formal
        else integrated._git_state()
    )
    matrix = []
    for item in matrix_plan:
        condition_id = str(item["condition_id"])
        started_utc = datetime.now(timezone.utc).isoformat()
        started_ns = time.perf_counter_ns()
        retained_root = (
            recorder.root / "runtime" / "matrix" / condition_id if recorder else None
        )
        if recorder:
            recorder.record(
                "matrix",
                condition_id,
                "started",
                {
                    "phase": "started",
                    "plan": item,
                    "started_utc": started_utc,
                    "started_monotonic_ns": started_ns,
                    "retained_runtime_root": str(retained_root),
                },
            )
        try:
            condition = run_condition(
                bundle.artifacts,
                rule_count=int(item["rule_count"]),
                project_count=int(item["project_count"]),
                mode=str(item["mode"]),
                event_count=int(item["events"]),
                repeat=int(item["repeat"]),
                warmups_per_project=config.warmups_per_project,
                timeout=config.timeout_seconds,
                max_hook_workers=config.max_hook_workers,
                drain_timeout=config.drain_timeout_seconds,
                schedule=str(item["schedule"]),
                strict=strict,
                retained_root=retained_root,
            )
        except Exception as exc:
            retained = _retained_error(exc, retained_root)
            condition = {
                **item,
                **retained,
                "started_utc": started_utc,
                "finished_utc": datetime.now(timezone.utc).isoformat(),
                "duration_ms": round(
                    (time.perf_counter_ns() - started_ns) / 1_000_000, 3
                ),
                "samples": [],
                "accounting": {},
            }
        if recorder and formal:
            condition["study_mode"] = FORMAL_STUDY_MODE
        matrix.append(condition)
        if recorder:
            recorder.record("matrix", condition_id, "terminal", condition)
    soak = None
    if config.soak_events:
        soak_id = f"soak-r{config.soak_rule_count}-p{config.soak_project_count}"
        soak_root = recorder.root / "runtime" / "soak" if recorder else None
        if recorder:
            recorder.record(
                "soak",
                soak_id,
                "started",
                {
                    "phase": "started",
                    "events": config.soak_events,
                    "started_utc": datetime.now(timezone.utc).isoformat(),
                    "retained_runtime_root": str(soak_root),
                },
            )
        try:
            soak = run_soak(
                bundle.artifacts,
                rule_count=config.soak_rule_count,
                project_count=config.soak_project_count,
                event_count=config.soak_events,
                batch_size=config.soak_batch_size,
                warmups_per_project=config.warmups_per_project,
                timeout=config.timeout_seconds,
                max_hook_workers=config.max_hook_workers,
                drain_timeout=config.drain_timeout_seconds,
                strict=strict,
                retained_root=soak_root,
            )
        except Exception as exc:
            retained = _retained_error(exc, soak_root)
            soak = {
                **retained,
            }
        if recorder and formal:
            soak["study_mode"] = FORMAL_STUDY_MODE
        if recorder:
            recorder.record("soak", soak_id, "terminal", soak)
    offline = None
    if run_offline_probe:
        offline_id = "online-offline-exact-replay"
        offline_root = recorder.root / "runtime" / "offline" if recorder else None
        if recorder:
            recorder.record(
                "offline",
                offline_id,
                "started",
                {
                    "phase": "started",
                    "started_utc": datetime.now(timezone.utc).isoformat(),
                    "network_boundary": _python_socket_boundary(),
                    "retained_runtime_root": str(offline_root),
                },
            )
        try:
            offline = run_offline_after_prepare(
                bundle.artifacts,
                rule_count=max(config.rule_counts),
                timeout=config.timeout_seconds,
                retained_root=offline_root,
            )
        except Exception as exc:
            retained = _retained_error(exc, offline_root)
            offline = {
                **retained,
                "network_boundary": _python_socket_boundary(),
            }
        if recorder and formal:
            offline["study_mode"] = FORMAL_STUDY_MODE
        if recorder:
            recorder.record("offline", offline_id, "terminal", offline)
    faults = run_fault_suite(
        bundle.artifacts,
        fault_names,
        timeout=config.timeout_seconds,
        repetitions=config.fault_repetitions,
        strict=strict,
        recorder=recorder,
    )
    analysis = reduce_matrix_attempts(matrix_plan, matrix)
    global_outcome_statuses: list[str] = []
    terminal_units = [
        {
            "component": "matrix",
            "unit_id": str(item.get("condition_id", "")),
            "status": str(item.get("status", "")),
        }
        for item in matrix
    ]
    if soak is not None:
        terminal_units.append(
            {
                "component": "soak",
                "unit_id": (
                    f"soak-r{config.soak_rule_count}-p{config.soak_project_count}"
                ),
                "status": str(soak.get("status", "")),
            }
        )
    if offline is not None:
        terminal_units.append(
            {
                "component": "offline",
                "unit_id": "online-offline-exact-replay",
                "status": str(offline.get("status", "")),
            }
        )
    terminal_units.extend(
        {
            "component": "faults",
            "unit_id": (
                f"{attempt.get('fault', '')}-rep{attempt.get('repetition', '')}"
            ),
            "status": str(attempt.get("status", "")),
        }
        for value in faults.values()
        for attempt in value.get("attempts", [])
    )
    planned_keys = [(str(item["component"]), str(item["unit_id"])) for item in plan]
    terminal_keys = [
        (str(item["component"]), str(item["unit_id"])) for item in terminal_units
    ]
    planned_key_set = set(planned_keys)
    terminal_key_counts = Counter(terminal_keys)
    missing_unit_keys = [
        {"component": component, "unit_id": unit_id}
        for component, unit_id in planned_keys
        if terminal_key_counts[(component, unit_id)] == 0
    ]
    duplicate_unit_keys = [
        {"component": component, "unit_id": unit_id, "count": count}
        for (component, unit_id), count in sorted(terminal_key_counts.items())
        if count > 1
    ]
    unexpected_unit_keys = [
        {"component": component, "unit_id": unit_id}
        for component, unit_id in sorted(set(terminal_keys) - planned_key_set)
    ]
    invalid_unit_statuses = [
        dict(item) for item in terminal_units if item["status"] not in UNIT_STATUSES
    ]
    unit_statuses = [str(item["status"]) for item in terminal_units]
    all_planned_units_terminal = not (
        missing_unit_keys
        or duplicate_unit_keys
        or unexpected_unit_keys
        or invalid_unit_statuses
    ) and len(terminal_units) == len(plan)
    has_harness_error = (
        not all_planned_units_terminal
        or any(status == "harness_error" for status in unit_statuses)
        or any(status == "harness_error" for status in global_outcome_statuses)
    )
    has_infrastructure_error = any(
        status == "infrastructure_error"
        for status in [*unit_statuses, *global_outcome_statuses]
    )
    has_unclassified_failure = any(
        status == "unclassified_failure"
        for status in [*unit_statuses, *global_outcome_statuses]
    )
    incomplete = (
        has_harness_error or has_infrastructure_error or has_unclassified_failure
    )
    system_violations = sum(
        status == "system_violation"
        for status in [*unit_statuses, *global_outcome_statuses]
    )
    attempt_status = (
        "incomplete_unclassified_failure"
        if has_unclassified_failure
        else "incomplete_infrastructure_error"
        if has_infrastructure_error
        else "incomplete_harness_error"
        if has_harness_error
        else "completed_with_system_violations"
        if system_violations
        else "completed"
    )
    return {
        "schema_version": 2,
        "status": attempt_status,
        "complete_plan": all_planned_units_terminal,
        "primary_numeric_eligible": not incomplete,
        "all_planned_units_terminal": all_planned_units_terminal,
        "terminal_unit_count": len(unit_statuses),
        "planned_unit_count": len(plan),
        "system_violation_units": system_violations,
        "unit_plan_accounting": {
            "planned": len(plan),
            "terminal": len(terminal_units),
            "missing": missing_unit_keys,
            "duplicate": duplicate_unit_keys,
            "unexpected": unexpected_unit_keys,
            "invalid_status": invalid_unit_statuses,
            "exact": all_planned_units_terminal,
        },
        "terminal_units": terminal_units,
        "global_outcomes": {
            "statuses": global_outcome_statuses,
        },
        "protocol_status": (FORMAL_STUDY_MODE if formal else "candidate_noncanonical"),
        "study_mode": FORMAL_STUDY_MODE if formal else "candidate_noncanonical",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "measurement_boundary": _measurement_boundary(),
        "non_censoring_policy": (
            "system timeouts, accounting defects, logical fault failures, and per-attempt "
            "exceptions are terminal records; independent planned attempts continue"
        ),
        "config": asdict(config),
        "plan": plan,
        "matrix_plan": matrix_plan,
        "artifact_provenance": bundle.provenance,
        "protocol_amendment": (
            {
                "path": str(FORMAL_AMENDMENT.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(FORMAL_AMENDMENT),
            }
            if formal
            else None
        ),
        "protocol_correction_amendment": (
            {
                "path": str(FORMAL_CORRECTION_AMENDMENT.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(FORMAL_CORRECTION_AMENDMENT),
            }
            if formal
            else None
        ),
        "protocol_routing_correction_amendment": (
            {
                "path": str(
                    FORMAL_ROUTING_CORRECTION_AMENDMENT.relative_to(REPO_ROOT)
                ),
                "sha256": _sha256_file(FORMAL_ROUTING_CORRECTION_AMENDMENT),
            }
            if formal
            else None
        ),
        "rules": [
            {
                key: value
                for key, value in asdict(artifact).items()
                if key not in ("source", "probe_tool_input")
            }
            for artifact in bundle.artifacts
        ],
        "matrix": matrix,
        "analysis": analysis,
        "soak": soak,
        "offline_after_prepare": offline,
        "faults": faults,
        "fault_capabilities": FAULT_CAPABILITIES,
        "machine": {
            "platform": platform.platform(),
            "system": platform.system(),
            "machine": platform.machine(),
            "python": sys.version,
            "cpu_count_logical": os.cpu_count(),
        },
        "packages": {
            "rules-as-programs": integrated._package_version("rules-as-programs"),
            "programasweights": integrated._package_version("programasweights"),
            "llama-cpp-python": integrated._package_version("llama-cpp-python"),
            "psutil": integrated._package_version("psutil"),
        },
        "git": {
            "start": source_state_at_start,
            "end": None,
            "unchanged_during_attempt": None,
            "end_receipt_pending": True,
        },
        "slurm": {
            "job_id": os.environ.get("SLURM_JOB_ID", ""),
            "partition": os.environ.get("SLURM_JOB_PARTITION", ""),
            "node_list": os.environ.get("SLURM_JOB_NODELIST", ""),
        },
        "runner": {
            "path": str(Path(__file__).resolve().relative_to(REPO_ROOT)),
            "sha256": _sha256_file(Path(__file__).resolve()),
        },
    }


def _validate_output_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(FROZEN_OUTPUT_DIR)
    except ValueError:
        return resolved
    raise SystemsHarnessError(
        "this candidate harness cannot write into outputs/frozen; amend the protocol first"
    )


def _formal_contract(*, require_frozen: bool = True) -> dict[str, Any]:
    if (
        FORMAL_BASE_AMENDMENT.is_symlink()
        or not FORMAL_BASE_AMENDMENT.is_file()
        or _sha256_file(FORMAL_BASE_AMENDMENT) != FORMAL_BASE_AMENDMENT_SHA256
    ):
        raise SystemsHarnessError("protocol-v3 amendment 007 bytes changed")
    if FORMAL_AMENDMENT.is_symlink() or not FORMAL_AMENDMENT.is_file():
        raise SystemsHarnessError("protocol-v3 amendment 008 is absent or a symlink")
    if (
        FORMAL_CORRECTION_AMENDMENT.is_symlink()
        or not FORMAL_CORRECTION_AMENDMENT.is_file()
    ):
        raise SystemsHarnessError("protocol-v3 amendment 009 is absent or a symlink")
    if (
        FORMAL_ROUTING_CORRECTION_AMENDMENT.is_symlink()
        or not FORMAL_ROUTING_CORRECTION_AMENDMENT.is_file()
    ):
        raise SystemsHarnessError("protocol-v3 amendment 010 is absent or a symlink")
    if (
        FORMAL_PREPUBLICATION_CORRECTION_AMENDMENT.is_symlink()
        or not FORMAL_PREPUBLICATION_CORRECTION_AMENDMENT.is_file()
    ):
        raise SystemsHarnessError("protocol-v3 amendment 011 is absent or a symlink")
    if (
        FORMAL_HISTORICAL_ROLE_CORRECTION_AMENDMENT.is_symlink()
        or not FORMAL_HISTORICAL_ROLE_CORRECTION_AMENDMENT.is_file()
    ):
        raise SystemsHarnessError("protocol-v3 amendment 012 is absent or a symlink")
    if (
        FORMAL_SUPERVISOR_WAIT_CORRECTION_AMENDMENT.is_symlink()
        or not FORMAL_SUPERVISOR_WAIT_CORRECTION_AMENDMENT.is_file()
    ):
        raise SystemsHarnessError("protocol-v3 amendment 013 is absent or a symlink")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key {key!r}")
            value[key] = child
        return value

    try:
        contract = json.loads(
            FORMAL_AMENDMENT.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise SystemsHarnessError(f"invalid strict amendment 008: {exc}") from exc
    if not isinstance(contract, dict):
        raise SystemsHarnessError("protocol-v3 amendment 008 is not a JSON object")
    if contract.get("amendment_id") != "protocol-v3-amendment-008":
        raise SystemsHarnessError("unexpected formal amendment identity")

    def pending_markers(value: Any) -> list[str]:
        if isinstance(value, dict):
            return [
                marker for child in value.values() for marker in pending_markers(child)
            ]
        if isinstance(value, list):
            return [marker for child in value for marker in pending_markers(child)]
        if isinstance(value, str) and re.fullmatch(
            r"PENDING_TERMINAL_[A-Z0-9_]+", value
        ):
            return [value]
        return []

    unresolved = pending_markers(contract)
    if unresolved:
        raise SystemsHarnessError(
            "protocol-v3 amendment 008 retains unresolved terminal markers"
        )
    if require_frozen:
        freeze_state = str(contract.get("freeze_state", ""))
        status = str(contract.get("status", ""))
        if not freeze_state.startswith("frozen_") or "draft" in status.lower():
            raise SystemsHarnessError("protocol-v3 amendment 008 is not frozen")
        frozen_utc = contract.get("frozen_utc")
        try:
            frozen_at = datetime.fromisoformat(str(frozen_utc).replace("Z", "+00:00"))
        except ValueError as exc:
            raise SystemsHarnessError(
                "protocol-v3 amendment 008 has no valid frozen_utc"
            ) from exc
        if frozen_at.tzinfo is None:
            raise SystemsHarnessError(
                "protocol-v3 amendment 008 frozen_utc must be timezone-aware"
            )
        if frozen_at > datetime.now(timezone.utc):
            raise SystemsHarnessError(
                "protocol-v3 amendment 008 frozen_utc may not be in the future"
            )
        try:
            correction = json.loads(
                FORMAL_CORRECTION_AMENDMENT.read_text(encoding="utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise SystemsHarnessError(f"invalid strict amendment 009: {exc}") from exc
        correction_identity = (
            correction.get("effective_protocol_identity")
            if isinstance(correction, dict)
            else None
        )
        if (
            not isinstance(correction, dict)
            or correction.get("amendment_id") != "protocol-v3-amendment-009"
            or correction.get("parent_amendment") != "protocol-v3-amendment-008"
            or not str(correction.get("status", "")).startswith("frozen ")
            or not isinstance(correction_identity, dict)
        ):
            raise SystemsHarnessError("protocol-v3 amendment 009 is not frozen")
        contract = json.loads(json.dumps(contract))
        contract["effective_protocol_identity"]["required_git_topology"] = (
            correction_identity["required_git_topology"]
        )
        contract["effective_protocol_identity"]["interpretation_order"] = (
            correction_identity["interpretation_order"]
        )
        try:
            routing = json.loads(
                FORMAL_ROUTING_CORRECTION_AMENDMENT.read_text(encoding="utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise SystemsHarnessError(f"invalid strict amendment 010: {exc}") from exc
        routing_identity = (
            routing.get("effective_protocol_identity")
            if isinstance(routing, dict)
            else None
        )
        if (
            not isinstance(routing, dict)
            or routing.get("amendment_id") != "protocol-v3-amendment-010"
            or routing.get("parent_amendment") != "protocol-v3-amendment-009"
            or not str(routing.get("status", "")).startswith("frozen ")
            or not isinstance(routing_identity, dict)
        ):
            raise SystemsHarnessError("protocol-v3 amendment 010 is not frozen")
        contract["effective_protocol_identity"]["required_git_topology"] = (
            routing_identity["required_git_topology"]
        )
        contract["effective_protocol_identity"]["interpretation_order"] = (
            routing_identity["interpretation_order"]
        )
        try:
            prepublication = json.loads(
                FORMAL_PREPUBLICATION_CORRECTION_AMENDMENT.read_text(encoding="utf-8"),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise SystemsHarnessError(f"invalid strict amendment 011: {exc}") from exc
        prepublication_identity = (
            prepublication.get("effective_protocol_identity")
            if isinstance(prepublication, dict)
            else None
        )
        override = (
            prepublication.get("explicit_override")
            if isinstance(prepublication, dict)
            else None
        )
        if (
            not isinstance(prepublication, dict)
            or prepublication.get("amendment_id") != "protocol-v3-amendment-011"
            or prepublication.get("parent_amendment")
            != "protocol-v3-amendment-010"
            or not str(prepublication.get("status", "")).startswith("frozen ")
            or not isinstance(prepublication_identity, dict)
            or not isinstance(override, dict)
        ):
            raise SystemsHarnessError("protocol-v3 amendment 011 is not frozen")
        contract["effective_protocol_identity"]["required_git_topology"] = (
            prepublication_identity["required_git_topology"]
        )
        contract["effective_protocol_identity"]["interpretation_order"] = (
            prepublication_identity["interpretation_order"]
        )
        fatal = contract["fatal_result_contract"]
        successor = str(override["successor_raw_attempt_id"])
        supervisor_root = Path(str(override["supervisor_root_exact"]))
        if (
            successor != "formal-v3-20260831t051023z-r04"
            or supervisor_root.name != successor
        ):
            raise SystemsHarnessError("amendment-011 successor identity differs")
        fatal["supervisor_parent_exact"] = str(override["supervisor_parent_exact"])
        fatal["supervisor_closeout_root_exact"] = str(supervisor_root)
        fatal["supervisor_start_path_exact"] = str(supervisor_root / "start.json")
        fatal["supervisor_child_stdout_path_exact"] = str(
            supervisor_root / "child.stdout.bin"
        )
        fatal["supervisor_child_stderr_path_exact"] = str(
            supervisor_root / "child.stderr.bin"
        )
        fatal["supervisor_closeout_path_exact"] = str(
            supervisor_root / "closeout.json"
        )
        try:
            historical = json.loads(
                FORMAL_HISTORICAL_ROLE_CORRECTION_AMENDMENT.read_text(
                    encoding="utf-8"
                ),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise SystemsHarnessError(f"invalid strict amendment 012: {exc}") from exc
        historical_identity = (
            historical.get("effective_protocol_identity")
            if isinstance(historical, dict)
            else None
        )
        if (
            not isinstance(historical, dict)
            or historical.get("amendment_id") != "protocol-v3-amendment-012"
            or historical.get("parent_amendment") != "protocol-v3-amendment-011"
            or not str(historical.get("status", "")).startswith("frozen ")
            or not isinstance(historical_identity, dict)
        ):
            raise SystemsHarnessError("protocol-v3 amendment 012 is not frozen")
        contract["effective_protocol_identity"]["required_git_topology"] = (
            historical_identity["required_git_topology"]
        )
        contract["effective_protocol_identity"]["interpretation_order"] = (
            historical_identity["interpretation_order"]
        )
        try:
            wait_correction = json.loads(
                FORMAL_SUPERVISOR_WAIT_CORRECTION_AMENDMENT.read_text(
                    encoding="utf-8"
                ),
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise SystemsHarnessError(f"invalid strict amendment 013: {exc}") from exc
        wait_identity = (
            wait_correction.get("effective_protocol_identity")
            if isinstance(wait_correction, dict)
            else None
        )
        wait_override = (
            wait_correction.get("explicit_override")
            if isinstance(wait_correction, dict)
            else None
        )
        if (
            not isinstance(wait_correction, dict)
            or wait_correction.get("amendment_id") != "protocol-v3-amendment-013"
            or wait_correction.get("parent_amendment")
            != "protocol-v3-amendment-012"
            or not str(wait_correction.get("status", "")).startswith("frozen ")
            or not isinstance(wait_identity, dict)
            or not isinstance(wait_override, dict)
        ):
            raise SystemsHarnessError("protocol-v3 amendment 013 is not frozen")
        contract["effective_protocol_identity"]["required_git_topology"] = (
            wait_identity["required_git_topology"]
        )
        contract["effective_protocol_identity"]["interpretation_order"] = (
            wait_identity["interpretation_order"]
        )
        successor = str(wait_override["successor_raw_attempt_id"])
        if successor != FORMAL_RAW_ATTEMPT_ID:
            raise SystemsHarnessError("amendment-013 successor identity differs")
        fatal = contract["fatal_result_contract"]
        fatal["supervisor_closeout_root_exact"] = str(FORMAL_SUPERVISOR_ROOT)
        fatal["supervisor_start_path_exact"] = str(FORMAL_SUPERVISOR_ROOT / "start.json")
        fatal["supervisor_child_stdout_path_exact"] = str(
            FORMAL_SUPERVISOR_ROOT / "child.stdout.bin"
        )
        fatal["supervisor_child_stderr_path_exact"] = str(
            FORMAL_SUPERVISOR_ROOT / "child.stderr.bin"
        )
        fatal["supervisor_closeout_path_exact"] = str(
            FORMAL_SUPERVISOR_ROOT / "closeout.json"
        )
    interpretation_order = list(
        (contract.get("effective_protocol_identity") or {}).get("interpretation_order")
        or []
    )
    expected_order = [
        "experiments/eacl2027/protocol-v3.json",
        *[
            f"experiments/eacl2027/protocol-v3-amendment-{index:03d}.json"
            for index in range(1, 14)
        ],
    ]
    if interpretation_order != expected_order:
        raise SystemsHarnessError(
            "protocol-v3 amendment 008 interpretation order is not exact"
        )
    for relative in interpretation_order:
        path = (REPO_ROOT / relative).resolve()
        try:
            path.relative_to(REPO_ROOT)
        except ValueError as exc:
            raise SystemsHarnessError(
                "protocol contract path escapes repository"
            ) from exc
        if not path.is_file() or path.is_symlink():
            raise SystemsHarnessError(f"formal protocol hash mismatch: {path}")
    return contract


def _formal_base_contract() -> dict[str, Any]:
    try:
        value = json.loads(FORMAL_BASE_AMENDMENT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemsHarnessError(f"invalid amendment 007: {exc}") from exc
    if value.get("amendment_id") != "protocol-v3-amendment-007":
        raise SystemsHarnessError("unexpected amendment-007 identity")
    return value


def _formal_runtime_profile() -> dict[str, Any]:
    """Apply amendment-008's two explicit cache/runtime-lock overrides."""

    profile = json.loads(
        json.dumps(_formal_base_contract().get("formal_runtime_profile") or {})
    )
    dependency = dict(profile.get("cache_and_dependency_receipt") or {})
    corrected = dict(
        _formal_contract().get("corrected_direct_paw_cache_contract") or {}
    )
    dependency["formal_cache_dir"] = corrected.get("r03_paw_cache_dir_exact")
    dependency["runtime_lock_path"] = "experiments/eacl2027/formal-runtime-lock-v9.json"
    profile["cache_and_dependency_receipt"] = dependency
    thread_environment = dict(profile.get("thread_environment") or {})
    thread_environment["PROGRAMASWEIGHTS_CACHE_DIR"] = "UNSET"
    profile["thread_environment"] = thread_environment
    return profile


def _formal_effective_config() -> dict[str, Any]:
    """Return amendment-007 config with amendment-008's exact r03 overrides."""

    effective = json.loads(
        json.dumps(_formal_base_contract().get("formal_effective_config") or {})
    )
    overrides = dict(
        (_formal_contract().get("effective_protocol_identity") or {}).get(
            "explicit_one_time_overrides"
        )
        or {}
    )
    if (
        overrides.get("formal_effective_config.fault_names_in_order")
        != FORMAL_FAULT_OVERRIDE_TEXT
    ):
        raise SystemsHarnessError(
            "amendment-008 r03 fault_names_in_order override differs"
        )
    if (
        overrides.get("formal_effective_config.study_mode")
        != FORMAL_STUDY_MODE_OVERRIDE_TEXT
    ):
        raise SystemsHarnessError("amendment-008 r03 study_mode override differs")
    effective["fault_names_in_order"] = list(FORMAL_FAULTS)
    effective["study_mode"] = FORMAL_STUDY_MODE
    return effective


def _required_git_state(contract: Mapping[str, Any]) -> dict[str, Any]:
    topology = dict(
        (contract.get("effective_protocol_identity") or {}).get("required_git_topology")
        or {}
    )
    p4 = dict(topology.get("p4") or {})
    i4 = dict(topology.get("i4") or {})
    h4 = dict(topology.get("h4") or {})
    return {
        "protocol_commit_parent_must_equal": p4.get("parent_must_equal"),
        "protocol_commit_diff_paths_exactly": p4.get("diff_paths_exactly"),
        "implementation_commit_parent_must_equal_protocol_commit": i4.get(
            "parent_must_equal_p4"
        ),
        "implementation_commit_diff_paths_exactly": i4.get("diff_paths_exactly"),
        "runtime_lock_commit_parent_must_equal_implementation_commit": h4.get(
            "parent_must_equal_i4"
        ),
        "runtime_lock_commit_diff_paths_exactly": h4.get("diff_paths_exactly"),
        "head_must_equal_runtime_lock_commit": topology.get(
            "head_must_equal_h4_before_r05_setup"
        ),
        "dirty_must_equal": topology.get("dirty_must_equal"),
        "dirty_scope": topology.get("dirty_scope"),
    }


def _git_commit_parent(commit: str) -> str:
    completed = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", commit],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    fields = completed.stdout.strip().split()
    if completed.returncode != 0 or len(fields) != 2 or fields[0] != commit:
        raise SystemsHarnessError(
            f"formal chronology requires a single-parent commit: {commit}"
        )
    return fields[1]


def _git_commit_diff_paths(commit: str) -> list[str]:
    completed = subprocess.run(
        [
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            commit,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemsHarnessError(
            f"formal chronology cannot inspect commit paths: {commit}"
        )
    return sorted(line for line in completed.stdout.splitlines() if line)


def _validate_formal_git_topology(
    head: str, required_git: Mapping[str, Any]
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise SystemsHarnessError("formal source HEAD is not a full Git commit")
    runtime_lock_commit = head
    implementation_commit = _git_commit_parent(runtime_lock_commit)
    protocol_commit = _git_commit_parent(implementation_commit)
    protocol_parent = _git_commit_parent(protocol_commit)
    expected_parent = str(required_git.get("protocol_commit_parent_must_equal", ""))
    expected_protocol_paths = sorted(
        str(path) for path in required_git.get("protocol_commit_diff_paths_exactly", [])
    )
    expected_implementation_paths = sorted(
        str(path)
        for path in required_git.get("implementation_commit_diff_paths_exactly", [])
    )
    expected_lock_paths = sorted(
        str(path)
        for path in required_git.get("runtime_lock_commit_diff_paths_exactly", [])
    )
    observed_paths = {
        "protocol": _git_commit_diff_paths(protocol_commit),
        "implementation": _git_commit_diff_paths(implementation_commit),
        "runtime_lock": _git_commit_diff_paths(runtime_lock_commit),
    }
    expected_paths = {
        "protocol": expected_protocol_paths,
        "implementation": expected_implementation_paths,
        "runtime_lock": expected_lock_paths,
    }
    if (
        re.fullmatch(r"[0-9a-f]{40}", expected_parent) is None
        or protocol_parent != expected_parent
        or required_git.get("implementation_commit_parent_must_equal_protocol_commit")
        is not True
        or required_git.get(
            "runtime_lock_commit_parent_must_equal_implementation_commit"
        )
        is not True
        or required_git.get("head_must_equal_runtime_lock_commit") is not True
        or observed_paths != expected_paths
    ):
        raise SystemsHarnessError(
            "formal source violates the frozen protocol/implementation/runtime-lock "
            "three-commit chronology"
        )
    return {
        "protocol_parent": protocol_parent,
        "protocol_commit": protocol_commit,
        "implementation_commit": implementation_commit,
        "runtime_lock_commit": runtime_lock_commit,
        "head_equals_runtime_lock_commit": head == runtime_lock_commit,
        "commit_diff_paths": observed_paths,
    }


def _git_remote_refs_containing(commit: str) -> list[str]:
    completed = subprocess.run(
        [
            "git",
            "for-each-ref",
            "--format=%(refname)",
            "--contains",
            commit,
            "refs/remotes",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemsHarnessError("formal chronology cannot inspect pushed refs")
    return sorted(
        ref
        for ref in completed.stdout.splitlines()
        if ref and not ref.endswith("/HEAD")
    )


def _formal_source_state() -> tuple[dict[str, Any], dict[str, Any]]:
    state = integrated._git_state()
    if state.get("dirty") or not state.get("commit"):
        raise SystemsHarnessError(
            "formal execution requires a clean scoped Git source state"
        )
    required_git = _required_git_state(_formal_contract())
    topology = _validate_formal_git_topology(str(state["commit"]), required_git)
    if not _git_remote_refs_containing(str(state["commit"])):
        raise SystemsHarnessError(
            "formal execution requires H4 to be contained by a pushed remote ref"
        )
    return state, topology


def _validate_formal_config(
    config: MatrixConfig,
    *,
    fault_names: Sequence[str],
    run_offline_probe: bool,
    strict: bool,
    require_partition: bool,
) -> None:
    contract = _formal_contract()
    effective = _formal_effective_config()
    expected = {name: effective[name] for name in asdict(config) if name in effective}
    observed = json.loads(json.dumps(asdict(config)))
    mismatches = {
        name: {"expected": value, "observed": observed[name]}
        for name, value in expected.items()
        if observed[name] != value
    }
    missing_config_fields = sorted(set(observed) - set(expected))
    if missing_config_fields:
        mismatches["unbound_config_fields"] = missing_config_fields
    expected_faults = FORMAL_FAULTS
    if tuple(fault_names) != expected_faults:
        mismatches["fault_names"] = {
            "expected": expected_faults,
            "observed": tuple(fault_names),
        }
    for name, expected_value, observed_value in (
        ("offline_probe", bool(effective.get("offline_probe")), run_offline_probe),
        ("strict_accounting", bool(effective.get("strict_accounting")), strict),
        (
            "traffic_patterns_in_order",
            tuple(effective.get("traffic_patterns_in_order") or ()),
            TRAFFIC_PATTERNS,
        ),
        (
            "query_poll_interval_seconds",
            effective.get("query_poll_interval_seconds"),
            QUERY_POLL_INTERVAL_SECONDS,
        ),
        (
            "matrix_history_duplicate_headroom",
            effective.get("matrix_history_duplicate_headroom"),
            MATRIX_HISTORY_DUPLICATE_HEADROOM,
        ),
        (
            "soak_journal_poll_interval_seconds",
            effective.get("soak_journal_poll_interval_seconds"),
            SOAK_JOURNAL_POLL_INTERVAL_SECONDS,
        ),
        (
            "soak_history_checkpoint_retry_seconds",
            effective.get("soak_history_checkpoint_retry_seconds"),
            SOAK_HISTORY_CHECKPOINT_RETRY_SECONDS,
        ),
        (
            "soak_batch_settle_seconds",
            effective.get("soak_batch_settle_seconds"),
            SOAK_BATCH_SETTLE_SECONDS,
        ),
        (
            "resource_sample_interval_seconds",
            effective.get("resource_sample_interval_seconds"),
            RESOURCE_SAMPLE_INTERVAL_SECONDS,
        ),
        (
            "evaluation_history_limit",
            effective.get("evaluation_history_limit"),
            EVALUATION_HISTORY_LIMIT,
        ),
        (
            "evaluation_journal_rotation_bytes",
            effective.get("evaluation_journal_rotation_bytes"),
            evaluation_log.MAX_LOG_BYTES,
        ),
        (
            "evaluation_journal_rotation_backups",
            effective.get("evaluation_journal_rotation_backups"),
            evaluation_log.MAX_BACKUPS,
        ),
        (
            "sqlite_busy_timeout_seconds",
            effective.get("sqlite_busy_timeout_seconds"),
            SQLITE_BUSY_TIMEOUT_SECONDS,
        ),
        (
            "hook_process_timeout_seconds",
            effective.get("hook_process_timeout_seconds"),
            integrated.HOOK_TIMEOUT_SECONDS,
        ),
        (
            "burst_and_soak_batch_drain_timeout_seconds",
            effective.get("burst_and_soak_batch_drain_timeout_seconds"),
            config.drain_timeout_seconds,
        ),
        (
            "soak_final_drain_timeout_seconds",
            effective.get("soak_final_drain_timeout_seconds"),
            config.drain_timeout_seconds,
        ),
        (
            "final_drain_settle_seconds",
            effective.get("final_drain_settle_seconds"),
            FINAL_DRAIN_SETTLE_SECONDS,
        ),
        (
            "offline_socket_boundary_id",
            effective.get("offline_socket_boundary_id"),
            PYTHON_SOCKET_BOUNDARY_ID,
        ),
    ):
        if observed_value != expected_value:
            mismatches[name] = {
                "expected": expected_value,
                "observed": observed_value,
            }
    plan = build_matrix_plan(config)
    checks = dict(effective.get("deterministic_plan_checks") or {})
    observed_checks = {
        "matrix_conditions": len(plan),
        "matrix_events": sum(int(item["events"]) for item in plan),
        "matrix_expected_evaluations": sum(
            int(item["events"]) * int(item["rule_count"]) for item in plan
        ),
        "soak_expected_evaluations": config.soak_events * config.soak_rule_count,
        "fault_attempts": len(expected_faults) * config.fault_repetitions,
        "top_level_units": len(
            build_study_plan(
                config,
                fault_names=expected_faults,
                run_offline_probe=run_offline_probe,
            )
        ),
        "rule_order": list(EXTERNAL_RULE_ORDER),
    }
    expected_checks = {
        **checks,
        "fault_attempts": len(FORMAL_FAULTS) * config.fault_repetitions,
        "top_level_units": 430,
    }
    for name, value in observed_checks.items():
        if expected_checks.get(name) != value:
            mismatches[f"plan.{name}"] = {
                "expected": expected_checks.get(name),
                "observed": value,
            }
    full_attempt = build_full_attempt_plan(config)
    full_expected = {
        "unit_count": 430,
        "canonical_sha256": FORMAL_FULL_PLAN_SHA256,
        "ordered_membership_sha256": FORMAL_FULL_PLAN_MEMBERSHIP_SHA256,
        "primary_source_attempt_id": FORMAL_RAW_ATTEMPT_ID,
    }
    for name, expected_value in full_expected.items():
        if full_attempt[name] != expected_value:
            mismatches[f"full_attempt_plan.{name}"] = {
                "expected": expected_value,
                "observed": full_attempt[name],
            }
    amendment_full = dict(
        ((contract.get("full_attempt_plan") or {}).get("full_plan") or {})
    )
    amendment_values = {
        "unit_count": amendment_full.get("unit_count"),
        "canonical_sha256": amendment_full.get("canonical_sha256"),
        "ordered_membership_sha256": amendment_full.get("ordered_membership_sha256"),
        "stored_json_sha256": amendment_full.get("stored_json_sha256"),
    }
    expected_amendment_values = {
        **{
            name: full_expected[name]
            for name in (
                "unit_count",
                "canonical_sha256",
                "ordered_membership_sha256",
            )
        },
        "stored_json_sha256": FORMAL_FULL_PLAN_STORED_SHA256,
    }
    if amendment_values != expected_amendment_values:
        mismatches["full_attempt_plan.amendment_bindings"] = {
            "expected": expected_amendment_values,
            "observed": amendment_values,
        }
    runtime_budget = dict(_formal_runtime_profile().get("runtime_budget") or {})
    matrix_warmup_evaluations = sum(
        int(item["project_count"])
        * config.warmups_per_project
        * int(item["rule_count"])
        for item in plan
    )
    soak_warmup_evaluations = (
        config.soak_project_count * config.warmups_per_project * config.soak_rule_count
    )
    offline_rule_count = max(config.rule_counts)
    offline_measured_evaluations = 2 * offline_rule_count
    offline_warmup_evaluations = offline_rule_count
    fault_allowance = int(
        runtime_budget.get("conservative_fault_evaluation_allowance", -1)
    )
    planned_evaluations = (
        observed_checks["matrix_expected_evaluations"]
        + matrix_warmup_evaluations
        + observed_checks["soak_expected_evaluations"]
        + soak_warmup_evaluations
        + offline_measured_evaluations
        + offline_warmup_evaluations
        + fault_allowance
    )
    evaluation_seconds = float(
        runtime_budget.get("validated_seconds_per_serial_evaluation", -1)
    )
    projected_seconds = planned_evaluations * evaluation_seconds
    soak_batches = math.ceil(config.soak_events / config.soak_batch_size)
    matrix_warmup_wait_seconds = sum(
        int(item["project_count"]) * config.warmups_per_project * config.timeout_seconds
        for item in plan
    )
    sequential_wait_seconds = sum(
        int(item["events"]) * config.timeout_seconds
        for item in plan
        if item["mode"] == "sequential"
    )
    burst_wait_seconds = sum(
        config.drain_timeout_seconds for item in plan if item["mode"] == "burst"
    )
    soak_wait_seconds = (
        config.soak_project_count * config.warmups_per_project * config.timeout_seconds
        + soak_batches * config.drain_timeout_seconds
        + config.drain_timeout_seconds
        + soak_batches * SOAK_BATCH_SETTLE_SECONDS
        + config.timeout_seconds
    )
    wait_reserve = float(runtime_budget.get("bounded_wait_reserve_seconds", -1))
    bounded_wait_envelope = (
        matrix_warmup_wait_seconds
        + sequential_wait_seconds
        + burst_wait_seconds
        + soak_wait_seconds
        + wait_reserve
    )
    budget_checks = {
        "matrix_warmup_evaluations": matrix_warmup_evaluations,
        "soak_warmup_evaluations": soak_warmup_evaluations,
        "offline_measured_evaluations": offline_measured_evaluations,
        "offline_warmup_evaluations": offline_warmup_evaluations,
        "planned_evaluations_including_matrix_soak_all_warmups_offline_and_conservative_fault_allowance": planned_evaluations,
        "projected_inference_seconds": projected_seconds,
        "projected_days": round(projected_seconds / 86400, 6),
        "conservative_bounded_wait_envelope_seconds": bounded_wait_envelope,
        "conservative_bounded_wait_envelope_days": round(
            bounded_wait_envelope / 86400, 6
        ),
    }
    for name, observed in budget_checks.items():
        if runtime_budget.get(name) != observed:
            mismatches[f"runtime_budget.{name}"] = {
                "expected": runtime_budget.get(name),
                "observed": observed,
            }
    if bounded_wait_envelope >= float(
        runtime_budget.get("seven_day_budget_seconds", -1)
    ):
        mismatches["runtime_budget.seven_day_feasibility"] = {
            "budget": runtime_budget.get("seven_day_budget_seconds"),
            "bounded_wait_envelope": bounded_wait_envelope,
        }
    if mismatches:
        raise SystemsHarnessError(
            "formal configuration differs from protocol v3 amendment 008: "
            + json.dumps(mismatches, sort_keys=True)
        )
    expected_partition = str(effective.get("slurm_partition", "ALL"))
    if (
        require_partition
        and os.environ.get("SLURM_JOB_PARTITION", "") != expected_partition
    ):
        raise SystemsHarnessError(
            f"formal watgpu execution requires SLURM_JOB_PARTITION={expected_partition!r}"
        )


def _fault_names(value: str) -> tuple[str, ...]:
    if value.strip().lower() == "none":
        return ()
    if value.strip().lower() == "all":
        return tuple(
            name
            for name, capability in FAULT_CAPABILITIES.items()
            if capability["feasible"]
        )
    names = tuple(item.strip() for item in value.split(",") if item.strip())
    unknown = sorted(set(names) - set(FAULT_CAPABILITIES))
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown fault names: {','.join(unknown)}")
    return names


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _git_blob_sha1(path: Path) -> str:
    value = path.read_bytes()
    return hashlib.sha1(
        f"blob {len(value)}\0".encode("ascii") + value,
        usedforsecurity=False,
    ).hexdigest()


def _replacement_retention_plan(
    replacement: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if replacement.get("kind") != "replacement_attempt":
        return {"self_contained": True, "copies": [], "references": []}, []
    retained: list[dict[str, Any]] = []
    copies: list[dict[str, Any]] = []
    references: list[dict[str, str]] = []
    source_paths: set[Path] = set()
    source_identities: set[tuple[int, int]] = set()
    target_paths: set[Path] = set()

    def add(role: str, source: str, target: str, byte_count: int, digest: str) -> None:
        source_path = Path(source)
        target_path = Path(target)
        if (
            not source_path.is_absolute()
            or source_path.is_symlink()
            or not source_path.is_file()
            or source_path.resolve(strict=True) != source_path
            or not target_path.parts
            or target_path.is_absolute()
            or ".." in target_path.parts
            or source_path in source_paths
            or target_path in target_paths
        ):
            raise SystemsHarnessError(
                "replacement retention copy set has a path collision or alias"
            )
        if (
            type(byte_count) is not int
            or byte_count < 0
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise SystemsHarnessError(
                "replacement retention copy has an invalid byte/hash binding"
            )
        observed_bytes = 0
        observed_digest = hashlib.sha256()
        with source_path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise SystemsHarnessError(
                    "replacement retention source is not a regular file"
                )
            identity = (opened.st_dev, opened.st_ino)
            if identity in source_identities:
                raise SystemsHarnessError(
                    "replacement retention copy set repeats a source identity"
                )
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                observed_bytes += len(chunk)
                observed_digest.update(chunk)
            closed = os.fstat(handle.fileno())
        if (
            opened.st_dev != closed.st_dev
            or opened.st_ino != closed.st_ino
            or opened.st_size != closed.st_size
            or observed_bytes != byte_count
            or observed_digest.hexdigest() != digest
        ):
            raise SystemsHarnessError(
                "replacement retention source changed before copy planning"
            )
        source_paths.add(source_path)
        source_identities.add(identity)
        target_paths.add(target_path)
        entry = {
            "role": role,
            "retained_path": target_path.as_posix(),
            "bytes": int(byte_count),
            "sha256": str(digest),
        }
        retained.append(entry)
        copies.append(
            {
                "source_path": str(source_path),
                "retained_path": target_path.as_posix(),
                "bytes": int(byte_count),
                "sha256": str(digest),
            }
        )

    add(
        "replacement_receipt",
        str(replacement["receipt_path"]),
        "replacement/replacement.json",
        int(replacement["receipt_bytes"]),
        str(replacement["receipt_sha256"]),
    )
    artifacts = dict(replacement.get("predecessor_artifacts") or {})
    predecessor_launch = artifacts.get("launch.json") or {}
    predecessor_root = Path(str(predecessor_launch.get("path", ""))).parent
    for receipt in replacement.get("predecessor_tree") or []:
        relative = Path(str(receipt.get("relative_path", "")))
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise SystemsHarnessError(
                "replacement predecessor tree contains an invalid relative path"
            )
        if receipt.get("type") != "regular_file":
            continue
        source = predecessor_root / relative
        add(
            f"predecessor_tree:{relative.as_posix()}",
            str(source),
            f"replacement/predecessor-tree/{relative.as_posix()}",
            int(receipt["bytes"]),
            str(receipt["sha256"]),
        )
    evidence_receipts = list(replacement.get("evidence_receipts") or [])
    evidence_kinds = [str(receipt.get("kind", "")) for receipt in evidence_receipts]
    expected_evidence_kinds = [
        "launch_wide_cache_root_adjudication",
        "paw_cache_semantics_receipt",
        "all_partition_paw_cache_canary",
        "whole_attempt_replacement_validation",
        "r02_effective_cache_forensic_inventory",
        "r02_terminal_archive",
        "scheduler_sacct",
        "scheduler_stdout",
        "scheduler_stderr",
    ]
    correction = dict(replacement.get("whole_attempt_protocol_correction") or {})
    if correction and evidence_kinds != expected_evidence_kinds:
        raise SystemsHarnessError(
            "whole-attempt evidence order differs from its frozen layout"
        )
    canary_archive_files = list(
        (
            (replacement.get("r02_partial_terminal_forensics") or {}).get(
                "validated_canary_archive_files"
            )
        )
        or []
    )
    whole_attempt_validation_target: str | None = None
    for index, receipt in enumerate(evidence_receipts):
        kind = (
            re.sub(r"[^A-Za-z0-9_.-]+", "_", str(receipt["kind"])).strip("._")
            or "evidence"
        )
        if receipt["kind"] == "all_partition_paw_cache_canary":
            archive_root = Path(str(receipt["path"])).parent
            if (
                len(canary_archive_files) != 28
                or any(
                    not isinstance(item, dict)
                    or set(item) != {"basename", "path", "bytes", "sha256"}
                    for item in canary_archive_files
                )
                or len({str(item["basename"]) for item in canary_archive_files}) != 28
                or any(
                    Path(str(item["path"])).parent != archive_root
                    or Path(str(item["path"])).name != item["basename"]
                    for item in canary_archive_files
                )
            ):
                raise SystemsHarnessError(
                    "validated canary archive is not an exact 28-file closure"
                )
            receipt_names = [
                str(item["basename"])
                for item in canary_archive_files
                if re.fullmatch(
                    r"rap-eacl-paw-cache-canary-v4-[1-9][0-9]*\.json",
                    str(item["basename"]),
                )
            ]
            if len(receipt_names) != 1:
                raise SystemsHarnessError(
                    "validated canary archive semantic receipt identity differs"
                )
            canary_job_id = (
                receipt_names[0]
                .removeprefix("rap-eacl-paw-cache-canary-v4-")
                .removesuffix(".json")
            )
            expected_archive_names = {
                template.replace("<job_id>", canary_job_id)
                for template in _COMPONENT_CANARY_ARCHIVE_MEMBER_TEMPLATES
            } | {"evidence.sha256", "evidence.sha256.sha256"}
            if {
                str(item["basename"]) for item in canary_archive_files
            } != expected_archive_names:
                raise SystemsHarnessError(
                    "validated canary archive member names differ"
                )
            sidecar = next(
                (
                    item
                    for item in canary_archive_files
                    if item["basename"] == "evidence.sha256.sha256"
                ),
                None,
            )
            if (
                sidecar is None
                or sidecar["path"] != receipt["path"]
                or sidecar["bytes"] != receipt["bytes"]
                or sidecar["sha256"] != receipt["sha256"]
            ):
                raise SystemsHarnessError(
                    "validated canary archive top anchor differs from evidence"
                )
            target_root = "replacement/evidence/002-all_partition_paw_cache_canary"
            for item in sorted(
                canary_archive_files, key=lambda value: os.fsencode(value["basename"])
            ):
                add(
                    f"evidence:{receipt['kind']}:{item['basename']}",
                    str(item["path"]),
                    f"{target_root}/{item['basename']}",
                    int(item["bytes"]),
                    str(item["sha256"]),
                )
            continue
        retained_target = f"replacement/evidence/{index:03d}-{kind}"
        add(
            f"evidence:{receipt['kind']}",
            str(receipt["path"]),
            retained_target,
            int(receipt["bytes"]),
            str(receipt["sha256"]),
        )
        if receipt["kind"] == "whole_attempt_replacement_validation":
            whole_attempt_validation_target = retained_target
    historical = dict(correction.get("historical_validation") or {})
    if correction:
        whole_attempt_validation = next(
            (
                item
                for item in evidence_receipts
                if item.get("kind") == "whole_attempt_replacement_validation"
            ),
            None,
        )
        if (
            whole_attempt_validation is None
            or whole_attempt_validation_target is None
            or historical.get("receipt_path") != whole_attempt_validation.get("path")
            or historical.get("receipt_bytes") != whole_attempt_validation.get("bytes")
            or historical.get("receipt_sha256")
            != whole_attempt_validation.get("sha256")
        ):
            raise SystemsHarnessError(
                "historical validation is not the typed whole-attempt evidence"
            )
        references.append(
            {
                "role": "gate:historical_validation",
                "retained_path": whole_attempt_validation_target,
            }
        )
    return {
        "self_contained": True,
        "copies": retained,
        "references": references,
    }, copies


def _runtime_preflight_retention_plan(
    runtime: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not runtime:
        return {"self_contained": True, "copies": []}, []
    retained: list[dict[str, Any]] = []
    copies: list[dict[str, Any]] = []
    for role, value, target in (
        (
            "setup_receipt",
            (runtime.get("setup_preflight_receipt") or {}).get("file") or {},
            "runtime/preflight/setup-receipt.json",
        ),
        (
            "setup_log",
            runtime.get("setup_preflight_log") or {},
            "runtime/preflight/setup.log",
        ),
    ):
        source = str(value.get("resolved_path") or value.get("path") or "")
        entry = {
            "role": role,
            "retained_path": target,
            "bytes": int(value.get("bytes", -1)),
            "sha256": str(value.get("sha256", "")),
        }
        if not source or entry["bytes"] < 0 or not entry["sha256"]:
            raise SystemsHarnessError(
                f"formal runtime omitted retainable {role} receipt"
            )
        retained.append(entry)
        copies.append(
            {
                "source_path": source,
                "retained_path": target,
                "bytes": entry["bytes"],
                "sha256": entry["sha256"],
            }
        )
    return {"self_contained": True, "copies": retained}, copies


def _launch_manifest(
    attempt_dir: Path,
    config: MatrixConfig,
    plan: Sequence[dict[str, Any]],
    bundle: ArtifactBundle,
    *,
    formal: bool,
) -> dict[str, Any]:
    attempt_id = attempt_dir.name
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", attempt_id):
        raise SystemsHarnessError(
            "formal attempt directory basename must be a caller-supplied unique slug"
        )
    contract = _formal_contract() if formal else _formal_base_contract()
    if formal:
        source, source_topology = _formal_source_state()
    else:
        source = integrated._git_state()
        source_topology = None
    runtime_profile = _formal_runtime_profile() if formal else {}
    replacement = (
        replacement_launch_binding(
            attempt_dir,
            os.environ.get("RAP_EACL_REPLACEMENT_RECEIPT"),
        )
        if formal
        else {"kind": "candidate_not_applicable"}
    )
    replacement_retention, prelaunch_copies = _replacement_retention_plan(replacement)
    if formal:
        expected_repo = str(
            (runtime_profile.get("cache_and_dependency_receipt") or {}).get(
                "formal_repository", ""
            )
        )
        if str(REPO_ROOT.resolve()) != expected_repo:
            raise SystemsHarnessError(
                f"formal repository must resolve to {expected_repo}, got {REPO_ROOT.resolve()}"
            )
        try:
            runtime = formal_runtime_receipt(
                runtime_profile,
                [artifact.program_id for artifact in bundle.artifacts],
                raw_attempt_id=attempt_id,
                expected_replacement_chain=replacement,
            )
        except RuntimeContractError as exc:
            raise SystemsHarnessError(str(exc)) from exc
    else:
        runtime = None
    runtime_retention, runtime_prelaunch_copies = _runtime_preflight_retention_plan(
        runtime
    )
    if formal:
        protocol_paths = list(
            (contract.get("effective_protocol_identity") or {}).get(
                "interpretation_order"
            )
            or []
        )
    else:
        protocol_paths = [
            str(item["path"])
            for item in (
                (contract.get("effective_protocol_identity") or {}).get("frozen_prefix")
                or []
            )
        ]
        protocol_paths.append(str(FORMAL_BASE_AMENDMENT.relative_to(REPO_ROOT)))
    protocol_documents = [
        {
            "path": str(relative),
            "sha256": _sha256_file(REPO_ROOT / str(relative)),
        }
        for relative in protocol_paths
    ]
    full_attempt = build_full_attempt_plan(config)
    runner = Path(__file__).resolve()
    identity = {
        "attempt_id": attempt_id,
        "study_mode": FORMAL_STUDY_MODE if formal else "candidate_noncanonical",
        "attempt_replacement": replacement,
        "replacement_retention": replacement_retention,
        "runtime_preflight_retention": runtime_retention,
        "git": source,
        "git_topology": source_topology,
        "runner": {
            "path": str(runner.relative_to(REPO_ROOT)),
            "sha256": _sha256_file(runner),
            "git_blob": _git_blob_sha1(runner),
        },
        "protocol_documents": protocol_documents,
        "config": json.loads(json.dumps(asdict(config))),
        "plan_sha256": _sha256_bytes(_canonical_json_bytes(list(plan))),
        "whole_attempt_protocol_correction": (
            {
                "analysis_id": FORMAL_COMPONENT_ANALYSIS_ID,
                "full_plan_unit_count": full_attempt["unit_count"],
                "full_plan_sha256": full_attempt["canonical_sha256"],
                "full_plan_stored_sha256": FORMAL_FULL_PLAN_STORED_SHA256,
                "ordered_membership_sha256": full_attempt["ordered_membership_sha256"],
                "primary_source_attempt_id": full_attempt["primary_source_attempt_id"],
                "execution_roles": full_attempt["execution_roles"],
            }
            if formal
            else None
        ),
        "artifact_provenance": bundle.provenance,
        "formal_runtime": runtime,
        "packages": {
            name: integrated._package_version(name)
            for name in (
                "rules-as-programs",
                "programasweights",
                "llama-cpp-python",
                "psutil",
            )
        },
        "machine": {
            "platform": platform.platform(),
            "python": sys.version,
            "cpu_count_logical": os.cpu_count(),
        },
        "slurm": {
            "job_id": os.environ.get("SLURM_JOB_ID", ""),
            "partition": os.environ.get("SLURM_JOB_PARTITION", ""),
            "node_list": os.environ.get("SLURM_JOB_NODELIST", ""),
        },
    }
    return {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "identity": identity,
        "identity_sha256": _sha256_bytes(_canonical_json_bytes(identity)),
        "plan": list(plan),
        "retention": {
            "immutable": True,
            "unit_terminal_journal": "units.jsonl",
            "runtime_roots": "runtime/",
        },
        "_prelaunch_copy_specs": [
            *prelaunch_copies,
            *runtime_prelaunch_copies,
        ],
    }


def _attempt_exit_code(status: str) -> int:
    return {
        "completed": 0,
        "plan_only": 0,
        "completed_with_system_violations": 3,
        "incomplete_harness_error": 2,
        "incomplete_infrastructure_error": 4,
        "incomplete_unclassified_failure": 5,
    }.get(status, 5)


def _capture_formal_cache_end(
    bundle: ArtifactBundle,
    recorder: AttemptRecorder,
) -> dict[str, Any]:
    try:
        runtime_profile = _formal_runtime_profile()
        launch_cache_receipt = dict(
            (
                (
                    (recorder.manifest.get("identity") or {}).get("formal_runtime")
                    or {}
                ).get("paw_cache")
                or {}
            )
        )
        changed_root = recorder.root / "runtime" / "cache-end-changed-files"
        return retain_cache_end_receipt(
            runtime_profile,
            [artifact.program_id for artifact in bundle.artifacts],
            launch_receipt=launch_cache_receipt,
            changed_files_root=changed_root,
        )
    except RuntimeContractError as exc:
        return {
            "status": "system_violation",
            "unchanged": False,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }
    except BaseException as exc:
        return _retained_error(exc, recorder.root / "runtime")


def _merge_global_outcome(
    result: dict[str, Any], name: str, outcome: dict[str, Any]
) -> dict[str, Any]:
    merged = dict(result)
    global_outcomes = dict(merged.get("global_outcomes") or {})
    statuses = list(global_outcomes.get("statuses") or [])
    status = str(outcome.get("status", "unclassified_failure"))
    global_outcomes[name] = outcome
    if status != "completed":
        statuses.append(status)
    global_outcomes["statuses"] = statuses
    merged["global_outcomes"] = global_outcomes
    if status == "system_violation":
        merged["system_violation_units"] = (
            int(merged.get("system_violation_units", 0)) + 1
        )
    current = str(merged.get("status", "incomplete_unclassified_failure"))
    ranks = {
        "completed": 0,
        "completed_with_system_violations": 1,
        "incomplete_harness_error": 2,
        "incomplete_infrastructure_error": 3,
        "incomplete_unclassified_failure": 4,
    }
    proposed = {
        "completed": current,
        "system_violation": "completed_with_system_violations",
        "harness_error": "incomplete_harness_error",
        "infrastructure_error": "incomplete_infrastructure_error",
        "unclassified_failure": "incomplete_unclassified_failure",
    }.get(status, "incomplete_unclassified_failure")
    if ranks.get(proposed, 4) > ranks.get(current, 4):
        merged["status"] = proposed
    if status in {"harness_error", "infrastructure_error", "unclassified_failure"}:
        merged["primary_numeric_eligible"] = False
    return merged


def _finalize_source_state(
    result: dict[str, Any], attempt_root: Path | None
) -> dict[str, Any]:
    """Capture the terminal source receipt and apply its eligibility decision."""
    merged = dict(result)
    git = dict(merged.get("git") or {})
    source_start = dict(git.get("start") or {})
    try:
        source_end: dict[str, Any] = _git_state_allowing_attempt(attempt_root)
        source_error = None
    except BaseException as exc:
        source_error = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        }
        source_end = {
            "status": "unavailable",
            "error": source_error,
        }
    source_unchanged = source_error is None and source_start == source_end
    git.update(
        {
            "start": source_start,
            "end": source_end,
            "unchanged_during_attempt": source_unchanged,
            "end_receipt_pending": False,
            "end_receipt_error": source_error,
        }
    )
    merged["git"] = git
    if not source_unchanged:
        merged["status"] = "incomplete_unclassified_failure"
        merged["primary_numeric_eligible"] = False
        merged["source_integrity_failure"] = {
            "cause": (
                "source_end_receipt_unavailable"
                if source_error is not None
                else "source_changed_during_attempt"
            ),
            "rerun_eligible": False,
        }
    return merged


def _aborted_attempt_result(
    exc: BaseException,
    *,
    config: MatrixConfig,
    plan: Sequence[dict[str, Any]],
    formal: bool,
    attempt_root: Path | None,
    launch_git: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    retained = _retained_error(exc, attempt_root)
    source_start = dict(launch_git or integrated._git_state())
    unit_classification = str(retained["status"])
    status = {
        "harness_error": "incomplete_harness_error",
        "infrastructure_error": "incomplete_infrastructure_error",
        "unclassified_failure": "incomplete_unclassified_failure",
        # A measured system violation is not rerun eligibility, but an escaping
        # exception means the runner failed to finish the independent plan.  The
        # cause of that plan-level incompleteness requires adjudication.
        "system_violation": "incomplete_unclassified_failure",
    }.get(unit_classification, "incomplete_unclassified_failure")
    return {
        "schema_version": 2,
        "status": status,
        "complete_plan": False,
        "primary_numeric_eligible": False,
        "all_planned_units_terminal": False,
        "terminal_unit_count": 0,
        "planned_unit_count": len(plan),
        "system_violation_units": int(unit_classification == "system_violation"),
        "protocol_status": (FORMAL_STUDY_MODE if formal else "candidate_noncanonical"),
        "study_mode": FORMAL_STUDY_MODE if formal else "candidate_noncanonical",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": asdict(config),
        "plan": list(plan),
        "git": {
            "start": source_start,
            "end": None,
            "unchanged_during_attempt": None,
            "end_receipt_pending": True,
        },
        "abort": {
            **retained,
            "attempt_status_rule": (
                "an escaping measured exception retains its unit classification, "
                "while unfinished orchestration is incomplete_unclassified_failure"
                if unit_classification == "system_violation"
                else "attempt status follows the positively evidenced abort class"
            ),
        },
    }


def _artifact_initialization_abort_result(
    recorder: AttemptRecorder,
    *,
    config: MatrixConfig,
    plan: Sequence[dict[str, Any]],
    formal: bool,
) -> dict[str, Any] | None:
    """Abort before measurement when attempt publication durability is uncertain."""

    if not recorder.initialization_warnings:
        return None
    try:
        raise ExternalInfrastructureError("; ".join(recorder.initialization_warnings))
    except ExternalInfrastructureError as exc:
        return _aborted_attempt_result(
            exc,
            config=config,
            plan=plan,
            formal=formal,
            attempt_root=recorder.root,
            launch_git=dict((recorder.manifest.get("identity") or {}).get("git") or {}),
        )


def _exclusive_canonical_json(path: Path, value: Mapping[str, Any]) -> None:
    """Durably create one canonical JSON object plus exactly one LF."""

    payload = _canonical_json_bytes(dict(value)) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short canonical JSON write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _formal_attempt_dir_from_argv(argv: Sequence[str]) -> Path | None:
    try:
        index = list(argv).index("--attempt-dir")
        raw = list(argv)[index + 1]
    except (ValueError, IndexError):
        return None
    return Path(raw).expanduser().resolve()


def _last_complete_lifecycle_phase(root: Path) -> str:
    path = root / "fatal-lifecycle.jsonl"
    if not path.is_file() or path.is_symlink():
        return "unavailable_before_first_lifecycle_record"
    phase = "unavailable_before_first_lifecycle_record"
    for raw in path.read_bytes().splitlines(keepends=True):
        if not raw.endswith(b"\n"):
            break
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            break
        if not isinstance(value, dict) or not isinstance(value.get("phase"), str):
            break
        phase = str(value["phase"])
    return phase


def _write_fatal_exception_envelope(exc: BaseException) -> None:
    root = _formal_attempt_dir_from_argv(sys.argv[1:])
    if (
        root is None
        or not root.is_dir()
        or root.is_symlink()
        or (root / "result.json").exists()
        or (root / "fatal-exception.json").exists()
    ):
        return
    exception_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
    traceback_utf8 = "".join(
        traceback.TracebackException.from_exception(exc).format(chain=True)
    )
    _exclusive_canonical_json(
        root / "fatal-exception.json",
        {
            "schema_version": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "raw_attempt_id": root.name,
            "phase": _last_complete_lifecycle_phase(root),
            "exception_type": exception_type,
            "exception_message": str(exc),
            "traceback_utf8": traceback_utf8,
        },
    )


def _supervisor_file_receipt(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SystemsHarnessError(f"supervisor artifact is not regular: {path}")
        digest = hashlib.sha256()
        byte_count = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            byte_count += len(chunk)
        closed_over = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) != (
            closed_over.st_dev,
            closed_over.st_ino,
            closed_over.st_size,
        ) or byte_count != closed_over.st_size:
            raise SystemsHarnessError(f"supervisor artifact changed while read: {path}")
    finally:
        os.close(descriptor)
    return {
        "path": str(path),
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
        "type": "regular_file",
    }


def _supervisor_process_identity(pid: int) -> dict[str, Any]:
    stat_path = Path(f"/proc/{pid}/stat")
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    try:
        first = stat_path.read_bytes()
        command = cmdline_path.read_bytes()
        second = stat_path.read_bytes()
    except OSError as exc:
        raise SystemsHarnessError(f"process identity vanished for pid {pid}") from exc

    def start_ticks(raw: bytes) -> int:
        suffix = raw[raw.rfind(b")") + 2 :].split()
        if len(suffix) < 20:
            raise SystemsHarnessError(f"malformed /proc stat for pid {pid}")
        return int(suffix[19])

    first_ticks = start_ticks(first)
    if first_ticks != start_ticks(second) or first_ticks <= 0 or not command:
        raise SystemsHarnessError(f"unstable process identity for pid {pid}")
    return {
        "pid": pid,
        "proc_start_ticks": first_ticks,
        "command_sha256": hashlib.sha256(command).hexdigest(),
    }


def _supervisor_environment() -> dict[str, str]:
    environment = {
        str(name): str(value)
        for name, value in os.environ.items()
        if not any(
            marker in str(name).upper() for marker in _SUPERVISOR_SENSITIVE_ENV_MARKERS
        )
        and name != "PROGRAMASWEIGHTS_CACHE_DIR"
    }
    corrected = dict(_formal_contract()["corrected_direct_paw_cache_contract"])
    environment.update(
        {
            "PAW_CACHE_DIR": str(corrected["r03_paw_cache_dir_exact"]),
            "RAP_EACL_SUPERVISED_CHILD": "1",
        }
    )
    for name in ("SLURM_JOB_ID", "SLURM_JOB_PARTITION", "SLURM_JOB_NODELIST"):
        if not environment.get(name):
            raise SystemsHarnessError(f"supervisor requires nonempty {name}")
    if not environment["SLURM_JOB_ID"].isdigit():
        raise SystemsHarnessError("supervisor SLURM_JOB_ID must be decimal")
    if environment["SLURM_JOB_PARTITION"] != "ALL":
        raise SystemsHarnessError("formal supervisor requires partition ALL")
    forbidden = sorted(
        name
        for name in environment
        if any(marker in name.upper() for marker in _SUPERVISOR_SENSITIVE_ENV_MARKERS)
        or name == "PROGRAMASWEIGHTS_CACHE_DIR"
    )
    if forbidden:
        raise SystemsHarnessError(
            f"supervisor child environment leaked keys: {forbidden}"
        )
    return dict(sorted(environment.items()))


def _supervisor_exception_diagnostic(
    stage: str, exc: BaseException
) -> dict[str, str]:
    return {
        "stage": stage,
        "type": f"{type(exc).__module__}.{type(exc).__qualname__}",
        "message": str(exc),
        "traceback_utf8": "".join(
            traceback.TracebackException.from_exception(exc).format(chain=True)
        ),
    }


def _wait_started_supervisor_child(
    child: subprocess.Popen[bytes], diagnostics: list[dict[str, str]]
) -> int:
    """Wait without a timeout; retain transient wait failures and retry."""

    while True:
        try:
            return child.wait()
        except BaseException as exc:
            diagnostics.append(_supervisor_exception_diagnostic("child_wait", exc))


def _register_initial_supervisor_child(
    pid: int,
    registered: dict[tuple[int, int], dict[str, Any]],
    diagnostics: list[dict[str, str]],
) -> None:
    """Best-effort identity capture that can never abandon a started child."""

    try:
        identity = _supervisor_process_identity(pid)
        registered[(pid, int(identity["proc_start_ticks"]))] = identity
    except BaseException as exc:
        diagnostics.append(
            _supervisor_exception_diagnostic("initial_child_identity", exc)
        )


def _start_supervisor_drain_thread(
    *,
    target: Callable[..., None],
    args: tuple[Any, Any],
    diagnostics: list[dict[str, str]],
) -> threading.Thread:
    """Start a required lossless drain, retaining and retrying sync failures."""

    while True:
        thread = threading.Thread(target=target, args=args, daemon=True)
        try:
            thread.start()
            return thread
        except BaseException as exc:
            diagnostics.append(
                _supervisor_exception_diagnostic("stream_drain_thread_start", exc)
            )


def _supervisor_observed_exit(
    returncode: int | None, spawn_error: BaseException | None
) -> dict[str, Any]:
    if spawn_error is not None:
        return {
            "state": "not_started",
            "returncode": None,
            "exit_code": None,
            "signal": None,
            "spawn_error": {
                "type": f"{type(spawn_error).__module__}.{type(spawn_error).__qualname__}",
                "message": str(spawn_error),
                "traceback_utf8": "".join(
                    traceback.TracebackException.from_exception(spawn_error).format(
                        chain=True
                    )
                ),
            },
        }
    if returncode is None:
        raise SystemsHarnessError("started supervisor child was not waited")
    return {
        "state": "waited",
        "returncode": returncode,
        "exit_code": returncode if returncode >= 0 else None,
        "signal": -returncode if returncode < 0 else None,
        "spawn_error": None,
    }


def _supervisor_live_identities(
    *,
    process_group_id: int | None,
    registered: Mapping[tuple[int, int], dict[str, Any]],
) -> list[dict[str, Any]]:
    identities: dict[tuple[int, int], dict[str, Any]] = {}
    for process in psutil.process_iter(["pid"]):
        pid = int(process.info["pid"])
        if pid == os.getpid():
            continue
        in_group = False
        if process_group_id is not None:
            try:
                in_group = os.getpgid(pid) == process_group_id
            except OSError:
                pass
        try:
            identity = _supervisor_process_identity(pid)
        except (OSError, ValueError, SystemsHarnessError):
            continue
        key = (pid, int(identity["proc_start_ticks"]))
        if in_group or key in registered:
            identities[key] = identity
    return sorted(
        identities.values(),
        key=lambda value: (
            int(value["pid"]),
            int(value["proc_start_ticks"]),
            str(value["command_sha256"]),
        ),
    )


def _supervisor_open_writers(root: Path) -> list[dict[str, Any]]:
    writers: list[dict[str, Any]] = []
    resolved_root = root.resolve(strict=True)
    for process in psutil.process_iter(["pid"]):
        pid = int(process.info["pid"])
        try:
            identity = _supervisor_process_identity(pid)
            for fd_path in Path(f"/proc/{pid}/fd").iterdir():
                if not fd_path.name.isdigit():
                    continue
                descriptor = int(fd_path.name)
                try:
                    target = fd_path.resolve(strict=True)
                    target.relative_to(resolved_root)
                    info = Path(f"/proc/{pid}/fdinfo/{descriptor}").read_text(
                        encoding="utf-8"
                    )
                    match = re.search(r"^flags:\s*([0-7]+)$", info, re.MULTILINE)
                    if match is None:
                        continue
                    flags = int(match.group(1), 8)
                    if flags & os.O_ACCMODE == os.O_RDONLY:
                        continue
                except (OSError, ValueError):
                    continue
                writers.append(
                    {
                        "process": identity,
                        "fd": descriptor,
                        "resolved_path": str(target),
                        "open_flags_octal": "0" + format(flags, "o"),
                    }
                )
        except (OSError, ValueError, SystemsHarnessError, psutil.Error):
            continue
    return sorted(
        writers,
        key=lambda value: (
            int(value["process"]["pid"]),
            int(value["process"]["proc_start_ticks"]),
            int(value["fd"]),
            str(value["resolved_path"]),
        ),
    )


def _supervisor_tree_inventory(
    root: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    regular_count = 0
    regular_bytes = 0
    for path in sorted(
        root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()
    ):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SystemsHarnessError(f"attempt tree contains symlink: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            entries.append(
                {
                    "relative_path": relative,
                    "type": "directory",
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            )
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemsHarnessError(
                f"attempt tree contains special entry: {relative}"
            )
        receipt = _supervisor_file_receipt(path)
        entries.append(
            {
                "relative_path": relative,
                "type": "regular_file",
                "mode": stat.S_IMODE(metadata.st_mode),
                "bytes": receipt["bytes"],
                "sha256": receipt["sha256"],
            }
        )
        regular_count += 1
        regular_bytes += int(receipt["bytes"])
    canonical = json.dumps(
        entries, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return entries, {
        "entry_count": len(entries),
        "regular_file_count": regular_count,
        "regular_file_bytes": regular_bytes,
        "canonical_json_bytes": len(canonical),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }


def _supervisor_quiesce(
    *,
    child: subprocess.Popen[bytes] | None,
    process_group_id: int | None,
    registered: Mapping[tuple[int, int], dict[str, Any]],
    drain_threads: Sequence[threading.Thread],
    stream_handles: Sequence[Any],
    stream_paths: Mapping[str, Path],
    attempt_root: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    before = (
        _supervisor_live_identities(
            process_group_id=process_group_id, registered=registered
        )
        if child is not None
        else []
    )
    actions: list[dict[str, Any]] = []
    for identity in before:
        result = "sent"
        try:
            os.kill(int(identity["pid"]), signal.SIGTERM)
        except ProcessLookupError:
            result = "already_exited"
        actions.append(
            {
                "process": identity,
                "signal": "TERM",
                "sent_monotonic_ns": time.monotonic_ns(),
                "result": result,
            }
        )
    while time.monotonic() - started < 5.0:
        if not _supervisor_live_identities(
            process_group_id=process_group_id, registered=registered
        ):
            break
        time.sleep(0.05)
    survivors = (
        _supervisor_live_identities(
            process_group_id=process_group_id, registered=registered
        )
        if child is not None
        else []
    )
    for identity in survivors:
        result = "sent"
        try:
            os.kill(int(identity["pid"]), signal.SIGKILL)
        except ProcessLookupError:
            result = "already_exited"
        actions.append(
            {
                "process": identity,
                "signal": "KILL",
                "sent_monotonic_ns": time.monotonic_ns(),
                "result": result,
            }
        )
    for thread in drain_threads:
        thread.join(max(0.0, 30.0 - (time.monotonic() - started)))
    for handle in stream_handles:
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
    after = (
        _supervisor_live_identities(
            process_group_id=process_group_id, registered=registered
        )
        if child is not None
        else []
    )
    drained = {
        name: _supervisor_file_receipt(path) for name, path in stream_paths.items()
    }
    first_writers: list[dict[str, Any]] = []
    second_writers: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    stable_tree: dict[str, Any] | None = None
    root_safe = False
    try:
        root_safe = (
            attempt_root.exists()
            and not attempt_root.is_symlink()
            and attempt_root.is_dir()
            and attempt_root.stat().st_uid == os.getuid()
        )
        if root_safe:
            first_writers = _supervisor_open_writers(attempt_root)
            first_entries, first_snapshot = _supervisor_tree_inventory(attempt_root)
            if not first_writers:
                for entry in first_entries:
                    if entry["type"] != "regular_file":
                        continue
                    path = attempt_root / str(entry["relative_path"])
                    descriptor = os.open(
                        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    )
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    sinks.append(_supervisor_file_receipt(path))
                directories = [
                    attempt_root,
                    *(
                        path
                        for path in attempt_root.rglob("*")
                        if path.is_dir() and not path.is_symlink()
                    ),
                ]
                for directory in sorted(
                    directories, key=lambda value: len(value.parts), reverse=True
                ):
                    _fsync_directory(directory)
            time.sleep(0.25)
            second_writers = _supervisor_open_writers(attempt_root)
            second_entries, second_snapshot = _supervisor_tree_inventory(attempt_root)
            stable_tree = {
                "first": first_snapshot,
                "second": second_snapshot,
                "stable": first_entries == second_entries,
            }
    except (OSError, SystemsHarnessError):
        root_safe = False
    passed = (
        not after
        and all(not thread.is_alive() for thread in drain_threads)
        and (
            not attempt_root.exists()
            or (
                root_safe
                and not first_writers
                and not second_writers
                and stable_tree is not None
                and stable_tree["stable"]
            )
        )
    )
    return {
        "process_group_id": process_group_id,
        "bounded_settle_seconds": 30.0,
        "descendants_before": before,
        "termination_actions": actions,
        "descendants_after": after,
        "open_attempt_writers_first_scan": first_writers,
        "open_attempt_writers_second_scan": second_writers,
        "writer_scan_separation_ms": 250,
        "drained_supervisor_streams": drained,
        "fsynced_attempt_sinks": sorted(sinks, key=lambda value: value["path"]),
        "stable_attempt_tree": stable_tree,
        "passed": passed,
    }


def _observe_supervisor_product(path: Path) -> dict[str, Any]:
    if not path.exists() and not path.is_symlink():
        return {"state": "absent", "receipt": None, "validation_error": None}
    if path.is_symlink() or not path.is_file():
        return {
            "state": "present_invalid",
            "receipt": None,
            "validation_error": "terminal product is a symlink or special entry",
        }
    receipt = _supervisor_file_receipt(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("terminal product is not a JSON object")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "state": "present_invalid",
            "receipt": receipt,
            "validation_error": str(exc),
        }
    return {"state": "valid", "receipt": receipt, "validation_error": None}


def _observe_ordinary_result(root: Path) -> dict[str, Any]:
    path = root / "result.json"
    observed = _observe_supervisor_product(path)
    if observed["state"] != "valid":
        return observed
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        plan_raw = (root / "plan.json").read_bytes()
        plan = json.loads(plan_raw)
        unit_index = value.get("unit_index")
        if value.get("raw_attempt_id") != FORMAL_RAW_ATTEMPT_ID:
            raise ValueError("ordinary result raw attempt ID differs")
        if not isinstance(plan, list) or len(plan) != 430:
            raise ValueError("ordinary result plan is not the immutable 430 rows")
        if (
            len(plan_raw) != 122245
            or hashlib.sha256(plan_raw).hexdigest() != FORMAL_FULL_PLAN_STORED_SHA256
        ):
            raise ValueError("ordinary result stored plan identity differs")
        if (
            hashlib.sha256(_canonical_json_bytes(plan)).hexdigest()
            != FORMAL_FULL_PLAN_SHA256
        ):
            raise ValueError("ordinary result canonical plan identity differs")
        terminal_count = value.get("terminal_unit_count")
        if (
            value.get("planned_unit_count") != 430
            or type(terminal_count) is not int
            or not 0 <= terminal_count <= 430
            or value.get("all_planned_units_terminal") is not (terminal_count == 430)
            or value.get("complete_plan") is not (terminal_count == 430)
            or not isinstance(unit_index, list)
            or len(unit_index) != 430
        ):
            raise ValueError("ordinary result 430-row completion accounting differs")
        if not all(isinstance(item, dict) for item in unit_index):
            raise ValueError("ordinary result unit index contains a non-object")
        terminal_rows = [
            item for item in unit_index if item.get("terminal_record") is not None
        ]
        if len(terminal_rows) != terminal_count or any(
            item.get("status") not in UNIT_STATUSES
            or type(item.get("started")) is not bool
            or (item.get("terminal_record") is not None and not item.get("started"))
            for item in unit_index
        ):
            raise ValueError("ordinary result unit index is internally inconsistent")
        if _last_complete_lifecycle_phase(root) != "result_published":
            raise ValueError("ordinary result lifecycle is not durably terminal")
        if (root / "fatal-result.json").exists() or (
            root / "fatal-exception.json"
        ).exists():
            raise ValueError("ordinary result conflicts with fatal evidence")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "state": "present_invalid",
            "receipt": observed["receipt"],
            "validation_error": str(exc),
        }
    return observed


def _supervisor_attempt_state(attempt_root: Path) -> str:
    if not attempt_root.exists() and not attempt_root.is_symlink():
        return "not_published"
    if attempt_root.is_symlink() or not attempt_root.is_dir():
        return "present_invalid"
    required = ("launch.json", "plan.json", "publication.json", "units.jsonl")
    return (
        "published"
        if all(
            (attempt_root / name).is_file() and not (attempt_root / name).is_symlink()
            for name in required
        )
        else "present_invalid"
    )


def _fatal_journal_item(path: Path, root: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    complete = raw.splitlines(keepends=True)
    complete_lines = [line for line in complete if line.endswith(b"\n")]
    trailing = b"" if not complete or complete[-1].endswith(b"\n") else complete[-1]
    valid = 0
    for line in complete_lines:
        try:
            value = json.loads(line)
            if isinstance(value, (dict, list)):
                valid += 1
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return {
        "relative_path": path.relative_to(root).as_posix(),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "complete_lf_terminated_line_count": len(complete_lines),
        "strict_valid_complete_line_count": valid,
        "invalid_complete_line_count": len(complete_lines) - valid,
        "trailing_fragment_bytes": len(trailing),
        "trailing_fragment_sha256": hashlib.sha256(trailing).hexdigest(),
    }


def _fatal_core_observation(
    root: Path, relative: str, validation_errors: list[str]
) -> dict[str, Any]:
    path = root / relative
    if not path.exists() and not path.is_symlink():
        return {
            "relative_path": relative,
            "state": "absent",
            "receipt": None,
            "validation_error": None,
        }
    if path.is_symlink() or not path.is_file():
        error = f"{relative} is a symlink or special entry"
        validation_errors.append(error)
        return {
            "relative_path": relative,
            "state": "present_invalid",
            "receipt": None,
            "validation_error": error,
        }
    try:
        receipt = _supervisor_file_receipt(path)
    except (OSError, SystemsHarnessError) as exc:
        error = f"{relative}: {exc}"
        validation_errors.append(error)
        return {
            "relative_path": relative,
            "state": "present_invalid",
            "receipt": None,
            "validation_error": error,
        }
    return {
        "relative_path": relative,
        "state": "valid_regular",
        "receipt": receipt,
        "validation_error": None,
    }


def _fatal_execution_counts(
    root: Path, plan: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    errors: list[str] = []
    expected = [
        (str(item.get("component", "")), str(item.get("unit_id", ""))) for item in plan
    ]
    if len(expected) != len(set(expected)):
        errors.append("plan contains duplicate component/unit keys")
    expected_set = set(expected)
    started: set[tuple[str, str]] = set()
    terminal: set[tuple[str, str]] = set()
    for component, unit_id in expected:
        component_root = root / AttemptRecorder._safe(component)
        stem = AttemptRecorder._safe(unit_id)
        started_path = component_root / f"{stem}.started.json"
        if started_path.is_file() and not started_path.is_symlink():
            started.add((component, unit_id))
        terminal_paths = [
            component_root / f"{stem}.{phase}.json"
            for phase in ("terminal", "completed", "error")
        ]
        present = [
            path for path in terminal_paths if path.is_file() and not path.is_symlink()
        ]
        if len(present) > 1:
            errors.append(f"multiple terminal files for {component}/{unit_id}")
        elif len(present) == 1:
            terminal.add((component, unit_id))
    for path in root.glob("*/*.started.json"):
        if path.is_symlink() or not path.is_file():
            errors.append(f"invalid started entry {path.relative_to(root).as_posix()}")
    if not terminal.issubset(started):
        errors.append("terminal unit set is not a subset of started units")
    units_path = root / "units.jsonl"
    journal_keys: list[tuple[str, str]] = []
    if units_path.is_file() and not units_path.is_symlink():
        for line in units_path.read_bytes().splitlines(keepends=True):
            if not line.endswith(b"\n"):
                continue
            try:
                value = json.loads(line)
                key = (str(value["component"]), str(value["record_id"]))
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
                errors.append("units.jsonl contains an invalid complete line")
                continue
            journal_keys.append(key)
    if len(journal_keys) != len(set(journal_keys)):
        errors.append("units.jsonl contains duplicate unit keys")
    if set(journal_keys) != terminal:
        errors.append("units.jsonl terminal keys differ from terminal files")
    if not started.issubset(expected_set) or not terminal.issubset(expected_set):
        errors.append("started or terminal artifact key escapes the immutable plan")
    return {
        "planned": len(expected),
        "started": len(started),
        "terminal": len(terminal),
        "started_without_terminal": len(started - terminal),
        "never_started": len(expected_set - started),
        "units_journal_terminal_lines": len(journal_keys),
        "validation_errors": sorted(set(errors)),
    }


def _fatal_exception_observation(root: Path) -> dict[str, Any]:
    path = root / "fatal-exception.json"
    if not path.exists() and not path.is_symlink():
        return {
            "observed": False,
            "type": None,
            "message": None,
            "traceback_utf8": None,
            "envelope_state": "absent",
            "envelope": None,
            "validation_error": None,
        }
    if path.is_symlink() or not path.is_file():
        return {
            "observed": False,
            "type": None,
            "message": None,
            "traceback_utf8": None,
            "envelope_state": "present_invalid",
            "envelope": None,
            "validation_error": "fatal exception envelope is symlink or special",
        }
    receipt = _supervisor_file_receipt(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        required = {
            "schema_version",
            "created_utc",
            "raw_attempt_id",
            "phase",
            "exception_type",
            "exception_message",
            "traceback_utf8",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("fatal exception envelope fields differ")
        if value["raw_attempt_id"] != FORMAL_RAW_ATTEMPT_ID:
            raise ValueError("fatal exception envelope raw ID differs")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "observed": False,
            "type": None,
            "message": None,
            "traceback_utf8": None,
            "envelope_state": "present_invalid",
            "envelope": receipt,
            "validation_error": str(exc),
        }
    return {
        "observed": True,
        "type": value["exception_type"],
        "message": value["exception_message"],
        "traceback_utf8": value["traceback_utf8"],
        "envelope_state": "valid",
        "envelope": receipt,
        "validation_error": None,
    }


def _publish_fatal_result(
    *,
    root: Path,
    observed_exit: Mapping[str, Any],
    quiescence: Mapping[str, Any],
) -> dict[str, Any]:
    if observed_exit.get("state") != "waited" or not quiescence.get("passed"):
        raise SystemsHarnessError("fatal result requires waited child and quiescence")
    if (root / "fatal-result.json").exists():
        raise SystemsHarnessError("fatal result cannot replace an existing fatal path")
    plan_path = root / "plan.json"
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    if not isinstance(plan, list):
        raise SystemsHarnessError("fatal result plan is not a list")
    plan_keys = [
        {
            "plan_index": index,
            "component": str(item.get("component", "")),
            "unit_id": str(item.get("unit_id", "")),
        }
        for index, item in enumerate(plan)
    ]
    plan_binding = {
        "unit_count": len(plan),
        "bytes": len(plan_raw),
        "stored_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "canonical_sha256": hashlib.sha256(_canonical_json_bytes(plan)).hexdigest(),
        "ordered_membership_sha256": hashlib.sha256(
            _canonical_json_bytes(plan_keys)
        ).hexdigest(),
    }
    if plan_binding != {
        "unit_count": 430,
        "bytes": 122245,
        "stored_sha256": FORMAL_FULL_PLAN_STORED_SHA256,
        "canonical_sha256": FORMAL_FULL_PLAN_SHA256,
        "ordered_membership_sha256": FORMAL_FULL_PLAN_MEMBERSHIP_SHA256,
    }:
        raise SystemsHarnessError("fatal result plan identity differs")
    validation_errors: list[str] = []
    execution_counts = _fatal_execution_counts(root, plan)
    validation_errors.extend(execution_counts["validation_errors"])
    lifecycle_path = root / "fatal-lifecycle.jsonl"
    units_path = root / "units.jsonl"
    lifecycle = (
        _fatal_journal_item(lifecycle_path, root)
        if lifecycle_path.is_file() and not lifecycle_path.is_symlink()
        else None
    )
    units = (
        _fatal_journal_item(units_path, root)
        if units_path.is_file() and not units_path.is_symlink()
        else None
    )
    incremental = [
        _fatal_journal_item(path, root)
        for path in sorted(
            root.rglob("*.jsonl"), key=lambda value: value.relative_to(root).as_posix()
        )
        if path not in {lifecycle_path, units_path}
        and path.is_file()
        and not path.is_symlink()
    ]
    for item in (lifecycle, units, *incremental):
        if item is not None and (
            item["invalid_complete_line_count"] or item["trailing_fragment_bytes"]
        ):
            validation_errors.append(
                f"journal is partial or malformed: {item['relative_path']}"
            )
    core = {
        name: _fatal_core_observation(root, relative, validation_errors)
        for name, relative in {
            "launch": "launch.json",
            "plan": "plan.json",
            "publication": "publication.json",
            "streams": "streams.json",
            "stdout": "stdout.log",
            "stderr": "stderr.log",
        }.items()
    }
    exception = _fatal_exception_observation(root)
    if exception["validation_error"]:
        validation_errors.append(str(exception["validation_error"]))
    partial_result = root / "result.json"
    result_observation = (
        {
            "state": "present_invalid_or_not_durable",
            "receipt": _supervisor_file_receipt(partial_result),
            "validation_error": "ordinary result failed frozen durability/schema validation",
        }
        if partial_result.is_file() and not partial_result.is_symlink()
        else {
            "state": "absent",
            "receipt": None,
            "validation_error": None,
        }
    )
    receipt = {
        "schema_version": 1,
        "receipt_type": "formal_fatal_result_v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "raw_attempt_id": FORMAL_RAW_ATTEMPT_ID,
        "attempt_root": str(root),
        "producer": "launcher_supervisor_after_runner_exit",
        "phase": _last_complete_lifecycle_phase(root),
        "observed_runner_exit": dict(observed_exit),
        "quiescence": dict(quiescence),
        "exception": exception,
        "result_observation": result_observation,
        "plan": plan_binding,
        "execution_counts": {
            **execution_counts,
            "validation_errors": sorted(set(validation_errors)),
        },
        "journals": {
            "lifecycle": lifecycle,
            "units": units,
            "incremental_jsonl": incremental,
        },
        "core_artifacts": core,
        "pre_fatal_tree": quiescence["stable_attempt_tree"],
        "canonical_process_exit_code": 5,
    }
    path = root / "fatal-result.json"
    _exclusive_canonical_json(path, receipt)
    _fsync_directory(root)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if parsed != receipt:
        raise SystemsHarnessError("fatal result verification differs after publication")
    return _supervisor_file_receipt(path)


def _run_formal_supervisor(argv: Sequence[str]) -> int:
    if "--supervised-child" in argv:
        raise SystemsHarnessError("supervisor recursion is forbidden")
    child_args = [argument for argument in argv if argument != "--supervise"]
    child_args.append("--supervised-child")
    attempt_root = _formal_attempt_dir_from_argv(child_args)
    if attempt_root is None or attempt_root.name != FORMAL_RAW_ATTEMPT_ID:
        raise SystemsHarnessError("supervisor requires exact r05 --attempt-dir")
    contract = _formal_contract()["fatal_result_contract"]
    supervisor_root = Path(str(contract["supervisor_closeout_root_exact"]))
    if supervisor_root != FORMAL_SUPERVISOR_ROOT:
        raise SystemsHarnessError("fatal supervisor root differs from frozen contract")
    supervisor_parent = Path(str(contract["supervisor_parent_exact"]))
    if supervisor_parent != supervisor_root.parent:
        raise SystemsHarnessError("fatal supervisor parent differs from frozen contract")
    _preclaim_formal_supervisor_root(supervisor_root)
    stream_paths = {
        "stdout": Path(str(contract["supervisor_child_stdout_path_exact"])),
        "stderr": Path(str(contract["supervisor_child_stderr_path_exact"])),
    }
    stream_handles = [path.open("xb", buffering=0) for path in stream_paths.values()]
    environment = _supervisor_environment()
    child_argv = [sys.executable, str(Path(__file__).resolve()), *child_args]
    start_path = Path(str(contract["supervisor_start_path_exact"]))
    _exclusive_canonical_json(
        start_path,
        {
            "schema_version": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "raw_attempt_id": FORMAL_RAW_ATTEMPT_ID,
            "attempt_root": str(attempt_root),
            "slurm_job_id": environment["SLURM_JOB_ID"],
            "slurm_partition": environment["SLURM_JOB_PARTITION"],
            "supervisor_process": _supervisor_process_identity(os.getpid()),
            "child_argv": child_argv,
            "child_environment": environment,
            "child_environment_sha256": hashlib.sha256(
                _canonical_json_bytes(environment)
            ).hexdigest(),
            "child_stream_paths": {
                name: str(path) for name, path in stream_paths.items()
            },
        },
    )
    child: subprocess.Popen[bytes] | None = None
    spawn_error: BaseException | None = None
    returncode: int | None = None
    process_group_id: int | None = None
    registered: dict[tuple[int, int], dict[str, Any]] = {}
    supervisor_diagnostics: list[dict[str, str]] = []
    diagnostics_lock = threading.Lock()
    drain_threads: list[threading.Thread] = []
    registry_stop = threading.Event()
    registry_thread: threading.Thread | None = None

    def drain(source: Any, sink: Any) -> None:
        try:
            while chunk := source.read(1024 * 1024):
                sink.write(chunk)
        except BaseException as exc:
            with diagnostics_lock:
                supervisor_diagnostics.append(
                    _supervisor_exception_diagnostic("stream_drain", exc)
                )
        finally:
            source.close()

    def register_descendants(pid: int) -> None:
        while not registry_stop.wait(0.05):
            try:
                descendants = psutil.Process(pid).children(recursive=True)
            except psutil.Error as exc:
                with diagnostics_lock:
                    supervisor_diagnostics.append(
                        _supervisor_exception_diagnostic("descendant_registry", exc)
                    )
                descendants = []
            for descendant in descendants:
                try:
                    identity = _supervisor_process_identity(descendant.pid)
                except (OSError, ValueError, SystemsHarnessError) as exc:
                    with diagnostics_lock:
                        supervisor_diagnostics.append(
                            _supervisor_exception_diagnostic(
                                "descendant_identity", exc
                            )
                        )
                    continue
                registered[(descendant.pid, int(identity["proc_start_ticks"]))] = (
                    identity
                )

    try:
        child = subprocess.Popen(
            child_argv,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except BaseException as exc:
        spawn_error = exc
    if child is not None:
        process_group_id = child.pid
        assert child.stdout is not None and child.stderr is not None
        drain_threads = [
            _start_supervisor_drain_thread(
                target=drain,
                args=(child.stdout, stream_handles[0]),
                diagnostics=supervisor_diagnostics,
            ),
            _start_supervisor_drain_thread(
                target=drain,
                args=(child.stderr, stream_handles[1]),
                diagnostics=supervisor_diagnostics,
            ),
        ]
        _register_initial_supervisor_child(
            child.pid, registered, supervisor_diagnostics
        )
        try:
            registry_thread = threading.Thread(
                target=register_descendants, args=(child.pid,), daemon=True
            )
            registry_thread.start()
        except BaseException as exc:
            registry_thread = None
            supervisor_diagnostics.append(
                _supervisor_exception_diagnostic("registry_thread_start", exc)
            )
        returncode = _wait_started_supervisor_child(child, supervisor_diagnostics)
    registry_stop.set()
    if registry_thread is not None:
        try:
            registry_thread.join(timeout=1)
        except BaseException as exc:
            supervisor_diagnostics.append(
                _supervisor_exception_diagnostic("registry_thread_join", exc)
            )
    observed_exit = _supervisor_observed_exit(returncode, spawn_error)
    quiescence = _supervisor_quiesce(
        child=child,
        process_group_id=process_group_id,
        registered=registered,
        drain_threads=drain_threads,
        stream_handles=stream_handles,
        stream_paths=stream_paths,
        attempt_root=attempt_root,
    )
    attempt_state = _supervisor_attempt_state(attempt_root)
    ordinary = _observe_ordinary_result(attempt_root)
    fatal = _observe_supervisor_product(attempt_root / "fatal-result.json")
    validation_errors: list[str] = []
    expected_exit: int | None = None
    if ordinary["state"] == "valid":
        ordinary_value = json.loads(
            (attempt_root / "result.json").read_text(encoding="utf-8")
        )
        expected_exit = {
            "completed": 0,
            "completed_with_system_violations": 3,
            "incomplete_harness_error": 2,
            "incomplete_infrastructure_error": 4,
            "incomplete_unclassified_failure": 5,
        }.get(str(ordinary_value.get("status", "")))
        if expected_exit is None:
            ordinary = {
                "state": "present_invalid",
                "receipt": ordinary["receipt"],
                "validation_error": "ordinary result has noncanonical status",
            }
    clean_quiescence = (
        quiescence["passed"]
        and not quiescence["descendants_before"]
        and not quiescence["termination_actions"]
        and not quiescence["open_attempt_writers_first_scan"]
        and not quiescence["open_attempt_writers_second_scan"]
    )
    if (
        ordinary["state"] != "valid"
        and fatal["state"] == "absent"
        and observed_exit["state"] == "waited"
        and attempt_state in {"published", "present_invalid"}
        and quiescence["passed"]
    ):
        try:
            _publish_fatal_result(
                root=attempt_root,
                observed_exit=observed_exit,
                quiescence=quiescence,
            )
            fatal = _observe_supervisor_product(attempt_root / "fatal-result.json")
        except (OSError, ValueError, SystemsHarnessError) as exc:
            validation_errors.append(f"fatal result publication failed: {exc}")
    if ordinary["state"] == "valid" and clean_quiescence:
        agrees = (
            observed_exit["state"] == "waited"
            and observed_exit["exit_code"] == expected_exit
        )
        disposition = (
            "ordinary_result_exit_agrees"
            if agrees
            else "ordinary_result_exit_disagrees"
        )
        final_exit = int(expected_exit) if agrees else 5
    elif ordinary["state"] == "valid":
        disposition = "ordinary_result_closeout_invalid"
        final_exit = 5
    elif observed_exit["state"] == "not_started" or attempt_state == "not_published":
        disposition = "prepublication_or_unpublished_failure"
        final_exit = 5
    elif fatal["state"] == "valid":
        disposition = "fatal_result_published"
        final_exit = 5
    else:
        disposition = "fatal_finalization_failed"
        final_exit = 5
        validation_errors.append(
            "published attempt lacks a valid ordinary or fatal terminal product"
        )
    closeout = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "raw_attempt_id": FORMAL_RAW_ATTEMPT_ID,
        "attempt_root": str(attempt_root),
        "start_receipt": _supervisor_file_receipt(start_path),
        "observed_runner_exit": observed_exit,
        "supervisor_diagnostics": supervisor_diagnostics,
        "quiescence": quiescence,
        "attempt_root_state": attempt_state,
        "ordinary_result": ordinary,
        "fatal_result": fatal,
        "disposition": disposition,
        "final_supervisor_exit_code": final_exit,
        "validation_errors": sorted(set(validation_errors)),
    }
    closeout_path = Path(str(contract["supervisor_closeout_path_exact"]))
    _exclusive_canonical_json(closeout_path, closeout)
    for path in (start_path, *stream_paths.values(), closeout_path):
        os.chmod(path, 0o444)
        _supervisor_file_receipt(path)
    _fsync_directory(supervisor_root)
    os.chmod(supervisor_root, 0o500)
    contract_paths = (start_path, *stream_paths.values(), closeout_path)
    if (
        any(path.parent != supervisor_root for path in contract_paths)
        or len({path.name for path in contract_paths}) != 4
    ):
        raise SystemsHarnessError("frozen supervisor paths are not four distinct members")
    expected_members = sorted(path.name for path in contract_paths)
    if sorted(path.name for path in supervisor_root.iterdir()) != expected_members:
        raise SystemsHarnessError("sealed supervisor root membership differs")
    return final_exit


def main() -> int:
    if "--supervise" in sys.argv[1:]:
        return _run_formal_supervisor(sys.argv[1:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rule-counts",
        type=lambda value: parse_int_tuple(value, allowed=set(DEFAULT_RULE_COUNTS)),
        default=DEFAULT_RULE_COUNTS,
    )
    parser.add_argument(
        "--project-counts",
        type=lambda value: parse_int_tuple(value, allowed=set(DEFAULT_PROJECT_COUNTS)),
        default=DEFAULT_PROJECT_COUNTS,
    )
    parser.add_argument(
        "--burst-sizes",
        type=lambda value: parse_int_tuple(value, allowed=set(DEFAULT_BURST_SIZES)),
        default=DEFAULT_BURST_SIZES,
    )
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument(
        "--sequential-events", type=int, default=DEFAULT_SEQUENTIAL_EVENTS
    )
    parser.add_argument(
        "--warmups-per-project", type=int, default=DEFAULT_WARMUPS_PER_PROJECT
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--drain-timeout", type=float, default=DEFAULT_DRAIN_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--max-hook-workers", type=int, default=DEFAULT_MAX_HOOK_WORKERS
    )
    parser.add_argument("--soak-events", type=int, default=0)
    parser.add_argument("--soak-rule-count", type=int, default=8)
    parser.add_argument("--soak-project-count", type=int, default=8)
    parser.add_argument("--soak-batch-size", type=int, default=DEFAULT_SOAK_BATCH_SIZE)
    parser.add_argument(
        "--fault-repetitions", type=int, default=DEFAULT_FAULT_REPETITIONS
    )
    parser.add_argument("--faults", type=_fault_names, default=_fault_names("all"))
    parser.add_argument("--skip-offline-probe", action="store_true")
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="record fault-probe errors instead of stopping (matrix accounting stays strict)",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="print the deterministic plan and capabilities without running experiments",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--attempt-dir",
        type=Path,
        help="new immutable directory for launch, unit, result, and raw runtime evidence",
    )
    parser.add_argument(
        "--formal",
        action="store_true",
        help="enforce the exact protocol-v3 design and ALL-partition execution",
    )
    parser.add_argument(
        "--supervised-child", action="store_true", help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    if args.supervised_child and os.environ.get("RAP_EACL_SUPERVISED_CHILD") != "1":
        raise SystemsHarnessError("supervised-child mode lacks supervisor environment")
    config = MatrixConfig(
        rule_counts=tuple(args.rule_counts),
        project_counts=tuple(args.project_counts),
        burst_sizes=tuple(args.burst_sizes),
        repeats=args.repeats,
        sequential_events=args.sequential_events,
        warmups_per_project=args.warmups_per_project,
        timeout_seconds=args.timeout,
        drain_timeout_seconds=args.drain_timeout,
        max_hook_workers=args.max_hook_workers,
        soak_events=args.soak_events,
        soak_rule_count=args.soak_rule_count,
        soak_project_count=args.soak_project_count,
        soak_batch_size=args.soak_batch_size,
        fault_repetitions=args.fault_repetitions,
    )
    config.validate()
    if args.formal:
        _validate_formal_config(
            config,
            fault_names=args.faults,
            run_offline_probe=not args.skip_offline_probe,
            strict=not args.continue_on_error,
            require_partition=not args.plan,
        )
        if not args.plan and args.attempt_dir is None:
            raise SystemsHarnessError("formal execution requires --attempt-dir")
        if not args.plan:
            expected_parent = FORMAL_RAW_ATTEMPT_ROOT.resolve()
            runtime_dependency = dict(
                _formal_runtime_profile().get("cache_and_dependency_receipt") or {}
            )
            configured_parent = str(runtime_dependency.get("formal_attempt_root", ""))
            if str(FORMAL_RAW_ATTEMPT_ROOT) != configured_parent:
                raise SystemsHarnessError(
                    "runner formal-attempt root differs from amendment runtime profile"
                )
            if FORMAL_RAW_ATTEMPT_ROOT.is_symlink():
                raise SystemsHarnessError(
                    "formal-attempt root must not itself be a symlink"
                )
            try:
                expected_parent.relative_to(REPO_ROOT.resolve())
            except ValueError:
                pass
            else:
                raise SystemsHarnessError(
                    "formal-attempt root must resolve outside the Git worktree"
                )
            if args.attempt_dir.expanduser().resolve().parent != expected_parent:
                raise SystemsHarnessError(
                    f"formal attempt directory must be directly below {expected_parent}"
                )
    recorder: AttemptRecorder | None = None
    if args.plan:
        result = {
            "status": "plan_only",
            "config": asdict(config),
            "plan": build_study_plan(
                config,
                fault_names=args.faults,
                run_offline_probe=not args.skip_offline_probe,
            ),
            "matrix": build_matrix_plan(config),
            "faults_selected": list(args.faults),
            "fault_capabilities": FAULT_CAPABILITIES,
            "offline_after_prepare_selected": not args.skip_offline_probe,
            "measurement_boundary": _measurement_boundary(),
        }
    else:
        bundle = load_external_artifacts()
        plan = build_study_plan(
            config,
            fault_names=args.faults,
            run_offline_probe=not args.skip_offline_probe,
        )
        recorder = (
            AttemptRecorder(
                args.attempt_dir,
                _launch_manifest(
                    args.attempt_dir,
                    config,
                    plan,
                    bundle,
                    formal=args.formal,
                ),
                capture_process_streams=args.formal,
            )
            if args.attempt_dir
            else None
        )
        if recorder is not None and args.formal:
            recorder.record_lifecycle("post_publication_gate_started")
        result = (
            _artifact_initialization_abort_result(
                recorder,
                config=config,
                plan=plan,
                formal=args.formal,
            )
            if recorder is not None
            else None
        )
        if result is None and recorder is not None and args.formal:
            recorder.record_lifecycle("post_publication_gate_passed")
        if result is None:
            try:
                result = run_study(
                    bundle,
                    config,
                    fault_names=args.faults,
                    run_offline_probe=not args.skip_offline_probe,
                    strict=not args.continue_on_error,
                    formal=args.formal,
                    recorder=recorder,
                )
            except BaseException as exc:
                result = _aborted_attempt_result(
                    exc,
                    config=config,
                    plan=plan,
                    formal=args.formal,
                    attempt_root=recorder.root if recorder else None,
                    launch_git=(
                        dict((recorder.manifest.get("identity") or {}).get("git") or {})
                        if recorder
                        else None
                    ),
                )
        if args.formal:
            if recorder is None:
                raise SystemsHarnessError(
                    "formal cache end retention requires an attempt recorder"
                )
            result = _merge_global_outcome(
                result,
                "cache_end_receipt",
                _capture_formal_cache_end(bundle, recorder),
            )
        result = _finalize_source_state(result, recorder.root if recorder else None)
        if recorder:
            result = recorder.finalize(result)
    exit_code = _attempt_exit_code(str(result.get("status", "")))
    if recorder is not None:
        result_path = recorder.root / "result.json"
        rendered_value = {
            "status": result.get("status"),
            "raw_attempt_id": recorder.root.name,
            "result_json": str(result_path),
            "result_sha256": _sha256_file(result_path),
            "exit_code": exit_code,
        }
    else:
        rendered_value = result
    rendered = json.dumps(rendered_value, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = _validate_output_path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        if args.formal:
            try:
                with output.open("x", encoding="utf-8") as handle:
                    handle.write(rendered)
            except FileExistsError as exc:
                raise SystemsHarnessError(
                    f"refusing to replace formal output: {output}"
                ) from exc
        else:
            temporary = output.with_suffix(output.suffix + ".tmp")
            temporary.write_text(rendered, encoding="utf-8")
            os.replace(temporary, output)
        print(output)
    else:
        print(rendered, end="")
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SystemsHarnessError, ValueError) as exc:
        try:
            _write_fatal_exception_envelope(exc)
        except Exception:
            traceback.print_exc()
        print(f"systems harness preflight error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception as exc:
        try:
            _write_fatal_exception_envelope(exc)
        except Exception:
            traceback.print_exc()
        traceback.print_exc()
        raise SystemExit(5) from None
    except BaseException as exc:
        try:
            _write_fatal_exception_envelope(exc)
        except Exception:
            traceback.print_exc()
        raise
