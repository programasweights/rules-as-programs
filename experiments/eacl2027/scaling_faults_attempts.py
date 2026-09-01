"""Immutable, incremental artifact retention for the systems study."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any


class SystemsHarnessError(RuntimeError):
    """Raised when a systems-study invariant is violated."""


UNIT_STATUSES = frozenset(
    {
        "completed",
        "system_violation",
        "harness_error",
        "infrastructure_error",
        "unclassified_failure",
        "not_started_after_abort",
        "not_applicable",
    }
)

_FORMAL_ATTEMPT_RE = re.compile(
    r"(?P<prefix>[a-z0-9][a-z0-9._-]{0,59})-r(?P<ordinal>[0-9]{2})"
)
_REPLACEMENT_CLASSIFICATIONS = frozenset({"harness_error", "infrastructure_error"})
_EXTERNAL_SCHEDULER_STATES = frozenset({"PREEMPTED", "NODE_FAIL", "BOOT_FAIL"})
_MAX_FORMAL_ATTEMPT_ORDINAL = 5
_MAX_PREDECESSOR_TREE_ENTRIES = 250_000
_MAX_PREDECESSOR_TREE_REGULAR_BYTES = 8 * 1024**3
_MIN_STAGING_FREE_RESERVE_BYTES = 1024**3
_FORMAL_STUDY_MODES = frozenset(
    {
        "formal",
        "formal_protocol_v3_amendment_007",
        "formal_protocol_v3_amendment_008",
    }
)
_PREDECESSOR_ARTIFACT_NAMES = (
    "launch.json",
    "plan.json",
    "publication.json",
    "result.json",
    "stderr.log",
    "stdout.log",
    "streams.json",
    "units.jsonl",
)
_REPO_ROOT = Path(__file__).resolve().parents[2]
_COMPONENT_AMENDMENT_PATH = (
    _REPO_ROOT / "experiments/eacl2027/protocol-v3-amendment-008.json"
)
_COMPONENT_CORRECTION_PATH = (
    _REPO_ROOT / "experiments/eacl2027/protocol-v3-amendment-009.json"
)
_COMPONENT_ROUTING_CORRECTION_PATH = (
    _REPO_ROOT / "experiments/eacl2027/protocol-v3-amendment-010.json"
)
_COMPONENT_PREPUBLICATION_CORRECTION_PATH = (
    _REPO_ROOT / "experiments/eacl2027/protocol-v3-amendment-011.json"
)
_COMPONENT_CANARY_ARCHIVE_PARENT = Path(
    "/u4/yuntian/rap-eacl-systems-formal-v3/scheduler/canary-v4"
)
_COMPONENT_CANARY_ARCHIVE_MEMBER_TEMPLATES = (
    "archive-ended-at-utc.txt",
    "canary-script.sha256",
    "launch-started-at-utc.txt",
    "launcher-script.sha256",
    "launcher.exit-status.txt",
    "postrun-sacct.attempts.txt",
    "postrun-sacct.exit-status.txt",
    "postrun-sacct.stderr.log",
    "postrun-sacct.txt",
    "r02-terminal-sacct.stderr.log",
    "r02-terminal-sacct.txt",
    "rap-eacl-paw-cache-canary-v4-<job_id>.guard-activations.jsonl",
    "rap-eacl-paw-cache-canary-v4-<job_id>.inner.stderr.log",
    "rap-eacl-paw-cache-canary-v4-<job_id>.inner.stdout.log",
    "rap-eacl-paw-cache-canary-v4-<job_id>.json",
    "rap-eacl-paw-cache-canary-v4-<job_id>.json.sha256",
    "rap-eacl-paw-cache-canary-v4-<job_id>.network.jsonl",
    "rap-eacl-paw-cache-canary-v4-<job_id>.setup.stderr.log",
    "rap-eacl-paw-cache-canary-v4-<job_id>.setup.stdout.log",
    "required-terminal-r02-job-id.txt",
    "slurm-job-id.txt",
    "srun-client.stderr.log",
    "srun-client.stdout.log",
    "srun-task-<job_id>.stderr.log",
    "srun-task-<job_id>.stdout.log",
    "srun.exit-status.txt",
)
_COMPONENT_PREDECESSOR_ID = "formal-v3-20260831t051023z-r02"
_COMPONENT_SUCCESSOR_ID = "formal-v3-20260831t051023z-r04"
_COMPONENT_BURNED_PREPUBLICATION_ID = "formal-v3-20260831t051023z-r03"
_COMPONENT_PREPUBLICATION_JOB_ID = "1524823"
_COMPONENT_PREPUBLICATION_MEMBER_NAMES = frozenset(
    {
        "evidence.sha256",
        "evidence.sha256.sha256",
        "repo-head.txt",
        "repo-status.txt",
        "setup-receipt.json",
        "setup.log",
        "source-files.sha256",
        "stderr.log",
        "stdout.log",
        "terminal-sacct.command.txt",
        "terminal-sacct.stderr.txt",
        "terminal-sacct.txt",
        "terminal-scontrol.exit-status.txt",
        "terminal-scontrol.stderr.txt",
        "terminal-scontrol.txt",
    }
)
_COMPONENT_CLASSIFICATION = (
    "outcome_aware_launch_wide_whole_attempt_protocol_correction"
)
_COMPONENT_ANALYSIS_ID = "protocol-v3-amendment-008-whole-attempt-replacement-v1"
_COMPONENT_FULL_PLAN_SHA256 = (
    "4cdf827bf1c07a7bea9cd9d1af5c5ab37086af294583c8a5775643209b3c917c"
)
_COMPONENT_FULL_PLAN_STORED_SHA256 = (
    "cab6e22893cea6a41f3140ce57a39d34b7a463ba5e7453aa3970d39ff67f5434"
)
_COMPONENT_FULL_PLAN_MEMBERSHIP_SHA256 = (
    "cd5885dba0bfe7584f4b44efe18e3f1b827a9de0bfef6abcb0127adab1b6b162"
)
_COMPONENT_DETERMINISTIC_FAULTS = frozenset(
    {"sqlite_lock", "malformed_payload", "duplicate_delivery", "deployment_failure"}
)
# Retained only so the pre-Amendment-008 validator definitions remain importable;
# the r02->r03 edge never calls them and the new whole-attempt validator rejects
# every cross-attempt plan assembly.
_COMPONENT_CARRY_PLAN_SHA256 = (
    "0e3cf713ef6cf693184fe6e572caf541716a5b20d5158fa0ffcc2f5635e95c7f"
)
_COMPONENT_REPAIR_PLAN_SHA256 = (
    "09fc89893fffd97392b289beb717737b43501da5a0550d4c34725ee382521644"
)
_COMPONENT_MAPPING_SHA256 = (
    "214adcb846145ca6e0cb5a7eb82552b731c15b46907330f47857cacf50dd1725"
)
_COMPONENT_DEPENDENCY_BASIS = {
    "matrix": "component_requires_direct_paw",
    "soak": "component_requires_direct_paw",
    "offline": "component_requires_direct_paw",
    "faults.daemon_crash": "fault_recovery_requires_direct_paw",
    "faults.worker_exit": "fault_recovery_requires_direct_paw",
    "faults.worker_timeout": "fault_recovery_requires_direct_paw",
    "faults.sqlite_lock": "fault_boundary_is_deterministic_no_paw",
    "faults.malformed_payload": "fault_boundary_is_deterministic_no_paw",
    "faults.duplicate_delivery": "fault_boundary_is_deterministic_no_paw",
    "faults.deployment_failure": "fault_boundary_is_deterministic_no_paw",
}
_COMPONENT_REQUIRED_EVIDENCE = frozenset(
    {
        "launch_wide_cache_root_adjudication",
        "paw_cache_semantics_receipt",
        "all_partition_paw_cache_canary",
        "whole_attempt_replacement_validation",
        "r02_effective_cache_forensic_inventory",
        "r02_terminal_archive",
        "scheduler_sacct",
        "scheduler_stdout",
        "scheduler_stderr",
    }
)
_FORENSICS_MISSING = object()


# Amendment 007 permits exactly one outcome-aware replacement.  These values
# intentionally duplicate the frozen protocol anchors: the validator must not
# learn a broader exception from a mutable label or from evidence supplied by
# the replacement author.
_OUTCOME_AWARE_REPAIR: dict[str, Any] = {
    "predecessor_raw_attempt_id": "formal-v3-20260831t051023z-r01",
    "successor_raw_attempt_id": "formal-v3-20260831t051023z-r02",
    "receipt_overrides": {
        "classification": "harness_error",
        "original_status": "completed_with_system_violations",
        "reason": (
            "The amendment-006 harness constructed every r01 daemon socket "
            "pathname beyond the Linux pathname-form AF_UNIX limit; every unit "
            "stopped at socket bind before readiness, warmup, hook invocation, "
            "or a measured event."
        ),
        "affected_boundary": (
            "harness runtime-path construction and UnixStreamServer bind before "
            "daemon readiness and before any warmup or measured event"
        ),
        "scheduler_adjudication": None,
    },
    "launch": {
        "identity_sha256": (
            "512438c9034c3edd4057c9ac30cc0c183f669e2d90c104fedff4af9bc751ee72"
        ),
        "git_commit": "d33e7dafeaf687838ebe009fa1426a9a6c2323b8",
        "runner_sha256": (
            "9d226d20d90924f58627fddeb940b18a46a12df74e7a4382663f64367ed486dc"
        ),
        "runner_git_blob": "3584b1831c3d07b6b86fed13c03ef601998f1a2f",
        "runtime_lock_sha256": (
            "7915c35700a1bb984d576a070c484e89c16c99ab456323e7a8b65ebd8fafd495"
        ),
        "slurm": {
            "job_id": "1524424",
            "partition": "ALL",
            "node_list": "watgpu108",
            "terminal_state": "FAILED",
            "exit_code": "3:0",
            "elapsed": "00:02:08",
        },
    },
    "core_artifacts": {
        "launch.json": {
            "bytes": 310922,
            "sha256": (
                "9c1352dcea9b76e0c1adb2d64f606710ae6563c1f0ebe0a559529136804995e1"
            ),
        },
        "plan.json": {
            "bytes": 122245,
            "sha256": (
                "cab6e22893cea6a41f3140ce57a39d34b7a463ba5e7453aa3970d39ff67f5434"
            ),
        },
        "publication.json": {
            "bytes": 580,
            "sha256": (
                "f29155947be45afd636aea6489f7c1ce5f1f05fcaa616177e2b997a26ba4d8eb"
            ),
        },
        "result.json": {
            "bytes": 3500920,
            "sha256": (
                "24b8f562e8d0c4b9fa8dd152f3afd8a16c93b2f5a4e17e75d502f815519f82c3"
            ),
        },
        "stdout.log": {
            "bytes": 321,
            "sha256": (
                "b3adb8cbd99cbd74aacd14c2796b84b7586df75b2431d81929353dd412afd464"
            ),
        },
        "stderr.log": {
            "bytes": 0,
            "sha256": (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
        },
        "streams.json": {
            "bytes": 212,
            "sha256": (
                "208d1fd5d724657b664ff706f656a55e5e0df94a3eaef04659a9e7885d5ccdc4"
            ),
        },
        "units.jsonl": {
            "bytes": 124974,
            "sha256": (
                "1717fded3508fde976782961a34121361473a4fd1d7770ca1cb4d3db443eedad"
            ),
        },
    },
    "publication_claim": {
        "path": (
            "/u4/yuntian/rap-eacl-systems-formal-v3/.attempts.staging/"
            ".publication-claims/formal-v3-20260831t051023z-r01.launch.json"
        ),
        "bytes": 310922,
        "sha256": ("9c1352dcea9b76e0c1adb2d64f606710ae6563c1f0ebe0a559529136804995e1"),
    },
    "tree": {
        "entries_excluding_root": 34670,
        "regular_file_bytes": 56010761,
        "type_counts": {
            "directory": 17926,
            "regular_file": 16744,
            "symlink": 0,
            "socket": 0,
            "fifo": 0,
            "other": 0,
        },
    },
    "result": {
        "status": "completed_with_system_violations",
        "primary_numeric_eligible": True,
        "complete_plan": True,
        "all_planned_units_terminal": True,
        "planned_unit_count": 430,
        "terminal_unit_count": 430,
        "system_violation_units": 430,
        "unit_status_histogram": {"system_violation": 430},
    },
    "gate": {
        "terminal_status": "system_violation",
        "error_type": "SystemViolationError",
        "error_message_fragment": "OSError: AF_UNIX path too long",
        "bind_frame": "self.socket.bind(self.server_address)",
        "socket_path_min_bytes": 109,
        "socket_path_max_bytes": 163,
        "pathname_limit_bytes": 107,
        "verdict_database_count": 430,
        "verdict_rows": 0,
        "attention_rows": 0,
        "evaluation_journal_records": 0,
        "audit_journal_records": 0,
    },
    "evidence": {
        "root": (
            "/u4/yuntian/rap-eacl-systems-formal-v3/scheduler/replacements/"
            "formal-v3-20260831t051023z-r02"
        ),
        "required_kinds": {
            "premeasurement_harness_adjudication",
            "af_unix_socket_probe",
            "scheduler_sacct",
            "scheduler_stdout",
            "scheduler_stderr",
        },
        "files": {
            "premeasurement_harness_adjudication": {
                "name": "premeasurement-harness-adjudication.json"
            },
            "af_unix_socket_probe": {
                "name": "af-unix-socket-probe.json",
                "bytes": 1509,
                "sha256": (
                    "6422013790bf3b63666497c35d71f0e2615aeac92b33bab90d647e95579e9ec4"
                ),
            },
            "scheduler_sacct": {
                "name": "scheduler-sacct.txt",
                "bytes": 176,
                "sha256": (
                    "0cffb5809d32bb190c2d14b1e4d6c4f63cbc9d904aad390df75cf3c1576bc957"
                ),
            },
            "scheduler_stdout": {
                "name": "scheduler-stdout.log",
                "bytes": 0,
                "sha256": (
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
            },
            "scheduler_stderr": {
                "name": "scheduler-stderr.log",
                "bytes": 0,
                "sha256": (
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
            },
        },
        "host": "watgpu",
    },
}


def _contains_system_violation(value: Any) -> bool:
    """Return whether a classified result subtree retains a system violation."""

    if value == "system_violation":
        return True
    if isinstance(value, dict):
        return any(_contains_system_violation(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_system_violation(item) for item in value)
    return False


def _result_contains_system_violation(result: dict[str, Any]) -> bool:
    return any(
        _contains_system_violation(result.get(name))
        for name in (
            "unit_index",
            "global_outcomes",
            "abort",
            "original_abort_classification",
        )
    )


def _predecessor_launch_job_id(predecessor_root: Path) -> str:
    try:
        launch = json.loads(
            (predecessor_root / "launch.json").read_text(encoding="utf-8")
        )
        identity = launch["identity"]
        slurm = identity["slurm"]
        job_id = slurm["job_id"]
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
    ) as exc:
        raise SystemsHarnessError(
            "predecessor launch lacks a valid identity Slurm job_id"
        ) from exc
    if not isinstance(job_id, str) or not job_id.isdigit():
        raise SystemsHarnessError(
            "predecessor launch lacks a valid identity Slurm job_id"
        )
    return job_id


def _file_receipt(path: Path) -> dict[str, Any]:
    digest = sha256()
    byte_count = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SystemsHarnessError(
            f"could not open bound evidence file: {path}"
        ) from exc
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise SystemsHarnessError(f"bound evidence is not a regular file: {path}")
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            byte_count += len(chunk)
        closed_over = os.fstat(handle.fileno())
    if (
        opened.st_dev != closed_over.st_dev
        or opened.st_ino != closed_over.st_ino
        or opened.st_size != closed_over.st_size
        or byte_count != closed_over.st_size
    ):
        raise SystemsHarnessError(f"bound evidence changed while hashing: {path}")
    return {
        "path": str(path),
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
    }


def _reject_symlink_components(path: Path, *, label: str) -> None:
    lexical = path.expanduser().absolute()
    current = Path(lexical.anchor)
    for part in lexical.parts[1:]:
        current /= part
        if current.is_symlink():
            raise SystemsHarnessError(
                f"{label} contains symlink path component: {current}"
            )


def _validate_declared_file_receipt(
    declared: Any,
    path: Path,
    *,
    allow_absent: bool,
) -> dict[str, Any] | None:
    if not path.exists():
        if allow_absent and declared is None:
            return None
        raise SystemsHarnessError(
            f"replacement receipt does not match absent predecessor artifact: {path}"
        )
    if declared is None:
        raise SystemsHarnessError(
            f"replacement receipt omits existing predecessor artifact: {path}"
        )
    if path.is_symlink() or not path.is_file():
        raise SystemsHarnessError(
            f"replacement evidence must be a regular non-symlink file: {path}"
        )
    observed = _file_receipt(path.resolve(strict=True))
    expected = {
        "path": str(path.resolve(strict=True)),
        "bytes": observed["bytes"],
        "sha256": observed["sha256"],
    }
    if declared != expected:
        raise SystemsHarnessError(
            f"replacement receipt hash/size/path mismatch for {path.name}"
        )
    return expected


def _predecessor_tree_receipts(root: Path) -> list[dict[str, Any]]:
    """Return a complete, ordered receipt for every predecessor artifact file."""

    if root.is_symlink() or not root.is_dir():
        raise SystemsHarnessError(
            "predecessor attempt must be a regular non-symlink directory"
        )
    resolved_root = root.resolve(strict=True)
    receipts: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise SystemsHarnessError(
                f"predecessor attempt tree contains a symlink: {path}"
            )
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        try:
            relative = resolved.relative_to(resolved_root).as_posix()
        except ValueError as exc:
            raise SystemsHarnessError(
                f"predecessor artifact escapes its attempt tree: {path}"
            ) from exc
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISREG(metadata.st_mode):
            receipt = _file_receipt(resolved)
            receipts.append(
                {
                    "relative_path": relative,
                    "type": "regular_file",
                    "mode": mode,
                    "bytes": receipt["bytes"],
                    "sha256": receipt["sha256"],
                }
            )
        else:
            entry_type = (
                "directory"
                if stat.S_ISDIR(metadata.st_mode)
                else "socket"
                if stat.S_ISSOCK(metadata.st_mode)
                else "fifo"
                if stat.S_ISFIFO(metadata.st_mode)
                else "character_device"
                if stat.S_ISCHR(metadata.st_mode)
                else "block_device"
                if stat.S_ISBLK(metadata.st_mode)
                else "unknown_special"
            )
            receipts.append(
                {
                    "relative_path": relative,
                    "type": entry_type,
                    "mode": mode,
                    "bytes": None,
                    "sha256": None,
                }
            )
    return receipts


def _outcome_aware_error(message: str) -> SystemsHarnessError:
    return SystemsHarnessError(
        f"amendment-007 outcome-aware replacement gate failed: {message}"
    )


def _walk_named_values(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk_named_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_named_values(child)


def _outcome_aware_units(result: dict[str, Any]) -> list[dict[str, Any]]:
    matrix = result.get("matrix")
    faults = result.get("faults")
    if not isinstance(matrix, list) or not isinstance(faults, dict):
        raise _outcome_aware_error("result does not retain the frozen unit topology")
    units: list[Any] = [
        *matrix,
        result.get("soak"),
        result.get("offline_after_prepare"),
    ]
    for fault in faults.values():
        if not isinstance(fault, dict):
            raise _outcome_aware_error(
                "result does not retain the frozen fault-attempt topology"
            )
        attempts = fault.get("attempts") or []
        if not isinstance(attempts, list):
            raise _outcome_aware_error(
                "result does not retain the frozen fault-attempt topology"
            )
        units.extend(attempts)
    if not all(isinstance(unit, dict) for unit in units):
        raise _outcome_aware_error("result contains a non-object terminal unit")
    return units


def _outcome_aware_tree_summary(
    tree: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = {
        "directory": 0,
        "regular_file": 0,
        "symlink": 0,
        "socket": 0,
        "fifo": 0,
        "other": 0,
    }
    regular_bytes = 0
    for item in tree:
        entry_type = str(item.get("type"))
        if entry_type in counts:
            counts[entry_type] += 1
        else:
            counts["other"] += 1
        if entry_type == "regular_file":
            regular_bytes += int(item["bytes"])
    return {
        "entries_excluding_root": len(tree),
        "regular_file_bytes": regular_bytes,
        "type_counts": counts,
    }


def _read_outcome_aware_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _outcome_aware_error(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise _outcome_aware_error(f"{label} must be a JSON object")
    return value


def _component_error(message: str) -> SystemsHarnessError:
    return SystemsHarnessError(
        f"amendment-008 component protocol-correction gate failed: {message}"
    )


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _component_error("value is not canonical-JSON serializable") from exc


def _strict_json_object(raw: str, *, label: str) -> dict[str, Any]:
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
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise _component_error(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise _component_error(f"{label} is not a JSON object")
    return value


def _pending_terminal_markers(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [
            marker
            for child in value.values()
            for marker in _pending_terminal_markers(child)
        ]
    if isinstance(value, list):
        return [
            marker for child in value for marker in _pending_terminal_markers(child)
        ]
    if isinstance(value, str) and re.fullmatch(r"PENDING_TERMINAL_[A-Z0-9_]+", value):
        return [value]
    return []


def _load_component_amendment() -> dict[str, Any]:
    if (
        _COMPONENT_AMENDMENT_PATH.is_symlink()
        or not _COMPONENT_AMENDMENT_PATH.is_file()
    ):
        raise _component_error("the frozen amendment-008 file is unavailable")
    try:
        amendment = _strict_json_object(
            _COMPONENT_AMENDMENT_PATH.read_text(encoding="utf-8"),
            label="amendment 008",
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("amendment 008 is unavailable") from exc
    if amendment.get("amendment_id") != "protocol-v3-amendment-008":
        raise _component_error("amendment identity differs")
    if not str(amendment.get("freeze_state", "")).startswith("frozen_"):
        raise _component_error("amendment is not frozen")
    if "draft" in str(amendment.get("status", "")).lower():
        raise _component_error("amendment status is still draft")
    if _pending_terminal_markers(amendment):
        raise _component_error("amendment retains unresolved terminal markers")
    try:
        frozen = datetime.fromisoformat(
            str(amendment.get("frozen_utc", "")).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise _component_error("amendment frozen_utc is invalid") from exc
    if frozen.tzinfo is None:
        raise _component_error("amendment frozen_utc is not timezone-aware")
    if frozen > datetime.now(timezone.utc):
        raise _component_error("amendment frozen_utc is in the future")
    if (
        _COMPONENT_CORRECTION_PATH.is_symlink()
        or not _COMPONENT_CORRECTION_PATH.is_file()
    ):
        raise _component_error("the frozen amendment-009 correction is unavailable")
    try:
        correction = _strict_json_object(
            _COMPONENT_CORRECTION_PATH.read_text(encoding="utf-8"),
            label="amendment 009",
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("amendment 009 is unavailable") from exc
    correction_identity = correction.get("effective_protocol_identity")
    if (
        correction.get("amendment_id") != "protocol-v3-amendment-009"
        or correction.get("parent_amendment") != "protocol-v3-amendment-008"
        or not str(correction.get("status", "")).startswith("frozen ")
        or not isinstance(correction_identity, dict)
        or not isinstance(correction_identity.get("required_git_topology"), dict)
    ):
        raise _component_error("amendment 009 is not the frozen exact correction")
    amendment = json.loads(json.dumps(amendment))
    amendment["effective_protocol_identity"]["required_git_topology"] = (
        correction_identity["required_git_topology"]
    )
    amendment["effective_protocol_identity"]["interpretation_order"] = (
        correction_identity["interpretation_order"]
    )
    if (
        _COMPONENT_ROUTING_CORRECTION_PATH.is_symlink()
        or not _COMPONENT_ROUTING_CORRECTION_PATH.is_file()
    ):
        raise _component_error("the frozen amendment-010 correction is unavailable")
    try:
        routing = _strict_json_object(
            _COMPONENT_ROUTING_CORRECTION_PATH.read_text(encoding="utf-8"),
            label="amendment 010",
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("amendment 010 is unavailable") from exc
    routing_identity = routing.get("effective_protocol_identity")
    if (
        routing.get("amendment_id") != "protocol-v3-amendment-010"
        or routing.get("parent_amendment") != "protocol-v3-amendment-009"
        or not str(routing.get("status", "")).startswith("frozen ")
        or not isinstance(routing_identity, dict)
    ):
        raise _component_error("amendment 010 is not the frozen exact correction")
    amendment["effective_protocol_identity"]["required_git_topology"] = (
        routing_identity["required_git_topology"]
    )
    amendment["effective_protocol_identity"]["interpretation_order"] = (
        routing_identity["interpretation_order"]
    )
    if (
        _COMPONENT_PREPUBLICATION_CORRECTION_PATH.is_symlink()
        or not _COMPONENT_PREPUBLICATION_CORRECTION_PATH.is_file()
    ):
        raise _component_error("the frozen amendment-011 correction is unavailable")
    try:
        prepublication = _strict_json_object(
            _COMPONENT_PREPUBLICATION_CORRECTION_PATH.read_text(encoding="utf-8"),
            label="amendment 011",
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("amendment 011 is unavailable") from exc
    prepublication_identity = prepublication.get("effective_protocol_identity")
    explicit_override = prepublication.get("explicit_override")
    if (
        prepublication.get("amendment_id") != "protocol-v3-amendment-011"
        or prepublication.get("parent_amendment") != "protocol-v3-amendment-010"
        or not str(prepublication.get("status", "")).startswith("frozen ")
        or not isinstance(prepublication_identity, dict)
        or not isinstance(explicit_override, dict)
        or explicit_override.get("successor_raw_attempt_id")
        != _COMPONENT_SUCCESSOR_ID
    ):
        raise _component_error("amendment 011 is not the frozen exact correction")
    amendment["effective_protocol_identity"]["required_git_topology"] = (
        prepublication_identity["required_git_topology"]
    )
    amendment["effective_protocol_identity"]["interpretation_order"] = (
        prepublication_identity["interpretation_order"]
    )
    amendment["prepublication_correction"] = prepublication
    return amendment


def r03_prepublication_failure_binding(
    amendment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate and bind the immutable r03 prepublication terminal archive."""

    amendment = amendment or _load_component_amendment()
    correction = amendment.get("prepublication_correction")
    if not isinstance(correction, dict):
        raise _component_error("amendment 011 prepublication correction is absent")
    observed = correction.get("observed_r03_terminal_boundary")
    if not isinstance(observed, dict):
        raise _component_error("amendment 011 r03 terminal boundary is absent")
    archive_contract = observed.get("terminal_archive")
    if not isinstance(archive_contract, dict):
        raise _component_error("amendment 011 terminal archive contract is absent")
    attempt_root = Path(str(observed.get("attempt_root", "")))
    archive_root = Path(str(archive_contract.get("path", "")))
    if (
        observed.get("raw_attempt_id") != _COMPONENT_BURNED_PREPUBLICATION_ID
        or str(observed.get("slurm_job_id")) != _COMPONENT_PREPUBLICATION_JOB_ID
        or observed.get("attempt_root_present") is not False
        or os.path.lexists(attempt_root)
    ):
        raise _component_error("r03 attempt-root absence or identity differs")
    _reject_symlink_components(archive_root, label="r03 prepublication archive")
    try:
        root_stat = archive_root.lstat()
    except OSError as exc:
        raise _component_error("r03 prepublication archive is unavailable") from exc
    effective_uid = getattr(os, "geteuid", lambda: root_stat.st_uid)()
    if (
        archive_root.is_symlink()
        or not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_IMODE(root_stat.st_mode) != int(archive_contract["directory_mode"])
        or root_stat.st_uid != effective_uid
    ):
        raise _component_error("r03 prepublication archive owner/type/mode differs")
    children = list(archive_root.iterdir())
    if {path.name for path in children} != _COMPONENT_PREPUBLICATION_MEMBER_NAMES:
        raise _component_error("r03 prepublication archive member set differs")
    members: dict[str, dict[str, Any]] = {}
    identities: set[tuple[int, int]] = set()
    for path in children:
        metadata = path.lstat()
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != int(archive_contract["member_mode"])
            or metadata.st_uid != root_stat.st_uid
            or identity in identities
        ):
            raise _component_error("r03 prepublication archive member metadata differs")
        identities.add(identity)
        members[path.name] = {
            "mode": stat.S_IMODE(metadata.st_mode),
            **_file_receipt(path),
        }
    manifest = archive_root / "evidence.sha256"
    sidecar = archive_root / "evidence.sha256.sha256"
    if (
        members["evidence.sha256"]["bytes"] != archive_contract["manifest_bytes"]
        or members["evidence.sha256"]["sha256"]
        != archive_contract["manifest_sha256"]
        or sidecar.read_text(encoding="utf-8")
        != f"{archive_contract['manifest_sha256']}  evidence.sha256\n"
    ):
        raise _component_error("r03 prepublication manifest or sidecar differs")
    manifest_entries: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./([^/]+)", line)
        if match is None or match.group(2) in manifest_entries:
            raise _component_error("r03 prepublication manifest syntax differs")
        manifest_entries[match.group(2)] = match.group(1)
    expected_manifest_names = _COMPONENT_PREPUBLICATION_MEMBER_NAMES - {
        "evidence.sha256",
        "evidence.sha256.sha256",
    }
    if set(manifest_entries) != expected_manifest_names or any(
        members[name]["sha256"] != digest
        for name, digest in manifest_entries.items()
    ):
        raise _component_error("r03 prepublication manifest rehash differs")
    setup = _strict_json_object(
        (archive_root / "setup-receipt.json").read_text(encoding="utf-8"),
        label="r03 setup receipt",
    )
    if (
        setup.get("raw_attempt_id") != _COMPONENT_BURNED_PREPUBLICATION_ID
        or str(setup.get("slurm_job_id")) != _COMPONENT_PREPUBLICATION_JOB_ID
        or setup.get("study_mode") != "formal_protocol_v3_amendment_008"
        or (archive_root / "repo-head.txt").read_text(encoding="utf-8").strip()
        != correction.get("parent_runtime_lock_commit")
    ):
        raise _component_error("r03 prepublication setup identity differs")
    terminal_sacct = (archive_root / "terminal-sacct.txt").read_text(encoding="utf-8")
    fields = terminal_sacct.rstrip("\n").split("|")
    if (
        len(fields) < 5
        or fields[0] != _COMPONENT_PREPUBLICATION_JOB_ID
        or fields[2:5] != ["ALL", "FAILED", "5:0"]
        or members["terminal-sacct.txt"]["sha256"]
        != archive_contract["terminal_sacct_sha256"]
        or members["stderr.log"]["sha256"] != archive_contract["stderr_sha256"]
        or members["setup-receipt.json"]["sha256"]
        != archive_contract["setup_receipt_sha256"]
    ):
        raise _component_error("r03 prepublication terminal evidence differs")
    return {
        "schema_version": 1,
        "kind": "retained_prepublication_launch_failure",
        "raw_attempt_id": _COMPONENT_BURNED_PREPUBLICATION_ID,
        "slurm_job_id": _COMPONENT_PREPUBLICATION_JOB_ID,
        "attempt_root": str(attempt_root),
        "attempt_root_absent": True,
        "terminal_archive_root": str(archive_root),
        "terminal_archive_mode": stat.S_IMODE(root_stat.st_mode),
        "terminal_archive_members": dict(sorted(members.items())),
        "classification": "prepublication_failure_before_child_spawn",
        "cause": "unclassified_beyond_observed_filenotfounderror",
    }


def _whole_attempt_plan(plan: list[dict[str, Any]]) -> dict[str, Any]:
    """Bind the full 430-row r03 plan and outcome-independent execution roles."""

    keys = [
        {
            "plan_index": index,
            "component": str(item.get("component", "")),
            "unit_id": str(item.get("unit_id", "")),
        }
        for index, item in enumerate(plan)
    ]

    def digest(start: int, stop: int) -> str:
        return sha256(_canonical_json_bytes(keys[start:stop])).hexdigest()

    return {
        "full_plan": plan,
        "unit_count": len(plan),
        "canonical_sha256": sha256(_canonical_json_bytes(plan)).hexdigest(),
        "ordered_membership_sha256": sha256(_canonical_json_bytes(keys)).hexdigest(),
        "primary_source_attempt_id": _COMPONENT_SUCCESSOR_ID,
        "execution_roles": {
            "provenance_rerun": {
                "count": 279,
                "membership_sha256": digest(0, 279),
            },
            "interrupted_direct": {
                "count": 1,
                "membership_sha256": digest(279, 280),
            },
            "unstarted_direct": {
                "count": 70,
                "membership_sha256": digest(280, 350),
            },
            "direct_first_completion": {
                "count": 71,
                "membership_sha256": digest(279, 350),
            },
            "deterministic_first_execution": {
                "count": 80,
                "membership_sha256": digest(350, 430),
            },
        },
    }


def _component_plans(_plan: list[dict[str, Any]]) -> dict[str, Any]:
    """Fail closed if any obsolete cross-attempt assembly path is reached."""

    raise _component_error("obsolete cross-attempt component assembly is forbidden")


def _forensics_exact_fields(
    value: Any,
    *,
    schema: dict[str, Any],
    schema_field: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _component_error(f"{label} is not an object")
    expected = schema.get(schema_field)
    if not isinstance(expected, list) or not all(
        isinstance(item, str) for item in expected
    ):
        raise _component_error(f"forensics schema omits {schema_field}")
    if set(value) != set(expected):
        raise _component_error(f"{label} fields differ from the frozen schema")
    return value


def _forensics_file_receipt(
    value: Any,
    *,
    schema: dict[str, Any],
    schema_field: str = "file_receipt_fields_exactly",
    label: str,
    expected_path: Path | None = None,
) -> tuple[dict[str, Any], Path]:
    receipt = _forensics_exact_fields(
        value,
        schema=schema,
        schema_field=schema_field,
        label=label,
    )
    declared = receipt.get("path")
    if not isinstance(declared, str) or not declared:
        raise _component_error(f"{label} path is invalid")
    path = Path(declared)
    if not path.is_absolute():
        raise _component_error(f"{label} path is not absolute")
    _reject_symlink_components(path, label=label)
    if path.is_symlink() or not path.is_file():
        raise _component_error(f"{label} is not a regular non-symlink file")
    resolved = path.resolve(strict=True)
    if path != resolved:
        raise _component_error(f"{label} path is not resolved")
    if expected_path is not None and resolved != expected_path.resolve(strict=True):
        raise _component_error(f"{label} path differs from the expected artifact")
    observed = _file_receipt(resolved)
    expected = {
        "path": str(resolved),
        "bytes": observed["bytes"],
        "sha256": observed["sha256"],
        "type": "regular_file",
    }
    if receipt != expected:
        raise _component_error(f"{label} bytes/hash/type differ")
    return receipt, resolved


def _forensics_json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise _component_error("forensics JSON pointer is invalid")
    current = value
    for raw_token in pointer[1:].split("/"):
        if re.search(r"~(?:[^01]|$)", raw_token):
            raise _component_error("forensics JSON pointer escape is invalid")
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            index = int(token)
            if index >= len(current):
                raise _component_error("forensics JSON pointer is out of range")
            current = current[index]
        else:
            raise _component_error("forensics JSON pointer does not resolve")
    return current


def _forensics_strict_json_file(
    path: Path, *, label: str, cache: dict[Path, Any]
) -> Any:
    if path in cache:
        return cache[path]

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key {key!r}")
            result[key] = child
        return result

    try:
        parsed = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _component_error(f"{label} is not strict JSON") from exc
    cache[path] = parsed
    return parsed


def _forensics_journal_lines(path: Path) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    if any(not line.endswith(b"\n") for line in lines):
        raise _component_error("r02 units.jsonl has a non-LF-terminated line")
    result: list[dict[str, Any]] = []
    offset = 0
    for line_number, line in enumerate(lines, start=1):
        try:
            parsed = _strict_json_object(
                line[:-1].decode("utf-8"),
                label=f"r02 units.jsonl line {line_number}",
            )
        except UnicodeDecodeError as exc:
            raise _component_error("r02 units.jsonl is not UTF-8") from exc
        result.append(
            {
                "line_number": line_number,
                "byte_offset": offset,
                "bytes_including_lf": len(line),
                "sha256": sha256(line).hexdigest(),
                "parsed": parsed,
            }
        )
        offset += len(line)
    return result


def _forensics_dependency(plan: dict[str, Any]) -> str:
    component = str(plan.get("component", ""))
    if component in {"matrix", "soak", "offline"}:
        return "direct_paw"
    if component != "faults":
        raise _component_error("r02 plan contains an unknown component")
    fault = str(plan.get("fault", ""))
    if fault in {"daemon_crash", "worker_exit", "worker_timeout"}:
        return "direct_paw"
    if fault in _COMPONENT_DETERMINISTIC_FAULTS:
        return "deterministic_no_paw"
    raise _component_error("r02 plan contains an unknown fault dependency")


def _forensics_dependency_basis(plan: dict[str, Any], *, schema: dict[str, Any]) -> str:
    frozen = schema.get("dependency_basis_by_static_plan_exactly")
    if frozen != _COMPONENT_DEPENDENCY_BASIS:
        raise _component_error("forensics dependency-basis schema differs")
    component = str(plan.get("component", ""))
    key = f"faults.{plan.get('fault')}" if component == "faults" else component
    try:
        return _COMPONENT_DEPENDENCY_BASIS[key]
    except KeyError as exc:
        raise _component_error("r02 plan has no exact dependency basis") from exc


def _forensics_positive_measurement(
    component: str, terminal: dict[str, Any]
) -> tuple[bool, list[str]]:
    if component == "matrix":
        pointers = [
            "/samples",
            "/accounting/evaluations_expected",
            "/daemon_identity/paw",
            "/incremental_evidence/journal_progress",
        ]
        values: list[Any] = []
        for pointer in pointers:
            try:
                values.append(_forensics_json_pointer(terminal, pointer))
            except SystemsHarnessError:
                values.append(_FORENSICS_MISSING)
        return bool(
            isinstance(values[0], list)
            and values[0]
            and type(values[1]) is int
            and values[1] >= 1
            and values[2] is True
            and isinstance(values[3], dict)
            and values[3]
        ), pointers
    if component == "soak":
        pointers = [
            "/events_submitted",
            "/batches",
            "/global_accounting/evaluations_expected",
            "/incremental_evidence/event_samples",
        ]
        values = []
        for pointer in pointers:
            try:
                values.append(_forensics_json_pointer(terminal, pointer))
            except SystemsHarnessError:
                values.append(_FORENSICS_MISSING)
        return bool(
            type(values[0]) is int
            and values[0] >= 1
            and isinstance(values[1], list)
            and values[1]
            and type(values[2]) is int
            and values[2] >= 1
            and isinstance(values[3], dict)
            and values[3]
        ), pointers
    if component == "offline":
        pointers = [
            "/prepared_online",
            "/online/sample",
            "/online/accounting/evaluations_expected",
            "/online_daemon_identity/paw",
        ]
        values = []
        for pointer in pointers:
            try:
                values.append(_forensics_json_pointer(terminal, pointer))
            except SystemsHarnessError:
                values.append(_FORENSICS_MISSING)
        return bool(
            values[0] is True
            and isinstance(values[1], dict)
            and type(values[2]) is int
            and values[2] >= 1
            and values[3] is True
        ), pointers
    if component == "faults":
        pointers = [
            "/error",
            "/probe_specific",
            "/probe_specific/recovery/sample",
            "/probe_specific/recovery/accounting/evaluations_expected",
            "/standardized_outcomes",
            "/started_monotonic_ns",
            "/finished_monotonic_ns",
        ]
        values = []
        for pointer in pointers:
            try:
                values.append(_forensics_json_pointer(terminal, pointer))
            except SystemsHarnessError:
                values.append(_FORENSICS_MISSING)
        return bool(
            values[0] is None
            and isinstance(values[1], dict)
            and "probe_exception" not in values[1]
            and isinstance(values[2], dict)
            and type(values[3]) is int
            and values[3] >= 1
            and isinstance(values[4], dict)
            and values[4]
            and values[4].get("orphan_process_count_status")
            != "unknown_after_caught_exception"
            and type(values[5]) is int
            and type(values[6]) is int
            and values[6] >= values[5]
        ), pointers
    raise _component_error("unknown direct-PAW component predicate")


def _forensics_carry_validity(
    plan: dict[str, Any], terminal: dict[str, Any]
) -> tuple[str, list[str]]:
    fault = str(plan.get("fault", ""))
    repetition = plan.get("repetition")
    common_pointers = [
        "/fault",
        "/repetition",
        "/passed",
        "/started_utc",
        "/finished_utc",
        "/started_monotonic_ns",
        "/finished_monotonic_ns",
        "/duration_ns",
        "/error",
        "/probe_specific",
        "/standardized_outcomes",
        "/probe_specific/persistent_state_integrity",
        "/probe_specific/post_shutdown_process_cleanup",
    ]
    try:
        values = {
            pointer: _forensics_json_pointer(terminal, pointer)
            for pointer in common_pointers
        }
    except SystemsHarnessError as exc:
        raise _component_error("deterministic carry common field is absent") from exc
    try:
        if not isinstance(values["/started_utc"], str) or not isinstance(
            values["/finished_utc"], str
        ):
            raise ValueError("UTC timestamp is not a string")
        started_utc = datetime.fromisoformat(
            values["/started_utc"].replace("Z", "+00:00")
        )
        finished_utc = datetime.fromisoformat(
            values["/finished_utc"].replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise _component_error(
            "deterministic carry UTC timestamps are invalid"
        ) from exc
    started_ns = values["/started_monotonic_ns"]
    finished_ns = values["/finished_monotonic_ns"]
    standardized = values["/standardized_outcomes"]
    standardized_fields = {
        "schema_version",
        "injected_boundary",
        "fail_open_hook_contract_and_latency",
        "current_event_survival",
        "loss_and_duplication",
        "healthy_recovery",
        "previous_deployment_continuity",
        "orphan_process_count",
        "orphan_process_count_status",
        "post_shutdown_process_cleanup",
        "persistent_state_integrity",
        "operator_visible_incident_records",
    }
    probe = values["/probe_specific"]
    if (
        values["/fault"] != fault
        or type(repetition) is not int
        or values["/repetition"] != repetition
        or type(values["/passed"]) is not bool
        or started_utc.tzinfo is None
        or finished_utc.tzinfo is None
        or type(started_ns) is not int
        or type(finished_ns) is not int
        or finished_ns < started_ns
        or values["/duration_ns"] != finished_ns - started_ns
        or values["/error"] is not None
        or not isinstance(probe, dict)
        or not probe
        or "probe_exception" in probe
        or not isinstance(standardized, dict)
        or set(standardized) != standardized_fields
        or standardized.get("schema_version") != 1
        or not isinstance(values["/probe_specific/persistent_state_integrity"], dict)
        or not values["/probe_specific/persistent_state_integrity"]
        or not isinstance(values["/probe_specific/post_shutdown_process_cleanup"], dict)
        or not values["/probe_specific/post_shutdown_process_cleanup"]
    ):
        raise _component_error("deterministic carry common predicate failed")

    family_pointers: list[str]
    if fault == "sqlite_lock":
        predicate = "sqlite_lock_carry_valid_v1"
        family_pointers = [
            "/probe_specific/lock_mode",
            "/probe_specific/lock_acquired_monotonic_ns",
            "/probe_specific/lock_release_started_monotonic_ns",
            "/probe_specific/lock_released_monotonic_ns",
            "/probe_specific/faulting_hook",
            "/probe_specific/recovery/sample",
            "/probe_specific/recovery/accounting/evaluations_expected",
        ]
    elif fault == "malformed_payload":
        predicate = "malformed_payload_carry_valid_v1"
        family_pointers = [
            "/probe_specific/invalid_json/hook",
            "/probe_specific/oversized_trigger_field/hook",
            "/probe_specific/final_exact_evaluation_accounting",
            "/probe_specific/recovery/sample",
            "/probe_specific/recovery/accounting/evaluations_expected",
        ]
    elif fault == "duplicate_delivery":
        predicate = "duplicate_delivery_carry_valid_v1"
        family_pointers = [
            "/probe_specific/deliveries",
            "/probe_specific/hooks",
            "/probe_specific/evaluations",
            "/probe_specific/findings",
            "/probe_specific/ingress_duplicate_counter_delta",
            "/probe_specific/exactly_once_within_live_daemon_window",
            "/probe_specific/scope",
        ]
    elif fault == "deployment_failure":
        predicate = "deployment_failure_carry_valid_v1"
        family_pointers = [
            "/probe_specific/prepare_ok",
            "/probe_specific/working_source_changed_after_prepare",
            "/probe_specific/working_behavior_changed_after_prepare",
            "/probe_specific/commit_ok",
            "/probe_specific/previous_active_revision_remained_effective",
            "/probe_specific/previous_active_source_sha256",
            "/probe_specific/post_failure_active_source_sha256",
            "/probe_specific/post_failure_sample",
            "/probe_specific/post_failure_accounting/evaluations_expected",
        ]
    else:
        raise _component_error("deterministic carry has an unknown family")
    try:
        family = {
            pointer: _forensics_json_pointer(terminal, pointer)
            for pointer in family_pointers
        }
    except SystemsHarnessError as exc:
        raise _component_error("deterministic carry family field is absent") from exc
    if fault == "sqlite_lock":
        times = [family[pointer] for pointer in family_pointers[1:4]]
        valid = bool(
            family[family_pointers[0]] == "BEGIN EXCLUSIVE"
            and all(type(value) is int for value in times)
            and times == sorted(times)
            and isinstance(family[family_pointers[4]], dict)
            and isinstance(family[family_pointers[5]], dict)
            and type(family[family_pointers[6]]) is int
            and family[family_pointers[6]] >= 1
        )
    elif fault == "malformed_payload":
        valid = bool(
            all(isinstance(family[pointer], dict) for pointer in family_pointers[:2])
            and isinstance(family[family_pointers[2]], dict)
            and family[family_pointers[2]]
            and isinstance(family[family_pointers[3]], dict)
            and type(family[family_pointers[4]]) is int
            and family[family_pointers[4]] >= 1
        )
    elif fault == "duplicate_delivery":
        hooks = family[family_pointers[1]]
        valid = bool(
            family[family_pointers[0]] == 2
            and isinstance(hooks, list)
            and len(hooks) == 2
            and all(isinstance(item, dict) for item in hooks)
            and all(type(family[pointer]) is int for pointer in family_pointers[2:5])
            and family[family_pointers[2]] >= 0
            and family[family_pointers[3]] >= 0
            and type(family[family_pointers[5]]) is bool
            and family[family_pointers[6]]
            == (
                "byte-identical concurrent redelivery while one daemon and its "
                "short-window admission cache remain live"
            )
        )
    else:
        source_hashes = [family[family_pointers[5]], family[family_pointers[6]]]
        valid = bool(
            family[family_pointers[0]] is True
            and all(type(family[pointer]) is bool for pointer in family_pointers[1:5])
            and all(
                isinstance(value, str)
                and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                for value in source_hashes
            )
            and isinstance(family[family_pointers[7]], dict)
            and type(family[family_pointers[8]]) is int
            and family[family_pointers[8]] >= 1
        )
    if not valid:
        raise _component_error("deterministic carry family predicate failed")
    return predicate, [*common_pointers, *family_pointers]


def _forensics_aware_datetime(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise _component_error(f"{label} is not a timestamp string")
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _component_error(f"{label} is not an ISO timestamp") from exc
    if observed.tzinfo is None:
        raise _component_error(f"{label} is not timezone-aware")
    return observed


def _forensics_validate_started_payload(
    *,
    component: str,
    unit_id: str,
    plan: dict[str, Any],
    payload: Any,
    attempt_root: Path,
    network_boundary: Any,
) -> None:
    """Validate the component-specific immutable ``*.started.json`` payload."""

    if not isinstance(payload, dict) or payload.get("phase") != "started":
        raise _component_error("r02 started payload phase differs")
    _forensics_aware_datetime(
        payload.get("started_utc"), label="r02 started payload started_utc"
    )
    stripped_plan = {
        key: value for key, value in plan.items() if key not in {"component", "unit_id"}
    }
    if component == "matrix":
        if (
            set(payload)
            != {
                "phase",
                "plan",
                "started_utc",
                "started_monotonic_ns",
                "retained_runtime_root",
            }
            or payload.get("plan") != stripped_plan
            or type(payload.get("started_monotonic_ns")) is not int
            or payload["started_monotonic_ns"] <= 0
            or payload.get("retained_runtime_root")
            != str(attempt_root / "runtime" / "matrix" / unit_id)
        ):
            raise _component_error("matrix started payload differs from its plan")
        return
    if component == "soak":
        if (
            set(payload) != {"phase", "events", "started_utc", "retained_runtime_root"}
            or payload.get("events") != plan.get("events")
            or payload.get("retained_runtime_root")
            != str(attempt_root / "runtime" / "soak")
        ):
            raise _component_error("soak started payload differs from its plan")
        return
    if component == "offline":
        if (
            set(payload)
            != {
                "phase",
                "started_utc",
                "network_boundary",
                "retained_runtime_root",
            }
            or payload.get("network_boundary") != network_boundary
            or payload.get("retained_runtime_root")
            != str(attempt_root / "runtime" / "offline")
        ):
            raise _component_error("offline started payload differs from its plan")
        return
    if component == "faults":
        fault = plan.get("fault")
        repetition = plan.get("repetition")
        if (
            set(payload)
            != {
                "fault",
                "repetition",
                "phase",
                "started_utc",
                "started_monotonic_ns",
            }
            or not isinstance(fault, str)
            or type(repetition) is not int
            or unit_id != f"{fault}-rep{repetition}"
            or payload.get("fault") != fault
            or payload.get("repetition") != repetition
            or type(payload.get("started_monotonic_ns")) is not int
            or payload["started_monotonic_ns"] <= 0
        ):
            raise _component_error("fault started payload differs from its plan")
        return
    raise _component_error("r02 started payload has an unknown component")


def _forensics_validate_terminal_payload(
    *,
    component: str,
    unit_id: str,
    plan: dict[str, Any],
    payload: dict[str, Any],
) -> None:
    """Validate component identity fields in one immutable terminal payload."""

    if component == "matrix":
        if payload.get("condition_id") != unit_id:
            raise _component_error("matrix terminal condition_id differs from plan")
        for field, value in plan.items():
            if field in {"component", "unit_id"}:
                continue
            if field in payload and payload[field] != value:
                raise _component_error(f"matrix terminal {field} differs from its plan")
        return
    if component == "soak":
        rule_count = plan.get("rule_count")
        project_count = plan.get("project_count")
        events = plan.get("events")
        if (
            type(rule_count) is not int
            or type(project_count) is not int
            or type(events) is not int
            or unit_id != f"soak-r{rule_count}-p{project_count}"
        ):
            raise _component_error("soak terminal identity differs from plan")
        expected = {
            "rule_count": rule_count,
            "project_count": project_count,
            "events": events,
        }
        if any(
            field in payload and payload[field] != value
            for field, value in expected.items()
        ):
            raise _component_error("soak terminal plan fields differ")
        if (
            payload.get("status") in {"completed", "system_violation"}
            and "error" not in payload
            and not set(expected).issubset(payload)
        ):
            raise _component_error("soak terminal omits successful plan fields")
        return
    if component == "offline":
        rules = plan.get("rules")
        if unit_id != "online-offline-exact-replay" or type(rules) is not int:
            raise _component_error("offline terminal identity differs from plan")
        if "rule_count" in payload and payload["rule_count"] != rules:
            raise _component_error("offline terminal rule_count differs from plan")
        if (
            payload.get("status") in {"completed", "system_violation"}
            and "error" not in payload
            and "rule_count" not in payload
        ):
            raise _component_error("offline terminal omits successful rule_count")
        return
    if component == "faults":
        fault = plan.get("fault")
        repetition = plan.get("repetition")
        if (
            not isinstance(fault, str)
            or type(repetition) is not int
            or unit_id != f"{fault}-rep{repetition}"
            or payload.get("fault") != fault
            or type(payload.get("repetition")) is not int
            or payload.get("repetition") != repetition
        ):
            raise _component_error("fault terminal identity differs from plan")
        return
    raise _component_error("r02 terminal payload has an unknown component")


def _forensics_validate_label_evidence(
    value: Any,
    *,
    schema: dict[str, Any],
    label: str,
    predecessor_root: Path,
    component: str,
    terminal_path: Path,
    tree_files: dict[str, dict[str, Any]],
    expected_pointers: list[str],
    expected_support_paths: set[Path],
    expected_text_literal_keys: set[tuple[str, bytes]],
    indirect_receipts: dict[str, dict[str, Any]],
    json_cache: dict[Path, Any],
) -> tuple[dict[tuple[str, str], Any], list[dict[str, Any]], dict[str, Path]]:
    """Validate lossless, sorted, exact-citation label evidence."""

    evidence = _forensics_exact_fields(
        value,
        schema=schema,
        schema_field="label_evidence_fields_exactly",
        label=label,
    )
    supporting = evidence.get("supporting_receipts")
    json_values = evidence.get("json_values")
    text_literals = evidence.get("text_literals")
    if not all(
        isinstance(items, list) for items in (supporting, json_values, text_literals)
    ):
        raise _component_error(f"{label} arrays are invalid")

    support_paths: dict[str, Path] = {}
    support_identities: set[tuple[int, int]] = set()
    ordered_support_paths: list[str] = []
    exact_paths = {terminal_path}
    for index, support in enumerate(supporting):
        receipt, path = _forensics_file_receipt(
            support,
            schema=schema,
            label=f"{label} support {index}",
        )
        identity = (path.stat().st_dev, path.stat().st_ino)
        if receipt["path"] in support_paths or identity in support_identities:
            raise _component_error(f"{label} repeats a support path or file identity")
        try:
            relative = path.relative_to(predecessor_root).as_posix()
        except ValueError as exc:
            raise _component_error(f"{label} support escapes immutable r02") from exc
        if path not in exact_paths:
            parts = PurePosixPath(relative).parts
            if not parts or parts[0] not in {component, "runtime"}:
                raise _component_error(f"{label} cites an unapproved r02 artifact")
            tree_item = tree_files.get(relative)
            if (
                not isinstance(tree_item, dict)
                or tree_item.get("type") != "regular_file"
                or tree_item.get("bytes") != receipt.get("bytes")
                or tree_item.get("sha256") != receipt.get("sha256")
            ):
                raise _component_error(f"{label} artifact is not raw-tree bound")
        support_paths[receipt["path"]] = path
        support_identities.add(identity)
        ordered_support_paths.append(receipt["path"])
    if [path.encode("utf-8") for path in ordered_support_paths] != sorted(
        path.encode("utf-8") for path in ordered_support_paths
    ):
        raise _component_error(f"{label} support paths are not strictly ordered")

    pointer_values: dict[tuple[str, str], Any] = {}
    ordered_pointer_keys: list[tuple[bytes, bytes]] = []
    for item in json_values:
        entry = _forensics_exact_fields(
            item,
            schema=schema,
            schema_field="json_value_evidence_fields_exactly",
            label=f"{label} JSON value",
        )
        receipt_path = entry.get("receipt_path")
        pointer = entry.get("json_pointer")
        if receipt_path not in support_paths or not isinstance(pointer, str):
            raise _component_error(f"{label} JSON value path is invalid")
        key = (str(receipt_path), pointer)
        if key in pointer_values:
            raise _component_error(f"{label} repeats a JSON value tuple")
        parsed = _forensics_strict_json_file(
            support_paths[receipt_path], label=f"{label} JSON source", cache=json_cache
        )
        actual = _forensics_json_pointer(parsed, pointer)
        if entry.get("value") != actual:
            raise _component_error(f"{label} JSON value differs")
        pointer_values[key] = actual
        ordered_pointer_keys.append(
            (str(receipt_path).encode("utf-8"), pointer.encode("utf-8"))
        )
    if ordered_pointer_keys != sorted(ordered_pointer_keys):
        raise _component_error(f"{label} JSON values are not strictly ordered")
    expected_pointer_keys = {
        (str(terminal_path), pointer) for pointer in expected_pointers
    }
    if set(pointer_values) != expected_pointer_keys:
        raise _component_error(f"{label} JSON pointer selection is not exact")

    literal_entries: list[dict[str, Any]] = []
    ordered_literal_keys: list[tuple[bytes, bytes]] = []
    observed_literal_keys: set[tuple[str, bytes]] = set()
    for item in text_literals:
        entry = _forensics_exact_fields(
            item,
            schema=schema,
            schema_field="text_literal_evidence_fields_exactly",
            label=f"{label} text literal",
        )
        receipt_path = entry.get("receipt_path")
        literal = entry.get("literal_utf8")
        count = entry.get("occurrence_count")
        if (
            receipt_path not in support_paths
            or not isinstance(literal, str)
            or not literal
            or type(count) is not int
            or count <= 0
        ):
            raise _component_error(f"{label} text literal is invalid")
        literal_bytes = literal.encode("utf-8")
        key = (str(receipt_path), literal_bytes)
        if key in observed_literal_keys:
            raise _component_error(f"{label} repeats a text literal tuple")
        try:
            actual_count = support_paths[receipt_path].read_bytes().count(literal_bytes)
        except OSError as exc:
            raise _component_error(f"{label} text source is unreadable") from exc
        if count != actual_count:
            raise _component_error(f"{label} text occurrence count differs")
        observed_literal_keys.add(key)
        ordered_literal_keys.append((str(receipt_path).encode("utf-8"), literal_bytes))
        literal_entries.append(entry)
    if ordered_literal_keys != sorted(ordered_literal_keys):
        raise _component_error(f"{label} text literals are not strictly ordered")

    if observed_literal_keys != expected_text_literal_keys:
        raise _component_error(f"{label} text literal selection is not exact")

    cited_paths = {
        *[path for path, _ in pointer_values],
        *[path for path, _ in observed_literal_keys],
    }
    expected_support = {
        str(path.resolve(strict=True)) for path in expected_support_paths
    }
    if (
        set(support_paths) != expected_support
        or cited_paths | set(indirect_receipts) != expected_support
    ):
        raise _component_error(f"{label} support receipts are not exact citations")
    for receipt_path, expected in indirect_receipts.items():
        path = support_paths.get(receipt_path)
        if path is None:
            raise _component_error(f"{label} omits an indirect support receipt")
        observed = _file_receipt(path)
        if (
            expected.get("path") != receipt_path
            or expected.get("bytes") != observed["bytes"]
            or expected.get("sha256") != observed["sha256"]
        ):
            raise _component_error(f"{label} indirect support receipt differs")
    return pointer_values, literal_entries, support_paths


def _forensics_cache_inventory_item(
    value: Any, *, schema: dict[str, Any], label: str
) -> dict[str, Any]:
    item = _forensics_exact_fields(
        value,
        schema=schema,
        schema_field="cache_inventory_item_fields_exactly",
        label=label,
    )
    relative_path = item.get("relative_path")
    relative = PurePosixPath(str(relative_path))
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or item.get("type") != "regular"
        or type(item.get("mode")) is not int
        or item["mode"] < 0
        or type(item.get("bytes")) is not int
        or item["bytes"] < 0
        or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None
    ):
        raise _component_error(f"{label} has an invalid cache-file identity")
    return item


def _forensics_validate_cache_closeout(
    closeout: dict[str, Any],
    *,
    schema: dict[str, Any],
    locked_required: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Recompute the complete direct-root inventory partition."""

    required = closeout.get("required_files")
    observed = closeout.get("observed_files")
    if not isinstance(required, list) or not isinstance(observed, list):
        raise _component_error("forensics cache inventory arrays are invalid")
    required_items = [
        _forensics_cache_inventory_item(
            item, schema=schema, label="forensics required cache inventory item"
        )
        for item in required
    ]
    observed_items = [
        _forensics_cache_inventory_item(
            item, schema=schema, label="forensics observed cache inventory item"
        )
        for item in observed
    ]
    if required_items != locked_required:
        raise _component_error("forensics required cache inventory differs from H3")
    for name, items in (("required", required_items), ("observed", observed_items)):
        paths = [item["relative_path"] for item in items]
        if paths != sorted(paths, key=lambda path: path.encode("utf-8")) or len(
            paths
        ) != len(set(paths)):
            raise _component_error(f"forensics {name} cache inventory order differs")
    required_by_path = {item["relative_path"]: item for item in required_items}
    observed_by_path = {item["relative_path"]: item for item in observed_items}
    for relative_path in observed_by_path:
        parts = PurePosixPath(relative_path).parts
        if (
            len(parts) < 2
            or parts[0] not in {"base_models", "programs", "runtimes"}
            or relative_path not in required_by_path
        ):
            raise _component_error("forensics observed cache inventory has an extra")
    matched: list[str] = []
    missing: list[str] = []
    mismatched: list[dict[str, Any]] = []
    for relative_path, required_item in required_by_path.items():
        observed_item = observed_by_path.get(relative_path)
        if observed_item is None:
            missing.append(relative_path)
        elif observed_item == required_item:
            matched.append(relative_path)
        else:
            mismatched.append(
                {
                    "relative_path": relative_path,
                    "required": required_item,
                    "observed": observed_item,
                }
            )
    declared_mismatches = closeout.get("mismatched_files")
    if not isinstance(declared_mismatches, list):
        raise _component_error("forensics mismatched cache inventory is invalid")
    for mismatch in declared_mismatches:
        parsed = _forensics_exact_fields(
            mismatch,
            schema=schema,
            schema_field="cache_mismatch_item_fields_exactly",
            label="forensics cache mismatch item",
        )
        _forensics_cache_inventory_item(
            parsed.get("required"),
            schema=schema,
            label="forensics cache mismatch required item",
        )
        if parsed.get("observed") is not None:
            _forensics_cache_inventory_item(
                parsed["observed"],
                schema=schema,
                label="forensics cache mismatch observed item",
            )
    if (
        closeout.get("matched_files") != matched
        or closeout.get("missing_files") != missing
        or declared_mismatches != mismatched
        or closeout.get("inventory_sha256")
        != sha256(_canonical_json_bytes(observed_items)).hexdigest()
    ):
        raise _component_error("forensics direct-cache partition differs")
    return observed_by_path


def _forensics_direct_root_inventory(root: Path) -> list[dict[str, Any]]:
    """Inventory the three direct content children of the configured root."""

    items: list[dict[str, Any]] = []
    content_children = [
        root / child for child in ("base_models", "programs", "runtimes")
    ]
    if any(path.is_symlink() or not path.is_dir() for path in content_children):
        raise _component_error("forensics configured direct content child is invalid")
    paths = [path for child in content_children for path in child.rglob("*")]
    for path in sorted(paths, key=lambda item: item.as_posix().encode("utf-8")):
        if path.is_symlink():
            raise _component_error(
                "forensics configured direct root contains a symlink"
            )
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(root).as_posix()
            receipt = _file_receipt(path.resolve(strict=True))
            items.append(
                {
                    "relative_path": relative,
                    "type": "regular",
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "bytes": receipt["bytes"],
                    "sha256": receipt["sha256"],
                }
            )
        elif not stat.S_ISDIR(metadata.st_mode):
            raise _component_error(
                "forensics configured direct root contains a special entry"
            )
    return items


def _forensics_validate_operational_active_set(
    operational: dict[str, Any],
    *,
    schema: dict[str, Any],
    observed_by_path: dict[str, dict[str, Any]],
    configured_root: Path,
    measured_membership_sha256: str,
) -> None:
    """Cross-bind operational program/runtime/model identities to closeout bytes."""

    program_ids = schema.get("operational_active_set_fixed_program_ids")
    tree_hashes = operational.get("program_tree_sha256_by_id")
    runtime_ids = operational.get("embedded_runtime_id_by_program_id")
    if (
        not isinstance(program_ids, list)
        or operational.get("program_ids") != program_ids
        or not isinstance(tree_hashes, dict)
        or set(tree_hashes) != set(program_ids)
        or not isinstance(runtime_ids, dict)
        or set(runtime_ids) != set(program_ids)
    ):
        raise _component_error("forensics operational program set differs")
    json_cache: dict[Path, Any] = {}
    for program_id in program_ids:
        prefix = f"programs/{program_id}/"
        items = [
            observed_by_path[relative_path]
            for relative_path in sorted(
                observed_by_path, key=lambda path: path.encode("utf-8")
            )
            if relative_path.startswith(prefix)
        ]
        if (
            not items
            or tree_hashes.get(program_id)
            != sha256(_canonical_json_bytes(items)).hexdigest()
        ):
            raise _component_error("forensics operational program-tree hash differs")
        meta_relative = f"programs/{program_id}/meta.json"
        meta_item = observed_by_path.get(meta_relative)
        meta_path = configured_root / PurePosixPath(meta_relative)
        if meta_item is None or meta_path.is_symlink() or not meta_path.is_file():
            raise _component_error("forensics operational program meta is absent")
        observed_meta = _file_receipt(meta_path.resolve(strict=True))
        if (
            observed_meta["bytes"] != meta_item["bytes"]
            or observed_meta["sha256"] != meta_item["sha256"]
        ):
            raise _component_error("forensics operational program meta differs")
        meta = _forensics_strict_json_file(
            meta_path.resolve(strict=True),
            label=f"forensics program {program_id} meta",
            cache=json_cache,
        )
        if (
            not isinstance(meta, dict)
            or meta.get("program_id") != program_id
            or meta.get("runtime_id") != "qwen3-0.6b-q6_k"
            or meta.get("runtime_manifest_version") != 1
            or runtime_ids.get(program_id) != "qwen3-0.6b-q6_k"
        ):
            raise _component_error("forensics operational program metadata differs")

    active = _forensics_exact_fields(
        operational.get("active_runtime_manifest"),
        schema=schema,
        schema_field="active_runtime_manifest_fields_exactly",
        label="forensics active runtime manifest",
    )
    active_relative = "runtimes/qwen3-0.6b-q6_k.json"
    active_item = observed_by_path.get(active_relative)
    active_path = configured_root / PurePosixPath(active_relative)
    if active_item is None or active_path.is_symlink() or not active_path.is_file():
        raise _component_error("forensics active runtime manifest is absent")
    active_receipt = _file_receipt(active_path.resolve(strict=True))
    active_json = _forensics_strict_json_file(
        active_path.resolve(strict=True),
        label="forensics active runtime manifest",
        cache=json_cache,
    )
    if (
        not isinstance(active_json, dict)
        or active_json.get("runtime_id") != "qwen3-0.6b-q6_k"
        or active
        != {
            "relative_path": active_relative,
            "bytes": active_item["bytes"],
            "sha256": active_item["sha256"],
            "embedded_runtime_id": "qwen3-0.6b-q6_k",
        }
        or active_receipt["bytes"] != active_item["bytes"]
        or active_receipt["sha256"] != active_item["sha256"]
    ):
        raise _component_error("forensics active runtime manifest differs")

    base = _forensics_exact_fields(
        operational.get("base_model"),
        schema=schema,
        schema_field="base_model_fields_exactly",
        label="forensics base model",
    )
    base_relative = "base_models/qwen3-0.6b-q6_k.gguf"
    base_item = observed_by_path.get(base_relative)
    if (
        base_item is None
        or base
        != {
            "relative_path": base_relative,
            "bytes": 622733120,
            "sha256": (
                "9a16ed5cacba959e63b62e2b6840c3eca2b51c3c3e51d31367ef8e4aafeae33c"
            ),
        }
        or base_item["bytes"] != base["bytes"]
        or base_item["sha256"] != base["sha256"]
        or operational.get("positive_measured_unit_membership_sha256")
        != measured_membership_sha256
    ):
        raise _component_error("forensics active runtime/model identity differs")


def _git_text(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise _component_error(f"could not inspect Git identity: {' '.join(args)}")
    return completed.stdout.strip()


def _git_parent(commit: str) -> str:
    fields = _git_text("rev-list", "--parents", "-n", "1", commit).split()
    if len(fields) != 2 or fields[0] != commit:
        raise _component_error("post-freeze commit is not single-parent")
    return fields[1]


def _git_diff_paths(commit: str) -> list[str]:
    return sorted(
        line
        for line in _git_text(
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            commit,
        ).splitlines()
        if line
    )


def _git_blob_sha1(raw: bytes) -> str:
    import hashlib

    return hashlib.sha1(
        f"blob {len(raw)}\0".encode("ascii") + raw,
        usedforsecurity=False,
    ).hexdigest()


def _git_remote_refs_containing(commit: str) -> list[str]:
    return sorted(
        ref
        for ref in _git_text(
            "for-each-ref",
            "--format=%(refname)",
            "--contains",
            commit,
            "refs/remotes",
        ).splitlines()
        if ref and not ref.endswith("/HEAD")
    )


def _tracked_source_receipt(relative: str, *, head: str) -> dict[str, Any]:
    path = _REPO_ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise _component_error(f"tracked source is unavailable: {relative}")
    raw = path.read_bytes()
    receipt = {
        "path": relative,
        "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "git_blob": _git_blob_sha1(raw),
    }
    if _git_text("rev-parse", f"{head}:{relative}") != receipt["git_blob"]:
        raise _component_error(f"working source differs from H4: {relative}")
    return receipt


def component_successor_source_binding(
    amendment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the acyclic P4/I4/H4 binding written into replacement.json."""

    amendment = amendment or _load_component_amendment()
    topology = dict(
        (amendment.get("effective_protocol_identity") or {}).get(
            "required_git_topology"
        )
        or {}
    )
    head = _git_text("rev-parse", "HEAD")
    implementation = _git_parent(head)
    protocol = _git_parent(implementation)
    parent = _git_parent(protocol)
    p4 = dict(topology.get("p4") or {})
    i4 = dict(topology.get("i4") or {})
    h4 = dict(topology.get("h4") or {})
    expected_paths = {
        "protocol": sorted(str(item) for item in p4.get("diff_paths_exactly") or []),
        "implementation": sorted(
            str(item) for item in i4.get("diff_paths_exactly") or []
        ),
        "runtime_lock": sorted(
            str(item) for item in h4.get("diff_paths_exactly") or []
        ),
    }
    observed_paths = {
        "protocol": _git_diff_paths(protocol),
        "implementation": _git_diff_paths(implementation),
        "runtime_lock": _git_diff_paths(head),
    }
    if (
        parent != p4.get("parent_must_equal")
        or i4.get("parent_must_equal_p4") is not True
        or h4.get("parent_must_equal_i4") is not True
        or topology.get("head_must_equal_h4_before_r04_setup") is not True
        or observed_paths != expected_paths
    ):
        raise _component_error("P4/I4/H4 topology differs from amendment 008")
    if not _git_remote_refs_containing(head):
        raise _component_error("H4 is not contained by a pushed remote ref")
    tracked_paths = [
        *expected_paths["protocol"],
        *expected_paths["implementation"],
        *expected_paths["runtime_lock"],
    ]
    return {
        "schema_version": 1,
        "protocol_parent": parent,
        "protocol_commit": protocol,
        "implementation_commit": implementation,
        "runtime_lock_commit": head,
        "commit_diff_paths": observed_paths,
        "tracked_files": [
            _tracked_source_receipt(relative, head=head) for relative in tracked_paths
        ],
    }


def whole_attempt_protocol_correction_binding(
    amendment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    amendment = amendment or _load_component_amendment()
    whole = dict(amendment.get("full_attempt_plan") or {})
    full = dict(whole.get("full_plan") or {})
    partial = dict(whole.get("r02_partial_execution") or {})
    history = dict(
        (amendment.get("pending_terminal_bindings") or {}).get("historical_validation")
        or {}
    )
    binding = {
        "schema_version": 1,
        "analysis_id": _COMPONENT_ANALYSIS_ID,
        "full_plan_unit_count": 430,
        "full_plan_stored_json_bytes": full.get("stored_json_bytes"),
        "full_plan_stored_json_sha256": full.get("stored_json_sha256"),
        "full_plan_canonical_sha256": full.get("canonical_sha256"),
        "full_plan_membership_sha256": full.get("ordered_membership_sha256"),
        "r02_started_unit_count": 280,
        "r02_terminal_unit_count": 279,
        "r02_started_without_terminal_unit_count": 1,
        "r02_never_started_unit_count": 150,
        "provenance_rerun_unit_count": 279,
        "provenance_rerun_membership_sha256": (
            partial.get("terminal_provenance_rerun") or {}
        ).get("unit_membership_sha256"),
        "interrupted_direct_unit_count": 1,
        "interrupted_direct_membership_sha256": (
            partial.get("interrupted_direct_first_completion") or {}
        ).get("unit_membership_sha256"),
        "unstarted_direct_unit_count": 70,
        "unstarted_direct_membership_sha256": (
            partial.get("unstarted_direct_first_execution") or {}
        ).get("unit_membership_sha256"),
        "direct_first_completion_unit_count": 71,
        "direct_first_completion_membership_sha256": (
            partial.get("all_direct_first_completion") or {}
        ).get("unit_membership_sha256"),
        "deterministic_first_execution_unit_count": 80,
        "deterministic_first_execution_membership_sha256": (
            partial.get("deterministic_first_execution") or {}
        ).get("unit_membership_sha256"),
        "primary_source_attempt_id": _COMPONENT_SUCCESSOR_ID,
        "amendment": {
            "path": "experiments/eacl2027/protocol-v3-amendment-008.json",
            "bytes": _COMPONENT_AMENDMENT_PATH.stat().st_size,
            "sha256": sha256(_COMPONENT_AMENDMENT_PATH.read_bytes()).hexdigest(),
        },
        "historical_validation": {
            key: history.get(key)
            for key in ("receipt_path", "receipt_bytes", "receipt_sha256")
        },
    }
    declared_fields = list(
        (amendment.get("replacement_and_evidence_contract") or {}).get(
            "whole_attempt_protocol_correction_fields_exactly"
        )
        or []
    )
    if set(binding) != set(declared_fields):
        raise _component_error("whole-attempt binding fields differ")
    fixed = {
        "full_plan_stored_json_bytes": 122245,
        "full_plan_stored_json_sha256": _COMPONENT_FULL_PLAN_STORED_SHA256,
        "full_plan_canonical_sha256": _COMPONENT_FULL_PLAN_SHA256,
        "full_plan_membership_sha256": _COMPONENT_FULL_PLAN_MEMBERSHIP_SHA256,
        "provenance_rerun_membership_sha256": "be08719a1247669532c0a0ce81b2af8620f6bc16f67aa866cddcd57e57c6d133",
        "interrupted_direct_membership_sha256": "61465b4f23df99fdbf8b2da08838a859c6b632a542970e90825afdf0f6ffbd72",
        "unstarted_direct_membership_sha256": "3a5211c5eb8924f1cff38af27d5fc7721b120441aba6bbdb603958415021e814",
        "direct_first_completion_membership_sha256": "5617983b1af61bdc492f4b980653e996b8fde172bfe10e93058e3dff0dfe4aed",
        "deterministic_first_execution_membership_sha256": "50a33139613a256b459317f71dfe3fb6de8114ecc673f94a85386feeb6df4b60",
    }
    if any(binding[name] != value for name, value in fixed.items()):
        raise _component_error("frozen whole-attempt hashes differ")
    historical = binding["historical_validation"]
    if (
        history.get("status") != "passed"
        or not isinstance(historical["receipt_path"], str)
        or not isinstance(historical["receipt_bytes"], int)
        or re.fullmatch(r"[0-9a-f]{64}", str(historical["receipt_sha256"])) is None
    ):
        raise _component_error("historical-validation binding is incomplete")
    return binding


def component_protocol_correction_binding(
    amendment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility name for the sole-source whole-attempt binding."""

    return whole_attempt_protocol_correction_binding(amendment)


def _outcome_aware_journal_records(
    predecessor_root: Path,
) -> tuple[int, int]:
    evaluation_records = 0
    audit_records = 0
    runtime = predecessor_root / "runtime"
    for path in runtime.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        name = path.name
        if name != "audit.jsonl" and not (
            name == "evaluations.jsonl" or name.startswith("evaluations.jsonl.")
        ):
            continue
        try:
            records = sum(bool(line.strip()) for line in path.read_bytes().splitlines())
        except OSError as exc:
            raise _outcome_aware_error(
                f"could not read retained journal {path}"
            ) from exc
        if name == "audit.jsonl":
            audit_records += records
        else:
            evaluation_records += records
    return evaluation_records, audit_records


def _validate_outcome_aware_replacement(
    *,
    receipt: dict[str, Any],
    predecessor_root: Path,
    predecessor_result: dict[str, Any],
    validated_artifacts: dict[str, dict[str, Any] | None],
    validated_tree: list[dict[str, Any]],
    validated_evidence: list[dict[str, Any]],
) -> None:
    """Recompute the one frozen amendment-007 premeasurement adjudication."""

    repair = _OUTCOME_AWARE_REPAIR
    overrides = repair["receipt_overrides"]
    for name in (
        "classification",
        "original_status",
        "reason",
        "affected_boundary",
        "scheduler_adjudication",
    ):
        if receipt.get(name) != overrides[name]:
            raise _outcome_aware_error(
                f"replacement receipt {name} does not match the frozen override"
            )

    for name, expected in repair["core_artifacts"].items():
        observed = validated_artifacts.get(name)
        if (
            observed is None
            or {
                "bytes": observed["bytes"],
                "sha256": observed["sha256"],
            }
            != expected
        ):
            raise _outcome_aware_error(f"{name} does not match its frozen anchor")

    launch = _read_outcome_aware_json(
        predecessor_root / "launch.json", label="predecessor launch"
    )
    identity = launch.get("identity")
    launch_anchor = repair["launch"]
    if not isinstance(identity, dict):
        raise _outcome_aware_error("predecessor launch lacks identity")
    formal_runtime = identity.get("formal_runtime")
    runtime_lock = (
        formal_runtime.get("runtime_lock") if isinstance(formal_runtime, dict) else None
    )
    runtime_lock_file = (
        runtime_lock.get("file") if isinstance(runtime_lock, dict) else None
    )
    if (
        launch.get("identity_sha256") != launch_anchor["identity_sha256"]
        or identity.get("attempt_id") != repair["predecessor_raw_attempt_id"]
        or identity.get("git")
        != {
            "commit": launch_anchor["git_commit"],
            "dirty": False,
            "scope": [
                "rules_as_programs",
                "experiments/eacl2027",
                "pyproject.toml",
            ],
        }
        or identity.get("runner")
        != {
            "git_blob": launch_anchor["runner_git_blob"],
            "path": "experiments/eacl2027/run_scaling_faults.py",
            "sha256": launch_anchor["runner_sha256"],
        }
        or identity.get("slurm")
        != {
            "job_id": launch_anchor["slurm"]["job_id"],
            "node_list": launch_anchor["slurm"]["node_list"],
            "partition": launch_anchor["slurm"]["partition"],
        }
        or not isinstance(runtime_lock_file, dict)
        or runtime_lock_file.get("sha256") != launch_anchor["runtime_lock_sha256"]
    ):
        raise _outcome_aware_error("predecessor launch identity does not match r01")

    claim_anchor = repair["publication_claim"]
    claim_path = Path(claim_anchor["path"])
    _reject_symlink_components(claim_path, label="r01 publication claim")
    if claim_path.is_symlink() or not claim_path.is_file():
        raise _outcome_aware_error("r01 publication claim is missing or not regular")
    claim_receipt = _file_receipt(claim_path.resolve(strict=True))
    if {
        "bytes": claim_receipt["bytes"],
        "sha256": claim_receipt["sha256"],
    } != {
        "bytes": claim_anchor["bytes"],
        "sha256": claim_anchor["sha256"],
    } or not os.path.samestat(
        claim_path.stat(follow_symlinks=False),
        (predecessor_root / "launch.json").stat(follow_symlinks=False),
    ):
        raise _outcome_aware_error(
            "r01 publication claim is not inode-identical to launch.json"
        )

    if _outcome_aware_tree_summary(validated_tree) != repair["tree"]:
        raise _outcome_aware_error("predecessor tree aggregates do not match r01")

    for name, expected in repair["result"].items():
        if predecessor_result.get(name) != expected:
            raise _outcome_aware_error(f"result {name} does not match r01")
    units = _outcome_aware_units(predecessor_result)
    expected_count = int(repair["result"]["terminal_unit_count"])
    if len(units) != expected_count:
        raise _outcome_aware_error("result does not contain all 430 terminal units")
    gate = repair["gate"]
    for unit in units:
        error = unit.get("error")
        if (
            unit.get("status") != gate["terminal_status"]
            or not isinstance(error, dict)
            or error.get("type") != gate["error_type"]
            or gate["error_message_fragment"] not in str(error.get("message", ""))
            or gate["bind_frame"] not in str(error.get("message", ""))
        ):
            raise _outcome_aware_error(
                "a result unit does not retain the exact pre-readiness bind failure"
            )

    sample_lists = [
        child
        for key, child in _walk_named_values(predecessor_result)
        if key == "samples" and isinstance(child, list)
    ]
    accounting_values = [
        child
        for key, child in _walk_named_values(predecessor_result)
        if key == "accounting"
    ]
    daemon_identities = [
        child
        for key, child in _walk_named_values(predecessor_result)
        if "daemon_identity" in key
    ]
    hook_activity = [
        child
        for key, child in _walk_named_values(predecessor_result)
        if key in {"hook", "hooks", "faulting_hook"} and bool(child)
    ]
    if (
        sum(len(value) for value in sample_lists) != 0
        or any(bool(value) for value in accounting_values)
        or any(value is not None for value in daemon_identities)
    ):
        raise _outcome_aware_error(
            "result contains a measured sample, accounting value, or daemon identity"
        )
    if hook_activity:
        raise _outcome_aware_error(
            "result contains a hook invocation before the frozen bind failure"
        )
    offline_result = predecessor_result.get("offline_after_prepare")
    if not isinstance(offline_result, dict) or any(
        bool(offline_result.get(name))
        for name in ("online", "offline", "comparison", "comparisons")
    ):
        raise _outcome_aware_error(
            "result contains offline replay activity before the frozen bind failure"
        )
    for fault in predecessor_result["faults"].values():
        for fault_attempt in fault.get("attempts") or []:
            standardized = fault_attempt.get("standardized_outcomes")
            if (
                fault_attempt.get("passed") is not False
                or not isinstance(standardized, dict)
                or any(
                    standardized.get(name) is not None
                    for name in (
                        "fail_open_hook_contract_and_latency",
                        "current_event_survival",
                        "loss_and_duplication",
                        "healthy_recovery",
                        "previous_deployment_continuity",
                        "persistent_state_integrity",
                    )
                )
                or bool(standardized.get("operator_visible_incident_records"))
            ):
                raise _outcome_aware_error(
                    "result contains an injected fault action before the frozen bind "
                    "failure"
                )

    unit_index = predecessor_result.get("unit_index")
    if not isinstance(unit_index, list) or len(unit_index) != expected_count:
        raise _outcome_aware_error("result unit_index is not complete")
    seen_terminal_paths: set[str] = set()
    for item in unit_index:
        if (
            not isinstance(item, dict)
            or item.get("started") is not True
            or item.get("status") != gate["terminal_status"]
            or not isinstance(item.get("terminal_record"), str)
            or not isinstance(item.get("terminal_record_sha256"), str)
        ):
            raise _outcome_aware_error("unit_index contains a non-r01 terminal entry")
        relative = Path(item["terminal_record"])
        if relative.is_absolute() or ".." in relative.parts:
            raise _outcome_aware_error("unit_index terminal path escapes r01")
        terminal_path = predecessor_root / relative
        _reject_symlink_components(terminal_path, label="r01 terminal record")
        try:
            resolved_terminal = terminal_path.resolve(strict=True)
            resolved_terminal.relative_to(predecessor_root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise _outcome_aware_error("unit_index terminal path escapes r01") from exc
        if terminal_path.is_symlink() or not terminal_path.is_file():
            raise _outcome_aware_error("unit_index terminal record is not regular")
        terminal_receipt = _file_receipt(resolved_terminal)
        if terminal_receipt["sha256"] != item["terminal_record_sha256"]:
            raise _outcome_aware_error("unit_index terminal record digest changed")
        terminal_key = str(resolved_terminal)
        if terminal_key in seen_terminal_paths:
            raise _outcome_aware_error("unit_index repeats a terminal record")
        seen_terminal_paths.add(terminal_key)
        terminal = _read_outcome_aware_json(
            resolved_terminal, label="r01 terminal record"
        )
        error = terminal.get("error")
        terminal_sample_lists = [
            child
            for key, child in _walk_named_values(terminal)
            if key == "samples" and isinstance(child, list)
        ]
        terminal_accounting = [
            child for key, child in _walk_named_values(terminal) if key == "accounting"
        ]
        terminal_daemon_identities = [
            child
            for key, child in _walk_named_values(terminal)
            if "daemon_identity" in key
        ]
        if (
            terminal.get("status") != gate["terminal_status"]
            or not isinstance(error, dict)
            or error.get("type") != gate["error_type"]
            or gate["error_message_fragment"] not in str(error.get("message", ""))
            or gate["bind_frame"] not in str(error.get("message", ""))
            or sum(len(value) for value in terminal_sample_lists) != 0
            or any(bool(value) for value in terminal_accounting)
            or any(value is not None for value in terminal_daemon_identities)
        ):
            raise _outcome_aware_error(
                "a retained terminal record is not the exact pre-readiness failure"
            )

    socket_paths: list[str] = []
    for unit in units:
        retained_root = (unit.get("error") or {}).get("retained_runtime_root")
        if not isinstance(retained_root, str):
            raise _outcome_aware_error("a unit lacks its retained runtime root")
        retained_path = Path(retained_root)
        try:
            retained_path.relative_to(predecessor_root / "runtime")
        except ValueError as exc:
            raise _outcome_aware_error("a retained runtime root escapes r01") from exc
        socket_paths.append(str(retained_path / "state" / "daemon.sock"))
    socket_lengths = [len(os.fsencode(path)) for path in socket_paths]
    if (
        min(socket_lengths) != gate["socket_path_min_bytes"]
        or max(socket_lengths) != gate["socket_path_max_bytes"]
        or any(length <= gate["pathname_limit_bytes"] for length in socket_lengths)
    ):
        raise _outcome_aware_error(
            "generated socket path lengths do not match the frozen AF_UNIX defect"
        )

    database_rows = {"databases": 0, "verdicts": 0, "attention": 0}
    for database in sorted((predecessor_root / "runtime").rglob("verdicts.db")):
        if database.is_symlink() or not database.is_file():
            raise _outcome_aware_error("retained verdict database is not regular")
        try:
            connection = sqlite3.connect(
                f"file:{database}?mode=ro&immutable=1", uri=True
            )
            try:
                database_rows["databases"] += 1
                database_rows["verdicts"] += int(
                    connection.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
                )
                database_rows["attention"] += int(
                    connection.execute("SELECT COUNT(*) FROM attention").fetchone()[0]
                )
            finally:
                connection.close()
        except (OSError, sqlite3.Error, TypeError) as exc:
            raise _outcome_aware_error(
                f"could not verify retained verdict database {database}"
            ) from exc
    if database_rows != {
        "databases": gate["verdict_database_count"],
        "verdicts": gate["verdict_rows"],
        "attention": gate["attention_rows"],
    }:
        raise _outcome_aware_error(
            "retained verdict databases are not measurement-empty"
        )
    evaluation_records, audit_records = _outcome_aware_journal_records(predecessor_root)
    if (
        evaluation_records != gate["evaluation_journal_records"]
        or audit_records != gate["audit_journal_records"]
    ):
        raise _outcome_aware_error("retained evaluation or audit journal is nonempty")

    evidence_anchor = repair["evidence"]
    evidence_by_kind = {item["kind"]: item for item in validated_evidence}
    counts = Counter(item["kind"] for item in validated_evidence)
    required_kinds = set(evidence_anchor["required_kinds"])
    if set(evidence_by_kind) != required_kinds or any(
        counts[kind] != 1 for kind in required_kinds
    ):
        raise _outcome_aware_error(
            "replacement evidence kinds do not exactly match amendment 007"
        )
    evidence_root = Path(evidence_anchor["root"])
    for kind, expected in evidence_anchor["files"].items():
        observed = evidence_by_kind[kind]
        expected_path = str((evidence_root / expected["name"]).resolve(strict=True))
        if observed["path"] != expected_path:
            raise _outcome_aware_error(f"{kind} does not use its frozen evidence path")
        if "bytes" in expected and {
            "bytes": observed["bytes"],
            "sha256": observed["sha256"],
        } != {"bytes": expected["bytes"], "sha256": expected["sha256"]}:
            raise _outcome_aware_error(f"{kind} does not match its frozen receipt")

    sacct_path = Path(evidence_by_kind["scheduler_sacct"]["path"])
    try:
        sacct_lines = sacct_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise _outcome_aware_error("scheduler_sacct is not exact UTF-8 text") from exc
    expected_parent_fields = [
        launch_anchor["slurm"]["job_id"],
        "rap-eacl-systems-v3",
        launch_anchor["slurm"]["partition"],
        launch_anchor["slurm"]["terminal_state"],
        launch_anchor["slurm"]["exit_code"],
        launch_anchor["slurm"]["elapsed"],
        launch_anchor["slurm"]["node_list"],
    ]
    parent_rows = [
        line.split("|")
        for line in sacct_lines
        if line.split("|", 1)[0] == launch_anchor["slurm"]["job_id"]
    ]
    if len(parent_rows) != 1 or parent_rows[0][:7] != expected_parent_fields:
        raise _outcome_aware_error("scheduler_sacct does not retain exact r01 state")

    adjudication_path = Path(
        evidence_by_kind["premeasurement_harness_adjudication"]["path"]
    )
    scheduler_receipts = {
        "sacct": {
            key: evidence_by_kind["scheduler_sacct"][key]
            for key in ("path", "bytes", "sha256")
        },
        "stdout": {
            key: evidence_by_kind["scheduler_stdout"][key]
            for key in ("path", "bytes", "sha256")
        },
        "stderr": {
            key: evidence_by_kind["scheduler_stderr"][key]
            for key in ("path", "bytes", "sha256")
        },
    }
    expected_adjudication = {
        "schema_version": 1,
        "classification": "harness_error",
        "attempt_id": repair["predecessor_raw_attempt_id"],
        "successor_attempt_id": repair["successor_raw_attempt_id"],
        "job": {
            "job_id": launch_anchor["slurm"]["job_id"],
            "partition": launch_anchor["slurm"]["partition"],
            "node": launch_anchor["slurm"]["node_list"],
            "state": launch_anchor["slurm"]["terminal_state"],
            "exit_code": launch_anchor["slurm"]["exit_code"],
            "elapsed": launch_anchor["slurm"]["elapsed"],
        },
        "git_commit": launch_anchor["git_commit"],
        "runner_sha256": launch_anchor["runner_sha256"],
        "runner_git_blob": launch_anchor["runner_git_blob"],
        "runtime_lock_sha256": launch_anchor["runtime_lock_sha256"],
        "launch_identity_sha256": launch_anchor["identity_sha256"],
        "result": {
            "status": predecessor_result["status"],
            "primary_numeric_eligible_raw": predecessor_result[
                "primary_numeric_eligible"
            ],
            "planned_units": predecessor_result["planned_unit_count"],
            "terminal_units": predecessor_result["terminal_unit_count"],
            "system_violation_labels": predecessor_result["system_violation_units"],
            "matrix_samples": sum(len(value) for value in sample_lists),
            "nonempty_accounting_values": sum(
                bool(value) for value in accounting_values
            ),
            "non_null_daemon_identities": sum(
                value is not None for value in daemon_identities
            ),
            "state_database_rows": database_rows,
        },
        "failure": {
            "stage": (
                "AF_UNIX bind before daemon readiness, warmup, wrapper invocation, "
                "or measured event"
            ),
            "error_signature": gate["error_message_fragment"],
            "units_with_exact_stage_signature": len(units),
            "linux_pathname_payload_limit_bytes": gate["pathname_limit_bytes"],
            "generated_socket_path_bytes": {
                "minimum": min(socket_lengths),
                "maximum": max(socket_lengths),
            },
            "example_socket_path": socket_paths[0],
        },
        "reason": (
            "the frozen harness constructed every daemon socket beyond the "
            "AF_UNIX pathname limit"
        ),
        "affected_boundary": (
            "socket-path construction and daemon bind before readiness, warmup, "
            "hook invocation, or measured event"
        ),
        "core_artifacts": {
            name: validated_artifacts[name] for name in _PREDECESSOR_ARTIFACT_NAMES
        },
        "tree": _outcome_aware_tree_summary(validated_tree),
        "scheduler_evidence": scheduler_receipts,
        "host": evidence_anchor["host"],
    }
    expected_adjudication_bytes = (
        json.dumps(expected_adjudication, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    try:
        observed_adjudication_bytes = adjudication_path.read_bytes()
    except OSError as exc:
        raise _outcome_aware_error(
            "could not read premeasurement adjudication"
        ) from exc
    if observed_adjudication_bytes != expected_adjudication_bytes:
        raise _outcome_aware_error(
            "premeasurement adjudication does not equal the recomputed r01 scan"
        )

    probe = _read_outcome_aware_json(
        Path(evidence_by_kind["af_unix_socket_probe"]["path"]),
        label="AF_UNIX socket probe",
    )
    proposed = probe.get("proposed_transport")
    frozen_failure = probe.get("frozen_failure_reproduction")
    slurm = probe.get("slurm")
    if (
        probe.get("schema_version") != 1
        or probe.get("status") != "passed"
        or probe.get("rap_inference_started") is not False
        or probe.get("r01_modified") is not False
        or probe.get("linux_pathname_payload_limit_bytes")
        != gate["pathname_limit_bytes"]
        or not isinstance(slurm, dict)
        or slurm != {"job_id": "1524434", "node": "watgpu108", "partition": "ALL"}
        or not isinstance(frozen_failure, dict)
        or frozen_failure.get("bind_failed") is not True
        or frozen_failure.get("encoded_path_bytes") != 163
        or (frozen_failure.get("error") or {}).get("type") != "OSError"
        or (frozen_failure.get("error") or {}).get("message") != "AF_UNIX path too long"
        or not isinstance(proposed, dict)
        or proposed.get("encoded_path_bytes") != 86
        or proposed.get("bind_connect_accept_payload_equal") is not True
        or proposed.get("endpoint_removed_after_probe") is not True
        or proposed.get("socket_root_mode") != "0700"
        or proposed.get("socket_root_symlink") is not False
    ):
        raise _outcome_aware_error("AF_UNIX probe semantics do not match the freeze")


def _validate_r02_terminal_forensics(
    *,
    amendment: dict[str, Any],
    evidence_receipt: dict[str, Any],
    predecessor_root: Path,
    predecessor_result: dict[str, Any],
    plan: list[dict[str, Any]],
    validated_tree: list[dict[str, Any]] | None = None,
    scheduler_sacct_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Consume the frozen, external 430-row r02 component-selection receipt."""

    schema = dict(
        (amendment.get("component_plan") or {}).get("r02_terminal_forensics_schema")
        or {}
    )
    if schema.get("schema_version") != 1 or schema.get("receipt_type") != (
        "r02_terminal_forensics"
    ):
        raise _component_error("r02 terminal-forensics schema identity differs")
    evidence_path = Path(str(evidence_receipt.get("path", "")))
    _, evidence_path = _forensics_file_receipt(
        {
            "path": evidence_receipt.get("path"),
            "bytes": evidence_receipt.get("bytes"),
            "sha256": evidence_receipt.get("sha256"),
            "type": "regular_file",
        },
        schema=schema,
        label="component-selection evidence",
        expected_path=evidence_path,
    )
    try:
        wrapper = _strict_json_object(
            evidence_path.read_text(encoding="utf-8"),
            label="r02 terminal-forensics receipt",
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("r02 terminal-forensics receipt is unreadable") from exc
    _forensics_exact_fields(
        wrapper,
        schema=schema,
        schema_field="wrapper_fields_exactly",
        label="r02 terminal-forensics wrapper",
    )
    payload = _forensics_exact_fields(
        wrapper.get("payload"),
        schema=schema,
        schema_field="payload_fields_exactly",
        label="r02 terminal-forensics payload",
    )
    payload_sha256 = sha256(_canonical_json_bytes(payload)).hexdigest()
    if (
        wrapper.get("schema_version") != 1
        or wrapper.get("receipt_type") != "r02_terminal_forensics"
        or wrapper.get("payload_sha256") != payload_sha256
    ):
        raise _component_error("r02 terminal-forensics payload digest differs")

    generated = str(payload.get("generated_utc", ""))
    try:
        generated_at = datetime.fromisoformat(generated.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _component_error("forensics generated_utc is invalid") from exc
    if generated_at.tzinfo is None or generated_at > datetime.now(timezone.utc):
        raise _component_error("forensics generated_utc is not an elapsed aware time")

    terminal = dict((amendment.get("pending_terminal_bindings") or {}).get("r02") or {})
    source = _forensics_exact_fields(
        payload.get("source_attempt"),
        schema=schema,
        schema_field="source_attempt_fields_exactly",
        label="forensics source_attempt",
    )
    predecessor_resolved = predecessor_root.resolve(strict=True)
    if (
        source.get("raw_attempt_id") != _COMPONENT_PREDECESSOR_ID
        or source.get("attempt_root") != str(predecessor_resolved)
        or source.get("job_id") != terminal.get("slurm_job_id")
        or source.get("launch_identity_sha256")
        != terminal.get("launch_identity_sha256")
        or source.get("plan_sha256") != _COMPONENT_FULL_PLAN_SHA256
    ):
        raise _component_error("forensics source-attempt binding differs")
    top_level = source.get("top_level_files")
    expected_top_level = {
        "launch": "launch.json",
        "plan": "plan.json",
        "publication": "publication.json",
        "units": "units.jsonl",
        "result": "result.json",
        "streams": "streams.json",
        "stdout": "stdout.log",
        "stderr": "stderr.log",
    }
    if not isinstance(top_level, dict) or set(top_level) != set(
        schema.get("source_top_level_files_exactly") or []
    ):
        raise _component_error("forensics top-level file set differs")
    top_level_paths: dict[str, Path] = {}
    for key, relative in expected_top_level.items():
        _, top_level_paths[key] = _forensics_file_receipt(
            top_level.get(key),
            schema=schema,
            label=f"forensics source {key}",
            expected_path=predecessor_resolved / relative,
        )

    json_cache: dict[Path, Any] = {}
    strict_launch = _forensics_strict_json_file(
        top_level_paths["launch"], label="forensics source launch", cache=json_cache
    )
    strict_plan = _forensics_strict_json_file(
        top_level_paths["plan"], label="forensics source plan", cache=json_cache
    )
    strict_result = _forensics_strict_json_file(
        top_level_paths["result"], label="forensics source result", cache=json_cache
    )
    launch_identity = (
        strict_launch.get("identity") if isinstance(strict_launch, dict) else None
    )
    if (
        not isinstance(launch_identity, dict)
        or strict_launch.get("identity_sha256") != source.get("launch_identity_sha256")
        or sha256(_canonical_json_bytes(launch_identity)).hexdigest()
        != source.get("launch_identity_sha256")
        or strict_launch.get("plan") != plan
        or strict_plan != plan
        or sha256(_canonical_json_bytes(strict_plan)).hexdigest()
        != source.get("plan_sha256")
        or strict_result != predecessor_result
    ):
        raise _component_error("forensics source JSON identities differ")

    selection = _forensics_exact_fields(
        payload.get("selection_contract"),
        schema=schema,
        schema_field="selection_contract_fields_exactly",
        label="forensics selection_contract",
    )
    if selection != schema.get("selection_contract_exact_value"):
        raise _component_error("forensics static selection contract differs")
    for name, source_value in selection["primary_source_by_dependency"].items():
        _forensics_exact_fields(
            source_value,
            schema=schema,
            schema_field="primary_source_dependency_value_fields_exactly",
            label=f"forensics primary source {name}",
        )

    frozen_predicates = dict(schema.get("label_predicates") or {})
    predicates = payload.get("label_predicates")
    if predicates != frozen_predicates:
        raise _component_error("forensics label predicates differ from amendment")

    journal = _forensics_journal_lines(top_level_paths["units"])
    unit_index = predecessor_result.get("unit_index")
    ordered = payload.get("ordered_units")
    if (
        not isinstance(unit_index, list)
        or len(unit_index) != 430
        or len(journal) != 430
        or not isinstance(ordered, list)
        or len(ordered) != 430
    ):
        raise _component_error("forensics ordered ledgers are not exactly 430 rows")

    tree_files = {
        str(item["relative_path"]): item
        for item in (validated_tree or [])
        if isinstance(item, dict) and item.get("type") == "regular_file"
    }
    for key, relative in expected_top_level.items():
        tree_item = tree_files.get(relative)
        receipt = top_level[key]
        if (
            not isinstance(tree_item, dict)
            or tree_item.get("bytes") != receipt.get("bytes")
            or tree_item.get("sha256") != receipt.get("sha256")
        ):
            raise _component_error("forensics source file is not complete-tree bound")

    observed_keys: set[tuple[str, str]] = set()
    label_rows: list[dict[str, Any]] = []
    status_memberships: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    error_memberships: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    label_memberships: dict[str, list[dict[str, Any]]] = {
        "premeasurement_cache_failure": [],
        "measured_after_unbound_cache_convergence": [],
        "other_structural_phase": [],
    }
    carry_membership: list[dict[str, Any]] = []
    replace_membership: list[dict[str, Any]] = []
    direct_rows: list[dict[str, Any]] = []
    deterministic_rows: list[dict[str, Any]] = []

    for plan_index, (planned, indexed, journal_line, row) in enumerate(
        zip(plan, unit_index, journal, ordered)
    ):
        row = _forensics_exact_fields(
            row,
            schema=schema,
            schema_field="ordered_unit_fields_exactly",
            label=f"forensics ordered unit {plan_index}",
        )
        component = str(planned.get("component", ""))
        unit_id = str(planned.get("unit_id", ""))
        key = (component, unit_id)
        if key in observed_keys:
            raise _component_error("forensics ordered_units repeats a plan key")
        observed_keys.add(key)
        dependency = _forensics_dependency(planned)
        dependency_basis = _forensics_dependency_basis(planned, schema=schema)
        expected_primary = (
            "replace_from_r03" if dependency == "direct_paw" else "carry_from_r02"
        )
        expected_sensitivity = (
            "retain_r02_sensitivity"
            if dependency == "direct_paw"
            else "primary_and_raw"
        )
        if (
            row.get("plan_index") != plan_index
            or row.get("plan_ordinal") != plan_index + 1
            or row.get("component") != component
            or row.get("unit_id") != unit_id
            or row.get("plan") != planned
            or row.get("plan_item_sha256")
            != sha256(_canonical_json_bytes(planned)).hexdigest()
            or row.get("dependency_class") != dependency
            or row.get("dependency_basis") != dependency_basis
            or row.get("primary_disposition") != expected_primary
            or row.get("sensitivity_disposition") != expected_sensitivity
        ):
            raise _component_error(f"forensics static row {plan_index} differs")
        if not isinstance(indexed, dict) or indexed.get("plan") != planned:
            raise _component_error("forensics result.unit_index differs from plan")

        expected_started = (
            predecessor_resolved
            / AttemptRecorder._safe(component)
            / f"{AttemptRecorder._safe(unit_id)}.started.json"
        )
        _, started_path = _forensics_file_receipt(
            row.get("started_receipt"),
            schema=schema,
            schema_field="started_receipt_fields_exactly",
            label=f"forensics started receipt {plan_index}",
            expected_path=expected_started,
        )
        started = _forensics_strict_json_file(
            started_path, label=f"r02 started payload {plan_index}", cache=json_cache
        )
        _forensics_validate_started_payload(
            component=component,
            unit_id=unit_id,
            plan=planned,
            payload=started,
            attempt_root=predecessor_resolved,
            network_boundary=schema.get("started_network_boundary_exact"),
        )

        terminal_relative = indexed.get("terminal_record")
        expected_terminal_relative = f"{component}/{unit_id}.terminal.json"
        if (
            not isinstance(terminal_relative, str)
            or terminal_relative != expected_terminal_relative
        ):
            raise _component_error("forensics unit has no terminal record")
        relative = Path(terminal_relative)
        if relative.is_absolute() or ".." in relative.parts:
            raise _component_error("forensics terminal record escapes r02")
        terminal_receipt = _forensics_exact_fields(
            row.get("terminal_receipt"),
            schema=schema,
            schema_field="terminal_receipt_fields_exactly",
            label=f"forensics terminal receipt {plan_index}",
        )
        terminal_file_fields = {
            key: terminal_receipt[key]
            for key in schema.get("file_receipt_fields_exactly") or []
        }
        _, terminal_path = _forensics_file_receipt(
            terminal_file_fields,
            schema=schema,
            label=f"forensics terminal file {plan_index}",
            expected_path=predecessor_resolved / relative,
        )
        terminal_payload = _forensics_strict_json_file(
            terminal_path,
            label=f"r02 terminal payload {plan_index}",
            cache=json_cache,
        )
        if not isinstance(terminal_payload, dict):
            raise _component_error("r02 terminal payload is not an object")
        raw_status = indexed.get("status")
        if (
            raw_status not in UNIT_STATUSES
            or terminal_receipt.get("status") != raw_status
            or terminal_receipt.get("payload_status") != terminal_payload.get("status")
            or terminal_receipt.get("status_matches_journal") is not True
            or terminal_payload.get("status") != raw_status
            or indexed.get("started") is not True
            or indexed.get("terminal_record_sha256") != terminal_receipt.get("sha256")
        ):
            raise _component_error("forensics terminal status/hash agreement failed")
        if started_path.stat().st_mtime_ns > terminal_path.stat().st_mtime_ns:
            raise _component_error("forensics started receipt postdates terminal")
        _forensics_validate_terminal_payload(
            component=component,
            unit_id=unit_id,
            plan=planned,
            payload=terminal_payload,
        )

        carry_validity = _forensics_exact_fields(
            row.get("carry_validity"),
            schema=schema,
            schema_field="carry_validity_fields_exactly",
            label=f"forensics carry validity {plan_index}",
        )
        empty_evidence = {
            "supporting_receipts": [],
            "json_values": [],
            "text_literals": [],
        }
        if dependency == "direct_paw":
            if carry_validity != {
                "applicable": False,
                "valid": None,
                "predicate_id": None,
                "evidence": empty_evidence,
            }:
                raise _component_error("direct-PAW row declares carry validity")
        else:
            if raw_status not in {"completed", "system_violation"}:
                raise _component_error("deterministic carry has an invalid status")
            carry_predicate, carry_pointers = _forensics_carry_validity(
                planned, terminal_payload
            )
            common_pointers = schema.get("carry_common_evidence_json_pointers_exactly")
            family_pointers = (
                schema.get("carry_family_evidence_json_pointers_exactly") or {}
            ).get(carry_predicate)
            exact_carry_pointers = [
                *(common_pointers if isinstance(common_pointers, list) else []),
                *(family_pointers if isinstance(family_pointers, list) else []),
            ]
            if (
                carry_validity.get("applicable") is not True
                or carry_validity.get("valid") is not True
                or carry_validity.get("predicate_id") != carry_predicate
                or carry_pointers != exact_carry_pointers
            ):
                raise _component_error("deterministic carry validity differs")
            _forensics_validate_label_evidence(
                carry_validity.get("evidence"),
                schema=schema,
                label=f"forensics carry evidence {plan_index}",
                predecessor_root=predecessor_resolved,
                component=component,
                terminal_path=terminal_path,
                tree_files=tree_files,
                expected_pointers=exact_carry_pointers,
                expected_support_paths={terminal_path},
                expected_text_literal_keys=set(),
                indirect_receipts={},
                json_cache=json_cache,
            )

        declared_journal = _forensics_exact_fields(
            row.get("journal_line_receipt"),
            schema=schema,
            schema_field="journal_line_receipt_fields_exactly",
            label=f"forensics journal line {plan_index}",
        )
        if declared_journal != journal_line:
            raise _component_error("forensics journal line receipt differs")
        parsed_journal = journal_line["parsed"]
        if (
            parsed_journal.get("component") != component
            or parsed_journal.get("record_id") != unit_id
            or parsed_journal.get("phase") != "terminal"
            or parsed_journal.get("status") != raw_status
            or parsed_journal.get("terminal_record") != terminal_relative
            or parsed_journal.get("terminal_record_sha256")
            != terminal_receipt.get("sha256")
        ):
            raise _component_error("forensics journal payload differs from unit")
        positive, positive_pointers = (
            _forensics_positive_measurement(component, terminal_payload)
            if dependency == "direct_paw"
            else (False, [])
        )
        daemon_log = (
            predecessor_resolved
            / "runtime"
            / "matrix"
            / unit_id
            / ("daemon-output.log")
        )
        download_literals: dict[str, int] = {}
        if (
            component == "matrix"
            and daemon_log.is_file()
            and not daemon_log.is_symlink()
        ):
            try:
                daemon_text = daemon_log.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                daemon_text = ""
            download_literals = {
                literal: daemon_text.count(literal)
                for literal in ("Downloading program", "Downloading interpreter")
            }
        error = terminal_payload.get("error")
        premeasurement = bool(
            dependency == "direct_paw"
            and component == "matrix"
            and raw_status == "system_violation"
            and isinstance(error, dict)
            and error.get("type") == "SystemViolationError"
            and isinstance(error.get("message"), str)
            and error["message"].startswith(
                "warmup exact evaluation accounting failed:"
            )
            and terminal_payload.get("samples") == []
            and terminal_payload.get("accounting") == {}
            and not positive
            and any(download_literals.values())
        )
        if premeasurement:
            label = "premeasurement_cache_failure"
            predicate_id = "premeasurement_cache_failure_v1"
            expected_pointers = [
                "",
                "/status",
                "/error/type",
                "/error/message",
                "/samples",
                "/accounting",
            ]
        elif dependency == "direct_paw" and positive:
            label = "measured_after_unbound_cache_convergence"
            predicate_id = "measured_after_unbound_cache_convergence_v1"
            expected_pointers = ["/status", *positive_pointers]
        else:
            label = "other_structural_phase"
            predicate_id = "other_structural_phase_v1"
            # The full terminal object is the only lossless JSON-pointer evidence
            # for a predicate that failed because one or more child keys are absent.
            expected_pointers = [""]
        if (
            row.get("repair_sensitivity_label") != label
            or row.get("matched_predicate_id") != predicate_id
        ):
            raise _component_error("forensics sensitivity label/predicate differs")

        if premeasurement:
            frozen_pointers = schema.get(
                "premeasurement_terminal_json_pointers_exactly"
            )
        elif label == "measured_after_unbound_cache_convergence":
            frozen_pointers = (
                schema.get(
                    "positive_measurement_terminal_json_pointers_by_component_exactly"
                )
                or {}
            ).get(component)
        else:
            frozen_pointers = [""]
        if frozen_pointers != expected_pointers:
            raise _component_error("forensics label pointer schema differs")

        expected_support_paths = {terminal_path}
        expected_text_literal_keys: set[tuple[str, bytes]] = set()
        indirect_receipts: dict[str, dict[str, Any]] = {}
        if premeasurement:
            resolved_daemon_log = daemon_log.resolve(strict=True)
            expected_support_paths.add(resolved_daemon_log)
            expected_text_literal_keys = {
                (str(resolved_daemon_log), literal.encode("utf-8"))
                for literal, count in download_literals.items()
                if count > 0
            }
        elif label == "measured_after_unbound_cache_convergence" and component in {
            "matrix",
            "soak",
        }:
            receipt_pointer = (
                "/incremental_evidence/journal_progress"
                if component == "matrix"
                else "/incremental_evidence/event_samples"
            )
            incremental = _forensics_json_pointer(terminal_payload, receipt_pointer)
            if not isinstance(incremental, dict) or not isinstance(
                incremental.get("path"), str
            ):
                raise _component_error("measured row incremental receipt is invalid")
            incremental_path = Path(incremental["path"])
            _reject_symlink_components(
                incremental_path, label="measured row incremental receipt"
            )
            if incremental_path.is_symlink() or not incremental_path.is_file():
                raise _component_error("measured row incremental receipt is absent")
            resolved_incremental = incremental_path.resolve(strict=True)
            expected_support_paths.add(resolved_incremental)
            indirect_receipts[str(resolved_incremental)] = incremental

        (
            observed_pointer_values,
            observed_literals,
            support_paths,
        ) = _forensics_validate_label_evidence(
            row.get("label_evidence"),
            schema=schema,
            label=f"forensics label evidence {plan_index}",
            predecessor_root=predecessor_resolved,
            component=component,
            terminal_path=terminal_path,
            tree_files=tree_files,
            expected_pointers=expected_pointers,
            expected_support_paths=expected_support_paths,
            expected_text_literal_keys=expected_text_literal_keys,
            indirect_receipts=indirect_receipts,
            json_cache=json_cache,
        )
        if label == "measured_after_unbound_cache_convergence" and component in {
            "matrix",
            "soak",
        }:
            receipt_pointer = (
                "/incremental_evidence/journal_progress"
                if component == "matrix"
                else "/incremental_evidence/event_samples"
            )
            incremental = observed_pointer_values[(str(terminal_path), receipt_pointer)]
            if not isinstance(incremental, dict):
                raise _component_error("measured row incremental receipt is invalid")
            incremental_path = incremental.get("path")
            if not isinstance(incremental_path, str):
                raise _component_error("measured row incremental path is invalid")
            resolved_incremental = Path(incremental_path).resolve(strict=True)
            if str(resolved_incremental) not in support_paths:
                raise _component_error("measured row omits incremental file receipt")
        if premeasurement and not any(
            item["receipt_path"] == str(daemon_log.resolve(strict=True))
            and item["literal_utf8"]
            in {"Downloading program", "Downloading interpreter"}
            and item["occurrence_count"] >= 1
            for item in observed_literals
        ):
            raise _component_error("premeasurement label omits download-log evidence")

        membership = {
            "plan_index": plan_index,
            "component": component,
            "unit_id": unit_id,
        }
        label_memberships[label].append(membership)
        (direct_rows if dependency == "direct_paw" else deterministic_rows).append(row)
        (replace_membership if dependency == "direct_paw" else carry_membership).append(
            membership
        )
        status_key = (dependency, label, component, raw_status)
        status_memberships.setdefault(status_key, []).append(membership)
        raw_error = terminal_payload.get("error")
        error_type = raw_error.get("type") if isinstance(raw_error, dict) else None
        error_message = (
            raw_error.get("message") if isinstance(raw_error, dict) else None
        )
        error_key = (
            dependency,
            label,
            component,
            raw_status,
            error_type,
            error_message,
        )
        error_memberships.setdefault(error_key, []).append(membership)
        label_rows.append(
            {
                **membership,
                "dependency_class": dependency,
                "primary_disposition": expected_primary,
                "repair_sensitivity_label": label,
                "matched_predicate_id": predicate_id,
                "raw_status": raw_status,
            }
        )

    validation = _forensics_exact_fields(
        payload.get("validation"),
        schema=schema,
        schema_field="validation_fields_exactly",
        label="forensics validation",
    )
    required_checks = schema.get("required_validation_checks")
    if (
        not isinstance(required_checks, list)
        or validation.get("checks") != {name: True for name in required_checks}
        or validation.get("failures") != []
    ):
        raise _component_error("forensics validation checks are not exact passes")

    expected_status_histogram = []
    for key, membership in sorted(status_memberships.items(), key=lambda item: item[0]):
        dependency, label, component, status = key
        expected_status_histogram.append(
            {
                "dependency_class": dependency,
                "repair_sensitivity_label": label,
                "component": component,
                "status": status,
                "count": len(membership),
                "unit_membership_sha256": sha256(
                    _canonical_json_bytes(membership)
                ).hexdigest(),
            }
        )
    if payload.get("terminal_status_histogram") != expected_status_histogram:
        raise _component_error("forensics terminal-status histogram differs")
    expected_error_histogram = []

    def error_sort_key(
        item: tuple[tuple[Any, ...], list[dict[str, Any]]],
    ) -> tuple[Any, ...]:
        dependency, label, component, status, error_type, error_message = item[0]
        return (
            dependency,
            label,
            component,
            status,
            error_type is not None,
            "" if error_type is None else error_type,
            error_message is not None,
            "" if error_message is None else error_message,
        )

    for key, membership in sorted(error_memberships.items(), key=error_sort_key):
        dependency, label, component, status, error_type, error_message = key
        expected_error_histogram.append(
            {
                "dependency_class": dependency,
                "repair_sensitivity_label": label,
                "component": component,
                "status": status,
                "error_type": error_type,
                "error_message": error_message,
                "count": len(membership),
                "unit_membership_sha256": sha256(
                    _canonical_json_bytes(membership)
                ).hexdigest(),
            }
        )
    if payload.get("error_histogram") != expected_error_histogram:
        raise _component_error("forensics error histogram differs")

    digests = payload.get("digests")
    required_digest_fields = schema.get("digests_fields_exactly")
    if (
        not isinstance(digests, dict)
        or not isinstance(required_digest_fields, list)
        or set(required_digest_fields) != set(digests)
    ):
        raise _component_error("forensics digest set is incomplete")
    expected_digests = {
        "ordered_plan_keys_sha256": sha256(
            _canonical_json_bytes(
                [
                    {
                        "plan_index": i,
                        "component": item["component"],
                        "unit_id": item["unit_id"],
                    }
                    for i, item in enumerate(plan)
                ]
            )
        ).hexdigest(),
        "ordered_units_sha256": sha256(_canonical_json_bytes(ordered)).hexdigest(),
        "direct_rows_sha256": sha256(_canonical_json_bytes(direct_rows)).hexdigest(),
        "deterministic_rows_sha256": sha256(
            _canonical_json_bytes(deterministic_rows)
        ).hexdigest(),
        "premeasurement_membership_sha256": sha256(
            _canonical_json_bytes(label_memberships["premeasurement_cache_failure"])
        ).hexdigest(),
        "measured_membership_sha256": sha256(
            _canonical_json_bytes(
                label_memberships["measured_after_unbound_cache_convergence"]
            )
        ).hexdigest(),
        "other_membership_sha256": sha256(
            _canonical_json_bytes(label_memberships["other_structural_phase"])
        ).hexdigest(),
        "carry_rows_sha256": sha256(
            _canonical_json_bytes(carry_membership)
        ).hexdigest(),
        "replace_rows_sha256": sha256(
            _canonical_json_bytes(replace_membership)
        ).hexdigest(),
        "terminal_status_histogram_sha256": sha256(
            _canonical_json_bytes(expected_status_histogram)
        ).hexdigest(),
        "error_histogram_sha256": sha256(
            _canonical_json_bytes(expected_error_histogram)
        ).hexdigest(),
    }
    if any(digests.get(name) != value for name, value in expected_digests.items()):
        raise _component_error("forensics recomputed digest differs")

    counts = _forensics_exact_fields(
        payload.get("counts"),
        schema=schema,
        schema_field="counts_fields_exactly",
        label="forensics counts",
    )
    fixed_counts = schema.get("counts_fixed_values")
    if not isinstance(fixed_counts, dict) or any(
        counts.get(name) != value for name, value in fixed_counts.items()
    ):
        raise _component_error("forensics total/carry/replace counts differ")
    if counts.get("cross_tabulation") != expected_status_histogram:
        raise _component_error("forensics count cross-tabulation differs")
    if len(direct_rows) != 350 or len(deterministic_rows) != 80:
        raise _component_error("forensics dependency partition differs from 350/80")

    cache = _forensics_exact_fields(
        payload.get("cache_root_misbinding"),
        schema=schema,
        schema_field="cache_root_misbinding_fields_exactly",
        label="forensics cache-root misbinding",
    )
    closeout = _forensics_exact_fields(
        cache.get("direct_closeout_inventory"),
        schema=schema,
        schema_field="direct_closeout_inventory_fields_exactly",
        label="forensics direct closeout inventory",
    )

    lock_relative = str(
        (
            ((amendment.get("known_at_draft") or {}).get("h3") or {}).get(
                "runtime_lock"
            )
            or {}
        ).get("path", "")
    )
    lock_path = _REPO_ROOT / lock_relative
    lock_anchor = ((amendment.get("known_at_draft") or {}).get("h3") or {}).get(
        "runtime_lock"
    ) or {}
    if (
        lock_relative != "experiments/eacl2027/formal-runtime-lock-v3.json"
        or lock_path.is_symlink()
        or not lock_path.is_file()
        or sha256(lock_path.read_bytes()).hexdigest() != lock_anchor.get("sha256")
    ):
        raise _component_error("forensics H3 runtime-lock identity differs")
    locked = _forensics_strict_json_file(
        lock_path.resolve(strict=True),
        label="forensics H3 runtime lock",
        cache=json_cache,
    )
    locked_cache = dict((locked or {}).get("paw_cache") or {})
    complete_tree = dict(locked_cache.get("complete_tree") or {})
    raw_tree = dict(locked_cache.get("raw_tree") or {})
    complete_files = complete_tree.get("files")
    raw_entries = raw_tree.get("entries")
    if not isinstance(complete_files, list) or not isinstance(raw_entries, list):
        raise _component_error("forensics H3 cache trees are invalid")
    complete_by_path = {
        str(item.get("path")): item for item in complete_files if isinstance(item, dict)
    }
    if len(complete_by_path) != len(complete_files):
        raise _component_error("forensics H3 complete tree repeats a file")
    locked_required: list[dict[str, Any]] = []
    for raw_item in raw_entries:
        if not isinstance(raw_item, dict) or raw_item.get("type") != "regular":
            continue
        relative_path = str(raw_item.get("path", ""))
        complete_item = complete_by_path.get(relative_path)
        projected = {
            "relative_path": relative_path,
            "type": "regular",
            "mode": raw_item.get("mode"),
            "bytes": raw_item.get("bytes"),
            "sha256": raw_item.get("sha256"),
        }
        _forensics_cache_inventory_item(
            projected,
            schema=schema,
            label="forensics H3 projected cache item",
        )
        if (
            not isinstance(complete_item, dict)
            or complete_item.get("bytes") != projected["bytes"]
            or complete_item.get("sha256") != projected["sha256"]
        ):
            raise _component_error("forensics H3 raw/complete cache trees disagree")
        locked_required.append(projected)
    locked_required.sort(key=lambda item: item["relative_path"].encode("utf-8"))
    complete_inventory_sha256 = sha256(
        _canonical_json_bytes(complete_files)
    ).hexdigest()
    raw_inventory_sha256 = sha256(
        _canonical_json_bytes(
            {"root_entry": raw_tree.get("root_entry"), "entries": raw_entries}
        )
    ).hexdigest()
    source_launch = _forensics_strict_json_file(
        top_level_paths["launch"], label="forensics r02 launch", cache=json_cache
    )
    source_runtime = dict(
        ((source_launch or {}).get("identity") or {}).get("formal_runtime") or {}
    )
    source_lock = dict(source_runtime.get("runtime_lock") or {})
    source_lock_file = dict(source_lock.get("file") or {})
    if (
        cache.get("configured_direct_root")
        != (amendment.get("corrected_direct_paw_cache_contract") or {}).get(
            "h3_incorrect_declared_root"
        )
        or not isinstance(cache.get("launch_inventoried_nested_root"), str)
        or cache["launch_inventoried_nested_root"]
        != (amendment.get("corrected_direct_paw_cache_contract") or {}).get(
            "r03_paw_cache_dir_exact"
        )
        or cache.get("launch_nested_inventory_sha256")
        != "6764a77f942f8a2699babb0801fcf4beb94b6511040e5b5f95b56e06e64c8977"
        or cache.get("launch_nested_inventory_sha256")
        != complete_tree.get("inventory_sha256")
        or cache.get("launch_nested_inventory_sha256") != complete_inventory_sha256
        or cache.get("launch_nested_raw_tree_inventory_sha256")
        != "7c849181a6de60b237ddfb3a7eab3678ec6f1e212696b217a4efcb9959f05b43"
        or cache.get("launch_nested_raw_tree_inventory_sha256")
        != raw_tree.get("inventory_sha256")
        or cache.get("launch_nested_raw_tree_inventory_sha256") != raw_inventory_sha256
        or len(locked_required) != 51
        or source_runtime.get("paw_cache") != locked_cache
        or source_lock.get("content") != locked
        or source_lock_file.get("sha256") != lock_anchor.get("sha256")
        or source_lock.get("paw_cache_receipt_sha256")
        != sha256(_canonical_json_bytes(locked_cache)).hexdigest()
    ):
        raise _component_error("forensics direct-cache closeout facts differ")

    configured_root = Path(str(cache.get("configured_direct_root", "")))
    if not configured_root.is_absolute():
        raise _component_error("forensics configured direct root is not absolute")
    _reject_symlink_components(
        configured_root, label="forensics configured direct root"
    )
    if configured_root.is_symlink() or not configured_root.is_dir():
        raise _component_error("forensics configured direct root is unavailable")
    configured_root = configured_root.resolve(strict=True)
    if closeout.get("observed_files") != _forensics_direct_root_inventory(
        configured_root
    ):
        raise _component_error("forensics observed cache inventory is not complete")
    observed_by_path = _forensics_validate_cache_closeout(
        closeout, schema=schema, locked_required=locked_required
    )
    if (
        closeout.get("matched_files")
        != [
            item["relative_path"]
            for item in locked_required
            if item["relative_path"] != "runtimes/qwen3-0.6b-q6_k.v1.json"
        ]
        or closeout.get("missing_files") != ["runtimes/qwen3-0.6b-q6_k.v1.json"]
        or closeout.get("mismatched_files") != []
    ):
        raise _component_error("forensics direct-cache closeout facts differ")

    operational = _forensics_exact_fields(
        cache.get("operational_active_set"),
        schema=schema,
        schema_field="operational_active_set_fields_exactly",
        label="forensics operational active set",
    )
    _forensics_validate_operational_active_set(
        operational,
        schema=schema,
        observed_by_path=observed_by_path,
        configured_root=configured_root,
        measured_membership_sha256=expected_digests["measured_membership_sha256"],
    )
    if cache.get("observation") != schema.get("cache_observation_exact"):
        raise _component_error("forensics cache observation differs")

    # These objects have amendment-defined exact field sets. Their internal values
    # remain externally byte-bound; require the independently checkable identities.
    scheduler = _forensics_exact_fields(
        payload.get("scheduler"),
        schema=schema,
        schema_field="scheduler_fields_exactly",
        label="forensics scheduler",
    )
    try:
        observed_at = datetime.fromisoformat(
            str(scheduler.get("observed_utc", "")).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise _component_error("forensics scheduler observed_utc is invalid") from exc
    if observed_at.tzinfo is None:
        raise _component_error("forensics scheduler observed_utc is not aware")
    scheduler_commands: dict[str, dict[str, Any]] = {}
    for name in ("squeue", "sacct", "scontrol_job"):
        command = _forensics_exact_fields(
            scheduler.get(name),
            schema=schema,
            schema_field="scheduler_command_receipt_fields_exactly",
            label=f"forensics scheduler {name}",
        )
        exact_command = (schema.get("scheduler_commands_exactly") or {}).get(name)
        stdout = command.get("stdout")
        stderr = command.get("stderr")
        parsed = command.get("parsed")
        if not isinstance(exact_command, dict):
            raise _component_error(f"forensics scheduler {name} schema is absent")
        if (
            command.get("command") != exact_command.get("argv")
            or type(command.get("exit_code")) is not int
            or command.get("exit_code") != 0
            or not isinstance(stdout, str)
            or command.get("stdout_bytes") != len(stdout.encode("utf-8"))
            or command.get("stdout_sha256")
            != sha256(stdout.encode("utf-8")).hexdigest()
            or stderr != ""
            or command.get("stderr_bytes") != 0
            or command.get("stderr_sha256") != sha256(b"").hexdigest()
            or not isinstance(parsed, dict)
            or set(parsed) != {"format", "rows"}
            or parsed.get("format") != exact_command.get("parsed_format")
            or not isinstance(parsed.get("rows"), list)
        ):
            raise _component_error(f"forensics scheduler {name} receipt differs")
        row_fields = exact_command.get("row_fields_exactly")
        for parsed_row in parsed["rows"]:
            if not isinstance(parsed_row, dict) or set(parsed_row) != set(
                row_fields or []
            ):
                raise _component_error(f"forensics scheduler {name} parsed row differs")
            if name == "scontrol_job":
                fields = parsed_row.get("fields")
                if not isinstance(fields, dict) or not all(
                    isinstance(key, str) and isinstance(value, str)
                    for key, value in fields.items()
                ):
                    raise _component_error("forensics scontrol fields are invalid")
            elif not all(isinstance(value, str) for value in parsed_row.values()):
                raise _component_error(
                    f"forensics scheduler {name} row is not exact text"
                )
        independently_parsed: list[dict[str, Any]] = []
        if name in {"squeue", "sacct"}:
            for raw_line in stdout.splitlines():
                if not raw_line:
                    continue
                fields = raw_line.split("|")
                if (
                    name == "sacct"
                    and len(fields) == len(row_fields or []) + 1
                    and fields[-1] == ""
                ):
                    fields.pop()
                if len(fields) != len(row_fields or []):
                    raise _component_error(
                        f"forensics scheduler {name} field count differs"
                    )
                independently_parsed.append(dict(zip(row_fields, fields)))
        else:
            for raw_line in stdout.splitlines():
                if not raw_line:
                    continue
                fields: dict[str, str] = {}
                for token in raw_line.split():
                    if "=" not in token:
                        raise _component_error("forensics scontrol token lacks equals")
                    key, value = token.split("=", 1)
                    if not key or key in fields:
                        raise _component_error("forensics scontrol key is duplicate")
                    fields[key] = value
                independently_parsed.append({"fields": fields})
        if parsed["rows"] != independently_parsed:
            raise _component_error(f"forensics scheduler {name} parsed value differs")
        scheduler_commands[name] = command

    squeue_rows = scheduler_commands["squeue"]["parsed"]["rows"]
    sacct_rows = scheduler_commands["sacct"]["parsed"]["rows"]
    scontrol_rows = scheduler_commands["scontrol_job"]["parsed"]["rows"]
    job_id = str(terminal.get("slurm_job_id", ""))
    top_level_sacct = [row for row in sacct_rows if row.get("job_id_raw") == job_id]
    if squeue_rows != [] or len(top_level_sacct) != 1 or len(scontrol_rows) != 1:
        raise _component_error("forensics scheduler terminal row cardinality differs")
    sacct_terminal = top_level_sacct[0]
    scontrol_terminal = scontrol_rows[0]["fields"]
    if (
        sacct_terminal.get("partition") != terminal.get("slurm_partition")
        or sacct_terminal.get("node_list") != terminal.get("slurm_node_list")
        or sacct_terminal.get("state") != terminal.get("slurm_terminal_state")
        or sacct_terminal.get("exit_code") != terminal.get("slurm_exit_code")
        or not str(sacct_terminal.get("start", ""))
        or not str(sacct_terminal.get("end", ""))
        or re.fullmatch(r"[0-9]+", str(sacct_terminal.get("elapsed_raw", ""))) is None
        or scontrol_terminal.get("JobId") != job_id
        or scontrol_terminal.get("Partition") != terminal.get("slurm_partition")
        or scontrol_terminal.get("NodeList") != terminal.get("slurm_node_list")
        or scontrol_terminal.get("JobState") != terminal.get("slurm_terminal_state")
        or scontrol_terminal.get("ExitCode") != terminal.get("slurm_exit_code")
        or any(
            suffix in str(sacct_terminal.get("state", "")).upper()
            for suffix in ("RUNNING", "PENDING", "CONFIGURING", "COMPLETING")
        )
    ):
        raise _component_error("forensics scheduler terminal identity differs")
    try:
        sacct_end = datetime.fromisoformat(
            str(sacct_terminal["end"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise _component_error("forensics sacct end time is invalid") from exc
    if sacct_end.tzinfo is None:
        sacct_end = sacct_end.replace(tzinfo=timezone.utc)
    if not (sacct_end <= observed_at <= generated_at):
        raise _component_error("forensics scheduler observation chronology differs")
    if scheduler_sacct_evidence is None:
        raise _component_error("forensics scheduler lacks separate sacct evidence")
    separate_sacct_path = Path(str(scheduler_sacct_evidence.get("path", "")))
    try:
        separate_sacct_stdout = separate_sacct_path.read_text(
            encoding="utf-8", errors="strict"
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("separate r02 sacct evidence is unreadable") from exc
    if separate_sacct_stdout != scheduler_commands["sacct"]["stdout"]:
        raise _component_error("forensics and separately bound sacct bytes differ")

    boundaries = _forensics_exact_fields(
        payload.get("boundaries"),
        schema=schema,
        schema_field="boundaries_fields_exactly",
        label="forensics boundaries",
    )
    expected_boundary_rows = []
    for label in (
        "premeasurement_cache_failure",
        "measured_after_unbound_cache_convergence",
        "other_structural_phase",
    ):
        membership = label_memberships[label]
        runs: list[dict[str, Any]] = []
        for item in membership:
            point = {"plan_index": item["plan_index"], "unit_id": item["unit_id"]}
            if runs and runs[-1]["last"]["plan_index"] + 1 == item["plan_index"]:
                runs[-1]["last"] = point
                runs[-1]["count"] += 1
            else:
                runs.append({"first": point, "last": point, "count": 1})
        expected_boundary_rows.append(
            {
                "label": label,
                "count": len(membership),
                "first": (
                    {
                        "plan_index": membership[0]["plan_index"],
                        "unit_id": membership[0]["unit_id"],
                    }
                    if membership
                    else None
                ),
                "last": (
                    {
                        "plan_index": membership[-1]["plan_index"],
                        "unit_id": membership[-1]["unit_id"],
                    }
                    if membership
                    else None
                ),
                "runs": runs,
                "unit_membership_sha256": sha256(
                    _canonical_json_bytes(membership)
                ).hexdigest(),
            }
        )
    if boundaries.get("labels") != expected_boundary_rows:
        raise _component_error("forensics label boundaries differ")

    return {
        "schema_version": 1,
        "receipt_type": "r02_terminal_forensics",
        "payload_sha256": payload_sha256,
        "receipt": dict(evidence_receipt),
        "label_counts": {
            name: len(membership) for name, membership in label_memberships.items()
        },
        "ordered_labels": label_rows,
        "boundaries": boundaries,
        "counts": counts,
        "digests": digests,
    }


def _forensics_validate_canary_inventory(value: Any, *, label: str) -> dict[str, Any]:
    """Recompute the reviewed canary's complete inventory projections."""

    if not isinstance(value, dict) or set(value) != {
        "root",
        "root_entry",
        "entries",
        "strict_temporal_entries",
        "strict_temporal_sha256",
        "content_equivalence_entries",
        "content_equivalence_sha256",
        "content_files",
        "content_sha256",
        "file_count",
        "total_bytes",
        "tmp_entries",
    }:
        raise _component_error(f"{label} fields differ")
    root = value.get("root")
    entries = value.get("entries")
    if not isinstance(root, str) or not Path(root).is_absolute():
        raise _component_error(f"{label} root is invalid")
    if not isinstance(entries, list) or not entries:
        raise _component_error(f"{label} entries are invalid")
    paths: list[str] = []
    regular_files: list[dict[str, Any]] = []
    content_entries: list[dict[str, Any]] = []
    content_keys = ("path", "type", "mode", "target", "bytes", "sha256", "rdev")
    for entry in entries:
        if not isinstance(entry, dict):
            raise _component_error(f"{label} entry is not an object")
        path = entry.get("path")
        entry_type = entry.get("type")
        required = {
            "path",
            "type",
            "mode",
            "uid",
            "gid",
            "dev",
            "inode",
            "nlink",
            "mtime_ns",
            "ctime_ns",
        }
        if (
            not isinstance(path, str)
            or not path
            or entry_type not in {"directory", "regular"}
            or not required.issubset(entry)
            or not all(
                type(entry.get(name)) is int for name in required - {"path", "type"}
            )
        ):
            raise _component_error(f"{label} entry identity is invalid")
        if entry_type == "regular":
            if (
                set(entry) != required | {"bytes", "sha256"}
                or entry.get("bytes", -1) < 0
                or re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))) is None
            ):
                raise _component_error(f"{label} regular entry is invalid")
            regular_files.append(
                {"path": path, "bytes": entry["bytes"], "sha256": entry["sha256"]}
            )
        elif set(entry) != required:
            raise _component_error(f"{label} directory entry is invalid")
        paths.append(path)
        content_entries.append(
            {name: entry[name] for name in content_keys if name in entry}
        )
    expected_order = sorted(
        range(len(entries)),
        key=lambda index: (
            paths[index].encode("utf-8"),
            str(entries[index]["type"]).encode("utf-8"),
        ),
    )
    if (
        expected_order != list(range(len(entries)))
        or len(paths) != len(set(paths))
        or paths[0] != "."
        or value.get("root_entry") != entries[0]
        or value.get("strict_temporal_entries") != entries
        or value.get("strict_temporal_sha256")
        != sha256(_canonical_json_bytes(entries)).hexdigest()
        or value.get("content_equivalence_entries") != content_entries
        or value.get("content_equivalence_sha256")
        != sha256(_canonical_json_bytes(content_entries)).hexdigest()
        or value.get("content_files") != regular_files
        or value.get("content_sha256")
        != sha256(_canonical_json_bytes(regular_files)).hexdigest()
        or value.get("file_count") != len(regular_files)
        or value.get("total_bytes") != sum(int(item["bytes"]) for item in regular_files)
        or value.get("tmp_entries")
        != sorted(
            path
            for path in paths
            if path != "." and ".tmp" in PurePosixPath(path).name.lower()
        )
    ):
        raise _component_error(f"{label} projection or digest differs")
    return value


def _forensics_canary_inventory_diff(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    projection: str,
) -> dict[str, Any]:
    """Independently reproduce the reviewed canary's inventory diff."""

    left = {str(item["path"]): dict(item) for item in before[projection]}
    right = {str(item["path"]): dict(item) for item in after[projection]}
    return {
        "added": [right[path] for path in sorted(set(right) - set(left))],
        "deleted": [left[path] for path in sorted(set(left) - set(right))],
        "changed": [
            {"path": path, "before": left[path], "after": right[path]}
            for path in sorted(set(left) & set(right))
            if left[path] != right[path]
        ],
    }


def _forensics_validate_canary_owner_proof(
    value: Any,
    *,
    inventory: dict[str, Any],
    label: str,
) -> None:
    """Cross-check the reviewed canary's effective-owner summary."""

    if not isinstance(value, dict) or set(value) != {
        "expected_uid",
        "expected_gid",
        "root_uid",
        "root_gid",
        "checked_entry_count",
        "all_entries_owned_by_effective_uid_gid",
    }:
        raise _component_error(f"{label} fields differ")
    expected_uid = value.get("expected_uid")
    expected_gid = value.get("expected_gid")
    effective_uid = getattr(os, "geteuid", lambda: expected_uid)()
    effective_gid = getattr(os, "getegid", lambda: expected_gid)()
    if (
        type(expected_uid) is not int
        or type(expected_gid) is not int
        or expected_uid != effective_uid
        or expected_gid != effective_gid
        or value.get("root_uid") != inventory["root_entry"]["uid"]
        or value.get("root_gid") != inventory["root_entry"]["gid"]
        or value.get("checked_entry_count") != len(inventory["strict_temporal_entries"])
        or value.get("all_entries_owned_by_effective_uid_gid") is not True
        or any(
            item["uid"] != expected_uid or item["gid"] != expected_gid
            for item in inventory["strict_temporal_entries"]
        )
    ):
        raise _component_error(f"{label} differs from its inventory")


def _forensics_parse_pipe_rows(
    raw: bytes,
    *,
    fields: tuple[str, ...],
    label: str,
) -> list[dict[str, str]]:
    if raw and not raw.endswith(b"\n"):
        raise _component_error(f"{label} is not LF-terminated")
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise _component_error(f"{label} is not UTF-8") from exc
    rows: list[dict[str, str]] = []
    for line in lines:
        values = line.split("|")
        if len(values) == len(fields) + 1 and values[-1] == "":
            values.pop()
        if len(values) != len(fields):
            raise _component_error(f"{label} field count differs")
        rows.append(dict(zip(fields, values)))
    return rows


def _forensics_archive_time(raw: bytes, *, label: str) -> datetime:
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise _component_error(f"{label} is not ASCII") from exc
    if (
        re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\n", text)
        is None
    ):
        raise _component_error(f"{label} is not one UTC-second timestamp plus LF")
    try:
        observed = datetime.fromisoformat(text[:-1].replace("Z", "+00:00"))
    except ValueError as exc:
        raise _component_error(f"{label} is not an ISO timestamp") from exc
    return observed.astimezone(timezone.utc)


def _forensics_receipt_time(value: Any, *, label: str) -> datetime:
    text = str(value)
    if (
        re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
            text,
        )
        is None
    ):
        raise _component_error(f"{label} is not a timezone-aware UTC timestamp")
    try:
        observed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _component_error(f"{label} is not an ISO timestamp") from exc
    return observed.astimezone(timezone.utc)


def _forensics_slurm_memory_mib(value: Any, *, label: str) -> int:
    match = re.fullmatch(
        r"\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)\s*([nc]?)\s*",
        str(value),
        flags=re.IGNORECASE,
    )
    if match is None:
        raise _component_error(f"{label} is not a Slurm memory quantity")
    amount = float(match.group(1))
    multiplier = {
        "": 1,
        "K": 1 / 1024,
        "M": 1,
        "G": 1024,
        "T": 1024**2,
    }[match.group(2).upper()]
    return int(amount * multiplier)


def _validate_all_partition_canary_archive(
    *,
    amendment: dict[str, Any],
    binding: dict[str, Any],
    evidence_receipt: dict[str, Any],
    r02_scheduler_sacct_evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    """Validate the sealed 28-file launcher archive and return its anchors."""

    canary_contract = dict(amendment.get("all_partition_canary") or {})
    sealed = dict(canary_contract.get("sealed_archive_contract") or {})
    templates = sealed.get("manifest_member_templates_exactly")
    job_id = str(binding.get("job_id", ""))
    if (
        not job_id.isdigit()
        or not isinstance(templates, list)
        or tuple(templates) != _COMPONENT_CANARY_ARCHIVE_MEMBER_TEMPLATES
    ):
        raise _component_error("canary sealed-archive schema differs")

    archive_root = Path(str(binding.get("archive_root", "")))
    evidence_path = Path(str(evidence_receipt.get("path", "")))
    expected_parent = _COMPONENT_CANARY_ARCHIVE_PARENT.resolve(strict=True)
    _reject_symlink_components(archive_root, label="canary archive root")
    if (
        not archive_root.is_absolute()
        or archive_root.is_symlink()
        or not archive_root.is_dir()
        or archive_root.resolve(strict=True) != archive_root
        or archive_root.parent.resolve(strict=True) != expected_parent
        or re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*", archive_root.name) is None
        or evidence_path != archive_root / "evidence.sha256.sha256"
        or binding.get("evidence_path") != str(evidence_path)
    ):
        raise _component_error("canary sealed archive root/top anchor differs")
    root_stat = archive_root.stat(follow_symlinks=False)
    effective_uid = getattr(os, "geteuid", lambda: root_stat.st_uid)()
    if stat.S_IMODE(root_stat.st_mode) != 0o500 or root_stat.st_uid != effective_uid:
        raise _component_error("canary sealed archive root mode/owner differs")

    children = list(archive_root.iterdir())
    expected_names = {item.replace("<job_id>", job_id) for item in templates} | {
        "evidence.sha256",
        "evidence.sha256.sha256",
    }
    if len(children) != 28 or {path.name for path in children} != expected_names:
        raise _component_error("canary sealed archive member set differs")
    identities: set[tuple[int, int]] = set()
    members: dict[str, Path] = {}
    for path in children:
        metadata = path.lstat()
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or metadata.st_uid != root_stat.st_uid
            or identity in identities
        ):
            raise _component_error("canary sealed archive member identity differs")
        identities.add(identity)
        members[path.name] = path.resolve(strict=True)

    manifest_path = members["evidence.sha256"]
    manifest_receipt = _file_receipt(manifest_path)
    if (
        binding.get("archive_manifest_path") != str(manifest_path)
        or binding.get("archive_manifest_bytes") != manifest_receipt["bytes"]
        or binding.get("archive_manifest_sha256") != manifest_receipt["sha256"]
    ):
        raise _component_error("canary archive-manifest binding differs")
    manifest_raw = manifest_path.read_bytes()
    if not manifest_raw.endswith(b"\n") or len(manifest_raw.splitlines()) != 26:
        raise _component_error("canary archive manifest line count differs")
    try:
        manifest_lines = manifest_raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise _component_error("canary archive manifest is not UTF-8") from exc
    expected_member_paths = sorted(
        (
            (archive_root / name).resolve(strict=True)
            for name in expected_names - {"evidence.sha256", "evidence.sha256.sha256"}
        ),
        key=lambda item: os.fsencode(str(item)),
    )
    parsed_manifest: dict[str, str] = {}
    for line, expected_path in zip(manifest_lines, expected_member_paths):
        match = re.fullmatch(r"([0-9a-f]{64})  (/.+)", line)
        if match is None or match.group(2) != str(expected_path):
            raise _component_error("canary archive manifest syntax/order differs")
        if match.group(2) in parsed_manifest:
            raise _component_error("canary archive manifest repeats a path")
        parsed_manifest[match.group(2)] = match.group(1)
        if _file_receipt(expected_path)["sha256"] != match.group(1):
            raise _component_error("canary archive member digest differs")
    if len(parsed_manifest) != 26:
        raise _component_error("canary archive manifest coverage differs")

    sidecar_path = members["evidence.sha256.sha256"]
    sidecar_receipt = _file_receipt(sidecar_path)
    expected_sidecar = f"{manifest_receipt['sha256']}  {manifest_path}\n".encode(
        "utf-8"
    )
    if (
        sidecar_path.read_bytes() != expected_sidecar
        or binding.get("evidence_path") != str(sidecar_path)
        or binding.get("evidence_bytes") != sidecar_receipt["bytes"]
        or binding.get("evidence_sha256") != sidecar_receipt["sha256"]
        or evidence_receipt.get("path") != str(sidecar_path)
        or evidence_receipt.get("bytes") != sidecar_receipt["bytes"]
        or evidence_receipt.get("sha256") != sidecar_receipt["sha256"]
    ):
        raise _component_error("canary archive sidecar/top evidence differs")

    receipt_name = f"rap-eacl-paw-cache-canary-v4-{job_id}.json"
    canary_receipt_path = members[receipt_name]
    canary_receipt = _file_receipt(canary_receipt_path)
    canary_sidecar = members[f"{receipt_name}.sha256"]
    if (
        binding.get("canary_receipt_path") != str(canary_receipt_path)
        or binding.get("canary_receipt_bytes") != canary_receipt["bytes"]
        or binding.get("canary_receipt_sha256") != canary_receipt["sha256"]
        or canary_sidecar.read_bytes()
        != f"{canary_receipt['sha256']}  {receipt_name}\n".encode("utf-8")
    ):
        raise _component_error("canary semantic-receipt archive binding differs")

    for field, name in (
        ("launcher_exit_status", "launcher.exit-status.txt"),
        ("srun_exit_status", "srun.exit-status.txt"),
        ("postrun_sacct_exit_status", "postrun-sacct.exit-status.txt"),
    ):
        if binding.get(field) != 0 or members[name].read_bytes() != b"0\n":
            raise _component_error("canary archive retains a nonzero status")
    attempts = binding.get("postrun_sacct_attempts")
    if (
        type(attempts) is not int
        or not 1 <= attempts <= 12
        or members["postrun-sacct.attempts.txt"].read_bytes()
        != f"{attempts}\n".encode("ascii")
        or members["slurm-job-id.txt"].read_bytes() != f"{job_id}\n".encode("ascii")
        or members["required-terminal-r02-job-id.txt"].read_bytes() != b"1524523\n"
    ):
        raise _component_error("canary archive scheduler scalar differs")

    postrun_fields = (
        "job_id_raw",
        "job_name",
        "partition",
        "state",
        "exit_code",
        "elapsed_raw",
        "start",
        "end",
        "node_list",
        "alloc_cpus",
        "req_mem",
        "alloc_tres",
        "max_rss",
        "max_vm_size",
    )
    postrun_rows = _forensics_parse_pipe_rows(
        members["postrun-sacct.txt"].read_bytes(),
        fields=postrun_fields,
        label="canary postrun sacct",
    )
    top_rows = [row for row in postrun_rows if row["job_id_raw"] == job_id]
    if (
        len(top_rows) != 1
        or top_rows[0]["job_name"] != "rap-paw-cache-canary-v4"
        or top_rows[0]["partition"] != "ALL"
        or top_rows[0]["state"] != "COMPLETED"
        or top_rows[0]["exit_code"] != "0:0"
        or top_rows[0]["node_list"] != canary_contract.get("node_exact")
        or top_rows[0]["alloc_cpus"] != "8"
        or "gres/gpu" in top_rows[0]["alloc_tres"].lower()
        or members["postrun-sacct.stderr.log"].read_bytes() != b""
    ):
        raise _component_error("canary terminal sacct identity differs")
    postrun_row = top_rows[0]

    r02_fields = (
        "job_id_raw",
        "job_name",
        "partition",
        "state",
        "exit_code",
        "elapsed_raw",
        "start",
        "end",
        "node_list",
    )
    archived_r02_raw = members["r02-terminal-sacct.txt"].read_bytes()
    archived_r02_rows = _forensics_parse_pipe_rows(
        archived_r02_raw, fields=r02_fields, label="canary archived r02 sacct"
    )
    archived_r02_top = [
        row for row in archived_r02_rows if row["job_id_raw"] == "1524523"
    ]
    terminal_r02 = dict(
        (amendment.get("pending_terminal_bindings") or {}).get("r02") or {}
    )
    if (
        len(archived_r02_top) != 1
        or members["r02-terminal-sacct.stderr.log"].read_bytes() != b""
        or archived_r02_top[0]["partition"] != terminal_r02.get("slurm_partition")
        or archived_r02_top[0]["state"] != terminal_r02.get("slurm_terminal_state")
        or archived_r02_top[0]["exit_code"] != terminal_r02.get("slurm_exit_code")
        or archived_r02_top[0]["node_list"] != terminal_r02.get("slurm_node_list")
    ):
        raise _component_error("canary archive r02 terminal gate differs")
    if r02_scheduler_sacct_evidence is not None:
        external_path = Path(str(r02_scheduler_sacct_evidence.get("path", "")))
        _reject_symlink_components(external_path, label="canonical r02 sacct")
        if (
            not external_path.is_absolute()
            or external_path.is_symlink()
            or not external_path.is_file()
            or external_path.resolve(strict=True) != external_path
        ):
            raise _component_error("canonical r02 sacct evidence is unavailable")
        external = _file_receipt(external_path.resolve(strict=True))
        if external.get("bytes") != r02_scheduler_sacct_evidence.get(
            "bytes"
        ) or external.get("sha256") != r02_scheduler_sacct_evidence.get("sha256"):
            raise _component_error("canonical r02 sacct evidence changed")
        external_rows = _forensics_parse_pipe_rows(
            external_path.read_bytes(), fields=r02_fields, label="external r02 sacct"
        )
        external_top = [row for row in external_rows if row["job_id_raw"] == "1524523"]
        stable_r02_fields = (
            "job_id_raw",
            "job_name",
            "partition",
            "state",
            "exit_code",
            "node_list",
        )
        if len(external_top) != 1 or any(
            external_top[0][field] != archived_r02_top[0][field]
            for field in stable_r02_fields
        ):
            raise _component_error("canary and canonical r02 sacct rows differ")

    canary_script = dict(canary_contract.get("canary_script") or {})
    launcher_script = dict(canary_contract.get("launcher_script") or {})
    for name, declaration, member_name in (
        ("canary", canary_script, "canary-script.sha256"),
        ("launcher", launcher_script, "launcher-script.sha256"),
    ):
        live_path = Path(str(declaration.get("remote_path", "")))
        _reject_symlink_components(live_path, label=f"live {name} script")
        if (
            not live_path.is_absolute()
            or live_path.is_symlink()
            or not live_path.is_file()
            or live_path.resolve(strict=True) != live_path
        ):
            raise _component_error(f"live {name} script is unavailable")
        live = _file_receipt(live_path.resolve(strict=True))
        expected_line = f"{declaration.get('sha256')}  {live_path}\n".encode("utf-8")
        if (
            live["sha256"] != declaration.get("sha256")
            or members[member_name].read_bytes() != expected_line
        ):
            raise _component_error(f"canary archived {name} script identity differs")

    task_summary_raw = members[f"srun-task-{job_id}.stdout.log"].read_bytes()
    if not task_summary_raw.endswith(b"\n") or task_summary_raw.count(b"\n") != 1:
        raise _component_error("canary task stdout is not one LF-terminated JSON row")
    try:
        task_summary = _strict_json_object(
            task_summary_raw[:-1].decode("utf-8"),
            label="canary task stdout summary",
        )
    except UnicodeDecodeError as exc:
        raise _component_error("canary task stdout is not UTF-8") from exc
    if task_summary != {
        "status": "passed",
        "receipt": str(canary_receipt_path),
        "receipt_sha256": canary_receipt["sha256"],
        "sha256_sidecar": str(canary_sidecar),
    }:
        raise _component_error("canary task stdout semantic summary differs")

    launch_at = _forensics_archive_time(
        members["launch-started-at-utc.txt"].read_bytes(),
        label="canary archive launch time",
    )
    archive_at = _forensics_archive_time(
        members["archive-ended-at-utc.txt"].read_bytes(),
        label="canary archive end time",
    )
    if launch_at > archive_at:
        raise _component_error("canary archive outer chronology differs")
    return {
        "receipt_path": canary_receipt_path,
        "members": members,
        "launch_at": launch_at,
        "archive_at": archive_at,
        "postrun_sacct_row": postrun_row,
        "member_receipts": [
            {"basename": name, **_file_receipt(path)}
            for name, path in sorted(members.items())
        ],
    }


def _validate_all_partition_canary_receipt(
    *,
    amendment: dict[str, Any],
    binding: dict[str, Any],
    evidence_receipt: dict[str, Any],
    r02_scheduler_sacct_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute the canary's activation, worker, and mutation pass gates."""

    archive = _validate_all_partition_canary_archive(
        amendment=amendment,
        binding=binding,
        evidence_receipt=evidence_receipt,
        r02_scheduler_sacct_evidence=r02_scheduler_sacct_evidence,
    )
    path = archive["receipt_path"]
    _reject_symlink_components(path, label="ALL-partition canary evidence")
    if path.is_symlink() or not path.is_file():
        raise _component_error("ALL-partition canary evidence is unavailable")
    try:
        raw = path.read_bytes()
        receipt = _strict_json_object(
            raw.decode("utf-8"), label="ALL-partition canary evidence"
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("ALL-partition canary evidence is unreadable") from exc
    if raw != _canonical_json_bytes(receipt) + b"\n":
        raise _component_error("ALL-partition canary evidence is not canonical plus LF")
    canonical_evidence = receipt.get("canonical_evidence_sha256")
    without_internal_digest = dict(receipt)
    without_internal_digest.pop("canonical_evidence_sha256", None)
    if (
        receipt.get("schema_version") != 1
        or receipt.get("canary") != "rap-eacl-paw-cache-canary-v4"
        or receipt.get("status") != "passed"
        or canonical_evidence
        != sha256(_canonical_json_bytes(without_internal_digest)).hexdigest()
    ):
        raise _component_error("ALL-partition canary canonical receipt differs")
    canary_contract = dict(amendment.get("all_partition_canary") or {})
    members = archive["members"]
    job_id = str(binding.get("job_id"))
    stem = f"rap-eacl-paw-cache-canary-v4-{job_id}"
    log_member_names = {
        "setup_stdout": f"{stem}.setup.stdout.log",
        "setup_stderr": f"{stem}.setup.stderr.log",
        "inner_stdout": f"{stem}.inner.stdout.log",
        "inner_stderr": f"{stem}.inner.stderr.log",
        "network": f"{stem}.network.jsonl",
        "guard_activations": f"{stem}.guard-activations.jsonl",
    }
    log_anchors = receipt.get("log_anchors")
    if not isinstance(log_anchors, dict) or set(log_anchors) != set(log_member_names):
        raise _component_error("canary archived log-anchor set differs")
    for anchor_name, member_name in log_member_names.items():
        anchor = log_anchors.get(anchor_name)
        member_path = members[member_name]
        member_receipt = _file_receipt(member_path)
        if (
            not isinstance(anchor, dict)
            or set(anchor) != {"path", "resolved_path", "bytes", "mode", "sha256"}
            or anchor.get("path") != str(member_path)
            or anchor.get("resolved_path") != str(member_path)
            or anchor.get("bytes") != member_receipt["bytes"]
            or anchor.get("mode") != 0o444
            or anchor.get("sha256") != member_receipt["sha256"]
        ):
            raise _component_error(f"canary archived {anchor_name} anchor differs")

    receipt_directory = receipt.get("receipt_directory")
    if receipt_directory != {
        "path": str(path.parent),
        "owner_uid": path.parent.stat(follow_symlinks=False).st_uid,
        "mode": 0o700,
    }:
        raise _component_error("canary receipt-directory provenance differs")
    script_declaration = dict(canary_contract.get("canary_script") or {})
    live_script = Path(str(script_declaration.get("remote_path", "")))
    live_script_stat = live_script.stat(follow_symlinks=False)
    if receipt.get("script") != {
        "path": str(live_script),
        "resolved_path": str(live_script),
        "bytes": live_script_stat.st_size,
        "mode": stat.S_IMODE(live_script_stat.st_mode),
        "sha256": script_declaration.get("sha256"),
    }:
        raise _component_error("canary semantic receipt script anchor differs")

    chronology = (
        archive["launch_at"],
        _forensics_receipt_time(
            receipt.get("started_at_utc"), label="canary outer start"
        ),
        _forensics_receipt_time(
            (receipt.get("inner") or {}).get("started_at_utc"),
            label="canary inner start",
        ),
        _forensics_receipt_time(
            (receipt.get("inner") or {}).get("ended_at_utc"),
            label="canary inner end",
        ),
        _forensics_receipt_time(receipt.get("ended_at_utc"), label="canary outer end"),
        archive["archive_at"],
    )
    if any(left > right for left, right in zip(chronology, chronology[1:])):
        raise _component_error("canary semantic/archive chronology differs")

    scheduler = dict(receipt.get("scheduler") or {})
    scheduler_environment = dict(scheduler.get("environment") or {})
    inner = dict(receipt.get("inner") or {})
    inner_environment = dict(inner.get("environment") or {})
    worker = dict(inner.get("worker") or {})
    inner_pid = inner_environment.get("process_pid")
    worker_pid = worker.get("stable_pid_before_shutdown")
    selected_environment_fields = {
        "SLURM_JOB_ID",
        "SLURM_JOB_PARTITION",
        "SLURM_JOB_NODELIST",
        "SLURM_CPUS_PER_TASK",
        "SLURM_MEM_PER_NODE",
        "SLURM_MEM_PER_CPU",
        "SLURM_JOB_GPUS",
        "SLURM_STEP_GPUS",
        "SLURM_GPUS",
        "SLURM_GPUS_ON_NODE",
        "CUDA_VISIBLE_DEVICES",
        "PAW_GPU_LAYERS",
    }
    scontrol_raw = scheduler.get("scontrol_raw")
    selected_scontrol = scheduler.get("scontrol_selected")
    if (
        not isinstance(scontrol_raw, str)
        or not scontrol_raw
        or "\n" in scontrol_raw
        or scheduler.get("scontrol_raw_sha256")
        != sha256(scontrol_raw.encode("utf-8")).hexdigest()
        or not isinstance(selected_scontrol, dict)
        or set(selected_scontrol)
        != {
            "JobId",
            "JobState",
            "Partition",
            "NodeList",
            "NumCPUs",
            "MinMemoryNode",
            "AllocTRES",
            "TimeLimit",
        }
    ):
        raise _component_error("ALL-partition canary scontrol receipt differs")
    parsed_scontrol = {
        key: value
        for token in scontrol_raw.split()
        if "=" in token
        for key, value in [token.split("=", 1)]
    }
    postrun_sacct = archive["postrun_sacct_row"]
    stable_scontrol = {key: parsed_scontrol.get(key) for key in selected_scontrol}
    gpu_environment_values = {
        None,
        "",
        "0",
        "-1",
        "NoDevFiles",
        "none",
        "None",
    }
    affinity = scheduler.get("affinity")
    if (
        set(scheduler_environment) != selected_environment_fields
        or scheduler_environment.get("SLURM_JOB_ID") != binding.get("job_id")
        or scheduler_environment.get("SLURM_CPUS_PER_TASK") != "8"
        or scheduler_environment.get("PAW_GPU_LAYERS") != "0"
        or scheduler_environment.get("CUDA_VISIBLE_DEVICES")
        not in gpu_environment_values
        or any(
            scheduler_environment.get(name) not in gpu_environment_values
            for name in (
                "SLURM_JOB_GPUS",
                "SLURM_STEP_GPUS",
                "SLURM_GPUS",
                "SLURM_GPUS_ON_NODE",
            )
        )
        or not isinstance(affinity, list)
        or len(affinity) != 8
        or len(set(affinity)) != 8
        or not all(type(value) is int for value in affinity)
        or type(scheduler.get("memory_mib")) is not int
        or scheduler.get("memory_mib", 0) < 16 * 1024
        or selected_scontrol != stable_scontrol
        or selected_scontrol.get("JobId") != binding.get("job_id")
        or selected_scontrol.get("JobState") != "RUNNING"
        or selected_scontrol.get("Partition") != "ALL"
        or selected_scontrol.get("NodeList") != canary_contract.get("node_exact")
        or selected_scontrol.get("NumCPUs") != "8"
        or selected_scontrol.get("TimeLimit") != "00:30:00"
        or parsed_scontrol.get("JobName") != postrun_sacct.get("job_name")
        or _forensics_slurm_memory_mib(
            selected_scontrol.get("MinMemoryNode"), label="canary scontrol memory"
        )
        != _forensics_slurm_memory_mib(
            postrun_sacct.get("req_mem"), label="canary sacct memory"
        )
        or set(str(selected_scontrol.get("AllocTRES", "")).split(","))
        != set(str(postrun_sacct.get("alloc_tres", "")).split(","))
        or "gres/gpu" in str(selected_scontrol.get("AllocTRES", "")).lower()
    ):
        raise _component_error("ALL-partition canary scheduler resources differ")

    if (
        scheduler.get("job_id") != binding.get("job_id")
        or scheduler_environment.get("SLURM_JOB_PARTITION")
        != canary_contract.get("partition_exact")
        or scheduler_environment.get("SLURM_JOB_NODELIST")
        != canary_contract.get("node_exact")
        or not str(scheduler.get("hostname", "")).split(".", 1)[0]
        == canary_contract.get("node_exact")
        or inner.get("status") != "passed"
        or type(inner_pid) is not int
        or type(worker_pid) is not int
        or worker.get("stable_generation") != binding.get("worker_generation")
        or worker_pid != binding.get("worker_pid")
    ):
        raise _component_error("ALL-partition canary scheduler/worker identity differs")

    calls = inner.get("calls")
    declared_results = binding.get("program_results_in_exact_order")
    ordered_programs = canary_contract.get("ordered_programs_exact")
    if (
        not isinstance(calls, list)
        or not isinstance(declared_results, list)
        or not isinstance(ordered_programs, list)
        or len(calls) != 8
        or len(declared_results) != 8
        or len(ordered_programs) != 8
    ):
        raise _component_error("ALL-partition canary call ledger is incomplete")
    for sequence, (call, declared, expected) in enumerate(
        zip(calls, declared_results, ordered_programs)
    ):
        if (
            not isinstance(call, dict)
            or call.get("sequence") != sequence
            or call.get("program_id") != expected.get("program_id")
            or call.get("rule_id") != expected.get("rule_id")
            or call.get("case_id") != declared.get("case_id")
            or call.get("frozen_expected") != declared.get("expected")
            or call.get("input_utf8_bytes") != declared.get("input_utf8_bytes")
            or call.get("input_utf8_sha256") != declared.get("input_sha256")
            or call.get("raw_output_utf8_bytes")
            != declared.get("raw_output_utf8_bytes")
            or call.get("raw_output_utf8_sha256")
            != declared.get("raw_output_utf8_sha256")
            or call.get("normalized_output") != declared.get("severity")
            or call.get("timed_out") is not False
            or call.get("generation_before") != binding.get("worker_generation")
            or call.get("generation_after") != binding.get("worker_generation")
            or call.get("worker_pid") != worker_pid
            or call.get("worker_last_error") != ""
        ):
            raise _component_error("ALL-partition canary call differs from binding")

    activation_anchor = dict(log_anchors["guard_activations"])
    activation_path = members[log_member_names["guard_activations"]]
    _reject_symlink_components(activation_path, label="canary activation log")
    if activation_path.is_symlink() or not activation_path.is_file():
        raise _component_error("canary activation log is unavailable")
    activation_raw = activation_path.read_bytes()
    if (
        activation_anchor.get("bytes") != len(activation_raw)
        or activation_anchor.get("sha256") != sha256(activation_raw).hexdigest()
        or binding.get("network_guard_activation_log_bytes") != len(activation_raw)
        or binding.get("network_guard_activation_log_sha256")
        != sha256(activation_raw).hexdigest()
    ):
        raise _component_error("canary activation-log anchor differs")
    activations: list[dict[str, Any]] = []
    for sequence, line in enumerate(activation_raw.splitlines(keepends=True)):
        if not line.endswith(b"\n"):
            raise _component_error("canary activation log has a non-LF line")
        try:
            value = _strict_json_object(
                line[:-1].decode("utf-8"),
                label=f"canary activation {sequence}",
            )
        except UnicodeDecodeError as exc:
            raise _component_error("canary activation log is not UTF-8") from exc
        activations.append({"sequence": sequence, **value})
    marker = binding.get("network_guard_marker")
    if (
        marker != "rap-eacl-paw-cache-canary-v4-network-guard-v2"
        or len(activations) != binding.get("network_guard_activation_count")
        or not activations
    ):
        raise _component_error("canary activation count/marker differs")
    for activation in activations:
        identity_checks = activation.get("identity_checks")
        if (
            activation.get("guard_marker") != marker
            or activation.get("all_identity_checks_passed") is not True
            or not isinstance(identity_checks, dict)
            or not identity_checks
            or not all(value is True for value in identity_checks.values())
            or type(activation.get("pid")) is not int
            or type(activation.get("parent_pid")) is not int
            or not isinstance(activation.get("sys_executable"), str)
        ):
            raise _component_error("canary guard activation identity differs")
    wrapper_purposes = {
        "bootstrap-pip:wrapper",
        "install-pip:wrapper",
        "freeze-pip:wrapper",
    }
    wrappers = [
        item
        for item in activations
        if str(item.get("purpose", "")).endswith(":wrapper")
    ]
    if (
        len(wrappers) != 3
        or {item.get("purpose") for item in wrappers} != wrapper_purposes
        or any(
            sum(item.get("purpose") == purpose for item in wrappers) != 1
            for purpose in wrapper_purposes
        )
        or binding.get("guarded_pip_wrapper_activation_count") != 3
    ):
        raise _component_error("canary explicit pip-wrapper activations differ")
    inner_explicit = [
        item
        for item in activations
        if item.get("purpose") == "inner-runtime:inner" and item.get("pid") == inner_pid
    ]
    worker_imports = [
        item
        for item in activations
        if item.get("purpose") == "inner-runtime"
        and item.get("pid") == worker_pid
        and item.get("parent_pid") == inner_pid
    ]
    embedded = inner.get("network_guard_activation")
    if (
        len(inner_explicit) != 1
        or not worker_imports
        or embedded
        != {key: value for key, value in inner_explicit[0].items() if key != "sequence"}
        or binding.get("guarded_pip_wrapper_identities_passed") is not True
        or binding.get("inner_guard_identity_passed") is not True
        or binding.get("spawned_worker_guard_identity_passed") is not True
    ):
        raise _component_error("canary inner/spawned-worker activation differs")
    proof = dict((receipt.get("network") or {}).get("guard_activation_proof") or {})
    if (
        proof.get("guard_marker") != marker
        or proof.get("activation_count") != len(activations)
        or proof.get("all_identity_checks_passed") is not True
        or proof.get("all_activations") != activations
        or proof.get("inner_explicit_activation") != inner_explicit[0]
        or proof.get("spawned_inference_worker_activations") != worker_imports
    ):
        raise _component_error("canary embedded activation proof differs")

    cache_before = _forensics_validate_canary_inventory(
        inner.get("cache_before"), label="canary copied-cache before inventory"
    )
    cache_after = _forensics_validate_canary_inventory(
        inner.get("cache_after"), label="canary copied-cache after inventory"
    )
    cache_proof = dict(inner.get("cache_postrun_proof") or {})
    if set(cache_proof) != {
        "content_equivalence_diff",
        "content_equivalence_unchanged",
        "strict_temporal_diff",
        "strict_temporal_unchanged",
        "permitted_runtime_manifest_metadata_rewrite",
        "permitted_rewrite_observed",
        "permitted_changed_fields",
    }:
        raise _component_error("canary copied-cache proof fields differ")
    content_diff = _forensics_canary_inventory_diff(
        cache_before,
        cache_after,
        projection="content_equivalence_entries",
    )
    temporal_diff = _forensics_canary_inventory_diff(
        cache_before,
        cache_after,
        projection="strict_temporal_entries",
    )
    if (
        cache_proof.get("content_equivalence_diff") != content_diff
        or cache_proof.get("strict_temporal_diff") != temporal_diff
    ):
        raise _component_error("canary copied-cache diff is not independently derived")
    source_cache = dict(receipt.get("source_cache") or {})
    if set(source_cache) != {"before", "before_owner", "after", "postrun_proof"}:
        raise _component_error("canary source-cache fields differ")
    source_before = _forensics_validate_canary_inventory(
        source_cache.get("before"), label="canary source before inventory"
    )
    source_after = _forensics_validate_canary_inventory(
        source_cache.get("after"), label="canary source after inventory"
    )
    preregistered = dict(receipt.get("preregistered_contract") or {})
    node_local = dict(receipt.get("node_local") or {})
    independence = dict(receipt.get("copy_independence") or {})
    if set(independence) != {
        "same_content",
        "content_equivalence_diff",
        "content_equivalence_sha256",
        "source_aliases",
        "destination_files_with_multiple_links",
        "all_destination_regular_file_link_counts_equal_one",
        "destination_owner",
    }:
        raise _component_error("canary copy-independence fields differ")
    _forensics_validate_canary_owner_proof(
        source_cache.get("before_owner"),
        inventory=source_before,
        label="canary source before owner proof",
    )
    _forensics_validate_canary_owner_proof(
        independence.get("destination_owner"),
        inventory=cache_before,
        label="canary copied-cache owner proof",
    )
    copy_durability = receipt.get("copy_durability")
    if copy_durability != {
        "regular_file_count": sum(
            item.get("type") == "regular" for item in cache_before["entries"]
        ),
        "directory_count": sum(
            item.get("type") == "directory" for item in cache_before["entries"]
        ),
        "files_fsynced_after_final_copystat": True,
        "directories_fsynced_bottom_up": True,
        "parent_directory_fsynced": True,
    }:
        raise _component_error("canary copy-durability proof differs")
    empty_diff = {"added": [], "deleted": [], "changed": []}
    source_regular = {
        str(item["path"]): item
        for item in source_before["entries"]
        if item.get("type") == "regular"
    }
    copy_regular = {
        str(item["path"]): item
        for item in cache_before["entries"]
        if item.get("type") == "regular"
    }
    inode_separated = bool(
        set(source_regular) == set(copy_regular)
        and all(
            (
                source_regular[path]["dev"],
                source_regular[path]["inode"],
            )
            != (copy_regular[path]["dev"], copy_regular[path]["inode"])
            and copy_regular[path]["nlink"] == 1
            for path in source_regular
        )
    )
    source_proof = dict(source_cache.get("postrun_proof") or {})
    if set(source_proof) != {
        "strict_temporal_diff",
        "strict_temporal_sha256_before",
        "strict_temporal_sha256_after",
        "content_equivalence_diff",
        "unchanged_exactly_excluding_atime",
        "zero_tmp_entries",
        "after_owner",
    }:
        raise _component_error("canary source postrun-proof fields differ")
    source_temporal_diff = _forensics_canary_inventory_diff(
        source_before,
        source_after,
        projection="strict_temporal_entries",
    )
    source_content_diff = _forensics_canary_inventory_diff(
        source_before,
        source_after,
        projection="content_equivalence_entries",
    )
    _forensics_validate_canary_owner_proof(
        source_proof.get("after_owner"),
        inventory=source_after,
        label="canary source after owner proof",
    )
    if (
        preregistered.get("source_cache_root")
        != canary_contract.get("source_cache_root_exact")
        or source_before.get("root") != canary_contract.get("source_cache_root_exact")
        or source_after.get("root") != canary_contract.get("source_cache_root_exact")
        or cache_before.get("root") != node_local.get("copied_cache")
        or cache_after.get("root") != node_local.get("copied_cache")
        or source_before["content_equivalence_entries"]
        != cache_before["content_equivalence_entries"]
        or source_before["content_equivalence_sha256"]
        != cache_before["content_equivalence_sha256"]
        or independence.get("same_content") is not True
        or independence.get("content_equivalence_diff") != empty_diff
        or independence.get("content_equivalence_sha256")
        != cache_before["content_equivalence_sha256"]
        or independence.get("source_aliases") != []
        or independence.get("destination_files_with_multiple_links") != []
        or independence.get("all_destination_regular_file_link_counts_equal_one")
        is not True
        or not inode_separated
        or source_before["strict_temporal_entries"]
        != source_after["strict_temporal_entries"]
        or source_before["strict_temporal_sha256"]
        != source_after["strict_temporal_sha256"]
        or source_temporal_diff != empty_diff
        or source_proof.get("strict_temporal_diff") != source_temporal_diff
        or source_proof.get("strict_temporal_sha256_before")
        != source_before["strict_temporal_sha256"]
        or source_proof.get("strict_temporal_sha256_after")
        != source_after["strict_temporal_sha256"]
        or source_content_diff != empty_diff
        or source_proof.get("content_equivalence_diff") != source_content_diff
        or source_proof.get("unchanged_exactly_excluding_atime") is not True
        or source_proof.get("zero_tmp_entries") is not True
    ):
        raise _component_error("canary initial source/copy equivalence differs")
    if (
        content_diff.get("added") != []
        or content_diff.get("deleted") != []
        or content_diff.get("changed") != []
        or cache_before["content_equivalence_entries"]
        != cache_after["content_equivalence_entries"]
        or cache_before["content_equivalence_sha256"]
        != cache_after["content_equivalence_sha256"]
        or temporal_diff.get("added") != []
        or temporal_diff.get("deleted") != []
        or cache_proof.get("content_equivalence_unchanged") is not True
        or cache_proof.get("strict_temporal_unchanged")
        is not (temporal_diff == empty_diff)
        or cache_proof.get("permitted_changed_fields") != ["ctime_ns", "mtime_ns"]
        or binding.get("copy_added_file_count") != 0
        or binding.get("copy_removed_file_count") != 0
        or binding.get("copy_changed_file_count") != 0
        or binding.get("copy_tmp_file_count") != 0
        or cache_before.get("tmp_entries") != []
        or cache_after.get("tmp_entries") != []
        or binding.get("copy_inventory_before_sha256")
        != cache_before.get("strict_temporal_sha256")
        or binding.get("copy_inventory_after_sha256")
        != cache_after.get("strict_temporal_sha256")
        or binding.get("source_inventory_before_sha256")
        != source_before.get("strict_temporal_sha256")
        or binding.get("source_inventory_after_sha256")
        != source_after.get("strict_temporal_sha256")
        or binding.get("node_local_cache_root") != node_local.get("copied_cache")
    ):
        raise _component_error("canary copy/source mutation proof differs")
    temporal_changes = temporal_diff.get("changed")
    permitted = cache_proof.get("permitted_runtime_manifest_metadata_rewrite")
    if not isinstance(temporal_changes, list):
        raise _component_error("canary temporal metadata diff is invalid")
    if temporal_changes:
        changed = temporal_changes[0] if len(temporal_changes) == 1 else {}
        before_entry = dict(changed.get("before") or {})
        after_entry = dict(changed.get("after") or {})
        changed_fields = sorted(
            field
            for field in set(before_entry) | set(after_entry)
            if before_entry.get(field) != after_entry.get(field)
        )
        expected_permitted = {
            "path": "runtimes/qwen3-0.6b-q6_k.json",
            "changed_fields": changed_fields,
            "before": before_entry,
            "after": after_entry,
            "content_bytes_and_sha256_unchanged": True,
        }
        if (
            len(temporal_changes) != 1
            or set(changed) != {"path", "before", "after"}
            or changed.get("path") != "runtimes/qwen3-0.6b-q6_k.json"
            or not isinstance(permitted, dict)
            or not changed_fields
            or not set(changed_fields).issubset({"mtime_ns", "ctime_ns"})
            or permitted != expected_permitted
            or cache_proof.get("permitted_rewrite_observed") is not True
        ):
            raise _component_error("canary metadata drift exceeds the exact exception")
    elif (
        permitted is not None
        or cache_proof.get("permitted_rewrite_observed") is not False
    ):
        raise _component_error("canary declares a metadata rewrite without a diff")
    return archive


def _validate_component_protocol_correction(
    *,
    receipt: dict[str, Any],
    predecessor_root: Path,
    predecessor_result: dict[str, Any],
    validated_artifacts: dict[str, dict[str, Any] | None],
    validated_tree: list[dict[str, Any]],
    validated_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """Revalidate amendment-008 without reclassifying any raw r02 value."""

    amendment = _load_component_amendment()
    replacement = dict(amendment.get("replacement_and_evidence_contract") or {})
    if (
        receipt.get("classification") != _COMPONENT_CLASSIFICATION
        or receipt.get("affected_boundary") != replacement.get("affected_boundary")
        or receipt.get("original_status") != replacement.get("original_status")
    ):
        raise _component_error("replacement fields differ from the frozen override")

    terminal = dict((amendment.get("pending_terminal_bindings") or {}).get("r02") or {})
    artifact_fields = {
        "launch.json": ("launch_json_bytes", "launch_json_sha256"),
        "plan.json": ("plan_json_bytes", "plan_json_sha256"),
        "publication.json": (
            "publication_json_bytes",
            "publication_json_sha256",
        ),
        "result.json": ("result_json_bytes", "result_json_sha256"),
        "units.jsonl": ("units_jsonl_bytes", "units_jsonl_sha256"),
    }
    for name, (byte_field, digest_field) in artifact_fields.items():
        observed = validated_artifacts.get(name)
        if (
            observed is None
            or observed.get("bytes") != terminal.get(byte_field)
            or observed.get("sha256") != terminal.get(digest_field)
        ):
            raise _component_error(
                f"r02 {name} differs from its frozen terminal anchor"
            )

    launch = _read_outcome_aware_json(
        predecessor_root / "launch.json", label="r02 launch"
    )
    identity = launch.get("identity")
    if (
        not isinstance(identity, dict)
        or launch.get("identity_sha256") != terminal.get("launch_identity_sha256")
        or sha256(_canonical_json_bytes(identity)).hexdigest()
        != terminal.get("launch_identity_sha256")
        or identity.get("attempt_id") != _COMPONENT_PREDECESSOR_ID
        or (identity.get("git") or {}).get("commit")
        != (amendment.get("known_at_draft") or {}).get("h3", {}).get("commit")
    ):
        raise _component_error("r02 launch identity differs from the frozen H3 anchor")

    plan = _forensics_strict_json_file(
        predecessor_root / "plan.json",
        label="r02 plan",
        cache={},
    )
    if not isinstance(plan, list) or not all(isinstance(item, dict) for item in plan):
        raise _component_error("r02 plan is not a list of unit objects")
    component_plans = _component_plans(plan)
    expected_hashes = {
        "full_plan_sha256": _COMPONENT_FULL_PLAN_SHA256,
        "carry_plan_sha256": _COMPONENT_CARRY_PLAN_SHA256,
        "repair_plan_sha256": _COMPONENT_REPAIR_PLAN_SHA256,
        "mapping_sha256": _COMPONENT_MAPPING_SHA256,
    }
    if (
        len(plan) != 430
        or len(component_plans["carry_plan"]) != 80
        or len(component_plans["repair_plan"]) != 350
        or any(
            component_plans[name] != value for name, value in expected_hashes.items()
        )
    ):
        raise _component_error("r02 static plan partition or mapping differs")

    if (
        predecessor_result.get("raw_attempt_id") != _COMPONENT_PREDECESSOR_ID
        or predecessor_result.get("status") != terminal.get("raw_status")
        or predecessor_result.get("planned_unit_count") != 430
        or predecessor_result.get("terminal_unit_count") != 430
        or predecessor_result.get("complete_plan") is not True
        or predecessor_result.get("all_planned_units_terminal") is not True
    ):
        raise _component_error("r02 raw terminal status/accounting differs")

    regular_tree = [
        item for item in validated_tree if item.get("type") == "regular_file"
    ]
    tree_sha256 = sha256(_canonical_json_bytes(validated_tree)).hexdigest()
    if (
        len(validated_tree) != terminal.get("complete_tree_entry_count")
        or len(regular_tree) != terminal.get("complete_tree_regular_file_count")
        or sum(int(item["bytes"]) for item in regular_tree)
        != terminal.get("complete_tree_regular_file_bytes")
        or tree_sha256 != terminal.get("complete_tree_sha256")
    ):
        raise _component_error("r02 complete-tree terminal binding differs")

    claim_path = _publication_claim_path(predecessor_root)
    _reject_symlink_components(claim_path, label="r02 publication claim")
    if claim_path.is_symlink() or not claim_path.is_file():
        raise _component_error("r02 publication claim is unavailable")
    claim = _file_receipt(claim_path.resolve(strict=True))
    launch_stat = (predecessor_root / "launch.json").stat(follow_symlinks=False)
    claim_stat = claim_path.stat(follow_symlinks=False)
    if (
        claim["bytes"] != terminal.get("publication_claim_bytes")
        or claim["sha256"] != terminal.get("publication_claim_sha256")
        or claim_stat.st_dev != launch_stat.st_dev
        or claim_stat.st_ino != launch_stat.st_ino
    ):
        raise _component_error("r02 publication claim differs from its frozen anchor")

    slurm = dict((launch.get("identity") or {}).get("slurm") or {})
    if (
        slurm.get("job_id") != terminal.get("slurm_job_id")
        or slurm.get("partition") != terminal.get("slurm_partition")
        or slurm.get("node_list") != terminal.get("slurm_node_list")
    ):
        raise _component_error("r02 Slurm launch identity differs")
    unit_index = predecessor_result.get("unit_index")
    if not isinstance(unit_index, list) or len(unit_index) != 430:
        raise _component_error("r02 unit_index is incomplete")
    carry_keys = {
        (str(item["component"]), str(item["unit_id"]))
        for item in component_plans["carry_plan"]
    }
    seen: set[tuple[str, str]] = set()
    for position, (planned, indexed) in enumerate(zip(plan, unit_index)):
        if not isinstance(indexed, dict) or indexed.get("plan") != planned:
            raise _component_error("r02 unit_index plan/order differs")
        key = (str(planned.get("component", "")), str(planned.get("unit_id", "")))
        terminal_record = indexed.get("terminal_record")
        if (
            key in seen
            or indexed.get("started") is not True
            or not isinstance(terminal_record, str)
            or re.fullmatch(
                r"[0-9a-f]{64}", str(indexed.get("terminal_record_sha256", ""))
            )
            is None
        ):
            raise _component_error(f"r02 unit {position} is not uniquely terminal")
        seen.add(key)
        relative = Path(terminal_record)
        if relative.is_absolute() or ".." in relative.parts:
            raise _component_error("r02 terminal record escapes the immutable tree")
        path = predecessor_root / relative
        if path.is_symlink() or not path.is_file():
            raise _component_error("r02 terminal record is missing or a symlink")
        if sha256(path.read_bytes()).hexdigest() != indexed["terminal_record_sha256"]:
            raise _component_error("r02 terminal record digest changed")
        terminal_value = _read_outcome_aware_json(path, label="r02 terminal record")
        if terminal_value.get("status") != indexed.get("status"):
            raise _component_error("r02 terminal record status changed")
        if key in carry_keys and indexed.get("status") not in {
            "completed",
            "system_violation",
        }:
            raise _component_error(
                "a carried deterministic r02 row is incomplete or invalid"
            )

    expected_evidence = dict(
        (amendment.get("pending_terminal_bindings") or {}).get("evidence_receipts")
        or {}
    )
    observed_by_kind = Counter(str(item.get("kind", "")) for item in validated_evidence)
    if (
        set(observed_by_kind) != _COMPONENT_REQUIRED_EVIDENCE
        or any(observed_by_kind[kind] != 1 for kind in _COMPONENT_REQUIRED_EVIDENCE)
        or set(expected_evidence) != _COMPONENT_REQUIRED_EVIDENCE
    ):
        raise _component_error("component evidence kinds are not exact-once")
    predecessor_resolved = predecessor_root.resolve(strict=True)
    for item in validated_evidence:
        kind = str(item["kind"])
        if item != expected_evidence[kind]:
            raise _component_error(f"{kind} differs from its frozen evidence receipt")
        evidence_path = Path(str(item["path"])).resolve(strict=True)
        if (
            evidence_path == predecessor_resolved
            or predecessor_resolved in evidence_path.parents
        ):
            raise _component_error("component evidence may not be stored inside r02")

    evidence_by_kind = {str(item["kind"]): item for item in validated_evidence}
    terminal_forensics = _validate_r02_terminal_forensics(
        amendment=amendment,
        evidence_receipt=evidence_by_kind["component_selection"],
        predecessor_root=predecessor_root,
        predecessor_result=predecessor_result,
        plan=plan,
        validated_tree=validated_tree,
        scheduler_sacct_evidence=evidence_by_kind["scheduler_sacct"],
    )
    sacct_path = Path(str(evidence_by_kind["scheduler_sacct"]["path"]))
    try:
        sacct_lines = [
            line
            for line in sacct_path.read_text(
                encoding="utf-8", errors="strict"
            ).splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError) as exc:
        raise _component_error("r02 sacct evidence is not readable UTF-8") from exc
    top_level_sacct_lines = [
        line
        for line in sacct_lines
        if line.split("|", 1)[0] == str(terminal.get("slurm_job_id"))
    ]
    if len(top_level_sacct_lines) != 1:
        raise _component_error(
            "r02 sacct evidence must contain exactly one top-level job row"
        )
    sacct_tokens = top_level_sacct_lines[0].split("|")
    required_sacct_tokens = {
        str(terminal.get("slurm_job_id")),
        str(terminal.get("slurm_partition")),
        str(terminal.get("slurm_node_list")),
        str(terminal.get("slurm_terminal_state")),
        str(terminal.get("slurm_exit_code")),
    }
    exit_code = str(terminal.get("slurm_exit_code", ""))
    if (
        not required_sacct_tokens.issubset(sacct_tokens)
        or re.fullmatch(r"[0-9]+:[0-9]+", exit_code) is None
        or terminal.get("process_exit_code") != int(exit_code.split(":", 1)[0])
    ):
        raise _component_error("r02 sacct/process terminal binding differs")

    canary = dict(
        (amendment.get("pending_terminal_bindings") or {}).get("all_partition_canary")
        or {}
    )
    program_results = list(canary.get("program_results_in_exact_order") or [])
    canary_contract = dict(amendment.get("all_partition_canary") or {})
    frozen_inputs = dict(canary_contract.get("frozen_input_source") or {})
    ordered_programs = list(canary_contract.get("ordered_programs_exact") or [])
    valid_severities = set(canary_contract.get("valid_severities_exact") or [])
    generations = {item.get("worker_generation") for item in program_results}
    pids = {item.get("worker_pid") for item in program_results}
    ordered_input_hashes = [item.get("input_sha256") for item in program_results]
    ordered_input_hashes_sha256 = sha256(
        _canonical_json_bytes(ordered_input_hashes)
    ).hexdigest()
    aggregate_generation = canary.get("worker_generation")
    aggregate_pid = canary.get("worker_pid")
    canary_evidence = evidence_by_kind["all_partition_paw_cache_canary"]
    if (
        canary.get("status") != "passed"
        or valid_severities != {"OK", "INFO", "WARNING", "CRITICAL"}
        or not str(canary.get("job_id", "")).isdigit()
        or canary.get("partition") != canary_contract.get("partition_exact")
        or canary.get("node_list") != canary_contract.get("node_exact")
        or canary.get("frozen_input_manifest_sha256")
        != frozen_inputs.get("manifest_sha256")
        or canary.get("frozen_input_output_sha256")
        != frozen_inputs.get("output_sha256")
        or canary.get("input_selection_rule")
        != "first expected=WARNING row per rule in canonical formal rule order"
        or canary.get("ordered_input_hashes_sha256")
        != frozen_inputs.get("ordered_input_hashes_sha256")
        or ordered_input_hashes_sha256
        != frozen_inputs.get("ordered_input_hashes_sha256")
        or not isinstance(canary.get("node_local_cache_root"), str)
        or not Path(canary["node_local_cache_root"]).is_absolute()
        or canary.get("node_local_cache_root")
        == canary_contract.get("source_cache_root_exact")
        or canary.get("source_inventory_before_sha256")
        != canary.get("source_inventory_after_sha256")
        or any(
            canary.get(name) != 0
            for name in (
                "copy_added_file_count",
                "copy_removed_file_count",
                "copy_changed_file_count",
                "copy_tmp_file_count",
            )
        )
        or canary.get("network_guard_marker")
        != "rap-eacl-paw-cache-canary-v4-network-guard-v2"
        or type(canary.get("network_guard_activation_count")) is not int
        or canary.get("network_guard_activation_count", 0) < 1
        or canary.get("guarded_pip_wrapper_activation_count") != 3
        or canary.get("guarded_pip_wrapper_identities_passed") is not True
        or canary.get("inner_guard_identity_passed") is not True
        or canary.get("spawned_worker_guard_identity_passed") is not True
        or canary.get("timed_out_count") != 0
        or canary.get("valid_severity_count") != 8
        or len(program_results) != 8
        or len(ordered_programs) != 8
        or any(
            item.get("rule_id") != expected.get("rule_id")
            or item.get("program_id") != expected.get("program_id")
            or item.get("expected") != "WARNING"
            or type(item.get("source_line")) is not int
            or item.get("source_line", 0) < 1
            or type(item.get("input_utf8_bytes")) is not int
            or item.get("input_utf8_bytes", 0) < 1
            or re.fullmatch(r"[0-9a-f]{64}", str(item.get("input_sha256", ""))) is None
            or type(item.get("raw_output_utf8_bytes")) is not int
            or item.get("raw_output_utf8_bytes", -1) < 0
            or re.fullmatch(
                r"[0-9a-f]{64}", str(item.get("raw_output_utf8_sha256", ""))
            )
            is None
            or item.get("severity") not in valid_severities
            or item.get("timed_out") is not False
            or item.get("worker_generation") != aggregate_generation
            or item.get("worker_pid") != aggregate_pid
            for item, expected in zip(program_results, ordered_programs)
        )
        or len(generations) != 1
        or generations != {aggregate_generation}
        or type(aggregate_generation) is not int
        or aggregate_generation < 1
        or len(pids) != 1
        or pids != {aggregate_pid}
        or type(aggregate_pid) is not int
        or aggregate_pid < 1
        or canary.get("evidence_path") != canary_evidence.get("path")
        or canary.get("evidence_bytes") != canary_evidence.get("bytes")
        or canary.get("evidence_sha256") != canary_evidence.get("sha256")
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(canary.get(name, ""))) is None
            for name in (
                "source_inventory_before_sha256",
                "source_inventory_after_sha256",
                "copy_inventory_before_sha256",
                "copy_inventory_after_sha256",
                "network_guard_activation_log_sha256",
            )
        )
        or type(canary.get("network_guard_activation_log_bytes")) is not int
        or canary.get("network_guard_activation_log_bytes", -1) < 1
    ):
        raise _component_error("ALL-partition canary binding is not a valid pass")
    canary_archive = _validate_all_partition_canary_receipt(
        amendment=amendment,
        binding=canary,
        evidence_receipt=canary_evidence,
        r02_scheduler_sacct_evidence=evidence_by_kind["scheduler_sacct"],
    )

    try:
        frozen_at = datetime.fromisoformat(
            str(amendment.get("frozen_utc", "")).replace("Z", "+00:00")
        )
        created_at = datetime.fromisoformat(
            str(receipt.get("created_utc", "")).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise _component_error("freeze/replacement chronology is invalid") from exc
    if created_at.tzinfo is None or frozen_at.tzinfo is None or created_at < frozen_at:
        raise _component_error("component replacement predates amendment freeze")

    correction = component_protocol_correction_binding(amendment)
    historical = correction["historical_validation"]
    historical_path = Path(str(historical["receipt_path"]))
    _reject_symlink_components(historical_path, label="historical validation")
    if historical_path.is_symlink() or not historical_path.is_file():
        raise _component_error("historical-validation receipt is unavailable")
    observed_history = _file_receipt(historical_path.resolve(strict=True))
    if (
        observed_history["bytes"] != historical["receipt_bytes"]
        or observed_history["sha256"] != historical["receipt_sha256"]
        or predecessor_resolved == historical_path.resolve(strict=True)
        or predecessor_resolved in historical_path.resolve(strict=True).parents
    ):
        raise _component_error("historical-validation receipt differs or is inside r02")

    if receipt.get("component_protocol_correction") != correction:
        raise _component_error(
            "component correction binding differs from amendment 008"
        )
    if receipt.get("successor_source") != component_successor_source_binding(amendment):
        raise _component_error("external P4/I4/H4 source binding differs")
    terminal_forensics["validated_canary_archive_files"] = canary_archive[
        "member_receipts"
    ]
    return terminal_forensics


def _validate_whole_attempt_protocol_correction(
    *,
    receipt: dict[str, Any],
    predecessor_root: Path,
    validated_artifacts: dict[str, dict[str, Any] | None],
    validated_tree: list[dict[str, Any]],
    validated_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate the exact r02 partial boundary and full-r03 sole-source contract."""

    amendment = _load_component_amendment()
    replacement = dict(amendment.get("replacement_and_evidence_contract") or {})
    if (
        receipt.get("classification") != _COMPONENT_CLASSIFICATION
        or receipt.get("affected_boundary") != replacement.get("affected_boundary")
        or receipt.get("original_status") != "missing"
        or receipt.get("scheduler_adjudication") is not None
        or validated_artifacts.get("result.json") is not None
        or (predecessor_root / "result.json").exists()
    ):
        raise _component_error("whole-attempt replacement edge fields differ")

    terminal = dict((amendment.get("pending_terminal_bindings") or {}).get("r02") or {})
    artifact_fields = {
        "launch.json": ("launch_json_bytes", "launch_json_sha256"),
        "plan.json": ("plan_json_bytes", "plan_json_sha256"),
        "publication.json": ("publication_json_bytes", "publication_json_sha256"),
        "units.jsonl": ("units_jsonl_bytes", "units_jsonl_sha256"),
        "streams.json": ("streams_json_bytes", "streams_json_sha256"),
        "stdout.log": ("stdout_log_bytes", "stdout_log_sha256"),
        "stderr.log": ("stderr_log_bytes", "stderr_log_sha256"),
    }
    for name, (bytes_field, digest_field) in artifact_fields.items():
        observed = validated_artifacts.get(name)
        if (
            observed is None
            or observed.get("bytes") != terminal.get(bytes_field)
            or observed.get("sha256") != terminal.get(digest_field)
        ):
            raise _component_error(f"r02 {name} differs from its terminal anchor")

    plan_path = predecessor_root / "plan.json"
    plan_raw = plan_path.read_bytes()
    plan = _forensics_strict_json_file(plan_path, label="r02 plan", cache={})
    if not isinstance(plan, list) or not all(isinstance(item, dict) for item in plan):
        raise _component_error("r02 plan is not a strict unit array")
    whole = _whole_attempt_plan(plan)
    if (
        len(plan) != 430
        or len(plan_raw) != 122245
        or sha256(plan_raw).hexdigest() != _COMPONENT_FULL_PLAN_STORED_SHA256
        or whole["canonical_sha256"] != _COMPONENT_FULL_PLAN_SHA256
        or whole["ordered_membership_sha256"] != _COMPONENT_FULL_PLAN_MEMBERSHIP_SHA256
    ):
        raise _component_error("r02 full-plan identity differs")

    units_path = predecessor_root / "units.jsonl"
    raw_lines = units_path.read_bytes().splitlines(keepends=True)
    if len(raw_lines) != 279 or any(not line.endswith(b"\n") for line in raw_lines):
        raise _component_error("r02 units ledger is not the exact 279-line prefix")
    status_histogram: Counter[str] = Counter()
    for index, raw in enumerate(raw_lines):
        try:
            row = _strict_json_object(raw.decode("utf-8"), label="r02 units row")
        except UnicodeDecodeError as exc:
            raise _component_error("r02 units ledger is not UTF-8") from exc
        planned = plan[index]
        component = str(planned.get("component", ""))
        unit_id = str(planned.get("unit_id", ""))
        expected_relative = f"{component}/{unit_id}.terminal.json"
        if (
            row.get("component") != component
            or row.get("record_id") != unit_id
            or row.get("phase") != "terminal"
            or row.get("terminal_record") != expected_relative
        ):
            raise _component_error("r02 terminal ledger differs from plan prefix")
        terminal_path = predecessor_root / expected_relative
        if terminal_path.is_symlink() or not terminal_path.is_file():
            raise _component_error("r02 terminal receipt is missing")
        if sha256(terminal_path.read_bytes()).hexdigest() != row.get(
            "terminal_record_sha256"
        ):
            raise _component_error("r02 terminal receipt hash differs")
        status_histogram[str(row.get("status", ""))] += 1
    if status_histogram != Counter({"system_violation": 268, "completed": 11}):
        raise _component_error("r02 terminal status histogram differs")

    tree_paths = {str(item.get("relative_path", "")) for item in validated_tree}
    expected_started = {
        f"{item['component']}/{item['unit_id']}.started.json" for item in plan[:280]
    }
    observed_started = {
        path
        for path in tree_paths
        if path.count("/") == 1 and path.endswith(".started.json")
    }
    if observed_started != expected_started:
        raise _component_error("r02 started receipts are not the exact 280-row prefix")
    if any(
        f"{item['component']}/{item['unit_id']}.terminal.json" in tree_paths
        for item in plan[279:]
    ):
        raise _component_error("r02 contains a terminal receipt outside its prefix")

    regular_tree = [
        item for item in validated_tree if item.get("type") == "regular_file"
    ]
    if (
        len(validated_tree) != terminal.get("complete_tree_entry_count")
        or len(regular_tree) != terminal.get("complete_tree_regular_file_count")
        or sum(int(item["bytes"]) for item in regular_tree)
        != terminal.get("complete_tree_regular_file_bytes")
        or sha256(_canonical_json_bytes(validated_tree)).hexdigest()
        != terminal.get("complete_tree_sha256")
    ):
        raise _component_error("r02 complete-tree identity differs")

    expected_evidence = dict(
        (amendment.get("pending_terminal_bindings") or {}).get("evidence_receipts")
        or {}
    )
    observed_kinds = [str(item.get("kind", "")) for item in validated_evidence]
    required_kinds = list(replacement.get("required_evidence_kinds_exactly_once") or [])
    if observed_kinds != required_kinds or set(expected_evidence) != set(
        required_kinds
    ):
        raise _component_error("whole-attempt evidence kinds/order differ")
    for item in validated_evidence:
        if item != expected_evidence[str(item["kind"])]:
            raise _component_error(f"{item['kind']} differs from its frozen binding")
    evidence_by_kind = {str(item["kind"]): item for item in validated_evidence}

    schema = dict(
        (amendment.get("full_attempt_plan") or {}).get(
            "r02_partial_terminal_forensics_schema"
        )
        or {}
    )
    validation_path = Path(
        str(evidence_by_kind["whole_attempt_replacement_validation"]["path"])
    )
    validation_raw = validation_path.read_bytes()
    validation_wrapper = _strict_json_object(
        validation_raw.decode("utf-8"), label="whole-attempt validation"
    )
    if set(validation_wrapper) != set(schema.get("wrapper_fields_exactly") or []):
        raise _component_error("whole-attempt validation wrapper fields differ")
    payload = validation_wrapper.get("payload")
    if (
        validation_wrapper.get("schema_version") != 1
        or validation_wrapper.get("receipt_type") != "r02_partial_terminal_forensics"
        or not isinstance(payload, dict)
        or sha256(_canonical_json_bytes(payload)).hexdigest()
        != validation_wrapper.get("payload_sha256")
        or set(payload) != set(schema.get("payload_fields_exactly") or [])
    ):
        raise _component_error("whole-attempt validation payload differs")
    checks = dict((payload.get("validation") or {}).get("checks") or {})
    failures = (payload.get("validation") or {}).get("failures")
    if (
        not checks
        or any(value is not True for value in checks.values())
        or failures != []
    ):
        raise _component_error("whole-attempt historical validation did not pass")
    counts = dict(payload.get("counts") or {})
    fixed_counts = dict(schema.get("counts_fixed_values") or {})
    if any(counts.get(name) != value for name, value in fixed_counts.items()):
        raise _component_error("whole-attempt validation counts differ")
    ordered_units = payload.get("ordered_units")
    if (
        not isinstance(ordered_units, list)
        or len(ordered_units) != 430
        or any(
            not isinstance(row, dict)
            or row.get("plan_index") != index
            or row.get("primary_source_attempt_id") != _COMPONENT_SUCCESSOR_ID
            for index, row in enumerate(ordered_units)
        )
    ):
        raise _component_error("whole-attempt uniform primary-source rows differ")

    canary_binding = dict(
        (amendment.get("pending_terminal_bindings") or {}).get("all_partition_canary")
        or {}
    )
    canary_archive = _validate_all_partition_canary_archive(
        amendment=amendment,
        binding=canary_binding,
        evidence_receipt=evidence_by_kind["all_partition_paw_cache_canary"],
        r02_scheduler_sacct_evidence=evidence_by_kind["scheduler_sacct"],
    )

    correction = receipt.get("whole_attempt_protocol_correction")
    correction_schema = list(
        replacement.get("whole_attempt_protocol_correction_fields_exactly") or []
    )
    if not isinstance(correction, dict) or set(correction) != set(correction_schema):
        raise _component_error("whole-attempt correction fields differ")
    expected_correction = {
        "schema_version": 1,
        "analysis_id": _COMPONENT_ANALYSIS_ID,
        "full_plan_unit_count": 430,
        "full_plan_stored_json_bytes": 122245,
        "full_plan_stored_json_sha256": _COMPONENT_FULL_PLAN_STORED_SHA256,
        "full_plan_canonical_sha256": _COMPONENT_FULL_PLAN_SHA256,
        "full_plan_membership_sha256": _COMPONENT_FULL_PLAN_MEMBERSHIP_SHA256,
        "r02_started_unit_count": 280,
        "r02_terminal_unit_count": 279,
        "r02_started_without_terminal_unit_count": 1,
        "r02_never_started_unit_count": 150,
        "provenance_rerun_unit_count": 279,
        "provenance_rerun_membership_sha256": whole["execution_roles"][
            "provenance_rerun"
        ]["membership_sha256"],
        "interrupted_direct_unit_count": 1,
        "interrupted_direct_membership_sha256": whole["execution_roles"][
            "interrupted_direct"
        ]["membership_sha256"],
        "unstarted_direct_unit_count": 70,
        "unstarted_direct_membership_sha256": whole["execution_roles"][
            "unstarted_direct"
        ]["membership_sha256"],
        "direct_first_completion_unit_count": 71,
        "direct_first_completion_membership_sha256": whole["execution_roles"][
            "direct_first_completion"
        ]["membership_sha256"],
        "deterministic_first_execution_unit_count": 80,
        "deterministic_first_execution_membership_sha256": whole["execution_roles"][
            "deterministic_first_execution"
        ]["membership_sha256"],
        "primary_source_attempt_id": _COMPONENT_SUCCESSOR_ID,
    }
    if any(
        correction.get(name) != value for name, value in expected_correction.items()
    ):
        raise _component_error("whole-attempt correction values differ")
    historical = dict(correction.get("historical_validation") or {})
    validation_receipt = evidence_by_kind["whole_attempt_replacement_validation"]
    if historical != {
        "receipt_path": validation_receipt["path"],
        "receipt_bytes": validation_receipt["bytes"],
        "receipt_sha256": validation_receipt["sha256"],
    }:
        raise _component_error("whole-attempt historical validation binding differs")
    return {
        "validated_canary_archive_files": canary_archive["member_receipts"],
        "whole_attempt_validation": validation_receipt,
        "full_attempt_plan": whole,
    }


def replacement_launch_binding(
    successor_attempt_dir: Path,
    receipt_value: str | None,
) -> dict[str, Any]:
    """Validate and bind an outcome-independent attempt-replacement receipt.

    Formal attempt IDs end in ``-rNN``.  The first attempt explicitly has no
    predecessor.  Every later attempt must be justified by a pre-existing,
    immutable receipt whose bytes and referenced evidence are verified before
    the successor attempt directory is created.
    """

    successor_input = successor_attempt_dir.expanduser().absolute()
    _reject_symlink_components(successor_input.parent, label="formal attempts root")
    successor_attempt_dir = successor_input.resolve()
    successor_id = successor_attempt_dir.name
    match = _FORMAL_ATTEMPT_RE.fullmatch(successor_id)
    if match is None:
        raise SystemsHarnessError(
            "formal raw attempt ID must end in -rNN with a two-digit ordinal"
        )
    ordinal = int(match.group("ordinal"))
    if ordinal < 1:
        raise SystemsHarnessError("formal raw attempt ordinal must be at least r01")
    if ordinal > _MAX_FORMAL_ATTEMPT_ORDINAL:
        raise SystemsHarnessError(
            f"formal raw attempt ordinal may not exceed r{_MAX_FORMAL_ATTEMPT_ORDINAL:02d}"
        )
    supplied = (receipt_value or "").strip()
    if ordinal == 1:
        if supplied:
            raise SystemsHarnessError("r01 must not declare a replacement receipt")
        return {
            "kind": "initial_attempt",
            "raw_attempt_ordinal": 1,
            "successor_raw_attempt_id": successor_id,
            "predecessor_raw_attempt_id": None,
            "created_utc": None,
            "classification": None,
            "original_status": None,
            "reason": None,
            "affected_boundary": None,
            "scheduler_adjudication": None,
            "predecessor_artifacts": {},
            "predecessor_tree": [],
            "evidence_receipts": [],
            "replacement_receipt": None,
        }
    if not supplied:
        raise SystemsHarnessError("r02+ requires RAP_EACL_REPLACEMENT_RECEIPT")

    receipt_path_input = Path(supplied).expanduser()
    _reject_symlink_components(receipt_path_input, label="replacement receipt")
    try:
        receipt_path = receipt_path_input.resolve(strict=True)
    except OSError as exc:
        raise SystemsHarnessError(f"replacement receipt is unavailable: {exc}") from exc
    if not receipt_path.is_file():
        raise SystemsHarnessError("replacement receipt must be a regular file")
    if receipt_path.name != "replacement.json":
        raise SystemsHarnessError(
            "replacement receipt basename must be replacement.json"
        )
    receipt_bytes = receipt_path.read_bytes()

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
        receipt = json.loads(
            receipt_bytes,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemsHarnessError(f"invalid replacement receipt JSON: {exc}") from exc
    if not isinstance(receipt, dict):
        raise SystemsHarnessError("replacement receipt must be a JSON object")
    component_edge = (
        successor_id == _COMPONENT_SUCCESSOR_ID
        and receipt.get("predecessor_raw_attempt_id") == _COMPONENT_PREDECESSOR_ID
    )
    expected_schema_version = 3 if component_edge else 1
    if receipt.get("schema_version") != expected_schema_version:
        raise SystemsHarnessError(
            f"replacement receipt schema_version must equal {expected_schema_version}"
        )
    expected_top_level = {
        "schema_version",
        "created_utc",
        "successor_raw_attempt_id",
        "predecessor_raw_attempt_id",
        "classification",
        "original_status",
        "reason",
        "affected_boundary",
        "predecessor_artifacts",
        "predecessor_tree",
        "evidence_receipts",
        "scheduler_adjudication",
    }
    if component_edge:
        expected_top_level.update(
            {
                "prepublication_failure",
                "successor_source",
                "whole_attempt_protocol_correction",
            }
        )
    if set(receipt) != expected_top_level:
        raise SystemsHarnessError("replacement receipt has unexpected top-level fields")

    predecessor_id = (
        _COMPONENT_PREDECESSOR_ID
        if component_edge
        else f"{match.group('prefix')}-r{ordinal - 1:02d}"
    )
    exact_scalars = {
        "successor_raw_attempt_id": successor_id,
        "predecessor_raw_attempt_id": predecessor_id,
    }
    for name, expected in exact_scalars.items():
        if receipt.get(name) != expected:
            raise SystemsHarnessError(
                f"replacement receipt {name} must equal {expected!r}"
            )
    classification = str(receipt.get("classification", ""))
    if component_edge:
        classification_allowed = classification == _COMPONENT_CLASSIFICATION
    else:
        classification_allowed = classification in _REPLACEMENT_CLASSIFICATIONS
    if not classification_allowed:
        raise SystemsHarnessError(
            "replacement classification is not permitted for this exact edge"
        )
    for name in ("reason", "affected_boundary"):
        if not isinstance(receipt.get(name), str) or not receipt[name].strip():
            raise SystemsHarnessError(f"replacement receipt requires nonempty {name}")
    created_utc = receipt.get("created_utc")
    try:
        created = datetime.fromisoformat(str(created_utc).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemsHarnessError(
            "replacement receipt created_utc must be ISO-8601"
        ) from exc
    if created.tzinfo is None or created > datetime.now(timezone.utc):
        raise SystemsHarnessError(
            "replacement receipt created_utc must be timezone-aware and pre-launch"
        )

    predecessor_root = successor_attempt_dir.parent / predecessor_id
    _reject_symlink_components(predecessor_root, label="predecessor attempt directory")
    artifacts = receipt.get("predecessor_artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(
        _PREDECESSOR_ARTIFACT_NAMES
    ):
        raise SystemsHarnessError(
            "replacement receipt must declare every required predecessor core and "
            "process-stream artifact"
        )
    validated_artifacts = {
        name: _validate_declared_file_receipt(
            artifacts[name],
            predecessor_root / name,
            allow_absent=name == "result.json",
        )
        for name in _PREDECESSOR_ARTIFACT_NAMES
    }
    declared_tree = receipt.get("predecessor_tree")
    if not isinstance(declared_tree, list):
        raise SystemsHarnessError("replacement receipt predecessor_tree must be a list")
    validated_tree = _predecessor_tree_receipts(predecessor_root)
    if declared_tree != validated_tree:
        raise SystemsHarnessError(
            "replacement receipt predecessor_tree is not the complete live file tree"
        )
    regular_tree_bytes = sum(
        int(item["bytes"]) for item in validated_tree if item["type"] == "regular_file"
    )
    if (
        len(validated_tree) > _MAX_PREDECESSOR_TREE_ENTRIES
        or regular_tree_bytes > _MAX_PREDECESSOR_TREE_REGULAR_BYTES
    ):
        raise SystemsHarnessError(
            "predecessor attempt tree exceeds the frozen replacement retention bound"
        )
    predecessor_result = validated_artifacts["result.json"]
    predecessor_result_value: dict[str, Any] | None = None
    outcome_aware_override = False
    whole_attempt_protocol_correction = False
    terminal_forensics: dict[str, Any] | None = None
    declared_original_status = str(receipt.get("original_status", ""))
    if predecessor_result is not None:
        try:
            loaded_result = json.loads(
                (predecessor_root / "result.json").read_text(encoding="utf-8")
            )
            if not isinstance(loaded_result, dict) or "status" not in loaded_result:
                raise TypeError("result must be an object with status")
            predecessor_result_value = loaded_result
            predecessor_status = str(loaded_result["status"])
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
        ) as exc:
            raise SystemsHarnessError(
                "predecessor result is not a valid classified result"
            ) from exc
        if declared_original_status != predecessor_status:
            raise SystemsHarnessError(
                "replacement original_status disagrees with predecessor result"
            )
        exact_outcome_aware_edge = (
            predecessor_id == _OUTCOME_AWARE_REPAIR["predecessor_raw_attempt_id"]
            and successor_id == _OUTCOME_AWARE_REPAIR["successor_raw_attempt_id"]
            and predecessor_status
            == _OUTCOME_AWARE_REPAIR["receipt_overrides"]["original_status"]
        )
        if exact_outcome_aware_edge:
            outcome_aware_override = True
        elif component_edge and classification == _COMPONENT_CLASSIFICATION:
            whole_attempt_protocol_correction = True
        elif _result_contains_system_violation(predecessor_result_value):
            raise SystemsHarnessError(
                "predecessor result retains a system_violation and is not "
                "replacement-eligible"
            )
        if not outcome_aware_override and not whole_attempt_protocol_correction:
            allowed_statuses = {f"incomplete_{classification}"}
            if classification == "infrastructure_error":
                allowed_statuses.add("incomplete_unclassified_failure")
            if predecessor_status not in allowed_statuses:
                raise SystemsHarnessError(
                    "predecessor result is not eligible for outcome-independent replacement"
                )
    elif declared_original_status != "missing":
        raise SystemsHarnessError(
            "replacement original_status must be 'missing' when result.json is absent"
        )
    elif component_edge and classification == _COMPONENT_CLASSIFICATION:
        whole_attempt_protocol_correction = True
    elif classification != "infrastructure_error":
        raise SystemsHarnessError(
            "a missing predecessor result is replacement-eligible only with positive "
            "infrastructure evidence"
        )

    evidence = receipt.get("evidence_receipts")
    if not isinstance(evidence, list) or not evidence:
        raise SystemsHarnessError("replacement receipt requires evidence_receipts")
    validated_evidence: list[dict[str, Any]] = []
    evidence_kinds: set[str] = set()
    evidence_kind_counts: Counter[str] = Counter()
    evidence_text: dict[str, str] = {}
    for item in evidence:
        if not isinstance(item, dict) or set(item) != {
            "kind",
            "path",
            "bytes",
            "sha256",
        }:
            raise SystemsHarnessError("invalid replacement evidence receipt fields")
        kind = str(item["kind"])
        if not kind:
            raise SystemsHarnessError("replacement evidence kind must be nonempty")
        if not isinstance(item["path"], str):
            raise SystemsHarnessError(
                "replacement evidence path must be an exact absolute string"
            )
        evidence_path_input = Path(item["path"]).expanduser()
        if not evidence_path_input.is_absolute():
            raise SystemsHarnessError(
                "replacement evidence path must be an exact absolute string"
            )
        _reject_symlink_components(evidence_path_input, label="replacement evidence")
        try:
            evidence_path = evidence_path_input.resolve(strict=True)
        except OSError as exc:
            raise SystemsHarnessError(
                f"replacement evidence is unavailable: {evidence_path_input}"
            ) from exc
        if item["path"] != str(evidence_path):
            raise SystemsHarnessError(
                "replacement evidence path must equal its resolved absolute path"
            )
        observed = _validate_declared_file_receipt(
            {
                "path": str(evidence_path),
                "bytes": item["bytes"],
                "sha256": item["sha256"],
            },
            evidence_path,
            allow_absent=False,
        )
        assert observed is not None
        validated_evidence.append({"kind": kind, **observed})
        evidence_kinds.add(kind)
        evidence_kind_counts[kind] += 1
        if kind in {"scheduler_sacct", "scheduler_scontrol"}:
            try:
                evidence_text[kind] = evidence_path.read_text(
                    encoding="utf-8", errors="strict"
                )
            except UnicodeDecodeError as exc:
                raise SystemsHarnessError(
                    f"{kind} replacement evidence must be UTF-8 text"
                ) from exc
    adjudication = receipt.get("scheduler_adjudication")
    needs_scheduler_adjudication = classification == "infrastructure_error" and (
        predecessor_result is None
        or declared_original_status == "incomplete_unclassified_failure"
    )
    if needs_scheduler_adjudication:
        required = {
            "scheduler_sacct",
            "scheduler_scontrol",
            "scheduler_stdout",
            "scheduler_stderr",
        }
        if not required.issubset(evidence_kinds):
            raise SystemsHarnessError(
                "missing-result infrastructure replacement requires sacct, scontrol, "
                "scheduler stdout, and scheduler stderr evidence"
            )
        if not isinstance(adjudication, dict) or set(adjudication) != {
            "scheduler_job_id",
            "state",
            "reason",
            "exit_code",
        }:
            raise SystemsHarnessError(
                "missing-result infrastructure replacement requires exact "
                "scheduler_adjudication fields"
            )
        job_id = str(adjudication["scheduler_job_id"])
        state = str(adjudication["state"])
        reason = str(adjudication["reason"])
        exit_code = adjudication["exit_code"]
        if (
            not job_id.isdigit()
            or state not in _EXTERNAL_SCHEDULER_STATES
            or not reason
            or not isinstance(exit_code, str)
            or re.fullmatch(r"[0-9]+:[0-9]+", exit_code) is None
        ):
            raise SystemsHarnessError(
                "replacement scheduler adjudication lacks a positively external state"
            )
        launch_job_id = _predecessor_launch_job_id(predecessor_root)
        if job_id != launch_job_id:
            raise SystemsHarnessError(
                "replacement scheduler job ID disagrees with predecessor launch "
                "identity Slurm job_id"
            )
        if any(evidence_kind_counts[kind] != 1 for kind in required):
            raise SystemsHarnessError(
                "scheduler replacement requires each scheduler evidence kind exactly once"
            )
        for kind in ("scheduler_sacct", "scheduler_scontrol"):
            retained = evidence_text[kind]
            job_token = re.search(rf"(?<![0-9]){re.escape(job_id)}(?![0-9])", retained)
            state_token = re.search(
                rf"(?<![A-Z0-9_]){re.escape(state)}(?![A-Z0-9_])",
                retained,
            )
            if job_token is None or state_token is None:
                raise SystemsHarnessError(
                    f"{kind} evidence does not contain the adjudicated job and state"
                )
    elif adjudication is not None:
        raise SystemsHarnessError(
            "scheduler_adjudication is allowed only for independently adjudicated "
            "infrastructure replacements"
        )
    if outcome_aware_override:
        assert predecessor_result_value is not None
        _validate_outcome_aware_replacement(
            receipt=receipt,
            predecessor_root=predecessor_root,
            predecessor_result=predecessor_result_value,
            validated_artifacts=validated_artifacts,
            validated_tree=validated_tree,
            validated_evidence=validated_evidence,
        )
    if whole_attempt_protocol_correction:
        expected_prepublication = r03_prepublication_failure_binding()
        if receipt.get("prepublication_failure") != expected_prepublication:
            raise SystemsHarnessError(
                "replacement receipt r03 prepublication failure binding differs"
            )
        terminal_forensics = _validate_whole_attempt_protocol_correction(
            receipt=receipt,
            predecessor_root=predecessor_root,
            validated_artifacts=validated_artifacts,
            validated_tree=validated_tree,
            validated_evidence=validated_evidence,
        )
    canonical_receipt = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    binding = {
        "kind": "replacement_attempt",
        "raw_attempt_ordinal": ordinal,
        "receipt_path": str(receipt_path),
        "receipt_bytes": len(receipt_bytes),
        "receipt_sha256": sha256(receipt_bytes).hexdigest(),
        "canonical_receipt_sha256": sha256(canonical_receipt).hexdigest(),
        "classification": classification,
        "original_status": declared_original_status,
        "successor_raw_attempt_id": successor_id,
        "predecessor_raw_attempt_id": predecessor_id,
        "created_utc": str(created_utc),
        "reason": receipt["reason"],
        "affected_boundary": receipt["affected_boundary"],
        "scheduler_adjudication": adjudication,
        "predecessor_artifacts": validated_artifacts,
        "predecessor_tree": validated_tree,
        "evidence_receipts": validated_evidence,
    }
    if whole_attempt_protocol_correction:
        binding["prepublication_failure"] = receipt["prepublication_failure"]
        binding["successor_source"] = receipt["successor_source"]
        binding["whole_attempt_protocol_correction"] = receipt[
            "whole_attempt_protocol_correction"
        ]
        binding["r02_partial_terminal_forensics"] = terminal_forensics
    return binding


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SystemsHarnessError(
            f"could not open artifact directory for fsync: {path}"
        ) from exc
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise SystemsHarnessError(
                f"could not fsync artifact directory: {path}"
            ) from exc
    finally:
        os.close(descriptor)


def _create_parent_directories(path: Path) -> list[Path]:
    """Create a path's missing parents and return them deepest-first."""

    missing: list[Path] = []
    current = path.parent
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise SystemsHarnessError(
            f"artifact parent chain is not a regular directory: {current}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    return missing


def _fsync_created_directory_chain(missing: list[Path]) -> None:
    """Persist nested directory entries from the leaf back to the old ancestor."""

    for directory in missing:
        _fsync_directory(directory)
    if missing:
        _fsync_directory(missing[-1].parent)


class _NativeNoReplaceUnsupported(RuntimeError):
    """The host or filesystem does not implement the native no-replace primitive."""

    def __init__(self, primitive: str, error: int):
        super().__init__(primitive, error)
        self.primitive = primitive
        self.error = error


_NATIVE_NOREPLACE_UNSUPPORTED_ERRNOS = frozenset(
    {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
        errno.EOPNOTSUPP,
    }
)


def _native_rename_directory_noreplace(source: Path, destination: Path) -> str:
    """Use the platform's atomic no-replace rename and return its primitive."""

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform.startswith("linux"):
        primitive = "renameat2_RENAME_NOREPLACE"
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise _NativeNoReplaceUnsupported(primitive, errno.ENOSYS)
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        ctypes.set_errno(0)
        status = renameat2(
            -100,
            source_bytes,
            -100,
            destination_bytes,
            1,
        )
    elif sys.platform == "darwin":
        primitive = "renamex_np_RENAME_EXCL"
        renamex_np = getattr(library, "renamex_np", None)
        if renamex_np is None:
            raise _NativeNoReplaceUnsupported(primitive, errno.ENOSYS)
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        ctypes.set_errno(0)
        status = renamex_np(source_bytes, destination_bytes, 0x00000004)
    else:
        raise _NativeNoReplaceUnsupported("unsupported_platform", errno.ENOSYS)
    if status != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise SystemsHarnessError(
                f"attempt directory already exists and is immutable: {destination}"
            )
        if error in _NATIVE_NOREPLACE_UNSUPPORTED_ERRNOS:
            raise _NativeNoReplaceUnsupported(primitive, error)
        raise SystemsHarnessError(
            f"could not atomically publish attempt directory: {os.strerror(error)}"
        )
    return primitive


def _publication_claim_path(destination: Path) -> Path:
    staging_parent = destination.parent.with_name(f".{destination.parent.name}.staging")
    return staging_parent / ".publication-claims" / f"{destination.name}.launch.json"


def _require_private_owned_directory(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise SystemsHarnessError(f"{label} is not a regular directory: {path}")
    observed = path.stat(follow_symlinks=False)
    effective_uid = getattr(os, "geteuid", lambda: observed.st_uid)()
    if observed.st_uid != effective_uid or stat.S_IMODE(observed.st_mode) != 0o700:
        raise SystemsHarnessError(
            f"{label} must be owned by the launcher with mode 0700: {path}"
        )


def _hardlink_claim_then_posix_rename(
    source: Path,
    destination: Path,
    *,
    native_primitive: str,
    native_error: int,
) -> dict[str, Any]:
    """Publish through one persistent, exclusive claim among compliant writers."""

    claim_path = _publication_claim_path(destination)
    staging_parent = claim_path.parent.parent
    claims_root = claim_path.parent
    _require_private_owned_directory(staging_parent, label="attempt staging root")
    if claims_root.is_symlink():
        raise SystemsHarnessError(
            f"attempt publication claims root must not be a symlink: {claims_root}"
        )
    try:
        claims_root.mkdir(mode=0o700)
    except FileExistsError:
        if not claims_root.is_dir() or claims_root.is_symlink():
            raise SystemsHarnessError(
                f"attempt publication claims root is not a directory: {claims_root}"
            )
    else:
        _fsync_directory(claims_root)
        _fsync_directory(staging_parent)
    _require_private_owned_directory(
        claims_root, label="attempt publication claims root"
    )

    launch_path = source / "launch.json"
    if launch_path.is_symlink() or not launch_path.is_file():
        raise SystemsHarnessError(
            f"staged attempt launch is not a regular file: {launch_path}"
        )
    try:
        os.link(launch_path, claim_path, follow_symlinks=False)
    except FileExistsError as exc:
        raise SystemsHarnessError(
            f"attempt publication claim already exists and is immutable: {claim_path}"
        ) from exc
    except OSError as exc:
        raise SystemsHarnessError(
            f"could not exclusively claim attempt publication: {exc}"
        ) from exc

    # The claim is the compliant-writer linearization point.  It is never
    # removed, including when the later rename fails or the process crashes.
    _fsync_directory(claims_root)
    launch_stat = launch_path.stat(follow_symlinks=False)
    claim_stat = claim_path.stat(follow_symlinks=False)
    launch_receipt = _file_receipt(launch_path)
    claim_receipt = _file_receipt(claim_path)
    if (
        not stat.S_ISREG(claim_stat.st_mode)
        or (launch_stat.st_dev, launch_stat.st_ino)
        != (claim_stat.st_dev, claim_stat.st_ino)
        or launch_stat.st_size != claim_stat.st_size
        or launch_receipt["bytes"] != claim_receipt["bytes"]
        or launch_receipt["sha256"] != claim_receipt["sha256"]
    ):
        raise SystemsHarnessError(
            "attempt publication claim is not the staged launch hard link"
        )
    if destination.exists() or destination.is_symlink():
        raise SystemsHarnessError(
            f"attempt directory already exists and is immutable: {destination}"
        )
    try:
        os.rename(source, destination)
    except OSError as exc:
        raise SystemsHarnessError(
            f"could not atomically publish claimed attempt directory: {exc}"
        ) from exc

    published_launch = destination / "launch.json"
    published_stat = published_launch.stat(follow_symlinks=False)
    if not stat.S_ISREG(published_stat.st_mode) or (
        published_stat.st_dev,
        published_stat.st_ino,
    ) != (claim_stat.st_dev, claim_stat.st_ino):
        raise SystemsHarnessError(
            "published launch does not match the persistent attempt claim"
        )
    return {
        "schema_version": 1,
        "destination": str(destination),
        "method": "hardlink_claim_then_posix_rename",
        "native_primitive": native_primitive,
        "native_unsupported": {
            "errno": native_error,
            "name": errno.errorcode.get(native_error, f"ERRNO_{native_error}"),
        },
        "claim": {
            "path": str(claim_path),
            "artifact": "launch.json",
            "bytes": claim_receipt["bytes"],
            "sha256": claim_receipt["sha256"],
        },
    }


def _rename_directory_noreplace(source: Path, destination: Path) -> dict[str, Any]:
    """Atomically publish a staged tree and return the exact method receipt."""

    claim_path = _publication_claim_path(destination)
    if claim_path.parent.is_symlink():
        raise SystemsHarnessError(
            f"attempt publication claims root must not be a symlink: {claim_path.parent}"
        )
    if claim_path.exists() or claim_path.is_symlink():
        raise SystemsHarnessError(
            f"attempt publication claim already exists and is immutable: {claim_path}"
        )
    try:
        primitive = _native_rename_directory_noreplace(source, destination)
    except _NativeNoReplaceUnsupported as unsupported:
        return _hardlink_claim_then_posix_rename(
            source,
            destination,
            native_primitive=unsupported.primitive,
            native_error=unsupported.error,
        )
    return {
        "schema_version": 1,
        "destination": str(destination),
        "method": "native_no_replace",
        "native_primitive": primitive,
        "native_unsupported": None,
        "claim": None,
    }


def _exclusive_empty(path: Path) -> None:
    missing = _create_parent_directories(path)
    with path.open("xb") as handle:
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_directory(path.parent)
    _fsync_created_directory_chain(missing)


def _exclusive_json(path: Path, value: Any) -> None:
    missing = _create_parent_directories(path)
    rendered = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".partial", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise SystemsHarnessError(
                f"immutable attempt record already exists: {path}"
            ) from exc
        _fsync_directory(path.parent)
        _fsync_created_directory_chain(missing)
    finally:
        temporary.unlink(missing_ok=True)


def _exclusive_verified_copy(
    source: Path,
    destination: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> None:
    """Stream one bound input into unpublished staging with bounded memory."""

    missing = _create_parent_directories(destination)
    digest = sha256()
    byte_count = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source, flags)
    except OSError as exc:
        raise SystemsHarnessError(
            f"prelaunch evidence source became unavailable: {source}"
        ) from exc
    with os.fdopen(source_descriptor, "rb") as reader, destination.open("xb") as writer:
        opened = os.fstat(reader.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise SystemsHarnessError(
                f"prelaunch evidence is not a regular file: {source}"
            )
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            writer.write(chunk)
            digest.update(chunk)
            byte_count += len(chunk)
        writer.flush()
        os.fsync(writer.fileno())
        closed_over = os.fstat(reader.fileno())
    _fsync_directory(destination.parent)
    _fsync_created_directory_chain(missing)
    if (
        opened.st_dev != closed_over.st_dev
        or opened.st_ino != closed_over.st_ino
        or opened.st_size != closed_over.st_size
        or byte_count != expected_bytes
        or digest.hexdigest() != expected_sha256
    ):
        raise SystemsHarnessError(
            f"prelaunch evidence changed while being retained: {source}"
        )


def _validate_retained_canary_archive_copy(
    staging: Path, validated_copies: list[dict[str, Any]]
) -> None:
    """Revalidate the preserved absolute-path manifest through basename mapping."""

    retained_root = Path("replacement/evidence/002-all_partition_paw_cache_canary")
    canary_copies = [
        item for item in validated_copies if item["relative"].parent == retained_root
    ]
    if not canary_copies:
        return
    if (
        len(canary_copies) != 28
        or len({item["relative"].name for item in canary_copies}) != 28
        or any(item["relative"].parent != retained_root for item in canary_copies)
    ):
        raise SystemsHarnessError(
            "retained canary archive is not an exact flat 28-file copy"
        )
    destination = staging / retained_root
    observed_names = {path.name for path in destination.iterdir()}
    manifest_path = destination / "evidence.sha256"
    sidecar_path = destination / "evidence.sha256.sha256"
    manifest_raw = manifest_path.read_bytes()
    if not manifest_raw.endswith(b"\n") or len(manifest_raw.splitlines()) != 26:
        raise SystemsHarnessError("retained canary manifest line count differs")
    try:
        manifest_lines = manifest_raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise SystemsHarnessError("retained canary manifest is not UTF-8") from exc
    original_parent: Path | None = None
    manifest_names: set[str] = set()
    original_paths: list[Path] = []
    for line in manifest_lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (/.+)", line)
        if match is None:
            raise SystemsHarnessError("retained canary manifest syntax differs")
        original_path = Path(match.group(2))
        if original_path.name in manifest_names or original_path.name in {
            "evidence.sha256",
            "evidence.sha256.sha256",
        }:
            raise SystemsHarnessError("retained canary manifest member repeats")
        if original_parent is None:
            original_parent = original_path.parent
        elif original_path.parent != original_parent:
            raise SystemsHarnessError("retained canary manifest roots differ")
        original_paths.append(original_path)
        retained_member = destination / original_path.name
        if (
            not retained_member.is_file()
            or retained_member.is_symlink()
            or sha256(retained_member.read_bytes()).hexdigest() != match.group(1)
        ):
            raise SystemsHarnessError(
                "retained canary member differs under basename mapping"
            )
        manifest_names.add(original_path.name)
    if original_paths != sorted(
        original_paths, key=lambda path: os.fsencode(str(path))
    ):
        raise SystemsHarnessError("retained canary manifest order differs")
    if observed_names != manifest_names | {"evidence.sha256", "evidence.sha256.sha256"}:
        raise SystemsHarnessError("retained canary archive member set differs")
    assert original_parent is not None
    manifest_sha256 = sha256(manifest_raw).hexdigest()
    if sidecar_path.read_bytes() != (
        f"{manifest_sha256}  {original_parent / 'evidence.sha256'}\n".encode("utf-8")
    ):
        raise SystemsHarnessError("retained canary manifest sidecar differs")


class AttemptRecorder:
    """Write launch, plan, terminal units, and result without replacement."""

    def __init__(
        self,
        root: Path,
        manifest: dict[str, Any],
        *,
        capture_process_streams: bool = False,
    ):
        self.root = root.expanduser().resolve()
        manifest = dict(manifest)
        prelaunch_copies = manifest.pop("_prelaunch_copy_specs", [])
        self.manifest = manifest
        self._plan_keys: list[tuple[str, str]] = []
        for item in manifest.get("plan", []):
            component = str(item.get("component", "matrix"))
            unit_id = str(item.get("unit_id") or item.get("condition_id") or "")
            key = (component, unit_id)
            if not unit_id or key in self._plan_keys:
                raise SystemsHarnessError(f"invalid or duplicate planned unit: {key}")
            self._plan_keys.append(key)

        validated_copies = []
        retained_paths: set[Path] = set()
        reserved_paths = {
            Path("fatal-exception.json"),
            Path("fatal-lifecycle.jsonl"),
            Path("fatal-result.json"),
            Path("launch.json"),
            Path("plan.json"),
            Path("publication.json"),
            Path("result.json"),
            Path("stderr.log"),
            Path("stdout.log"),
            Path("streams.json"),
            Path("units.jsonl"),
        }
        for item in prelaunch_copies:
            if not isinstance(item, dict) or set(item) != {
                "source_path",
                "retained_path",
                "bytes",
                "sha256",
            }:
                raise SystemsHarnessError(
                    "invalid prelaunch evidence copy specification"
                )
            relative = Path(str(item["retained_path"]))
            if (
                not relative.parts
                or relative.is_absolute()
                or ".." in relative.parts
                or relative in reserved_paths
                or relative in retained_paths
            ):
                raise SystemsHarnessError(
                    "prelaunch evidence path escapes attempt root"
                )
            retained_paths.add(relative)
            source = Path(str(item["source_path"]))
            if source.is_symlink() or not source.is_file():
                raise SystemsHarnessError(
                    f"prelaunch evidence source is unavailable: {source}"
                )
            resolved_source = source.resolve(strict=True)
            observed = _file_receipt(resolved_source)
            if (
                not isinstance(item["bytes"], int)
                or isinstance(item["bytes"], bool)
                or int(item["bytes"]) < 0
                or not isinstance(item["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
                or observed["bytes"] != item["bytes"]
                or observed["sha256"] != item["sha256"]
            ):
                raise SystemsHarnessError(
                    f"prelaunch evidence changed before attempt creation: {source}"
                )
            validated_copies.append(
                {
                    "source": resolved_source,
                    "relative": relative,
                    "bytes": int(item["bytes"]),
                    "sha256": str(item["sha256"]),
                }
            )
        self.root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        formal = (
            str((manifest.get("identity") or {}).get("study_mode", ""))
            in _FORMAL_STUDY_MODES
        )
        if formal:
            _require_private_owned_directory(
                self.root.parent, label="formal attempt root"
            )
        if self.root.exists() or self.root.is_symlink():
            raise SystemsHarnessError(
                f"attempt directory already exists and is immutable: {self.root}"
            )
        staging_parent = self.root.parent.with_name(f".{self.root.parent.name}.staging")
        if staging_parent.is_symlink():
            raise SystemsHarnessError(
                f"attempt staging root must not be a symlink: {staging_parent}"
            )
        staging_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _require_private_owned_directory(staging_parent, label="attempt staging root")
        required_staging_bytes = sum(int(item["bytes"]) for item in validated_copies)
        available_staging_bytes = shutil.disk_usage(staging_parent).free
        if (
            available_staging_bytes
            < required_staging_bytes + _MIN_STAGING_FREE_RESERVE_BYTES
        ):
            raise SystemsHarnessError(
                "insufficient free space for bounded immutable staging retention"
            )
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{self.root.name}.",
                suffix=".partial",
                dir=staging_parent,
            )
        )
        saved_descriptors: dict[int, int] = {}
        target_descriptors: dict[int, int] = {}
        self._initialization_warnings: list[str] = []
        try:
            _fsync_directory(staging_parent)
            _fsync_directory(staging)
            stdout_path = staging / "stdout.log"
            stderr_path = staging / "stderr.log"
            _exclusive_empty(stdout_path)
            _exclusive_empty(stderr_path)
            _exclusive_json(
                staging / "streams.json",
                {
                    "stdout": "stdout.log",
                    "stderr": "stderr.log",
                    "capture": (
                        "process file descriptors 1 and 2 redirected immediately after "
                        "immutable launch creation through process exit"
                        if capture_process_streams
                        else "files reserved; candidate caller did not request fd capture"
                    ),
                    "lossless_from_launch": bool(capture_process_streams),
                },
            )
            for item in validated_copies:
                _exclusive_verified_copy(
                    item["source"],
                    staging / item["relative"],
                    expected_bytes=item["bytes"],
                    expected_sha256=item["sha256"],
                )
            _validate_retained_canary_archive_copy(staging, validated_copies)
            _exclusive_json(staging / "plan.json", manifest.get("plan", []))
            _exclusive_empty(staging / "units.jsonl")

            if capture_process_streams:
                # Open and duplicate every descriptor before the immutable launch
                # exists.  Descriptor setup therefore finishes before the native
                # publish or fallback claim linearization point.  A later fallback
                # failure deliberately retains its claim and burns the raw ID.
                try:
                    import sys

                    sys.stdout.flush()
                    sys.stderr.flush()
                    for descriptor, path in ((1, stdout_path), (2, stderr_path)):
                        saved_descriptors[descriptor] = os.dup(descriptor)
                        target_descriptors[descriptor] = os.open(
                            path, os.O_WRONLY | os.O_APPEND
                        )
                except (AttributeError, OSError) as exc:
                    raise SystemsHarnessError(
                        f"could not prepare lossless process-stream capture: {exc}"
                    ) from exc

            # launch.json is deliberately the final staged artifact.  No measured
            # operation begins until the complete staged tree is atomically published.
            _exclusive_json(staging / "launch.json", manifest)
            if capture_process_streams:
                try:
                    for descriptor in (1, 2):
                        os.dup2(target_descriptors[descriptor], descriptor)
                except OSError as exc:
                    raise SystemsHarnessError(
                        f"could not establish lossless process-stream capture: {exc}"
                    ) from exc
            if self.root.exists() or self.root.is_symlink():
                raise SystemsHarnessError(
                    f"attempt directory already exists and is immutable: {self.root}"
                )
            publication = _rename_directory_noreplace(staging, self.root)
            _exclusive_json(self.root / "publication.json", publication)
        except BaseException:
            if capture_process_streams and saved_descriptors:
                for descriptor, saved in saved_descriptors.items():
                    try:
                        os.dup2(saved, descriptor)
                    except OSError:
                        pass
            for descriptor in (
                *target_descriptors.values(),
                *saved_descriptors.values(),
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            shutil.rmtree(staging, ignore_errors=True)
            raise
        else:
            for descriptor in (
                *target_descriptors.values(),
                *saved_descriptors.values(),
            ):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            for directory in (self.root.parent, staging_parent):
                try:
                    _fsync_directory(directory)
                except SystemsHarnessError as exc:
                    self._initialization_warnings.append(str(exc))
        self._journal_lock = threading.Lock()
        self._lifecycle_sequence = 0
        self._lifecycle_globals: list[str] = []
        self._lifecycle_unit_state: dict[tuple[str, str], str] = {}
        self._lifecycle_next_plan_index = 0
        self._lifecycle_finalizing = False
        self._lifecycle_result_published = False
        self._strict_r03_lifecycle = self.root.name == _COMPONENT_SUCCESSOR_ID
        _exclusive_empty(self.root / "fatal-lifecycle.jsonl")
        self.record_lifecycle("attempt_published")
        self._started: set[tuple[str, str]] = set()
        self._terminal: dict[tuple[str, str], dict[str, Any]] = {}

    @property
    def initialization_warnings(self) -> tuple[str, ...]:
        """Durability failures observed after atomic attempt publication."""

        return tuple(self._initialization_warnings)

    @staticmethod
    def _safe(value: str) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
        if not sanitized:
            raise SystemsHarnessError("attempt record ID has no safe characters")
        return sanitized

    def record_lifecycle(
        self,
        phase: str,
        *,
        component: str | None = None,
        unit_id: str | None = None,
    ) -> None:
        """Append one durable canonical r03 lifecycle transition."""

        allowed = {
            "attempt_published",
            "post_publication_gate_started",
            "post_publication_gate_passed",
            "unit_started",
            "evaluation_started",
            "unit_terminal",
            "finalizing_result",
            "result_published",
        }
        if phase not in allowed:
            raise SystemsHarnessError(f"unknown fatal lifecycle phase: {phase}")
        unit_phase = phase in {"unit_started", "evaluation_started", "unit_terminal"}
        if unit_phase != (component is not None and unit_id is not None):
            raise SystemsHarnessError("fatal lifecycle unit identity differs")
        plan_index: int | None = None
        if unit_phase:
            key = (str(component), str(unit_id))
            try:
                plan_index = self._plan_keys.index(key)
            except ValueError as exc:
                raise SystemsHarnessError(
                    f"fatal lifecycle unit is absent from plan: {key}"
                ) from exc
        with self._journal_lock:
            if self._lifecycle_result_published:
                raise SystemsHarnessError("fatal lifecycle is already terminal")
            if phase in {
                "attempt_published",
                "post_publication_gate_started",
                "post_publication_gate_passed",
            }:
                expected_globals = [
                    "attempt_published",
                    "post_publication_gate_started",
                    "post_publication_gate_passed",
                ]
                expected = (
                    expected_globals[len(self._lifecycle_globals)]
                    if len(self._lifecycle_globals) < len(expected_globals)
                    else None
                )
                if phase != expected or self._lifecycle_finalizing:
                    raise SystemsHarnessError("fatal lifecycle global order differs")
                self._lifecycle_globals.append(phase)
            elif unit_phase:
                if self._strict_r03_lifecycle and (
                    self._lifecycle_globals
                    != [
                        "attempt_published",
                        "post_publication_gate_started",
                        "post_publication_gate_passed",
                    ]
                    or self._lifecycle_finalizing
                ):
                    raise SystemsHarnessError(
                        "fatal lifecycle unit phase is out of order"
                    )
                assert plan_index is not None
                key = (str(component), str(unit_id))
                state = self._lifecycle_unit_state.get(key)
                if phase == "unit_started":
                    if (
                        state is not None
                        or plan_index != self._lifecycle_next_plan_index
                    ):
                        raise SystemsHarnessError(
                            "fatal lifecycle plan-ordered unit start differs"
                        )
                    self._lifecycle_unit_state[key] = "started"
                elif phase == "evaluation_started":
                    if state != "started":
                        raise SystemsHarnessError(
                            "fatal lifecycle evaluation start differs"
                        )
                    self._lifecycle_unit_state[key] = "evaluation_started"
                else:
                    if state not in {"started", "evaluation_started"}:
                        raise SystemsHarnessError("fatal lifecycle terminal differs")
                    self._lifecycle_unit_state[key] = "terminal"
                    self._lifecycle_next_plan_index += 1
            elif phase == "finalizing_result":
                if self._lifecycle_finalizing or (
                    self._strict_r03_lifecycle
                    and len(self._lifecycle_globals) not in {2, 3}
                ):
                    raise SystemsHarnessError("fatal lifecycle finalization differs")
                self._lifecycle_finalizing = True
            elif phase == "result_published":
                if not self._lifecycle_finalizing:
                    raise SystemsHarnessError(
                        "fatal lifecycle result publication differs"
                    )
                self._lifecycle_result_published = True
            self._lifecycle_sequence += 1
            line = json.dumps(
                {
                    "schema_version": 1,
                    "sequence": self._lifecycle_sequence,
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "raw_attempt_id": self.root.name,
                    "phase": phase,
                    "plan_index": plan_index,
                    "component": component,
                    "unit_id": unit_id,
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            with (self.root / "fatal-lifecycle.jsonl").open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            _fsync_directory(self.root)

    def record(
        self,
        component: str,
        record_id: str,
        phase: str,
        value: dict[str, Any],
    ) -> str:
        path = (
            self.root
            / self._safe(component)
            / f"{self._safe(record_id)}.{self._safe(phase)}.json"
        )
        key = (component, record_id)
        if phase == "started":
            if key not in self._plan_keys:
                raise SystemsHarnessError(f"started unit is absent from plan: {key}")
            if key in self._started:
                raise SystemsHarnessError(f"unit started more than once: {key}")
            self._started.add(key)
        if phase in ("terminal", "completed", "error"):
            if key not in self._plan_keys:
                raise SystemsHarnessError(f"terminal unit is absent from plan: {key}")
            if key in self._terminal:
                raise SystemsHarnessError(f"unit terminated more than once: {key}")
            if key not in self._started:
                raise SystemsHarnessError(f"unit terminated before start: {key}")
            status = str(value.get("status", ""))
            if status not in UNIT_STATUSES:
                raise SystemsHarnessError(
                    f"unit {key} has noncanonical terminal status {status!r}"
                )
        _exclusive_json(path, value)
        if phase == "started":
            self.record_lifecycle(
                "unit_started", component=component, unit_id=record_id
            )
        if phase in ("terminal", "completed", "error"):
            record_sha256 = sha256(path.read_bytes()).hexdigest()
            line = json.dumps(
                {
                    "component": component,
                    "record_id": record_id,
                    "phase": phase,
                    "status": status,
                    "terminal_record": str(path.relative_to(self.root)),
                    "terminal_record_sha256": record_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            with (
                self._journal_lock,
                (self.root / "units.jsonl").open("a", encoding="utf-8") as handle,
            ):
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._terminal[key] = {
                "status": status,
                "record": str(path.relative_to(self.root)),
                "sha256": record_sha256,
            }
            self.record_lifecycle(
                "unit_terminal", component=component, unit_id=record_id
            )
        return str(path.relative_to(self.root))

    def finalize(self, value: dict[str, Any]) -> dict[str, Any]:
        # Unit payloads have already been written immutably.  A shallow copy avoids
        # momentarily doubling a potentially multi-gigabyte formal result in memory.
        final = dict(value)
        if self._initialization_warnings:
            final["artifact_initialization_warnings"] = list(
                self._initialization_warnings
            )
            final["primary_numeric_eligible"] = False
            if not final.get("abort"):
                final["abort"] = {
                    "status": "infrastructure_error",
                    "classification_basis": (
                        "the atomically published attempt tree could not be fully "
                        "directory-fsynced before measurement"
                    ),
                    "error": {
                        "type": "ArtifactDirectoryFsyncError",
                        "message": "; ".join(self._initialization_warnings),
                    },
                }
                final["status"] = "incomplete_infrastructure_error"
        abort_status = str((final.get("abort") or {}).get("status", ""))
        if abort_status not in UNIT_STATUSES:
            abort_status = "unclassified_failure"
        unit_index = []
        for item, key in zip(self.manifest.get("plan", []), self._plan_keys):
            terminal = self._terminal.get(key)
            started = key in self._started
            status = (
                terminal["status"]
                if terminal is not None
                else abort_status
                if started
                else "not_started_after_abort"
            )
            unit_index.append(
                {
                    "component": key[0],
                    "unit_id": key[1],
                    "plan": item,
                    "started": started,
                    "status": status,
                    "terminal_record": (
                        terminal["record"] if terminal is not None else None
                    ),
                    "terminal_record_sha256": (
                        terminal["sha256"] if terminal is not None else None
                    ),
                }
            )
        final["raw_attempt_id"] = self.root.name
        final["unit_index"] = unit_index
        complete = len(self._terminal) == len(self._plan_keys)
        status_histogram = Counter(item["status"] for item in unit_index)
        global_system_violations = sum(
            status == "system_violation"
            for status in ((final.get("global_outcomes") or {}).get("statuses") or [])
        )
        abort_payload = dict(final.get("abort") or {})
        abort_system_violation = (
            abort_payload.get("status") == "system_violation"
            or (abort_payload.get("original_abort_classification") or {}).get("status")
            == "system_violation"
        )
        final["planned_unit_count"] = len(self._plan_keys)
        final["terminal_unit_count"] = len(self._terminal)
        final["all_planned_units_terminal"] = complete
        final["complete_plan"] = complete
        final["unit_status_histogram"] = dict(sorted(status_histogram.items()))
        final["system_violation_units"] = (
            int(status_histogram.get("system_violation", 0)) + global_system_violations
        )
        final["abort_system_violation"] = abort_system_violation
        if not complete:
            final["primary_numeric_eligible"] = False
            if str(final.get("status", "")) in {
                "completed",
                "completed_with_system_violations",
            }:
                final["status"] = "incomplete_harness_error"
        final["plan_completion"] = {
            "planned": len(self._plan_keys),
            "started": len(self._started),
            "terminal": len(self._terminal),
            "not_started_after_abort": sum(
                item["status"] == "not_started_after_abort" for item in unit_index
            ),
            "started_without_terminal": sum(
                item["started"] and item["terminal_record"] is None
                for item in unit_index
            ),
            "complete": complete,
        }
        final["process_streams"] = {
            "index": "streams.json",
            "stdout": "stdout.log",
            "stderr": "stderr.log",
        }
        self.record_lifecycle("finalizing_result")
        _exclusive_json(self.root / "result.json", final)
        _fsync_directory(self.root)
        self.record_lifecycle("result_published")
        return final
