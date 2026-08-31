"""Immutable, incremental artifact retention for the systems study."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
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
_REPLACEMENT_CLASSIFICATIONS = frozenset(
    {"harness_error", "infrastructure_error"}
)
_EXTERNAL_SCHEDULER_STATES = frozenset(
    {"PREEMPTED", "NODE_FAIL", "BOOT_FAIL"}
)
_MAX_FORMAL_ATTEMPT_ORDINAL = 5
_MAX_PREDECESSOR_TREE_ENTRIES = 250_000
_MAX_PREDECESSOR_TREE_REGULAR_BYTES = 8 * 1024**3
_MIN_STAGING_FREE_RESERVE_BYTES = 1024**3
_PREDECESSOR_ARTIFACT_NAMES = (
    "launch.json",
    "plan.json",
    "result.json",
    "stderr.log",
    "stdout.log",
    "streams.json",
    "units.jsonl",
)


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
        raise SystemsHarnessError(f"could not open bound evidence file: {path}") from exc
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise SystemsHarnessError(
                f"bound evidence is not a regular file: {path}"
            )
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
    _reject_symlink_components(
        successor_input.parent, label="formal attempts root"
    )
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
    try:
        receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemsHarnessError(f"invalid replacement receipt JSON: {exc}") from exc
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise SystemsHarnessError("replacement receipt schema_version must equal 1")
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
    if set(receipt) != expected_top_level:
        raise SystemsHarnessError("replacement receipt has unexpected top-level fields")

    predecessor_id = (
        f"{match.group('prefix')}-r{ordinal - 1:02d}"
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
    if classification not in _REPLACEMENT_CLASSIFICATIONS:
        raise SystemsHarnessError(
            "replacement classification must be harness_error or infrastructure_error"
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
    _reject_symlink_components(
        predecessor_root, label="predecessor attempt directory"
    )
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
        int(item["bytes"])
        for item in validated_tree
        if item["type"] == "regular_file"
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
        if _result_contains_system_violation(predecessor_result_value):
            raise SystemsHarnessError(
                "predecessor result retains a system_violation and is not "
                "replacement-eligible"
            )
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
        _reject_symlink_components(
            evidence_path_input, label="replacement evidence"
        )
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
            job_token = re.search(
                rf"(?<![0-9]){re.escape(job_id)}(?![0-9])", retained
            )
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
    canonical_receipt = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return {
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


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a staged directory without replacing any destination."""

    library = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform.startswith("linux"):
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise SystemsHarnessError(
                "atomic no-replace directory publication requires renameat2"
            )
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        status = renameat2(
            -100,
            source_bytes,
            -100,
            destination_bytes,
            1,
        )
    elif sys.platform == "darwin":
        renamex_np = getattr(library, "renamex_np", None)
        if renamex_np is None:
            raise SystemsHarnessError(
                "atomic no-replace directory publication requires renamex_np"
            )
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        status = renamex_np(source_bytes, destination_bytes, 0x00000004)
    else:
        raise SystemsHarnessError(
            "atomic no-replace directory publication is unsupported on this platform"
        )
    if status != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise SystemsHarnessError(
                f"attempt directory already exists and is immutable: {destination}"
            )
        raise SystemsHarnessError(
            f"could not atomically publish attempt directory: {os.strerror(error)}"
        )


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
            Path("launch.json"),
            Path("plan.json"),
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
                raise SystemsHarnessError("invalid prelaunch evidence copy specification")
            relative = Path(str(item["retained_path"]))
            if (
                not relative.parts
                or relative.is_absolute()
                or ".." in relative.parts
                or relative in reserved_paths
                or relative in retained_paths
            ):
                raise SystemsHarnessError("prelaunch evidence path escapes attempt root")
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
        self.root.parent.mkdir(parents=True, exist_ok=True)
        if self.root.exists() or self.root.is_symlink():
            raise SystemsHarnessError(
                f"attempt directory already exists and is immutable: {self.root}"
            )
        staging_parent = self.root.parent.with_name(
            f".{self.root.parent.name}.staging"
        )
        if staging_parent.is_symlink():
            raise SystemsHarnessError(
                f"attempt staging root must not be a symlink: {staging_parent}"
            )
        staging_parent.mkdir(parents=True, exist_ok=True)
        required_staging_bytes = sum(
            int(item["bytes"]) for item in validated_copies
        )
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
            _exclusive_json(staging / "plan.json", manifest.get("plan", []))
            _exclusive_empty(staging / "units.jsonl")

            if capture_process_streams:
                # Open and duplicate every descriptor before the immutable launch
                # exists.  After launch creation only dup2 and the same-filesystem
                # staging rename remain, so any setup failure leaves no claimed raw
                # attempt ID.
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
            _rename_directory_noreplace(staging, self.root)
        except BaseException:
            if capture_process_streams and saved_descriptors:
                for descriptor, saved in saved_descriptors.items():
                    try:
                        os.dup2(saved, descriptor)
                    except OSError:
                        pass
            for descriptor in (*target_descriptors.values(), *saved_descriptors.values()):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            shutil.rmtree(staging, ignore_errors=True)
            raise
        else:
            for descriptor in (*target_descriptors.values(), *saved_descriptors.values()):
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
            with self._journal_lock, (self.root / "units.jsonl").open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._terminal[key] = {
                "status": status,
                "record": str(path.relative_to(self.root)),
                "sha256": record_sha256,
            }
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
            for status in (
                (final.get("global_outcomes") or {}).get("statuses") or []
            )
        )
        abort_payload = dict(final.get("abort") or {})
        abort_system_violation = (
            abort_payload.get("status") == "system_violation"
            or (
                abort_payload.get("original_abort_classification") or {}
            ).get("status")
            == "system_violation"
        )
        final["planned_unit_count"] = len(self._plan_keys)
        final["terminal_unit_count"] = len(self._terminal)
        final["all_planned_units_terminal"] = complete
        final["complete_plan"] = complete
        final["unit_status_histogram"] = dict(sorted(status_histogram.items()))
        final["system_violation_units"] = (
            int(status_histogram.get("system_violation", 0))
            + global_system_violations
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
        _exclusive_json(self.root / "result.json", final)
        return final
