#!/usr/bin/env python3
"""Validate and reduce immutable amendment-007/008/009 systems attempts."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
from collections import Counter, defaultdict
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from experiments.eacl2027 import run_scaling_faults as systems
from experiments.eacl2027 import scaling_faults_attempts as attempts_contract
from experiments.eacl2027 import scaling_faults_runtime as runtime_contract


REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_VERSION = "protocol-v3-amendment-007-systems-reducer-v1"
COMPONENT_ANALYSIS_ID = systems.FORMAL_COMPONENT_ANALYSIS_ID
ANALYSIS_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
FORMAL_ATTEMPT_PATTERN = re.compile(
    r"(?P<prefix>[a-z0-9][a-z0-9._-]{0,59})-r(?P<ordinal>[0-9]{2})"
)
FORMAL_COMPONENT_COUNTS = {"matrix": 288, "soak": 1, "offline": 1, "faults": 140}
FORMAL_R03_COMPONENT_COUNTS = dict(FORMAL_COMPONENT_COUNTS)
PROTOCOL_PATHS_007 = (
    "experiments/eacl2027/protocol-v3.json",
    "experiments/eacl2027/protocol-v3-amendment-001.json",
    "experiments/eacl2027/protocol-v3-amendment-002.json",
    "experiments/eacl2027/protocol-v3-amendment-003.json",
    "experiments/eacl2027/protocol-v3-amendment-004.json",
    "experiments/eacl2027/protocol-v3-amendment-005.json",
    "experiments/eacl2027/protocol-v3-amendment-006.json",
    "experiments/eacl2027/protocol-v3-amendment-007.json",
)
PROTOCOL_PATHS_008 = (
    *PROTOCOL_PATHS_007,
    "experiments/eacl2027/protocol-v3-amendment-008.json",
)
PROTOCOL_PATHS_009 = (
    *PROTOCOL_PATHS_008,
    "experiments/eacl2027/protocol-v3-amendment-009.json",
)
PROTOCOL_PATHS_010 = (
    *PROTOCOL_PATHS_009,
    "experiments/eacl2027/protocol-v3-amendment-010.json",
)
PROTOCOL_PATHS_011 = (
    *PROTOCOL_PATHS_010,
    "experiments/eacl2027/protocol-v3-amendment-011.json",
)
PROTOCOL_PATHS_012 = (
    *PROTOCOL_PATHS_011,
    "experiments/eacl2027/protocol-v3-amendment-012.json",
)
PROTOCOL_PATHS_013 = (
    *PROTOCOL_PATHS_012,
    "experiments/eacl2027/protocol-v3-amendment-013.json",
)
PROTOCOL_PATHS_014 = (
    *PROTOCOL_PATHS_013,
    "experiments/eacl2027/protocol-v3-amendment-014.json",
)
PROTOCOL_PATHS_015 = (
    *PROTOCOL_PATHS_014,
    "experiments/eacl2027/protocol-v3-amendment-015.json",
)
PROTOCOL_PATHS_016 = (
    *PROTOCOL_PATHS_015,
    "experiments/eacl2027/protocol-v3-amendment-016.json",
)
# Backward-compatible name for the amendment-007 single-attempt reducer.
PROTOCOL_PATHS = PROTOCOL_PATHS_007
TERMINAL_STATUSES = frozenset(
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
PRIMARY_ELIGIBLE_STATUSES = frozenset({"completed", "system_violation"})
RERUN_ELIGIBLE_ATTEMPT_STATUSES = frozenset(
    {"incomplete_harness_error", "incomplete_infrastructure_error"}
)
REDUCER_CONFIG = {
    "version": ANALYSIS_VERSION,
    "matrix_plan_component": "matrix",
    "matrix_reducer": "run_scaling_faults.reduce_matrix_attempts",
    "component_order": ["matrix", "soak", "offline", "faults"],
    "primary_eligible_unit_statuses": sorted(PRIMARY_ELIGIBLE_STATUSES),
    "terminal_statuses": sorted(TERMINAL_STATUSES),
    "numeric_promotion": "only_complete_primary_eligible_attempt",
    "formal_component_counts": FORMAL_COMPONENT_COUNTS,
    "outcome_aware_r01_overlay": "superseded_premeasurement_harness_error",
    "replacement_policy": (
        "launch order; only an immutable pre-launch replacement receipt for an "
        "earlier positively evidenced harness/infrastructure failure may be crossed"
    ),
}
COMPONENT_REDUCER_CONFIG = {
    "version": COMPONENT_ANALYSIS_ID,
    "base_reducer_version": ANALYSIS_VERSION,
    "component_order": ["matrix", "soak", "offline", "faults"],
    "full_plan_unit_count": 430,
    "r08_primary_unit_count": 430,
    "r02_partial_sensitivity_terminal_count": 279,
    "primary_source_attempt_id": "formal-v3-20260831t051023z-r08",
    "ordered_membership_sha256": systems.FORMAL_FULL_PLAN_MEMBERSHIP_SHA256,
    "primary_eligible_unit_statuses": sorted(PRIMARY_ELIGIBLE_STATUSES),
    "terminal_statuses": sorted(TERMINAL_STATUSES),
    "numeric_promotion": "only_complete_exact_r08_whole_attempt",
    "sensitivity": "all_raw_r02_partial_rows_without_source_selection",
    "raw_status_policy": "preserve_r01_r02_r03_r04_r05_r06_r07_r08_without_relabeling",
}

_FORMAL_STUDY_MODE = "formal_protocol_v3_amendment_007"
_FORMAL_PROTOCOL_STATUS = _FORMAL_STUDY_MODE
_COMPONENT_STUDY_MODE = "formal_protocol_v3_amendment_008"
_SOCKET_ENDPOINT_MAX_BYTES = 107


class AnalysisValidationError(ValueError):
    """An immutable attempt failed a binding or ledger check."""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(path: Path) -> str:
    return _stream_file_identity(path)[1]


def _stream_file_identity(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
            closed_over = os.fstat(handle.fileno())
    except OSError as exc:
        raise AnalysisValidationError(f"could not hash {path}: {exc}") from exc
    if (
        opened.st_dev != closed_over.st_dev
        or opened.st_ino != closed_over.st_ino
        or opened.st_size != closed_over.st_size
        or byte_count != closed_over.st_size
    ):
        raise AnalysisValidationError(f"file changed while hashing: {path}")
    return byte_count, digest.hexdigest()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AnalysisValidationError(f"could not read {path}: {exc}") from exc


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AnalysisValidationError(f"{label} must be a JSON object")
    return value


_PUBLICATION_METHODS = frozenset(
    {"native_no_replace", "hardlink_claim_then_posix_rename"}
)
_FORMAL_NATIVE_PUBLICATION_PRIMITIVE = "renameat2_RENAME_NOREPLACE"
# Formal execution is pinned to Linux on watgpu.  Keep this mapping independent
# of the reducer host so a Linux receipt remains valid when analyzed on macOS.
_LINUX_NATIVE_UNSUPPORTED_ERRNOS = {
    "EINVAL": 22,
    "ENOSYS": 38,
    "ENOTSUP": 95,
    "EOPNOTSUPP": 95,
}


def _expected_publication_claim_path(root: Path) -> Path:
    staging_parent = root.parent.with_name(f".{root.parent.name}.staging")
    return staging_parent / ".publication-claims" / f"{root.name}.launch.json"


def _validate_publication(root: Path) -> dict[str, Any]:
    """Validate the immutable publication method and any NFS claim guard."""

    publication_path = root / "publication.json"
    if publication_path.is_symlink() or not publication_path.is_file():
        raise AnalysisValidationError(
            "publication.json is missing, non-regular, or a symlink"
        )
    publication = _require_dict(_load_json(publication_path), "publication.json")
    if set(publication) != {
        "schema_version",
        "destination",
        "method",
        "native_primitive",
        "native_unsupported",
        "claim",
    }:
        raise AnalysisValidationError("publication.json has unexpected fields")
    if type(publication.get("schema_version")) is not int or (
        publication["schema_version"] != 1
    ):
        raise AnalysisValidationError("publication.json schema_version must equal 1")
    if publication.get("destination") != str(root):
        raise AnalysisValidationError(
            "publication destination differs from the exact attempt root"
        )
    method = publication.get("method")
    primitive = publication.get("native_primitive")
    if method not in _PUBLICATION_METHODS:
        raise AnalysisValidationError("publication method is invalid")
    if primitive != _FORMAL_NATIVE_PUBLICATION_PRIMITIVE:
        raise AnalysisValidationError(
            "formal publication must use the pinned Linux renameat2 primitive"
        )

    unsupported = publication.get("native_unsupported")
    claim_value = publication.get("claim")
    expected_claim = _expected_publication_claim_path(root)
    if method == "native_no_replace":
        if unsupported is not None or claim_value is not None:
            raise AnalysisValidationError(
                "native publication must not declare fallback evidence"
            )
        if expected_claim.parent.is_symlink():
            raise AnalysisValidationError(
                "native publication claim namespace is a symlink"
            )
        if expected_claim.exists() or expected_claim.is_symlink():
            raise AnalysisValidationError(
                "native publication has an unexpected fallback claim"
            )
        return publication

    unsupported_receipt = _require_dict(
        unsupported, "fallback native unsupported receipt"
    )
    if set(unsupported_receipt) != {"errno", "name"}:
        raise AnalysisValidationError(
            "fallback native unsupported receipt has unexpected fields"
        )
    error_number = unsupported_receipt.get("errno")
    error_name = unsupported_receipt.get("name")
    if (
        type(error_number) is not int
        or not isinstance(error_name, str)
        or error_name not in _LINUX_NATIVE_UNSUPPORTED_ERRNOS
        or _LINUX_NATIVE_UNSUPPORTED_ERRNOS.get(error_name) != error_number
    ):
        raise AnalysisValidationError(
            "fallback is not bound to an allowed unsupported native errno"
        )

    claim = _require_dict(claim_value, "fallback publication claim")
    if set(claim) != {"path", "artifact", "bytes", "sha256"}:
        raise AnalysisValidationError(
            "fallback publication claim has unexpected fields"
        )
    if claim.get("path") != str(expected_claim):
        raise AnalysisValidationError(
            "fallback publication claim path differs from the derived path"
        )
    if claim.get("artifact") != "launch.json":
        raise AnalysisValidationError(
            "fallback publication claim must bind launch.json"
        )
    byte_count = claim.get("bytes")
    digest = claim.get("sha256")
    if (
        type(byte_count) is not int
        or byte_count < 0
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise AnalysisValidationError(
            "fallback publication claim byte identity is invalid"
        )

    # Resolve no part of the declared path before checking it: a lexical
    # symlink in the staging/claim chain must not be normalized away.
    for candidate in (
        expected_claim.parent.parent,
        expected_claim.parent,
        expected_claim,
    ):
        if candidate.is_symlink():
            raise AnalysisValidationError(
                "fallback publication claim path contains a symlink"
            )
    expected_owner = root.parent.stat(follow_symlinks=False).st_uid
    for label, directory in (
        ("attempt root", root.parent),
        ("attempt staging root", expected_claim.parent.parent),
        ("publication claims root", expected_claim.parent),
    ):
        if not directory.is_dir():
            raise AnalysisValidationError(f"fallback {label} is not a directory")
        observed = directory.stat(follow_symlinks=False)
        if observed.st_uid != expected_owner or stat.S_IMODE(observed.st_mode) != 0o700:
            raise AnalysisValidationError(
                f"fallback {label} is not owner-exclusive mode 0700"
            )
    if not expected_claim.is_file():
        raise AnalysisValidationError(
            "fallback publication claim is missing or non-regular"
        )
    launch_path = root / "launch.json"
    if launch_path.is_symlink() or not launch_path.is_file():
        raise AnalysisValidationError(
            "fallback publication launch artifact is missing or non-regular"
        )
    claim_bytes, claim_digest = _stream_file_identity(expected_claim)
    launch_bytes, launch_digest = _stream_file_identity(launch_path)
    if (
        byte_count != claim_bytes
        or digest != claim_digest
        or claim_bytes != launch_bytes
        or claim_digest != launch_digest
    ):
        raise AnalysisValidationError(
            "fallback publication claim does not match launch bytes"
        )
    claim_stat = expected_claim.stat(follow_symlinks=False)
    launch_stat = launch_path.stat(follow_symlinks=False)
    if (
        claim_stat.st_dev != launch_stat.st_dev
        or claim_stat.st_ino != launch_stat.st_ino
    ):
        raise AnalysisValidationError(
            "fallback publication claim is not a hard link to launch.json"
        )
    return publication


_HOOK_CONTRACT_FIELDS = frozenset(
    {
        "returncode",
        "stdout",
        "stderr",
        "timed_out",
        "contract_preserved",
        "contract_error",
    }
)
_HOOK_TIMING_FIELDS = frozenset(
    {
        "started_monotonic_ns",
        "exited_monotonic_ns",
        "latency_ns",
        "latency_ms",
    }
)


def _is_exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _hook_contract_preserved(hook: Mapping[str, Any]) -> bool:
    return bool(
        _is_exact_int(hook.get("returncode"))
        and hook.get("returncode") == 0
        and hook.get("stdout") == "{}"
        and hook.get("stderr") == ""
        and hook.get("timed_out") is False
    )


def _validate_hook_projection(
    hook: Mapping[str, Any], label: str, *, expected_full: bool | None = None
) -> None:
    valid_schemas = (
        {_HOOK_CONTRACT_FIELDS | _HOOK_TIMING_FIELDS}
        if expected_full is True
        else {_HOOK_CONTRACT_FIELDS}
        if expected_full is False
        else {_HOOK_CONTRACT_FIELDS, _HOOK_CONTRACT_FIELDS | _HOOK_TIMING_FIELDS}
    )
    if frozenset(hook) not in valid_schemas:
        raise AnalysisValidationError(f"{label} has an invalid hook projection schema")
    if (
        not isinstance(hook.get("stdout"), str)
        or not isinstance(hook.get("stderr"), str)
        or not isinstance(hook.get("timed_out"), bool)
        or not isinstance(hook.get("contract_preserved"), bool)
        or not isinstance(hook.get("contract_error"), str)
        or (
            hook.get("returncode") is not None
            and not _is_exact_int(hook.get("returncode"))
        )
    ):
        raise AnalysisValidationError(f"{label} has invalid hook process fields")
    expected_contract = _hook_contract_preserved(hook)
    if hook.get("contract_preserved") is not expected_contract:
        raise AnalysisValidationError(
            f"{label} contract_preserved is not derived from process output"
        )
    if bool(hook.get("contract_error")) is expected_contract:
        raise AnalysisValidationError(
            f"{label} contract_error disagrees with the derived hook contract"
        )
    present_timing = _HOOK_TIMING_FIELDS.intersection(hook)
    if not present_timing:
        return
    if present_timing != _HOOK_TIMING_FIELDS:
        raise AnalysisValidationError(f"{label} has an incomplete timing projection")
    started = hook.get("started_monotonic_ns")
    exited = hook.get("exited_monotonic_ns")
    latency = hook.get("latency_ns")
    if (
        not _is_exact_int(started)
        or not _is_exact_int(exited)
        or not _is_exact_int(latency)
        or started < 0
        or exited < started
        or latency != exited - started
        or hook.get("latency_ms") != round(latency / 1_000_000, 3)
    ):
        raise AnalysisValidationError(
            f"{label} monotonic hook latency is not recomputed"
        )


def _validate_hook_parent(parent: Mapping[str, Any], hook_key: str, label: str) -> None:
    hook = _require_dict(parent.get(hook_key), f"{label} {hook_key}")
    expected_full = True if hook_key == "faulting_hook" else None
    if (
        hook_key == "hook"
        and "hook_exit_ms" in parent
        and not {
            "hook_started_monotonic_ns",
            "hook_exited_monotonic_ns",
        }.issubset(parent)
    ):
        expected_full = True
    _validate_hook_projection(hook, f"{label} {hook_key}", expected_full=expected_full)
    prefix = "faulting_hook" if hook_key == "faulting_hook" else "hook"
    contract_name = f"{prefix}_contract_preserved"
    latency_name = f"{prefix}_exit_ms"
    if contract_name in parent and parent.get(
        contract_name
    ) is not _hook_contract_preserved(hook):
        raise AnalysisValidationError(
            f"{label} {contract_name} disagrees with its hook projection"
        )
    if latency_name in parent and "latency_ms" in hook:
        if parent.get(latency_name) != hook.get("latency_ms"):
            raise AnalysisValidationError(
                f"{label} {latency_name} disagrees with its hook projection"
            )

    outer_timing = {
        "hook_started_monotonic_ns",
        "hook_exited_monotonic_ns",
        "hook_exit_ns",
        "hook_exit_ms",
    }
    present_outer = outer_timing.intersection(parent)
    if not present_outer:
        return
    if present_outer != outer_timing:
        raise AnalysisValidationError(f"{label} has incomplete outer hook timing")
    started = parent.get("hook_started_monotonic_ns")
    exited = parent.get("hook_exited_monotonic_ns")
    latency = parent.get("hook_exit_ns")
    if (
        not _is_exact_int(started)
        or not _is_exact_int(exited)
        or not _is_exact_int(latency)
        or started < 0
        or exited < started
        or latency != exited - started
        or parent.get("hook_exit_ms") != round(latency / 1_000_000, 3)
    ):
        raise AnalysisValidationError(
            f"{label} outer monotonic hook latency is not recomputed"
        )
    if "started_monotonic_ns" in hook and (
        hook.get("started_monotonic_ns") != started
        or hook.get("exited_monotonic_ns") != exited
        or hook.get("latency_ns") != latency
    ):
        raise AnalysisValidationError(
            f"{label} outer timing disagrees with its hook projection"
        )
    if "submitted_monotonic_ns" not in parent:
        return
    submitted = parent.get("submitted_monotonic_ns")
    if not _is_exact_int(submitted) or not 0 <= submitted <= started:
        raise AnalysisValidationError(
            f"{label} hook timestamps regress before submission"
        )
    derived = {
        "executor_queue_ns": started - submitted,
        "submission_to_hook_exit_ns": exited - submitted,
    }
    for name, expected in derived.items():
        if name in parent and parent.get(name) != expected:
            raise AnalysisValidationError(f"{label} {name} is not recomputed")
        display_name = name.removesuffix("_ns") + "_ms"
        if display_name in parent and parent.get(display_name) != round(
            expected / 1_000_000, 3
        ):
            raise AnalysisValidationError(f"{label} {display_name} is not recomputed")


def _validate_embedded_hook_projections(value: Any, label: str) -> None:
    def visit(node: Any, path: str) -> None:
        if isinstance(node, dict):
            if _HOOK_CONTRACT_FIELDS.issubset(node):
                _validate_hook_projection(node, path)
            for hook_key in ("hook", "faulting_hook"):
                if isinstance(node.get(hook_key), dict):
                    _validate_hook_parent(node, hook_key, path)
            hooks = node.get("hooks")
            if "hook_contracts_preserved" in node:
                if not isinstance(hooks, list) or not all(
                    isinstance(item, dict) for item in hooks
                ):
                    raise AnalysisValidationError(f"{path}.hooks is invalid")
                for index, hook in enumerate(hooks):
                    _validate_hook_projection(
                        hook, f"{path}.hooks[{index}]", expected_full=True
                    )
                expected = len(hooks) == 2 and all(
                    _hook_contract_preserved(item) for item in hooks
                )
                if node.get("hook_contracts_preserved") is not expected:
                    raise AnalysisValidationError(
                        f"{path} hook_contracts_preserved is not recomputed"
                    )
            for name, item in node.items():
                visit(item, f"{path}.{name}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}[{index}]")

    visit(value, label)


_EVALUATION_DETAIL_COUNTS = {
    "loss_count": "missing",
    "unexpected_count": "unexpected",
    "cross_project_contamination_count": "cross_project_contamination",
    "failed_count": "failed",
    "running_count": "running",
    "provenance_mismatch_count": "provenance_mismatches",
}
_FINDING_DETAIL_COUNTS = {
    "loss_count": "missing",
    "unexpected_count": "unexpected",
    "wrong_project_count": "wrong_project",
    "finding_id_mismatch_count": "finding_id_mismatches",
    "evaluation_id_mismatch_count": "evaluation_id_mismatches",
}


def _nonnegative_count(value: Any, label: str) -> int:
    if not _is_exact_int(value) or value < 0:
        raise AnalysisValidationError(f"{label} must be a nonnegative integer")
    return value


def _duplicate_excess(value: Any, label: str) -> int:
    duplicates = value
    if not isinstance(duplicates, list):
        raise AnalysisValidationError(f"{label} must be a list")
    excess = 0
    for item in duplicates:
        if not isinstance(item, dict):
            raise AnalysisValidationError(f"{label} contains a non-object detail")
        count = _nonnegative_count(item.get("count"), f"{label} count")
        if count <= 1:
            raise AnalysisValidationError(f"{label} contains a non-duplicate detail")
        excess += count - 1
    return excess


def _validate_accounting_projection(accounting: Mapping[str, Any], label: str) -> None:
    if "evaluations_expected" in accounting:
        count_fields = {
            "evaluations_expected",
            "evaluations_observed_for_expected_keys",
            "expected_keys_observed",
            "loss_count",
            "duplicate_count",
            "unexpected_count",
            "cross_project_contamination_count",
            "failed_count",
            "running_count",
            "provenance_mismatch_count",
        }
        for name in count_fields.intersection(accounting):
            _nonnegative_count(accounting[name], f"{label}.{name}")
        for count_name, details_name in _EVALUATION_DETAIL_COUNTS.items():
            if count_name in accounting and details_name in accounting:
                details = accounting[details_name]
                if not isinstance(details, list) or accounting[count_name] != len(
                    details
                ):
                    raise AnalysisValidationError(
                        f"{label}.{count_name} disagrees with {details_name}"
                    )
        if "duplicates" in accounting and "duplicate_count" in accounting:
            if accounting["duplicate_count"] != _duplicate_excess(
                accounting["duplicates"], f"{label}.duplicates"
            ):
                raise AnalysisValidationError(
                    f"{label}.duplicate_count disagrees with duplicates"
                )
        detailed = all(
            name in accounting
            for name in (*_EVALUATION_DETAIL_COUNTS.values(), "duplicates")
        )
        if detailed:
            expected = _nonnegative_count(
                accounting.get("evaluations_expected"),
                f"{label}.evaluations_expected",
            )
            observed_keys = _nonnegative_count(
                accounting.get("expected_keys_observed"),
                f"{label}.expected_keys_observed",
            )
            observed_rows = _nonnegative_count(
                accounting.get("evaluations_observed_for_expected_keys"),
                f"{label}.evaluations_observed_for_expected_keys",
            )
            if observed_keys != expected - int(accounting["loss_count"]):
                raise AnalysisValidationError(
                    f"{label}.expected_keys_observed is not reconstructed"
                )
            if observed_rows != observed_keys + int(accounting["duplicate_count"]):
                raise AnalysisValidationError(
                    f"{label}.evaluations_observed_for_expected_keys is not reconstructed"
                )
            result_counts = accounting.get("result_counts")
            if not isinstance(result_counts, dict) or any(
                not isinstance(name, str) or not _is_exact_int(count) or count < 0
                for name, count in result_counts.items()
            ):
                raise AnalysisValidationError(f"{label}.result_counts is invalid")
            if sum(result_counts.values()) != observed_rows:
                raise AnalysisValidationError(
                    f"{label}.result_counts disagrees with observed evaluations"
                )

    if "findings_expected" in accounting:
        count_fields = {
            "findings_expected",
            "findings_observed_for_expected_keys",
            "loss_count",
            "duplicate_count",
            "unexpected_count",
            "wrong_project_count",
            "finding_id_mismatch_count",
            "evaluation_id_mismatch_count",
        }
        for name in count_fields.intersection(accounting):
            _nonnegative_count(accounting[name], f"{label}.{name}")
        for count_name, details_name in _FINDING_DETAIL_COUNTS.items():
            if count_name in accounting and details_name in accounting:
                details = accounting[details_name]
                if not isinstance(details, list) or accounting[count_name] != len(
                    details
                ):
                    raise AnalysisValidationError(
                        f"{label}.{count_name} disagrees with {details_name}"
                    )
        if "duplicates" in accounting and "duplicate_count" in accounting:
            if accounting["duplicate_count"] != _duplicate_excess(
                accounting["duplicates"], f"{label}.duplicates"
            ):
                raise AnalysisValidationError(
                    f"{label}.duplicate_count disagrees with duplicates"
                )


def _validate_fault_record_scan(scan: Mapping[str, Any], label: str) -> None:
    records = scan.get("records")
    if not isinstance(records, list) or not all(
        isinstance(item, dict) for item in records
    ):
        raise AnalysisValidationError(f"{label}.records is invalid")
    started = scan.get("started_monotonic_ns")
    finished = scan.get("finished_monotonic_ns")
    if (
        not _is_exact_int(started)
        or not _is_exact_int(finished)
        or started < 0
        or finished < started
    ):
        raise AnalysisValidationError(f"{label} scan timestamps are invalid")
    expected_counts = dict(
        sorted(Counter(str(item.get("input_sha256", "")) for item in records).items())
    )
    expected_terminal = sum(
        str(item.get("status", "")) in {"completed", "failed"} for item in records
    )
    canonical = sorted(records, key=_canonical_json_bytes)
    if (
        scan.get("count") != len(records)
        or scan.get("terminal_count") != expected_terminal
        or scan.get("input_sha256_counts") != expected_counts
        or scan.get("canonical_projection_sha256")
        != _sha256_bytes(_canonical_json_bytes(canonical))
    ):
        raise AnalysisValidationError(
            f"{label} counts/digest are not reconstructed from records"
        )


def _validate_embedded_accounting(value: Any, label: str, *, fault: bool) -> None:
    fault_scan_fields = {
        "started_monotonic_ns",
        "finished_monotonic_ns",
        "count",
        "terminal_count",
        "input_sha256_counts",
        "canonical_projection_sha256",
        "records",
    }

    def visit(node: Any, path: str) -> None:
        if isinstance(node, dict):
            if "evaluations_expected" in node or "findings_expected" in node:
                _validate_accounting_projection(node, path)
            if fault and fault_scan_fields.issubset(node):
                _validate_fault_record_scan(node, path)
            for name, item in node.items():
                visit(item, f"{path}.{name}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}[{index}]")

    visit(value, label)


def _component(item: Mapping[str, Any]) -> str:
    return str(item.get("component") or "matrix")


def _unit_id(item: Mapping[str, Any]) -> str:
    return str(item.get("unit_id") or item.get("condition_id") or "")


def _checked_file(root: Path, relative: str) -> Path:
    declared = Path(relative)
    if declared.is_absolute() or ".." in declared.parts:
        raise AnalysisValidationError(f"terminal path must be relative: {relative}")
    lexical = root / declared
    current = root
    for part in declared.parts:
        current = current / part
        if current.is_symlink():
            raise AnalysisValidationError(f"symlink in terminal path: {relative}")
    resolved = lexical.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AnalysisValidationError(
            f"terminal record escapes attempt directory: {relative}"
        ) from exc
    if not resolved.is_file():
        raise AnalysisValidationError(f"terminal record is missing: {relative}")
    return resolved


def _checked_receipt_file(root: Path, declared_value: str) -> Path:
    declared = Path(declared_value)
    if not declared_value or ".." in declared.parts:
        raise AnalysisValidationError(
            f"incremental receipt path must be nonempty and confined: {declared_value}"
        )
    lexical = declared if declared.is_absolute() else root / declared
    try:
        lexical_relative = lexical.relative_to(root)
    except ValueError as exc:
        raise AnalysisValidationError(
            f"incremental receipt path escapes attempt: {declared_value}"
        ) from exc
    current = root
    for part in lexical_relative.parts:
        current = current / part
        if current.is_symlink():
            raise AnalysisValidationError(
                f"symlink in incremental receipt path: {declared_value}"
            )
    resolved = lexical.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AnalysisValidationError(
            f"incremental receipt path escapes attempt: {declared_value}"
        ) from exc
    if not resolved.is_file():
        raise AnalysisValidationError(
            f"incremental receipt file is missing: {declared_value}"
        )
    return resolved


def _validated_jsonl(
    root: Path, receipt_value: Any, label: str
) -> tuple[dict[str, Any], list[Any]]:
    receipt = _require_dict(receipt_value, label)
    original_path = str(receipt.get("path", ""))
    if not original_path:
        raise AnalysisValidationError(f"{label} lacks original path provenance")
    relative_value = receipt.get("attempt_relative_path")
    path = _checked_receipt_file(
        root,
        str(relative_value) if relative_value is not None else original_path,
    )
    raw = path.read_bytes()
    if receipt.get("bytes") != len(raw) or receipt.get("sha256") != _sha256_bytes(raw):
        raise AnalysisValidationError(f"{label} byte/hash receipt mismatch")
    try:
        lines = raw.decode("utf-8").splitlines()
        values = [json.loads(line) for line in lines if line]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisValidationError(f"{label} is not valid JSONL: {exc}") from exc
    if receipt.get("records") != sum(bool(line) for line in lines):
        raise AnalysisValidationError(f"{label} record count mismatch")
    return (
        {
            "path": str(path.relative_to(root)),
            "original_path": original_path,
            "records": receipt["records"],
            "bytes": receipt["bytes"],
            "sha256": receipt["sha256"],
        },
        values,
    )


def _validated_binary_receipt(
    root: Path, receipt_value: Any, label: str
) -> tuple[dict[str, Any], bytes]:
    receipt = _require_dict(receipt_value, label)
    if set(receipt) not in (
        {"path", "bytes", "sha256"},
        {"path", "attempt_relative_path", "bytes", "sha256"},
    ):
        raise AnalysisValidationError(f"{label} has an invalid receipt schema")
    original_path = str(receipt.get("path", ""))
    if not original_path:
        raise AnalysisValidationError(f"{label} lacks original path provenance")
    relative = receipt.get("attempt_relative_path")
    path = _checked_receipt_file(
        root, str(relative) if relative is not None else original_path
    )
    raw = path.read_bytes()
    if receipt.get("bytes") != len(raw) or receipt.get("sha256") != _sha256_bytes(raw):
        raise AnalysisValidationError(f"{label} byte/hash receipt mismatch")
    return receipt, raw


def _validate_jsonl_receipt(
    root: Path, receipt_value: Any, label: str
) -> dict[str, Any]:
    summary, _values = _validated_jsonl(root, receipt_value, label)
    return summary


def _validate_sources(
    identity: Mapping[str, Any],
    *,
    legacy_r01: Mapping[str, Any] | None = None,
    runner_anchor: Mapping[str, Any] | None = None,
    protocol_paths: Sequence[str] | None = None,
) -> list[dict[str, str]]:
    raw_documents = identity.get("protocol_documents")
    if not isinstance(raw_documents, list) or not all(
        isinstance(item, dict) for item in raw_documents
    ):
        raise AnalysisValidationError("launch identity lacks protocol_documents")
    documents = [
        {"path": str(item.get("path", "")), "sha256": str(item.get("sha256", ""))}
        for item in raw_documents
    ]
    expected_paths = list(
        protocol_paths
        if protocol_paths is not None
        else PROTOCOL_PATHS[:-1]
        if legacy_r01 is not None
        else PROTOCOL_PATHS
    )
    if [item["path"] for item in documents] != expected_paths:
        raise AnalysisValidationError("launch does not bind the ordered protocol set")
    for item in documents:
        path = (REPO_ROOT / item["path"]).resolve()
        try:
            path.relative_to(REPO_ROOT)
        except ValueError as exc:
            raise AnalysisValidationError("protocol path escapes repository") from exc
        if not path.is_file() or _sha256(path) != item["sha256"]:
            raise AnalysisValidationError(f"protocol hash mismatch: {item['path']}")
    runner = _require_dict(identity.get("runner"), "launch identity runner")
    anchor = runner_anchor or legacy_r01
    if anchor is not None:
        if runner != {
            "path": "experiments/eacl2027/run_scaling_faults.py",
            "sha256": anchor["runner_sha256"],
            "git_blob": anchor["runner_git_blob"],
        }:
            raise AnalysisValidationError(
                "historical runner identity differs from anchor"
            )
    else:
        imported = Path(systems.__file__).resolve()
        if runner.get("path") != str(imported.relative_to(REPO_ROOT)):
            raise AnalysisValidationError(
                "launch runner path differs from imported reducer"
            )
        if runner.get("sha256") != _sha256(imported):
            raise AnalysisValidationError(
                "launch runner hash differs from imported reducer"
            )
        runner_bytes = imported.read_bytes()
        runner_blob = hashlib.sha1(
            f"blob {len(runner_bytes)}\0".encode("ascii") + runner_bytes,
            usedforsecurity=False,
        ).hexdigest()
        if runner.get("git_blob") != runner_blob:
            raise AnalysisValidationError(
                "launch runner Git blob differs from exact bytes"
            )
    return documents


def _is_anchored_r01(
    raw_attempt_id: str, contract: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    repair = _require_dict(contract.get("outcome_aware_repair"), "amendment-007 repair")
    if raw_attempt_id != repair.get("predecessor_raw_attempt_id"):
        return None
    return _require_dict(repair.get("predecessor_launch"), "amendment-007 r01 anchor")


def _load_amendment_008() -> dict[str, Any] | None:
    path = REPO_ROOT / PROTOCOL_PATHS_008[-1]
    if not path.is_file() or path.is_symlink():
        return None
    try:
        value = attempts_contract._strict_json_object(
            path.read_text(encoding="utf-8"), label="amendment 008"
        )
    except (OSError, UnicodeDecodeError, attempts_contract.SystemsHarnessError) as exc:
        raise AnalysisValidationError(str(exc)) from exc
    if (
        value.get("amendment_id") != "protocol-v3-amendment-008"
        or not str(value.get("freeze_state", "")).startswith("frozen_")
        or "draft" in str(value.get("status", "")).lower()
        or attempts_contract._pending_terminal_markers(value)
    ):
        raise AnalysisValidationError("amendment 008 is not a terminal frozen contract")
    try:
        frozen_at = datetime.fromisoformat(
            str(value.get("frozen_utc", "")).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise AnalysisValidationError("amendment 008 frozen_utc is invalid") from exc
    if frozen_at.tzinfo is None or frozen_at > datetime.now(timezone.utc):
        raise AnalysisValidationError(
            "amendment 008 frozen_utc is not a past timestamp"
        )
    correction_path = REPO_ROOT / PROTOCOL_PATHS_009[-1]
    if correction_path.is_symlink() or not correction_path.is_file():
        raise AnalysisValidationError("amendment 009 is unavailable")
    correction = _require_dict(_load_json(correction_path), "amendment 009")
    correction_identity = _require_dict(
        correction.get("effective_protocol_identity"),
        "amendment-009 effective identity",
    )
    if (
        correction.get("amendment_id") != "protocol-v3-amendment-009"
        or correction.get("parent_amendment") != "protocol-v3-amendment-008"
        or not str(correction.get("status", "")).startswith("frozen ")
    ):
        raise AnalysisValidationError("amendment 009 is not frozen")
    value = json.loads(json.dumps(value))
    value["effective_protocol_identity"]["required_git_topology"] = (
        correction_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        correction_identity["interpretation_order"]
    )
    routing_path = REPO_ROOT / PROTOCOL_PATHS_010[-1]
    if routing_path.is_symlink() or not routing_path.is_file():
        raise AnalysisValidationError("amendment 010 is unavailable")
    routing = _require_dict(_load_json(routing_path), "amendment 010")
    routing_identity = _require_dict(
        routing.get("effective_protocol_identity"),
        "amendment-010 effective identity",
    )
    if (
        routing.get("amendment_id") != "protocol-v3-amendment-010"
        or routing.get("parent_amendment") != "protocol-v3-amendment-009"
        or not str(routing.get("status", "")).startswith("frozen ")
    ):
        raise AnalysisValidationError("amendment 010 is not frozen")
    value["effective_protocol_identity"]["required_git_topology"] = (
        routing_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        routing_identity["interpretation_order"]
    )
    prepublication_path = REPO_ROOT / PROTOCOL_PATHS_011[-1]
    if prepublication_path.is_symlink() or not prepublication_path.is_file():
        raise AnalysisValidationError("amendment 011 is unavailable")
    prepublication = _require_dict(
        _load_json(prepublication_path), "amendment 011"
    )
    prepublication_identity = _require_dict(
        prepublication.get("effective_protocol_identity"),
        "amendment-011 effective identity",
    )
    explicit_override = _require_dict(
        prepublication.get("explicit_override"), "amendment-011 explicit override"
    )
    if (
        prepublication.get("amendment_id") != "protocol-v3-amendment-011"
        or prepublication.get("parent_amendment") != "protocol-v3-amendment-010"
        or not str(prepublication.get("status", "")).startswith("frozen ")
        or explicit_override.get("successor_raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R04_ID
    ):
        raise AnalysisValidationError("amendment 011 is not frozen")
    value["effective_protocol_identity"]["required_git_topology"] = (
        prepublication_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        prepublication_identity["interpretation_order"]
    )
    value["prepublication_correction"] = prepublication
    historical_path = REPO_ROOT / PROTOCOL_PATHS_012[-1]
    if historical_path.is_symlink() or not historical_path.is_file():
        raise AnalysisValidationError("amendment 012 is unavailable")
    historical = _require_dict(_load_json(historical_path), "amendment 012")
    historical_identity = _require_dict(
        historical.get("effective_protocol_identity"),
        "amendment-012 effective identity",
    )
    if (
        historical.get("amendment_id") != "protocol-v3-amendment-012"
        or historical.get("parent_amendment") != "protocol-v3-amendment-011"
        or not str(historical.get("status", "")).startswith("frozen ")
    ):
        raise AnalysisValidationError("amendment 012 is not frozen")
    value["effective_protocol_identity"]["required_git_topology"] = (
        historical_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        historical_identity["interpretation_order"]
    )
    value["historical_role_correction"] = historical
    wait_path = REPO_ROOT / PROTOCOL_PATHS_013[-1]
    if wait_path.is_symlink() or not wait_path.is_file():
        raise AnalysisValidationError("amendment 013 is unavailable")
    wait_correction = _require_dict(_load_json(wait_path), "amendment 013")
    wait_identity = _require_dict(
        wait_correction.get("effective_protocol_identity"),
        "amendment-013 effective identity",
    )
    wait_override = _require_dict(
        wait_correction.get("explicit_override"),
        "amendment-013 explicit override",
    )
    if (
        wait_correction.get("amendment_id") != "protocol-v3-amendment-013"
        or wait_correction.get("parent_amendment") != "protocol-v3-amendment-012"
        or not str(wait_correction.get("status", "")).startswith("frozen ")
        or wait_override.get("successor_raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R05_ID
    ):
        raise AnalysisValidationError("amendment 013 is not frozen")
    value["effective_protocol_identity"]["required_git_topology"] = (
        wait_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        wait_identity["interpretation_order"]
    )
    value["supervisor_wait_correction"] = wait_correction
    host_path = REPO_ROOT / PROTOCOL_PATHS_014[-1]
    if host_path.is_symlink() or not host_path.is_file():
        raise AnalysisValidationError("amendment 014 is unavailable")
    host_routing = _require_dict(_load_json(host_path), "amendment 014")
    host_identity = _require_dict(
        host_routing.get("effective_protocol_identity"),
        "amendment-014 effective identity",
    )
    host_override = _require_dict(
        host_routing.get("explicit_override"),
        "amendment-014 explicit override",
    )
    if (
        host_routing.get("amendment_id") != "protocol-v3-amendment-014"
        or host_routing.get("parent_amendment") != "protocol-v3-amendment-013"
        or not str(host_routing.get("status", "")).startswith("frozen ")
        or host_override.get("successor_raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R06_ID
        or host_override.get("requested_partition") != "ALL"
        or host_override.get("requested_node") != "watgpu108"
    ):
        raise AnalysisValidationError("amendment 014 is not frozen")
    value["effective_protocol_identity"]["required_git_topology"] = (
        host_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        host_identity["interpretation_order"]
    )
    value["host_routing_correction"] = host_routing
    cache_path = REPO_ROOT / PROTOCOL_PATHS_015[-1]
    if cache_path.is_symlink() or not cache_path.is_file():
        raise AnalysisValidationError("amendment 015 is unavailable")
    cache_isolation = _require_dict(_load_json(cache_path), "amendment 015")
    cache_identity = _require_dict(
        cache_isolation.get("effective_protocol_identity"),
        "amendment-015 effective identity",
    )
    cache_override = _require_dict(
        cache_isolation.get("explicit_override"),
        "amendment-015 explicit override",
    )
    if (
        cache_isolation.get("amendment_id") != "protocol-v3-amendment-015"
        or cache_isolation.get("parent_amendment") != "protocol-v3-amendment-014"
        or not str(cache_isolation.get("status", "")).startswith("frozen ")
        or cache_override.get("successor_raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R07_ID
        or cache_override.get("requested_partition") != "ALL"
        or cache_override.get("requested_node") != "watgpu108"
    ):
        raise AnalysisValidationError("amendment 015 is not frozen")
    value["effective_protocol_identity"]["required_git_topology"] = (
        cache_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        cache_identity["interpretation_order"]
    )
    value["cache_isolation_correction"] = cache_isolation
    supervisor_path = REPO_ROOT / PROTOCOL_PATHS_016[-1]
    if supervisor_path.is_symlink() or not supervisor_path.is_file():
        raise AnalysisValidationError("amendment 016 is unavailable")
    supervisor_cache = _require_dict(
        _load_json(supervisor_path), "amendment 016"
    )
    supervisor_identity = _require_dict(
        supervisor_cache.get("effective_protocol_identity"),
        "amendment-016 effective identity",
    )
    supervisor_override = _require_dict(
        supervisor_cache.get("explicit_override"),
        "amendment-016 explicit override",
    )
    if (
        supervisor_cache.get("amendment_id") != "protocol-v3-amendment-016"
        or supervisor_cache.get("parent_amendment")
        != "protocol-v3-amendment-015"
        or not str(supervisor_cache.get("status", "")).startswith("frozen ")
        or supervisor_override.get("successor_raw_attempt_id")
        != attempts_contract._COMPONENT_SUCCESSOR_ID
        or supervisor_override.get("requested_partition") != "ALL"
        or supervisor_override.get("requested_node") != "watgpu108"
        or supervisor_override.get("effective_dedicated_cache_root")
        != cache_override.get("dedicated_cache_root")
    ):
        raise AnalysisValidationError("amendment 016 is not frozen")
    value["effective_protocol_identity"]["required_git_topology"] = (
        supervisor_identity["required_git_topology"]
    )
    value["effective_protocol_identity"]["interpretation_order"] = (
        supervisor_identity["interpretation_order"]
    )
    value["supervisor_cache_environment_correction"] = supervisor_cache
    return value


def _is_anchored_r02(
    raw_attempt_id: str, amendment_008: Mapping[str, Any] | None
) -> Mapping[str, Any] | None:
    if (
        amendment_008 is None
        or raw_attempt_id != attempts_contract._COMPONENT_PREDECESSOR_ID
    ):
        return None
    h3 = _require_dict(amendment_008.get("known_at_draft"), "amendment-008 known facts")
    h3 = _require_dict(h3.get("h3"), "amendment-008 H3 anchor")
    runner = _require_dict(h3.get("runner"), "amendment-008 H3 runner")
    return {
        "runner_sha256": runner.get("sha256"),
        "runner_git_blob": runner.get("git_blob"),
        "git_commit": h3.get("commit"),
    }


def _validate_anchored_r01(
    identity: Mapping[str, Any],
    result: Mapping[str, Any],
    launch: Mapping[str, Any],
    anchor: Mapping[str, Any],
    contract: Mapping[str, Any],
    root: Path,
) -> None:
    repair = _require_dict(contract.get("outcome_aware_repair"), "amendment-007 repair")
    raw_result = _require_dict(repair.get("raw_result"), "amendment-007 r01 result")
    core_artifacts = _require_dict(
        repair.get("core_artifacts"), "amendment-007 r01 core artifacts"
    )
    for name, expected_value in core_artifacts.items():
        expected = _require_dict(expected_value, f"amendment-007 r01 {name}")
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise AnalysisValidationError(
                f"anchored r01 core artifact is missing: {name}"
            )
        byte_count, digest = _stream_file_identity(path)
        if expected.get("bytes") != byte_count or expected.get("sha256") != digest:
            raise AnalysisValidationError(
                f"anchored r01 core artifact differs from amendment-007 anchor: {name}"
            )
    if (
        launch.get("identity_sha256") != anchor.get("identity_sha256")
        or identity.get("git", {}).get("commit") != anchor.get("git_commit")
        or identity.get("slurm")
        != {key: anchor["slurm"][key] for key in ("job_id", "partition", "node_list")}
        or result.get("status") != raw_result.get("status")
        or result.get("primary_numeric_eligible")
        is not raw_result.get("raw_primary_numeric_eligible")
    ):
        raise AnalysisValidationError("raw r01 differs from the amendment-007 anchor")


def _validate_anchored_r02(
    identity: Mapping[str, Any],
    result: Mapping[str, Any],
    launch: Mapping[str, Any],
    anchor: Mapping[str, Any],
    contract: Mapping[str, Any],
    root: Path,
) -> None:
    terminal = _require_dict(
        _require_dict(
            contract.get("pending_terminal_bindings"),
            "amendment-008 terminal bindings",
        ).get("r02"),
        "amendment-008 r02 binding",
    )
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
    for name, (byte_field, hash_field) in artifact_fields.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise AnalysisValidationError(f"anchored r02 artifact is missing: {name}")
        byte_count, digest = _stream_file_identity(path)
        if byte_count != terminal.get(byte_field) or digest != terminal.get(hash_field):
            raise AnalysisValidationError(
                f"anchored r02 artifact differs from amendment 008: {name}"
            )
    if (
        launch.get("identity_sha256") != terminal.get("launch_identity_sha256")
        or (identity.get("git") or {}).get("commit") != anchor.get("git_commit")
        or result.get("status") != terminal.get("raw_status")
        or result.get("planned_unit_count") != 430
        or result.get("terminal_unit_count") != 430
        or result.get("complete_plan") is not True
        or result.get("all_planned_units_terminal") is not True
    ):
        raise AnalysisValidationError(
            "raw r02 differs from amendment-008 terminal anchor"
        )


def _is_exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _socket_runtime_root(root: Path, unit: Mapping[str, Any]) -> Path:
    component = str(unit["component"])
    unit_id = str(unit["unit_id"])
    if component in {"matrix", "faults"}:
        return root / "runtime" / component / unit_id
    if component == "soak":
        return root / "runtime" / "soak"
    if component == "offline":
        return root / "runtime" / "offline"
    raise AnalysisValidationError(f"socket endpoint has unknown component: {component}")


def _socket_endpoint_receipt_expected(
    *,
    root: Path,
    component: str,
    unit_id: str,
    raw_attempt_id: str,
    slurm: Mapping[str, Any],
    socket_root: Mapping[str, Any],
    retained_runtime_root: Path,
) -> dict[str, Any]:
    job_id = str(slurm.get("job_id", ""))
    if not job_id.isdecimal():
        raise AnalysisValidationError("socket endpoint lacks a numeric Slurm job ID")
    if socket_root.get("path") != f"/tmp/rf3-{job_id}":
        raise AnalysisValidationError("socket endpoint root differs from the Slurm job")
    if (
        not _is_exact_int(socket_root.get("owner_uid"))
        or int(socket_root["owner_uid"]) < 0
        or socket_root.get("mode") != 0o700
        or not _is_exact_int(socket_root.get("device"))
        or int(socket_root["device"]) < 0
    ):
        raise AnalysisValidationError("socket endpoint root receipt is invalid")
    digest_input = {
        "schema_version": 1,
        "raw_attempt_id": raw_attempt_id,
        "component": component,
        "unit_id": unit_id,
        "retained_runtime_root": str(retained_runtime_root),
    }
    digest = _sha256_bytes(_canonical_json_bytes(digest_input))
    endpoint = Path(str(socket_root["path"])) / f"{digest}.sock"
    encoded_length = len(os.fsencode(endpoint))
    if encoded_length > _SOCKET_ENDPOINT_MAX_BYTES:
        raise AnalysisValidationError("socket endpoint exceeds the AF_UNIX limit")
    return {
        "schema_version": 1,
        "digest_input": digest_input,
        "endpoint_digest": digest,
        "endpoint": str(endpoint),
        "encoded_pathname_bytes": encoded_length,
        "maximum_encoded_pathname_bytes": _SOCKET_ENDPOINT_MAX_BYTES,
        "socket_root": dict(socket_root),
        "rap_state_dir": str(retained_runtime_root / "state"),
        "component": component,
        "unit_id": unit_id,
        "raw_attempt_id": raw_attempt_id,
        "slurm": dict(slurm),
    }


def _validate_socket_endpoint_receipts(
    root: Path, identity: Mapping[str, Any], units: Sequence[Mapping[str, Any]]
) -> None:
    """Recompute every amendment-007 per-unit AF_UNIX endpoint receipt."""
    runtime = root / "runtime"
    if runtime.is_dir():
        failures = sorted(runtime.rglob("socket-cleanup-failure-*.json"))
        if failures:
            raise AnalysisValidationError(
                "socket cleanup failure receipt retained: "
                + str(failures[0].relative_to(root))
            )
    raw_attempt_id = str(identity.get("attempt_id", ""))
    slurm = _require_dict(identity.get("slurm"), "formal Slurm identity")
    formal_runtime = _require_dict(
        identity.get("formal_runtime"), "formal runtime receipt"
    )
    setup_receipt = _require_dict(
        formal_runtime.get("setup_preflight_receipt"), "formal setup receipt"
    )
    setup = _require_dict(setup_receipt.get("content"), "formal setup receipt content")
    setup_socket_root = _require_dict(
        _require_dict(setup.get("socket_preflight"), "formal socket preflight").get(
            "socket_root"
        ),
        "formal socket preflight root",
    )
    for unit in units:
        if unit.get("started") is not True:
            continue
        retained = _socket_runtime_root(root, unit)
        receipt_path = retained / "socket-endpoint.json"
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise AnalysisValidationError(
                "started formal unit lacks socket-endpoint.json: "
                f"{unit['component']}/{unit['unit_id']}"
            )
        receipt = _require_dict(_load_json(receipt_path), "socket endpoint receipt")
        expected = _socket_endpoint_receipt_expected(
            root=root,
            component=str(unit["component"]),
            unit_id=str(unit["unit_id"]),
            raw_attempt_id=raw_attempt_id,
            slurm=slurm,
            socket_root=setup_socket_root,
            retained_runtime_root=retained,
        )
        if receipt != expected:
            raise AnalysisValidationError(
                "socket-endpoint.json differs from the recomputed runner schema: "
                f"{unit['component']}/{unit['unit_id']}"
            )


def _validate_setup_socket_preflight(
    root: Path, identity: Mapping[str, Any], setup: Mapping[str, Any]
) -> None:
    """Validate the already retained pre-launch socket canary without local I/O."""
    slurm = _require_dict(identity.get("slurm"), "formal Slurm identity")
    job_id = str(slurm.get("job_id", ""))
    socket_root_path = str(setup.get("socket_root", ""))
    receipt = _require_dict(setup.get("socket_preflight"), "formal socket preflight")
    root_receipt = _require_dict(receipt.get("socket_root"), "formal socket root")
    retained = root / "runtime" / "preflight"
    digest_input = {
        "schema_version": 1,
        "raw_attempt_id": str(identity.get("attempt_id", "")),
        "component": "preflight",
        "unit_id": "socket-canary",
        "retained_runtime_root": str(retained),
    }
    digest = _sha256_bytes(_canonical_json_bytes(digest_input))
    endpoint = Path(f"/tmp/rf3-{job_id}") / f"{digest}.sock"
    if (
        not job_id.isdecimal()
        or socket_root_path != str(endpoint.parent)
        or root_receipt.get("path") != socket_root_path
        or not _is_exact_int(root_receipt.get("owner_uid"))
        or int(root_receipt["owner_uid"]) < 0
        or root_receipt.get("mode") != 0o700
        or not _is_exact_int(root_receipt.get("device"))
        or int(root_receipt["device"]) < 0
    ):
        raise AnalysisValidationError("formal socket preflight root is invalid")
    expected = {
        "schema_version": 1,
        "digest_input": digest_input,
        "endpoint_digest": digest,
        "endpoint": str(endpoint),
        "encoded_pathname_bytes": len(os.fsencode(endpoint)),
        "maximum_encoded_pathname_bytes": _SOCKET_ENDPOINT_MAX_BYTES,
        "socket_root": dict(root_receipt),
        "bind_connect_accept_payload_equal": True,
        "endpoint_removed_after_probe": True,
    }
    if (
        expected["encoded_pathname_bytes"] > _SOCKET_ENDPOINT_MAX_BYTES
        or receipt != expected
    ):
        raise AnalysisValidationError("formal socket preflight receipt mismatch")


def _validate_file_receipt_shape(value: Any, label: str) -> dict[str, Any]:
    receipt = _require_dict(value, label)
    if (
        not isinstance(receipt.get("path"), str)
        or not receipt["path"]
        or not isinstance(receipt.get("resolved_path"), str)
        or not receipt["resolved_path"]
        or int(receipt.get("bytes", -1)) < 0
        or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("sha256", ""))) is None
    ):
        raise AnalysisValidationError(f"{label} is not a complete file receipt")
    return receipt


def _validate_retained_copy(
    root: Path, value: Any, label: str
) -> tuple[dict[str, Any], Path]:
    item = _require_dict(value, label)
    if set(item) != {"role", "retained_path", "bytes", "sha256"}:
        raise AnalysisValidationError(f"{label} has unexpected fields")
    path = _checked_file(root, str(item.get("retained_path", "")))
    byte_count, digest = _stream_file_identity(path)
    if (
        int(item.get("bytes", -1)) != byte_count
        or str(item.get("sha256", "")) != digest
    ):
        raise AnalysisValidationError(f"{label} byte receipt mismatch")
    return item, path


def _validate_predecessor_tree_binding(
    replacement: Mapping[str, Any],
) -> list[dict[str, Any]]:
    artifacts = _require_dict(
        replacement.get("predecessor_artifacts"),
        "replacement predecessor artifacts",
    )
    if set(artifacts) != set(attempts_contract._PREDECESSOR_ARTIFACT_NAMES):
        raise AnalysisValidationError(
            "replacement predecessor core artifact binding is incomplete"
        )
    tree = list(replacement.get("predecessor_tree") or [])
    allowed_types = {
        "regular_file",
        "directory",
        "socket",
        "fifo",
        "character_device",
        "block_device",
        "unknown_special",
    }
    by_relative: dict[str, dict[str, Any]] = {}
    observed_order: list[str] = []
    for value in tree:
        receipt = _require_dict(value, "replacement predecessor tree receipt")
        if set(receipt) != {
            "relative_path",
            "type",
            "mode",
            "bytes",
            "sha256",
        }:
            raise AnalysisValidationError(
                "replacement predecessor tree receipt has unexpected fields"
            )
        relative_value = receipt.get("relative_path")
        if not isinstance(relative_value, str):
            raise AnalysisValidationError(
                "replacement predecessor tree path must be a string"
            )
        relative_text = relative_value
        relative = Path(relative_text)
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or relative.as_posix() != relative_text
            or relative_text in by_relative
        ):
            raise AnalysisValidationError(
                "replacement predecessor tree paths are invalid or duplicated"
            )
        entry_type = receipt.get("type")
        mode = receipt.get("mode")
        if (
            entry_type not in allowed_types
            or not isinstance(mode, int)
            or isinstance(mode, bool)
            or not 0 <= mode <= 0o7777
        ):
            raise AnalysisValidationError(
                "replacement predecessor tree type or mode is invalid"
            )
        if entry_type == "regular_file":
            byte_count = receipt.get("bytes")
            digest = receipt.get("sha256")
            if (
                not isinstance(byte_count, int)
                or isinstance(byte_count, bool)
                or byte_count < 0
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise AnalysisValidationError(
                    "replacement predecessor file receipt is incomplete"
                )
        elif receipt.get("bytes") is not None or receipt.get("sha256") is not None:
            raise AnalysisValidationError(
                "replacement predecessor non-file receipt contains byte identity"
            )
        observed_order.append(relative_text)
        by_relative[relative_text] = receipt
    if observed_order != sorted(observed_order):
        raise AnalysisValidationError(
            "replacement predecessor tree is not in canonical path order"
        )
    regular_tree_bytes = sum(
        int(item["bytes"]) for item in tree if item.get("type") == "regular_file"
    )
    if (
        len(tree) > attempts_contract._MAX_PREDECESSOR_TREE_ENTRIES
        or regular_tree_bytes > attempts_contract._MAX_PREDECESSOR_TREE_REGULAR_BYTES
    ):
        raise AnalysisValidationError(
            "replacement predecessor tree exceeds the frozen retention bound"
        )
    for relative_text in observed_order:
        relative = Path(relative_text)
        for parent in relative.parents:
            if parent == Path("."):
                break
            parent_value = by_relative.get(parent.as_posix())
            if parent_value is None or parent_value.get("type") != "directory":
                raise AnalysisValidationError(
                    "replacement predecessor tree omits a directory ancestor"
                )
    predecessor_id = replacement.get("predecessor_raw_attempt_id")
    if not isinstance(predecessor_id, str) or not predecessor_id:
        raise AnalysisValidationError(
            "replacement predecessor raw attempt ID is invalid"
        )
    artifact_parents: set[Path] = set()
    for name in attempts_contract._PREDECESSOR_ARTIFACT_NAMES:
        artifact_value = artifacts.get(name)
        tree_value = by_relative.get(name)
        if artifact_value is None:
            if name != "result.json" or tree_value is not None:
                raise AnalysisValidationError(
                    f"replacement predecessor core/tree mismatch for {name}"
                )
            continue
        artifact = _require_dict(
            artifact_value, f"replacement predecessor artifact {name}"
        )
        artifact_path_value = artifact.get("path")
        if (
            set(artifact) != {"path", "bytes", "sha256"}
            or not isinstance(artifact_path_value, str)
            or not Path(artifact_path_value).is_absolute()
            or Path(artifact_path_value).name != name
            or Path(artifact_path_value).parent.name != predecessor_id
            or tree_value is None
            or tree_value.get("type") != "regular_file"
            or artifact.get("bytes") != tree_value.get("bytes")
            or artifact.get("sha256") != tree_value.get("sha256")
        ):
            raise AnalysisValidationError(
                f"replacement predecessor core/tree mismatch for {name}"
            )
        artifact_parents.add(Path(artifact_path_value).parent)
    if len(artifact_parents) != 1:
        raise AnalysisValidationError(
            "replacement predecessor core artifacts do not share one exact root"
        )
    return tree


def _validate_retained_replacement_semantics(
    root: Path, replacement: Mapping[str, Any]
) -> None:
    expected_fields = {
        "kind",
        "raw_attempt_ordinal",
        "receipt_path",
        "receipt_bytes",
        "receipt_sha256",
        "canonical_receipt_sha256",
        "classification",
        "original_status",
        "successor_raw_attempt_id",
        "predecessor_raw_attempt_id",
        "created_utc",
        "reason",
        "affected_boundary",
        "scheduler_adjudication",
        "predecessor_artifacts",
        "predecessor_tree",
        "evidence_receipts",
    }
    whole_attempt_correction = (
        replacement.get("predecessor_raw_attempt_id")
        == attempts_contract._COMPONENT_PREDECESSOR_ID
        and replacement.get("successor_raw_attempt_id")
        == attempts_contract._COMPONENT_SUCCESSOR_ID
        and replacement.get("classification")
        == attempts_contract._COMPONENT_CLASSIFICATION
    )
    if whole_attempt_correction:
        expected_fields.update(
            {
                "prepublication_failure",
                "r04_prepublication_failure",
                "r05_prepublication_failure",
                "r06_prepublication_failure",
                "r07_prepublication_failure",
                "successor_source",
                "whole_attempt_protocol_correction",
                "r02_partial_terminal_forensics",
            }
        )
    if set(replacement) != expected_fields:
        raise AnalysisValidationError(
            "retained replacement binding has unexpected fields"
        )
    successor_id = replacement.get("successor_raw_attempt_id")
    predecessor_id = replacement.get("predecessor_raw_attempt_id")
    match = (
        FORMAL_ATTEMPT_PATTERN.fullmatch(successor_id)
        if isinstance(successor_id, str)
        else None
    )
    if (
        replacement.get("kind") != "replacement_attempt"
        or match is None
        or successor_id != root.name
        or int(match.group("ordinal")) < 2
        or int(match.group("ordinal"))
        > (
            attempts_contract._COMPONENT_MAX_FORMAL_ATTEMPT_ORDINAL
            if successor_id == attempts_contract._COMPONENT_SUCCESSOR_ID
            else attempts_contract._MAX_FORMAL_ATTEMPT_ORDINAL
        )
        or replacement.get("raw_attempt_ordinal") != int(match.group("ordinal"))
        or predecessor_id
        != f"{match.group('prefix')}-r{int(match.group('ordinal')) - 1:02d}"
    ):
        raise AnalysisValidationError(
            "retained replacement binding violates immediate rNN adjacency"
        )
    if not whole_attempt_correction and replacement.get("classification") not in {
        "harness_error",
        "infrastructure_error",
    }:
        raise AnalysisValidationError(
            "retained replacement classification is not allowed"
        )
    if whole_attempt_correction and (
        replacement.get("prepublication_failure")
        != attempts_contract.r03_prepublication_failure_binding()
        or replacement.get("r04_prepublication_failure")
        != attempts_contract.r04_prepublication_failure_binding()
        or replacement.get("r05_prepublication_failure")
        != attempts_contract.r05_prepublication_failure_binding()
        or replacement.get("r06_prepublication_failure")
        != attempts_contract.r06_prepublication_failure_binding()
        or replacement.get("r07_prepublication_failure")
        != attempts_contract.r07_prepublication_failure_binding()
        or replacement.get("successor_source")
        != attempts_contract.component_successor_source_binding()
        or replacement.get("whole_attempt_protocol_correction")
        != attempts_contract.whole_attempt_protocol_correction_binding()
    ):
        raise AnalysisValidationError(
            "retained whole-attempt correction has different P4/I4/H4 or plan identities"
        )
    for name in ("reason", "affected_boundary"):
        if not isinstance(replacement.get(name), str) or not replacement[name].strip():
            raise AnalysisValidationError(
                f"retained replacement requires nonempty {name}"
            )
    created_value = replacement.get("created_utc")
    try:
        created = datetime.fromisoformat(str(created_value).replace("Z", "+00:00"))
        launched = datetime.fromisoformat(
            str(_load_json(root / "launch.json").get("created_utc", "")).replace(
                "Z", "+00:00"
            )
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AnalysisValidationError(
            "retained replacement timestamp is invalid"
        ) from exc
    if created.tzinfo is None or launched.tzinfo is None or created > launched:
        raise AnalysisValidationError(
            "retained replacement was not created before successor launch"
        )
    for name in ("receipt_sha256", "canonical_receipt_sha256"):
        if (
            not isinstance(replacement.get(name), str)
            or re.fullmatch(r"[0-9a-f]{64}", replacement[name]) is None
        ):
            raise AnalysisValidationError(f"retained replacement {name} is invalid")
    if (
        not isinstance(replacement.get("receipt_path"), str)
        or not isinstance(replacement.get("receipt_bytes"), int)
        or isinstance(replacement.get("receipt_bytes"), bool)
        or replacement["receipt_bytes"] < 0
    ):
        raise AnalysisValidationError(
            "retained replacement receipt byte identity is invalid"
        )
    evidence = replacement.get("evidence_receipts")
    if not isinstance(evidence, list) or not evidence:
        raise AnalysisValidationError(
            "retained replacement requires nonempty evidence receipts"
        )
    for value in evidence:
        item = _require_dict(value, "retained replacement evidence receipt")
        evidence_path = (
            Path(item["path"]) if isinstance(item.get("path"), str) else Path()
        )
        if (
            set(item) != {"kind", "path", "bytes", "sha256"}
            or not isinstance(item.get("kind"), str)
            or not item["kind"]
            or not isinstance(item.get("path"), str)
            or not evidence_path.is_absolute()
            or ".." in evidence_path.parts
            or evidence_path.as_posix() != item.get("path")
            or not isinstance(item.get("bytes"), int)
            or isinstance(item.get("bytes"), bool)
            or item["bytes"] < 0
            or not isinstance(item.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
        ):
            raise AnalysisValidationError(
                "retained replacement evidence receipt is invalid"
            )
    _validate_predecessor_tree_binding(replacement)


def _validate_replacement_retention(root: Path, identity: Mapping[str, Any]) -> None:
    replacement = _require_dict(
        identity.get("attempt_replacement"), "formal replacement binding"
    )
    retention = _require_dict(
        identity.get("replacement_retention"), "formal replacement retention"
    )
    if retention.get("self_contained") is not True:
        raise AnalysisValidationError(
            "formal replacement evidence is not self-contained"
        )
    copies = list(retention.get("copies") or [])
    references = list(retention.get("references") or [])
    if replacement.get("kind") == "initial_attempt":
        if (
            copies
            or references
            or replacement != systems.replacement_launch_binding(root, None)
        ):
            raise AnalysisValidationError("formal r01 replacement binding is invalid")
        return
    if replacement.get("kind") != "replacement_attempt":
        raise AnalysisValidationError("formal replacement binding kind is invalid")
    _validate_retained_replacement_semantics(root, replacement)

    expected: list[dict[str, Any]] = [
        {
            "role": "replacement_receipt",
            "retained_path": "replacement/replacement.json",
            "bytes": int(replacement.get("receipt_bytes", -1)),
            "sha256": str(replacement.get("receipt_sha256", "")),
        }
    ]
    predecessor_tree = _validate_predecessor_tree_binding(replacement)
    for value in predecessor_tree:
        receipt = _require_dict(value, "replacement predecessor tree receipt")
        relative = Path(str(receipt.get("relative_path", "")))
        if receipt.get("type") != "regular_file":
            continue
        expected.append(
            {
                "role": f"predecessor_tree:{relative.as_posix()}",
                "retained_path": (
                    f"replacement/predecessor-tree/{relative.as_posix()}"
                ),
                "bytes": int(receipt.get("bytes", -1)),
                "sha256": str(receipt.get("sha256", "")),
            }
        )
    evidence = list(replacement.get("evidence_receipts") or [])
    canary_archive_files = list(
        (
            (replacement.get("r02_partial_terminal_forensics") or {}).get(
                "validated_canary_archive_files"
            )
        )
        or []
    )
    whole_attempt_validation_target: str | None = None
    for index, value in enumerate(evidence):
        receipt = _require_dict(value, "replacement evidence receipt")
        kind = (
            re.sub(r"[^A-Za-z0-9_.-]+", "_", str(receipt.get("kind", ""))).strip("._")
            or "evidence"
        )
        if receipt.get("kind") == "all_partition_paw_cache_canary":
            if index != 2 or len(canary_archive_files) != 28:
                raise AnalysisValidationError(
                    "retained canary archive does not have its exact 28-file layout"
                )
            archive_names = {
                str(item.get("basename", ""))
                for item in canary_archive_files
                if isinstance(item, dict)
            }
            receipt_names = [
                name
                for name in archive_names
                if re.fullmatch(r"rap-eacl-paw-cache-canary-v4-[1-9][0-9]*\.json", name)
            ]
            if len(receipt_names) != 1:
                raise AnalysisValidationError(
                    "retained canary semantic receipt identity differs"
                )
            canary_job_id = (
                receipt_names[0]
                .removeprefix("rap-eacl-paw-cache-canary-v4-")
                .removesuffix(".json")
            )
            expected_archive_names = {
                template.replace("<job_id>", canary_job_id)
                for template in attempts_contract._COMPONENT_CANARY_ARCHIVE_MEMBER_TEMPLATES
            } | {"evidence.sha256", "evidence.sha256.sha256"}
            if archive_names != expected_archive_names:
                raise AnalysisValidationError(
                    "retained canary archive member names differ"
                )
            archive_root = Path(str(receipt.get("path", ""))).parent
            for item in canary_archive_files:
                archive_file = _require_dict(
                    item, "validated canary archive file receipt"
                )
                archive_path = Path(str(archive_file.get("path", "")))
                if (
                    set(archive_file) != {"basename", "path", "bytes", "sha256"}
                    or not archive_path.is_absolute()
                    or archive_path.parent != archive_root
                    or archive_path.name != archive_file.get("basename")
                    or type(archive_file.get("bytes")) is not int
                    or archive_file["bytes"] < 0
                    or re.fullmatch(
                        r"[0-9a-f]{64}", str(archive_file.get("sha256", ""))
                    )
                    is None
                ):
                    raise AnalysisValidationError(
                        "validated canary archive file identity differs"
                    )
            sidecar = next(
                item
                for item in canary_archive_files
                if item["basename"] == "evidence.sha256.sha256"
            )
            if (
                sidecar["path"] != receipt.get("path")
                or sidecar["bytes"] != receipt.get("bytes")
                or sidecar["sha256"] != receipt.get("sha256")
            ):
                raise AnalysisValidationError(
                    "retained canary top anchor differs from evidence binding"
                )
            for item in sorted(
                canary_archive_files,
                key=lambda child: os.fsencode(str(child.get("basename", ""))),
            ):
                archive_file = _require_dict(
                    item, "validated canary archive file receipt"
                )
                if set(archive_file) != {"basename", "path", "bytes", "sha256"}:
                    raise AnalysisValidationError(
                        "validated canary archive file receipt differs"
                    )
                expected.append(
                    {
                        "role": (
                            "evidence:all_partition_paw_cache_canary:"
                            f"{archive_file['basename']}"
                        ),
                        "retained_path": (
                            "replacement/evidence/"
                            "002-all_partition_paw_cache_canary/"
                            f"{archive_file['basename']}"
                        ),
                        "bytes": int(archive_file.get("bytes", -1)),
                        "sha256": str(archive_file.get("sha256", "")),
                    }
                )
            continue
        retained_target = f"replacement/evidence/{index:03d}-{kind}"
        expected.append(
            {
                "role": f"evidence:{receipt.get('kind')}",
                "retained_path": retained_target,
                "bytes": int(receipt.get("bytes", -1)),
                "sha256": str(receipt.get("sha256", "")),
            }
        )
        if receipt.get("kind") == "whole_attempt_replacement_validation":
            whole_attempt_validation_target = retained_target
    correction = dict(replacement.get("whole_attempt_protocol_correction") or {})
    expected_references: list[dict[str, str]] = []
    if correction:
        historical = _require_dict(
            correction.get("historical_validation"),
            "whole-attempt historical-validation binding",
        )
        whole_attempt_validation = next(
            (
                item
                for item in evidence
                if isinstance(item, dict)
                and item.get("kind") == "whole_attempt_replacement_validation"
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
            raise AnalysisValidationError(
                "historical validation is not the whole-attempt evidence"
            )
        expected_references.append(
            {
                "role": "gate:historical_validation",
                "retained_path": whole_attempt_validation_target,
            }
        )
    if copies != expected or references != expected_references:
        raise AnalysisValidationError(
            "formal replacement retention plan differs from launch binding"
        )
    retained_paths = [
        _validate_retained_copy(root, item, "replacement retained copy")[1]
        for item in copies
    ]
    canary_retained = [
        {"relative": Path(item["retained_path"])}
        for item in copies
        if Path(item["retained_path"]).parent
        == Path("replacement/evidence/002-all_partition_paw_cache_canary")
    ]
    try:
        attempts_contract._validate_retained_canary_archive_copy(root, canary_retained)
    except attempts_contract.SystemsHarnessError as exc:
        raise AnalysisValidationError(str(exc)) from exc
    receipt_path = retained_paths[0]
    try:
        raw_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisValidationError(
            f"retained replacement receipt is invalid: {exc}"
        ) from exc
    raw_receipt = _require_dict(raw_receipt, "retained replacement receipt")
    if _sha256_bytes(_canonical_json_bytes(raw_receipt)) != replacement.get(
        "canonical_receipt_sha256"
    ):
        raise AnalysisValidationError(
            "retained replacement receipt canonical digest mismatch"
        )
    for name in (
        "successor_raw_attempt_id",
        "predecessor_raw_attempt_id",
        "classification",
        "original_status",
        "created_utc",
        "reason",
        "affected_boundary",
        "scheduler_adjudication",
    ):
        if raw_receipt.get(name) != replacement.get(name):
            raise AnalysisValidationError(
                f"retained replacement receipt differs on {name}"
            )
    for name in (
        "prepublication_failure",
        "successor_source",
        "whole_attempt_protocol_correction",
    ):
        if name in replacement and raw_receipt.get(name) != replacement.get(name):
            raise AnalysisValidationError(
                f"retained replacement receipt differs on {name}"
            )
    raw_evidence = list(raw_receipt.get("evidence_receipts") or [])
    expected_raw_fields = {
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
    whole_attempt_correction = bool(correction)
    if whole_attempt_correction:
        expected_raw_fields.update(
            {
                "prepublication_failure",
                "successor_source",
                "whole_attempt_protocol_correction",
            }
        )
    if (
        set(raw_receipt) != expected_raw_fields
        or raw_receipt.get("schema_version") != (3 if whole_attempt_correction else 1)
        or raw_receipt.get("predecessor_artifacts")
        != replacement.get("predecessor_artifacts")
        or raw_receipt.get("predecessor_tree") != replacement.get("predecessor_tree")
        or len(raw_evidence) != len(evidence)
        or not all(
            isinstance(raw, dict) and isinstance(bound, dict)
            for raw, bound in zip(raw_evidence, evidence)
        )
        or any(
            set(raw) != {"kind", "path", "bytes", "sha256"}
            or {key: raw.get(key) for key in ("kind", "path", "bytes", "sha256")}
            != {key: bound.get(key) for key in ("kind", "path", "bytes", "sha256")}
            for raw, bound in zip(raw_evidence, evidence)
        )
    ):
        raise AnalysisValidationError(
            "retained replacement evidence declarations differ from binding"
        )

    classification = str(replacement.get("classification", ""))
    original_status = str(replacement.get("original_status", ""))
    predecessor_launch = _require_dict(
        _load_json(root / "replacement/predecessor-tree/launch.json"),
        "retained predecessor launch",
    )
    result_copy = root / "replacement/predecessor-tree/result.json"
    predecessor_result: dict[str, Any] | None = None
    if result_copy.exists():
        predecessor_result = _require_dict(
            _load_json(result_copy), "retained predecessor result"
        )
        predecessor_status = str(predecessor_result.get("status", ""))
        if predecessor_status != original_status:
            raise AnalysisValidationError(
                "retained predecessor status differs from replacement binding"
            )
        exact_outcome_aware_edge = (
            replacement.get("predecessor_raw_attempt_id")
            == "formal-v3-20260831t051023z-r01"
            and replacement.get("successor_raw_attempt_id")
            == "formal-v3-20260831t051023z-r02"
            and classification == "harness_error"
            and original_status == "completed_with_system_violations"
        )
        exact_component_correction = (
            replacement.get("predecessor_raw_attempt_id")
            == attempts_contract._COMPONENT_PREDECESSOR_ID
            and replacement.get("successor_raw_attempt_id")
            == attempts_contract._COMPONENT_SUCCESSOR_ID
            and classification == attempts_contract._COMPONENT_CLASSIFICATION
        )
        if (
            attempts_contract._result_contains_system_violation(predecessor_result)
            and not exact_outcome_aware_edge
            and not exact_component_correction
        ):
            raise AnalysisValidationError(
                "retained predecessor contains a non-replaceable system violation"
            )
        if not exact_outcome_aware_edge and not exact_component_correction:
            allowed_statuses = {f"incomplete_{classification}"}
            if classification == "infrastructure_error":
                allowed_statuses.add("incomplete_unclassified_failure")
            if predecessor_status not in allowed_statuses:
                raise AnalysisValidationError(
                    "retained predecessor status is not replacement-eligible"
                )
    elif original_status != "missing" or (
        classification != "infrastructure_error" and not whole_attempt_correction
    ):
        raise AnalysisValidationError(
            "missing retained predecessor result is not infrastructure-eligible"
        )

    evidence_kinds = [str(item.get("kind", "")) for item in evidence]
    evidence_counts = Counter(evidence_kinds)
    evidence_text: dict[str, str] = {}
    for index, item in enumerate(evidence):
        kind = str(item.get("kind", ""))
        retained_name = expected[
            1
            + sum(item.get("type") == "regular_file" for item in predecessor_tree)
            + index
        ]["retained_path"]
        if kind in {"scheduler_sacct", "scheduler_scontrol"}:
            try:
                evidence_text[kind] = (root / retained_name).read_text(
                    encoding="utf-8", errors="strict"
                )
            except UnicodeDecodeError as exc:
                raise AnalysisValidationError(
                    f"retained {kind} evidence is not UTF-8"
                ) from exc
    adjudication = replacement.get("scheduler_adjudication")
    needs_scheduler = classification == "infrastructure_error" and (
        predecessor_result is None
        or original_status == "incomplete_unclassified_failure"
    )
    if needs_scheduler:
        required = {
            "scheduler_sacct",
            "scheduler_scontrol",
            "scheduler_stdout",
            "scheduler_stderr",
        }
        if any(evidence_counts[name] != 1 for name in required):
            raise AnalysisValidationError(
                "retained scheduler replacement evidence is not exact-once"
            )
        adjudication = _require_dict(adjudication, "retained scheduler adjudication")
        if set(adjudication) != {
            "scheduler_job_id",
            "state",
            "reason",
            "exit_code",
        }:
            raise AnalysisValidationError(
                "retained scheduler adjudication fields are invalid"
            )
        job_id = str(adjudication.get("scheduler_job_id", ""))
        state = str(adjudication.get("state", ""))
        exit_code = str(adjudication.get("exit_code", ""))
        launch_job_id = str(
            _require_dict(
                _require_dict(
                    predecessor_launch.get("identity"),
                    "retained predecessor identity",
                ).get("slurm"),
                "retained predecessor Slurm identity",
            ).get("job_id", "")
        )
        if (
            not job_id.isdigit()
            or job_id != launch_job_id
            or state not in {"PREEMPTED", "NODE_FAIL", "BOOT_FAIL"}
            or not str(adjudication.get("reason", "")).strip()
            or re.fullmatch(r"[0-9]+:[0-9]+", exit_code) is None
        ):
            raise AnalysisValidationError(
                "retained scheduler adjudication is not positively external/bound"
            )
        for kind in ("scheduler_sacct", "scheduler_scontrol"):
            text = evidence_text.get(kind, "")
            if (
                re.search(rf"(?<![0-9]){re.escape(job_id)}(?![0-9])", text) is None
                or re.search(
                    rf"(?<![A-Z0-9_]){re.escape(state)}(?![A-Z0-9_])",
                    text,
                )
                is None
            ):
                raise AnalysisValidationError(
                    f"retained {kind} evidence lacks adjudicated job/state"
                )
    elif adjudication is not None:
        raise AnalysisValidationError(
            "retained scheduler adjudication is present outside its allowed case"
        )


def _validate_tree_receipt(value: Any, label: str) -> dict[str, Any]:
    receipt = _require_dict(value, label)
    files = list(receipt.get("files") or [])
    normalized = []
    for item_value in files:
        item = _require_dict(item_value, f"{label} file")
        if set(item) != {"path", "resolved_path", "bytes", "sha256"}:
            raise AnalysisValidationError(f"{label} file receipt fields are invalid")
        relative = Path(str(item.get("path", "")))
        if (
            not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or int(item.get("bytes", -1)) < 0
            or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))) is None
        ):
            raise AnalysisValidationError(f"{label} file receipt is invalid")
        normalized.append(item)
    paths = [str(item["path"]) for item in normalized]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise AnalysisValidationError(f"{label} file inventory is not sorted/unique")
    if (
        int(receipt.get("file_count", -1)) != len(normalized)
        or int(receipt.get("total_bytes", -1))
        != sum(int(item["bytes"]) for item in normalized)
        or receipt.get("inventory_sha256")
        != _sha256_bytes(_canonical_json_bytes(normalized))
    ):
        raise AnalysisValidationError(f"{label} inventory summary mismatch")
    return receipt


def _validate_tracked_file_receipt(
    value: Any,
    current_path: Path,
    expected_formal_path: Path,
    label: str,
) -> dict[str, Any]:
    receipt = _validate_file_receipt_shape(value, label)
    if (
        receipt.get("path") != str(expected_formal_path)
        or receipt.get("resolved_path") != str(expected_formal_path)
        or int(receipt["bytes"]) != current_path.stat().st_size
        or receipt["sha256"] != _sha256(current_path)
    ):
        raise AnalysisValidationError(f"{label} differs from tracked exact bytes")
    return receipt


def _effective_formal_runtime_profile(
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    if contract.get("amendment_id") != "protocol-v3-amendment-008":
        return _require_dict(
            contract.get("formal_runtime_profile"), "formal runtime profile"
        )
    base = _require_dict(
        _load_json(REPO_ROOT / PROTOCOL_PATHS_007[-1]), "amendment 007"
    )
    profile = json.loads(json.dumps(base.get("formal_runtime_profile") or {}))
    dependency = dict(profile.get("cache_and_dependency_receipt") or {})
    correction = _require_dict(
        contract.get("corrected_direct_paw_cache_contract"),
        "amendment-008 cache correction",
    )
    dependency["formal_cache_dir"] = correction.get("r03_paw_cache_dir_exact")
    dependency["formal_cache_dir"] = (
        _require_dict(
            contract.get("cache_isolation_correction"),
            "amendment-015 cache isolation",
        )
        .get("explicit_override", {})
        .get("dedicated_cache_root")
    )
    dependency["runtime_lock_path"] = "experiments/eacl2027/formal-runtime-lock-v12.json"
    profile["cache_and_dependency_receipt"] = dependency
    thread_environment = dict(profile.get("thread_environment") or {})
    thread_environment["PROGRAMASWEIGHTS_CACHE_DIR"] = "UNSET"
    profile["thread_environment"] = thread_environment
    return profile


def _validate_formal_runtime(
    root: Path,
    identity: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    runtime = _require_dict(identity.get("formal_runtime"), "formal runtime receipt")
    profile = _effective_formal_runtime_profile(contract)
    scheduler_profile = _require_dict(
        profile.get("scheduler"), "formal scheduler profile"
    )
    cpu_profile = _require_dict(profile.get("cpu_and_inference"), "formal CPU profile")
    dependency = _require_dict(
        profile.get("cache_and_dependency_receipt"),
        "formal dependency profile",
    )
    scheduler = _require_dict(runtime.get("scheduler"), "formal scheduler receipt")
    job_id = str(scheduler.get("job_id", ""))
    if re.fullmatch(r"\d+(?:_[0-9]+)?", job_id) is None:
        raise AnalysisValidationError("formal scheduler receipt lacks a real job ID")
    scheduler_environment = _require_dict(
        scheduler.get("environment"), "formal scheduler environment"
    )
    selected = _require_dict(
        scheduler.get("scontrol_selected"), "formal scontrol receipt"
    )
    affinity_ids = list(scheduler.get("affinity_ids") or [])
    affinity_valid = bool(
        all(
            isinstance(item, int) and not isinstance(item, bool)
            for item in affinity_ids
        )
        and affinity_ids == sorted(set(affinity_ids))
    )
    if (
        scheduler_environment.get("SLURM_JOB_PARTITION")
        != str(scheduler_profile["partition"])
        or scheduler_environment.get("SLURM_JOB_NODELIST")
        != str(scheduler_profile["node_list"])
        or scheduler_environment.get("SLURM_CPUS_PER_TASK")
        != str(scheduler_profile["cpus_per_task"])
        or selected.get("Partition") != str(scheduler_profile["partition"])
        or selected.get("NodeList") != str(scheduler_profile["node_list"])
        or selected.get("NumCPUs") != str(scheduler_profile["cpus_per_task"])
        or int(scheduler.get("memory_mib", -1))
        < int(scheduler_profile["minimum_memory_mib"])
        or int(scheduler.get("time_limit_seconds", -1))
        < int(scheduler_profile["minimum_time_limit_seconds"])
        or int(scheduler.get("affinity_cardinality", -1))
        != int(cpu_profile["affinity_cardinality"])
        or len(affinity_ids) != int(cpu_profile["affinity_cardinality"])
        or scheduler.get("shared_node_contention_uncontrolled") is not True
        or scheduler.get("exclusive_node_claimed") is not False
        or str(selected.get("JobId", "")).split("_")[0] != job_id.split("_")[0]
        or "gres/gpu" in str(selected.get("AllocTRES", "")).lower()
        or not affinity_valid
        or re.fullmatch(r"[0-9a-f]{64}", str(scheduler.get("scontrol_raw_sha256", "")))
        is None
    ):
        raise AnalysisValidationError("formal scheduler receipt differs from profile")
    for name in (
        "SLURM_JOB_GPUS",
        "SLURM_STEP_GPUS",
        "SLURM_GPUS",
        "SLURM_GPUS_ON_NODE",
        "CUDA_VISIBLE_DEVICES",
    ):
        if scheduler_environment.get(name) not in {
            None,
            "",
            "0",
            "-1",
            "NoDevFiles",
            "none",
            "None",
        }:
            raise AnalysisValidationError("formal scheduler receipt exposes a GPU")
    slurm_identity = _require_dict(identity.get("slurm"), "formal Slurm identity")
    if slurm_identity != {
        "job_id": job_id,
        "partition": str(scheduler_profile["partition"]),
        "node_list": str(scheduler_profile["node_list"]),
    }:
        raise AnalysisValidationError("formal Slurm identity differs from scheduler")

    python = _require_dict(runtime.get("python"), "formal Python receipt")
    version_info = list(python.get("version_info") or [])
    required_minor = list(
        _require_dict(profile.get("python"), "formal Python profile").get(
            "required_major_minor"
        )
        or []
    )
    expected_invocation = str(profile["python"]["invoked_executable_template"]).replace(
        "${SLURM_JOB_ID}", job_id
    )
    invocation = _validate_file_receipt_shape(
        _require_dict(python.get("invocation"), "formal Python invocation"),
        "formal Python invocation",
    )
    base = _validate_file_receipt_shape(
        _require_dict(python.get("base"), "formal Python base"),
        "formal Python base",
    )
    if (
        version_info[:2] != required_minor
        or python.get("implementation") != "CPython"
        or invocation.get("path") != expected_invocation
        or invocation.get("symlink_chain", [None])[0] != expected_invocation
        or base.get("resolved_path")
        != str(profile["python"]["required_base_executable_resolved"])
    ):
        raise AnalysisValidationError("formal Python receipt differs from profile")

    process = _require_dict(runtime.get("process"), "formal process receipt")
    if (
        int(process.get("os_cpu_count", -1))
        != int(cpu_profile["host_logical_cpu_count"])
        or int(process.get("multiprocessing_cpu_count", -1))
        != int(cpu_profile["multiprocessing_cpu_count"])
        or int(process.get("llama_cpp_implied_n_threads", -1))
        != int(cpu_profile["llama_cpp_n_threads"])
        or int(process.get("llama_cpp_implied_n_threads_batch", -1))
        != int(cpu_profile["llama_cpp_n_threads_batch"])
        or process.get("oversubscription_limitation")
        != cpu_profile["oversubscription_limit"]
    ):
        raise AnalysisValidationError("formal process receipt differs from CPU profile")
    machine = _require_dict(identity.get("machine"), "formal machine identity")
    if (
        machine.get("platform") != process.get("platform")
        or machine.get("python") != python.get("version")
        or machine.get("cpu_count_logical") != process.get("os_cpu_count")
    ):
        raise AnalysisValidationError("formal machine identity differs from runtime")
    named_environment = _require_dict(
        runtime.get("named_environment"), "formal named environment"
    )
    expected_named = {
        "PAW_CACHE_DIR": str(dependency["formal_cache_dir"]),
        "PAW_GPU_LAYERS": str(cpu_profile["paw_gpu_layers_environment"]),
        "HOME": f"/tmp/rap-eacl-systems-formal-v3-{job_id}/home",
        "RAP_EACL_SOCKET_ROOT": f"/tmp/rf3-{job_id}",
        **{
            name: None
            for name, expected in _require_dict(
                profile.get("thread_environment"), "formal thread environment"
            ).items()
            if expected == "UNSET"
        },
    }
    if named_environment != expected_named:
        raise AnalysisValidationError("formal named environment differs from profile")

    formal_repository = Path(str(dependency["formal_repository"]))
    launcher_relative = Path("experiments/eacl2027/run_scaling_faults_watgpu.sbatch")
    launcher_current = REPO_ROOT / launcher_relative
    launcher_formal = formal_repository / launcher_relative
    _validate_tracked_file_receipt(
        runtime.get("launch_script"),
        launcher_current,
        launcher_formal,
        "formal launcher",
    )
    wheelhouse = _validate_tree_receipt(runtime.get("wheelhouse"), "formal wheelhouse")
    if wheelhouse.get("root") != str(dependency["formal_wheelhouse"]):
        raise AnalysisValidationError("formal wheelhouse root differs from profile")
    paw_cache = _require_dict(runtime.get("paw_cache"), "formal PAW cache")
    if paw_cache.get("declared_root") != str(dependency["formal_cache_dir"]):
        raise AnalysisValidationError("formal PAW cache root differs from profile")
    if contract.get("amendment_id") == "protocol-v3-amendment-008" and (
        paw_cache.get("root") != str(dependency["formal_cache_dir"])
        or paw_cache.get("required_direct_children")
        != ["base_models", "programs", "runtimes"]
        or sorted(paw_cache.get("direct_children") or [])
        != ["base_models", "programs", "runtimes"]
        or "programasweights_subtree" in paw_cache
    ):
        raise AnalysisValidationError(
            "formal PAW receipt does not bind the corrected direct content root"
        )
    raw_paw_cache = _validate_raw_tree_receipt(
        paw_cache.get("raw_tree"), "formal PAW raw-tree receipt"
    )
    temporal_fields = {
        "uid",
        "gid",
        "device",
        "inode",
        "link_count",
        "mtime_ns",
        "ctime_ns",
    }
    if contract.get("amendment_id") == "protocol-v3-amendment-008" and (
        raw_paw_cache.get("declared_root") != str(dependency["formal_cache_dir"])
        or raw_paw_cache.get("root_type") != "directory"
        or raw_paw_cache.get("errors")
        or any(
            not temporal_fields.issubset(item)
            for item in [
                raw_paw_cache.get("root_entry") or {},
                *(raw_paw_cache.get("entries") or []),
            ]
        )
    ):
        raise AnalysisValidationError(
            "formal PAW direct-root temporal inventory is incomplete"
        )
    _validate_tree_receipt(
        paw_cache.get("complete_tree"), "formal PAW complete-tree receipt"
    )
    programs = _require_dict(paw_cache.get("programs"), "formal PAW programs")
    provenance = _require_dict(
        identity.get("artifact_provenance"), "formal artifact provenance"
    )
    rule_order = list(provenance.get("rule_order") or [])
    if rule_order != list(systems.EXTERNAL_RULE_ORDER) or len(programs) != len(
        rule_order
    ):
        raise AnalysisValidationError(
            "formal PAW cache/program count is not eight-rule bound"
        )
    for name in ("manifest", "dataset", "output"):
        tracked = _require_dict(provenance.get(name), f"formal artifact {name}")
        relative = Path(str(tracked.get("path", "")))
        path = (REPO_ROOT / relative).resolve()
        try:
            path.relative_to(REPO_ROOT)
        except ValueError as exc:
            raise AnalysisValidationError(
                "formal artifact path escapes repository"
            ) from exc
        if not path.is_file() or tracked.get("sha256") != _sha256(path):
            raise AnalysisValidationError(f"formal artifact {name} hash mismatch")
    manifest_path = REPO_ROOT / str(provenance["manifest"]["path"])
    manifest_programs = _require_dict(
        _require_dict(_load_json(manifest_path), "formal compiled manifest").get(
            "program_ids"
        ),
        "formal compiled program IDs",
    )
    if set(manifest_programs) != set(rule_order) or set(
        str(item) for item in manifest_programs.values()
    ) != set(programs):
        raise AnalysisValidationError(
            "formal PAW cache program IDs differ from compiled manifest"
        )

    runtime_lock = _require_dict(runtime.get("runtime_lock"), "formal runtime lock")
    runtime_lock_relative = Path(str(dependency["runtime_lock_path"]))
    runtime_lock_current = REPO_ROOT / runtime_lock_relative
    runtime_lock_formal = formal_repository / runtime_lock_relative
    _validate_tracked_file_receipt(
        runtime_lock.get("file"),
        runtime_lock_current,
        runtime_lock_formal,
        "formal runtime lock file",
    )
    lock_content = _require_dict(
        runtime_lock.get("content"), "formal runtime lock content"
    )
    if (
        lock_content != _load_json(runtime_lock_current)
        or lock_content.get("wheelhouse") != wheelhouse
        or lock_content.get("paw_cache") != paw_cache
        or runtime_lock.get("wheelhouse_receipt_sha256")
        != _sha256_bytes(_canonical_json_bytes(wheelhouse))
        or runtime_lock.get("paw_cache_receipt_sha256")
        != _sha256_bytes(_canonical_json_bytes(paw_cache))
    ):
        raise AnalysisValidationError("formal runtime lock does not bind live receipts")

    replacement = _require_dict(
        identity.get("attempt_replacement"), "formal replacement binding"
    )
    setup_receipt = _require_dict(
        runtime.get("setup_preflight_receipt"), "formal setup receipt"
    )
    setup_file = _validate_file_receipt_shape(
        setup_receipt.get("file"), "formal setup receipt file"
    )
    setup = _require_dict(setup_receipt.get("content"), "formal setup receipt content")
    setup_log = _validate_file_receipt_shape(
        runtime.get("setup_preflight_log"), "formal setup log"
    )
    required_setup = {
        "schema_version": 1,
        "slurm_job_id": job_id,
        "raw_attempt_id": str(identity["attempt_id"]),
        "replacement_chain": replacement,
        "wheelhouse_path": str(dependency["formal_wheelhouse"]),
        "wheelhouse_inventory_sha256": wheelhouse["inventory_sha256"],
        "wheelhouse_files": wheelhouse["files"],
        "venv_executable": expected_invocation,
        "base_executable_resolved": str(
            profile["python"]["required_base_executable_resolved"]
        ),
        "launch_script_path": str(launcher_formal),
        "node_runtime_root": f"/tmp/rap-eacl-systems-formal-v3-{job_id}",
        "home": f"/tmp/rap-eacl-systems-formal-v3-{job_id}/home",
        "socket_root": f"/tmp/rf3-{job_id}",
        "setup_log_path": setup_log["resolved_path"],
        "setup_log_sha256": setup_log["sha256"],
    }
    if contract.get("amendment_id") == "protocol-v3-amendment-008":
        required_setup["study_mode"] = _COMPONENT_STUDY_MODE
    if any(setup.get(name) != expected for name, expected in required_setup.items()):
        raise AnalysisValidationError(
            "formal setup receipt differs from runtime identity"
        )
    _validate_setup_socket_preflight(root, identity, setup)
    setup_log_content = setup.get("setup_log_content")
    if (
        not isinstance(setup_log_content, str)
        or _sha256_bytes(setup_log_content.encode("utf-8")) != setup_log["sha256"]
        or len(setup_log_content.encode("utf-8")) != int(setup_log["bytes"])
    ):
        raise AnalysisValidationError("formal setup log content/receipt mismatch")
    offline = _require_dict(setup.get("offline_pip"), "formal offline pip receipt")
    offline_argv = [str(item) for item in offline.get("argv") or []]
    if (
        offline.get("returncode") != 0
        or "--no-index" not in offline_argv
        or "--find-links" not in offline_argv
        or str(dependency["formal_wheelhouse"]) not in offline_argv
        or _require_dict(setup.get("import_preflight"), "formal import preflight").get(
            "returncode"
        )
        != 0
        or _require_dict(setup.get("pip_freeze"), "formal pip freeze").get("returncode")
        != 0
    ):
        raise AnalysisValidationError("formal node-local setup did not succeed offline")

    packages = _require_dict(runtime.get("packages"), "formal package receipts")
    package_versions = _require_dict(
        identity.get("packages"), "formal package versions"
    )
    expected_packages = {
        "rules-as-programs",
        "programasweights",
        "llama-cpp-python",
        "psutil",
    }
    if set(packages) != expected_packages or set(package_versions) != expected_packages:
        raise AnalysisValidationError("formal package receipt set is incomplete")
    for name in sorted(expected_packages):
        package = _require_dict(packages[name], f"formal package {name}")
        metadata = _require_dict(
            package.get("metadata_files"), f"formal package {name} metadata"
        )
        if (
            package.get("version") != package_versions[name]
            or not {"METADATA", "RECORD"}.issubset(metadata)
            or package.get("module_origin") is None
        ):
            raise AnalysisValidationError(
                f"formal package {name} provenance is incomplete"
            )
        for receipt in [*metadata.values(), package["module_origin"]]:
            _validate_file_receipt_shape(receipt, f"formal package {name} file")
    if contract.get("amendment_id") == "protocol-v3-amendment-008":
        anchors = _require_dict(
            _require_dict(
                contract.get("known_at_draft"), "amendment-008 known facts"
            ).get("direct_paw_semantics_anchors"),
            "amendment-008 direct PAW anchors",
        )
        semantic_modules = _require_dict(
            _require_dict(packages["programasweights"], "ProgramAsWeights package").get(
                "semantic_modules"
            ),
            "ProgramAsWeights semantic modules",
        )
        expected_semantic = {
            "programasweights.config": anchors.get("installed_config_py_sha256"),
            "programasweights.cache": anchors.get("installed_cache_py_sha256"),
        }
        if set(semantic_modules) != set(expected_semantic):
            raise AnalysisValidationError(
                "ProgramAsWeights semantic module receipt set is incomplete"
            )
        for module, expected_sha256 in expected_semantic.items():
            receipt = _validate_file_receipt_shape(
                semantic_modules[module], f"formal package {module}"
            )
            if receipt.get("sha256") != expected_sha256:
                raise AnalysisValidationError(
                    f"formal package semantic anchor differs: {module}"
                )
        wheel_candidates = [
            item
            for item in wheelhouse.get("files") or []
            if Path(str(item.get("path", ""))).name.startswith("programasweights-")
            and str(item.get("path", "")).endswith(".whl")
        ]
        if len(wheel_candidates) != 1 or wheel_candidates[0].get(
            "sha256"
        ) != anchors.get("programasweights_wheel_sha256"):
            raise AnalysisValidationError(
                "formal ProgramAsWeights wheel differs from amendment 008"
            )
        expected_model = _require_dict(
            anchors.get("base_model"), "amendment-008 base-model anchor"
        )
        models = _require_dict(paw_cache.get("base_models"), "formal base models")
        matching_models = [
            value
            for value in models.values()
            if isinstance(value, dict)
            and (value.get("local") or {}).get("bytes") == expected_model.get("bytes")
            and (value.get("local") or {}).get("sha256") == expected_model.get("sha256")
        ]
        if len(matching_models) != 1:
            raise AnalysisValidationError(
                "formal base model differs from amendment-008 exact bytes"
            )

    retention = _require_dict(
        identity.get("runtime_preflight_retention"),
        "formal runtime preflight retention",
    )
    expected_retention = [
        {
            "role": "setup_receipt",
            "retained_path": "runtime/preflight/setup-receipt.json",
            "bytes": int(setup_file["bytes"]),
            "sha256": setup_file["sha256"],
        },
        {
            "role": "setup_log",
            "retained_path": "runtime/preflight/setup.log",
            "bytes": int(setup_log["bytes"]),
            "sha256": setup_log["sha256"],
        },
    ]
    if retention != {"self_contained": True, "copies": expected_retention}:
        raise AnalysisValidationError(
            "formal runtime preflight retention plan mismatch"
        )
    retained = [
        _validate_retained_copy(root, item, "runtime preflight retained copy")[1]
        for item in expected_retention
    ]
    if (
        _load_json(retained[0]) != setup
        or retained[1].read_text(encoding="utf-8") != setup_log_content
    ):
        raise AnalysisValidationError(
            "formal retained runtime preflight bytes disagree"
        )


def _static_analysis_binding(analysis_id: str) -> dict[str, Any]:
    analyzer_path = Path(__file__).resolve()
    runner_path = Path(systems.__file__).resolve()
    attempts_path = Path(attempts_contract.__file__).resolve()
    runtime_path = Path(runtime_contract.__file__).resolve()
    protocols = [
        {"path": relative, "sha256": _sha256(REPO_ROOT / relative)}
        for relative in PROTOCOL_PATHS
    ]
    return {
        "analysis_id": analysis_id,
        "analysis_version": ANALYSIS_VERSION,
        "analysis_code": [
            {
                "path": str(analyzer_path.relative_to(REPO_ROOT)),
                "sha256": _sha256(analyzer_path),
            },
            {
                "path": str(runner_path.relative_to(REPO_ROOT)),
                "sha256": _sha256(runner_path),
            },
            {
                "path": str(attempts_path.relative_to(REPO_ROOT)),
                "sha256": _sha256(attempts_path),
            },
            {
                "path": str(runtime_path.relative_to(REPO_ROOT)),
                "sha256": _sha256(runtime_path),
            },
        ],
        "protocol_documents": protocols,
        "reducer_config": REDUCER_CONFIG,
        "reducer_config_sha256": _sha256_bytes(_canonical_json_bytes(REDUCER_CONFIG)),
    }


def _component_static_analysis_binding(analysis_id: str) -> dict[str, Any]:
    binding = _static_analysis_binding(analysis_id)
    binding["analysis_version"] = COMPONENT_ANALYSIS_ID
    binding["protocol_documents"] = [
        {"path": relative, "sha256": _sha256(REPO_ROOT / relative)}
        for relative in PROTOCOL_PATHS_016
    ]
    binding["reducer_config"] = COMPONENT_REDUCER_CONFIG
    binding["reducer_config_sha256"] = _sha256_bytes(
        _canonical_json_bytes(COMPONENT_REDUCER_CONFIG)
    )
    return binding


def _read_journal(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise AnalysisValidationError("units.jsonl must not be a symlink")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AnalysisValidationError(f"could not read {path}: {exc}") from exc
    records = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AnalysisValidationError(
                f"invalid units.jsonl line {line_number}: {exc}"
            ) from exc
        records.append(_require_dict(value, f"units.jsonl line {line_number}"))
    return records


def _validate_units(
    root: Path,
    plan: Sequence[dict[str, Any]],
    result: Mapping[str, Any],
    *,
    exact_terminal_phase: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    planned_keys = [(_component(item), _unit_id(item)) for item in plan]
    planned_key_set = set(planned_keys)
    if any(not unit_id for _name, unit_id in planned_keys):
        raise AnalysisValidationError("plan contains an empty unit ID")
    if len(planned_key_set) != len(planned_keys):
        raise AnalysisValidationError("plan contains a duplicate component/unit ID")
    index = result.get("unit_index")
    if not isinstance(index, list) or len(index) != len(plan):
        raise AnalysisValidationError("result unit_index does not enumerate the plan")
    journal_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for record in _read_journal(root / "units.jsonl"):
        key = (str(record.get("component", "")), str(record.get("record_id", "")))
        if key not in planned_key_set:
            raise AnalysisValidationError(f"unexpected journal unit: {key}")
        if key in journal_by_key:
            raise AnalysisValidationError(f"duplicate terminal journal unit: {key}")
        if (
            record.get("phase") != "terminal"
            if exact_terminal_phase
            else record.get("phase") not in {"terminal", "completed", "error"}
        ):
            raise AnalysisValidationError(f"nonterminal journal phase for {key}")
        journal_by_key[key] = record

    units = []
    for planned, expected_key, indexed_value in zip(plan, planned_keys, index):
        indexed = _require_dict(indexed_value, f"unit_index entry {expected_key}")
        key = (str(indexed.get("component", "")), str(indexed.get("unit_id", "")))
        if key != expected_key or indexed.get("plan") != planned:
            raise AnalysisValidationError(
                f"unit_index plan mismatch for {expected_key}"
            )
        status = str(indexed.get("status", ""))
        if status not in TERMINAL_STATUSES:
            raise AnalysisValidationError(
                f"noncanonical unit status for {key}: {status!r}"
            )
        relative = indexed.get("terminal_record")
        indexed_hash = indexed.get("terminal_record_sha256")
        journal_record = journal_by_key.get(key)
        value = None
        record_hash = None
        if relative is None:
            started = bool(indexed.get("started"))
            abort_status = str((result.get("abort") or {}).get("status", ""))
            expected_status = (
                abort_status
                if started and abort_status in TERMINAL_STATUSES
                else "unclassified_failure"
                if started
                else "not_started_after_abort"
            )
            if (
                status != expected_status
                or journal_record is not None
                or indexed_hash is not None
            ):
                raise AnalysisValidationError(f"invalid aborted unit index for {key}")
        else:
            if not isinstance(relative, str) or journal_record is None:
                raise AnalysisValidationError(
                    f"terminal index/journal disagreement for {key}"
                )
            if indexed.get("started") is not True:
                raise AnalysisValidationError(
                    f"terminal unit was not marked started: {key}"
                )
            terminal_path = _checked_file(root, relative)
            value = _require_dict(_load_json(terminal_path), f"terminal record {key}")
            record_hash = _sha256(terminal_path)
            if (
                journal_record.get("terminal_record") != relative
                or journal_record.get("terminal_record_sha256") != record_hash
                or journal_record.get("status") != status
                or indexed_hash != record_hash
            ):
                raise AnalysisValidationError(
                    f"journal/index/file receipt mismatch for {key}"
                )
            if str(value.get("status", "")) != status:
                raise AnalysisValidationError(f"terminal status mismatch for {key}")
        units.append(
            {
                "component": key[0],
                "unit_id": key[1],
                "plan": planned,
                "started": bool(indexed.get("started")),
                "status": status,
                "terminal_record": relative,
                "terminal_sha256": record_hash,
                "value": value,
            }
        )
    if set(journal_by_key) != {
        (unit["component"], unit["unit_id"])
        for unit in units
        if unit["terminal_record"] is not None
    }:
        raise AnalysisValidationError("journal and unit_index terminal sets differ")
    accounting = {
        "planned": len(plan),
        "started": sum(unit["started"] for unit in units),
        "terminal": len(journal_by_key),
        "not_started_after_abort": sum(
            unit["status"] == "not_started_after_abort" for unit in units
        ),
        "started_without_terminal": sum(
            unit["started"] and unit["terminal_record"] is None for unit in units
        ),
        "complete": len(journal_by_key) == len(plan),
    }
    completion = result.get("plan_completion")
    if not isinstance(completion, dict) or any(
        completion.get(key) != value for key, value in accounting.items()
    ):
        raise AnalysisValidationError("result plan_completion disagrees with ledger")
    for field, expected in (
        ("planned_unit_count", len(plan)),
        ("terminal_unit_count", len(journal_by_key)),
        ("complete_plan", accounting["complete"]),
        ("all_planned_units_terminal", accounting["complete"]),
    ):
        if field in result and result[field] != expected:
            raise AnalysisValidationError(f"result {field} disagrees with ledger")
    return units, accounting


def _component_endpoint(
    component: str, plan: Sequence[dict[str, Any]], units: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    selected = [unit for unit in units if unit["component"] == component]
    projected = []
    for unit in selected:
        value = unit.get("value") or {}
        summary: dict[str, Any] = {}
        if component == "soak":
            summary = {
                name: value.get(name)
                for name in (
                    "events",
                    "events_submitted",
                    "events_not_submitted_after_drain_timeout",
                    "event_to_all_query_visible_evaluations",
                    "evaluation_history_query",
                    "global_accounting",
                    "post_drain",
                    "resources",
                    "restart_persistence",
                    "storage",
                    "batches",
                )
            }
            summary["incremental_evidence"] = unit.get("incremental_receipts")
        elif component == "offline":
            summary = {
                name: value.get(name)
                for name in (
                    "network_boundary",
                    "boundary_source_receipt",
                    "boundary_activation_records",
                    "offline_daemon_boundary_activated",
                    "blocked_internet_attempts",
                    "exact_declared_input",
                    "comparison",
                    "paired_event_to_all_latency",
                    "limitation",
                )
            }
        elif component == "faults":
            summary = {
                name: value.get(name)
                for name in (
                    "fault",
                    "repetition",
                    "passed",
                    "duration_ns",
                    "standardized_outcomes",
                    "classification_basis",
                    "error",
                )
            }
        projected.append(
            {
                "unit_id": unit["unit_id"],
                "status": unit["status"],
                "terminal_record": unit["terminal_record"],
                "terminal_sha256": unit["terminal_sha256"],
                "summary": summary if unit["value"] is not None else None,
            }
        )
    return {
        "plan_accounting": {
            "planned": sum(_component(item) == component for item in plan),
            "terminal": sum(unit["value"] is not None for unit in selected),
            "status_counts": dict(
                sorted(Counter(unit["status"] for unit in selected).items())
            ),
            "missing_terminal_unit_ids": [
                unit["unit_id"] for unit in selected if unit["value"] is None
            ],
        },
        "units": projected,
    }


def _fault_endpoint(
    plan: Sequence[dict[str, Any]], units: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    endpoint = _component_endpoint("faults", plan, units)
    plan_by_id = {_unit_id(item): item for item in plan}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in endpoint["units"]:
        grouped[str(plan_by_id[unit["unit_id"]].get("fault", ""))].append(unit)
    endpoint["by_fault"] = {
        fault: {
            "repetitions_planned": len(attempts),
            "repetitions_passed": sum(
                bool((attempt.get("summary") or {}).get("passed"))
                for attempt in attempts
            ),
            "status_counts": dict(
                sorted(Counter(attempt["status"] for attempt in attempts).items())
            ),
            "attempts": attempts,
        }
        for fault, attempts in grouped.items()
    }
    return endpoint


def _validate_formal_plan(
    root: Path,
    identity: Mapping[str, Any],
    result: Mapping[str, Any],
    plan: Sequence[dict[str, Any]],
) -> None:
    if identity.get("study_mode") != _FORMAL_STUDY_MODE:
        raise AnalysisValidationError("launch identity is not amendment-007 formal")
    if result.get("study_mode") != _FORMAL_STUDY_MODE:
        raise AnalysisValidationError("result study_mode is not amendment-007 formal")
    if result.get("protocol_status") != _FORMAL_PROTOCOL_STATUS:
        raise AnalysisValidationError("result protocol status is not amendment 007")
    if not isinstance(identity.get("formal_runtime"), dict):
        raise AnalysisValidationError("formal launch lacks runtime identity")
    git = _require_dict(identity.get("git"), "launch Git identity")
    if git.get("dirty") is not False or not git.get("commit"):
        raise AnalysisValidationError("formal launch Git identity is not clean")
    config_value = _require_dict(identity.get("config"), "launch config")
    names = {item.name for item in fields(systems.MatrixConfig)}
    if set(config_value) != names:
        raise AnalysisValidationError(
            "launch config does not bind every MatrixConfig field"
        )
    contract = _require_dict(
        _load_json(REPO_ROOT / PROTOCOL_PATHS[-1]), "amendment 007"
    )
    if contract.get(
        "freeze_state"
    ) != "frozen_outcome_aware_repair" or not contract.get("frozen_utc"):
        raise AnalysisValidationError("formal amendment 007 was not frozen")
    required_git = _require_dict(
        _require_dict(
            _require_dict(
                contract.get("effective_protocol_identity"),
                "formal protocol identity",
            ).get("acyclic_formal_binding"),
            "formal acyclic binding",
        ).get("required_git_state"),
        "formal required Git state",
    )
    commit = str(git.get("commit", ""))
    if (
        re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or git.get("dirty") is not required_git.get("dirty_must_equal")
        or git.get("scope") != required_git.get("dirty_scope")
    ):
        raise AnalysisValidationError("formal Git identity differs from frozen scope")
    try:
        topology = systems._validate_formal_git_topology(commit, required_git)
    except systems.SystemsHarnessError as exc:
        raise AnalysisValidationError(
            f"formal Git three-commit chronology is invalid: {exc}"
        ) from exc
    if identity.get("git_topology") != topology:
        raise AnalysisValidationError(
            "launch Git topology receipt is not independently reconstructed"
        )
    effective = _require_dict(
        contract.get("formal_effective_config"), "formal effective config"
    )
    mismatches = {
        name: {"expected": effective.get(name), "observed": config_value.get(name)}
        for name in sorted(names)
        if name not in effective or config_value.get(name) != effective.get(name)
    }
    if mismatches:
        raise AnalysisValidationError(
            "launch config differs from formal effective config: "
            + json.dumps(mismatches, sort_keys=True)
        )
    kwargs = dict(config_value)
    for name in ("rule_counts", "project_counts", "burst_sizes"):
        kwargs[name] = tuple(kwargs[name])
    config = systems.MatrixConfig(**kwargs)
    expected_plan = systems.build_study_plan(
        config,
        fault_names=tuple(effective["fault_names_in_order"]),
        run_offline_probe=bool(effective["offline_probe"]),
    )
    if list(plan) != expected_plan:
        raise AnalysisValidationError("plan is not the deterministic formal study plan")
    if result.get("config") is not None and result.get("config") != config_value:
        raise AnalysisValidationError("result config differs from launch identity")
    if result.get("plan") is not None and result.get("plan") != list(plan):
        raise AnalysisValidationError("result plan differs from immutable plan.json")
    _validate_replacement_retention(root, identity)
    _validate_formal_runtime(root, identity, contract)


def _validate_whole_attempt_plan(
    root: Path,
    identity: Mapping[str, Any],
    result: Mapping[str, Any],
    plan: Sequence[dict[str, Any]],
    contract: Mapping[str, Any],
) -> None:
    if (
        identity.get("study_mode") != _COMPONENT_STUDY_MODE
        or result.get("study_mode") != _COMPONENT_STUDY_MODE
        or result.get("protocol_status") != _COMPONENT_STUDY_MODE
    ):
        raise AnalysisValidationError("r03 is not the amendment-008 whole attempt")
    if not isinstance(identity.get("formal_runtime"), dict):
        raise AnalysisValidationError("r03 launch lacks formal runtime identity")
    git = _require_dict(identity.get("git"), "r03 Git identity")
    required_git = systems._required_git_state(contract)
    commit = str(git.get("commit", ""))
    if (
        re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or git.get("dirty") is not required_git.get("dirty_must_equal")
        or git.get("scope") != required_git.get("dirty_scope")
    ):
        raise AnalysisValidationError("r03 Git identity differs from amendment 008")
    try:
        topology = systems._validate_formal_git_topology(commit, required_git)
    except systems.SystemsHarnessError as exc:
        raise AnalysisValidationError(
            f"r03 P4/I4/H4 topology is invalid: {exc}"
        ) from exc
    if identity.get("git_topology") != topology:
        raise AnalysisValidationError("r03 Git topology was not reconstructed")
    overrides = _require_dict(
        _require_dict(
            contract.get("effective_protocol_identity"),
            "amendment-008 effective protocol identity",
        ).get("explicit_one_time_overrides"),
        "amendment-008 explicit overrides",
    )
    if (
        overrides.get("formal_effective_config.fault_names_in_order")
        != systems.FORMAL_FAULT_OVERRIDE_TEXT
    ):
        raise AnalysisValidationError("r03 fault_names_in_order override differs")
    if (
        overrides.get("formal_effective_config.study_mode")
        != systems.FORMAL_STUDY_MODE_OVERRIDE_TEXT
    ):
        raise AnalysisValidationError("r03 study_mode override differs")

    config_value = _require_dict(identity.get("config"), "r03 config")
    names = {item.name for item in fields(systems.MatrixConfig)}
    if set(config_value) != names:
        raise AnalysisValidationError("r03 config omits a MatrixConfig field")
    base = _require_dict(
        _load_json(REPO_ROOT / PROTOCOL_PATHS_007[-1]), "amendment 007"
    )
    effective = _require_dict(
        base.get("formal_effective_config"), "amendment-007 effective config"
    )
    mismatches = {
        name: {"expected": effective.get(name), "observed": config_value.get(name)}
        for name in sorted(names)
        if name not in effective or config_value.get(name) != effective.get(name)
    }
    if mismatches:
        raise AnalysisValidationError(
            "r03 config differs from inherited formal config: "
            + json.dumps(mismatches, sort_keys=True)
        )
    kwargs = dict(config_value)
    for name in ("rule_counts", "project_counts", "burst_sizes"):
        kwargs[name] = tuple(kwargs[name])
    config = systems.MatrixConfig(**kwargs)
    full_attempt = systems.build_full_attempt_plan(config)
    if list(plan) != full_attempt["full_plan"]:
        raise AnalysisValidationError("r03 raw plan is not the exact full 430-row plan")
    expected_binding = {
        "analysis_id": COMPONENT_ANALYSIS_ID,
        "full_plan_unit_count": 430,
        "full_plan_sha256": systems.FORMAL_FULL_PLAN_SHA256,
        "full_plan_stored_sha256": systems.FORMAL_FULL_PLAN_STORED_SHA256,
        "ordered_membership_sha256": systems.FORMAL_FULL_PLAN_MEMBERSHIP_SHA256,
        "primary_source_attempt_id": attempts_contract._COMPONENT_SUCCESSOR_ID,
        "execution_roles": full_attempt["execution_roles"],
    }
    if identity.get("whole_attempt_protocol_correction") != expected_binding:
        raise AnalysisValidationError("r03 launch lacks exact whole-attempt identities")
    if result.get("config") is not None and result.get("config") != config_value:
        raise AnalysisValidationError("r03 result config differs from launch")
    if result.get("plan") is not None and result.get("plan") != list(plan):
        raise AnalysisValidationError("r03 result plan differs from plan.json")
    _validate_replacement_retention(root, identity)
    _validate_formal_runtime(root, identity, contract)


def _validate_timed_history_query(value: Any, label: str) -> dict[str, Any]:
    query = _require_dict(value, label)
    started = query.get("started_monotonic_ns")
    finished = query.get("finished_monotonic_ns")
    latency = query.get("latency_ns")
    rows = query.get("rows")
    if (
        not _is_exact_int(started)
        or not _is_exact_int(finished)
        or not _is_exact_int(latency)
        or not _is_exact_int(rows)
        or started < 0
        or finished < started
        or latency != finished - started
        or rows < 0
        or query.get("latency_ms") != round(latency / 1_000_000, 3)
    ):
        raise AnalysisValidationError(f"{label} timing/row evidence is invalid")
    return query


def _query_summary(values: Sequence[int], *, empty_unit: str = "ns") -> dict[str, Any]:
    if values:
        return systems._summary_ns([int(value) for value in values])
    return {"unit": empty_unit, "count": 0, "available": False}


def _validate_soak_query_summaries(
    value: Mapping[str, Any],
    checkpoints: Sequence[Any],
    post_restart_queries: Sequence[Any],
) -> None:
    """Recompute retained per-batch and aggregate History-query reductions."""

    cursor = 0
    aggregate: list[int] = []

    def consume(summary_value: Any, label: str) -> list[int]:
        nonlocal cursor
        summary = _require_dict(summary_value, f"{label} checkpoint summary")
        attempts = int(summary.get("attempts", -1))
        if attempts < 0 or cursor + attempts > len(checkpoints):
            raise AnalysisValidationError(f"{label} query segment is invalid")
        segment = checkpoints[cursor : cursor + attempts]
        cursor += attempts
        latencies: list[int] = []
        for checkpoint_index, checkpoint_value in enumerate(segment):
            checkpoint = _require_dict(
                checkpoint_value, f"{label} checkpoint {checkpoint_index}"
            )
            for query_index, query_value in enumerate(
                checkpoint.get("per_project_queries") or []
            ):
                query = _validate_timed_history_query(
                    query_value, f"{label} query {query_index}"
                )
                latencies.append(int(query["latency_ns"]))
        aggregate.extend(latencies)
        return latencies

    for index, batch_value in enumerate(value.get("batches") or []):
        batch = _require_dict(batch_value, f"soak batch {index}")
        wait = _require_dict(batch.get("wait"), f"soak batch {index} wait")
        latencies = consume(wait.get("history_checkpoint"), f"soak batch {index}")
        expected = _query_summary(latencies)
        if batch.get("evaluation_history_query") != expected:
            raise AnalysisValidationError(
                f"soak batch {index} History summary is not recomputed from queries"
            )

    final_wait = _require_dict(
        _require_dict(value.get("post_drain"), "soak post-drain").get(
            "final_drain_wait"
        ),
        "soak final-drain wait",
    )
    if final_wait.get("history_checkpoint") is not None:
        consume(final_wait["history_checkpoint"], "soak final drain")
    if cursor != len(checkpoints):
        raise AnalysisValidationError(
            "soak query summaries leave unbound checkpoint records"
        )
    for index, query_value in enumerate(post_restart_queries):
        query = _validate_timed_history_query(
            query_value, f"soak post-restart query {index}"
        )
        aggregate.append(int(query["latency_ns"]))
    if value.get("evaluation_history_query") != _query_summary(aggregate):
        raise AnalysisValidationError(
            "soak aggregate History summary is not recomputed from queries"
        )


def _validate_soak_checkpoint_chain(
    root: Path,
    value: Mapping[str, Any],
    checkpoints: Sequence[Any],
    post_restart_queries: Sequence[Any],
    expected_keys_by_batch: Mapping[str, Sequence[dict[str, str]]],
) -> None:
    """Rebuild every bounded soak History wait from its append-only records."""
    if not all(isinstance(item, dict) for item in checkpoints):
        raise AnalysisValidationError("soak History checkpoints are invalid")
    batches = list(value.get("batches") or [])
    project_count = int(value.get("project_count", -1))
    rule_count = int(value.get("rule_count", -1))
    cursor = 0
    total_query_count = 0
    saw_timeout = False

    def consume(
        summary_value: Any,
        *,
        batch_id: str,
        expected_key_set_sha256: str,
        expected_keys: Sequence[dict[str, str]],
        expected_terminal: int,
        deadline_ns: int,
        label: str,
        zero_attempt_missing_exact: bool = True,
    ) -> tuple[int, bool]:
        nonlocal cursor
        summary = _require_dict(summary_value, f"{label} summary")
        if (
            summary.get("batch_id") != batch_id
            or summary.get("expected_key_set_sha256") != expected_key_set_sha256
            or expected_terminal != len(expected_keys)
        ):
            raise AnalysisValidationError(f"{label} batch/key-set binding is invalid")
        attempts = int(summary.get("attempts", -1))
        if attempts < 0 or cursor + attempts > len(checkpoints):
            raise AnalysisValidationError(f"{label} attempt count is invalid")
        segment = list(checkpoints[cursor : cursor + attempts])
        cursor += attempts
        query_count = 0
        for expected_attempt, checkpoint in enumerate(segment, start=1):
            observed = int(checkpoint.get("observed_monotonic_ns", -1))
            visible = int(checkpoint.get("visible_terminal_tuples", -1))
            missing = int(checkpoint.get("missing_count", -1))
            within = bool(observed >= 0 and observed <= deadline_ns)
            queries = list(checkpoint.get("per_project_queries") or [])
            if (
                checkpoint.get("batch_id") != batch_id
                or checkpoint.get("expected_key_set_sha256") != expected_key_set_sha256
                or int(checkpoint.get("attempt", -1)) != expected_attempt
                or int(checkpoint.get("expected_terminal_tuples", -1))
                != expected_terminal
                or visible < 0
                or missing < 0
                or visible + missing != expected_terminal
                or checkpoint.get("within_deadline") is not within
                or len(queries) != project_count
            ):
                raise AnalysisValidationError(
                    f"{label} checkpoint accounting/deadline is invalid"
                )
            validated_queries = [
                _validate_timed_history_query(item, f"{label} project query")
                for item in queries
            ]
            if (
                validated_queries
                and max(
                    int(item["finished_monotonic_ns"]) for item in validated_queries
                )
                > observed
            ):
                raise AnalysisValidationError(
                    f"{label} checkpoint precedes its History queries"
                )
            query_count += len(validated_queries)
        if segment:
            last = segment[-1]
            last_missing = int(last["missing_count"])
            last_within = bool(last["within_deadline"])
            expected_complete = bool(last_missing == 0 and last_within)
            expected_visible = (
                int(last["observed_monotonic_ns"]) if last_missing == 0 else None
            )
        else:
            last_missing = expected_terminal
            expected_complete = False
            expected_visible = None
        declared_missing = list(summary.get("missing") or [])
        expected_key_text = {
            json.dumps(item, sort_keys=True, separators=(",", ":"))
            for item in expected_keys
        }
        declared_missing_dicts = [
            _require_dict(item, f"{label} missing key") for item in declared_missing
        ]
        if any(
            set(item) != {"project_root", "input_sha256", "rule_id"}
            for item in declared_missing_dicts
        ):
            raise AnalysisValidationError(f"{label} has malformed missing keys")
        declared_missing_text = [
            json.dumps(item, sort_keys=True, separators=(",", ":"))
            for item in declared_missing_dicts
        ]
        declared_missing_tuples = [
            (item["project_root"], item["input_sha256"], item["rule_id"])
            for item in declared_missing_dicts
        ]
        missing_count_matches = (
            len(declared_missing) == last_missing
            if segment or zero_attempt_missing_exact
            else len(declared_missing) <= expected_terminal
        )
        if (
            summary.get("complete") is not expected_complete
            or summary.get("timed_out") is not (not expected_complete)
            or int(summary.get("attempts", -1)) != len(segment)
            or summary.get("visible_monotonic_ns") != expected_visible
            or not missing_count_matches
            or len(declared_missing_text) != len(set(declared_missing_text))
            or any(item not in expected_key_text for item in declared_missing_text)
            or declared_missing_tuples != sorted(declared_missing_tuples)
        ):
            raise AnalysisValidationError(
                f"{label} summary is not reconstructed from checkpoints"
            )
        if not expected_complete and last_missing == 0:
            if summary.get("complete_after_deadline") is not True:
                raise AnalysisValidationError(
                    f"{label} late completion is not explicitly retained"
                )
        return query_count, not expected_complete

    for index, batch in enumerate(batches):
        if saw_timeout:
            raise AnalysisValidationError(
                "soak submitted a later batch after a timed-out batch"
            )
        batch = _require_dict(batch, "soak batch")
        wait = _require_dict(batch.get("wait"), "soak batch wait")
        batch_id = str(batch.get("batch_id", ""))
        expected_batch_id = (
            f"soak-r{rule_count}-p{project_count}-offset{int(batch.get('offset', -1))}"
        )
        expected_keys = list(expected_keys_by_batch.get(batch_id) or [])
        expected_key_set_sha256 = _sha256_bytes(_canonical_json_bytes(expected_keys))
        expected_terminal = int(batch.get("events", -1)) * rule_count
        if (
            batch_id != expected_batch_id
            or batch.get("expected_key_set_sha256") != expected_key_set_sha256
            or wait.get("batch_id") != batch_id
            or wait.get("expected_key_set_sha256") != expected_key_set_sha256
            or len(expected_keys) != expected_terminal
        ):
            raise AnalysisValidationError(
                f"soak batch {index} is not bound to its expected key set"
            )
        query_count, timed_out = consume(
            wait.get("history_checkpoint"),
            batch_id=batch_id,
            expected_key_set_sha256=expected_key_set_sha256,
            expected_keys=expected_keys,
            expected_terminal=expected_terminal,
            deadline_ns=int(wait.get("deadline_monotonic_ns", -1)),
            label=f"soak batch {index}",
        )
        settle = _require_dict(wait.get("settle"), "soak batch settle")
        if (
            wait.get("timed_out") is not timed_out
            or (query_count > 0 and settle.get("complete") is not True)
            or int(
                _require_dict(
                    batch.get("evaluation_history_query"),
                    "soak batch History summary",
                ).get("count", -1)
            )
            != query_count
        ):
            raise AnalysisValidationError(
                "soak batch wait/query gate is not reconstructed"
            )
        total_query_count += query_count
        saw_timeout = timed_out

    final_wait = _require_dict(
        _require_dict(value.get("post_drain"), "soak post-drain").get(
            "final_drain_wait"
        ),
        "soak final-drain wait",
    )
    final_checkpoint_value = final_wait.get("history_checkpoint")
    if saw_timeout is (final_checkpoint_value is None):
        raise AnalysisValidationError(
            "soak final checkpoint presence does not match the batch-timeout state"
        )
    if final_checkpoint_value is not None:
        if not batches:
            raise AnalysisValidationError(
                "soak final checkpoint exists without a timed-out batch"
            )
        last_batch = _require_dict(batches[-1], "last soak batch")
        last_batch_id = str(last_batch.get("batch_id", ""))
        last_expected_keys = list(expected_keys_by_batch.get(last_batch_id) or [])
        last_expected_key_set_sha256 = _sha256_bytes(
            _canonical_json_bytes(last_expected_keys)
        )
        final_queries, final_timed_out = consume(
            final_checkpoint_value,
            batch_id=last_batch_id,
            expected_key_set_sha256=last_expected_key_set_sha256,
            expected_keys=last_expected_keys,
            expected_terminal=int(last_batch.get("events", -1)) * rule_count,
            deadline_ns=int(final_wait.get("deadline_monotonic_ns", -1)),
            label="soak final drain",
            zero_attempt_missing_exact=False,
        )
        if final_wait.get("timed_out") is not final_timed_out:
            raise AnalysisValidationError(
                "soak final-drain timeout is not reconstructed"
            )
        total_query_count += final_queries
    elif final_wait.get("timed_out") is not False:
        raise AnalysisValidationError(
            "soak no-timeout final drain nevertheless declares a timeout"
        )
    if cursor != len(checkpoints):
        raise AnalysisValidationError(
            "soak History checkpoint receipt has unbound trailing records"
        )

    restart = _require_dict(
        value.get("restart_persistence"), "soak restart persistence"
    )
    before_sha = restart.get("persisted_projection_sha256_before")
    after_sha = restart.get("persisted_projection_sha256_after")

    def retained_projection(role: str, receipt_value: Any, declared_sha: Any) -> bytes:
        _receipt, raw = _validated_binary_receipt(
            root, receipt_value, f"soak {role} projection"
        )
        if declared_sha != _sha256_bytes(raw):
            raise AnalysisValidationError(
                f"soak {role} projection digest differs from retained bytes"
            )
        try:
            projection = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AnalysisValidationError(
                f"soak {role} projection is not valid UTF-8 JSON"
            ) from exc
        if (
            not isinstance(projection, dict)
            or set(projection) != {"evaluations", "findings"}
            or not all(isinstance(projection[name], dict) for name in projection)
            or raw
            != json.dumps(projection, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ):
            raise AnalysisValidationError(f"soak {role} projection is not canonical")
        return raw

    if restart.get("status") == "completed":
        before_bytes = retained_projection(
            "pre-restart",
            restart.get("persisted_projection_before_receipt"),
            before_sha,
        )
        after_bytes = retained_projection(
            "post-restart",
            restart.get("persisted_projection_after_receipt"),
            after_sha,
        )
        if (
            not isinstance(before_sha, str)
            or re.fullmatch(r"[0-9a-f]{64}", before_sha) is None
            or not isinstance(after_sha, str)
            or re.fullmatch(r"[0-9a-f]{64}", after_sha) is None
            or restart.get("exact_projection_bytes_preserved")
            is not (before_sha == after_sha and before_bytes == after_bytes)
        ):
            raise AnalysisValidationError(
                "soak restart projection equality is not recomputed from bytes"
            )
        if len(post_restart_queries) != 1:
            raise AnalysisValidationError(
                "completed soak restart must retain exactly one History query"
            )
        query = _validate_timed_history_query(
            post_restart_queries[0], "soak post-restart History query"
        )
        if restart.get("history_query") != query or int(
            restart.get("first_project_history_rows_query_visible", -1)
        ) != int(query["rows"]):
            raise AnalysisValidationError(
                "soak post-restart query receipt disagrees with restart outcome"
            )
        total_query_count += 1
    else:
        before_receipt = restart.get("persisted_projection_before_receipt")
        if (before_sha is None) is not (before_receipt is None):
            raise AnalysisValidationError(
                "non-completed soak restart has an inconsistent pre-projection receipt"
            )
        if before_receipt is not None:
            retained_projection("pre-restart", before_receipt, before_sha)
        if (
            post_restart_queries
            or after_sha is not None
            or restart.get("persisted_projection_after_receipt") is not None
            or restart.get("exact_projection_bytes_preserved") is not None
        ):
            raise AnalysisValidationError(
                "non-completed soak restart has post-restart evidence"
            )
    if (
        int(
            _require_dict(
                value.get("evaluation_history_query"),
                "soak aggregate History summary",
            ).get("count", -1)
        )
        != total_query_count
    ):
        raise AnalysisValidationError(
            "soak aggregate History count disagrees with incremental evidence"
        )


def _validate_soak_evidence(root: Path, units: Sequence[dict[str, Any]]) -> None:
    for unit in units:
        if unit["component"] != "soak" or unit["value"] is None:
            continue
        value = unit["value"]
        # A caught, positively classified measured failure is itself a retained
        # system outcome.  It cannot manufacture success-shaped incremental
        # artifacts that were never opened; the error/classification record is
        # the evidence for this unit and numeric fields remain unavailable.
        if value.get("error") is not None:
            if not value.get("classification_basis"):
                raise AnalysisValidationError(
                    "caught soak outcome lacks its classification basis"
                )
            continue
        evidence = _require_dict(value.get("incremental_evidence"), "soak evidence")
        normalized = {}
        evidence_values: dict[str, list[Any]] = {}
        for name in (
            "event_samples",
            "journal_progress",
            "history_checkpoints",
            "resource_samples",
        ):
            normalized[name], evidence_values[name] = _validated_jsonl(
                root, evidence.get(name), f"soak {name}"
            )
        if evidence.get("post_restart_history_query") is not None:
            (
                normalized["post_restart_history_query"],
                evidence_values["post_restart_history_query"],
            ) = _validated_jsonl(
                root,
                evidence["post_restart_history_query"],
                "soak post-restart history query",
            )
        _validate_soak_query_summaries(
            value,
            evidence_values["history_checkpoints"],
            evidence_values.get("post_restart_history_query", []),
        )
        _validate_embedded_hook_projections(
            evidence_values["event_samples"], "soak retained event samples"
        )
        unit["retained_hook_contracts_preserved"] = all(
            _hook_contract_preserved(item["hook"])
            for item in evidence_values["event_samples"]
            if isinstance(item, dict) and isinstance(item.get("hook"), dict)
        ) and len(evidence_values["event_samples"]) == len(
            [
                item
                for item in evidence_values["event_samples"]
                if isinstance(item, dict) and isinstance(item.get("hook"), dict)
            ]
        )
        resources_receipt = (value.get("resources") or {}).get(
            "timestamped_samples_receipt"
        )
        if resources_receipt != evidence.get("resource_samples"):
            raise AnalysisValidationError(
                "soak resource receipt disagrees across evidence fields"
            )
        events_submitted = int(value.get("events_submitted", -1))
        if len(evidence_values["event_samples"]) != events_submitted or not all(
            isinstance(item, dict) for item in evidence_values["event_samples"]
        ):
            raise AnalysisValidationError(
                "soak event-sample receipt count differs from events_submitted"
            )
        if value.get("event_to_all_query_visible_evaluations") != (
            systems._latency_summary(
                evidence_values["event_samples"],
                "event_to_all_query_visible_evaluations_ms",
            )
        ):
            raise AnalysisValidationError(
                "soak event-to-query summary is not recomputed from event samples"
            )
        hook_latencies = [
            int(item.get("hook_exit_ns", -1))
            for item in evidence_values["event_samples"]
            if isinstance(item, dict)
        ]
        if (
            len(hook_latencies) != events_submitted
            or any(value < 0 for value in hook_latencies)
            or value.get("hook_process_exit") != _query_summary(hook_latencies)
        ):
            raise AnalysisValidationError(
                "soak hook-exit summary is not recomputed from event samples"
            )
        event_cases = [
            str(item.get("case_id", ""))
            for item in evidence_values["event_samples"]
            if isinstance(item, dict)
        ]
        event_hashes = [
            str(item.get("input_sha256", ""))
            for item in evidence_values["event_samples"]
            if isinstance(item, dict)
        ]
        if (
            len(event_cases) != events_submitted
            or len(set(event_cases)) != events_submitted
            or len(set(event_hashes)) != events_submitted
            or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in event_hashes)
        ):
            raise AnalysisValidationError("soak event samples are not uniquely bound")
        batches = [
            _require_dict(item, "soak batch")
            for item in list(value.get("batches") or [])
        ]
        samples_by_batch: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for sample in evidence_values["event_samples"]:
            batch_id = str(sample.get("batch_id", ""))
            if not batch_id:
                raise AnalysisValidationError("soak event sample lacks batch identity")
            samples_by_batch[batch_id].append(sample)
        expected_keys_by_batch: dict[str, list[dict[str, str]]] = {}
        rule_ids = systems.EXTERNAL_RULE_ORDER[: int(value.get("rule_count", -1))]
        for batch in batches:
            batch_id = str(batch.get("batch_id", ""))
            batch_samples = samples_by_batch.get(batch_id, [])
            expected_key_tuples = sorted(
                (
                    str(sample.get("project_root", "")),
                    str(sample.get("input_sha256", "")),
                    rule_id,
                )
                for sample in batch_samples
                for rule_id in rule_ids
            )
            expected_keys = [
                {
                    "project_root": project_root,
                    "input_sha256": input_sha256,
                    "rule_id": rule_id,
                }
                for project_root, input_sha256, rule_id in expected_key_tuples
            ]
            digest = _sha256_bytes(_canonical_json_bytes(expected_keys))
            if (
                not batch_id
                or len(batch_samples) != int(batch.get("events", -1))
                or batch.get("expected_key_set_sha256") != digest
                or any(
                    sample.get("expected_key_set_sha256") != digest
                    for sample in batch_samples
                )
            ):
                raise AnalysisValidationError(
                    "soak batch/event samples do not bind one expected key set"
                )
            expected_keys_by_batch[batch_id] = expected_keys
        if set(samples_by_batch) != set(expected_keys_by_batch):
            raise AnalysisValidationError("soak event samples contain an unknown batch")
        _validate_soak_checkpoint_chain(
            root,
            value,
            evidence_values["history_checkpoints"],
            evidence_values.get("post_restart_history_query", []),
            expected_keys_by_batch,
        )
        if len(evidence_values["resource_samples"]) != int(
            (value.get("resources") or {}).get("sample_count", -1)
        ):
            raise AnalysisValidationError(
                "soak resource sample count disagrees with incremental receipt"
            )
        resource_values = evidence_values["resource_samples"]
        if not resource_values or not all(
            isinstance(item, dict) for item in resource_values
        ):
            raise AnalysisValidationError("soak resource sample evidence is empty")
        event_started = min(
            int(item.get("submitted_monotonic_ns", -1))
            for item in evidence_values["event_samples"]
        )
        resources = _require_dict(value.get("resources"), "soak resources")
        window_binding = _require_dict(
            resources.get("rss_slope_window"), "soak RSS slope window"
        )
        drain_value = _require_dict(value.get("post_drain"), "soak post-drain")
        drain_finished = int(drain_value.get("true_drain_finished_monotonic_ns", -1))
        if (
            int(window_binding.get("start_first_submission_monotonic_ns", -1))
            != event_started
            or int(window_binding.get("end_true_drain_monotonic_ns", -1))
            != drain_finished
        ):
            raise AnalysisValidationError("soak RSS slope window binding mismatch")
        rss_window = [
            {
                "observed_monotonic_ns": int(item.get("observed_monotonic_ns", -1)),
                "rss_bytes": int(item.get("rss_bytes", -1)),
            }
            for item in resource_values
            if event_started
            <= int(item.get("observed_monotonic_ns", -1))
            <= drain_finished
        ]
        if not rss_window:
            raise AnalysisValidationError(
                "soak RSS claim window has no retained samples"
            )
        if resources.get("rss_slope") != systems._rss_slope(rss_window):
            raise AnalysisValidationError("soak RSS slope is not recomputed")
        if int(resources.get("peak_sampled_rss_bytes", -1)) != max(
            item["rss_bytes"] for item in rss_window
        ):
            raise AnalysisValidationError("soak peak RSS is not recomputed")
        before = _require_dict(resources.get("before"), "soak resources before")
        after = _require_dict(resources.get("after"), "soak resources after")
        rss_change = int(after.get("rss_bytes", -1)) - int(before.get("rss_bytes", -1))
        if (
            int(resources.get("rss_change_bytes", 0)) != rss_change
            or resources.get("rss_change_bytes_per_event")
            != round(rss_change / events_submitted, 6)
            or resources.get("rss_change_bytes_per_event_denominator")
            != {"field": "events_submitted", "value": events_submitted}
        ):
            raise AnalysisValidationError(
                "soak RSS change/per-submitted-event metric is not recomputed"
            )
        formal_batch_size = int(
            (
                _load_json(REPO_ROOT / PROTOCOL_PATHS[-1]).get(
                    "formal_effective_config", {}
                )
            ).get("soak_batch_size", -1)
        )
        if int(value.get("batch_size", -1)) != formal_batch_size:
            raise AnalysisValidationError("soak batch size differs from frozen config")
        next_offset = 0
        for batch in batches:
            if (
                not isinstance(batch, dict)
                or int(batch.get("offset", -1)) != next_offset
                or int(batch.get("events", 0)) <= 0
                or int(batch.get("events", 0)) > formal_batch_size
                or int(batch.get("events", 0)) * int(value.get("rule_count", -1)) > 512
            ):
                raise AnalysisValidationError("soak batches are not contiguous")
            next_offset += int(batch["events"])
        if next_offset != events_submitted:
            raise AnalysisValidationError(
                "soak batch coverage differs from events_submitted"
            )
        full = _require_dict(
            (
                ((value.get("post_drain") or {}).get("final_drain_wait") or {}).get(
                    "full_journal_accounting"
                )
            ),
            "soak full-journal accounting",
        )
        for name in (
            "expected_terminal_tuples",
            "observed_terminal_tuples",
            "missing",
            "complete",
            "accounting",
            "accounting_source",
            "journal_inode_reachability",
        ):
            if name not in full:
                raise AnalysisValidationError(
                    f"soak full-journal accounting lacks {name}"
                )
        expected_terminal = events_submitted * int(value.get("rule_count", -1))
        missing = list(full.get("missing") or [])
        observed_terminal = int(full.get("observed_terminal_tuples", -1))
        if (
            int(full.get("expected_terminal_tuples", -1)) != expected_terminal
            or observed_terminal + len(missing) != expected_terminal
            or bool(full.get("complete"))
            is not (not missing and observed_terminal == expected_terminal)
        ):
            raise AnalysisValidationError(
                "soak full-journal union accounting is internally inconsistent"
            )
        full_accounting = _require_dict(
            full.get("accounting"), "soak full-journal exact accounting"
        )
        if int(full_accounting.get("evaluations_expected", -1)) != expected_terminal:
            raise AnalysisValidationError(
                "soak exact accounting denominator differs from submitted workload"
            )
        drain = _require_dict(value.get("post_drain"), "soak post-drain outcome")
        final_wait = _require_dict(
            drain.get("final_drain_wait"), "soak final-drain wait"
        )
        settle = _require_dict(final_wait.get("final_settle"), "soak final settle")
        drain_complete = bool(
            not final_wait.get("timed_out")
            and full.get("complete") is True
            and settle.get("quiescent") is True
        )
        expected_drain_status = "completed" if drain_complete else "not_applicable"
        if drain.get("status") != expected_drain_status:
            raise AnalysisValidationError("soak post-drain status gate mismatch")
        if not isinstance(value.get("restart_persistence"), dict):
            raise AnalysisValidationError("soak lacks restart eligibility/outcome")
        if (
            value["restart_persistence"].get("status") == "completed"
            and "post_restart_history_query" not in normalized
        ):
            raise AnalysisValidationError(
                "completed soak restart lacks incremental post-restart query"
            )
        unit["incremental_receipts"] = normalized


def _validate_matrix_evidence(root: Path, units: Sequence[dict[str, Any]]) -> None:
    for unit in units:
        if unit["component"] != "matrix" or unit["value"] is None:
            continue
        value = unit["value"]
        if value.get("error") is not None:
            continue
        evidence = _require_dict(
            value.get("incremental_evidence"), "matrix incremental evidence"
        )
        receipts: dict[str, Any] = {}
        values: dict[str, list[Any]] = {}
        for name in ("journal_progress", "history_checkpoints"):
            receipts[name], values[name] = _validated_jsonl(
                root, evidence.get(name), f"matrix {name}"
            )
        if not values["journal_progress"] or not all(
            isinstance(item, dict) for item in values["journal_progress"]
        ):
            raise AnalysisValidationError("matrix journal progress is empty/invalid")
        observed = [
            int(item.get("observed_monotonic_ns", -1))
            for item in values["journal_progress"]
        ]
        if observed != sorted(observed) or any(value < 0 for value in observed):
            raise AnalysisValidationError(
                "matrix journal progress timestamps are not monotonic"
            )
        checkpoints = values["history_checkpoints"]
        if not checkpoints or not all(isinstance(item, dict) for item in checkpoints):
            raise AnalysisValidationError(
                "matrix history checkpoints are empty/invalid"
            )
        allowed = {"journal_transition_confirmation", "condition_quiescence"}
        if any(item.get("kind") not in allowed for item in checkpoints):
            raise AnalysisValidationError("matrix history checkpoint kind is invalid")
        transition_count = sum(
            item.get("kind") == "journal_transition_confirmation"
            for item in checkpoints
        )
        query_latencies = [
            item.get("query_latency_ns")
            for item in checkpoints
            if item.get("kind") == "journal_transition_confirmation"
        ]
        if any(not _is_exact_int(item) or item < 0 for item in query_latencies):
            raise AnalysisValidationError(
                "matrix History checkpoint query latency is invalid"
            )
        if transition_count != len(query_latencies) or value.get(
            "evaluation_history_query"
        ) != _query_summary(query_latencies, empty_unit="ms"):
            raise AnalysisValidationError(
                "matrix History summary disagrees with incremental query samples"
            )
        if not any(item.get("kind") == "condition_quiescence" for item in checkpoints):
            raise AnalysisValidationError("matrix lacks a quiescence checkpoint")
        samples = list(value.get("samples") or [])
        sample_by_hash = {str(item.get("input_sha256", "")): item for item in samples}
        sample_hashes = set(sample_by_hash)
        if len(sample_by_hash) != len(samples):
            raise AnalysisValidationError("matrix sample hashes are not unique")
        formal_config = _require_dict(
            _load_json(REPO_ROOT / PROTOCOL_PATHS[-1]).get("formal_effective_config"),
            "formal effective config",
        )
        submissions = [int(item.get("submitted_monotonic_ns", -1)) for item in samples]
        if not submissions or any(item < 0 for item in submissions):
            raise AnalysisValidationError("matrix sample lacks submission timestamp")
        burst_deadline = min(submissions) + int(
            float(formal_config["drain_timeout_seconds"]) * 1_000_000_000
        )
        deadlines = {
            input_hash: (
                int(sample["submitted_monotonic_ns"])
                + int(float(formal_config["timeout_seconds"]) * 1_000_000_000)
                if value.get("mode") == "sequential"
                else burst_deadline
            )
            for input_hash, sample in sample_by_hash.items()
        }
        first_confirmed: dict[str, int] = {}
        all_confirmed: dict[str, int] = {}
        saturated_inputs: set[str] = set()
        for checkpoint in checkpoints:
            if checkpoint.get("kind") != "journal_transition_confirmation":
                continue
            observed_ns = int(checkpoint.get("observed_monotonic_ns", -1))
            if observed_ns < 0:
                raise AnalysisValidationError(
                    "matrix History checkpoint lacks a monotonic timestamp"
                )
            triggers = {
                str(item) for item in checkpoint.get("trigger_input_sha256") or []
            }
            if not triggers or not triggers.issubset(sample_hashes):
                raise AnalysisValidationError(
                    "matrix History checkpoint trigger inputs are invalid"
                )
            expected_within_deadline = all(
                observed_ns <= deadlines[input_hash] for input_hash in triggers
            )
            if checkpoint.get("within_deadline") is not expected_within_deadline:
                raise AnalysisValidationError(
                    "matrix History checkpoint deadline flag is not recomputed"
                )
            limit = int(checkpoint.get("limit", -1))
            rows = int(checkpoint.get("rows", -1))
            if limit <= 0 or rows < 0 or rows > limit:
                raise AnalysisValidationError(
                    "matrix History checkpoint row/limit evidence is invalid"
                )
            if rows >= limit:
                saturated_inputs.update(triggers)
            for name, target in (
                ("first_visible_confirmed", first_confirmed),
                ("all_visible_confirmed", all_confirmed),
            ):
                confirmations = {str(item) for item in checkpoint.get(name) or []}
                if not confirmations.issubset(triggers):
                    raise AnalysisValidationError(
                        "matrix checkpoint confirms an untriggered input"
                    )
                if confirmations and not expected_within_deadline:
                    raise AnalysisValidationError(
                        "matrix checkpoint confirms an input after its deadline"
                    )
                for input_hash in confirmations:
                    if input_hash not in sample_hashes:
                        raise AnalysisValidationError(
                            "matrix checkpoint confirms an unexpected input"
                        )
                    target.setdefault(input_hash, observed_ns)
        for sample in samples:
            input_hash = str(sample["input_sha256"])
            submitted = int(sample["submitted_monotonic_ns"])
            expected_deadline = deadlines[input_hash]
            first_ns = first_confirmed.get(input_hash)
            all_ns = all_confirmed.get(input_hash)
            expected_first_latency = (
                first_ns - submitted if first_ns is not None else None
            )
            expected_all_latency = all_ns - submitted if all_ns is not None else None
            expected_censor = (
                None if all_ns is not None else max(0, expected_deadline - submitted)
            )
            for name, expected in (
                ("censor_deadline_monotonic_ns", expected_deadline),
                ("first_visible_monotonic_ns", first_ns),
                ("all_visible_monotonic_ns", all_ns),
                ("event_to_first_query_visible_evaluation_ns", expected_first_latency),
                ("event_to_all_query_visible_evaluations_ns", expected_all_latency),
                ("latency_censored_at_ns", expected_censor),
            ):
                if sample.get(name) != expected:
                    raise AnalysisValidationError(
                        f"matrix sample endpoint/deadline mismatch: {name}"
                    )
        for field in (
            "event_to_first_query_visible_evaluation",
            "event_to_all_query_visible_evaluations",
        ):
            recomputed = systems._latency_summary(samples, f"{field}_ms")
            if value.get(field) != recomputed:
                raise AnalysisValidationError(
                    f"matrix {field} summary is not recomputed from samples"
                )
        for field, sample_field in (
            ("hook_process_exit", "hook_exit_ns"),
            ("submission_to_hook_exit", "submission_to_hook_exit_ns"),
            ("executor_queue", "executor_queue_ns"),
        ):
            if field not in value:
                continue
            raw_values = [sample.get(sample_field) for sample in samples]
            if any(
                not _is_exact_int(item) or item < 0 for item in raw_values
            ) or value.get(field) != _query_summary(raw_values):
                raise AnalysisValidationError(
                    f"matrix {field} summary is not recomputed from samples"
                )
        quiescence = [
            item for item in checkpoints if item.get("kind") == "condition_quiescence"
        ]
        ordered_hashes = [
            str(item["input_sha256"])
            for item in sorted(
                samples, key=lambda item: int(item["submitted_monotonic_ns"])
            )
        ]
        quiescence_groups = (
            [[item] for item in ordered_hashes]
            if value.get("mode") == "sequential"
            else [ordered_hashes]
        )
        if len(quiescence) != len(quiescence_groups):
            raise AnalysisValidationError(
                "matrix quiescence checkpoint count differs from traffic mode"
            )
        group_complete: dict[str, bool] = {}
        for checkpoint, group in zip(quiescence, quiescence_groups):
            observed_ns = int(checkpoint.get("observed_monotonic_ns", -1))
            started_ns = int(checkpoint.get("started_monotonic_ns", -1))
            inflight = int(checkpoint.get("inflight_evaluations", -1))
            outcomes_without_start = int(
                checkpoint.get("outcomes_without_observed_start", -1)
            )
            expected_within = bool(
                observed_ns >= started_ns >= 0
                and all(observed_ns <= deadlines[input_hash] for input_hash in group)
            )
            if checkpoint.get("within_deadline") is not expected_within:
                raise AnalysisValidationError(
                    "matrix quiescence deadline flag is not recomputed"
                )
            expected_complete = bool(
                expected_within
                and inflight == 0
                and outcomes_without_start == 0
                and all(
                    input_hash in all_confirmed
                    and all_confirmed[input_hash] <= observed_ns
                    for input_hash in group
                )
            )
            if checkpoint.get("complete") is not expected_complete:
                raise AnalysisValidationError(
                    "matrix quiescence completion flag is not recomputed"
                )
            for input_hash in group:
                group_complete[input_hash] = expected_complete

        missing = sorted(sample_hashes - set(all_confirmed))
        expected_saturated = bool(saturated_inputs)
        expected_integrity = bool(
            expected_saturated or not all(group_complete.values())
        )
        wait = _require_dict(value.get("wait"), "matrix wait outcome")
        if (
            wait.get("timed_out") is not bool(missing)
            or sorted(wait.get("missing_input_sha256") or []) != missing
            or wait.get("history_limit_saturated") is not expected_saturated
            or wait.get("integrity_violation") is not expected_integrity
        ):
            raise AnalysisValidationError(
                "matrix wait timeout/integrity gate is not recomputed"
            )
        if value.get("mode") == "sequential":
            per_event = list(wait.get("per_event_wait") or [])
            if len(per_event) != len(samples):
                raise AnalysisValidationError(
                    "matrix sequential waits do not cover every event"
                )
            by_input = {str(item.get("input_sha256", "")): item for item in per_event}
            if set(by_input) != sample_hashes:
                raise AnalysisValidationError(
                    "matrix sequential wait/input binding is invalid"
                )
            for input_hash, per_wait in by_input.items():
                per_missing = [] if input_hash in all_confirmed else [input_hash]
                per_saturated = input_hash in saturated_inputs
                per_integrity = bool(per_saturated or not group_complete[input_hash])
                settle = _require_dict(
                    per_wait.get("settle"), "matrix sequential settle"
                )
                checkpoint = quiescence[ordered_hashes.index(input_hash)]
                if (
                    int(per_wait.get("deadline_monotonic_ns", -1))
                    != deadlines[input_hash]
                    or per_wait.get("timed_out") is not bool(per_missing)
                    or sorted(per_wait.get("missing_input_sha256") or []) != per_missing
                    or per_wait.get("history_limit_saturated") is not per_saturated
                    or per_wait.get("integrity_violation") is not per_integrity
                    or settle.get("complete") is not group_complete[input_hash]
                    or int(settle.get("started_monotonic_ns", -1))
                    != int(checkpoint["started_monotonic_ns"])
                    or int(settle.get("finished_monotonic_ns", -1))
                    != int(checkpoint["observed_monotonic_ns"])
                ):
                    raise AnalysisValidationError(
                        "matrix per-event wait gate is not recomputed"
                    )
        else:
            settle = _require_dict(wait.get("settle"), "matrix burst settle")
            checkpoint = quiescence[0]
            if (
                settle.get("complete") is not all(group_complete.values())
                or int(settle.get("started_monotonic_ns", -1))
                != int(checkpoint["started_monotonic_ns"])
                or int(settle.get("finished_monotonic_ns", -1))
                != int(checkpoint["observed_monotonic_ns"])
            ):
                raise AnalysisValidationError(
                    "matrix burst settle gate is not recomputed"
                )
        unit["incremental_receipts"] = receipts


def _validate_unit_plan_bindings(units: Sequence[dict[str, Any]]) -> None:
    for unit in units:
        value = unit.get("value")
        if not isinstance(value, dict):
            continue
        plan = dict(unit.get("plan") or {})
        component = unit["component"]
        if component == "faults":
            expected = {
                "fault": plan.get("fault"),
                "repetition": plan.get("repetition"),
            }
            observed = {name: value.get(name) for name in expected}
            if observed != expected:
                raise AnalysisValidationError(
                    f"fault terminal/plan binding mismatch for {unit['unit_id']}"
                )
            continue
        if value.get("error") is not None:
            continue
        if component == "matrix":
            expected = {
                "condition_id": plan.get("condition_id"),
                "rule_count": plan.get("rule_count"),
                "project_count": plan.get("project_count"),
                "schedule": plan.get("schedule"),
                "mode": plan.get("mode"),
                "event_count": plan.get("events"),
                "repeat": plan.get("repeat"),
            }
            observed = {name: value.get(name) for name in expected}
            if observed != expected:
                raise AnalysisValidationError(
                    f"matrix terminal/plan binding mismatch for {unit['unit_id']}"
                )
            samples = list(value.get("samples") or [])
            expected_cases = {
                f"{unit['unit_id']}-p"
                f"{sequence % int(plan['project_count']) if plan['schedule'] == 'round_robin_across_projects' else 0}"
                f"-e{sequence}"
                for sequence in range(int(plan["events"]))
            }
            cases = {str(item.get("case_id", "")) for item in samples}
            hashes = [str(item.get("input_sha256", "")) for item in samples]
            if (
                len(samples) != int(plan["events"])
                or cases != expected_cases
                or len(cases) != len(samples)
                or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
                or len(set(hashes)) != len(hashes)
            ):
                raise AnalysisValidationError(
                    f"matrix sample/plan binding mismatch for {unit['unit_id']}"
                )
        elif component == "soak":
            expected = {
                "events": plan.get("events"),
                "rule_count": plan.get("rule_count"),
                "project_count": plan.get("project_count"),
            }
            if {name: value.get(name) for name in expected} != expected:
                raise AnalysisValidationError(
                    f"soak terminal/plan binding mismatch for {unit['unit_id']}"
                )
        elif component == "offline":
            if value.get("rule_count") != plan.get("rules"):
                raise AnalysisValidationError(
                    f"offline terminal/plan binding mismatch for {unit['unit_id']}"
                )


def _evaluation_accountings(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            if "evaluations_expected" in node:
                found.append(node)
            for item in node.values():
                visit(item)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(value)
    return found


def _require_expected_evaluations(value: Any, expected: int, label: str) -> None:
    if not isinstance(value, dict) or "evaluations_expected" not in value:
        return
    if value.get("evaluations_expected") != expected:
        raise AnalysisValidationError(
            f"{label} evaluations_expected differs from the planned workload"
        )


def _validate_fault_quiescence_projection(value: Mapping[str, Any], label: str) -> None:
    required = {
        "complete",
        "stable_across_settle",
        "exact_declared_terminal_records",
        "expected_input_sha256_counts",
        "before_settle",
        "after_settle",
        "settle_started_monotonic_ns",
        "settle_finished_monotonic_ns",
    }
    if not required.issubset(value):
        return
    before = _require_dict(value.get("before_settle"), f"{label} before_settle")
    after = _require_dict(value.get("after_settle"), f"{label} after_settle")
    expected_counts = _require_dict(
        value.get("expected_input_sha256_counts"),
        f"{label} expected_input_sha256_counts",
    )
    if any(
        not isinstance(key, str) or not _is_exact_int(count) or count < 0
        for key, count in expected_counts.items()
    ):
        raise AnalysisValidationError(f"{label} expected counts are invalid")
    stable = bool(
        before.get("canonical_projection_sha256")
        == after.get("canonical_projection_sha256")
    )
    expected_total = sum(expected_counts.values())
    exact = bool(
        after.get("count") == expected_total
        and after.get("terminal_count") == expected_total
        and after.get("input_sha256_counts") == expected_counts
    )
    settle_started = value.get("settle_started_monotonic_ns")
    settle_finished = value.get("settle_finished_monotonic_ns")
    if (
        not _is_exact_int(settle_started)
        or not _is_exact_int(settle_finished)
        or settle_started < 0
        or settle_finished < settle_started
        or value.get("stable_across_settle") is not stable
        or value.get("exact_declared_terminal_records") is not exact
        or value.get("complete") is not (stable and exact)
    ):
        raise AnalysisValidationError(
            f"{label} quiescence accounting is not reconstructed"
        )


def _validate_process_scan_diagnostics(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise AnalysisValidationError(f"{label} must be a list")
    records = []
    for index, item_value in enumerate(value):
        item = _require_dict(item_value, f"{label} record {index}")
        if (
            set(item) != {"pid", "type", "message"}
            or not _is_exact_int(item.get("pid"))
            or int(item["pid"]) < -1
            or not isinstance(item.get("type"), str)
            or not item["type"]
            or not isinstance(item.get("message"), str)
        ):
            raise AnalysisValidationError(f"{label} record {index} is invalid")
        records.append(item)
    if records != sorted(
        records, key=lambda item: (item["pid"], item["type"], item["message"])
    ):
        raise AnalysisValidationError(f"{label} is not canonical")
    return records


def _validate_orphan_processes(
    value: Any, label: str, *, allow_none: bool = False
) -> list[dict[str, Any]] | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, list):
        raise AnalysisValidationError(f"{label} must be a process list")
    records = []
    for index, item_value in enumerate(value):
        item = _require_dict(item_value, f"{label} process {index}")
        create_time = item.get("create_time")
        cmdline = item.get("cmdline")
        if (
            set(item) != {"pid", "create_time", "cmdline"}
            or not _is_exact_int(item.get("pid"))
            or int(item["pid"]) <= 0
            or not isinstance(create_time, (int, float))
            or isinstance(create_time, bool)
            or not math.isfinite(float(create_time))
            or float(create_time) <= 0.0
            or not isinstance(cmdline, list)
            or not all(isinstance(part, str) for part in cmdline)
        ):
            raise AnalysisValidationError(f"{label} process {index} is invalid")
        records.append(item)
    if records != sorted(records, key=lambda item: int(item["pid"])) or len(
        {int(item["pid"]) for item in records}
    ) != len(records):
        raise AnalysisValidationError(f"{label} process list is not canonical")
    return records


def _validate_fault_settle(value: Any, label: str) -> dict[str, Any]:
    settle = _require_dict(value, label)
    base_fields = {
        "status",
        "started_monotonic_ns",
        "deadline_monotonic_ns",
        "finished_monotonic_ns",
        "poll_interval_seconds",
        "completed_within_deadline",
        "observations",
        "final_orphan_processes",
        "final_scan_errors",
    }
    status = settle.get("status")
    expected_fields = (
        base_fields | {"stage", "error"}
        if status == "measurement_error"
        else base_fields
    )
    if set(settle) != expected_fields:
        raise AnalysisValidationError(f"{label} has an invalid schema")
    started = settle.get("started_monotonic_ns")
    deadline = settle.get("deadline_monotonic_ns")
    finished = settle.get("finished_monotonic_ns")
    if (
        not _is_exact_int(started)
        or not _is_exact_int(deadline)
        or not _is_exact_int(finished)
        or started < 0
        or deadline < started
        or finished < started
        or settle.get("poll_interval_seconds") != systems.QUERY_POLL_INTERVAL_SECONDS
        or not isinstance(settle.get("completed_within_deadline"), bool)
        or not isinstance(settle.get("observations"), list)
    ):
        raise AnalysisValidationError(f"{label} has invalid timing fields")
    if status == "measurement_error":
        error = _require_dict(settle.get("error"), f"{label} error")
        if (
            settle.get("stage") not in {"initial_settle", "post_force_settle"}
            or set(error) != {"type", "message", "traceback"}
            or not all(isinstance(error.get(name), str) for name in error)
            or settle.get("completed_within_deadline") is not False
            or settle.get("observations") != []
            or settle.get("final_orphan_processes") is not None
        ):
            raise AnalysisValidationError(f"{label} measurement error is invalid")
        _validate_process_scan_diagnostics(
            settle.get("final_scan_errors"), f"{label} final scan errors"
        )
        return settle

    if status not in {
        "complete",
        "timed_out",
        "not_measured_without_retained_runtime_root",
    }:
        raise AnalysisValidationError(f"{label} status is invalid")
    observations = list(settle["observations"])
    if not observations:
        raise AnalysisValidationError(f"{label} has no scan observations")
    previous_finished = started
    for index, observation_value in enumerate(observations):
        observation = _require_dict(observation_value, f"{label} observation {index}")
        if set(observation) != {
            "query_started_monotonic_ns",
            "query_finished_monotonic_ns",
            "within_deadline",
            "processes",
            "scan_errors",
            "race_diagnostics",
        }:
            raise AnalysisValidationError(
                f"{label} observation {index} has an invalid schema"
            )
        query_started = observation.get("query_started_monotonic_ns")
        query_finished = observation.get("query_finished_monotonic_ns")
        if (
            not _is_exact_int(query_started)
            or not _is_exact_int(query_finished)
            or query_started < previous_finished
            or query_finished < query_started
            or observation.get("within_deadline") is not (query_finished <= deadline)
        ):
            raise AnalysisValidationError(
                f"{label} observation {index} timing is invalid"
            )
        _validate_orphan_processes(
            observation.get("processes"),
            f"{label} observation {index}",
            allow_none=True,
        )
        _validate_process_scan_diagnostics(
            observation.get("scan_errors"),
            f"{label} observation {index} scan errors",
        )
        _validate_process_scan_diagnostics(
            observation.get("race_diagnostics"),
            f"{label} observation {index} race diagnostics",
        )
        previous_finished = query_finished
    last = observations[-1]
    final_orphans = _validate_orphan_processes(
        settle.get("final_orphan_processes"),
        f"{label} final orphan processes",
        allow_none=True,
    )
    final_errors = _validate_process_scan_diagnostics(
        settle.get("final_scan_errors"), f"{label} final scan errors"
    )
    if (
        finished != last.get("query_finished_monotonic_ns")
        or final_orphans != last.get("processes")
        or final_errors != last.get("scan_errors")
    ):
        raise AnalysisValidationError(f"{label} final scan mirrors disagree")
    expected_status = (
        "not_measured_without_retained_runtime_root"
        if final_orphans is None
        else "complete"
        if final_orphans == []
        and not final_errors
        and last.get("within_deadline") is True
        else "timed_out"
        if finished >= deadline
        else None
    )
    if (
        expected_status is None
        or status != expected_status
        or settle.get("completed_within_deadline") is not (status == "complete")
    ):
        raise AnalysisValidationError(f"{label} outcome is not reconstructed")
    return settle


def _validate_forced_cleanup(
    value: Any,
    label: str,
    *,
    expected_state_dir: str,
    initial_orphans: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    forced = _require_dict(value, label)
    force_error = forced.get("status") == "force_error"
    expected_fields = {
        "status",
        "started_monotonic_ns",
        "finished_monotonic_ns",
        "expected_rap_state_dir",
        "actions",
    } | ({"error"} if force_error else set())
    if set(forced) != expected_fields:
        raise AnalysisValidationError(f"{label} has an invalid schema")
    started = forced.get("started_monotonic_ns")
    finished = forced.get("finished_monotonic_ns")
    if (
        not _is_exact_int(started)
        or not _is_exact_int(finished)
        or started < 0
        or finished < started
        or forced.get("expected_rap_state_dir") != expected_state_dir
        or not isinstance(forced.get("actions"), list)
    ):
        raise AnalysisValidationError(f"{label} has invalid timing/identity fields")
    if force_error:
        error = _require_dict(forced.get("error"), f"{label} error")
        if (
            forced.get("actions") != []
            or set(error) != {"type", "message", "traceback"}
            or not all(isinstance(error.get(name), str) for name in error)
        ):
            raise AnalysisValidationError(f"{label} force error is invalid")
        return forced

    captured = initial_orphans or []
    actions = list(forced["actions"])
    if len(actions) != len(captured):
        raise AnalysisValidationError(f"{label} does not cover every initial orphan")
    any_kill_error = False
    for index, (action_value, process) in enumerate(zip(actions, captured)):
        action = _require_dict(action_value, f"{label} action {index}")
        base_fields = {
            "pid",
            "captured_create_time",
            "captured_cmdline",
            "expected_rap_state_dir",
            "ownership_confirmed",
            "action",
        }
        optional_fields = {
            "observed_create_time",
            "observed_rap_state_dir",
            "observed_cmdline",
            "error",
        }
        if not base_fields.issubset(action) or not set(action).issubset(
            base_fields | optional_fields
        ):
            raise AnalysisValidationError(f"{label} action {index} schema is invalid")
        if (
            action.get("pid") != process.get("pid")
            or action.get("captured_create_time") != process.get("create_time")
            or action.get("captured_cmdline") != process.get("cmdline")
            or action.get("expected_rap_state_dir") != expected_state_dir
            or not isinstance(action.get("ownership_confirmed"), bool)
        ):
            raise AnalysisValidationError(
                f"{label} action {index} is not bound to the captured process"
            )
        observed_fields = {
            "observed_create_time",
            "observed_rap_state_dir",
            "observed_cmdline",
        }
        present_observed = observed_fields.intersection(action)
        if present_observed and present_observed != observed_fields:
            raise AnalysisValidationError(
                f"{label} action {index} has partial observed identity"
            )
        identity_matches = bool(
            present_observed
            and action.get("observed_create_time") == process.get("create_time")
            and action.get("observed_rap_state_dir") == expected_state_dir
        )
        if action.get("ownership_confirmed") is not identity_matches:
            raise AnalysisValidationError(
                f"{label} action {index} ownership is not reconstructed"
            )
        action_name = action.get("action")
        if action_name not in {
            "sigkill_sent",
            "skipped_identity_mismatch",
            "already_exited",
            "kill_error",
        }:
            raise AnalysisValidationError(f"{label} action {index} is invalid")
        if action_name == "sigkill_sent" and not identity_matches:
            raise AnalysisValidationError(
                f"{label} action {index} sent SIGKILL without exact ownership"
            )
        if action_name == "skipped_identity_mismatch" and (
            not present_observed or identity_matches
        ):
            raise AnalysisValidationError(
                f"{label} action {index} identity-mismatch result is invalid"
            )
        if action_name == "already_exited" and (present_observed or "error" in action):
            raise AnalysisValidationError(
                f"{label} action {index} already-exited result is invalid"
            )
        if action_name == "kill_error":
            any_kill_error = True
            if not isinstance(action.get("error"), str) or not action["error"]:
                raise AnalysisValidationError(
                    f"{label} action {index} kill error is missing"
                )
        elif "error" in action:
            raise AnalysisValidationError(
                f"{label} action {index} unexpectedly carries an error"
            )
    expected_status = "completed_with_errors" if any_kill_error else "completed"
    if forced.get("status") != expected_status:
        raise AnalysisValidationError(f"{label} status is not reconstructed")
    return forced


def _validate_fault_cleanup(
    value: Mapping[str, Any], unit: Mapping[str, Any], root: Path | None = None
) -> None:
    label = f"fault cleanup {unit.get('unit_id')}"
    probe = _require_dict(value.get("probe_specific"), f"{label} probe")
    cleanup = _require_dict(
        probe.get("post_shutdown_process_cleanup"), f"{label} receipt"
    )
    if set(cleanup) != {
        "initial_settle",
        "forced_actions",
        "final_settle",
        "measurable",
        "safe_to_continue",
        "final_orphan_processes",
        "final_scan_errors",
    }:
        raise AnalysisValidationError(f"{label} receipt schema is invalid")
    runtime_evidence = probe.get("runtime_evidence") or {}
    retained_root = (
        runtime_evidence.get("retained_runtime_root")
        if isinstance(runtime_evidence, dict)
        else None
    )
    error = value.get("error") or {}
    if retained_root is None and isinstance(error, dict):
        retained_root = error.get("retained_runtime_root")
    if not isinstance(retained_root, str) or not retained_root:
        raise AnalysisValidationError(f"{label} lacks a retained runtime root")
    retained_path = Path(retained_root)
    unit_id = str(unit.get("unit_id", ""))
    if (
        not retained_path.is_absolute()
        or retained_path.name != unit_id
        or retained_path.parent.name != "faults"
        or retained_path.parent.parent.name != "runtime"
    ):
        raise AnalysisValidationError(f"{label} retained runtime root is not bound")
    if root is not None:
        expected_root = root / "runtime" / "faults" / unit_id
        if retained_path != expected_root or not expected_root.is_dir():
            raise AnalysisValidationError(
                f"{label} retained runtime root differs from the attempt"
            )
        for candidate in (
            root / "runtime",
            root / "runtime" / "faults",
            expected_root,
        ):
            if candidate.is_symlink():
                raise AnalysisValidationError(
                    f"{label} retained runtime path contains a symlink"
                )
    expected_state_dir = str(retained_path / "state")

    initial = _validate_fault_settle(cleanup.get("initial_settle"), f"{label} initial")
    final = _validate_fault_settle(cleanup.get("final_settle"), f"{label} final")
    if cleanup.get("measurable") is not True:
        raise AnalysisValidationError(f"{label} was not measured in retained runtime")
    forced_value = cleanup.get("forced_actions")
    if initial.get("completed_within_deadline") is True:
        if forced_value is not None or final != initial:
            raise AnalysisValidationError(
                f"{label} forced cleanup ran after an already-complete settle"
            )
    else:
        forced = _validate_forced_cleanup(
            forced_value,
            f"{label} forced actions",
            expected_state_dir=expected_state_dir,
            initial_orphans=initial.get("final_orphan_processes"),
        )
        if initial.get("finished_monotonic_ns") > forced.get(
            "started_monotonic_ns"
        ) or forced.get("finished_monotonic_ns") > final.get("started_monotonic_ns"):
            raise AnalysisValidationError(f"{label} phase timestamps overlap")
    final_orphans = final.get("final_orphan_processes")
    final_scan_errors = final.get("final_scan_errors")
    safe = bool(
        final.get("completed_within_deadline") is True
        and final_orphans == []
        and final_scan_errors == []
    )
    if (
        cleanup.get("final_orphan_processes") != final_orphans
        or cleanup.get("final_scan_errors") != final_scan_errors
        or cleanup.get("safe_to_continue") is not safe
    ):
        raise AnalysisValidationError(f"{label} final isolation is not reconstructed")
    expected_count = len(final_orphans) if isinstance(final_orphans, list) else None
    expected_count_status = (
        "measurement incomplete because the final process scan had errors"
        if final_scan_errors
        else "measured after bounded post-shutdown fixture cleanup and forced recheck"
        if final_orphans is not None
        else "not measured without a retained runtime root"
    )
    mirrors = {
        "post_shutdown_process_settle": initial,
        "forced_process_cleanup": forced_value,
        "post_force_process_settle": final,
        "orphan_processes_after_cleanup": final_orphans,
        "orphan_process_count": expected_count,
        "orphan_process_count_status": expected_count_status,
    }
    for name, expected in mirrors.items():
        if probe.get(name) != expected:
            raise AnalysisValidationError(f"{label} mirror {name} disagrees")
    standardized = _require_dict(
        value.get("standardized_outcomes"), f"{label} standardized outcome"
    )
    if (
        standardized.get("orphan_process_count") != expected_count
        or standardized.get("orphan_process_count_status") != expected_count_status
        or standardized.get("post_shutdown_process_cleanup") != cleanup
    ):
        raise AnalysisValidationError(f"{label} standardized cleanup disagrees")
    cleanup_violation = value.get("cleanup_system_violation")
    if safe:
        if cleanup_violation is not None:
            raise AnalysisValidationError(f"{label} safe cleanup carries a violation")
    else:
        expected_violation = {
            "classification_basis": (
                "post-shutdown retained-runtime processes could not be proven "
                "absent after exact-owner forced cleanup"
            ),
            "cleanup": cleanup,
        }
        if (
            value.get("status") != "system_violation"
            or value.get("passed") is not False
            or cleanup_violation != expected_violation
        ):
            raise AnalysisValidationError(
                f"{label} unsafe isolation is not a terminal system violation"
            )


def _validate_component_internal_consistency(
    unit: Mapping[str, Any], root: Path | None = None
) -> None:
    value = unit.get("value")
    if not isinstance(value, dict):
        return
    label = f"{unit.get('component')} unit {unit.get('unit_id')}"
    _validate_embedded_hook_projections(value, label)
    component = str(unit.get("component", ""))
    _validate_embedded_accounting(value, label, fault=component == "faults")
    if component == "faults":
        _validate_fault_cleanup(value, unit, root)
    if value.get("error") is not None:
        return

    if component == "matrix":
        expected = int(value.get("event_count", -1)) * int(value.get("rule_count", -1))
        _require_expected_evaluations(
            value.get("accounting"), expected, f"{label} accounting"
        )
        return

    if component == "soak":
        events = int(value.get("events", -1))
        submitted = int(value.get("events_submitted", -1))
        rule_count = int(value.get("rule_count", -1))
        not_submitted = int(value.get("events_not_submitted_after_drain_timeout", -1))
        if (
            events < 0
            or submitted < 0
            or submitted > events
            or not_submitted != events - submitted
            or rule_count <= 0
        ):
            raise AnalysisValidationError(
                f"{label} submitted/not-submitted accounting is inconsistent"
            )
        batch_sum_fields = (
            "evaluations_expected",
            "evaluations_observed_for_expected_keys",
            "loss_count",
            "duplicate_count",
            "unexpected_count",
            "cross_project_contamination_count",
            "failed_count",
            "running_count",
            "provenance_mismatch_count",
        )
        batches = list(value.get("batches") or [])
        expected_sums = {name: 0 for name in batch_sum_fields}
        for index, batch_value in enumerate(batches):
            batch = _require_dict(batch_value, f"{label} batch {index}")
            batch_accounting = _require_dict(
                batch.get("accounting"), f"{label} batch {index} accounting"
            )
            _require_expected_evaluations(
                batch_accounting,
                int(batch.get("events", -1)) * rule_count,
                f"{label} batch {index} accounting",
            )
            for name in batch_sum_fields:
                expected_sums[name] += _nonnegative_count(
                    batch_accounting.get(name),
                    f"{label} batch {index} accounting.{name}",
                )
        if (
            "batch_accounting_diagnostic_sums_not_global" in value
            and value.get("batch_accounting_diagnostic_sums_not_global")
            != expected_sums
        ):
            raise AnalysisValidationError(
                f"{label} batch diagnostic sums are not reconstructed"
            )
        expected_terminal = submitted * rule_count
        _require_expected_evaluations(
            value.get("global_accounting"),
            expected_terminal,
            f"{label} global accounting",
        )
        full = (
            ((value.get("post_drain") or {}).get("final_drain_wait") or {}).get(
                "full_journal_accounting"
            )
        ) or {}
        _require_expected_evaluations(
            full.get("accounting"),
            expected_terminal,
            f"{label} full-journal accounting",
        )
        return

    if component == "offline":
        expected = int(value.get("rule_count", -1))
        for arm_name in ("online", "offline"):
            arm = value.get(arm_name)
            if not isinstance(arm, dict):
                continue
            _require_expected_evaluations(
                arm.get("accounting"), expected, f"{label} {arm_name} accounting"
            )
            sample = arm.get("sample")
            if isinstance(sample, dict) and isinstance(sample.get("hook"), dict):
                expected_contract = _hook_contract_preserved(sample["hook"])
                if (
                    "hook_contract_preserved" in arm
                    and arm.get("hook_contract_preserved") is not expected_contract
                ):
                    raise AnalysisValidationError(
                        f"{label} {arm_name} hook contract mirror disagrees"
                    )
        paired = value.get("paired_event_to_all_latency")
        if isinstance(paired, dict):
            online_sample = (value.get("online") or {}).get("sample") or {}
            offline_sample = (value.get("offline") or {}).get("sample") or {}
            online_ns = online_sample.get("event_to_all_query_visible_evaluations_ns")
            offline_ns = offline_sample.get("event_to_all_query_visible_evaluations_ns")
            expected_paired = {
                "online_ns": online_ns,
                "offline_ns": offline_ns,
                "offline_minus_online_ns": (
                    int(offline_ns) - int(online_ns)
                    if online_ns is not None and offline_ns is not None
                    else None
                ),
                "descriptive_only": True,
            }
            if any(
                paired.get(name) != expected_value
                for name, expected_value in expected_paired.items()
            ):
                raise AnalysisValidationError(
                    f"{label} paired query latency is not reconstructed"
                )
        return

    if component == "faults":
        for accounting in _evaluation_accountings(value):
            _require_expected_evaluations(accounting, 1, f"{label} accounting")

        def visit(node: Any, path: str) -> None:
            if isinstance(node, dict):
                _validate_fault_quiescence_projection(node, path)
                for name, item in node.items():
                    visit(item, f"{path}.{name}")
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    visit(item, f"{path}[{index}]")

        visit(value, label)


def _validated_daemon_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _require_dict(value, label)
    expected_fields = {"ok", "pid", "paw", "protocol", "version", "started_at"}
    if set(identity) != expected_fields:
        raise AnalysisValidationError(f"{label} has an invalid schema")
    started_at = identity.get("started_at")
    if (
        identity.get("ok") is not True
        or not _is_exact_int(identity.get("pid"))
        or int(identity["pid"]) <= 0
        or not isinstance(identity.get("paw"), bool)
        or not _is_exact_int(identity.get("protocol"))
        or int(identity["protocol"]) <= 0
        or not isinstance(identity.get("version"), str)
        or not identity["version"]
        or not isinstance(started_at, (int, float))
        or isinstance(started_at, bool)
        or not math.isfinite(float(started_at))
        or float(started_at) <= 0.0
    ):
        raise AnalysisValidationError(f"{label} has invalid process identity fields")
    return identity


def _validate_offline_boundary_evidence(
    value: Mapping[str, Any], root: Path | None = None
) -> None:
    if value.get("prepared_online") is not True:
        raise AnalysisValidationError(
            "offline probe did not retain prepared-online evidence"
        )
    if value.get("network_boundary") != systems._python_socket_boundary():
        raise AnalysisValidationError(
            "offline network-boundary declaration is not canonical"
        )
    source_receipt = _require_dict(
        value.get("boundary_source_receipt"), "offline boundary source receipt"
    )
    if set(source_receipt) not in (
        {"path", "bytes", "sha256"},
        {"path", "attempt_relative_path", "bytes", "sha256"},
    ):
        raise AnalysisValidationError(
            "offline boundary source receipt schema is invalid"
        )
    expected_source = systems._network_blocker_source().encode("utf-8")
    if (
        source_receipt.get("bytes") != len(expected_source)
        or source_receipt.get("sha256") != _sha256_bytes(expected_source)
        or Path(str(source_receipt.get("path", ""))).name != "sitecustomize.py"
    ):
        raise AnalysisValidationError(
            "offline boundary source receipt differs from the frozen blocker"
        )
    if root is not None:
        _receipt, retained_source = _validated_binary_receipt(
            root, source_receipt, "offline boundary source receipt"
        )
        if retained_source != expected_source:
            raise AnalysisValidationError(
                "offline retained boundary source differs from the frozen blocker"
            )
    records_value = value.get("blocked_attempt_records")
    if not isinstance(records_value, list):
        raise AnalysisValidationError("offline blocked-attempt records must be a list")
    if not _is_exact_int(value.get("blocked_internet_attempts")) or value.get(
        "blocked_internet_attempts"
    ) != len(records_value):
        raise AnalysisValidationError(
            "offline blocked-attempt count differs from retained records"
        )
    allowed_apis = {
        "socket.socket.connect",
        "socket.socket.connect_ex",
        "socket.socket.send",
        "socket.socket.sendall",
        "socket.socket.sendto",
        "socket.socket.sendmsg",
        "socket.create_connection",
    }
    activation_values = value.get("boundary_activation_records")
    if not isinstance(activation_values, list):
        raise AnalysisValidationError(
            "offline boundary-activation records must be a list"
        )
    activation_by_pid: dict[int, list[float]] = defaultdict(list)
    for index, activation_value in enumerate(activation_values):
        activation = _require_dict(
            activation_value, f"offline boundary-activation record {index}"
        )
        timestamp = activation.get("time")
        if (
            set(activation) != {"kind", "pid", "time"}
            or activation.get("kind") != "sitecustomize_loaded"
            or not _is_exact_int(activation.get("pid"))
            or int(activation["pid"]) <= 0
            or not isinstance(timestamp, (int, float))
            or isinstance(timestamp, bool)
            or not math.isfinite(float(timestamp))
            or float(timestamp) <= 0.0
        ):
            raise AnalysisValidationError(
                f"offline boundary-activation record {index} has invalid fields"
            )
        activation_by_pid[int(activation["pid"])].append(float(timestamp))

    for index, record_value in enumerate(records_value):
        record = _require_dict(record_value, f"offline blocked-attempt record {index}")
        if set(record) != {"pid", "time", "api", "family", "address"}:
            raise AnalysisValidationError(
                f"offline blocked-attempt record {index} has an invalid schema"
            )
        timestamp = record.get("time")
        if (
            not _is_exact_int(record.get("pid"))
            or int(record["pid"]) <= 0
            or not isinstance(timestamp, (int, float))
            or isinstance(timestamp, bool)
            or not math.isfinite(float(timestamp))
            or float(timestamp) <= 0.0
            or record.get("api") not in allowed_apis
            or not _is_exact_int(record.get("family"))
            or int(record["family"]) not in {0, 2, 10, 30}
            or not isinstance(record.get("address"), str)
        ):
            raise AnalysisValidationError(
                f"offline blocked-attempt record {index} has invalid fields"
            )
        pid = int(record["pid"])
        if not any(
            activated_at <= float(timestamp)
            for activated_at in activation_by_pid.get(pid, [])
        ):
            raise AnalysisValidationError(
                f"offline blocked-attempt record {index} lacks a prior boundary activation"
            )

    online_identity = _validated_daemon_identity(
        value.get("online_daemon_identity"), "online daemon identity"
    )
    online_arm = _require_dict(value.get("online"), "offline online arm")
    offline_arm = _require_dict(value.get("offline"), "offline offline arm")
    online_evidence = _require_dict(
        online_arm.get("evidence"), "offline online-arm evidence"
    )
    if online_evidence.get("daemon_identity") != online_identity:
        raise AnalysisValidationError(
            "offline online-arm daemon identity differs from retained evidence"
        )
    fresh_offline = value.get("fresh_offline_daemon")
    if fresh_offline is True:
        offline_identity = _validated_daemon_identity(
            value.get("offline_daemon_identity"), "offline daemon identity"
        )
        if float(offline_identity["started_at"]) <= float(
            online_identity["started_at"]
        ):
            raise AnalysisValidationError(
                "offline arm did not retain a later fresh-daemon identity"
            )
        if offline_identity.get("protocol") != online_identity.get(
            "protocol"
        ) or offline_identity.get("version") != online_identity.get("version"):
            raise AnalysisValidationError(
                "online/offline daemon identity versions differ"
            )
        offline_evidence = _require_dict(
            offline_arm.get("evidence"), "offline arm evidence"
        )
        if offline_evidence.get("daemon_identity") != offline_identity:
            raise AnalysisValidationError(
                "offline daemon identity differs from retained arm evidence"
            )
    elif fresh_offline is False:
        if value.get("offline_daemon_identity") is not None:
            raise AnalysisValidationError(
                "failed offline daemon startup nevertheless carries an identity"
            )
    else:
        raise AnalysisValidationError("offline fresh-daemon flag is not Boolean")

    expected_activation = bool(
        fresh_offline is True
        and int(value["offline_daemon_identity"]["pid"]) in activation_by_pid
    )
    if value.get("offline_daemon_boundary_activated") is not expected_activation:
        raise AnalysisValidationError(
            "offline daemon boundary-activation flag is not reconstructed"
        )

    expected_arm_statuses = {
        "online": (
            "system_violation"
            if systems._offline_arm_system_violation(
                online_arm.get("wait") or {},
                online_arm.get("accounting") or {},
                online_arm.get("sample"),
            )
            else "completed"
        ),
        "offline": (
            "system_violation"
            if systems._offline_arm_system_violation(
                offline_arm.get("wait") or {},
                offline_arm.get("accounting") or {},
                offline_arm.get("sample"),
            )
            else "completed"
        ),
    }
    for arm_name, expected_status in expected_arm_statuses.items():
        arm = online_arm if arm_name == "online" else offline_arm
        if arm.get("status") != expected_status:
            raise AnalysisValidationError(
                f"offline {arm_name}-arm status is not independently reconstructed"
            )
    if fresh_offline is False:
        nested_evidence = _require_dict(
            offline_arm.get("evidence"), "failed offline-arm evidence"
        )
        if (
            nested_evidence.get("blocked_attempt_records") != records_value
            or nested_evidence.get("boundary_activation_records") != activation_values
        ):
            raise AnalysisValidationError(
                "failed offline-arm boundary evidence differs from the top-level receipt"
            )

    online_envelope = _require_dict(
        online_arm.get("envelope"), "offline online-arm envelope"
    )
    offline_envelope = _require_dict(
        offline_arm.get("envelope"), "offline offline-arm envelope"
    )
    envelope_fields = {
        "session_id",
        "turn_id",
        "tool_use_id",
        "hook_event_name",
        "tool_name",
        "cwd",
    }
    if (
        set(online_envelope) != envelope_fields
        or set(offline_envelope) != envelope_fields
    ):
        raise AnalysisValidationError("offline arm envelope schema is invalid")
    if any(
        not isinstance(envelope.get(name), str) or not envelope.get(name)
        for envelope in (online_envelope, offline_envelope)
        for name in envelope_fields
    ):
        raise AnalysisValidationError("offline arm envelope fields are invalid")
    for identity_field in ("session_id", "turn_id", "tool_use_id"):
        if (
            offline_envelope[identity_field]
            != f"{online_envelope[identity_field]}-offline"
        ):
            raise AnalysisValidationError(
                f"offline envelope {identity_field} is not paired to the online arm"
            )
    for shared_field in ("hook_event_name", "tool_name"):
        if offline_envelope[shared_field] != online_envelope[shared_field]:
            raise AnalysisValidationError(
                f"offline envelope {shared_field} differs between arms"
            )
    online_cwd = Path(online_envelope["cwd"])
    offline_cwd = Path(offline_envelope["cwd"])
    if (
        online_cwd.name != "project-0"
        or offline_cwd.name != "project-1"
        or online_cwd.parent != offline_cwd.parent
    ):
        raise AnalysisValidationError("offline paired project envelopes are not bound")


def _normal_unit_expected_status(
    unit: Mapping[str, Any], root: Path | None = None
) -> str | None:
    """Recompute success-shaped unit gates; caught errors keep their class."""
    value = dict(unit.get("value") or {})
    if not value or value.get("error") is not None:
        return None
    component = str(unit.get("component", ""))
    if component == "matrix":
        wait = dict(value.get("wait") or {})
        accounting = dict(value.get("accounting") or {})
        findings = dict(accounting.get("findings") or {})
        samples = list(value.get("samples") or [])
        accounting_failure = any(
            accounting.get(key) for key in systems.ACCOUNTING_FAILURE_KEYS
        )
        finding_failure = any(
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
        hook_failure = any(
            not bool(((sample.get("hook") or {}).get("contract_preserved")))
            for sample in samples
        )
        failed = bool(
            wait.get("timed_out")
            or wait.get("integrity_violation")
            or accounting_failure
            or finding_failure
            or hook_failure
            or len(samples) != int(value.get("event_count", -1))
        )
        return "system_violation" if failed else "completed"
    if component == "soak":
        accounting = dict(value.get("global_accounting") or {})
        post_drain = dict(value.get("post_drain") or {})
        restart = dict(value.get("restart_persistence") or {})
        batches = list(value.get("batches") or [])
        batch_failure = any(
            bool(((batch.get("wait") or {}).get("timed_out")))
            or not bool(
                (((batch.get("wait") or {}).get("settle") or {}).get("complete"))
            )
            for batch in batches
            if isinstance(batch, dict)
        ) or len(batches) != sum(isinstance(batch, dict) for batch in batches)
        failed = bool(
            not systems._accounting_is_clean(accounting)
            or unit.get("retained_hook_contracts_preserved") is not True
            or int(value.get("events_submitted", -1)) != int(value.get("events", -2))
            or int(value.get("events_not_submitted_after_drain_timeout", -1)) != 0
            or batch_failure
            or post_drain.get("status") != "completed"
            or restart.get("status") != "completed"
            or restart.get("exact_projection_bytes_preserved") is not True
            or not systems._accounting_is_clean(restart.get("post_restart_accounting"))
            or not bool(
                ((restart.get("post_restart_event") or {}).get("hook") or {}).get(
                    "contract_preserved"
                )
            )
        )
        return "system_violation" if failed else "completed"
    if component == "offline":
        _validate_offline_boundary_evidence(value, root)
        startup_failed = value.get("fresh_offline_daemon") is not True
        online = dict(value.get("online") or {})
        offline = dict(value.get("offline") or {})
        exact_input = dict(value.get("exact_declared_input") or {})
        comparison = dict(value.get("comparison") or {})
        if exact_input.get("encoding") != "UTF-8 rendered as lowercase hexadecimal":
            raise AnalysisValidationError(
                "offline exact declared input encoding is not canonical"
            )
        try:
            online_bytes = bytes.fromhex(str(exact_input.get("online_utf8_hex", "")))
            offline_bytes = bytes.fromhex(str(exact_input.get("offline_utf8_hex", "")))
        except ValueError as exc:
            raise AnalysisValidationError(
                "offline exact declared input is not valid hexadecimal"
            ) from exc
        online_hash = _sha256_bytes(online_bytes)
        offline_hash = _sha256_bytes(offline_bytes)
        input_equal = bool(
            online_bytes == offline_bytes
            and online_hash == offline_hash
            and exact_input.get("online_sha256") == online_hash
            and exact_input.get("offline_sha256") == offline_hash
        )
        if exact_input.get("identical") is not input_equal:
            raise AnalysisValidationError(
                "offline exact-input identity flag is not recomputed"
            )
        online_predictions = _require_dict(
            online.get("persisted_predictions"), "online persisted predictions"
        )
        offline_predictions = _require_dict(
            offline.get("persisted_predictions"), "offline persisted predictions"
        )
        planned_rules = int((unit.get("plan") or {}).get("rules", -1))
        expected_rule_ids = set(systems.EXTERNAL_RULE_ORDER[:planned_rules])
        if (
            set(online_predictions) != expected_rule_ids
            or set(offline_predictions) != expected_rule_ids
        ):
            raise AnalysisValidationError(
                "offline prediction projection does not enumerate every planned rule"
            )
        for arm, predictions in (
            ("online", online_predictions),
            ("offline", offline_predictions),
        ):
            for rule_id, record_value in predictions.items():
                record = _require_dict(
                    record_value, f"{arm} persisted prediction {rule_id}"
                )
                present = record.get("persisted_prediction_utf8_present") is True
                encoded = record.get("persisted_prediction_utf8_hex")
                digest = record.get("persisted_prediction_utf8_sha256")
                if present:
                    try:
                        raw = bytes.fromhex(str(encoded))
                    except ValueError as exc:
                        raise AnalysisValidationError(
                            f"{arm} persisted prediction is invalid hex for {rule_id}"
                        ) from exc
                    if digest != _sha256_bytes(raw):
                        raise AnalysisValidationError(
                            f"{arm} persisted prediction hash mismatch for {rule_id}"
                        )
                elif encoded is not None or digest is not None:
                    raise AnalysisValidationError(
                        f"{arm} absent prediction carries bytes/hash for {rule_id}"
                    )
        recomputed = systems.compare_persisted_predictions(
            online_predictions, offline_predictions
        )
        expected_comparison = dict(recomputed)
        expected_comparison["prediction_records_exactly_equal"] = recomputed[
            "exactly_equal"
        ]
        expected_comparison["input_identity_equal"] = input_equal
        expected_comparison["exactly_equal"] = bool(
            input_equal and recomputed["exactly_equal"]
        )
        if not input_equal:
            expected_comparison["first_difference"] = {
                "rule_id": None,
                "differing_fields": ["exact_declared_input_utf8"],
                "online": {
                    "sha256": online_hash,
                    "utf8_hex": online_bytes.hex(),
                },
                "offline": {
                    "sha256": offline_hash,
                    "utf8_hex": offline_bytes.hex(),
                },
            }
        for name in (
            "comparison_unit",
            "rule_count",
            "exactly_equal",
            "mismatches",
            "first_difference",
            "prediction_records_exactly_equal",
            "input_identity_equal",
        ):
            if comparison.get(name) != expected_comparison.get(name):
                raise AnalysisValidationError(
                    f"offline comparison field is not recomputed: {name}"
                )
        failed = bool(
            startup_failed
            or (online.get("wait") or {}).get("timed_out")
            or (offline.get("wait") or {}).get("timed_out")
            or not bool(
                ((online.get("sample") or {}).get("hook") or {}).get(
                    "contract_preserved"
                )
            )
            or (
                not startup_failed
                and not bool(
                    ((offline.get("sample") or {}).get("hook") or {}).get(
                        "contract_preserved"
                    )
                )
            )
            or not systems._accounting_is_clean(online.get("accounting"))
            or not systems._accounting_is_clean(offline.get("accounting"))
            or value.get("offline_daemon_boundary_activated") is not True
            or not input_equal
            or not recomputed["exactly_equal"]
        )
        return "system_violation" if failed else "completed"
    if component == "faults":
        passed = bool(value.get("passed"))
        probe = value.get("probe_specific")
        fault = str(value.get("fault") or (unit.get("plan") or {}).get("fault", ""))
        if not isinstance(probe, dict):
            raise AnalysisValidationError(
                f"success-shaped fault unit {unit.get('unit_id')} lacks probe_specific"
            )
        recomputed = systems._fault_passed(fault, probe)
        if passed != recomputed:
            raise AnalysisValidationError(
                f"fault passed gate mismatch for {unit.get('unit_id')}"
            )
        return "completed" if passed else "system_violation"
    return None


def _validate_component_gates(
    units: Sequence[dict[str, Any]], root: Path | None = None
) -> None:
    required_standardized = {
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
    for unit in units:
        value = unit.get("value")
        if not isinstance(value, dict):
            continue
        if value.get("error") is not None and not value.get("classification_basis"):
            raise AnalysisValidationError(
                f"caught {unit['component']} outcome lacks classification basis for "
                f"{unit['unit_id']}"
            )
        if value.get("error") is not None and unit["status"] in {
            "completed",
            "not_applicable",
        }:
            raise AnalysisValidationError(
                f"caught {unit['component']} error has a success status for "
                f"{unit['unit_id']}"
            )
        if unit["component"] == "faults":
            standardized = _require_dict(
                value.get("standardized_outcomes"),
                f"fault standardized outcomes {unit['unit_id']}",
            )
            if standardized.get(
                "schema_version"
            ) != 1 or not required_standardized.issubset(standardized):
                raise AnalysisValidationError(
                    f"fault standardized outcome schema mismatch for {unit['unit_id']}"
                )
            if value.get("error") is not None and value.get("passed") is not False:
                raise AnalysisValidationError(
                    f"caught fault outcome cannot pass for {unit['unit_id']}"
                )
            fault = str(value.get("fault", ""))
            if fault in systems.FAULT_CAPABILITIES:
                if value.get("error") is not None:
                    probe = _require_dict(
                        value.get("probe_specific"),
                        f"fault probe-specific result {unit['unit_id']}",
                    )
                    expected_standardized = (
                        systems._unknown_standardized_fault_outcomes(fault)
                    )
                    expected_standardized["orphan_process_count"] = probe.get(
                        "orphan_process_count"
                    )
                    expected_standardized["orphan_process_count_status"] = probe.get(
                        "orphan_process_count_status"
                    )
                    expected_standardized["post_shutdown_process_cleanup"] = probe.get(
                        "post_shutdown_process_cleanup"
                    )
                else:
                    expected_standardized = systems._standardized_fault_outcomes(
                        fault,
                        _require_dict(
                            value.get("probe_specific"),
                            f"fault probe-specific result {unit['unit_id']}",
                        ),
                    )
                if standardized != expected_standardized:
                    raise AnalysisValidationError(
                        f"fault standardized outcome diverges from raw probe for "
                        f"{unit['unit_id']}"
                    )
        expected = _normal_unit_expected_status(unit, root)
        if expected is not None and unit["status"] != expected:
            raise AnalysisValidationError(
                f"{unit['component']} gate disagrees with status for "
                f"{unit['unit_id']}: expected {expected}"
            )


def _validate_fault_cleanup_abort_linkage(
    units: Sequence[dict[str, Any]], result: Mapping[str, Any]
) -> None:
    unsafe_indexes = []
    for index, unit in enumerate(units):
        if unit.get("component") != "faults" or not isinstance(unit.get("value"), dict):
            continue
        probe = unit["value"].get("probe_specific") or {}
        cleanup = probe.get("post_shutdown_process_cleanup") or {}
        if isinstance(cleanup, dict) and cleanup.get("safe_to_continue") is False:
            unsafe_indexes.append(index)
    if not unsafe_indexes:
        return
    if len(unsafe_indexes) != 1:
        raise AnalysisValidationError("multiple unsafe fault cleanups were retained")
    unsafe_index = unsafe_indexes[0]
    unsafe_unit = units[unsafe_index]
    abort = _require_dict(result.get("abort"), "unsafe-cleanup abort")
    error = _require_dict(abort.get("error"), "unsafe-cleanup abort error")
    expected_message = (
        f"fault cleanup isolation failed after {unsafe_unit['unit_id']}; "
        "subsequent units were not started"
    )
    if (
        abort.get("status") != "system_violation"
        or error.get("type") != "SystemViolationError"
        or error.get("message") != expected_message
    ):
        raise AnalysisValidationError(
            "unsafe fault cleanup is not bound to the plan-level abort"
        )
    for later in units[unsafe_index + 1 :]:
        if (
            later.get("started") is not False
            or later.get("status") != "not_started_after_abort"
            or later.get("terminal_record") is not None
        ):
            raise AnalysisValidationError(
                "a unit started after unsafe fault cleanup isolation"
            )


def _validate_process_streams(
    root: Path, result: Mapping[str, Any], *, require_lossless: bool
) -> dict[str, dict[str, Any]]:
    expected_result = {
        "index": "streams.json",
        "stdout": "stdout.log",
        "stderr": "stderr.log",
    }
    if result.get("process_streams") != expected_result:
        raise AnalysisValidationError("result process-stream index is invalid")
    paths = {
        "streams.json": root / "streams.json",
        "stdout.log": root / "stdout.log",
        "stderr.log": root / "stderr.log",
    }
    receipts = {}
    for name, path in paths.items():
        if path.is_symlink() or not path.is_file():
            raise AnalysisValidationError(
                f"required process-stream artifact is missing or non-regular: {name}"
            )
        byte_count, digest = _stream_file_identity(path)
        receipts[name] = {"bytes": byte_count, "sha256": digest}
    try:
        stream_index = json.loads(paths["streams.json"].read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisValidationError("streams.json is not valid UTF-8 JSON") from exc
    expected_capture = (
        "process file descriptors 1 and 2 redirected immediately after immutable "
        "launch creation through process exit"
        if require_lossless
        else "files reserved; candidate caller did not request fd capture"
    )
    expected_index = {
        "stdout": "stdout.log",
        "stderr": "stderr.log",
        "capture": expected_capture,
        "lossless_from_launch": require_lossless,
    }
    if stream_index != expected_index:
        raise AnalysisValidationError(
            "process-stream capture declaration differs from the execution mode"
        )
    return receipts


def _validate_raw_tree_receipt(value: Any, label: str) -> dict[str, Any]:
    receipt = _require_dict(value, label)
    required = {
        "declared_root",
        "root_type",
        "root_entry",
        "entries",
        "errors",
        "inventory_sha256",
    }
    allowed = required | {"root_symlink_target"}
    if not required.issubset(receipt) or not set(receipt).issubset(allowed):
        raise AnalysisValidationError(f"{label} has an invalid top-level schema")
    if not isinstance(receipt.get("declared_root"), str) or not receipt.get(
        "declared_root"
    ):
        raise AnalysisValidationError(f"{label} has no declared root")
    valid_types = {
        "regular",
        "directory",
        "symlink",
        "fifo",
        "socket",
        "block_device",
        "character_device",
        "other",
    }
    errors = list(receipt.get("errors") or [])
    for error in errors:
        if (
            not isinstance(error, dict)
            or set(error) != {"path", "type", "message"}
            or not all(isinstance(error.get(name), str) for name in error)
        ):
            raise AnalysisValidationError(f"{label} has an invalid read error")
    if errors != sorted(
        errors, key=lambda item: (item["path"], item["type"], item["message"])
    ):
        raise AnalysisValidationError(f"{label} read errors are not canonical")

    def validate_entry(entry_value: Any, *, root: bool = False) -> dict[str, Any]:
        entry = _require_dict(entry_value, f"{label} entry")
        entry_type = str(entry.get("type", ""))
        expected = {"path", "type", "mode"}
        temporal = {
            "uid",
            "gid",
            "device",
            "inode",
            "link_count",
            "mtime_ns",
            "ctime_ns",
        }
        if set(entry) & temporal:
            expected |= temporal
        if entry_type == "regular":
            expected |= {"bytes", "sha256"}
        elif entry_type == "symlink":
            expected.add("target")
        elif entry_type in {"block_device", "character_device"}:
            expected |= {"device_major", "device_minor"}
        if set(entry) != expected or entry_type not in valid_types:
            raise AnalysisValidationError(f"{label} entry has an invalid schema")
        path = str(entry.get("path", ""))
        if not path or (root and path != ".") or (not root and path == "."):
            raise AnalysisValidationError(f"{label} entry path is invalid")
        if not isinstance(entry.get("mode"), int) or not 0 <= entry["mode"] <= 0o7777:
            raise AnalysisValidationError(f"{label} entry mode is invalid")
        if temporal.issubset(entry) and any(
            not _is_exact_int(entry[name]) or entry[name] < 0 for name in temporal
        ):
            raise AnalysisValidationError(f"{label} entry metadata is invalid")
        if entry_type == "regular":
            digest = entry.get("sha256")
            if int(entry.get("bytes", -1)) < 0 or (
                digest is not None
                and re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
            ):
                raise AnalysisValidationError(f"{label} regular entry is invalid")
            if digest is None and not any(error["path"] == path for error in errors):
                raise AnalysisValidationError(
                    f"{label} unhashed regular entry has no retained error"
                )
        return entry

    root_entry = receipt.get("root_entry")
    root_type = str(receipt.get("root_type", ""))
    if root_entry is None:
        if root_type not in {"missing", "unreadable"} or not errors:
            raise AnalysisValidationError(f"{label} missing root is unexplained")
    else:
        root_entry = validate_entry(root_entry, root=True)
        if root_type != root_entry.get("type"):
            raise AnalysisValidationError(
                f"{label} root type disagrees with root entry"
            )
    entries = [validate_entry(item) for item in list(receipt.get("entries") or [])]
    if entries != sorted(entries, key=lambda item: (item["path"], item["type"])):
        raise AnalysisValidationError(f"{label} entries are not canonical")
    paths = [str(item["path"]) for item in entries]
    if len(paths) != len(set(paths)):
        raise AnalysisValidationError(f"{label} contains duplicate paths")
    expected_inventory = _sha256_bytes(
        _canonical_json_bytes({"root_entry": root_entry, "entries": entries})
    )
    if receipt.get("inventory_sha256") != expected_inventory:
        raise AnalysisValidationError(f"{label} inventory digest mismatch")
    if root_type == "symlink":
        if receipt.get("root_symlink_target") != (root_entry or {}).get("target"):
            raise AnalysisValidationError(f"{label} root symlink target mismatch")
    elif "root_symlink_target" in receipt:
        raise AnalysisValidationError(f"{label} has a spurious root symlink target")
    return receipt


def _validate_cache_receipt(
    root: Path, identity: Mapping[str, Any], result: Mapping[str, Any]
) -> list[str]:
    global_outcomes = _require_dict(
        result.get("global_outcomes"), "result global_outcomes"
    )
    statuses = list(global_outcomes.get("statuses") or [])
    if any(status not in TERMINAL_STATUSES for status in statuses):
        raise AnalysisValidationError("global_outcomes contains a noncanonical status")
    named_outcomes = [
        _require_dict(value, f"global outcome {name}")
        for name, value in global_outcomes.items()
        if name != "statuses"
    ]
    expected_statuses = [
        str(value.get("status", ""))
        for value in named_outcomes
        if value.get("status") != "completed"
    ]
    if statuses != expected_statuses:
        raise AnalysisValidationError(
            "global_outcomes statuses disagree with named outcomes"
        )
    outcome = _require_dict(
        global_outcomes.get("cache_end_receipt"), "cache-end outcome"
    )
    if outcome.get("status") not in TERMINAL_STATUSES:
        raise AnalysisValidationError("cache-end outcome has a noncanonical status")
    if outcome.get("error") is not None:
        error = _require_dict(outcome.get("error"), "cache-end error")
        if not all(
            isinstance(error.get(name), str) and error.get(name)
            for name in (
                "type",
                "message",
                "traceback",
            )
        ):
            raise AnalysisValidationError("cache-end error evidence is incomplete")
        status = str(outcome.get("status", ""))
        if status == "system_violation":
            if error.get("type") != "RuntimeContractError":
                raise AnalysisValidationError(
                    "cache-end system violation lacks a runtime-contract cause"
                )
        elif not isinstance(
            outcome.get("classification_basis"), str
        ) or not outcome.get("classification_basis"):
            raise AnalysisValidationError(
                "cache-end non-system error lacks a classification basis"
            )
        if outcome.get("unchanged") not in {None, False}:
            raise AnalysisValidationError(
                "cache-end error cannot claim unchanged cache"
            )
        return statuses
    if outcome.get("status") not in {"completed", "system_violation"}:
        raise AnalysisValidationError("cache-end receipt has an invalid success status")
    launch_cache = (
        _require_dict(identity.get("formal_runtime"), "formal runtime")
    ).get("paw_cache") or {}
    if outcome.get("launch_receipt_sha256") != _sha256_bytes(
        _canonical_json_bytes(launch_cache)
    ):
        raise AnalysisValidationError("cache-end launch receipt hash mismatch")
    end = outcome.get("end_receipt")
    end = end if end is not None else outcome.get("raw_end_tree")
    if outcome.get("end_receipt_sha256") != _sha256_bytes(_canonical_json_bytes(end)):
        raise AnalysisValidationError("cache-end receipt hash mismatch")
    raw_before = _validate_raw_tree_receipt(
        launch_cache.get("raw_tree"), "raw cache launch tree"
    )
    raw_end = _validate_raw_tree_receipt(
        outcome.get("raw_end_tree"), "raw cache-end tree"
    )
    if isinstance(end, dict) and end.get("raw_tree") != raw_end:
        raise AnalysisValidationError(
            "strict cache-end receipt has a different raw tree"
        )

    def index_raw(receipt: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        root_entry = receipt.get("root_entry")
        if isinstance(root_entry, dict):
            indexed["."] = dict(root_entry)
        for item in receipt.get("entries") or []:
            indexed[str(item["path"])] = dict(item)
        return indexed

    before_entries = index_raw(raw_before)
    after_all_entries = index_raw(raw_end)
    entry_changes = []
    permitted_runtime_manifest_temporal_changes = []
    allow_runtime_manifest_temporal_change = (
        identity.get("study_mode") == _COMPONENT_STUDY_MODE
    )
    for path in sorted(after_all_entries):
        after = after_all_entries[path]
        before = before_entries.get(path)
        if before is None:
            entry_changes.append(
                {"path": path, "change": "added", "before": None, "after": after}
            )
        elif before != after:
            changed_fields = sorted(
                key
                for key in set(before) | set(after)
                if before.get(key) != after.get(key)
            )
            if (
                allow_runtime_manifest_temporal_change
                and path == "runtimes/qwen3-0.6b-q6_k.json"
                and changed_fields
                and set(changed_fields).issubset({"mtime_ns", "ctime_ns"})
                and before.get("type") == "regular"
                and after.get("type") == "regular"
            ):
                permitted_runtime_manifest_temporal_changes.append(
                    {
                        "path": path,
                        "changed_fields": changed_fields,
                        "before": before,
                        "after": after,
                        "bytes_sha256_and_identity_unchanged": True,
                    }
                )
                continue
            entry_changes.append(
                {
                    "path": path,
                    "change": (
                        "type_changed"
                        if before.get("type") != after.get("type")
                        else "modified"
                    ),
                    "before": before,
                    "after": after,
                }
            )
    deleted_entries = [
        before_entries[path]
        for path in sorted(set(before_entries) - set(after_all_entries))
    ]
    special_entries = [
        after_all_entries[path]
        for path in sorted(after_all_entries)
        if after_all_entries[path].get("type") not in {"regular", "directory"}
    ]
    for name, expected in (
        ("entry_changes", entry_changes),
        (
            "permitted_runtime_manifest_temporal_changes",
            permitted_runtime_manifest_temporal_changes,
        ),
        ("deleted_entries", deleted_entries),
        ("special_entries", special_entries),
    ):
        observed = (
            outcome.get(name, [])
            if name == "permitted_runtime_manifest_temporal_changes"
            and not allow_runtime_manifest_temporal_change
            else outcome.get(name)
        )
        if observed != expected:
            raise AnalysisValidationError(f"cache-end {name} disagrees with raw trees")
    before_files = {
        str(item.get("path", "")): dict(item)
        for item in ((launch_cache.get("complete_tree") or {}).get("files") or [])
        if isinstance(item, dict)
    }
    after_entries = {
        str(item.get("path", "")): dict(item)
        for item in (raw_end.get("entries") or [])
        if isinstance(item, dict)
    }
    if len(after_entries) != len(raw_end.get("entries") or []):
        raise AnalysisValidationError("raw cache-end tree has duplicate/invalid paths")
    after_files = {
        path: receipt
        for path, receipt in after_entries.items()
        if receipt.get("type") == "regular"
    }
    changed_or_new = sorted(
        path
        for path, receipt in after_files.items()
        if {key: receipt.get(key) for key in ("path", "bytes", "sha256")}
        != {
            key: (before_files.get(path) or {}).get(key)
            for key in ("path", "bytes", "sha256")
        }
    )
    deleted = sorted(set(before_files) - set(after_files))
    non_regular = [str(item["path"]) for item in special_entries]
    for name, observed, expected in (
        ("changed_or_new", outcome.get("changed_or_new"), changed_or_new),
        ("deleted", outcome.get("deleted"), deleted),
        (
            "non_regular_or_symlink",
            outcome.get("non_regular_or_symlink"),
            non_regular,
        ),
    ):
        if observed != expected:
            raise AnalysisValidationError(
                f"cache-end {name} disagrees with inventories"
            )
    strict_error = outcome.get("strict_validation_error")
    comparison_errors = list(outcome.get("comparison_errors") or [])
    if outcome.get("prelaunch_raw_tree_missing") is not False:
        raise AnalysisValidationError("cache-end omitted its prelaunch raw tree")
    if outcome.get("prelaunch_raw_tree_errors") != list(raw_before.get("errors") or []):
        raise AnalysisValidationError("cache-end prelaunch error projection mismatch")
    if comparison_errors:
        raise AnalysisValidationError("cache-end has unexplained comparison errors")
    expected_unchanged = bool(
        not entry_changes
        and not deleted_entries
        and not special_entries
        and not raw_before.get("errors")
        and not raw_end.get("errors")
        and not comparison_errors
        and strict_error is None
    )
    if outcome.get("unchanged") is not expected_unchanged:
        raise AnalysisValidationError("cache-end unchanged gate mismatch")
    expected_cache_status = "completed" if expected_unchanged else "system_violation"
    if outcome.get("status") != expected_cache_status:
        raise AnalysisValidationError("cache-end status disagrees with inventory gate")
    retained_root = outcome.get("retained_changed_files_root")
    retained_root_relative = outcome.get("retained_changed_files_root_relative")
    copies = list(outcome.get("retained_changed_files") or [])
    copy_errors = list(outcome.get("retained_copy_errors") or [])
    copy_paths = [str((receipt or {}).get("path", "")) for receipt in copies]
    error_paths = [str((receipt or {}).get("path", "")) for receipt in copy_errors]
    if sorted(copy_paths + error_paths) != changed_or_new:
        raise AnalysisValidationError(
            "retained cache copies/errors do not cover every changed/new file exactly"
        )
    if bool(changed_or_new) != bool(retained_root):
        raise AnalysisValidationError(
            "retained cache root presence disagrees with changed/new inventory"
        )
    if retained_root is not None:
        if retained_root_relative != {
            "base": "attempt_root",
            "path": "runtime/cache-end-changed-files",
        }:
            raise AnalysisValidationError("retained cache root is not attempt-relative")
        retained = (root / "runtime" / "cache-end-changed-files").resolve()
        for receipt in copies:
            relative = str((receipt or {}).get("path", ""))
            path = _checked_receipt_file(root, str(retained / relative))
            if (
                (receipt or {}).get("bytes") != path.stat().st_size
                or (receipt or {}).get("sha256") != _sha256(path)
                or (after_files.get(relative) or {}).get("sha256") != _sha256(path)
            ):
                raise AnalysisValidationError("retained cache file receipt mismatch")
    elif retained_root_relative is not None:
        raise AnalysisValidationError("empty cache diff has a retained relative root")
    return statuses


def validate_attempt(
    path: Path,
    *,
    _expected_component_counts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Validate an attempt; the private count seam supports compact unit fixtures."""
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise AnalysisValidationError("attempt directory must not be a symlink")
    root = expanded.resolve()
    if not root.is_dir():
        raise AnalysisValidationError("--input must be an immutable attempt directory")
    required = {
        name: root / name
        for name in (
            "launch.json",
            "plan.json",
            "publication.json",
            "result.json",
        )
    }
    if any(path.is_symlink() for path in required.values()):
        raise AnalysisValidationError(
            "launch, plan, publication, and result must not be symlinks"
        )
    launch = _require_dict(_load_json(required["launch.json"]), "launch.json")
    publication = _validate_publication(root)
    result = _require_dict(_load_json(required["result.json"]), "result.json")
    plan_value = _load_json(required["plan.json"])
    if not isinstance(plan_value, list) or not all(
        isinstance(item, dict) for item in plan_value
    ):
        raise AnalysisValidationError("plan.json must be a list of objects")
    plan: list[dict[str, Any]] = plan_value
    if launch.get("plan") != plan:
        raise AnalysisValidationError("launch plan differs from plan.json")
    identity = _require_dict(launch.get("identity"), "launch identity")
    if launch.get("identity_sha256") != _sha256_bytes(_canonical_json_bytes(identity)):
        raise AnalysisValidationError("launch canonical identity SHA-256 mismatch")
    if identity.get("plan_sha256") != _sha256_bytes(_canonical_json_bytes(plan)):
        raise AnalysisValidationError("launch plan digest mismatch")
    raw_attempt_id = root.name
    if identity.get("attempt_id") != raw_attempt_id:
        raise AnalysisValidationError("launch raw attempt ID differs from directory")
    if result.get("raw_attempt_id") != raw_attempt_id:
        raise AnalysisValidationError("result raw attempt ID differs from launch")
    amendment_007 = _require_dict(
        _load_json(REPO_ROOT / PROTOCOL_PATHS[-1]), "amendment 007"
    )
    amendment_008 = _load_amendment_008()
    legacy_r01 = _is_anchored_r01(raw_attempt_id, amendment_007)
    anchored_r02 = _is_anchored_r02(raw_attempt_id, amendment_008)
    component_r08 = identity.get("study_mode") == _COMPONENT_STUDY_MODE
    if component_r08 and raw_attempt_id != attempts_contract._COMPONENT_SUCCESSOR_ID:
        raise AnalysisValidationError("amendment-016 mode is restricted to exact r08")
    protocols = _validate_sources(
        identity,
        legacy_r01=legacy_r01,
        runner_anchor=anchored_r02,
        protocol_paths=(
            PROTOCOL_PATHS_016
            if component_r08
            else PROTOCOL_PATHS_007[:-1]
            if legacy_r01 is not None
            else PROTOCOL_PATHS_007
        ),
    )
    observed_counts = dict(Counter(_component(item) for item in plan))
    expected_component_counts = dict(
        _expected_component_counts
        if _expected_component_counts is not None
        else FORMAL_R03_COMPONENT_COUNTS
        if component_r08
        else FORMAL_COMPONENT_COUNTS
    )
    if observed_counts != expected_component_counts:
        raise AnalysisValidationError(
            "plan component counts mismatch: "
            f"expected {expected_component_counts}, observed {observed_counts}"
        )
    if not component_r08 and expected_component_counts == FORMAL_COMPONENT_COUNTS:
        contract = amendment_007
        try:
            launched = datetime.fromisoformat(
                str(launch.get("created_utc", "")).replace("Z", "+00:00")
            )
            frozen = datetime.fromisoformat(
                str(contract.get("frozen_utc", "")).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise AnalysisValidationError(
                "formal launch/freeze timestamp is invalid"
            ) from exc
        if (
            legacy_r01 is None
            and anchored_r02 is None
            and (launched.tzinfo is None or frozen.tzinfo is None or launched < frozen)
        ):
            raise AnalysisValidationError(
                "formal attempt launch predates amendment-007 freeze"
            )
        if legacy_r01 is not None:
            _validate_anchored_r01(identity, result, launch, legacy_r01, contract, root)
        elif anchored_r02 is not None:
            assert amendment_008 is not None
            _validate_anchored_r02(
                identity,
                result,
                launch,
                anchored_r02,
                amendment_008,
                root,
            )
            _validate_formal_plan(root, identity, result, plan)
        else:
            _validate_formal_plan(root, identity, result, plan)
    elif component_r08:
        if amendment_008 is None:
            raise AnalysisValidationError("r08 requires frozen amendment 016")
        try:
            launched = datetime.fromisoformat(
                str(launch.get("created_utc", "")).replace("Z", "+00:00")
            )
            frozen = datetime.fromisoformat(
                str(amendment_008.get("frozen_utc", "")).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise AnalysisValidationError(
                "r08 launch/freeze timestamp is invalid"
            ) from exc
        if launched.tzinfo is None or frozen.tzinfo is None or launched < frozen:
            raise AnalysisValidationError("r08 launch predates amendment-008 freeze")
        _validate_whole_attempt_plan(root, identity, result, plan, amendment_008)
    units, plan_accounting = _validate_units(
        root, plan, result, exact_terminal_phase=component_r08
    )
    if component_r08 and any(
        unit["terminal_record"] is not None
        and (unit.get("value") or {}).get("study_mode") != _COMPONENT_STUDY_MODE
        for unit in units
    ):
        raise AnalysisValidationError("r08 terminal result study_mode differs")
    _validate_unit_plan_bindings(units)
    if identity.get("study_mode") in {_FORMAL_STUDY_MODE, _COMPONENT_STUDY_MODE}:
        _validate_socket_endpoint_receipts(root, identity, units)
    for unit in units:
        _validate_component_internal_consistency(unit, root)
    _validate_matrix_evidence(root, units)
    _validate_soak_evidence(root, units)
    _validate_component_gates(units, root)
    _validate_fault_cleanup_abort_linkage(units, result)
    global_statuses = _validate_cache_receipt(root, identity, result)
    result_git = _require_dict(result.get("git"), "result Git state")
    source_start = result_git.get("start")
    source_end = result_git.get("end")
    source_unchanged = result_git.get("unchanged_during_attempt")
    if source_start != identity.get("git"):
        raise AnalysisValidationError(
            "result source start differs from launch Git identity"
        )
    if source_unchanged is not (source_start == source_end):
        raise AnalysisValidationError("result source unchanged flag is not recomputed")
    all_statuses = [*(unit["status"] for unit in units), *global_statuses]
    abort = result.get("abort") or {}
    has_abort = bool(abort)
    eligible = bool(
        plan_accounting["complete"]
        and all(status in PRIMARY_ELIGIBLE_STATUSES for status in all_statuses)
        and source_unchanged is True
        and not has_abort
    )
    if result.get("primary_numeric_eligible") is not eligible:
        raise AnalysisValidationError("result eligibility disagrees with unit ledger")
    source_mutated = source_unchanged is False
    abort_status = str(abort.get("status", ""))
    if has_abort and abort_status not in {
        "system_violation",
        "harness_error",
        "infrastructure_error",
        "unclassified_failure",
    }:
        raise AnalysisValidationError(
            "result abort lacks a positively classified status"
        )
    if not plan_accounting["complete"] and not has_abort:
        raise AnalysisValidationError("incomplete result lacks an abort record")
    has_unclassified = bool(
        source_mutated
        or source_unchanged is not True
        or "unclassified_failure" in all_statuses
        or (has_abort and abort_status in {"system_violation", "unclassified_failure"})
    )
    has_infrastructure = bool(
        "infrastructure_error" in all_statuses
        or (has_abort and abort_status == "infrastructure_error")
    )
    has_harness = bool(
        "harness_error" in all_statuses
        or (has_abort and abort_status == "harness_error")
    )
    system_violations = sum(status == "system_violation" for status in all_statuses)
    expected_abort_system_violation = bool(
        has_abort
        and (
            abort_status == "system_violation"
            or str(
                _require_dict(
                    abort.get("original_abort_classification") or {},
                    "original abort classification",
                ).get("status", "")
            )
            == "system_violation"
        )
    )
    if result.get("abort_system_violation") is not expected_abort_system_violation:
        raise AnalysisValidationError(
            "result abort-system-violation flag is not recomputed"
        )
    expected_status = (
        "incomplete_unclassified_failure"
        if has_unclassified
        else "incomplete_infrastructure_error"
        if has_infrastructure
        else "incomplete_harness_error"
        if has_harness
        else "completed_with_system_violations"
        if system_violations
        else "completed"
    )
    if result.get("status") != expected_status:
        raise AnalysisValidationError(
            f"result status disagrees with ledger/global outcomes: expected {expected_status}"
        )
    expected_histogram = dict(sorted(Counter(unit["status"] for unit in units).items()))
    if result.get("unit_status_histogram") != expected_histogram:
        raise AnalysisValidationError(
            "result unit status histogram disagrees with ledger"
        )
    if result.get("system_violation_units") != system_violations:
        raise AnalysisValidationError(
            "result system-violation count disagrees with ledger"
        )
    if result.get("terminal_units") is not None:
        expected_terminal_units = [
            {
                "component": unit["component"],
                "unit_id": unit["unit_id"],
                "status": unit["status"],
            }
            for unit in units
            if unit["terminal_record"] is not None
        ]
        if result.get("terminal_units") != expected_terminal_units:
            raise AnalysisValidationError(
                "result terminal_units disagrees with immutable unit ledger"
            )
    process_stream_receipts = _validate_process_streams(
        root,
        result,
        require_lossless=(
            expected_component_counts == FORMAL_COMPONENT_COUNTS
            or expected_component_counts == FORMAL_R03_COMPONENT_COUNTS
        ),
    )
    input_hashes = {
        name: _sha256(required[name])
        for name in (
            "launch.json",
            "plan.json",
            "publication.json",
            "result.json",
        )
    }
    input_hashes["units.jsonl"] = _sha256(root / "units.jsonl")
    input_hashes.update(
        {name: receipt["sha256"] for name, receipt in process_stream_receipts.items()}
    )
    input_receipts = {
        name: {
            "bytes": (root / name).stat().st_size,
            "sha256": digest,
        }
        for name, digest in input_hashes.items()
    }
    return {
        "root": root,
        "identity": identity,
        "publication": publication,
        "plan": plan,
        "result": result,
        "result_sha256": input_hashes["result.json"],
        "input_hashes": input_hashes,
        "input_receipts": input_receipts,
        "protocol_documents": protocols,
        "anchored_r01": legacy_r01 is not None,
        "anchored_r02": anchored_r02 is not None,
        "component_r08": component_r08,
        "units": units,
        "plan_accounting": plan_accounting,
        "eligible": eligible,
        "global_statuses": global_statuses,
        "source_unchanged": source_unchanged,
    }


def analyze(
    path: Path,
    analysis_id: str,
    *,
    _expected_component_counts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    if ANALYSIS_ID_PATTERN.fullmatch(analysis_id) is None:
        raise AnalysisValidationError(
            "analysis_id must match ^[a-z0-9][a-z0-9._-]{0,63}$"
        )
    validated = validate_attempt(
        path, _expected_component_counts=_expected_component_counts
    )
    plan = validated["plan"]
    units = validated["units"]
    matrix_plan = [item for item in plan if _component(item) == "matrix"]
    matrix_records = []
    for unit in units:
        if unit["component"] != "matrix" or unit["value"] is None:
            continue
        record = dict(unit["value"])
        record.setdefault("condition_id", unit["unit_id"])
        matrix_records.append(record)
    endpoints = (
        None
        if validated["anchored_r01"]
        else {
            "matrix": systems.reduce_matrix_attempts(matrix_plan, matrix_records),
            "soak": _component_endpoint("soak", plan, units),
            "offline": _component_endpoint("offline", plan, units),
            "faults": _fault_endpoint(plan, units),
        }
    )
    binding = {
        **_static_analysis_binding(analysis_id),
        "raw_attempt_id": validated["identity"]["attempt_id"],
        "raw_result_sha256": validated["result_sha256"],
        "raw_input_sha256": validated["input_hashes"],
        "raw_input_receipts": validated["input_receipts"],
        "protocol_documents": validated["protocol_documents"],
    }
    eligible = validated["eligible"]
    candidate_eligible = eligible and not validated["anchored_r01"]
    return {
        "schema_version": 2,
        "analysis_id": analysis_id,
        "analysis_binding": binding,
        "analysis_binding_sha256": _sha256_bytes(_canonical_json_bytes(binding)),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_attempt": {
            "id": validated["identity"]["attempt_id"],
            "result_sha256": validated["result_sha256"],
            "input_sha256": validated["input_hashes"],
            "input_receipts": validated["input_receipts"],
            "status": validated["result"].get("status"),
            "startup_only_numeric_aggregate_excluded": validated["anchored_r01"],
            "amendment_008_historical_anchor": validated["anchored_r02"],
            "component_repair_attempt": validated["component_r08"],
            "plan_accounting": validated["plan_accounting"],
            "global_statuses": validated["global_statuses"],
            "source_unchanged_during_attempt": validated["source_unchanged"],
            "attempt_replacement": validated["identity"].get("attempt_replacement"),
            "replacement_retention": validated["identity"].get("replacement_retention"),
        },
        "attempt_ledger": [
            {
                key: unit[key]
                for key in (
                    "component",
                    "unit_id",
                    "started",
                    "status",
                    "terminal_record",
                    "terminal_sha256",
                )
            }
            for unit in units
        ],
        "endpoints": endpoints,
        "analysis": endpoints["matrix"] if endpoints is not None else None,
        "numeric_candidate": {
            "candidate_eligible": candidate_eligible,
            "promoted": False,
            "requires": "launch-ordered --attempts-root ledger",
            "reason": (
                "anchored r01 is startup-only and awaits the exact authorized r02 replacement"
                if validated["anchored_r01"]
                else "complete plan with only completed/system_violation outcomes and unchanged source"
                if candidate_eligible
                else "incomplete or harness/infrastructure/unclassified/integrity failure; numeric promotion forbidden"
            ),
        },
    }


def _loose_hashes(root: Path) -> dict[str, str | None]:
    values = {}
    for name in (
        "launch.json",
        "plan.json",
        "publication.json",
        "result.json",
        "units.jsonl",
        "streams.json",
        "stdout.log",
        "stderr.log",
    ):
        path = root / name
        values[name] = (
            _sha256(path) if path.is_file() and not path.is_symlink() else None
        )
    return values


def _validate_live_predecessor_artifacts(
    predecessor_root: Path, binding: Mapping[str, Any]
) -> None:
    _validate_predecessor_tree_binding(binding)
    declared = _require_dict(
        binding.get("predecessor_artifacts"),
        "replacement predecessor artifact binding",
    )
    names = attempts_contract._PREDECESSOR_ARTIFACT_NAMES
    if set(declared) != set(names):
        raise AnalysisValidationError(
            "replacement predecessor artifact binding is incomplete"
        )
    for name in names:
        path = predecessor_root / name
        expected_value = declared.get(name)
        if expected_value is None:
            if path.exists() or path.is_symlink():
                raise AnalysisValidationError(
                    f"live predecessor artifact appeared after binding: {name}"
                )
            continue
        expected = _require_dict(
            expected_value, f"replacement predecessor artifact {name}"
        )
        if (
            set(expected) != {"path", "bytes", "sha256"}
            or Path(str(expected.get("path", ""))).name != name
            or not path.is_file()
            or path.is_symlink()
            or expected.get("path") != str(path.resolve(strict=True))
        ):
            raise AnalysisValidationError(
                f"live predecessor artifact is missing or invalid: {name}"
            )
        byte_count, digest = _stream_file_identity(path)
        if expected.get("bytes") != byte_count or expected.get("sha256") != digest:
            raise AnalysisValidationError(
                f"live predecessor artifact differs from replacement binding: {name}"
            )

    declared_tree = list(binding.get("predecessor_tree") or [])
    observed_tree = attempts_contract._predecessor_tree_receipts(predecessor_root)
    if declared_tree != observed_tree:
        raise AnalysisValidationError(
            "live predecessor file tree differs from replacement binding"
        )


def analyze_attempts_root(
    path: Path,
    analysis_id: str,
    *,
    _expected_component_counts: Mapping[str, int] = FORMAL_COMPONENT_COUNTS,
) -> dict[str, Any]:
    """Select the earliest eligible attempt from a complete sibling ledger."""
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise AnalysisValidationError("attempts root must not be a symlink")
    root = expanded.resolve()
    if not root.is_dir():
        raise AnalysisValidationError("--attempts-root must be a directory")
    if ANALYSIS_ID_PATTERN.fullmatch(analysis_id) is None:
        raise AnalysisValidationError("invalid analysis_id slug")
    ledger = []
    reports: dict[str, dict[str, Any]] = {}
    # Every directory entry is part of the immutable attempt ledger.  Silently
    # filtering a symlink, file, or corrupted directory would let an earlier
    # unfavorable launch disappear from primary-attempt selection.
    children = sorted(root.iterdir(), key=lambda item: item.name)
    if not children:
        raise AnalysisValidationError("attempts root contains no attempt directories")
    for child in children:
        created_utc = ""
        try:
            launch = _require_dict(_load_json(child / "launch.json"), "launch.json")
            created_utc = str(launch.get("created_utc", ""))
        except AnalysisValidationError:
            pass
        try:
            report = analyze(
                child,
                analysis_id,
                _expected_component_counts=_expected_component_counts,
            )
        except AnalysisValidationError as exc:
            ledger.append(
                {
                    "raw_attempt_id": child.name,
                    "created_utc": created_utc,
                    "candidate_eligible": False,
                    "status": "incomplete_or_integrity_failure",
                    "input_sha256": _loose_hashes(child),
                    "validation_error": str(exc),
                }
            )
        else:
            reports[child.name] = report
            ledger.append(
                {
                    "raw_attempt_id": child.name,
                    "created_utc": created_utc,
                    "candidate_eligible": report["numeric_candidate"][
                        "candidate_eligible"
                    ],
                    "status": report["raw_attempt"]["status"],
                    "input_sha256": report["raw_attempt"]["input_sha256"],
                    "analysis_binding_sha256": report["analysis_binding_sha256"],
                    "validation_error": None,
                }
            )
    chain_error: str | None = None
    prefixes = set()
    ordinals = []
    for item in ledger:
        match = FORMAL_ATTEMPT_PATTERN.fullmatch(item["raw_attempt_id"])
        if match is None:
            item["attempt_id_valid"] = False
            item["chain_prefix"] = None
            item["raw_attempt_ordinal"] = None
            chain_error = "attempt ledger contains an ID outside the rNN chain"
        else:
            item["attempt_id_valid"] = True
            item["chain_prefix"] = match.group("prefix")
            item["raw_attempt_ordinal"] = int(match.group("ordinal"))
            prefixes.add(match.group("prefix"))
            ordinals.append(int(match.group("ordinal")))
        try:
            instant = datetime.fromisoformat(item["created_utc"].replace("Z", "+00:00"))
            if instant.tzinfo is None or instant > datetime.now(timezone.utc):
                raise ValueError("launch timestamp lacks timezone")
        except (AttributeError, TypeError, ValueError):
            item["launch_order_valid"] = False
            item["launch_order_key"] = None
        else:
            item["launch_order_valid"] = True
            item["launch_order_key"] = instant.astimezone(timezone.utc).isoformat()
        item["rerun_eligible_status"] = bool(
            item.get("validation_error") is None
            and item.get("status") in RERUN_ELIGIBLE_ATTEMPT_STATUSES
        )
        item["replacement_authorized_by_successor"] = False
    if len(prefixes) != 1:
        chain_error = "attempt ledger must contain one shared rNN prefix"
    if sorted(ordinals) != list(range(1, len(ledger) + 1)):
        chain_error = "attempt ledger ordinals must be contiguous from r01"
    ledger.sort(
        key=lambda item: (
            item["raw_attempt_ordinal"] is None,
            item["raw_attempt_ordinal"] or 0,
            item["raw_attempt_id"],
        )
    )
    timestamp_keys = [item["launch_order_key"] for item in ledger]
    if any(value is None for value in timestamp_keys) or timestamp_keys != sorted(
        timestamp_keys
    ):
        chain_error = "attempt launch timestamps are invalid or regress across rNN"

    # Re-run the exact versioned pre-launch validator against every successor's
    # bound receipt.  This verifies predecessor bytes and adjudication evidence
    # again at analysis time rather than trusting a favorable status label.  A
    # malformed edge anywhere poisons the complete ledger, including when an
    # earlier attempt would otherwise be eligible for promotion.
    replacement_blocker: dict[str, Any] | None = None
    for predecessor, successor in zip(ledger, ledger[1:]):
        successor_report = reports.get(successor["raw_attempt_id"])
        raw_attempt = (successor_report or {}).get("raw_attempt", {})
        binding = raw_attempt.get("attempt_replacement") or {}
        receipt_path = binding.get("receipt_path")
        try:
            if (
                binding.get("original_status") != "missing"
                and predecessor["raw_attempt_id"] not in reports
            ):
                raise AnalysisValidationError(
                    "result-present predecessor must remain independently analyzable"
                )
            _validate_live_predecessor_artifacts(
                root / predecessor["raw_attempt_id"], binding
            )
            retention = raw_attempt.get("replacement_retention")
            if retention is not None:
                _validate_replacement_retention(
                    root / successor["raw_attempt_id"],
                    {
                        "attempt_replacement": binding,
                        "replacement_retention": retention,
                    },
                )
                exact_outcome_aware_edge = (
                    predecessor["raw_attempt_id"] == "formal-v3-20260831t051023z-r01"
                    and successor["raw_attempt_id"] == "formal-v3-20260831t051023z-r02"
                )
                if exact_outcome_aware_edge:
                    if not receipt_path:
                        raise AnalysisValidationError(
                            "successor does not bind a replacement receipt"
                        )
                    recomputed = systems.replacement_launch_binding(
                        root / successor["raw_attempt_id"], str(receipt_path)
                    )
                    if binding != recomputed:
                        raise AnalysisValidationError(
                            "successor replacement binding differs from live revalidation"
                        )
                else:
                    recomputed = binding
            else:
                if not receipt_path:
                    raise AnalysisValidationError(
                        "successor does not bind a replacement receipt"
                    )
                recomputed = systems.replacement_launch_binding(
                    root / successor["raw_attempt_id"], str(receipt_path)
                )
                if binding != recomputed:
                    raise AnalysisValidationError(
                        "successor replacement binding differs from revalidation"
                    )
            if (
                recomputed.get("successor_raw_attempt_id")
                != successor["raw_attempt_id"]
            ):
                raise AnalysisValidationError(
                    "successor replacement binding names a different successor"
                )
            if (
                recomputed.get("predecessor_raw_attempt_id")
                != predecessor["raw_attempt_id"]
            ):
                raise AnalysisValidationError(
                    "successor replacement does not name immediate predecessor"
                )
        except Exception as exc:
            # SystemsHarnessError is intentionally not imported through a second
            # module; the exact message is retained and the predecessor blocks.
            successor["replacement_validation_error"] = str(exc)
            if replacement_blocker is None:
                replacement_blocker = successor
        else:
            successor["replacement_validation_error"] = None
            successor["validated_replacement_binding"] = recomputed
            predecessor["replacement_authorized_by_successor"] = True
            if (
                predecessor["raw_attempt_id"] == "formal-v3-20260831t051023z-r01"
                and successor["raw_attempt_id"] == "formal-v3-20260831t051023z-r02"
                and recomputed.get("classification") == "harness_error"
                and recomputed.get("original_status")
                == "completed_with_system_violations"
            ):
                predecessor["adjudicated_status"] = (
                    "superseded_premeasurement_harness_error"
                )
                predecessor["raw_status_preserved"] = predecessor["status"]
                predecessor["numeric_aggregate_excluded"] = True
                predecessor["candidate_eligible"] = False
    if replacement_blocker is not None and chain_error is None:
        chain_error = (
            "attempt ledger contains an invalid replacement edge at "
            f"{replacement_blocker['raw_attempt_id']}"
        )
    selected = None
    blocking = None
    if chain_error is not None:
        blocking = ledger[0]
    for item in ledger:
        if blocking is not None:
            break
        if not item["launch_order_valid"]:
            blocking = item
            break
        if item["candidate_eligible"]:
            selected = item
            break
        if item.get("replacement_authorized_by_successor", False):
            continue
        blocking = item
        break
    selected_id = selected["raw_attempt_id"] if selected else None
    root_binding = {
        **_static_analysis_binding(analysis_id),
        "attempts_root": str(root),
        "launch_ordered_attempts": ledger,
        "selected_primary_raw_attempt_id": selected_id,
        "selection_blocked_by": blocking["raw_attempt_id"] if blocking else None,
        "chain_error": chain_error,
    }
    return {
        "schema_version": 1,
        "analysis_id": analysis_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_binding": root_binding,
        "analysis_binding_sha256": _sha256_bytes(_canonical_json_bytes(root_binding)),
        "attempt_ledger": ledger,
        "primary_numeric": {
            "promoted": selected_id is not None,
            "selected_raw_attempt_id": selected_id,
            "selection_blocked_by": (blocking["raw_attempt_id"] if blocking else None),
            "selection_rule": (
                "earliest launch-ordered eligible attempt after only immutable, "
                "pre-authorized harness/infrastructure replacements"
            ),
        },
        "endpoints": reports[selected_id]["endpoints"] if selected_id else None,
        "sensitivity_endpoints": (
            {
                raw_id: report["endpoints"]
                for raw_id, report in sorted(reports.items())
                if raw_id != selected_id
                and next(
                    item["candidate_eligible"]
                    for item in ledger
                    if item["raw_attempt_id"] == raw_id
                )
                and report["endpoints"] is not None
            }
            if chain_error is None
            else {}
        ),
    }


def _reduce_endpoints(
    plan: Sequence[dict[str, Any]], units: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    matrix_plan = [item for item in plan if _component(item) == "matrix"]
    matrix_records = []
    for unit in units:
        if unit["component"] != "matrix" or unit.get("value") is None:
            continue
        record = dict(unit["value"])
        record.setdefault("condition_id", unit["unit_id"])
        matrix_records.append(record)
    return {
        "matrix": systems.reduce_matrix_attempts(matrix_plan, matrix_records),
        "soak": _component_endpoint("soak", plan, units),
        "offline": _component_endpoint("offline", plan, units),
        "faults": _fault_endpoint(plan, units),
    }


def _revalidate_exact_replacement_edge(
    predecessor: dict[str, Any], successor: dict[str, Any]
) -> dict[str, Any]:
    binding = _require_dict(
        successor["identity"].get("attempt_replacement"),
        "successor replacement binding",
    )
    receipt_path = binding.get("receipt_path")
    if not isinstance(receipt_path, str) or not receipt_path:
        raise AnalysisValidationError("successor does not bind replacement.json")
    _validate_live_predecessor_artifacts(predecessor["root"], binding)
    try:
        recomputed = systems.replacement_launch_binding(successor["root"], receipt_path)
    except Exception as exc:
        raise AnalysisValidationError(
            f"replacement edge failed live revalidation: {exc}"
        ) from exc
    if binding != recomputed:
        raise AnalysisValidationError(
            "successor replacement binding differs from live revalidation"
        )
    if recomputed.get("predecessor_raw_attempt_id") != predecessor["identity"].get(
        "attempt_id"
    ) or recomputed.get("successor_raw_attempt_id") != successor["identity"].get(
        "attempt_id"
    ):
        raise AnalysisValidationError(
            "replacement edge is not exact immediate adjacency"
        )
    return recomputed


def analyze_component_composite(path: Path, analysis_id: str) -> dict[str, Any]:
    """Reduce the fixed 80-r02/350-r03 amendment-008 component mapping."""

    raise AnalysisValidationError(
        "the 80-r02/350-r03 composite reducer is withdrawn and fails closed; "
        "use the exact complete r05 whole-attempt reducer"
    )

    if analysis_id != COMPONENT_ANALYSIS_ID:
        raise AnalysisValidationError(
            f"component analysis_id must equal {COMPONENT_ANALYSIS_ID}"
        )
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise AnalysisValidationError("component attempts root must not be a symlink")
    root = expanded.resolve()
    if not root.is_dir():
        raise AnalysisValidationError("component attempts root is not a directory")
    expected_ids = [
        "formal-v3-20260831t051023z-r01",
        attempts_contract._COMPONENT_PREDECESSOR_ID,
        attempts_contract._COMPONENT_SUCCESSOR_ID,
    ]
    observed = sorted(child.name for child in root.iterdir())
    if observed != sorted(expected_ids):
        raise AnalysisValidationError(
            "component attempts root must contain exactly immutable r01/r02/r03"
        )
    validated = {
        attempt_id: validate_attempt(root / attempt_id) for attempt_id in expected_ids
    }
    r01 = validated[expected_ids[0]]
    r02 = validated[expected_ids[1]]
    r03 = validated[expected_ids[2]]
    if not r01["anchored_r01"] or not r02["anchored_r02"] or not r03["component_r03"]:
        raise AnalysisValidationError(
            "raw attempts do not match frozen r01/r02/r03 roles"
        )
    edge_12 = _revalidate_exact_replacement_edge(r01, r02)
    edge_23 = _revalidate_exact_replacement_edge(r02, r03)
    if (
        edge_12.get("classification") != "harness_error"
        or edge_12.get("original_status") != "completed_with_system_violations"
        or edge_23.get("classification") != attempts_contract._COMPONENT_CLASSIFICATION
    ):
        raise AnalysisValidationError("raw replacement chain differs from amendments")
    forensics = _require_dict(
        edge_23.get("r02_terminal_forensics"),
        "r02 terminal-forensics binding",
    )
    forensics_labels = forensics.get("ordered_labels")
    if not isinstance(forensics_labels, list) or len(forensics_labels) != 430:
        raise AnalysisValidationError(
            "r02 terminal-forensics binding does not label all 430 rows"
        )
    forensics_by_position: dict[int, dict[str, Any]] = {}
    for label_row in forensics_labels:
        if (
            not isinstance(label_row, dict)
            or type(label_row.get("plan_index")) is not int
        ):
            raise AnalysisValidationError("r02 terminal-forensics label row is invalid")
        position = int(label_row["plan_index"])
        if position in forensics_by_position:
            raise AnalysisValidationError("r02 terminal-forensics repeats a position")
        forensics_by_position[position] = label_row
    if set(forensics_by_position) != set(range(430)):
        raise AnalysisValidationError("r02 terminal-forensics positions are incomplete")

    config_value = _require_dict(r03["identity"].get("config"), "r03 config")
    config_kwargs = dict(config_value)
    for name in ("rule_counts", "project_counts", "burst_sizes"):
        config_kwargs[name] = tuple(config_kwargs[name])
    component_plans = systems.build_component_repair_plans(
        systems.MatrixConfig(**config_kwargs)
    )
    if (
        r02["plan"] != component_plans["full_plan"]
        or r03["plan"] != component_plans["repair_plan"]
        or component_plans["mapping_sha256"] != systems.FORMAL_COMPONENT_MAPPING_SHA256
    ):
        raise AnalysisValidationError(
            "raw plans differ from the fixed component mapping"
        )

    r02_units = r02["units"]
    r03_units = r03["units"]
    composite_units: list[dict[str, Any]] = []
    sensitivity_rows: list[dict[str, Any]] = []
    for row in component_plans["mapping"]["rows"]:
        canonical_position = int(row["canonical_position"])
        if row["source_attempt_id"] == attempts_contract._COMPONENT_PREDECESSOR_ID:
            source = r02_units[int(row["source_plan_position"])]
        else:
            source = r03_units[int(row["source_plan_position"])]
            r02_source = r02_units[canonical_position]
            forensic = forensics_by_position[canonical_position]
            if (
                forensic.get("component") != r02_source["component"]
                or forensic.get("unit_id") != r02_source["unit_id"]
                or forensic.get("dependency_class") != "direct_paw"
                or forensic.get("primary_disposition") != "replace_from_r03"
                or forensic.get("raw_status") != r02_source["status"]
                or forensic.get("repair_sensitivity_label")
                not in {
                    "premeasurement_cache_failure",
                    "measured_after_unbound_cache_convergence",
                    "other_structural_phase",
                }
            ):
                raise AnalysisValidationError(
                    "r02 terminal-forensics direct row differs from raw ledger"
                )
            sensitivity_rows.append(
                {
                    "canonical_position": canonical_position,
                    "component": r02_source["component"],
                    "unit_id": r02_source["unit_id"],
                    "raw_status": r02_source["status"],
                    "started": r02_source["started"],
                    "terminal_record": r02_source["terminal_record"],
                    "terminal_sha256": r02_source["terminal_sha256"],
                    "repair_sensitivity_label": forensic["repair_sensitivity_label"],
                    "matched_predicate_id": forensic["matched_predicate_id"],
                    "raw_value": r02_source["value"],
                }
            )
        if (
            source["component"] != row["component"]
            or source["unit_id"] != row["unit_id"]
        ):
            raise AnalysisValidationError("mapping row selects a different raw unit")
        composite_units.append(
            {
                **source,
                "canonical_position": canonical_position,
                "source_attempt_id": row["source_attempt_id"],
                "source_plan_position": row["source_plan_position"],
            }
        )
    if len(composite_units) != 430 or len(sensitivity_rows) != 350:
        raise AnalysisValidationError("component mapping does not cover 430/350 rows")
    if [row["canonical_position"] for row in sensitivity_rows] != list(range(350)):
        raise AnalysisValidationError("r02 direct-PAW sensitivity ledger is incomplete")
    for position in range(350, 430):
        forensic = forensics_by_position[position]
        r02_source = r02_units[position]
        if (
            forensic.get("component") != r02_source["component"]
            or forensic.get("unit_id") != r02_source["unit_id"]
            or forensic.get("dependency_class") != "deterministic_no_paw"
            or forensic.get("primary_disposition") != "carry_from_r02"
            or forensic.get("repair_sensitivity_label") != "other_structural_phase"
            or forensic.get("raw_status") != r02_source["status"]
        ):
            raise AnalysisValidationError(
                "r02 terminal-forensics carry row differs from raw ledger"
            )

    carry_units = [
        unit
        for unit in composite_units
        if unit["source_attempt_id"] == attempts_contract._COMPONENT_PREDECESSOR_ID
    ]
    repaired_units = [
        unit
        for unit in composite_units
        if unit["source_attempt_id"] == attempts_contract._COMPONENT_SUCCESSOR_ID
    ]
    promoted = bool(
        len(carry_units) == 80
        and len(repaired_units) == 350
        and r02["source_unchanged"] is True
        and all(unit["status"] in PRIMARY_ELIGIBLE_STATUSES for unit in carry_units)
        and r03["eligible"]
    )
    endpoints = (
        _reduce_endpoints(component_plans["full_plan"], composite_units)
        if promoted
        else None
    )
    sensitivity_units = r02_units[:350]
    sensitivity = {
        "raw_attempt_id": attempts_contract._COMPONENT_PREDECESSOR_ID,
        "raw_status": r02["result"].get("status"),
        "row_count": len(sensitivity_rows),
        "rows": sensitivity_rows,
        "label_counts": forensics.get("label_counts"),
        "boundaries": forensics.get("boundaries"),
        "forensics_payload_sha256": forensics.get("payload_sha256"),
        "endpoints": _reduce_endpoints(
            component_plans["repair_plan"], sensitivity_units
        ),
        "selection_effect": "none; every row is diagnostic and r03 remains the fixed primary source",
    }
    amendment = _load_amendment_008()
    if amendment is None:
        raise AnalysisValidationError(
            "frozen amendment 008 disappeared during reduction"
        )
    binding = {
        **_component_static_analysis_binding(analysis_id),
        "component_mapping": component_plans["mapping"],
        "component_mapping_sha256": component_plans["mapping_sha256"],
        "raw_attempt_inputs": {
            attempt_id: validated[attempt_id]["input_receipts"]
            for attempt_id in expected_ids
        },
        "replacement_edges": {
            "r01_to_r02": {
                "receipt_sha256": edge_12.get("receipt_sha256"),
                "classification": edge_12.get("classification"),
            },
            "r02_to_r03": {
                "receipt_sha256": edge_23.get("receipt_sha256"),
                "classification": edge_23.get("classification"),
                "component_protocol_correction": edge_23.get(
                    "component_protocol_correction"
                ),
                "r02_terminal_forensics": {
                    key: forensics.get(key)
                    for key in (
                        "receipt_type",
                        "payload_sha256",
                        "receipt",
                        "label_counts",
                        "boundaries",
                        "counts",
                        "digests",
                    )
                },
            },
        },
        "amendment_008_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_008[-1]),
        "amendment_009_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_009[-1]),
        "amendment_010_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_010[-1]),
        "amendment_011_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_011[-1]),
        "amendment_012_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_012[-1]),
        "amendment_013_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_013[-1]),
        "amendment_014_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_014[-1]),
        "amendment_015_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_015[-1]),
        "amendment_016_sha256": _sha256(REPO_ROOT / PROTOCOL_PATHS_016[-1]),
    }
    return {
        "schema_version": 1,
        "analysis_id": analysis_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_binding": binding,
        "analysis_binding_sha256": _sha256_bytes(_canonical_json_bytes(binding)),
        "raw_attempt_ledger": [
            {
                "raw_attempt_id": attempt_id,
                "raw_status": validated[attempt_id]["result"].get("status"),
                "raw_result_sha256": validated[attempt_id]["result_sha256"],
                "raw_status_preserved": True,
                "unit_count": len(validated[attempt_id]["units"]),
                "units": [
                    {
                        "source_plan_position": position,
                        "component": unit["component"],
                        "unit_id": unit["unit_id"],
                        "raw_status": unit["status"],
                        "started": unit["started"],
                        "terminal_record": unit["terminal_record"],
                        "terminal_sha256": unit["terminal_sha256"],
                        "raw_value": unit["value"],
                    }
                    for position, unit in enumerate(validated[attempt_id]["units"])
                ],
            }
            for attempt_id in expected_ids
        ],
        "component_mapping": component_plans["mapping"],
        "component_mapping_sha256": component_plans["mapping_sha256"],
        "composite_primary": {
            "promoted": promoted,
            "unit_count": 430 if promoted else 0,
            "source_counts": {
                attempts_contract._COMPONENT_PREDECESSOR_ID: len(carry_units),
                attempts_contract._COMPONENT_SUCCESSOR_ID: len(repaired_units),
            },
            "reason": (
                "all exact replacement, evidence, plan, cache, source, and terminal gates passed"
                if promoted
                else "one or more fail-closed component promotion gates did not pass"
            ),
        },
        "endpoints": endpoints,
        "composite_unit_ledger": [
            {
                "canonical_position": unit["canonical_position"],
                "component": unit["component"],
                "unit_id": unit["unit_id"],
                "source_attempt_id": unit["source_attempt_id"],
                "source_plan_position": unit["source_plan_position"],
                "raw_status": unit["status"],
                "started": unit["started"],
                "terminal_record": unit["terminal_record"],
                "terminal_sha256": unit["terminal_sha256"],
                "raw_value": unit["value"],
            }
            for unit in composite_units
        ],
        "r02_direct_paw_sensitivity": sensitivity,
    }


def analyze_whole_attempt(path: Path, analysis_id: str) -> dict[str, Any]:
    """Reduce exact r08 as the sole primary source and retain r02 as sensitivity."""

    if analysis_id != COMPONENT_ANALYSIS_ID:
        raise AnalysisValidationError(
            f"whole-attempt analysis_id must equal {COMPONENT_ANALYSIS_ID}"
        )
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise AnalysisValidationError("whole-attempt root must not be a symlink")
    root = expanded.resolve()
    if not root.is_dir():
        raise AnalysisValidationError("whole-attempt root is not a directory")
    expected_ids = [
        "formal-v3-20260831t051023z-r01",
        attempts_contract._COMPONENT_PREDECESSOR_ID,
        attempts_contract._COMPONENT_SUCCESSOR_ID,
    ]
    if sorted(child.name for child in root.iterdir()) != sorted(expected_ids):
        raise AnalysisValidationError(
            "whole-attempt root must contain exactly immutable r01/r02/r08"
        )
    r08 = validate_attempt(root / attempts_contract._COMPONENT_SUCCESSOR_ID)
    if not r08.get("component_r08"):
        raise AnalysisValidationError("r08 does not have amendment-016 identity")
    if (
        len(r08.get("plan") or []) != 430
        or len(r08.get("units") or []) != 430
        or not r08.get("eligible")
        or r08.get("source_unchanged") is not True
    ):
        raise AnalysisValidationError("r08 is not a complete eligible 430-row attempt")
    identity = _require_dict(r08.get("identity"), "r08 identity")
    replacement = _require_dict(
        identity.get("attempt_replacement"), "r08 replacement binding"
    )
    if (
        replacement.get("classification") != attempts_contract._COMPONENT_CLASSIFICATION
        or replacement.get("predecessor_raw_attempt_id")
        != attempts_contract._COMPONENT_PREDECESSOR_ID
        or replacement.get("successor_raw_attempt_id")
        != attempts_contract._COMPONENT_SUCCESSOR_ID
    ):
        raise AnalysisValidationError("r02/r03/r04/r05/r06/r07-to-r08 edge differs")
    prepublication = _require_dict(
        replacement.get("prepublication_failure"),
        "r03 prepublication failure binding",
    )
    members = _require_dict(
        prepublication.get("terminal_archive_members"),
        "r03 prepublication archive members",
    )
    if (
        prepublication.get("raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_PREPUBLICATION_ID
        or prepublication.get("attempt_root_absent") is not True
        or set(members) != set(attempts_contract._COMPONENT_PREPUBLICATION_MEMBER_NAMES)
    ):
        raise AnalysisValidationError("r03 prepublication retention binding differs")
    r04_prepublication = _require_dict(
        replacement.get("r04_prepublication_failure"),
        "r04 prepublication failure binding",
    )
    r04_members = _require_dict(
        r04_prepublication.get("terminal_archive_members"),
        "r04 prepublication archive members",
    )
    if (
        r04_prepublication.get("raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R04_ID
        or r04_prepublication.get("attempt_root_absent") is not True
        or r04_prepublication.get("measurement_started") is not False
        or set(r04_members)
        != set(attempts_contract._COMPONENT_R04_PREPUBLICATION_MEMBER_NAMES)
    ):
        raise AnalysisValidationError("r04 prepublication retention binding differs")
    r05_prepublication = _require_dict(
        replacement.get("r05_prepublication_failure"),
        "r05 prepublication failure binding",
    )
    r05_members = _require_dict(
        r05_prepublication.get("terminal_archive_members"),
        "r05 prepublication archive members",
    )
    if (
        r05_prepublication.get("raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R05_ID
        or r05_prepublication.get("attempt_root_absent") is not True
        or r05_prepublication.get("measurement_started") is not False
        or set(r05_members)
        != set(attempts_contract._COMPONENT_R05_PREPUBLICATION_MEMBER_NAMES)
    ):
        raise AnalysisValidationError("r05 prepublication retention binding differs")
    r06_prepublication = _require_dict(
        replacement.get("r06_prepublication_failure"),
        "r06 prepublication failure binding",
    )
    r06_members = _require_dict(
        r06_prepublication.get("terminal_archive_members"),
        "r06 prepublication archive members",
    )
    if (
        r06_prepublication.get("raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R06_ID
        or r06_prepublication.get("attempt_root_absent") is not True
        or r06_prepublication.get("measurement_started") is not False
        or set(r06_members)
        != set(attempts_contract._COMPONENT_R06_PREPUBLICATION_MEMBER_NAMES)
    ):
        raise AnalysisValidationError("r06 prepublication retention binding differs")
    r07_prepublication = _require_dict(
        replacement.get("r07_prepublication_failure"),
        "r07 prepublication failure binding",
    )
    r07_members = _require_dict(
        r07_prepublication.get("terminal_archive_members"),
        "r07 prepublication archive members",
    )
    if (
        r07_prepublication.get("raw_attempt_id")
        != attempts_contract._COMPONENT_BURNED_R07_ID
        or r07_prepublication.get("attempt_root_absent") is not True
        or r07_prepublication.get("measurement_started") is not False
        or set(r07_members)
        != set(attempts_contract._COMPONENT_R07_PREPUBLICATION_MEMBER_NAMES)
    ):
        raise AnalysisValidationError("r07 prepublication retention binding differs")
    correction = _require_dict(
        replacement.get("whole_attempt_protocol_correction"),
        "whole-attempt correction",
    )
    if (
        correction.get("primary_source_attempt_id")
        != attempts_contract._COMPONENT_SUCCESSOR_ID
    ):
        raise AnalysisValidationError("whole-attempt primary source is not exact r08")
    partial = _require_dict(
        replacement.get("r02_partial_terminal_forensics"),
        "r02 partial terminal forensics",
    )
    ordered_partial = partial.get("ordered_units")
    if not isinstance(ordered_partial, list) or len(ordered_partial) != 430:
        raise AnalysisValidationError("r02 partial forensics does not cover 430 roles")
    for position, row in enumerate(ordered_partial):
        if (
            not isinstance(row, dict)
            or row.get("plan_index") != position
            or row.get("primary_source_attempt_id")
            != attempts_contract._COMPONENT_SUCCESSOR_ID
        ):
            raise AnalysisValidationError("r02 partial role ledger differs")
    endpoints = _reduce_endpoints(r08["plan"], r08["units"])
    primary_ledger = [
        {
            "canonical_position": position,
            "component": unit["component"],
            "unit_id": unit["unit_id"],
            "source_attempt_id": attempts_contract._COMPONENT_SUCCESSOR_ID,
            "source_plan_position": position,
            "raw_status": unit["status"],
            "started": unit["started"],
            "terminal_record": unit["terminal_record"],
            "terminal_sha256": unit["terminal_sha256"],
            "raw_value": unit["value"],
        }
        for position, unit in enumerate(r08["units"])
    ]
    binding = {
        **_component_static_analysis_binding(analysis_id),
        "primary_source_attempt_id": attempts_contract._COMPONENT_SUCCESSOR_ID,
        "full_plan_sha256": systems.FORMAL_FULL_PLAN_SHA256,
        "full_plan_stored_sha256": systems.FORMAL_FULL_PLAN_STORED_SHA256,
        "ordered_membership_sha256": systems.FORMAL_FULL_PLAN_MEMBERSHIP_SHA256,
        "r08_input_receipts": r08["input_receipts"],
        "r02_partial_forensics_receipt": {
            key: partial.get(key)
            for key in (
                "receipt_type",
                "payload_sha256",
                "receipt",
                "counts",
                "digests",
            )
        },
    }
    return {
        "schema_version": 1,
        "analysis_id": analysis_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_binding": binding,
        "analysis_binding_sha256": _sha256_bytes(_canonical_json_bytes(binding)),
        "primary_r08": {
            "promoted": True,
            "unit_count": 430,
            "source_attempt_id": attempts_contract._COMPONENT_SUCCESSOR_ID,
            "reason": "all exact whole-attempt promotion gates passed",
        },
        "endpoints": endpoints,
        "primary_unit_ledger": primary_ledger,
        "r02_partial_sensitivity": {
            "raw_attempt_id": attempts_contract._COMPONENT_PREDECESSOR_ID,
            "primary_selection_effect": "none",
            "counts": partial.get("counts"),
            "ordered_units": ordered_partial,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path)
    source.add_argument("--attempts-root", type=Path)
    source.add_argument("--component-attempts-root", type=Path)
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.component_attempts_root:
        value = analyze_whole_attempt(args.component_attempts_root, args.analysis_id)
    elif args.attempts_root:
        value = analyze_attempts_root(args.attempts_root, args.analysis_id)
    else:
        value = analyze(args.input, args.analysis_id)
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with output.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
        except FileExistsError as exc:
            raise SystemExit(
                f"refusing to replace immutable analysis: {output}"
            ) from exc
        print(output)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
