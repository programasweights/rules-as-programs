#!/usr/bin/env python3
"""Run the frozen systems reducer and atomically publish its evidence bundle.

This wrapper is intentionally independent from the reducer.  It binds the
exact H3 inputs, records the execution even when reduction is incomplete or
fails, and publishes one four-file directory without replacement.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
H3_COMMIT = "efea2a704433602fdfa159429ba7b4620b22fc62"
H3_ROOT_TREE_GIT_SHA1 = "d2bd96663a8f3aac144fec74738c86ae720539a0"
H3_EXPERIMENTS_TREE_GIT_SHA1 = "f098ebb90df90dd349c9fb8ec3689cda19035087"
H3_EXPERIMENTS_FILE_COUNT = 102
H3_EXPERIMENTS_TOTAL_BYTES = 3_993_510
H3_EXPERIMENTS_INVENTORY_SHA256 = (
    "383b1bbf033a6237a24de3115c68f73499e1428d130373e8c557761e6fbecd0f"
)
ANALYZER_MODULE = "experiments.eacl2027.analyze_scaling_faults"
ANALYSIS_VERSION = "protocol-v3-amendment-007-systems-reducer-v1"
R01 = "formal-v3-20260831t051023z-r01"
R02 = "formal-v3-20260831t051023z-r02"
ANALYSIS_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
REDUCER_CONFIG_SHA256 = (
    "b604ccc14a2ae38920567915aa744c4aaf9ae3180179fc82e405dd4dab62caea"
)
SELECTION_RULE = (
    "earliest launch-ordered eligible attempt after only immutable, "
    "pre-authorized harness/infrastructure replacements"
)
FINAL_FILE_NAMES = (
    "environment.json",
    "gate.json",
    "reduced.json",
    "run-receipt.json",
)

# These are the exact bytes at H3.  The wrapper itself is deliberately not in
# this mapping because it is introduced after H3; all scientific inputs are.
BOUND_H3_FILES: dict[str, str] = {
    "experiments/eacl2027/analyze_scaling_faults.py": (
        "95b74b4bb934bc7f9e1a6f906774d882d2fba9d82608ba3e7ef3f60eec8f8ad4"
    ),
    "experiments/eacl2027/run_scaling_faults.py": (
        "16078b7c9b58871ff377648dd0d8b5575eca63cf4f7bd2d1b55cb26f5d78b58c"
    ),
    "experiments/eacl2027/scaling_faults_attempts.py": (
        "b31f850f867da39d08468a5d627c68f91a885b0335fcb9afcd0c6d2ab6029bbf"
    ),
    "experiments/eacl2027/scaling_faults_runtime.py": (
        "b27c89b139627a411e60969b59c8041770d8cea764b1a3ebfced9e6312df3931"
    ),
    "experiments/eacl2027/run_integrated.py": (
        "4299821948dc946b472caf80bc5721406a6e9ff1e3bfeaec92e949f63f204add"
    ),
    "experiments/eacl2027/protocol-v3.json": (
        "9509153c7afe3620c3ed847d9531554bf9111819d7dd4ec0612053d13333db62"
    ),
    "experiments/eacl2027/protocol-v3-amendment-001.json": (
        "c0b89366c7b9110f9443dea5f8d3455432ac92b9d622e9632ec7fead710340b2"
    ),
    "experiments/eacl2027/protocol-v3-amendment-002.json": (
        "999a26079fc08e0dc910f0407c82f9211fa3a789c66793167fef8fdd2e869f50"
    ),
    "experiments/eacl2027/protocol-v3-amendment-003.json": (
        "bb3241a7f347f000151dbc72831e22ba1f30125c7461033eec13bc4d8494e75e"
    ),
    "experiments/eacl2027/protocol-v3-amendment-004.json": (
        "94020b51609ded8be42158111a2bd1670bb292db004aca5875ddf78059c48d6b"
    ),
    "experiments/eacl2027/protocol-v3-amendment-005.json": (
        "11ee9f268076b2fc56a3cedad8a8b1919ec4407db826b1d998dec84a68743bb3"
    ),
    "experiments/eacl2027/protocol-v3-amendment-006.json": (
        "f2ce7848370630b82024bb84668600fcda765b34af734f0fe94392ed9a530a2f"
    ),
    "experiments/eacl2027/protocol-v3-amendment-007.json": (
        "540ee245cd025d3cb5c4146fb36ec30b7d54b40ccc74de78a3a4df9a06f4aa91"
    ),
    "experiments/eacl2027/formal-runtime-lock-v3.json": (
        "2a7dac0d6d3a57a6416fabc665255d09001e3054572532527b724ed9be7ee5c7"
    ),
}
ANALYZER_CODE_PATHS = (
    "experiments/eacl2027/analyze_scaling_faults.py",
    "experiments/eacl2027/run_scaling_faults.py",
    "experiments/eacl2027/scaling_faults_attempts.py",
    "experiments/eacl2027/scaling_faults_runtime.py",
)
PROTOCOL_PATHS = (
    "experiments/eacl2027/protocol-v3.json",
    "experiments/eacl2027/protocol-v3-amendment-001.json",
    "experiments/eacl2027/protocol-v3-amendment-002.json",
    "experiments/eacl2027/protocol-v3-amendment-003.json",
    "experiments/eacl2027/protocol-v3-amendment-004.json",
    "experiments/eacl2027/protocol-v3-amendment-005.json",
    "experiments/eacl2027/protocol-v3-amendment-006.json",
    "experiments/eacl2027/protocol-v3-amendment-007.json",
)
TOOLING_PATHS = (
    "experiments/eacl2027/run_scaling_faults_analysis_bundle.py",
    "experiments/eacl2027/run_scaling_faults_analysis_watgpu.sbatch",
)

SAFE_ENVIRONMENT_NAMES = (
    "CUDA_VISIBLE_DEVICES",
    "HOME",
    "LANG",
    "LC_ALL",
    "OMP_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "PATH",
    "PAW_CACHE_DIR",
    "PAW_GPU_LAYERS",
    "PIP_CONFIG_FILE",
    "PIP_DISABLE_PIP_VERSION_CHECK",
    "PIP_FIND_LINKS",
    "PIP_NO_INDEX",
    "PIP_NO_INPUT",
    "PIP_REQUIRE_VIRTUALENV",
    "PYTHONHASHSEED",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONNOUSERSITE",
    "PYTHONPATH",
    "RAP_ANALYSIS_H3_SOURCE_ROOT",
    "RAP_ANALYSIS_NETWORK_GUARD",
    "TZ",
    "VECLIB_MAXIMUM_THREADS",
)
EXPECTED_DISTRIBUTIONS = {
    "anyio": "4.14.2",
    "certifi": "2026.7.22",
    "diskcache": "5.6.3",
    "exceptiongroup": "1.3.1",
    "h11": "0.16.0",
    "httpcore": "1.0.9",
    "httpx": "0.28.1",
    "idna": "3.19",
    "jinja2": "3.1.6",
    "llama-cpp-python": "0.3.19",
    "markupsafe": "3.0.3",
    "numpy": "2.2.6",
    "pillow": "12.3.0",
    "pip": "26.1.2",
    "programasweights": "0.4.2",
    "psutil": "7.2.2",
    "pystray": "0.19.5",
    "python-xlib": "0.33",
    "rules-as-programs": "0.1.0",
    "six": "1.17.0",
    "typing-extensions": "4.16.0",
}
RULES_ORIGIN_MODULES = (
    "rules_as_programs",
    "rules_as_programs.config",
    "rules_as_programs.ipc",
    "rules_as_programs.rules_api",
    "rules_as_programs.adapters.codex.adapter",
    "rules_as_programs.core.evaluation_log",
    "rules_as_programs.core.revisions",
    "rules_as_programs.core.triggers",
)
RULES_ORIGIN_PROBE_CODE = """\
import importlib
import json

names = json.loads(%r)
result = {}
for name in names:
    module = importlib.import_module(name)
    result[name] = {
        "file": getattr(module, "__file__", None),
        "spec_origin": getattr(getattr(module, "__spec__", None), "origin", None),
    }
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
""" % json.dumps(list(RULES_ORIGIN_MODULES))


class AnalysisBundleError(RuntimeError):
    """Base class for wrapper failures."""


class SourceBindingError(AnalysisBundleError):
    """A frozen scientific input differs from H3."""


class EnvironmentGateError(AnalysisBundleError):
    """The execution environment is not the required formal environment."""


class BundleCollisionError(AnalysisBundleError):
    """The immutable output or its serialization claim already exists."""


class PublicationError(AnalysisBundleError):
    """The bundle could not be published with no-replace semantics."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _stream_file_receipt(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    byte_count = 0
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise SourceBindingError(f"not a regular file: {path}")
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                byte_count += len(chunk)
            closed = os.fstat(handle.fileno())
    except OSError as exc:
        raise SourceBindingError(f"could not hash {path}: {exc}") from exc
    if (
        path.is_symlink()
        or opened.st_dev != closed.st_dev
        or opened.st_ino != closed.st_ino
        or opened.st_size != closed.st_size
        or byte_count != closed.st_size
    ):
        raise SourceBindingError(f"file changed while hashing: {path}")
    return {
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
        "mode": stat.S_IMODE(closed.st_mode),
        "device": closed.st_dev,
        "inode": closed.st_ino,
    }


def _verify_bound_sources(root: Path = REPO_ROOT) -> list[dict[str, Any]]:
    receipts = []
    for relative, expected_sha256 in BOUND_H3_FILES.items():
        path = root / relative
        receipt = _stream_file_receipt(path)
        if receipt["sha256"] != expected_sha256:
            raise SourceBindingError(
                f"H3 source hash mismatch for {relative}: "
                f"expected {expected_sha256}, observed {receipt['sha256']}"
            )
        receipts.append(
            {
                "path": relative,
                "bytes": receipt["bytes"],
                "sha256": receipt["sha256"],
            }
        )
    return receipts


def _h3_source_snapshot_receipt(root: Path) -> dict[str, Any]:
    """Verify the complete, read-only H3 ``experiments`` source snapshot.

    The analyzer deliberately runs from this snapshot rather than the checkout.
    There is no ``rules_as_programs`` directory in the snapshot, so the import
    path can resolve RAP only from the freshly installed locked wheel.
    """
    root_info = _ensure_owner_private_directory(root, "H3 analysis source snapshot")
    if stat.S_IMODE(root_info.st_mode) != 0o500:
        raise EnvironmentGateError("H3 source snapshot root must have mode 0500")
    top_level = sorted(item.name for item in root.iterdir())
    if top_level != ["experiments"]:
        raise EnvironmentGateError(
            "H3 source snapshot must contain only the experiments tree"
        )

    receipts: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        current_info = current_path.lstat()
        if (
            stat.S_ISLNK(current_info.st_mode)
            or not stat.S_ISDIR(current_info.st_mode)
            or current_info.st_uid != os.getuid()
            or stat.S_IMODE(current_info.st_mode) != 0o500
        ):
            raise EnvironmentGateError(
                f"H3 source snapshot has an unsafe directory: {current_path}"
            )
        directories.append(
            {
                "path": str(current_path.relative_to(root)) or ".",
                "mode": stat.S_IMODE(current_info.st_mode),
            }
        )
        for name in sorted(directory_names):
            child = current_path / name
            child_info = child.lstat()
            if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISDIR(
                child_info.st_mode
            ):
                raise EnvironmentGateError(
                    f"H3 source snapshot has a symlink/non-directory: {child}"
                )
        for name in sorted(file_names):
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise EnvironmentGateError(
                    f"H3 source snapshot has a symlink/non-file: {path}"
                )
            receipt = _stream_file_receipt(path)
            if receipt["mode"] != 0o400 or info.st_uid != os.getuid():
                raise EnvironmentGateError(
                    f"H3 source snapshot file is not owner-read-only: {path}"
                )
            receipts.append(
                {
                    "path": str(path.relative_to(root)),
                    "bytes": receipt["bytes"],
                    "sha256": receipt["sha256"],
                }
            )

    receipts.sort(key=lambda item: str(item["path"]))
    inventory_sha256 = _sha256_bytes(_canonical_json_bytes(receipts))
    total_bytes = sum(int(item["bytes"]) for item in receipts)
    if (
        len(receipts) != H3_EXPERIMENTS_FILE_COUNT
        or total_bytes != H3_EXPERIMENTS_TOTAL_BYTES
        or inventory_sha256 != H3_EXPERIMENTS_INVENTORY_SHA256
    ):
        raise EnvironmentGateError(
            "H3 source snapshot inventory differs from the exact commit tree"
        )
    bound = _verify_bound_sources(root)
    return {
        "root": str(root),
        "h3_commit": H3_COMMIT,
        "root_tree_git_sha1": H3_ROOT_TREE_GIT_SHA1,
        "experiments_tree_git_sha1": H3_EXPERIMENTS_TREE_GIT_SHA1,
        "file_count": len(receipts),
        "total_bytes": total_bytes,
        "inventory_sha256": inventory_sha256,
        "directories": sorted(directories, key=lambda item: str(item["path"])),
        "bound_sources": bound,
        "bound_sources_sha256": _binding_digest(bound),
        "rules_as_programs_present": False,
    }


def _binding_digest(receipts: Sequence[Mapping[str, Any]]) -> str:
    return _sha256_bytes(_canonical_json_bytes(list(receipts)))


def _tooling_receipts() -> list[dict[str, Any]]:
    receipts = []
    for relative in TOOLING_PATHS:
        receipt = _stream_file_receipt(REPO_ROOT / relative)
        receipts.append(
            {
                "path": relative,
                "bytes": receipt["bytes"],
                "sha256": receipt["sha256"],
            }
        )
    return receipts


def _strict_json_object(data: bytes, label: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite number {value}")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=no_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise AnalysisBundleError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AnalysisBundleError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    if set(value) != expected:
        raise AnalysisBundleError(
            f"{label} fields differ: expected {sorted(expected)}, got {sorted(value)}"
        )


def _validate_timestamp(value: Any, label: str) -> None:
    if not isinstance(value, str):
        raise AnalysisBundleError(f"{label} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AnalysisBundleError(f"{label} is invalid: {value}") from exc
    if parsed.tzinfo is None:
        raise AnalysisBundleError(f"{label} lacks a timezone")


def _validate_analysis_binding(
    reduced: Mapping[str, Any], attempts_root: Path, analysis_id: str
) -> None:
    _require_exact_keys(
        reduced,
        {
            "schema_version",
            "analysis_id",
            "generated_at",
            "analysis_binding",
            "analysis_binding_sha256",
            "attempt_ledger",
            "primary_numeric",
            "endpoints",
            "sensitivity_endpoints",
        },
        "reduced root",
    )
    if (
        reduced.get("schema_version") != 1
        or type(reduced.get("schema_version")) is not int
    ):
        raise AnalysisBundleError("reduced schema_version must be integer 1")
    if reduced.get("analysis_id") != analysis_id:
        raise AnalysisBundleError("reduced analysis_id differs from requested ID")
    _validate_timestamp(reduced.get("generated_at"), "reduced generated_at")
    binding = reduced.get("analysis_binding")
    if not isinstance(binding, dict):
        raise AnalysisBundleError("analysis_binding must be an object")
    _require_exact_keys(
        binding,
        {
            "analysis_id",
            "analysis_version",
            "analysis_code",
            "protocol_documents",
            "reducer_config",
            "reducer_config_sha256",
            "attempts_root",
            "launch_ordered_attempts",
            "selected_primary_raw_attempt_id",
            "selection_blocked_by",
            "chain_error",
        },
        "analysis binding",
    )
    expected_binding_hash = _sha256_bytes(_canonical_json_bytes(binding))
    if reduced.get("analysis_binding_sha256") != expected_binding_hash:
        raise AnalysisBundleError("analysis_binding_sha256 mismatch")
    if binding.get("analysis_id") != analysis_id:
        raise AnalysisBundleError("analysis binding has a different analysis_id")
    if binding.get("analysis_version") != ANALYSIS_VERSION:
        raise AnalysisBundleError("analysis binding has a different reducer version")
    if binding.get("attempts_root") != str(attempts_root):
        raise AnalysisBundleError("analysis binding has a different attempts root")

    code = binding.get("analysis_code")
    expected_code = [
        {"path": path, "sha256": BOUND_H3_FILES[path]} for path in ANALYZER_CODE_PATHS
    ]
    if code != expected_code:
        raise AnalysisBundleError("analysis code binding differs from exact H3")
    protocols = binding.get("protocol_documents")
    expected_protocols = [
        {"path": path, "sha256": BOUND_H3_FILES[path]} for path in PROTOCOL_PATHS
    ]
    if protocols != expected_protocols:
        raise AnalysisBundleError("protocol binding differs from exact H3")
    reducer_config = binding.get("reducer_config")
    if not isinstance(reducer_config, dict):
        raise AnalysisBundleError("reducer_config must be an object")
    observed_reducer_config_sha256 = _sha256_bytes(
        _canonical_json_bytes(reducer_config)
    )
    if (
        binding.get("reducer_config_sha256") != observed_reducer_config_sha256
        or observed_reducer_config_sha256 != REDUCER_CONFIG_SHA256
    ):
        raise AnalysisBundleError("reducer_config hash mismatch")


def _classify_reduced(
    reduced: Mapping[str, Any], attempts_root: Path, analysis_id: str
) -> tuple[str, list[str]]:
    """Validate provenance/coherence and return complete or incomplete."""
    _validate_analysis_binding(reduced, attempts_root, analysis_id)
    ledger = reduced.get("attempt_ledger")
    if not isinstance(ledger, list) or len(ledger) != 2:
        raise AnalysisBundleError("attempt ledger must contain exactly r01 and r02")
    if any(not isinstance(item, dict) for item in ledger):
        raise AnalysisBundleError("attempt ledger entries must be objects")
    if [item.get("raw_attempt_id") for item in ledger] != [R01, R02]:
        raise AnalysisBundleError("attempt ledger is not the exact r01/r02 chain")
    binding = reduced["analysis_binding"]
    if binding.get("launch_ordered_attempts") != ledger:
        raise AnalysisBundleError("binding ledger differs from reported attempt ledger")

    r01, r02 = ledger
    if r01.get("status") != "completed_with_system_violations":
        raise AnalysisBundleError("r01 raw status was not preserved")
    if r01.get("candidate_eligible") is not False:
        raise AnalysisBundleError("r01 must never be a numeric candidate")
    if r01.get("replacement_authorized_by_successor") not in {True, False}:
        raise AnalysisBundleError("r01 replacement authorization must be boolean")
    if r01.get("replacement_authorized_by_successor") is True:
        if (
            r01.get("adjudicated_status") != "superseded_premeasurement_harness_error"
            or r01.get("raw_status_preserved") != "completed_with_system_violations"
            or r01.get("numeric_aggregate_excluded") is not True
        ):
            raise AnalysisBundleError("r01 amendment-007 adjudication is incomplete")

    allowed_r02_statuses = {
        "completed",
        "completed_with_system_violations",
        "incomplete_harness_error",
        "incomplete_infrastructure_error",
        "incomplete_unclassified_failure",
        "incomplete_or_integrity_failure",
    }
    if r02.get("status") not in allowed_r02_statuses:
        raise AnalysisBundleError("r02 has a noncanonical attempt status")
    if r02.get("candidate_eligible") not in {True, False}:
        raise AnalysisBundleError("r02 candidate eligibility must be boolean")
    if r02.get("candidate_eligible") is True and r02.get("status") not in {
        "completed",
        "completed_with_system_violations",
    }:
        raise AnalysisBundleError("incomplete r02 cannot be numeric eligible")

    primary = reduced.get("primary_numeric")
    if not isinstance(primary, dict):
        raise AnalysisBundleError("primary_numeric must be an object")
    _require_exact_keys(
        primary,
        {
            "promoted",
            "selected_raw_attempt_id",
            "selection_blocked_by",
            "selection_rule",
        },
        "primary numeric",
    )
    if primary.get("selection_rule") != SELECTION_RULE:
        raise AnalysisBundleError("primary selection rule differs from amendment 007")
    selected = primary.get("selected_raw_attempt_id")
    promoted = primary.get("promoted")
    if selected not in {None, R02} or promoted is not (selected == R02):
        raise AnalysisBundleError("primary selection is incoherent or not exact r02")
    if binding.get("selected_primary_raw_attempt_id") != selected:
        raise AnalysisBundleError("binding and primary selection differ")
    if binding.get("selection_blocked_by") != primary.get("selection_blocked_by"):
        raise AnalysisBundleError("binding and primary blocker differ")
    if (reduced.get("endpoints") is not None) is not promoted:
        raise AnalysisBundleError("endpoint presence differs from promotion status")
    if reduced.get("sensitivity_endpoints") != {}:
        raise AnalysisBundleError(
            "exact r01/r02 ledger must have no sensitivity endpoint"
        )
    blocker = primary.get("selection_blocked_by")
    if promoted:
        if blocker is not None:
            raise AnalysisBundleError("complete r02 promotion cannot retain a blocker")
    else:
        expected_blocker = (
            R01
            if binding.get("chain_error") is not None
            or r01.get("replacement_authorized_by_successor") is not True
            else R02
        )
        if blocker != expected_blocker:
            raise AnalysisBundleError(
                "incomplete selection blocker differs from the exact ledger state"
            )

    complete_checks = {
        "ledger chain has no error": binding.get("chain_error") is None,
        "r01 replacement is authorized": (
            r01.get("replacement_authorized_by_successor") is True
        ),
        "r01 adjudication is exact": (
            r01.get("adjudicated_status") == "superseded_premeasurement_harness_error"
            and r01.get("raw_status_preserved") == "completed_with_system_violations"
            and r01.get("numeric_aggregate_excluded") is True
        ),
        "r01 validates without error": (
            "validation_error" in r01 and r01.get("validation_error") is None
        ),
        "r02 validates without error": (
            "validation_error" in r02 and r02.get("validation_error") is None
        ),
        "r02 replacement edge validates": (
            "replacement_validation_error" in r02
            and r02.get("replacement_validation_error") is None
        ),
        "r02 is numeric eligible": r02.get("candidate_eligible") is True,
        "r02 is the promoted primary": promoted and selected == R02,
        "numeric endpoints are present": (
            isinstance(reduced.get("endpoints"), dict)
            and set(reduced["endpoints"]) == {"matrix", "soak", "offline", "faults"}
            and all(isinstance(value, dict) for value in reduced["endpoints"].values())
        ),
    }
    reasons = [label for label, passed in complete_checks.items() if not passed]
    if not reasons:
        return "complete", []
    if promoted:
        raise AnalysisBundleError(
            "reducer promoted r02 despite incomplete amendment-007 gates: "
            + "; ".join(reasons)
        )
    return "incomplete", reasons


def _ensure_owner_private_directory(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AnalysisBundleError(f"could not inspect {label} {path}: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise AnalysisBundleError(f"{label} must be a non-symlink directory: {path}")
    if info.st_uid != os.getuid():
        raise AnalysisBundleError(f"{label} must be owned by the executing uid")
    if stat.S_IMODE(info.st_mode) & 0o022:
        raise AnalysisBundleError(f"{label} must not be group/world writable")
    return info


def _prepare_paths(
    attempts_root_argument: Path, bundle_output_argument: Path
) -> tuple[Path, int, os.stat_result, Path, int, os.stat_result]:
    raw_attempts = attempts_root_argument.expanduser()
    if not raw_attempts.is_absolute():
        raw_attempts = Path.cwd() / raw_attempts
    lexical_attempts = Path(os.path.abspath(raw_attempts))
    if lexical_attempts.is_symlink():
        raise AnalysisBundleError("attempts root must not be a symlink")
    attempts_root = lexical_attempts.resolve(strict=True)
    if attempts_root != lexical_attempts:
        raise AnalysisBundleError("attempts root must not traverse symlinks")
    attempts_info = _ensure_owner_private_directory(attempts_root, "attempts root")
    if sorted(item.name for item in attempts_root.iterdir()) != [R01, R02]:
        raise AnalysisBundleError("attempts root must contain exactly r01 and r02")
    for attempt_id in (R01, R02):
        child = attempts_root / attempt_id
        if child.is_symlink() or not child.is_dir():
            raise AnalysisBundleError(f"{attempt_id} must be a non-symlink directory")
    attempts_fd = os.open(
        attempts_root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    opened_attempts = os.fstat(attempts_fd)
    if (opened_attempts.st_dev, opened_attempts.st_ino) != (
        attempts_info.st_dev,
        attempts_info.st_ino,
    ):
        os.close(attempts_fd)
        raise AnalysisBundleError("attempts root was swapped while opening")
    parent_fd: int | None = None
    try:
        raw_output = bundle_output_argument.expanduser()
        if not raw_output.is_absolute():
            raw_output = Path.cwd() / raw_output
        bundle_output = Path(os.path.abspath(raw_output))
        if bundle_output.name in {"", ".", ".."}:
            raise AnalysisBundleError("bundle output must name a new directory")
        try:
            inside_repo = os.path.commonpath(
                (str(REPO_ROOT), str(bundle_output))
            ) == str(REPO_ROOT)
        except ValueError:
            inside_repo = False
        if inside_repo:
            raise AnalysisBundleError(
                "bundle output must be outside the Git repository"
            )
        parent = bundle_output.parent.resolve(strict=True)
        if parent != bundle_output.parent:
            raise AnalysisBundleError("bundle output parent must not traverse symlinks")
        parent_info = _ensure_owner_private_directory(parent, "bundle parent")
        if parent == attempts_root or parent.is_relative_to(attempts_root):
            raise AnalysisBundleError(
                "bundle parent must be disjoint from the immutable attempts tree"
            )
        if attempts_root.is_relative_to(parent):
            raise AnalysisBundleError(
                "bundle parent must not contain the immutable attempts root"
            )
        parent_fd = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_parent = os.fstat(parent_fd)
        if (opened_parent.st_dev, opened_parent.st_ino) != (
            parent_info.st_dev,
            parent_info.st_ino,
        ):
            raise AnalysisBundleError("bundle parent was swapped while opening")
        try:
            os.stat(bundle_output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise BundleCollisionError(
                f"immutable bundle already exists: {bundle_output}"
            )
        return (
            attempts_root,
            attempts_fd,
            attempts_info,
            bundle_output,
            parent_fd,
            parent_info,
        )
    except Exception:
        os.close(attempts_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        raise


def _revalidate_directory(
    path: Path, fd: int, expected: os.stat_result, label: str
) -> None:
    try:
        by_path = path.lstat()
        by_fd = os.fstat(fd)
    except OSError as exc:
        raise AnalysisBundleError(f"{label} disappeared or changed: {exc}") from exc
    expected_id = (expected.st_dev, expected.st_ino)
    if path.is_symlink() or (by_path.st_dev, by_path.st_ino) != expected_id:
        raise AnalysisBundleError(f"{label} path was swapped during analysis")
    if (by_fd.st_dev, by_fd.st_ino) != expected_id:
        raise AnalysisBundleError(f"{label} descriptor identity changed")


def _slurm_receipt(environ: Mapping[str, str]) -> dict[str, Any]:
    partition = environ.get("SLURM_JOB_PARTITION")
    job_id = environ.get("SLURM_JOB_ID")
    if partition != "ALL":
        raise EnvironmentGateError("formal analysis requires SLURM_JOB_PARTITION=ALL")
    if not isinstance(job_id, str) or re.fullmatch(r"[0-9]+", job_id) is None:
        raise EnvironmentGateError("formal analysis requires a numeric SLURM_JOB_ID")
    if environ.get("SLURM_JOB_NODELIST") != "watgpu108":
        raise EnvironmentGateError(
            "formal analysis requires SLURM_JOB_NODELIST=watgpu108"
        )
    values = {
        key: value for key, value in sorted(environ.items()) if key.startswith("SLURM_")
    }
    return {
        "required_partition": "ALL",
        "partition_accepted": True,
        "job_id": job_id,
        "environment": values,
        "environment_sha256": _sha256_bytes(_canonical_json_bytes(values)),
    }


def _runtime_receipt(environ: Mapping[str, str]) -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    distributions = sorted(
        {
            re.sub(r"[-_.]+", "-", (dist.metadata.get("Name") or "").lower()): (
                dist.version
            )
            for dist in importlib.metadata.distributions()
            if dist.metadata.get("Name")
        }.items()
    )
    safe_environment = {
        name: environ[name] for name in SAFE_ENVIRONMENT_NAMES if name in environ
    }
    environment_names = sorted(environ)
    return {
        "python": {
            "executable": str(executable),
            "executable_receipt": _stream_file_receipt(executable),
            "version": sys.version,
            "version_info": list(sys.version_info),
            "implementation": platform.python_implementation(),
            "distributions": [
                {"name": name, "version": version} for name, version in distributions
            ],
        },
        "process": {
            "argv": list(sys.argv),
            "cwd": str(Path.cwd().resolve()),
            "pid": os.getpid(),
            "uid": os.getuid(),
            "gid": os.getgid(),
            "umask": _read_umask(),
        },
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "uname": list(platform.uname()),
        },
        "safe_environment": safe_environment,
        "safe_environment_sha256": _sha256_bytes(
            _canonical_json_bytes(safe_environment)
        ),
        "all_environment_names": environment_names,
        "all_environment_names_sha256": _sha256_bytes(
            _canonical_json_bytes(environment_names)
        ),
        "uncaptured_values_reason": "Only execution-relevant allowlisted and SLURM variables are retained; secret-bearing values are never copied into publication evidence.",
    }


def _formal_runtime_gate(
    environ: Mapping[str, str],
    slurm: Mapping[str, Any],
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    job_id = str(slurm["job_id"])
    node_root = Path(f"/tmp/rap-eacl-analysis-{job_id}")
    expected_venv = node_root / "venv"
    expected_executable = expected_venv / "bin" / "python"
    expected_guard = node_root / "network-guard" / "sitecustomize.py"
    expected_wheelhouse = node_root / "wheelhouse"
    expected_source_root = node_root / "h3-source"
    required_environment = {
        "CUDA_VISIBLE_DEVICES": "",
        "HOME": str(node_root / "home"),
        "PAW_GPU_LAYERS": "0",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_FIND_LINKS": str(expected_wheelhouse),
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PIP_REQUIRE_VIRTUALENV": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": f"{node_root / 'network-guard'}:{REPO_ROOT}",
        "RAP_ANALYSIS_H3_SOURCE_ROOT": str(expected_source_root),
    }
    mismatched = {
        name: {"expected": expected, "observed": environ.get(name)}
        for name, expected in required_environment.items()
        if environ.get(name) != expected
    }
    if mismatched:
        raise EnvironmentGateError(
            "formal analysis environment differs from the locked sbatch wrapper: "
            + json.dumps(mismatched, sort_keys=True)
        )
    if Path(sys.executable) != expected_executable or Path(sys.prefix) != expected_venv:
        raise EnvironmentGateError(
            "analysis is not running from the fresh job-local venv"
        )
    if sys.prefix == sys.base_prefix or sys.flags.no_user_site != 1:
        raise EnvironmentGateError("analysis Python is not isolated from user packages")

    node_info = _ensure_owner_private_directory(node_root, "node runtime root")
    wheelhouse_info = _ensure_owner_private_directory(
        expected_wheelhouse, "snapshotted wheelhouse"
    )
    if (
        stat.S_IMODE(node_info.st_mode) != 0o700
        or stat.S_IMODE(wheelhouse_info.st_mode) != 0o700
    ):
        raise EnvironmentGateError("formal runtime directories must have mode 0700")

    guard_receipt = _stream_file_receipt(expected_guard)
    guard_declaration = environ.get("RAP_ANALYSIS_NETWORK_GUARD", "")
    expected_declaration = f"python-inet-deny-v1:{guard_receipt['sha256']}"
    if guard_declaration != expected_declaration or guard_receipt["mode"] != 0o400:
        raise EnvironmentGateError("network guard declaration or file identity differs")
    guard_module = sys.modules.get("sitecustomize")
    guard_module_path = Path(str(getattr(guard_module, "__file__", "")))
    if (
        guard_module is None
        or guard_module_path != expected_guard
        or socket.create_connection.__module__ != "sitecustomize"
        or socket.getaddrinfo.__module__ != "sitecustomize"
    ):
        raise EnvironmentGateError(
            "network guard is not active in the analysis process"
        )
    try:
        socket.create_connection(("127.0.0.1", 9), timeout=0.001)
    except PermissionError as exc:
        guard_probe = {"passed": True, "type": type(exc).__name__, "message": str(exc)}
    except OSError as exc:
        raise EnvironmentGateError(
            f"network guard probe reached an operating-system socket: {exc}"
        ) from exc
    else:
        raise EnvironmentGateError("network guard probe unexpectedly connected")

    distributions = {
        str(item["name"]): str(item["version"])
        for item in runtime["python"]["distributions"]
    }
    if distributions != EXPECTED_DISTRIBUTIONS:
        raise EnvironmentGateError(
            "installed distribution set differs from locked wheels"
        )

    lock = _strict_json_object(
        (REPO_ROOT / "experiments/eacl2027/formal-runtime-lock-v3.json").read_bytes(),
        "formal runtime lock",
    )
    locked_wheelhouse = lock.get("wheelhouse")
    if not isinstance(locked_wheelhouse, dict) or not isinstance(
        locked_wheelhouse.get("files"), list
    ):
        raise EnvironmentGateError("formal runtime lock wheel inventory is invalid")
    locked_files = locked_wheelhouse["files"]
    expected_names = sorted(str(item.get("path")) for item in locked_files)
    observed_names = sorted(item.name for item in expected_wheelhouse.iterdir())
    if observed_names != expected_names:
        raise EnvironmentGateError(
            "snapshotted wheelhouse has missing or extra entries"
        )
    snapshot_receipts = []
    for item in locked_files:
        name = str(item["path"])
        receipt = _stream_file_receipt(expected_wheelhouse / name)
        if (
            receipt["bytes"] != item.get("bytes")
            or receipt["sha256"] != item.get("sha256")
            or receipt["mode"] != 0o400
        ):
            raise EnvironmentGateError(f"snapshotted wheel differs from lock: {name}")
        snapshot_receipts.append(
            {"path": name, "bytes": receipt["bytes"], "sha256": receipt["sha256"]}
        )
    source_snapshot = _h3_source_snapshot_receipt(expected_source_root)
    return {
        "version": "formal-analysis-runtime-gate-v1",
        "node_root": str(node_root),
        "venv": str(expected_venv),
        "python_executable": str(expected_executable),
        "required_environment": required_environment,
        "guard": {
            "path": str(expected_guard),
            "bytes": guard_receipt["bytes"],
            "sha256": guard_receipt["sha256"],
            "active_probe": guard_probe,
        },
        "wheel_snapshot": {
            "root": str(expected_wheelhouse),
            "locked_inventory_sha256": locked_wheelhouse.get("inventory_sha256"),
            "files": snapshot_receipts,
            "snapshot_sha256": _sha256_bytes(_canonical_json_bytes(snapshot_receipts)),
        },
        "h3_source_snapshot": source_snapshot,
        "distributions": [
            {"name": name, "version": version}
            for name, version in sorted(distributions.items())
        ],
    }


def _read_umask() -> str:
    current = os.umask(0)
    os.umask(current)
    return f"{current:04o}"


def _analyzer_environment(
    environ: Mapping[str, str], formal_runtime_gate: Mapping[str, Any]
) -> tuple[dict[str, str], Path]:
    source_value = formal_runtime_gate.get("h3_source_snapshot")
    guard_value = formal_runtime_gate.get("guard")
    if not isinstance(source_value, dict) or not isinstance(guard_value, dict):
        raise EnvironmentGateError("formal gate lacks analyzer isolation roots")
    source_root = Path(str(source_value.get("root", "")))
    guard_path = Path(str(guard_value.get("path", "")))
    expected_source = Path(str(environ.get("RAP_ANALYSIS_H3_SOURCE_ROOT", "")))
    if source_root != expected_source or not source_root.is_absolute():
        raise EnvironmentGateError("formal gate source snapshot binding differs")
    if source_root == REPO_ROOT or source_root.is_relative_to(REPO_ROOT):
        raise EnvironmentGateError("analyzer source must be outside the checkout")
    expected_guard_root = source_root.parent / "network-guard"
    if guard_path != expected_guard_root / "sitecustomize.py":
        raise EnvironmentGateError("formal gate network guard binding differs")
    analyzer_environ = dict(environ)
    analyzer_environ["PYTHONPATH"] = f"{expected_guard_root}:{source_root}"
    analyzer_environ["PYTHONDONTWRITEBYTECODE"] = "1"
    if str(REPO_ROOT) in analyzer_environ["PYTHONPATH"].split(os.pathsep):
        raise EnvironmentGateError("analyzer PYTHONPATH contains the working checkout")
    return analyzer_environ, source_root


def _invoke_origin_probe(
    argv: Sequence[str], environ: Mapping[str, str], cwd: Path
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(argv),
        cwd=cwd,
        env=dict(environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _rules_origin_probe(
    environ: Mapping[str, str], source_root: Path, expected_venv: Path
) -> dict[str, Any]:
    argv = [sys.executable, "-c", RULES_ORIGIN_PROBE_CODE]
    started_utc = _utc_now()
    started_monotonic_ns = time.monotonic_ns()
    try:
        completed = _invoke_origin_probe(argv, environ, source_root)
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnvironmentGateError(
            f"could not execute RAP import-origin probe: {type(exc).__name__}: {exc}"
        ) from exc
    ended_monotonic_ns = time.monotonic_ns()
    ended_utc = _utc_now()
    stdout = bytes(completed.stdout)
    stderr = bytes(completed.stderr)
    if completed.returncode != 0:
        raise EnvironmentGateError(
            "RAP import-origin probe failed: "
            f"exit={completed.returncode}, stderr_sha256={_sha256_bytes(stderr)}"
        )
    value = _strict_json_object(stdout, "RAP import-origin probe stdout")
    if set(value) != set(RULES_ORIGIN_MODULES):
        raise EnvironmentGateError("RAP import-origin probe module set differs")

    site_packages = (
        expected_venv
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    ).resolve(strict=True)
    modules = []
    for name in RULES_ORIGIN_MODULES:
        item = value.get(name)
        if not isinstance(item, dict) or set(item) != {"file", "spec_origin"}:
            raise EnvironmentGateError(f"RAP origin shape differs for {name}")
        if item.get("file") != item.get("spec_origin") or not isinstance(
            item.get("file"), str
        ):
            raise EnvironmentGateError(f"RAP origin is ambiguous for {name}")
        lexical = Path(str(item["file"]))
        if not lexical.is_absolute() or lexical.is_symlink():
            raise EnvironmentGateError(f"RAP origin is not a regular path for {name}")
        resolved = lexical.resolve(strict=True)
        try:
            relative = resolved.relative_to(site_packages)
        except ValueError as exc:
            raise EnvironmentGateError(
                f"RAP module resolved outside the locked venv wheel: {name}"
            ) from exc
        if not relative.parts or relative.parts[0] != "rules_as_programs":
            raise EnvironmentGateError(
                f"RAP module resolved outside the installed package: {name}"
            )
        receipt = _stream_file_receipt(resolved)
        modules.append(
            {
                "module": name,
                "origin": str(resolved),
                "relative_to_site_packages": str(relative),
                "bytes": receipt["bytes"],
                "sha256": receipt["sha256"],
            }
        )
    return {
        "argv": argv,
        "cwd": str(source_root),
        "started_utc": started_utc,
        "ended_utc": ended_utc,
        "elapsed_monotonic_ns": ended_monotonic_ns - started_monotonic_ns,
        "exit_code": completed.returncode,
        "stdout": {
            "bytes": len(stdout),
            "sha256": _sha256_bytes(stdout),
            "base64": base64.b64encode(stdout).decode("ascii"),
        },
        "stderr": {
            "bytes": len(stderr),
            "sha256": _sha256_bytes(stderr),
            "base64": base64.b64encode(stderr).decode("ascii"),
        },
        "site_packages": str(site_packages),
        "modules": modules,
        "modules_sha256": _sha256_bytes(_canonical_json_bytes(modules)),
    }


def _invoke_analyzer(
    argv: Sequence[str], environ: Mapping[str, str]
) -> subprocess.CompletedProcess[bytes]:
    source_root = Path(environ["RAP_ANALYSIS_H3_SOURCE_ROOT"])
    return subprocess.run(
        list(argv),
        cwd=source_root,
        env=dict(environ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _write_exclusive_file(directory_fd: int, name: str, data: bytes) -> dict[str, Any]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise PublicationError(f"short write for {name}")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        info = os.fstat(fd)
    finally:
        os.close(fd)
    return {
        "path": name,
        "bytes": len(data),
        "sha256": _sha256_bytes(data),
        "mode": stat.S_IMODE(info.st_mode),
    }


def _read_staged_file_receipt(directory_fd: int, name: str) -> dict[str, Any]:
    fd = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    digest = hashlib.sha256()
    byte_count = 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise PublicationError(f"staged entry is not regular: {name}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
        closed = os.fstat(fd)
    finally:
        os.close(fd)
    if (
        opened.st_dev != closed.st_dev
        or opened.st_ino != closed.st_ino
        or opened.st_size != closed.st_size
        or byte_count != closed.st_size
    ):
        raise PublicationError(f"staged file changed while hashing: {name}")
    return {
        "path": name,
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
        "mode": stat.S_IMODE(closed.st_mode),
    }


def _validate_staged_bundle(
    staging_fd: int,
    staging_info: os.stat_result,
    expected_files: Mapping[str, Mapping[str, Any]],
) -> None:
    directory_info = os.fstat(staging_fd)
    if not stat.S_ISDIR(directory_info.st_mode) or (
        directory_info.st_dev,
        directory_info.st_ino,
    ) != (staging_info.st_dev, staging_info.st_ino):
        raise PublicationError("staging descriptor identity changed")
    if stat.S_IMODE(directory_info.st_mode) != 0o500:
        raise PublicationError("staging directory must be owner-only and read-only")
    if sorted(os.listdir(staging_fd)) != sorted(FINAL_FILE_NAMES):
        raise PublicationError("staging bundle has unexpected files")
    if set(expected_files) != set(FINAL_FILE_NAMES):
        raise PublicationError("staging receipt set is incomplete")
    for name in FINAL_FILE_NAMES:
        observed = _read_staged_file_receipt(staging_fd, name)
        if observed != dict(expected_files[name]) or observed["mode"] != 0o444:
            raise PublicationError(f"staged file identity differs: {name}")
    os.fsync(staging_fd)


def _create_staging_directory(
    parent_fd: int, destination_name: str
) -> tuple[str, os.stat_result]:
    for _attempt in range(128):
        name = f".{destination_name}.staging-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        directory_fd: int | None = None
        try:
            directory_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
            os.fchmod(directory_fd, 0o700)
            os.fsync(directory_fd)
            info = os.fstat(directory_fd)
            by_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (by_path.st_dev, by_path.st_ino)
            ):
                raise PublicationError("new staging directory is not owner-private")
            os.fsync(parent_fd)
            return name, info
        except Exception:
            try:
                os.rmdir(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
            raise
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
    raise PublicationError("could not allocate an exclusive staging directory")


def _cleanup_staging(
    parent_fd: int,
    staging_name: str,
    expected: os.stat_result | None,
    staging_fd: int | None = None,
) -> None:
    try:
        current = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if expected is not None and (current.st_dev, current.st_ino) != (
        expected.st_dev,
        expected.st_ino,
    ):
        return
    if not stat.S_ISDIR(current.st_mode):
        return
    owned_fd = staging_fd is None
    if staging_fd is None:
        try:
            staging_fd = os.open(
                staging_name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        except OSError:
            return
    opened = os.fstat(staging_fd)
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        if owned_fd:
            os.close(staging_fd)
        return
    try:
        try:
            os.fchmod(staging_fd, 0o700)
        except OSError:
            return
        for name in FINAL_FILE_NAMES:
            try:
                os.unlink(name, dir_fd=staging_fd)
            except FileNotFoundError:
                pass
        os.fsync(staging_fd)
        try:
            final_path_info = os.stat(
                staging_name, dir_fd=parent_fd, follow_symlinks=False
            )
        except FileNotFoundError:
            return
        if (final_path_info.st_dev, final_path_info.st_ino) != (
            current.st_dev,
            current.st_ino,
        ):
            return
        try:
            os.rmdir(staging_name, dir_fd=parent_fd)
        except OSError:
            pass
    finally:
        if owned_fd:
            os.close(staging_fd)
        try:
            os.fsync(parent_fd)
        except OSError:
            pass


def _native_publication_method() -> str:
    libc = ctypes.CDLL(None, use_errno=True)
    system = platform.system()
    if system == "Linux":
        if getattr(libc, "renameat2", None) is not None:
            return "renameat2_RENAME_NOREPLACE"
        machine = platform.machine().lower()
        if (
            machine in {"x86_64", "amd64", "aarch64", "arm64"}
            and getattr(libc, "syscall", None) is not None
        ):
            return "syscall_renameat2_RENAME_NOREPLACE"
        raise PublicationError("Linux renameat2 is unavailable")
    if system == "Darwin" and getattr(libc, "renameatx_np", None) is not None:
        return "renameatx_np_RENAME_EXCL"
    raise PublicationError(f"no no-replace directory rename for {system}")


def _rename_noreplace(parent_fd: int, source_name: str, destination_name: str) -> str:
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    libc = ctypes.CDLL(None, use_errno=True)
    method = _native_publication_method()
    if method == "renameat2_RENAME_NOREPLACE":
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(parent_fd, source, parent_fd, destination, 1)
    elif method == "syscall_renameat2_RENAME_NOREPLACE":
        syscall = libc.syscall
        machine = platform.machine().lower()
        numbers = {"x86_64": 316, "amd64": 316, "aarch64": 276, "arm64": 276}
        number = numbers[machine]
        syscall.restype = ctypes.c_long
        result = syscall(number, parent_fd, source, parent_fd, destination, 1)
    elif method == "renameatx_np_RENAME_EXCL":
        function = libc.renameatx_np
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(parent_fd, source, parent_fd, destination, 0x00000004)
    else:  # pragma: no cover - guarded by _native_publication_method
        raise PublicationError(f"unsupported native publication method: {method}")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise BundleCollisionError(
                f"immutable bundle appeared before publication: {destination_name}"
            )
        raise PublicationError(
            f"native no-replace publication failed: {os.strerror(error_number)}"
        )
    return method


def _publish_bundle(
    *,
    parent_fd: int,
    parent_path: Path,
    parent_info: os.stat_result,
    staging_name: str,
    staging_info: os.stat_result,
    staging_fd: int,
    expected_files: Mapping[str, Mapping[str, Any]],
    destination_name: str,
    expected_method: str,
    claim_payload: bytes,
) -> str:
    _revalidate_directory(parent_path, parent_fd, parent_info, "bundle parent")
    _validate_staged_bundle(staging_fd, staging_info, expected_files)
    claim_name = f".{destination_name}.publication-claim"
    claim_fd: int | None = None
    renamed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            claim_fd = os.open(claim_name, flags, 0o400, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise BundleCollisionError(
                f"publication claim already exists: {parent_path / claim_name}"
            ) from exc
        view = memoryview(claim_payload)
        while view:
            written = os.write(claim_fd, view)
            if written <= 0:
                raise PublicationError("short write for publication claim")
            view = view[written:]
        os.fsync(claim_fd)
        os.close(claim_fd)
        claim_fd = None
        try:
            os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise BundleCollisionError(
                f"immutable bundle appeared before publication: {destination_name}"
            )
        observed_staging = os.stat(
            staging_name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (observed_staging.st_dev, observed_staging.st_ino) != (
            staging_info.st_dev,
            staging_info.st_ino,
        ):
            raise PublicationError("staging directory was swapped before publication")
        _validate_staged_bundle(staging_fd, staging_info, expected_files)
        method = _rename_noreplace(parent_fd, staging_name, destination_name)
        renamed = True
        if method != expected_method:
            raise PublicationError(
                "successful publication method differs from the bound receipt"
            )
        final_info = os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        if (final_info.st_dev, final_info.st_ino) != (
            staging_info.st_dev,
            staging_info.st_ino,
        ):
            raise PublicationError("published bundle identity differs from staging")
        os.fsync(staging_fd)
        os.fsync(parent_fd)
        return method
    finally:
        if claim_fd is not None:
            os.close(claim_fd)
        try:
            os.unlink(claim_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            pass
        if not renamed:
            _cleanup_staging(parent_fd, staging_name, staging_info, staging_fd)


def run_analysis_bundle(
    attempts_root_argument: Path,
    analysis_id: str,
    bundle_output_argument: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run the analyzer and publish one immutable evidence bundle."""
    if ANALYSIS_ID_PATTERN.fullmatch(analysis_id) is None:
        raise AnalysisBundleError("analysis_id must match the frozen slug grammar")
    effective_environ = dict(os.environ if environ is None else environ)
    slurm = _slurm_receipt(effective_environ)
    runtime = _runtime_receipt(effective_environ)
    formal_runtime_gate = _formal_runtime_gate(effective_environ, slurm, runtime)
    sources_before = _verify_bound_sources()
    tooling_before = _tooling_receipts()
    analyzer_environ, analyzer_cwd = _analyzer_environment(
        effective_environ, formal_runtime_gate
    )
    source_snapshot_before = dict(formal_runtime_gate["h3_source_snapshot"])
    origin_probe = _rules_origin_probe(
        analyzer_environ, analyzer_cwd, Path(str(formal_runtime_gate["venv"]))
    )
    (
        attempts_root,
        attempts_fd,
        attempts_info,
        bundle_output,
        parent_fd,
        parent_info,
    ) = _prepare_paths(attempts_root_argument, bundle_output_argument)
    staging_name = ""
    staging_info: os.stat_result | None = None
    staging_fd: int | None = None
    try:
        staging_name, staging_info = _create_staging_directory(
            parent_fd, bundle_output.name
        )
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        opened_staging = os.fstat(staging_fd)
        if (opened_staging.st_dev, opened_staging.st_ino) != (
            staging_info.st_dev,
            staging_info.st_ino,
        ):
            raise PublicationError("staging directory was swapped while opening")
        try:
            started_utc = _utc_now()
            started_monotonic_ns = time.monotonic_ns()
            analyzer_argv = [
                sys.executable,
                "-m",
                ANALYZER_MODULE,
                "--attempts-root",
                str(attempts_root),
                "--analysis-id",
                analysis_id,
            ]
            environment_receipt = {
                "schema_version": 1,
                "created_utc": started_utc,
                "h3_commit": H3_COMMIT,
                "source_binding": sources_before,
                "source_binding_sha256": _binding_digest(sources_before),
                "bundle_tooling": tooling_before,
                "bundle_tooling_sha256": _binding_digest(tooling_before),
                "slurm": slurm,
                "runtime": runtime,
                "formal_runtime_gate": formal_runtime_gate,
                "rules_as_programs_import_origin_probe": origin_probe,
                "requested": {
                    "attempts_root": str(attempts_root),
                    "analysis_id": analysis_id,
                    "bundle_output": str(bundle_output),
                },
                "analyzer_argv": analyzer_argv,
                "analyzer_cwd": str(analyzer_cwd),
                "analyzer_safe_environment": {
                    name: analyzer_environ[name]
                    for name in SAFE_ENVIRONMENT_NAMES
                    if name in analyzer_environ
                },
            }
            invocation_error: dict[str, str] | None = None
            try:
                completed = _invoke_analyzer(analyzer_argv, analyzer_environ)
            except (OSError, subprocess.SubprocessError) as exc:
                invocation_error = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                completed = subprocess.CompletedProcess(
                    args=analyzer_argv,
                    returncode=127,
                    stdout=b"",
                    stderr=(f"{type(exc).__name__}: {exc}\n").encode(
                        "utf-8", errors="backslashreplace"
                    ),
                )
            ended_monotonic_ns = time.monotonic_ns()
            ended_utc = _utc_now()
            _revalidate_directory(
                attempts_root, attempts_fd, attempts_info, "attempts root"
            )
            _revalidate_directory(
                bundle_output.parent, parent_fd, parent_info, "bundle parent"
            )
            sources_after = _verify_bound_sources()
            if sources_after != sources_before:
                raise SourceBindingError("H3 sources changed during analysis")
            tooling_after = _tooling_receipts()
            if tooling_after != tooling_before:
                raise SourceBindingError("bundle tooling changed during analysis")
            source_snapshot_after = _h3_source_snapshot_receipt(analyzer_cwd)
            if source_snapshot_after != source_snapshot_before:
                raise SourceBindingError("H3 source snapshot changed during analysis")

            raw_stdout = bytes(completed.stdout)
            raw_stderr = bytes(completed.stderr)
            validation_error: str | None = None
            incomplete_reasons: list[str] = []
            reduced_kind = "analyzer_stdout"
            if completed.returncode == 0:
                try:
                    reduced_value = _strict_json_object(raw_stdout, "analyzer stdout")
                    classification, incomplete_reasons = _classify_reduced(
                        reduced_value, attempts_root, analysis_id
                    )
                    reduced_bytes = raw_stdout
                except AnalysisBundleError as exc:
                    classification = "analyzer_invalid_output"
                    validation_error = str(exc)
                    reduced_kind = "runner_failure_envelope"
                    reduced_bytes = _pretty_json_bytes(
                        {
                            "schema_version": 1,
                            "status": classification,
                            "analysis_id": analysis_id,
                            "validation_error": validation_error,
                            "raw_stdout": {
                                "bytes": len(raw_stdout),
                                "sha256": _sha256_bytes(raw_stdout),
                                "base64": base64.b64encode(raw_stdout).decode("ascii"),
                            },
                        }
                    )
            else:
                classification = "analyzer_failed"
                validation_error = f"analyzer exited with status {completed.returncode}"
                reduced_kind = "runner_failure_envelope"
                reduced_bytes = _pretty_json_bytes(
                    {
                        "schema_version": 1,
                        "status": classification,
                        "analysis_id": analysis_id,
                        "analyzer_exit_code": completed.returncode,
                        "raw_stdout": {
                            "bytes": len(raw_stdout),
                            "sha256": _sha256_bytes(raw_stdout),
                            "base64": base64.b64encode(raw_stdout).decode("ascii"),
                        },
                    }
                )

            environment_file = _write_exclusive_file(
                staging_fd, "environment.json", _pretty_json_bytes(environment_receipt)
            )
            reduced_file = _write_exclusive_file(
                staging_fd, "reduced.json", reduced_bytes
            )
            gate_value = {
                "schema_version": 1,
                "generated_at": ended_utc,
                "classification": classification,
                "complete": classification == "complete",
                "incomplete_reasons": incomplete_reasons,
                "validation_error": validation_error,
                "formal_numeric_publication_authorized": classification == "complete",
                "r01": {
                    "raw_status_required": "completed_with_system_violations",
                    "adjudicated_status_required": (
                        "superseded_premeasurement_harness_error"
                    ),
                    "numeric_aggregate_excluded_required": True,
                },
                "r02": {
                    "selected_primary_required": R02,
                    "eligible_statuses": [
                        "completed",
                        "completed_with_system_violations",
                    ],
                },
                "source_binding_sha256": _binding_digest(sources_after),
            }
            gate_file = _write_exclusive_file(
                staging_fd, "gate.json", _pretty_json_bytes(gate_value)
            )
            publication_method = _native_publication_method()
            run_value = {
                "schema_version": 1,
                "started_utc": started_utc,
                "ended_utc": ended_utc,
                "elapsed_monotonic_ns": ended_monotonic_ns - started_monotonic_ns,
                "classification": classification,
                "analyzer": {
                    "argv": analyzer_argv,
                    "cwd": str(analyzer_cwd),
                    "environment": environment_receipt["analyzer_safe_environment"],
                    "environment_sha256": _sha256_bytes(
                        _canonical_json_bytes(
                            environment_receipt["analyzer_safe_environment"]
                        )
                    ),
                    "exit_code": completed.returncode,
                    "invocation_error": invocation_error,
                    "stdout": {
                        "bytes": len(raw_stdout),
                        "sha256": _sha256_bytes(raw_stdout),
                        "base64": base64.b64encode(raw_stdout).decode("ascii"),
                    },
                    "stderr": {
                        "bytes": len(raw_stderr),
                        "sha256": _sha256_bytes(raw_stderr),
                        "base64": base64.b64encode(raw_stderr).decode("ascii"),
                    },
                },
                "reduced_source": reduced_kind,
                "files": {
                    item["path"]: item
                    for item in (environment_file, gate_file, reduced_file)
                },
                "source_binding_before": sources_before,
                "source_binding_after": sources_after,
                "bundle_tooling_before": tooling_before,
                "bundle_tooling_after": tooling_after,
                "h3_source_snapshot_before": source_snapshot_before,
                "h3_source_snapshot_after": source_snapshot_after,
                "rules_as_programs_import_origin_probe": origin_probe,
                "publication": {
                    "destination": str(bundle_output),
                    "claim": str(
                        bundle_output.parent
                        / f".{bundle_output.name}.publication-claim"
                    ),
                    "method": publication_method,
                    "semantics": "native directory rename no-replace",
                },
            }
            run_file = _write_exclusive_file(
                staging_fd, "run-receipt.json", _pretty_json_bytes(run_value)
            )
            expected_files = {
                item["path"]: item
                for item in (environment_file, gate_file, reduced_file, run_file)
            }
            os.fchmod(staging_fd, 0o500)
            _validate_staged_bundle(staging_fd, staging_info, expected_files)
        finally:
            os.fsync(staging_fd)

        _revalidate_directory(
            attempts_root, attempts_fd, attempts_info, "attempts root"
        )
        final_sources = _verify_bound_sources()
        if final_sources != sources_before:
            raise SourceBindingError("H3 sources changed before publication")
        final_tooling = _tooling_receipts()
        if final_tooling != tooling_before:
            raise SourceBindingError("bundle tooling changed before publication")
        final_source_snapshot = _h3_source_snapshot_receipt(analyzer_cwd)
        if final_source_snapshot != source_snapshot_before:
            raise SourceBindingError("H3 source snapshot changed before publication")
        claim = {
            "schema_version": 1,
            "destination": str(bundle_output),
            "staging": staging_name,
            "publication_method": publication_method,
            "files": expected_files,
        }
        method = _publish_bundle(
            parent_fd=parent_fd,
            parent_path=bundle_output.parent,
            parent_info=parent_info,
            staging_name=staging_name,
            staging_info=staging_info,
            staging_fd=staging_fd,
            expected_files=expected_files,
            destination_name=bundle_output.name,
            expected_method=publication_method,
            claim_payload=_pretty_json_bytes(claim),
        )
        staging_name = ""
        return {
            "bundle": str(bundle_output),
            "classification": classification,
            "analyzer_exit_code": completed.returncode,
            "publication_method": method,
            "files": claim["files"],
        }
    finally:
        if staging_name:
            _cleanup_staging(parent_fd, staging_name, staging_info, staging_fd)
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(attempts_fd)
        os.close(parent_fd)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempts_root", type=Path)
    parser.add_argument("analysis_id")
    parser.add_argument("bundle_output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = run_analysis_bundle(
            args.attempts_root, args.analysis_id, args.bundle_output
        )
    except BundleCollisionError as exc:
        print(str(exc), file=sys.stderr)
        return 73
    except EnvironmentGateError as exc:
        print(str(exc), file=sys.stderr)
        return 64
    except AnalysisBundleError as exc:
        print(str(exc), file=sys.stderr)
        return 70
    print(result["bundle"])
    if result["classification"] == "complete":
        return 0
    if result["classification"] == "incomplete":
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
