from __future__ import annotations

import copy
import hashlib
import errno
import json
import os
import shutil
import socket
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from experiments.eacl2027 import scaling_faults_attempts as attempts


PROTOCOL_AMENDMENT = (
    Path(__file__).resolve().parents[1]
    / "experiments/eacl2027/protocol-v3-amendment-007.json"
)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _file_receipt(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "bytes": resolved.stat().st_size,
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
    }


def _predecessor(
    tmp_path: Path,
    result: dict[str, Any],
    *,
    slurm_job_id: str = "12345",
) -> tuple[Path, Path]:
    attempts_root = tmp_path / "attempts"
    predecessor = attempts_root / "formal-study-r01"
    predecessor.mkdir(parents=True)
    _write_json(
        predecessor / "launch.json",
        {
            "identity": {
                "attempt_id": predecessor.name,
                "slurm": {"job_id": slurm_job_id},
            }
        },
    )
    _write_json(predecessor / "plan.json", [])
    _write_json(
        predecessor / "publication.json",
        {
            "schema_version": 1,
            "destination": str(predecessor),
            "method": "native_no_replace",
            "native_primitive": "renameat2_RENAME_NOREPLACE",
            "native_unsupported": None,
            "claim": None,
        },
    )
    _write_json(predecessor / "result.json", result)
    _write_json(
        predecessor / "streams.json",
        {
            "stdout": "stdout.log",
            "stderr": "stderr.log",
            "capture": "synthetic",
            "lossless_from_launch": True,
        },
    )
    (predecessor / "stdout.log").write_text("", encoding="utf-8")
    (predecessor / "stderr.log").write_text("", encoding="utf-8")
    (predecessor / "units.jsonl").write_text("", encoding="utf-8")
    return predecessor, attempts_root / "formal-study-r02"


def _replacement_receipt(
    predecessor: Path,
    successor: Path,
    *,
    classification: str,
    original_status: str,
    evidence: list[tuple[str, Path]],
    scheduler_adjudication: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "successor_raw_attempt_id": successor.name,
        "predecessor_raw_attempt_id": predecessor.name,
        "classification": classification,
        "original_status": original_status,
        "reason": "independently adjudicated prelaunch replacement",
        "affected_boundary": "predecessor process termination",
        "predecessor_artifacts": {
            name: (
                _file_receipt(predecessor / name)
                if (predecessor / name).exists()
                else None
            )
            for name in attempts._PREDECESSOR_ARTIFACT_NAMES
        },
        "predecessor_tree": attempts._predecessor_tree_receipts(predecessor),
        "evidence_receipts": [
            {"kind": kind, **_file_receipt(path)} for kind, path in evidence
        ],
        "scheduler_adjudication": scheduler_adjudication,
    }


def _create_outcome_aware_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, Any]:
    repair = copy.deepcopy(attempts._OUTCOME_AWARE_REPAIR)
    attempts_root = tmp_path / "attempts"
    predecessor = attempts_root / repair["predecessor_raw_attempt_id"]
    successor = attempts_root / repair["successor_raw_attempt_id"]
    predecessor.mkdir(parents=True)

    launch_anchor = repair["launch"]
    launch = {
        "identity_sha256": launch_anchor["identity_sha256"],
        "identity": {
            "attempt_id": predecessor.name,
            "git": {
                "commit": launch_anchor["git_commit"],
                "dirty": False,
                "scope": [
                    "rules_as_programs",
                    "experiments/eacl2027",
                    "pyproject.toml",
                ],
            },
            "runner": {
                "git_blob": launch_anchor["runner_git_blob"],
                "path": "experiments/eacl2027/run_scaling_faults.py",
                "sha256": launch_anchor["runner_sha256"],
            },
            "slurm": {
                "job_id": launch_anchor["slurm"]["job_id"],
                "node_list": launch_anchor["slurm"]["node_list"],
                "partition": launch_anchor["slurm"]["partition"],
            },
            "formal_runtime": {
                "runtime_lock": {
                    "file": {"sha256": launch_anchor["runtime_lock_sha256"]}
                }
            },
        },
    }
    _write_json(predecessor / "launch.json", launch)
    _write_json(predecessor / "plan.json", ["soak", "offline"])
    _write_json(predecessor / "publication.json", {"method": "test"})
    _write_json(
        predecessor / "streams.json",
        {
            "stdout": "stdout.log",
            "stderr": "stderr.log",
            "capture": "synthetic",
            "lossless_from_launch": True,
        },
    )
    (predecessor / "stdout.log").write_text("fixture\n", encoding="utf-8")
    (predecessor / "stderr.log").write_text("", encoding="utf-8")

    gate = repair["gate"]
    error_message = (
        "daemon startup failed\n"
        f"{gate['bind_frame']}\n"
        f"{gate['error_message_fragment']}"
    )
    units: list[dict[str, Any]] = []
    unit_index: list[dict[str, Any]] = []
    for component in ("soak", "offline"):
        retained_root = predecessor / "runtime" / component
        state = retained_root / "state"
        state.mkdir(parents=True)
        database = state / "verdicts.db"
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE verdicts (id INTEGER PRIMARY KEY)")
            connection.execute("CREATE TABLE attention (id INTEGER PRIMARY KEY)")
            connection.commit()
        finally:
            connection.close()
        terminal = {
            "status": gate["terminal_status"],
            "error": {
                "type": gate["error_type"],
                "message": error_message,
                "traceback": error_message,
                "retained_runtime_root": str(retained_root),
            },
            "samples": [],
            "accounting": {},
            "daemon_identity": None,
        }
        terminal_path = predecessor / component / f"{component}.terminal.json"
        terminal_path.parent.mkdir()
        _write_json(terminal_path, terminal)
        units.append(terminal)
        unit_index.append(
            {
                "component": component,
                "unit_id": component,
                "plan": {"component": component, "unit_id": component},
                "started": True,
                "status": gate["terminal_status"],
                "terminal_record": terminal_path.relative_to(predecessor).as_posix(),
                "terminal_record_sha256": hashlib.sha256(
                    terminal_path.read_bytes()
                ).hexdigest(),
            }
        )
    result = {
        "raw_attempt_id": predecessor.name,
        "status": repair["receipt_overrides"]["original_status"],
        "primary_numeric_eligible": True,
        "complete_plan": True,
        "all_planned_units_terminal": True,
        "planned_unit_count": len(units),
        "terminal_unit_count": len(units),
        "system_violation_units": len(units),
        "unit_status_histogram": {gate["terminal_status"]: len(units)},
        "matrix": [],
        "soak": units[0],
        "offline_after_prepare": units[1],
        "faults": {},
        "unit_index": unit_index,
    }
    _write_json(predecessor / "result.json", result)
    (predecessor / "units.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in unit_index),
        encoding="utf-8",
    )

    repair["core_artifacts"] = {
        name: {
            "bytes": (predecessor / name).stat().st_size,
            "sha256": hashlib.sha256((predecessor / name).read_bytes()).hexdigest(),
        }
        for name in attempts._PREDECESSOR_ARTIFACT_NAMES
    }
    claim_path = (
        tmp_path
        / ".attempts.staging"
        / ".publication-claims"
        / f"{predecessor.name}.launch.json"
    )
    claim_path.parent.mkdir(parents=True)
    os.link(predecessor / "launch.json", claim_path)
    repair["publication_claim"] = {
        "path": str(claim_path),
        **repair["core_artifacts"]["launch.json"],
    }
    tree = attempts._predecessor_tree_receipts(predecessor)
    repair["tree"] = attempts._outcome_aware_tree_summary(tree)
    repair["result"] = {
        name: result[name]
        for name in (
            "status",
            "primary_numeric_eligible",
            "complete_plan",
            "all_planned_units_terminal",
            "planned_unit_count",
            "terminal_unit_count",
            "system_violation_units",
            "unit_status_histogram",
        )
    }
    socket_paths = [
        str(Path(unit["error"]["retained_runtime_root"]) / "state" / "daemon.sock")
        for unit in units
    ]
    socket_lengths = [len(os.fsencode(path)) for path in socket_paths]
    repair["gate"].update(
        {
            "socket_path_min_bytes": min(socket_lengths),
            "socket_path_max_bytes": max(socket_lengths),
            "pathname_limit_bytes": min(socket_lengths) - 1,
            "verdict_database_count": len(units),
        }
    )

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    repair["evidence"]["root"] = str(evidence_root)
    repair["evidence"]["host"] = "fixture-host"
    sacct = evidence_root / "scheduler-sacct.txt"
    sacct.write_text(
        "|".join(
            [
                launch_anchor["slurm"]["job_id"],
                "rap-eacl-systems-v3",
                launch_anchor["slurm"]["partition"],
                launch_anchor["slurm"]["terminal_state"],
                launch_anchor["slurm"]["exit_code"],
                launch_anchor["slurm"]["elapsed"],
                launch_anchor["slurm"]["node_list"],
                "None",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    stdout = evidence_root / "scheduler-stdout.log"
    stderr = evidence_root / "scheduler-stderr.log"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    probe_path = evidence_root / "af-unix-socket-probe.json"
    _write_json(
        probe_path,
        {
            "schema_version": 1,
            "status": "passed",
            "rap_inference_started": False,
            "r01_modified": False,
            "linux_pathname_payload_limit_bytes": repair["gate"][
                "pathname_limit_bytes"
            ],
            "slurm": {
                "job_id": "1524434",
                "node": "watgpu108",
                "partition": "ALL",
            },
            "frozen_failure_reproduction": {
                "bind_failed": True,
                "encoded_path_bytes": 163,
                "error": {"type": "OSError", "message": "AF_UNIX path too long"},
            },
            "proposed_transport": {
                "encoded_path_bytes": 86,
                "bind_connect_accept_payload_equal": True,
                "endpoint_removed_after_probe": True,
                "socket_root_mode": "0700",
                "socket_root_symlink": False,
            },
        },
    )
    for kind, path in (
        ("af_unix_socket_probe", probe_path),
        ("scheduler_sacct", sacct),
        ("scheduler_stdout", stdout),
        ("scheduler_stderr", stderr),
    ):
        repair["evidence"]["files"][kind] = {
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    artifacts = {
        name: _file_receipt(predecessor / name)
        for name in attempts._PREDECESSOR_ARTIFACT_NAMES
    }
    scheduler_receipts = {
        "sacct": _file_receipt(sacct),
        "stdout": _file_receipt(stdout),
        "stderr": _file_receipt(stderr),
    }
    adjudication = {
        "schema_version": 1,
        "classification": "harness_error",
        "attempt_id": predecessor.name,
        "successor_attempt_id": successor.name,
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
            "status": result["status"],
            "primary_numeric_eligible_raw": result["primary_numeric_eligible"],
            "planned_units": len(units),
            "terminal_units": len(units),
            "system_violation_labels": len(units),
            "matrix_samples": 0,
            "nonempty_accounting_values": 0,
            "non_null_daemon_identities": 0,
            "state_database_rows": {
                "databases": len(units),
                "verdicts": 0,
                "attention": 0,
            },
        },
        "failure": {
            "stage": (
                "AF_UNIX bind before daemon readiness, warmup, wrapper invocation, "
                "or measured event"
            ),
            "error_signature": gate["error_message_fragment"],
            "units_with_exact_stage_signature": len(units),
            "linux_pathname_payload_limit_bytes": repair["gate"][
                "pathname_limit_bytes"
            ],
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
        "core_artifacts": artifacts,
        "tree": repair["tree"],
        "scheduler_evidence": scheduler_receipts,
        "host": repair["evidence"]["host"],
    }
    adjudication_path = evidence_root / "premeasurement-harness-adjudication.json"
    adjudication_path.write_text(
        json.dumps(adjudication, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(attempts, "_OUTCOME_AWARE_REPAIR", repair)

    evidence = [
        ("premeasurement_harness_adjudication", adjudication_path),
        ("af_unix_socket_probe", probe_path),
        ("scheduler_sacct", sacct),
        ("scheduler_stdout", stdout),
        ("scheduler_stderr", stderr),
    ]
    receipt = _replacement_receipt(
        predecessor,
        successor,
        classification=repair["receipt_overrides"]["classification"],
        original_status=repair["receipt_overrides"]["original_status"],
        evidence=evidence,
    )
    receipt.update(
        {
            "reason": repair["receipt_overrides"]["reason"],
            "affected_boundary": repair["receipt_overrides"]["affected_boundary"],
        }
    )
    receipt_path = tmp_path / "replacement.json"
    _write_json(receipt_path, receipt)
    return {
        "predecessor": predecessor,
        "successor": successor,
        "receipt": receipt,
        "receipt_path": receipt_path,
        "repair": repair,
        "evidence_root": evidence_root,
    }


def _rebind_fixture_result_after_tamper(fixture: dict[str, Any]) -> None:
    predecessor = fixture["predecessor"]
    result_path = predecessor / "result.json"
    result_receipt = _file_receipt(result_path)
    fixture["repair"]["core_artifacts"]["result.json"] = {
        "bytes": result_receipt["bytes"],
        "sha256": result_receipt["sha256"],
    }
    fixture["receipt"]["predecessor_artifacts"]["result.json"] = result_receipt
    tree = attempts._predecessor_tree_receipts(predecessor)
    fixture["receipt"]["predecessor_tree"] = tree
    fixture["repair"]["tree"] = attempts._outcome_aware_tree_summary(tree)
    _write_json(fixture["receipt_path"], fixture["receipt"])


@pytest.mark.parametrize(
    "classified_fragment",
    [
        {"unit_index": [{"status": "system_violation"}]},
        {"global_outcomes": {"statuses": ["system_violation"]}},
        {
            "global_outcomes": {
                "cache_end_receipt": {"status": "system_violation"},
                "statuses": [],
            }
        },
        {"abort": {"status": "system_violation"}},
        {
            "abort": {
                "status": "unclassified_failure",
                "original_abort_classification": {
                    "status": "system_violation"
                },
            }
        },
        {
            "original_abort_classification": {
                "status": "system_violation"
            }
        },
    ],
    ids=[
        "unit-index",
        "global-statuses",
        "named-global-outcome",
        "abort",
        "nested-original-abort-classification",
        "top-level-original-abort-classification",
    ],
)
def test_replacement_rejects_any_retained_system_violation(
    tmp_path: Path,
    classified_fragment: dict[str, Any],
) -> None:
    result = {"status": "incomplete_harness_error", **classified_fragment}
    predecessor, successor = _predecessor(tmp_path, result)
    evidence_path = tmp_path / "harness-traceback.txt"
    evidence_path.write_text("proven runner assertion failure\n", encoding="utf-8")
    receipt = _replacement_receipt(
        predecessor,
        successor,
        classification="harness_error",
        original_status="incomplete_harness_error",
        evidence=[("harness_traceback", evidence_path)],
    )
    receipt_path = tmp_path / "replacement.json"
    _write_json(receipt_path, receipt)

    with pytest.raises(
        attempts.SystemsHarnessError,
        match="retains a system_violation",
    ):
        attempts.replacement_launch_binding(successor, str(receipt_path))


def test_exact_outcome_aware_premeasurement_replacement_can_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _create_outcome_aware_fixture(tmp_path, monkeypatch)

    binding = attempts.replacement_launch_binding(
        fixture["successor"], str(fixture["receipt_path"])
    )

    assert binding["kind"] == "replacement_attempt"
    assert binding["classification"] == "harness_error"
    assert binding["original_status"] == "completed_with_system_violations"
    assert binding["scheduler_adjudication"] is None
    assert binding["predecessor_raw_attempt_id"] == fixture["predecessor"].name
    assert binding["successor_raw_attempt_id"] == fixture["successor"].name


def test_outcome_aware_override_rejects_a_nearby_attempt_chain(
    tmp_path: Path,
) -> None:
    result = {
        "status": "completed_with_system_violations",
        "unit_index": [{"status": "system_violation"}],
    }
    predecessor, successor = _predecessor(tmp_path, result)
    evidence_path = tmp_path / "forged-adjudication.json"
    _write_json(evidence_path, {"classification": "harness_error"})
    receipt = _replacement_receipt(
        predecessor,
        successor,
        classification="harness_error",
        original_status="completed_with_system_violations",
        evidence=[("premeasurement_harness_adjudication", evidence_path)],
    )
    receipt_path = tmp_path / "replacement.json"
    _write_json(receipt_path, receipt)

    with pytest.raises(
        attempts.SystemsHarnessError,
        match="retains a system_violation",
    ):
        attempts.replacement_launch_binding(successor, str(receipt_path))


def test_outcome_aware_override_rejects_receipt_label_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _create_outcome_aware_fixture(tmp_path, monkeypatch)
    fixture["receipt"]["reason"] = "same evidence, broader replacement label"
    _write_json(fixture["receipt_path"], fixture["receipt"])

    with pytest.raises(
        attempts.SystemsHarnessError,
        match="reason does not match the frozen override",
    ):
        attempts.replacement_launch_binding(
            fixture["successor"], str(fixture["receipt_path"])
        )


@pytest.mark.parametrize(
    ("unit_name", "field", "value", "error"),
    [
        ("soak", "daemon_identity", {"pid": 123}, "daemon identity"),
        ("soak", "samples", [{"warmup_completed": True}], "measured sample"),
        ("soak", "hook", {"returncode": 0}, "hook invocation"),
        (
            "offline_after_prepare",
            "offline_daemon_identity",
            {"pid": 456},
            "daemon identity",
        ),
        ("soak", "faulting_hook", {"returncode": 0}, "hook invocation"),
    ],
    ids=[
        "daemon-ready",
        "warmup-or-measured-event",
        "hook-invocation",
        "offline-replay-daemon",
        "fault-action-hook",
    ],
)
def test_outcome_aware_override_rejects_any_premeasurement_activity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unit_name: str,
    field: str,
    value: Any,
    error: str,
) -> None:
    fixture = _create_outcome_aware_fixture(tmp_path, monkeypatch)
    result_path = fixture["predecessor"] / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result[unit_name][field] = value
    _write_json(result_path, result)
    _rebind_fixture_result_after_tamper(fixture)

    with pytest.raises(attempts.SystemsHarnessError, match=error):
        attempts.replacement_launch_binding(
            fixture["successor"], str(fixture["receipt_path"])
        )


def test_outcome_aware_override_recomputes_adjudication_instead_of_trusting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _create_outcome_aware_fixture(tmp_path, monkeypatch)
    adjudication_path = (
        fixture["evidence_root"] / "premeasurement-harness-adjudication.json"
    )
    adjudication = json.loads(adjudication_path.read_text(encoding="utf-8"))
    adjudication["result"]["matrix_samples"] = 1
    adjudication_path.write_text(
        json.dumps(adjudication, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    evidence_receipt = next(
        item
        for item in fixture["receipt"]["evidence_receipts"]
        if item["kind"] == "premeasurement_harness_adjudication"
    )
    evidence_receipt.update(_file_receipt(adjudication_path))
    _write_json(fixture["receipt_path"], fixture["receipt"])

    with pytest.raises(
        attempts.SystemsHarnessError,
        match="does not equal the recomputed r01 scan",
    ):
        attempts.replacement_launch_binding(
            fixture["successor"], str(fixture["receipt_path"])
        )


def test_outcome_aware_override_rejects_probe_tampering_even_when_rebound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _create_outcome_aware_fixture(tmp_path, monkeypatch)
    probe_path = fixture["evidence_root"] / "af-unix-socket-probe.json"
    probe = json.loads(probe_path.read_text(encoding="utf-8"))
    probe["rap_inference_started"] = True
    _write_json(probe_path, probe)
    evidence_receipt = next(
        item
        for item in fixture["receipt"]["evidence_receipts"]
        if item["kind"] == "af_unix_socket_probe"
    )
    evidence_receipt.update(_file_receipt(probe_path))
    _write_json(fixture["receipt_path"], fixture["receipt"])

    with pytest.raises(
        attempts.SystemsHarnessError,
        match="does not match its frozen receipt",
    ):
        attempts.replacement_launch_binding(
            fixture["successor"], str(fixture["receipt_path"])
        )


def test_outcome_aware_override_rejects_nonempty_verdict_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _create_outcome_aware_fixture(tmp_path, monkeypatch)
    database = next(fixture["predecessor"].rglob("verdicts.db"))
    connection = sqlite3.connect(database)
    try:
        connection.execute("INSERT INTO verdicts DEFAULT VALUES")
        connection.commit()
    finally:
        connection.close()
    fixture["receipt"]["predecessor_tree"] = attempts._predecessor_tree_receipts(
        fixture["predecessor"]
    )
    _write_json(fixture["receipt_path"], fixture["receipt"])

    with pytest.raises(
        attempts.SystemsHarnessError,
        match=(
            "tree aggregates do not match r01|"
            "verdict databases are not measurement-empty"
        ),
    ):
        attempts.replacement_launch_binding(
            fixture["successor"], str(fixture["receipt_path"])
        )


def test_outcome_aware_override_rejects_a_copied_publication_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _create_outcome_aware_fixture(tmp_path, monkeypatch)
    claim_path = Path(fixture["repair"]["publication_claim"]["path"])
    claim_bytes = claim_path.read_bytes()
    claim_path.unlink()
    claim_path.write_bytes(claim_bytes)

    with pytest.raises(
        attempts.SystemsHarnessError,
        match="not inode-identical",
    ):
        attempts.replacement_launch_binding(
            fixture["successor"], str(fixture["receipt_path"])
        )


def test_scheduler_adjudication_is_bound_to_predecessor_launch_job(
    tmp_path: Path,
) -> None:
    predecessor, successor = _predecessor(
        tmp_path,
        {"status": "incomplete_unclassified_failure"},
        slurm_job_id="12345",
    )
    sacct = tmp_path / "sacct.txt"
    scontrol = tmp_path / "scontrol.txt"
    stdout = tmp_path / "scheduler.stdout"
    stderr = tmp_path / "scheduler.stderr"
    stdout.write_text("predecessor stdout\n", encoding="utf-8")
    stderr.write_text("predecessor stderr\n", encoding="utf-8")

    def write_scheduler_evidence(job_id: str) -> list[tuple[str, Path]]:
        sacct.write_text(f"{job_id}|NODE_FAIL|1:0\n", encoding="utf-8")
        scontrol.write_text(
            f"JobId={job_id} JobState=NODE_FAIL ExitCode=1:0\n",
            encoding="utf-8",
        )
        return [
            ("scheduler_sacct", sacct),
            ("scheduler_scontrol", scontrol),
            ("scheduler_stdout", stdout),
            ("scheduler_stderr", stderr),
        ]

    def adjudication(job_id: str) -> dict[str, Any]:
        return {
            "scheduler_job_id": job_id,
            "state": "NODE_FAIL",
            "reason": "node failed outside the measured system",
            "exit_code": "1:0",
        }

    receipt_path = tmp_path / "replacement.json"
    mismatched = _replacement_receipt(
        predecessor,
        successor,
        classification="infrastructure_error",
        original_status="incomplete_unclassified_failure",
        evidence=write_scheduler_evidence("99999"),
        scheduler_adjudication=adjudication("99999"),
    )
    _write_json(receipt_path, mismatched)
    with pytest.raises(
        attempts.SystemsHarnessError,
        match="predecessor launch identity Slurm job_id",
    ):
        attempts.replacement_launch_binding(successor, str(receipt_path))

    matched = _replacement_receipt(
        predecessor,
        successor,
        classification="infrastructure_error",
        original_status="incomplete_unclassified_failure",
        evidence=write_scheduler_evidence("12345"),
        scheduler_adjudication=adjudication("12345"),
    )
    _write_json(receipt_path, matched)
    binding = attempts.replacement_launch_binding(successor, str(receipt_path))

    assert binding["scheduler_adjudication"] == adjudication("12345")
    assert set(binding) == {
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


def test_one_byte_label_cannot_reclassify_unclassified_as_harness(
    tmp_path: Path,
) -> None:
    predecessor, successor = _predecessor(
        tmp_path, {"status": "incomplete_unclassified_failure"}
    )
    evidence_path = tmp_path / "one-byte-assertion.bin"
    evidence_path.write_bytes(b"x")
    receipt = _replacement_receipt(
        predecessor,
        successor,
        classification="harness_error",
        original_status="incomplete_unclassified_failure",
        evidence=[("harness_assertion", evidence_path)],
    )
    receipt_path = tmp_path / "replacement.json"
    _write_json(receipt_path, receipt)

    with pytest.raises(attempts.SystemsHarnessError, match="not eligible"):
        attempts.replacement_launch_binding(successor, str(receipt_path))


def test_replacement_rejects_relative_evidence_paths(tmp_path: Path) -> None:
    predecessor, successor = _predecessor(
        tmp_path, {"status": "incomplete_harness_error"}
    )
    evidence_path = tmp_path / "harness-traceback.txt"
    evidence_path.write_text("proven runner assertion failure\n", encoding="utf-8")
    receipt = _replacement_receipt(
        predecessor,
        successor,
        classification="harness_error",
        original_status="incomplete_harness_error",
        evidence=[("harness_traceback", evidence_path)],
    )
    receipt["evidence_receipts"][0]["path"] = evidence_path.name
    receipt_path = tmp_path / "replacement.json"
    _write_json(receipt_path, receipt)

    with pytest.raises(attempts.SystemsHarnessError, match="exact absolute"):
        attempts.replacement_launch_binding(successor, str(receipt_path))


def test_formal_attempt_id_accepts_the_frozen_64_character_limit(
    tmp_path: Path,
) -> None:
    attempt_id = f"{'a' * 60}-r01"
    assert len(attempt_id) == 64
    binding = attempts.replacement_launch_binding(tmp_path / attempt_id, None)
    assert binding["successor_raw_attempt_id"] == attempt_id


def test_replacement_retention_limits_match_the_frozen_protocol() -> None:
    protocol = json.loads(PROTOCOL_AMENDMENT.read_text(encoding="utf-8"))
    chain = protocol["formal_attempt_retention"]["replacement_chain"]
    tree = chain["replacement_receipt_schema"]["predecessor_tree"]
    repair = protocol["outcome_aware_repair"]
    override = chain["outcome_aware_premeasurement_override"]
    implementation = attempts._OUTCOME_AWARE_REPAIR

    assert chain["max_raw_attempt_ordinal"] == attempts._MAX_FORMAL_ATTEMPT_ORDINAL
    assert protocol["formal_effective_config"]["study_mode"] in (
        attempts._FORMAL_STUDY_MODES
    )
    assert tree["max_entries"] == attempts._MAX_PREDECESSOR_TREE_ENTRIES
    assert (
        tree["max_regular_file_bytes"]
        == attempts._MAX_PREDECESSOR_TREE_REGULAR_BYTES
    )
    assert (
        tree["min_staging_free_reserve_bytes"]
        == attempts._MIN_STAGING_FREE_RESERVE_BYTES
    )
    assert implementation["predecessor_raw_attempt_id"] == repair[
        "predecessor_raw_attempt_id"
    ]
    assert implementation["successor_raw_attempt_id"] == repair[
        "successor_raw_attempt_id"
    ]
    assert implementation["receipt_overrides"] == override[
        "receipt_field_overrides"
    ]
    assert {
        name: implementation["launch"][name]
        for name in (
            "identity_sha256",
            "git_commit",
            "runner_sha256",
            "runner_git_blob",
            "slurm",
        )
    } == {
        "identity_sha256": repair["predecessor_launch"]["identity_sha256"],
        "git_commit": repair["predecessor_launch"]["git_commit"],
        "runner_sha256": repair["predecessor_launch"]["runner_sha256"],
        "runner_git_blob": repair["predecessor_launch"]["runner_git_blob"],
        "slurm": repair["predecessor_launch"]["slurm"],
    }
    assert implementation["launch"]["runtime_lock_sha256"] in "\n".join(
        protocol["known_before_freeze"]
    )
    assert implementation["core_artifacts"] == repair["core_artifacts"]
    assert implementation["publication_claim"] == {
        name: repair["publication_claim"][name]
        for name in ("path", "bytes", "sha256")
    }
    assert implementation["tree"] == {
        "entries_excluding_root": repair["predecessor_tree"][
            "entry_count_excluding_root"
        ],
        "regular_file_bytes": repair["predecessor_tree"][
            "regular_file_bytes"
        ],
        "type_counts": {
            "directory": repair["predecessor_tree"]["directory_count"],
            "regular_file": repair["predecessor_tree"]["regular_file_count"],
            "symlink": repair["predecessor_tree"]["symlink_count"],
            "socket": repair["predecessor_tree"]["socket_count"],
            "fifo": repair["predecessor_tree"]["fifo_count"],
            "other": 0,
        },
    }
    frozen_probe = protocol["required_before_freeze"][
        "external_all_partition_probe"
    ]
    implementation_probe = implementation["evidence"]["files"][
        "af_unix_socket_probe"
    ]
    assert (
        Path(implementation["evidence"]["root"]) / implementation_probe["name"]
        == Path(frozen_probe["evidence_path"])
    )
    assert implementation_probe["bytes"] == frozen_probe["evidence_bytes"]
    assert implementation_probe["sha256"] == frozen_probe["evidence_sha256"]


def test_prelaunch_copy_failure_does_not_strand_an_unidentifiable_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"bound evidence")
    good = {
        "source_path": str(source),
        "retained_path": "replacement/evidence.bin",
        "bytes": source.stat().st_size,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }

    invalid_root = tmp_path / "invalid-r01"
    invalid = {**good, "sha256": "0" * 64}
    with pytest.raises(attempts.SystemsHarnessError, match="before attempt creation"):
        attempts.AttemptRecorder(
            invalid_root, {"plan": [], "_prelaunch_copy_specs": [invalid]}
        )
    assert not invalid_root.exists()

    race_root = tmp_path / "race-r01"

    def changed_during_copy(*_args, **_kwargs):
        raise attempts.SystemsHarnessError("synthetic copy race")

    monkeypatch.setattr(attempts, "_exclusive_verified_copy", changed_during_copy)
    with pytest.raises(attempts.SystemsHarnessError, match="copy race"):
        attempts.AttemptRecorder(
            race_root, {"plan": [], "_prelaunch_copy_specs": [good]}
        )
    assert not race_root.exists()


def test_atomic_attempt_publication_never_replaces_a_racing_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt_root = tmp_path / "formal-r01"
    publish = attempts._rename_directory_noreplace

    def create_racing_destination(source: Path, destination: Path) -> None:
        destination.mkdir()
        publish(source, destination)

    monkeypatch.setattr(
        attempts, "_rename_directory_noreplace", create_racing_destination
    )
    with pytest.raises(attempts.SystemsHarnessError, match="already exists"):
        attempts.AttemptRecorder(attempt_root, {"plan": []})

    assert attempt_root.is_dir()
    assert list(attempt_root.iterdir()) == []


def test_native_publication_writes_the_exact_method_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt_root = tmp_path / "attempts" / "formal-r01"
    real_rename = attempts.os.rename

    def native_success(source: Path, destination: Path) -> str:
        real_rename(source, destination)
        return "renameat2_RENAME_NOREPLACE"

    monkeypatch.setattr(
        attempts, "_native_rename_directory_noreplace", native_success
    )

    attempts.AttemptRecorder(attempt_root, {"plan": []})

    publication = json.loads(
        (attempt_root / "publication.json").read_text(encoding="utf-8")
    )
    assert publication == {
        "schema_version": 1,
        "destination": str(attempt_root),
        "method": "native_no_replace",
        "native_primitive": "renameat2_RENAME_NOREPLACE",
        "native_unsupported": None,
        "claim": None,
    }


def _force_native_unsupported(
    monkeypatch: pytest.MonkeyPatch,
    *,
    error: int = errno.EINVAL,
) -> None:
    def unsupported(_source: Path, _destination: Path) -> str:
        raise attempts._NativeNoReplaceUnsupported(
            "renameat2_RENAME_NOREPLACE", error
        )

    monkeypatch.setattr(
        attempts, "_native_rename_directory_noreplace", unsupported
    )


def test_unsupported_native_publish_uses_persistent_launch_hardlink_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_unsupported(monkeypatch)
    attempt_root = tmp_path / "attempts" / "formal-r01"

    attempts.AttemptRecorder(attempt_root, {"plan": []})

    publication = json.loads(
        (attempt_root / "publication.json").read_text(encoding="utf-8")
    )
    claim_path = Path(publication["claim"]["path"])
    assert publication == {
        "schema_version": 1,
        "destination": str(attempt_root),
        "method": "hardlink_claim_then_posix_rename",
        "native_primitive": "renameat2_RENAME_NOREPLACE",
        "native_unsupported": {"errno": errno.EINVAL, "name": "EINVAL"},
        "claim": {
            "path": str(claim_path),
            "artifact": "launch.json",
            "bytes": (attempt_root / "launch.json").stat().st_size,
            "sha256": hashlib.sha256(
                (attempt_root / "launch.json").read_bytes()
            ).hexdigest(),
        },
    }
    assert claim_path == (
        tmp_path
        / ".attempts.staging"
        / ".publication-claims"
        / "formal-r01.launch.json"
    )
    assert claim_path.is_file()
    assert os.path.samestat(
        claim_path.stat(), (attempt_root / "launch.json").stat()
    )


def test_publication_receipt_is_written_and_fsynced_only_after_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_unsupported(monkeypatch)
    attempt_root = tmp_path / "attempts" / "formal-r01"
    publication_observed = False
    synced_directories: list[Path] = []
    real_json = attempts._exclusive_json
    real_fsync = attempts._fsync_directory

    def observe_json(path: Path, value: Any) -> None:
        nonlocal publication_observed
        if path.name == "publication.json":
            assert path.parent == attempt_root
            assert (attempt_root / "launch.json").is_file()
            publication_observed = True
        real_json(path, value)

    def observe_fsync(path: Path) -> None:
        synced_directories.append(path)
        real_fsync(path)

    monkeypatch.setattr(attempts, "_exclusive_json", observe_json)
    monkeypatch.setattr(attempts, "_fsync_directory", observe_fsync)

    attempts.AttemptRecorder(attempt_root, {"plan": []})

    assert publication_observed
    assert (attempt_root / "publication.json").is_file()
    assert attempt_root in synced_directories


def test_claim_persists_when_posix_rename_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_unsupported(monkeypatch)
    attempt_root = tmp_path / "attempts" / "formal-r01"

    def fail_rename(_source: Path, _destination: Path) -> None:
        raise OSError(5, "synthetic storage error")

    monkeypatch.setattr(attempts.os, "rename", fail_rename)
    with pytest.raises(
        attempts.SystemsHarnessError,
        match="could not atomically publish claimed attempt directory",
    ):
        attempts.AttemptRecorder(attempt_root, {"plan": []})

    claim_path = (
        tmp_path
        / ".attempts.staging"
        / ".publication-claims"
        / "formal-r01.launch.json"
    )
    assert claim_path.is_file()
    assert not attempt_root.exists()
    assert json.loads(claim_path.read_text(encoding="utf-8"))["plan"] == []


def test_duplicate_compliant_writer_loses_exclusive_publication_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_unsupported(monkeypatch)
    attempt_root = tmp_path / "attempts" / "formal-r01"
    real_rename = attempts.os.rename

    def leave_claim_without_publish(_source: Path, _destination: Path) -> None:
        raise OSError(5, "synthetic first-writer crash")

    monkeypatch.setattr(attempts.os, "rename", leave_claim_without_publish)
    with pytest.raises(attempts.SystemsHarnessError, match="claimed attempt"):
        attempts.AttemptRecorder(attempt_root, {"plan": []})
    claim_path = (
        tmp_path
        / ".attempts.staging"
        / ".publication-claims"
        / "formal-r01.launch.json"
    )
    first_identity = claim_path.stat()
    first_bytes = claim_path.read_bytes()

    monkeypatch.setattr(attempts.os, "rename", real_rename)
    with pytest.raises(
        attempts.SystemsHarnessError, match="publication claim already exists"
    ):
        attempts.AttemptRecorder(attempt_root, {"plan": [{"condition_id": "other"}]})

    assert claim_path.read_bytes() == first_bytes
    assert os.path.samestat(first_identity, claim_path.stat())
    assert not attempt_root.exists()


def test_racing_compliant_writers_have_exactly_one_claim_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_unsupported(monkeypatch)
    attempt_root = tmp_path / "attempts" / "formal-r01"
    claim_barrier = threading.Barrier(2)
    real_link = attempts.os.link

    def synchronize_claim_links(
        source: Path,
        destination: Path,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        if Path(destination).parent.name == ".publication-claims":
            claim_barrier.wait(timeout=5)
        real_link(
            source,
            destination,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(attempts.os, "link", synchronize_claim_links)
    outcomes: list[Exception | None] = []

    def publish(manifest: dict[str, Any]) -> None:
        try:
            attempts.AttemptRecorder(attempt_root, manifest)
        except Exception as exc:
            outcomes.append(exc)
        else:
            outcomes.append(None)

    writers = [
        threading.Thread(target=publish, args=({"plan": []},)),
        threading.Thread(
            target=publish,
            args=({"plan": [{"condition_id": "other"}]},),
        ),
    ]
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join(timeout=10)

    assert all(not writer.is_alive() for writer in writers)
    assert sum(outcome is None for outcome in outcomes) == 1
    loser = next(outcome for outcome in outcomes if outcome is not None)
    assert isinstance(loser, attempts.SystemsHarnessError)
    assert "publication claim already exists" in str(loser)
    publication = json.loads(
        (attempt_root / "publication.json").read_text(encoding="utf-8")
    )
    claim_path = Path(publication["claim"]["path"])
    assert os.path.samestat(
        claim_path.stat(), (attempt_root / "launch.json").stat()
    )


def test_nonunsupported_native_error_never_falls_back_to_posix_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempt_root = tmp_path / "attempts" / "formal-r01"
    posix_rename_called = False

    def fail_closed(_source: Path, _destination: Path) -> str:
        raise attempts.SystemsHarnessError("synthetic native EIO")

    def observe_posix_rename(_source: Path, _destination: Path) -> None:
        nonlocal posix_rename_called
        posix_rename_called = True

    monkeypatch.setattr(
        attempts, "_native_rename_directory_noreplace", fail_closed
    )
    monkeypatch.setattr(attempts.os, "rename", observe_posix_rename)

    with pytest.raises(attempts.SystemsHarnessError, match="native EIO"):
        attempts.AttemptRecorder(attempt_root, {"plan": []})

    assert not posix_rename_called
    assert not attempt_root.exists()
    assert not (
        tmp_path
        / ".attempts.staging"
        / ".publication-claims"
        / "formal-r01.launch.json"
    ).exists()


def test_burned_fallback_claim_blocks_later_native_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_unsupported(monkeypatch)
    attempt_root = tmp_path / "attempts" / "formal-r01"

    def fail_after_claim(_source: Path, _destination: Path) -> None:
        raise OSError(5, "synthetic post-claim failure")

    monkeypatch.setattr(attempts.os, "rename", fail_after_claim)
    with pytest.raises(attempts.SystemsHarnessError, match="claimed attempt"):
        attempts.AttemptRecorder(attempt_root, {"plan": []})

    native_called = False

    def unexpected_native(_source: Path, _destination: Path) -> str:
        nonlocal native_called
        native_called = True
        return "renameat2_RENAME_NOREPLACE"

    monkeypatch.setattr(
        attempts, "_native_rename_directory_noreplace", unexpected_native
    )
    with pytest.raises(
        attempts.SystemsHarnessError, match="publication claim already exists"
    ):
        attempts.AttemptRecorder(attempt_root, {"plan": []})

    assert not native_called
    assert not attempt_root.exists()


def test_fallback_requires_owner_exclusive_claim_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_unsupported(monkeypatch)
    attempt_root = tmp_path / "attempts" / "formal-r01"
    staging_root = tmp_path / ".attempts.staging"
    staging_root.mkdir(mode=0o700)
    claims_root = staging_root / ".publication-claims"
    claims_root.mkdir(mode=0o700)
    claims_root.chmod(0o755)

    with pytest.raises(attempts.SystemsHarnessError, match="mode 0700"):
        attempts.AttemptRecorder(attempt_root, {"plan": []})

    assert not attempt_root.exists()


def test_formal_attempt_root_must_be_owner_exclusive(tmp_path: Path) -> None:
    attempts_root = tmp_path / "attempts"
    attempts_root.mkdir(mode=0o700)
    attempts_root.chmod(0o755)

    with pytest.raises(attempts.SystemsHarnessError, match="mode 0700"):
        attempts.AttemptRecorder(
            attempts_root / "formal-r01",
            {"identity": {"study_mode": "formal"}, "plan": []},
        )


def test_amendment_007_formal_attempt_root_must_be_owner_exclusive(
    tmp_path: Path,
) -> None:
    attempts_root = tmp_path / "attempts"
    attempts_root.mkdir(mode=0o700)
    attempts_root.chmod(0o755)
    attempt_root = attempts_root / "formal-v3-r02"

    with pytest.raises(attempts.SystemsHarnessError, match="mode 0700"):
        attempts.AttemptRecorder(
            attempt_root,
            {
                "identity": {
                    "study_mode": "formal_protocol_v3_amendment_007"
                },
                "plan": [],
            },
        )

    assert not attempt_root.exists()


def test_deep_staged_copy_fsyncs_every_created_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"deep retained evidence")
    destination = tmp_path / "stage" / "one" / "two" / "three" / "value.bin"
    observed: list[Path] = []
    fsync = attempts._fsync_directory

    def record(path: Path) -> None:
        observed.append(path)
        fsync(path)

    monkeypatch.setattr(attempts, "_fsync_directory", record)
    attempts._exclusive_verified_copy(
        source,
        destination,
        expected_bytes=source.stat().st_size,
        expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )

    for directory in (
        destination.parent,
        destination.parent.parent,
        destination.parent.parent.parent,
        destination.parent.parent.parent.parent,
    ):
        assert directory in observed


def test_missing_result_node_failure_can_bind_a_stale_runtime_socket(
    tmp_path: Path,
) -> None:
    short_root = Path(tempfile.mkdtemp(prefix="rapsock-", dir="/private/tmp"))
    try:
        predecessor, successor = _predecessor(
            short_root,
            {"status": "incomplete_unclassified_failure"},
            slurm_job_id="12345",
        )
        (predecessor / "result.json").unlink()
        runtime = predecessor / "runtime"
        runtime.mkdir()
        special_path = runtime / "daemon.sock"
        special_type = "socket"
        daemon_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                daemon_socket.bind(str(special_path))
            except PermissionError:
                special_path = runtime / "daemon.fifo"
                special_type = "fifo"
                os.mkfifo(special_path)
        finally:
            daemon_socket.close()
        sacct = tmp_path / "sacct.txt"
        scontrol = tmp_path / "scontrol.txt"
        scheduler_stdout = tmp_path / "scheduler.stdout"
        scheduler_stderr = tmp_path / "scheduler.stderr"
        sacct.write_text("12345|NODE_FAIL|1:0\n", encoding="utf-8")
        scontrol.write_text(
            "JobId=12345 JobState=NODE_FAIL ExitCode=1:0\n", encoding="utf-8"
        )
        scheduler_stdout.write_text("node failed\n", encoding="utf-8")
        scheduler_stderr.write_text("node failed\n", encoding="utf-8")
        receipt = _replacement_receipt(
            predecessor,
            successor,
            classification="infrastructure_error",
            original_status="missing",
            evidence=[
                ("scheduler_sacct", sacct),
                ("scheduler_scontrol", scontrol),
                ("scheduler_stdout", scheduler_stdout),
                ("scheduler_stderr", scheduler_stderr),
            ],
            scheduler_adjudication={
                "scheduler_job_id": "12345",
                "state": "NODE_FAIL",
                "reason": "external node failure",
                "exit_code": "1:0",
            },
        )
        receipt_path = tmp_path / "replacement.json"
        _write_json(receipt_path, receipt)

        binding = attempts.replacement_launch_binding(successor, str(receipt_path))

        assert any(
            item["relative_path"] == f"runtime/{special_path.name}"
            and item["type"] == special_type
            and item["bytes"] is None
            and item["sha256"] is None
            for item in binding["predecessor_tree"]
        )
    finally:
        shutil.rmtree(short_root, ignore_errors=True)


def test_started_system_abort_is_counted_once_in_the_unit_ledger(
    tmp_path: Path,
) -> None:
    recorder = attempts.AttemptRecorder(
        tmp_path / "started-abort",
        {"plan": [{"condition_id": "started"}, {"condition_id": "not-started"}]},
    )
    recorder.record("matrix", "started", "started", {"phase": "started"})

    result = recorder.finalize(
        {
            "status": "incomplete_unclassified_failure",
            "primary_numeric_eligible": False,
            "abort": {"status": "system_violation"},
        }
    )

    assert result["system_violation_units"] == 1
    assert result["abort_system_violation"] is True
    assert result["unit_status_histogram"] == {
        "not_started_after_abort": 1,
        "system_violation": 1,
    }


def test_post_terminal_system_abort_remains_a_separate_flag(
    tmp_path: Path,
) -> None:
    recorder = attempts.AttemptRecorder(
        tmp_path / "post-terminal-abort",
        {"plan": [{"condition_id": "done"}]},
    )
    recorder.record("matrix", "done", "started", {"phase": "started"})
    recorder.record("matrix", "done", "terminal", {"status": "completed"})

    result = recorder.finalize(
        {
            "status": "incomplete_unclassified_failure",
            "primary_numeric_eligible": False,
            "abort": {
                "status": "unclassified_failure",
                "original_abort_classification": {
                    "status": "system_violation"
                },
            },
        }
    )

    assert result["system_violation_units"] == 0
    assert result["abort_system_violation"] is True
    assert result["unit_status_histogram"] == {"completed": 1}
