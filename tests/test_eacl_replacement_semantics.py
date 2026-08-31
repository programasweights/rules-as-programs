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


def test_component_pending_scan_matches_only_exact_scalar_placeholders():
    value = {
        "ordinary": "prefix PENDING_TERMINAL_VALUE suffix",
        "PENDING_TERMINAL_KEY": "resolved",
        "placeholder": "PENDING_TERMINAL_VALUE",
        "metadata_prefix": "PENDING_TERMINAL_",
    }

    assert attempts._pending_terminal_markers(value) == ["PENDING_TERMINAL_VALUE"]


def test_component_successor_binding_requires_pushed_exact_h4_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p4 = "1" * 40
    i4 = "2" * 40
    h4 = "3" * 40
    h3 = "4" * 40
    paths = {
        "protocol": ["protocol.json"],
        "implementation": ["runner.py"],
        "runtime_lock": ["runtime-lock.json"],
    }
    for relative in [item for group in paths.values() for item in group]:
        (tmp_path / relative).write_text(f"{relative}\n", encoding="utf-8")
    amendment = {
        "effective_protocol_identity": {
            "required_git_topology": {
                "p4": {"parent_must_equal": h3, "diff_paths_exactly": paths["protocol"]},
                "i4": {
                    "parent_must_equal_p4": True,
                    "diff_paths_exactly": paths["implementation"],
                },
                "h4": {
                    "parent_must_equal_i4": True,
                    "diff_paths_exactly": paths["runtime_lock"],
                },
                "head_must_equal_h4_before_r03_setup": True,
            }
        }
    }
    parents = {h4: i4, i4: p4, p4: h3}

    def git_text(*args: str) -> str:
        if args == ("rev-parse", "HEAD"):
            return h4
        if args[:3] == ("rev-list", "--parents", "-n"):
            commit = args[-1]
            return f"{commit} {parents[commit]}"
        if args[0] == "diff-tree":
            commit = args[-1]
            group = {p4: "protocol", i4: "implementation", h4: "runtime_lock"}[
                commit
            ]
            return "\n".join(paths[group])
        if args[0] == "for-each-ref":
            return "refs/remotes/origin/formal-h4"
        if args[:1] == ("rev-parse",) and ":" in args[-1]:
            relative = args[-1].split(":", 1)[1]
            return attempts._git_blob_sha1((tmp_path / relative).read_bytes())
        raise AssertionError(args)

    monkeypatch.setattr(attempts, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(attempts, "_git_text", git_text)

    binding = attempts.component_successor_source_binding(amendment)
    assert binding["protocol_commit"] == p4
    assert binding["implementation_commit"] == i4
    assert binding["runtime_lock_commit"] == h4
    assert [item["path"] for item in binding["tracked_files"]] == [
        "protocol.json",
        "runner.py",
        "runtime-lock.json",
    ]

    def unpushed_git_text(*args: str) -> str:
        if args[0] == "for-each-ref":
            return ""
        return git_text(*args)

    monkeypatch.setattr(attempts, "_git_text", unpushed_git_text)
    with pytest.raises(attempts.SystemsHarnessError, match="pushed remote ref"):
        attempts.component_successor_source_binding(amendment)


def test_exact_whole_attempt_override_preserves_raw_r02_partial_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_result = {"status": "incomplete_unclassified_failure"}
    predecessor, _unused = _predecessor(tmp_path, original_result)
    exact_predecessor = predecessor.with_name(attempts._COMPONENT_PREDECESSOR_ID)
    predecessor.rename(exact_predecessor)
    (exact_predecessor / "result.json").unlink()
    successor = exact_predecessor.with_name(attempts._COMPONENT_SUCCESSOR_ID)
    evidence_root = tmp_path / "component-evidence"
    evidence_root.mkdir()
    evidence = []
    for kind in sorted(attempts._COMPONENT_REQUIRED_EVIDENCE):
        path = evidence_root / f"{kind}.txt"
        path.write_text(f"{kind}\n", encoding="utf-8")
        evidence.append((kind, path))
    receipt = _replacement_receipt(
        exact_predecessor,
        successor,
        classification=attempts._COMPONENT_CLASSIFICATION,
        original_status="missing",
        evidence=evidence,
    )
    receipt.update(
        {
            "schema_version": 2,
            "successor_source": {"external": "p4-i4-h4"},
            "whole_attempt_protocol_correction": {"source": "r03-full-430"},
        }
    )
    receipt_path = tmp_path / "replacement.json"
    _write_json(receipt_path, receipt)
    before = attempts._predecessor_tree_receipts(exact_predecessor)
    observed: dict[str, Any] = {}

    def validate_component(**kwargs: Any) -> dict[str, Any]:
        observed.update(kwargs)
        return {"raw_partial_preserved": True}

    monkeypatch.setattr(
        attempts, "_validate_whole_attempt_protocol_correction", validate_component
    )

    binding = attempts.replacement_launch_binding(successor, str(receipt_path))

    assert binding["classification"] == attempts._COMPONENT_CLASSIFICATION
    assert binding["original_status"] == "missing"
    assert binding["successor_source"] == receipt["successor_source"]
    assert observed["predecessor_root"] == exact_predecessor
    assert binding["r02_partial_terminal_forensics"] == {
        "raw_partial_preserved": True
    }
    assert attempts._predecessor_tree_receipts(exact_predecessor) == before

    wrong_edge = successor.with_name("formal-v3-20260831t051023z-r04")
    wrong_receipt = dict(receipt)
    wrong_receipt.update(
        {
            "schema_version": 1,
            "successor_raw_attempt_id": wrong_edge.name,
            "predecessor_raw_attempt_id": successor.name,
        }
    )
    wrong_receipt.pop("successor_source")
    wrong_receipt.pop("whole_attempt_protocol_correction")
    _write_json(receipt_path, wrong_receipt)
    with pytest.raises(attempts.SystemsHarnessError, match="not permitted"):
        attempts.replacement_launch_binding(wrong_edge, str(receipt_path))


def test_canary_validator_accepts_extra_import_activations_but_requires_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inner_pid = 2001
    worker_pid = 2002
    marker = "rap-eacl-paw-cache-canary-v4-network-guard-v2"
    job_id = "123"
    stem = f"rap-eacl-paw-cache-canary-v4-{job_id}"
    archive_parent = tmp_path / "scheduler" / "canary-v4"
    archive_parent.mkdir(parents=True)
    archive_root = archive_parent / "20260831T120000Z-999"
    archive_root.mkdir()
    monkeypatch.setattr(
        attempts, "_COMPONENT_CANARY_ARCHIVE_PARENT", archive_parent
    )
    canary_script = tmp_path / "rap-eacl-paw-cache-canary-v4.py"
    launcher_script = tmp_path / "run-rap-eacl-paw-cache-canary-v4.sh"
    canary_script.write_bytes(b"#!/usr/bin/env python3\n")
    launcher_script.write_bytes(b"#!/bin/bash\n")

    def activation(purpose: str, pid: int, parent_pid: int) -> dict[str, Any]:
        return {
            "guard_marker": marker,
            "purpose": purpose,
            "pid": pid,
            "parent_pid": parent_pid,
            "sys_executable": "/tmp/canary/venv/bin/python",
            "all_identity_checks_passed": True,
            "identity_checks": {"socket.socket": True, "_socket.socket": True},
            "time_ns": 1,
            "monotonic_ns": 1,
        }

    raw_activations = [
        activation("bootstrap-pip", 1001, 1),
        activation("bootstrap-pip:wrapper", 1001, 1),
        activation("install-pip", 1002, 1),
        activation("install-pip:wrapper", 1002, 1),
        activation("freeze-pip", 1003, 1),
        activation("freeze-pip:wrapper", 1003, 1),
        activation("inner-runtime", inner_pid, 1),
        activation("inner-runtime:inner", inner_pid, 1),
        activation("inner-runtime", worker_pid, inner_pid),
    ]
    activation_raw = b"".join(
        attempts._canonical_json_bytes(value) + b"\n" for value in raw_activations
    )
    activations = [
        {"sequence": sequence, **value}
        for sequence, value in enumerate(raw_activations)
    ]
    programs = [
        {"program_id": f"program-{index}", "rule_id": f"rule-{index}"}
        for index in range(8)
    ]
    declared = [
        {
            "program_id": item["program_id"],
            "rule_id": item["rule_id"],
            "case_id": f"case-{index}",
            "expected": "WARNING",
            "input_utf8_bytes": 4,
            "input_sha256": f"{index + 1:064x}",
            "raw_output_utf8_bytes": 2,
            "raw_output_utf8_sha256": f"{index + 11:064x}",
            "severity": "OK",
            "timed_out": False,
            "worker_generation": 1,
            "worker_pid": worker_pid,
        }
        for index, item in enumerate(programs)
    ]
    calls = [
        {
            "sequence": index,
            "program_id": item["program_id"],
            "rule_id": item["rule_id"],
            "case_id": declared[index]["case_id"],
            "frozen_expected": "WARNING",
            "input_utf8_bytes": 4,
            "input_utf8_sha256": declared[index]["input_sha256"],
            "raw_output_utf8_bytes": 2,
            "raw_output_utf8_sha256": declared[index]["raw_output_utf8_sha256"],
            "normalized_output": "OK",
            "timed_out": False,
            "generation_before": 1,
            "generation_after": 1,
            "worker_pid": worker_pid,
            "worker_last_error": "",
        }
        for index, item in enumerate(programs)
    ]
    empty_diff = {"added": [], "deleted": [], "changed": []}

    def inventory(root: str, *, device: int, inode: int) -> dict[str, Any]:
        entries = [
            {
                "path": ".",
                "type": "directory",
                "mode": 0o700,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "dev": device,
                "inode": inode,
                "nlink": 2,
                "mtime_ns": 1,
                "ctime_ns": 1,
            },
            {
                "path": "runtimes/qwen3-0.6b-q6_k.json",
                "type": "regular",
                "mode": 0o600,
                "uid": os.geteuid(),
                "gid": os.getegid(),
                "dev": device,
                "inode": inode + 1,
                "nlink": 1,
                "mtime_ns": 1,
                "ctime_ns": 1,
                "bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            },
        ]
        content = [
            {key: entry[key] for key in ("path", "type", "mode", "bytes", "sha256") if key in entry}
            for entry in entries
        ]
        files = [
            {
                "path": entries[1]["path"],
                "bytes": entries[1]["bytes"],
                "sha256": entries[1]["sha256"],
            }
        ]
        return {
            "root": root,
            "root_entry": entries[0],
            "entries": entries,
            "strict_temporal_entries": entries,
            "strict_temporal_sha256": hashlib.sha256(
                attempts._canonical_json_bytes(entries)
            ).hexdigest(),
            "content_equivalence_entries": content,
            "content_equivalence_sha256": hashlib.sha256(
                attempts._canonical_json_bytes(content)
            ).hexdigest(),
            "content_files": files,
            "content_sha256": hashlib.sha256(
                attempts._canonical_json_bytes(files)
            ).hexdigest(),
            "file_count": 1,
            "total_bytes": 2,
            "tmp_entries": [],
        }

    source_inventory = inventory("/u4/source-cache", device=1, inode=10)
    copied_inventory = inventory("/tmp/canary/cache", device=2, inode=20)
    receipt = {
        "schema_version": 1,
        "canary": "rap-eacl-paw-cache-canary-v4",
        "status": "passed",
        "started_at_utc": "2026-08-31T00:00:01.000001Z",
        "ended_at_utc": "2026-08-31T00:00:04.000001Z",
        "receipt_directory": {
            "path": str(archive_root),
            "owner_uid": os.geteuid(),
            "mode": 0o700,
        },
        "scheduler": {
            "job_id": job_id,
            "hostname": "watgpu808",
            "environment": {
                "SLURM_JOB_ID": job_id,
                "SLURM_JOB_PARTITION": "ALL",
                "SLURM_JOB_NODELIST": "watgpu808",
                "SLURM_CPUS_PER_TASK": "8",
                "SLURM_MEM_PER_NODE": "16G",
                "SLURM_MEM_PER_CPU": None,
                "SLURM_JOB_GPUS": None,
                "SLURM_STEP_GPUS": None,
                "SLURM_GPUS": None,
                "SLURM_GPUS_ON_NODE": None,
                "CUDA_VISIBLE_DEVICES": "",
                "PAW_GPU_LAYERS": "0",
            },
            "affinity": list(range(8)),
            "memory_mib": 16 * 1024,
        },
        "inner": {
            "status": "passed",
            "started_at_utc": "2026-08-31T00:00:02.000001Z",
            "ended_at_utc": "2026-08-31T00:00:03.000001Z",
            "environment": {"process_pid": inner_pid},
            "worker": {"stable_pid_before_shutdown": worker_pid, "stable_generation": 1},
            "calls": calls,
            "network_guard_activation": raw_activations[7],
            "cache_before": copied_inventory,
            "cache_after": copy.deepcopy(copied_inventory),
            "cache_postrun_proof": {
                "content_equivalence_diff": empty_diff,
                "strict_temporal_diff": empty_diff,
                "content_equivalence_unchanged": True,
                "strict_temporal_unchanged": True,
                "permitted_runtime_manifest_metadata_rewrite": None,
                "permitted_rewrite_observed": False,
                "permitted_changed_fields": ["ctime_ns", "mtime_ns"],
            },
        },
        "preregistered_contract": {"source_cache_root": "/u4/source-cache"},
        "network": {
            "guard_activation_proof": {
                "guard_marker": marker,
                "activation_count": len(activations),
                "all_identity_checks_passed": True,
                "all_activations": activations,
                "inner_explicit_activation": activations[7],
                "spawned_inference_worker_activations": [activations[8]],
            }
        },
        "source_cache": {
            "before": source_inventory,
            "before_owner": {
                "expected_uid": os.geteuid(),
                "expected_gid": os.getegid(),
                "root_uid": os.geteuid(),
                "root_gid": os.getegid(),
                "checked_entry_count": len(source_inventory["entries"]),
                "all_entries_owned_by_effective_uid_gid": True,
            },
            "after": copy.deepcopy(source_inventory),
            "postrun_proof": {
                "strict_temporal_diff": empty_diff,
                "strict_temporal_sha256_before": source_inventory[
                    "strict_temporal_sha256"
                ],
                "strict_temporal_sha256_after": source_inventory[
                    "strict_temporal_sha256"
                ],
                "content_equivalence_diff": empty_diff,
                "unchanged_exactly_excluding_atime": True,
                "zero_tmp_entries": True,
                "after_owner": {
                    "expected_uid": os.geteuid(),
                    "expected_gid": os.getegid(),
                    "root_uid": os.geteuid(),
                    "root_gid": os.getegid(),
                    "checked_entry_count": len(source_inventory["entries"]),
                    "all_entries_owned_by_effective_uid_gid": True,
                },
            },
        },
        "copy_independence": {
            "same_content": True,
            "content_equivalence_diff": empty_diff,
            "content_equivalence_sha256": copied_inventory[
                "content_equivalence_sha256"
            ],
            "source_aliases": [],
            "destination_files_with_multiple_links": [],
            "all_destination_regular_file_link_counts_equal_one": True,
            "destination_owner": {
                "expected_uid": os.geteuid(),
                "expected_gid": os.getegid(),
                "root_uid": os.geteuid(),
                "root_gid": os.getegid(),
                "checked_entry_count": len(copied_inventory["entries"]),
                "all_entries_owned_by_effective_uid_gid": True,
            },
        },
        "copy_durability": {
            "regular_file_count": 1,
            "directory_count": 1,
            "files_fsynced_after_final_copystat": True,
            "directories_fsynced_bottom_up": True,
            "parent_directory_fsynced": True,
        },
        "node_local": {"copied_cache": "/tmp/canary/cache"},
        "log_anchors": {},
    }
    scontrol_raw = (
        f"JobId={job_id} JobName=rap-paw-cache-canary-v4 JobState=RUNNING "
        "Partition=ALL NodeList=watgpu808 NumCPUs=8 MinMemoryNode=16G "
        "AllocTRES=cpu=8,mem=16G,node=1,billing=8 TimeLimit=00:30:00"
    )
    receipt["scheduler"].update(
        {
            "scontrol_selected": {
                "JobId": job_id,
                "JobState": "RUNNING",
                "Partition": "ALL",
                "NodeList": "watgpu808",
                "NumCPUs": "8",
                "MinMemoryNode": "16G",
                "AllocTRES": "cpu=8,mem=16G,node=1,billing=8",
                "TimeLimit": "00:30:00",
            },
            "scontrol_raw": scontrol_raw,
            "scontrol_raw_sha256": hashlib.sha256(
                scontrol_raw.encode()
            ).hexdigest(),
        }
    )
    receipt["script"] = {
        "path": str(canary_script),
        "resolved_path": str(canary_script),
        "bytes": canary_script.stat().st_size,
        "mode": canary_script.stat().st_mode & 0o777,
        "sha256": hashlib.sha256(canary_script.read_bytes()).hexdigest(),
    }
    evidence_path = archive_root / f"{stem}.json"
    binding = {
        "job_id": job_id,
        "worker_generation": 1,
        "worker_pid": worker_pid,
        "program_results_in_exact_order": declared,
        "network_guard_marker": marker,
        "network_guard_activation_count": len(activations),
        "network_guard_activation_log_bytes": len(activation_raw),
        "network_guard_activation_log_sha256": hashlib.sha256(activation_raw).hexdigest(),
        "guarded_pip_wrapper_activation_count": 3,
        "guarded_pip_wrapper_identities_passed": True,
        "inner_guard_identity_passed": True,
        "spawned_worker_guard_identity_passed": True,
        "copy_added_file_count": 0,
        "copy_removed_file_count": 0,
        "copy_changed_file_count": 0,
        "copy_tmp_file_count": 0,
        "copy_inventory_before_sha256": copied_inventory["strict_temporal_sha256"],
        "copy_inventory_after_sha256": copied_inventory["strict_temporal_sha256"],
        "source_inventory_before_sha256": source_inventory[
            "strict_temporal_sha256"
        ],
        "source_inventory_after_sha256": source_inventory[
            "strict_temporal_sha256"
        ],
        "node_local_cache_root": "/tmp/canary/cache",
        "launcher_exit_status": 0,
        "srun_exit_status": 0,
        "postrun_sacct_exit_status": 0,
        "postrun_sacct_attempts": 2,
    }
    canary_script_sha256 = hashlib.sha256(canary_script.read_bytes()).hexdigest()
    launcher_script_sha256 = hashlib.sha256(launcher_script.read_bytes()).hexdigest()
    amendment = {
        "all_partition_canary": {
            "partition_exact": "ALL",
            "node_exact": "watgpu808",
            "source_cache_root_exact": "/u4/source-cache",
            "ordered_programs_exact": programs,
            "sealed_archive_contract": {
                "manifest_member_templates_exactly": list(
                    attempts._COMPONENT_CANARY_ARCHIVE_MEMBER_TEMPLATES
                )
            },
            "canary_script": {
                "remote_path": str(canary_script),
                "sha256": canary_script_sha256,
            },
            "launcher_script": {
                "remote_path": str(launcher_script),
                "sha256": launcher_script_sha256,
            },
        },
        "pending_terminal_bindings": {
            "r02": {
                "slurm_partition": "ALL",
                "slurm_terminal_state": "FAILED",
                "slurm_exit_code": "5:0",
                "slurm_node_list": "watgpu108",
            }
        },
    }
    top_evidence_path = archive_root / "evidence.sha256.sha256"
    evidence: dict[str, Any] = {
        "kind": "all_partition_paw_cache_canary",
        "path": str(top_evidence_path),
    }

    log_names = {
        "setup_stdout": f"{stem}.setup.stdout.log",
        "setup_stderr": f"{stem}.setup.stderr.log",
        "inner_stdout": f"{stem}.inner.stdout.log",
        "inner_stderr": f"{stem}.inner.stderr.log",
        "network": f"{stem}.network.jsonl",
        "guard_activations": f"{stem}.guard-activations.jsonl",
    }

    def seal_archive() -> None:
        archive_root.chmod(0o700)
        for child in archive_root.iterdir():
            child.chmod(0o600)

        log_payloads = {
            "setup_stdout": b"setup output\n",
            "setup_stderr": b"",
            "inner_stdout": b"inner output\n",
            "inner_stderr": b"",
            "network": b"",
            "guard_activations": activation_raw,
        }
        anchors: dict[str, Any] = {}
        for anchor_name, member_name in log_names.items():
            member = archive_root / member_name
            member.write_bytes(log_payloads[anchor_name])
            member.chmod(0o444)
            anchors[anchor_name] = {
                "path": str(member),
                "resolved_path": str(member),
                "bytes": member.stat().st_size,
                "mode": 0o444,
                "sha256": hashlib.sha256(member.read_bytes()).hexdigest(),
            }
        receipt["log_anchors"] = anchors
        receipt.pop("canonical_evidence_sha256", None)
        receipt["canonical_evidence_sha256"] = hashlib.sha256(
            attempts._canonical_json_bytes(receipt)
        ).hexdigest()
        rendered_receipt = attempts._canonical_json_bytes(receipt) + b"\n"
        evidence_path.write_bytes(rendered_receipt)
        evidence_path.chmod(0o444)
        receipt_sha256 = hashlib.sha256(rendered_receipt).hexdigest()
        receipt_sidecar = archive_root / f"{stem}.json.sha256"
        receipt_sidecar.write_bytes(
            f"{receipt_sha256}  {evidence_path.name}\n".encode()
        )
        receipt_sidecar.chmod(0o444)

        postrun_row = [
            job_id,
            "rap-paw-cache-canary-v4",
            "ALL",
            "COMPLETED",
            "0:0",
            "10",
            "2026-08-31T00:00:00",
            "2026-08-31T00:00:05",
            "watgpu808",
            "8",
            "16Gn",
            "cpu=8,mem=16G,node=1,billing=8",
            "",
            "",
        ]
        r02_row = [
            "1524523",
            "rap-eacl-systems-v3",
            "ALL",
            "FAILED",
            "5:0",
            "100",
            "2026-08-30T00:00:00",
            "2026-08-31T00:00:00",
            "watgpu108",
        ]
        task_summary = {
            "status": "passed",
            "receipt": str(evidence_path),
            "receipt_sha256": receipt_sha256,
            "sha256_sidecar": str(receipt_sidecar),
        }
        fixed_payloads = {
            "archive-ended-at-utc.txt": b"2026-08-31T00:00:05Z\n",
            "canary-script.sha256": (
                f"{canary_script_sha256}  {canary_script}\n".encode()
            ),
            "launch-started-at-utc.txt": b"2026-08-31T00:00:00Z\n",
            "launcher-script.sha256": (
                f"{launcher_script_sha256}  {launcher_script}\n".encode()
            ),
            "launcher.exit-status.txt": b"0\n",
            "postrun-sacct.attempts.txt": b"2\n",
            "postrun-sacct.exit-status.txt": b"0\n",
            "postrun-sacct.stderr.log": b"",
            "postrun-sacct.txt": ("|".join(postrun_row) + "\n").encode(),
            "r02-terminal-sacct.stderr.log": b"",
            "r02-terminal-sacct.txt": ("|".join(r02_row) + "\n").encode(),
            "required-terminal-r02-job-id.txt": b"1524523\n",
            "slurm-job-id.txt": f"{job_id}\n".encode(),
            "srun-client.stderr.log": b"",
            "srun-client.stdout.log": f"{job_id}\n".encode(),
            f"srun-task-{job_id}.stderr.log": b"",
            f"srun-task-{job_id}.stdout.log": (
                json.dumps(task_summary, sort_keys=True).encode() + b"\n"
            ),
            "srun.exit-status.txt": b"0\n",
        }
        for member_name, payload in fixed_payloads.items():
            member = archive_root / member_name
            member.write_bytes(payload)
            member.chmod(0o444)

        expanded = {
            name.replace("<job_id>", job_id)
            for name in attempts._COMPONENT_CANARY_ARCHIVE_MEMBER_TEMPLATES
        }
        assert {
            path.name
            for path in archive_root.iterdir()
            if path.name not in {"evidence.sha256", "evidence.sha256.sha256"}
        } == expanded
        manifest_path = archive_root / "evidence.sha256"
        member_paths = sorted(
            (archive_root / name for name in expanded),
            key=lambda item: os.fsencode(str(item)),
        )
        manifest_raw = b"".join(
            f"{hashlib.sha256(member.read_bytes()).hexdigest()}  {member}\n".encode()
            for member in member_paths
        )
        manifest_path.write_bytes(manifest_raw)
        manifest_path.chmod(0o444)
        manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        top_evidence_path.write_bytes(
            f"{manifest_sha256}  {manifest_path}\n".encode()
        )
        top_evidence_path.chmod(0o444)
        binding.update(
            {
                "archive_root": str(archive_root),
                "archive_manifest_path": str(manifest_path),
                "archive_manifest_bytes": len(manifest_raw),
                "archive_manifest_sha256": manifest_sha256,
                "canary_receipt_path": str(evidence_path),
                "canary_receipt_bytes": len(rendered_receipt),
                "canary_receipt_sha256": receipt_sha256,
                "evidence_path": str(top_evidence_path),
                "evidence_bytes": top_evidence_path.stat().st_size,
                "evidence_sha256": hashlib.sha256(
                    top_evidence_path.read_bytes()
                ).hexdigest(),
            }
        )
        evidence.update(
            {
                "bytes": binding["evidence_bytes"],
                "sha256": binding["evidence_sha256"],
            }
        )
        for child in archive_root.iterdir():
            child.chmod(0o444)
        archive_root.chmod(0o500)

    seal_archive()

    attempts._validate_all_partition_canary_receipt(
        amendment=amendment,
        binding=binding,
        evidence_receipt=evidence,
    )

    missing_member = archive_root / "srun-client.stderr.log"
    archive_root.chmod(0o700)
    missing_member.unlink()
    archive_root.chmod(0o500)
    with pytest.raises(attempts.SystemsHarnessError, match="member set"):
        attempts._validate_all_partition_canary_receipt(
            amendment=amendment,
            binding=binding,
            evidence_receipt=evidence,
        )
    seal_archive()

    tampered_member = archive_root / "srun-client.stdout.log"
    archive_root.chmod(0o700)
    tampered_member.chmod(0o600)
    tampered_member.write_bytes(b"tampered\n")
    tampered_member.chmod(0o444)
    archive_root.chmod(0o500)
    with pytest.raises(attempts.SystemsHarnessError, match="member digest"):
        attempts._validate_all_partition_canary_receipt(
            amendment=amendment,
            binding=binding,
            evidence_receipt=evidence,
        )
    seal_archive()

    copied_regular = receipt["inner"]["cache_before"]["entries"][1]
    copied_after_regular = receipt["inner"]["cache_after"]["entries"][1]
    original_copy_identity = (copied_regular["dev"], copied_regular["inode"])
    copied_regular["dev"] = source_inventory["entries"][1]["dev"]
    copied_regular["inode"] = source_inventory["entries"][1]["inode"]
    copied_after_regular["dev"] = copied_regular["dev"]
    copied_after_regular["inode"] = copied_regular["inode"]
    copied_before = receipt["inner"]["cache_before"]
    copied_after = receipt["inner"]["cache_after"]
    copied_before["strict_temporal_sha256"] = hashlib.sha256(
        attempts._canonical_json_bytes(copied_before["entries"])
    ).hexdigest()
    copied_after["strict_temporal_sha256"] = hashlib.sha256(
        attempts._canonical_json_bytes(copied_after["entries"])
    ).hexdigest()
    binding["copy_inventory_before_sha256"] = copied_before[
        "strict_temporal_sha256"
    ]
    binding["copy_inventory_after_sha256"] = copied_after[
        "strict_temporal_sha256"
    ]
    seal_archive()
    with pytest.raises(
        attempts.SystemsHarnessError, match="initial source/copy equivalence"
    ):
        attempts._validate_all_partition_canary_receipt(
            amendment=amendment,
            binding=binding,
            evidence_receipt=evidence,
        )

    copied_regular["dev"], copied_regular["inode"] = original_copy_identity
    copied_after_regular["dev"], copied_after_regular["inode"] = original_copy_identity
    copied_before["strict_temporal_sha256"] = hashlib.sha256(
        attempts._canonical_json_bytes(copied_before["entries"])
    ).hexdigest()
    copied_after["strict_temporal_sha256"] = hashlib.sha256(
        attempts._canonical_json_bytes(copied_after["entries"])
    ).hexdigest()
    binding["copy_inventory_before_sha256"] = copied_before[
        "strict_temporal_sha256"
    ]
    binding["copy_inventory_after_sha256"] = copied_after[
        "strict_temporal_sha256"
    ]

    copied_after_regular["mtime_ns"] = 2
    copied_after["strict_temporal_sha256"] = hashlib.sha256(
        attempts._canonical_json_bytes(copied_after["entries"])
    ).hexdigest()
    binding["copy_inventory_after_sha256"] = copied_after[
        "strict_temporal_sha256"
    ]
    seal_archive()
    with pytest.raises(
        attempts.SystemsHarnessError, match="diff is not independently derived"
    ):
        attempts._validate_all_partition_canary_receipt(
            amendment=amendment,
            binding=binding,
            evidence_receipt=evidence,
        )

    temporal_change = {
        "path": "runtimes/qwen3-0.6b-q6_k.json",
        "before": dict(copied_regular),
        "after": dict(copied_after_regular),
    }
    cache_proof = receipt["inner"]["cache_postrun_proof"]
    cache_proof["strict_temporal_diff"] = {
        "added": [],
        "deleted": [],
        "changed": [temporal_change],
    }
    cache_proof["strict_temporal_unchanged"] = False
    cache_proof["permitted_runtime_manifest_metadata_rewrite"] = {
        "path": temporal_change["path"],
        "changed_fields": ["mtime_ns"],
        "before": temporal_change["before"],
        "after": temporal_change["after"],
        "content_bytes_and_sha256_unchanged": True,
    }
    cache_proof["permitted_rewrite_observed"] = True
    seal_archive()
    attempts._validate_all_partition_canary_receipt(
        amendment=amendment,
        binding=binding,
        evidence_receipt=evidence,
    )

    worker_line = raw_activations.pop()
    assert worker_line["pid"] == worker_pid
    activation_raw = b"".join(
        attempts._canonical_json_bytes(value) + b"\n" for value in raw_activations
    )
    activations = [
        {"sequence": sequence, **value}
        for sequence, value in enumerate(raw_activations)
    ]
    activation_hash = hashlib.sha256(activation_raw).hexdigest()
    binding["network_guard_activation_count"] = len(activations)
    binding["network_guard_activation_log_bytes"] = len(activation_raw)
    binding["network_guard_activation_log_sha256"] = activation_hash
    receipt["log_anchors"]["guard_activations"].update(
        {"bytes": len(activation_raw), "sha256": activation_hash}
    )
    proof = receipt["network"]["guard_activation_proof"]
    proof["activation_count"] = len(activations)
    proof["all_activations"] = activations
    proof["inner_explicit_activation"] = activations[7]
    proof["spawned_inference_worker_activations"] = []
    seal_archive()
    with pytest.raises(attempts.SystemsHarnessError, match="inner/spawned-worker"):
        attempts._validate_all_partition_canary_receipt(
            amendment=amendment,
            binding=binding,
            evidence_receipt=evidence,
        )


@pytest.mark.parametrize(
    ("component", "payload"),
    [
        (
            "matrix",
            {
                "samples": [{}],
                "accounting": {"evaluations_expected": 1},
                "daemon_identity": {"paw": True},
                "incremental_evidence": {"journal_progress": {"path": "/x"}},
            },
        ),
        (
            "soak",
            {
                "events_submitted": 1,
                "batches": [{}],
                "global_accounting": {"evaluations_expected": 1},
                "incremental_evidence": {"event_samples": {"path": "/x"}},
            },
        ),
        (
            "offline",
            {
                "prepared_online": True,
                "online": {"sample": {}, "accounting": {"evaluations_expected": 1}},
                "online_daemon_identity": {"paw": True},
            },
        ),
        (
            "faults",
            {
                "error": None,
                "probe_specific": {
                    "recovery": {
                        "sample": {},
                        "accounting": {"evaluations_expected": 1},
                    }
                },
                "standardized_outcomes": {"measured": True},
                "started_monotonic_ns": 1,
                "finished_monotonic_ns": 2,
            },
        ),
    ],
)
def test_forensics_positive_measurement_predicates_are_component_exact(
    component: str, payload: dict[str, Any]
) -> None:
    positive, pointers = attempts._forensics_positive_measurement(component, payload)
    assert positive is True
    assert len(pointers) >= 4

    broken = json.loads(json.dumps(payload))
    first = pointers[0].split("/")[1]
    broken.pop(first)
    assert attempts._forensics_positive_measurement(component, broken)[0] is False


def test_forensics_exception_only_fault_is_not_positive_measurement() -> None:
    exception_only = {
        "error": {"type": "RuntimeError", "message": "boom"},
        "probe_specific": {"probe_exception": {"type": "RuntimeError"}},
        "standardized_outcomes": {"healthy_recovery": None},
        "started_monotonic_ns": 1,
        "finished_monotonic_ns": 2,
    }
    assert attempts._forensics_positive_measurement("faults", exception_only)[0] is False


@pytest.mark.parametrize(
    ("plan", "expected"),
    [
        ({"component": "matrix"}, "component_requires_direct_paw"),
        (
            {"component": "faults", "fault": "worker_timeout"},
            "fault_recovery_requires_direct_paw",
        ),
        (
            {"component": "faults", "fault": "sqlite_lock"},
            "fault_boundary_is_deterministic_no_paw",
        ),
    ],
)
def test_forensics_dependency_basis_is_exact_static_mapping(
    plan: dict[str, Any], expected: str
) -> None:
    schema = {
        "dependency_basis_by_static_plan_exactly": dict(
            attempts._COMPONENT_DEPENDENCY_BASIS
        )
    }

    assert attempts._forensics_dependency_basis(plan, schema=schema) == expected

    schema["dependency_basis_by_static_plan_exactly"]["matrix"] = "arbitrary"
    with pytest.raises(attempts.SystemsHarnessError, match="schema differs"):
        attempts._forensics_dependency_basis(plan, schema=schema)


def _deterministic_carry_terminal(fault: str) -> dict[str, Any]:
    standardized = {
        "schema_version": 1,
        "injected_boundary": "synthetic",
        "fail_open_hook_contract_and_latency": {},
        "current_event_survival": {},
        "loss_and_duplication": {},
        "healthy_recovery": {},
        "previous_deployment_continuity": None,
        "orphan_process_count": 0,
        "orphan_process_count_status": "known",
        "post_shutdown_process_cleanup": {},
        "persistent_state_integrity": {},
        "operator_visible_incident_records": [],
    }
    probe = {
        "persistent_state_integrity": {"ok": True},
        "post_shutdown_process_cleanup": {"safe_to_continue": True},
    }
    if fault == "sqlite_lock":
        probe.update(
            {
                "lock_mode": "BEGIN EXCLUSIVE",
                "lock_acquired_monotonic_ns": 10,
                "lock_release_started_monotonic_ns": 20,
                "lock_released_monotonic_ns": 30,
                "faulting_hook": {},
                "recovery": {
                    "sample": {},
                    "accounting": {"evaluations_expected": 1},
                },
            }
        )
    elif fault == "malformed_payload":
        probe.update(
            {
                "invalid_json": {"hook": {}},
                "oversized_trigger_field": {"hook": {}},
                "final_exact_evaluation_accounting": {"complete": True},
                "recovery": {
                    "sample": {},
                    "accounting": {"evaluations_expected": 1},
                },
            }
        )
    elif fault == "duplicate_delivery":
        probe.update(
            {
                "deliveries": 2,
                "hooks": [{}, {}],
                "evaluations": 1,
                "findings": 1,
                "ingress_duplicate_counter_delta": 1,
                "exactly_once_within_live_daemon_window": True,
                "scope": (
                    "byte-identical concurrent redelivery while one daemon and its "
                    "short-window admission cache remain live"
                ),
            }
        )
    elif fault == "deployment_failure":
        probe.update(
            {
                "prepare_ok": True,
                "working_source_changed_after_prepare": True,
                "working_behavior_changed_after_prepare": True,
                "commit_ok": False,
                "previous_active_revision_remained_effective": True,
                "previous_active_source_sha256": "1" * 64,
                "post_failure_active_source_sha256": "1" * 64,
                "post_failure_sample": {},
                "post_failure_accounting": {"evaluations_expected": 1},
            }
        )
    else:  # pragma: no cover - fixture misuse
        raise AssertionError(fault)
    return {
        "fault": fault,
        "repetition": 0,
        "passed": False,
        "started_utc": "2026-08-31T12:00:00+00:00",
        "finished_utc": "2026-08-31T12:00:01+00:00",
        "started_monotonic_ns": 1,
        "finished_monotonic_ns": 3,
        "duration_ns": 2,
        "error": None,
        "probe_specific": probe,
        "standardized_outcomes": standardized,
    }


@pytest.mark.parametrize(
    ("fault", "predicate"),
    [
        ("sqlite_lock", "sqlite_lock_carry_valid_v1"),
        ("malformed_payload", "malformed_payload_carry_valid_v1"),
        ("duplicate_delivery", "duplicate_delivery_carry_valid_v1"),
        ("deployment_failure", "deployment_failure_carry_valid_v1"),
    ],
)
def test_forensics_deterministic_carry_predicates_are_family_exact(
    fault: str, predicate: str
) -> None:
    terminal = _deterministic_carry_terminal(fault)
    observed_predicate, pointers = attempts._forensics_carry_validity(
        {"fault": fault, "repetition": 0}, terminal
    )
    assert observed_predicate == predicate
    assert len(pointers) >= 18

    terminal["probe_specific"]["probe_exception"] = {"type": "RuntimeError"}
    with pytest.raises(attempts.SystemsHarnessError, match="common predicate"):
        attempts._forensics_carry_validity(
            {"fault": fault, "repetition": 0}, terminal
        )


def test_forensics_fault_measurement_requires_monotonic_order() -> None:
    terminal = {
        "error": None,
        "probe_specific": {
            "recovery": {
                "sample": {},
                "accounting": {"evaluations_expected": 1},
            }
        },
        "standardized_outcomes": {"measured": True},
        "started_monotonic_ns": 2,
        "finished_monotonic_ns": 1,
    }
    assert attempts._forensics_positive_measurement("faults", terminal)[0] is False


def test_replacement_receipt_rejects_duplicate_keys_before_edge_selection(
    tmp_path: Path,
) -> None:
    successor = tmp_path / "formal-v3-20260831t051023z-r03"
    receipt_path = tmp_path / "replacement.json"
    receipt_path.write_text(
        '{"schema_version":2,"schema_version":1}\n', encoding="utf-8"
    )
    with pytest.raises(attempts.SystemsHarnessError, match="duplicate JSON object key"):
        attempts.replacement_launch_binding(successor, str(receipt_path))


def test_whole_attempt_validation_rejects_duplicate_wrapper_keys(tmp_path: Path) -> None:
    path = tmp_path / "whole-attempt-validation.json"
    raw = b'{"schema_version":1,"schema_version":1}\n'
    path.write_bytes(raw)
    with pytest.raises(attempts.SystemsHarnessError, match="not strict JSON"):
        attempts._forensics_strict_json_file(
            path,
            label="whole-attempt validation",
            cache={},
        )


def test_forensics_component_started_and_terminal_receipts_are_exact(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    matrix_plan = {
        "component": "matrix",
        "unit_id": "r1-p1-round_robin_across_projects-sequential20-rep0",
        "condition_id": "r1-p1-round_robin_across_projects-sequential20-rep0",
        "rule_count": 1,
        "project_count": 1,
        "events": 20,
    }
    matrix_started = {
        "phase": "started",
        "plan": {
            key: value
            for key, value in matrix_plan.items()
            if key not in {"component", "unit_id"}
        },
        "started_utc": "2026-08-31T12:00:00+00:00",
        "started_monotonic_ns": 1,
        "retained_runtime_root": str(
            root / "runtime" / "matrix" / matrix_plan["unit_id"]
        ),
    }
    attempts._forensics_validate_started_payload(
        component="matrix",
        unit_id=matrix_plan["unit_id"],
        plan=matrix_plan,
        payload=matrix_started,
        attempt_root=root,
        network_boundary={},
    )
    attempts._forensics_validate_terminal_payload(
        component="matrix",
        unit_id=matrix_plan["unit_id"],
        plan=matrix_plan,
        payload={
            "status": "completed",
            "condition_id": matrix_plan["unit_id"],
            "rule_count": 1,
            "project_count": 1,
        },
    )

    invalid_started = {**matrix_started, "unexpected": True}
    with pytest.raises(attempts.SystemsHarnessError, match="matrix started"):
        attempts._forensics_validate_started_payload(
            component="matrix",
            unit_id=matrix_plan["unit_id"],
            plan=matrix_plan,
            payload=invalid_started,
            attempt_root=root,
            network_boundary={},
        )
    with pytest.raises(attempts.SystemsHarnessError, match="condition_id"):
        attempts._forensics_validate_terminal_payload(
            component="matrix",
            unit_id=matrix_plan["unit_id"],
            plan=matrix_plan,
            payload={"status": "completed"},
        )

    soak_plan = {
        "component": "soak",
        "unit_id": "soak-r8-p8",
        "rule_count": 8,
        "project_count": 8,
        "events": 10_000,
    }
    with pytest.raises(attempts.SystemsHarnessError, match="omits successful"):
        attempts._forensics_validate_terminal_payload(
            component="soak",
            unit_id="soak-r8-p8",
            plan=soak_plan,
            payload={"status": "completed"},
        )


def test_forensics_fault_positive_measurement_rejects_unknown_outcomes() -> None:
    terminal = {
        "error": None,
        "probe_specific": {
            "recovery": {"sample": {}, "accounting": {"evaluations_expected": 1}}
        },
        "standardized_outcomes": {
            "orphan_process_count_status": "unknown_after_caught_exception"
        },
        "started_monotonic_ns": 1,
        "finished_monotonic_ns": 2,
    }
    assert attempts._forensics_positive_measurement("faults", terminal)[0] is False
    terminal["standardized_outcomes"]["orphan_process_count_status"] = "measured"
    assert attempts._forensics_positive_measurement("faults", terminal)[0] is True


def test_forensics_label_evidence_is_sorted_exact_and_byte_counted(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    matrix = root / "matrix"
    runtime = root / "runtime" / "matrix" / "u"
    matrix.mkdir(parents=True)
    runtime.mkdir(parents=True)
    started = matrix / "u.started.json"
    terminal = matrix / "u.terminal.json"
    log = runtime / "daemon-output.log"
    _write_json(started, {"phase": "started"})
    _write_json(terminal, {"status": "completed"})
    log.write_bytes(b"ababa")

    def receipt(path: Path) -> dict[str, Any]:
        base = _file_receipt(path)
        return {**base, "type": "regular_file"}

    schema = {
        "file_receipt_fields_exactly": ["path", "bytes", "sha256", "type"],
        "label_evidence_fields_exactly": [
            "supporting_receipts",
            "json_values",
            "text_literals",
        ],
        "json_value_evidence_fields_exactly": [
            "receipt_path",
            "json_pointer",
            "value",
        ],
        "text_literal_evidence_fields_exactly": [
            "receipt_path",
            "literal_utf8",
            "occurrence_count",
        ],
    }
    supports = sorted([receipt(terminal), receipt(log)], key=lambda item: item["path"])
    evidence = {
        "supporting_receipts": supports,
        "json_values": [
            {
                "receipt_path": str(terminal.resolve()),
                "json_pointer": "/status",
                "value": "completed",
            }
        ],
        "text_literals": [
            {
                "receipt_path": str(log.resolve()),
                "literal_utf8": "aba",
                "occurrence_count": 1,
            }
        ],
    }
    tree_files = {
        "matrix/u.started.json": {
            "relative_path": "matrix/u.started.json",
            "type": "regular_file",
            "bytes": started.stat().st_size,
            "sha256": hashlib.sha256(started.read_bytes()).hexdigest(),
        },
        "runtime/matrix/u/daemon-output.log": {
            "relative_path": "runtime/matrix/u/daemon-output.log",
            "type": "regular_file",
            "bytes": log.stat().st_size,
            "sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        }
    }
    pointers, literals, _ = attempts._forensics_validate_label_evidence(
        evidence,
        schema=schema,
        label="test evidence",
        predecessor_root=root,
        component="matrix",
        terminal_path=terminal.resolve(),
        tree_files=tree_files,
        expected_pointers=["/status"],
        expected_support_paths={terminal.resolve(), log.resolve()},
        expected_text_literal_keys={(str(log.resolve()), b"aba")},
        indirect_receipts={},
        json_cache={},
    )
    assert pointers[(str(terminal.resolve()), "/status")] == "completed"
    assert literals[0]["occurrence_count"] == 1

    wrong_count = copy.deepcopy(evidence)
    wrong_count["text_literals"][0]["occurrence_count"] = 2
    with pytest.raises(attempts.SystemsHarnessError, match="occurrence count"):
        attempts._forensics_validate_label_evidence(
            wrong_count,
            schema=schema,
            label="test evidence",
            predecessor_root=root,
            component="matrix",
            terminal_path=terminal.resolve(),
            tree_files=tree_files,
            expected_pointers=["/status"],
            expected_support_paths={terminal.resolve(), log.resolve()},
            expected_text_literal_keys={(str(log.resolve()), b"aba")},
            indirect_receipts={},
            json_cache={},
        )
    uncited = copy.deepcopy(evidence)
    uncited["supporting_receipts"] = sorted(
        [*uncited["supporting_receipts"], receipt(started)],
        key=lambda item: item["path"],
    )
    with pytest.raises(attempts.SystemsHarnessError, match="exact citations"):
        attempts._forensics_validate_label_evidence(
            uncited,
            schema=schema,
            label="test evidence",
            predecessor_root=root,
            component="matrix",
            terminal_path=terminal.resolve(),
            tree_files=tree_files,
            expected_pointers=["/status"],
            expected_support_paths={terminal.resolve(), log.resolve()},
            expected_text_literal_keys={(str(log.resolve()), b"aba")},
            indirect_receipts={},
            json_cache={},
        )


def test_forensics_closeout_derives_observed_partition_exhaustively() -> None:
    schema = {
        "cache_inventory_item_fields_exactly": [
            "relative_path",
            "type",
            "mode",
            "bytes",
            "sha256",
        ],
        "cache_mismatch_item_fields_exactly": [
            "relative_path",
            "required",
            "observed",
        ],
    }
    required = [
        {
            "relative_path": "base_models/model.gguf",
            "type": "regular",
            "mode": 0o600,
            "bytes": 1,
            "sha256": "1" * 64,
        },
        {
            "relative_path": "runtimes/current.json",
            "type": "regular",
            "mode": 0o600,
            "bytes": 2,
            "sha256": "2" * 64,
        },
    ]
    observed = [required[0]]
    closeout = {
        "required_files": required,
        "observed_files": observed,
        "matched_files": ["base_models/model.gguf"],
        "missing_files": ["runtimes/current.json"],
        "mismatched_files": [],
        "inventory_sha256": hashlib.sha256(
            attempts._canonical_json_bytes(observed)
        ).hexdigest(),
    }
    assert set(
        attempts._forensics_validate_cache_closeout(
            closeout, schema=schema, locked_required=required
        )
    ) == {"base_models/model.gguf"}

    extra = copy.deepcopy(closeout)
    extra_item = {
        "relative_path": "programs/extra/meta.json",
        "type": "regular",
        "mode": 0o600,
        "bytes": 3,
        "sha256": "3" * 64,
    }
    extra["observed_files"].append(extra_item)
    extra["inventory_sha256"] = hashlib.sha256(
        attempts._canonical_json_bytes(extra["observed_files"])
    ).hexdigest()
    with pytest.raises(attempts.SystemsHarnessError, match="extra"):
        attempts._forensics_validate_cache_closeout(
            extra, schema=schema, locked_required=required
        )


def test_forensics_operational_active_set_recomputes_tree_and_metadata(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    program_id = "program-id"
    program_dir = root / "programs" / program_id
    runtime_dir = root / "runtimes"
    program_dir.mkdir(parents=True)
    runtime_dir.mkdir()
    meta = program_dir / "meta.json"
    manifest = runtime_dir / "qwen3-0.6b-q6_k.json"
    _write_json(
        meta,
        {
            "program_id": program_id,
            "runtime_id": "qwen3-0.6b-q6_k",
            "runtime_manifest_version": 1,
        },
    )
    _write_json(
        manifest,
        {"runtime_id": "qwen3-0.6b-q6_k", "manifest_version": 1},
    )

    def inventory(path: Path, relative: str) -> dict[str, Any]:
        return {
            "relative_path": relative,
            "type": "regular",
            "mode": 0o600,
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    meta_item = inventory(meta, f"programs/{program_id}/meta.json")
    manifest_item = inventory(manifest, "runtimes/qwen3-0.6b-q6_k.json")
    base_item = {
        "relative_path": "base_models/qwen3-0.6b-q6_k.gguf",
        "type": "regular",
        "mode": 0o600,
        "bytes": 622733120,
        "sha256": "9a16ed5cacba959e63b62e2b6840c3eca2b51c3c3e51d31367ef8e4aafeae33c",
    }
    observed = {
        base_item["relative_path"]: base_item,
        meta_item["relative_path"]: meta_item,
        manifest_item["relative_path"]: manifest_item,
    }
    measured = "4" * 64
    operational = {
        "program_ids": [program_id],
        "program_tree_sha256_by_id": {
            program_id: hashlib.sha256(
                attempts._canonical_json_bytes([meta_item])
            ).hexdigest()
        },
        "embedded_runtime_id_by_program_id": {
            program_id: "qwen3-0.6b-q6_k"
        },
        "active_runtime_manifest": {
            "relative_path": manifest_item["relative_path"],
            "bytes": manifest_item["bytes"],
            "sha256": manifest_item["sha256"],
            "embedded_runtime_id": "qwen3-0.6b-q6_k",
        },
        "base_model": {
            "relative_path": base_item["relative_path"],
            "bytes": base_item["bytes"],
            "sha256": base_item["sha256"],
        },
        "positive_measured_unit_membership_sha256": measured,
    }
    schema = {
        "operational_active_set_fixed_program_ids": [program_id],
        "active_runtime_manifest_fields_exactly": [
            "relative_path",
            "bytes",
            "sha256",
            "embedded_runtime_id",
        ],
        "base_model_fields_exactly": ["relative_path", "bytes", "sha256"],
    }
    attempts._forensics_validate_operational_active_set(
        operational,
        schema=schema,
        observed_by_path=observed,
        configured_root=root,
        measured_membership_sha256=measured,
    )
    invalid = copy.deepcopy(operational)
    invalid["program_tree_sha256_by_id"][program_id] = "0" * 64
    with pytest.raises(attempts.SystemsHarnessError, match="program-tree"):
        attempts._forensics_validate_operational_active_set(
            invalid,
            schema=schema,
            observed_by_path=observed,
            configured_root=root,
            measured_membership_sha256=measured,
        )
