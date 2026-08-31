from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from experiments.eacl2027 import scaling_faults_attempts as attempts


PROTOCOL_AMENDMENT = (
    Path(__file__).resolve().parents[1]
    / "experiments/eacl2027/protocol-v3-amendment-005.json"
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

    assert chain["max_raw_attempt_ordinal"] == attempts._MAX_FORMAL_ATTEMPT_ORDINAL
    assert tree["max_entries"] == attempts._MAX_PREDECESSOR_TREE_ENTRIES
    assert (
        tree["max_regular_file_bytes"]
        == attempts._MAX_PREDECESSOR_TREE_REGULAR_BYTES
    )
    assert (
        tree["min_staging_free_reserve_bytes"]
        == attempts._MIN_STAGING_FREE_RESERVE_BYTES
    )


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
