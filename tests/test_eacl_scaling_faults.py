from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from experiments.eacl2027 import run_scaling_faults as systems
from experiments.eacl2027 import scaling_faults_attempts as attempts_contract
from experiments.eacl2027 import scaling_faults_runtime as systems_runtime


def _artifact(rule_id: str, name: str) -> systems.RuleArtifact:
    raw_source = f'''from rules_as_programs import rule


@rule(id="{rule_id}", name="{name}", trigger="PreToolUse")
def synthetic_rule(ctx):
    """{name}."""
    return ctx.result("WARNING")
'''
    source = systems._normalized_managed_source(rule_id, raw_source)
    return systems.RuleArtifact(
        rule_id=rule_id,
        source=source,
        source_path=f"<test fixture {rule_id}>",
        source_file_sha256=hashlib.sha256(raw_source.encode()).hexdigest(),
        source_sha256=systems.revisions.hash_source(source),
        behavior_sha256=systems.revisions.behavior_hash(source),
        probe_tool_input={"command": f"synthetic command for {rule_id}"},
    )


def _row(
    project: Path,
    input_hash: str,
    artifact: systems.RuleArtifact,
    *,
    status: str = "completed",
) -> dict:
    outcome = (
        {"type": "evaluation_failed", "error_code": "synthetic", "error": "x"}
        if status == "failed"
        else {
            "type": "evaluation_completed",
            "result": "WARNING",
            "finding_id": 1,
        }
    )
    return {
        "evaluation_id": f"{project.name}-{input_hash[:6]}-{artifact.rule_id}",
        "timestamp": 10.0,
        "project_root": str(project),
        "status": status,
        "result": outcome.get("result", ""),
        "outcome": outcome,
        "input": {"sha256": input_hash, "text": "synthetic"},
        "rule": {
            "id": artifact.rule_id,
            "source_hash": artifact.source_sha256,
            "behavior_hash": artifact.behavior_sha256,
            "compiler": artifact.compiler,
            "compiler_snapshot": artifact.compiler_snapshot,
            "program_id": artifact.program_id,
        },
    }


def test_matrix_plan_covers_fixed_factorial_with_fresh_daemons():
    config = systems.MatrixConfig()
    plan = systems.build_matrix_plan(config)

    assert len(plan) == 4 * 3 * 3 * 4 * 2
    assert len({item["condition_id"] for item in plan}) == len(plan)
    assert {item["rule_count"] for item in plan} == {1, 2, 4, 8}
    assert {item["project_count"] for item in plan} == {1, 4, 8}
    assert {(item["mode"], item["events"]) for item in plan} == {
        ("sequential", 20),
        ("burst", 24),
        ("burst", 64),
    }
    assert {item["schedule"] for item in plan} == set(systems.TRAFFIC_PATTERNS)
    assert all(item["fresh_daemon"] and item["fresh_state"] for item in plan)


def test_socket_path_override_preserves_default_state_layout(monkeypatch, tmp_path):
    state = tmp_path / "durable-state"
    override = tmp_path / "short.sock"
    monkeypatch.setenv("RAP_STATE_DIR", str(state))
    monkeypatch.delenv("RAP_SOCKET_PATH", raising=False)

    assert systems.rap_config.socket_path() == state / "daemon.sock"
    monkeypatch.setenv("RAP_SOCKET_PATH", "")
    assert systems.rap_config.socket_path() == state / "daemon.sock"
    monkeypatch.setenv("RAP_SOCKET_PATH", str(override))
    assert systems.rap_config.socket_path() == override
    assert systems.rap_config.db_path() == state / "verdicts.db"


def test_formal_unit_socket_receipt_is_deterministic_and_restores_environment(
    monkeypatch, tmp_path
):
    attempt = (tmp_path / "formal-r02").resolve()
    retained = attempt / "runtime" / "matrix" / "matrix-unit"
    retained.mkdir(parents=True)
    (attempt / "launch.json").write_text("{}\n", encoding="utf-8")
    job_id = str(int(hashlib.sha256(str(tmp_path).encode()).hexdigest()[:14], 16))
    socket_root = Path("/tmp") / f"rf3-{job_id}"
    socket_root.mkdir(mode=0o700)
    monkeypatch.setenv("RAP_SOCKET_PATH", "/tmp/original-rap.sock")
    environment = {
        "RAP_EACL_SOCKET_ROOT": str(socket_root),
        "RAP_STATE_DIR": str(retained / "state"),
        "SLURM_JOB_ID": job_id,
        "SLURM_JOB_PARTITION": "ALL",
        "SLURM_JOB_NODELIST": "watgpu108",
    }
    try:
        with systems._unit_socket_environment(
            retained,
            environment,
            component="matrix",
            unit_id="matrix-unit",
        ) as unit_environment:
            endpoint = Path(unit_environment["RAP_SOCKET_PATH"])
            assert endpoint.parent == socket_root
            assert endpoint.name.endswith(".sock")
            assert len(endpoint.stem) == 64
            assert len(os.fsencode(endpoint)) <= systems.MAX_AF_UNIX_PATHNAME_BYTES
            assert systems.rap_config.socket_path() == endpoint
            assert unit_environment["RAP_STATE_DIR"] == str(retained / "state")
        assert os.environ["RAP_SOCKET_PATH"] == "/tmp/original-rap.sock"

        receipt_path = retained / "socket-endpoint.json"
        receipt_bytes = receipt_path.read_bytes()
        assert receipt_bytes.endswith(b"\n")
        receipt = json.loads(receipt_bytes)
        digest_input = {
            "schema_version": 1,
            "raw_attempt_id": "formal-r02",
            "component": "matrix",
            "unit_id": "matrix-unit",
            "retained_runtime_root": str(retained),
        }
        expected_digest = hashlib.sha256(
            json.dumps(
                digest_input,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        assert receipt["digest_input"] == digest_input
        assert receipt["endpoint_digest"] == expected_digest
        assert receipt["endpoint"] == str(socket_root / f"{expected_digest}.sock")
        assert receipt["rap_state_dir"] == str(retained / "state")
        assert receipt["socket_root"]["owner_uid"] == os.geteuid()
        assert receipt["socket_root"]["mode"] == 0o700
        assert receipt["slurm"] == {
            "job_id": job_id,
            "partition": "ALL",
            "node_list": "watgpu108",
        }
        with pytest.raises(systems.SystemsHarnessError, match="receipt collision"):
            with systems._unit_socket_environment(
                retained,
                environment,
                component="matrix",
                unit_id="matrix-unit",
            ):
                pass
    finally:
        socket_root.rmdir()


def test_formal_unit_socket_rejects_wrong_root_mode_before_receipt(
    monkeypatch, tmp_path
):
    attempt = (tmp_path / "formal-r02").resolve()
    retained = attempt / "runtime" / "faults" / "daemon-crash-rep1"
    retained.mkdir(parents=True)
    (attempt / "launch.json").write_text("{}\n", encoding="utf-8")
    job_id = str(
        int(hashlib.sha256((str(tmp_path) + "-mode").encode()).hexdigest()[:14], 16)
    )
    socket_root = Path("/tmp") / f"rf3-{job_id}"
    socket_root.mkdir(mode=0o755)
    environment = {
        "RAP_EACL_SOCKET_ROOT": str(socket_root),
        "RAP_STATE_DIR": str(retained / "state"),
        "SLURM_JOB_ID": job_id,
        "SLURM_JOB_PARTITION": "ALL",
        "SLURM_JOB_NODELIST": "watgpu108",
    }
    try:
        with pytest.raises(systems.SystemsHarnessError, match="mode 0700"):
            with systems._unit_socket_environment(retained, environment):
                pass
        assert not (retained / "socket-endpoint.json").exists()
    finally:
        socket_root.chmod(0o700)
        socket_root.rmdir()


def test_running_fixture_propagates_socket_to_daemon_and_hook_environment(
    monkeypatch, tmp_path
):
    attempt = (tmp_path / "formal-r02").resolve()
    unit_id = "r1-p1-round_robin_across_projects-sequential20-rep1"
    retained = attempt / "runtime" / "matrix" / unit_id
    retained.parent.mkdir(parents=True)
    (attempt / "launch.json").write_text("{}\n", encoding="utf-8")
    job_id = str(
        int(hashlib.sha256((str(tmp_path) + "-fixture").encode()).hexdigest()[:14], 16)
    )
    socket_root = Path("/tmp") / f"rf3-{job_id}"
    socket_root.mkdir(mode=0o700)
    monkeypatch.setenv("RAP_EACL_SOCKET_ROOT", str(socket_root))
    monkeypatch.setenv("SLURM_JOB_ID", job_id)
    monkeypatch.setenv("SLURM_JOB_PARTITION", "ALL")
    monkeypatch.setenv("SLURM_JOB_NODELIST", "watgpu108")
    monkeypatch.delenv("RAP_SOCKET_PATH", raising=False)
    observed = {}

    class FakeDaemon:
        pid = 123

    def start(environment, _diagnostics, _timeout):
        observed["daemon_environment"] = dict(environment)
        observed["client_socket"] = str(systems.rap_config.socket_path())
        return FakeDaemon(), {"pid": 123}

    monkeypatch.setattr(systems, "_install_projects", lambda *_a, **_k: [])
    monkeypatch.setattr(systems.integrated, "_start_daemon", start)
    monkeypatch.setattr(systems.integrated, "_stop_daemon", lambda _daemon: None)
    monkeypatch.setattr(systems.ipc, "send_request", lambda *_a, **_k: None)
    try:
        with systems._running_fixture(
            (_artifact("systemstest00001", "Socket fixture"),),
            1,
            retained_root=retained,
            component="matrix",
            unit_id=unit_id,
        ) as fixture:
            observed["hook_environment"] = dict(fixture.environment)
            assert str(systems.rap_config.socket_path()) == fixture.environment[
                "RAP_SOCKET_PATH"
            ]
        assert "RAP_SOCKET_PATH" not in os.environ
        assert observed["daemon_environment"]["RAP_SOCKET_PATH"] == observed[
            "hook_environment"
        ]["RAP_SOCKET_PATH"]
        assert observed["client_socket"] == observed["hook_environment"][
            "RAP_SOCKET_PATH"
        ]
        assert (retained / "socket-endpoint.json").is_file()
    finally:
        socket_root.rmdir()


@pytest.mark.parametrize("body_raises", [False, True])
def test_running_fixture_records_stale_socket_without_masking_body_error(
    monkeypatch, tmp_path, body_raises
):
    attempt = (tmp_path / "formal-r02").resolve()
    unit_id = "r1-p1-round_robin_across_projects-sequential1-rep0"
    retained = attempt / "runtime" / "matrix" / unit_id
    retained.parent.mkdir(parents=True)
    (attempt / "launch.json").write_text("{}\n", encoding="utf-8")
    job_id = str(
        int(
            hashlib.sha256(
                (str(tmp_path) + f"-cleanup-{body_raises}").encode()
            ).hexdigest()[:14],
            16,
        )
    )
    socket_root = Path("/tmp") / f"rf3-{job_id}"
    socket_root.mkdir(mode=0o700)
    monkeypatch.setenv("RAP_EACL_SOCKET_ROOT", str(socket_root))
    monkeypatch.setenv("SLURM_JOB_ID", job_id)
    monkeypatch.setenv("SLURM_JOB_PARTITION", "ALL")
    monkeypatch.setenv("SLURM_JOB_NODELIST", "watgpu108")
    monkeypatch.setattr(systems, "SOCKET_CLEANUP_TIMEOUT_SECONDS", 0.0)

    class FakeDaemon:
        pid = 123

    def start(environment, _diagnostics, _timeout):
        Path(environment["RAP_SOCKET_PATH"]).touch()
        return FakeDaemon(), {"pid": 123}

    monkeypatch.setattr(systems, "_install_projects", lambda *_a, **_k: [])
    monkeypatch.setattr(systems.integrated, "_start_daemon", start)
    monkeypatch.setattr(systems.integrated, "_stop_daemon", lambda _daemon: None)
    monkeypatch.setattr(systems.ipc, "send_request", lambda *_a, **_k: None)
    expected_exception = ValueError if body_raises else systems.SystemsHarnessError
    expected_message = "original workload error" if body_raises else "remained"
    try:
        with pytest.raises(expected_exception, match=expected_message):
            with systems._running_fixture(
                (_artifact("systemstest00001", "Cleanup fixture"),),
                1,
                retained_root=retained,
                component="matrix",
                unit_id=unit_id,
            ):
                if body_raises:
                    raise ValueError("original workload error")
        failure = json.loads(
            (
                retained
                / "socket-cleanup-failure-final-daemon-shutdown.json"
            ).read_text()
        )
        assert failure["status"] == (
            "socket_endpoint_persisted_after_verified_shutdown"
        )
        assert failure["endpoint"]["type"] == "regular_file"
        assert failure["active_exception"] == {
            "present": body_raises,
            "type": "ValueError" if body_raises else None,
        }
    finally:
        for endpoint in socket_root.glob("*.sock"):
            endpoint.unlink()
        socket_root.rmdir()


def test_offline_replay_checks_endpoint_after_both_verified_shutdowns():
    source = inspect.getsource(systems.run_offline_after_prepare)

    assert 'stage="online-daemon-shutdown"' in source
    assert 'stage="offline-daemon-shutdown"' in source
    assert source.rindex("integrated._stop_daemon(offline)") < source.rindex(
        'stage="offline-daemon-shutdown"'
    )


def test_formal_study_plan_enumerates_all_430_units():
    config = systems.MatrixConfig(soak_events=systems.DEFAULT_SOAK_EVENTS)
    faults = tuple(
        name
        for name, capability in systems.FAULT_CAPABILITIES.items()
        if capability["feasible"]
    )
    plan = systems.build_study_plan(
        config, fault_names=faults, run_offline_probe=True
    )

    assert len(plan) == 430
    assert {item["component"] for item in plan} == {
        "matrix",
        "soak",
        "offline",
        "faults",
    }
    assert len({(item["component"], item["unit_id"]) for item in plan}) == 430


def test_count_parser_and_soak_validation_reject_ambiguous_protocols():
    assert systems.parse_int_tuple("1, 2,8", allowed={1, 2, 4, 8}) == (1, 2, 8)

    with pytest.raises(argparse.ArgumentTypeError, match="repeated"):
        systems.parse_int_tuple("1,1")
    with pytest.raises(argparse.ArgumentTypeError, match="selected from"):
        systems.parse_int_tuple("3", allowed={1, 2, 4, 8})
    with pytest.raises(ValueError, match="soak rule/project count"):
        systems.MatrixConfig(
            rule_counts=(1,),
            project_counts=(1,),
            burst_sizes=(24,),
            soak_events=10,
            soak_rule_count=8,
            soak_project_count=1,
        ).validate()


def test_external_artifact_bundle_is_exactly_the_frozen_eight_rule_set():
    bundle = systems.load_external_artifacts()

    assert (
        tuple(item.rule_id for item in bundle.artifacts) == systems.EXTERNAL_RULE_ORDER
    )
    assert all(item.program_id for item in bundle.artifacts)
    assert all(item.compiler == "paw-ft-bs48" for item in bundle.artifacts)
    assert all(
        item.compiler_snapshot == "paw-ft-bs48-20260530" for item in bundle.artifacts
    )


def test_exact_accounting_detects_duplicate_failure_and_cross_project_leakage(
    tmp_path,
):
    first = (tmp_path / "first").resolve()
    second = (tmp_path / "second").resolve()
    first.mkdir()
    second.mkdir()
    artifacts = (
        _artifact("systemstest00001", "First system rule"),
        _artifact("systemstest00002", "Second system rule"),
    )
    first_hash = "a" * 64
    second_hash = "b" * 64
    expected = [
        *(
            systems.ExpectedEvaluation("first", str(first), first_hash, item.rule_id)
            for item in artifacts
        ),
        *(
            systems.ExpectedEvaluation("second", str(second), second_hash, item.rule_id)
            for item in artifacts
        ),
    ]
    rows = {
        str(first): [_row(first, first_hash, item) for item in artifacts],
        str(second): [_row(second, second_hash, item) for item in artifacts],
    }

    clean = systems.account_evaluations(
        rows, expected, artifacts, started_wall_time=1.0
    )
    assert clean["evaluations_expected"] == 4
    assert clean["loss_count"] == 0
    assert clean["cross_project_contamination_count"] == 0
    assert clean["provenance_mismatch_count"] == 0

    rows[str(first)].append(_row(first, first_hash, artifacts[0]))
    rows[str(first)].append(_row(first, second_hash, artifacts[1]))
    rows[str(second)][0] = _row(second, second_hash, artifacts[0], status="failed")
    broken = systems.account_evaluations(
        rows, expected, artifacts, started_wall_time=1.0
    )

    assert broken["duplicate_count"] == 1
    assert broken["cross_project_contamination_count"] == 1
    assert broken["unexpected_count"] == 1
    assert broken["failed_count"] == 1


def test_storage_accounting_separates_state_and_project_logs(tmp_path):
    state = tmp_path / "state"
    log = tmp_path / "project" / ".codex" / "rules-as-programs" / "log"
    state.mkdir()
    log.mkdir(parents=True)
    (state / "verdicts.db").write_bytes(b"1234")
    (log / "evaluations.jsonl").write_bytes(b"123456")

    assert systems._tree_size(state) == {"files": 1, "bytes": 4}
    assert systems._tree_size(log) == {"files": 1, "bytes": 6}
    before = {
        "state": {"files": 1, "bytes": 4},
        "project_logs": {"p": {"files": 1, "bytes": 6}},
        "total_runtime_bytes": 10,
    }
    after = {
        "state": {"files": 1, "bytes": 9},
        "project_logs": {"p": {"files": 1, "bytes": 14}},
        "total_runtime_bytes": 23,
    }
    assert systems._storage_delta(before, after) == {
        "state_bytes": 5,
        "project_log_bytes": {"p": 8},
        "total_runtime_bytes": 13,
    }


def test_candidate_harness_refuses_frozen_output(monkeypatch, tmp_path):
    frozen = (tmp_path / "frozen").resolve()
    frozen.mkdir()
    monkeypatch.setattr(systems, "FROZEN_OUTPUT_DIR", frozen)

    with pytest.raises(systems.SystemsHarnessError, match="cannot write"):
        systems._validate_output_path(frozen / "systems.json")
    assert (
        systems._validate_output_path(tmp_path / "candidate.json")
        == (tmp_path / "candidate.json").resolve()
    )


def test_fault_registry_marks_remote_compiler_outage_as_infeasible():
    remote = systems.FAULT_CAPABILITIES["remote_compiler_transport_failure"]

    assert not remote["feasible"]
    assert "already-compiled" in remote["reason"]
    assert systems.FAULT_CAPABILITIES["deployment_failure"]["feasible"]


def test_formal_gate_requires_exact_design_and_all_partition(monkeypatch):
    config = systems.MatrixConfig(soak_events=systems.DEFAULT_SOAK_EVENTS)
    feasible = tuple(
        name
        for name, capability in systems.FAULT_CAPABILITIES.items()
        if capability["feasible"]
    )
    monkeypatch.setenv("SLURM_JOB_PARTITION", "ALL")
    contract = json.loads(systems.FORMAL_AMENDMENT.read_text())
    contract["freeze_state"] = "frozen_outcome_aware_repair"
    contract["frozen_utc"] = "2026-08-30T17:45:00Z"
    monkeypatch.setattr(systems, "_formal_contract", lambda: contract)

    systems._validate_formal_config(
        config,
        fault_names=feasible,
        run_offline_probe=True,
        strict=True,
        require_partition=True,
    )

    monkeypatch.setenv("SLURM_JOB_PARTITION", "gpu")
    with pytest.raises(systems.SystemsHarnessError, match="ALL"):
        systems._validate_formal_config(
            config,
            fault_names=feasible,
            run_offline_probe=True,
            strict=True,
            require_partition=True,
        )


def test_immutable_attempt_recorder_retains_terminal_units(tmp_path):
    root = tmp_path / "formal-attempt-001"
    recorder = systems.AttemptRecorder(
        root,
        {"identity": {"attempt_id": root.name}, "plan": [{"condition_id": "c1"}]},
    )
    recorder.record("matrix", "c1", "started", {"status": "started"})
    recorder.record(
        "matrix",
        "c1",
        "terminal",
        {"status": "system_violation", "loss_count": 1},
    )
    final = recorder.finalize({"status": "completed_with_system_violations"})

    assert (root / "launch.json").is_file()
    assert json.loads((root / "plan.json").read_text()) == [{"condition_id": "c1"}]
    journal = [json.loads(line) for line in (root / "units.jsonl").read_text().splitlines()]
    assert [item["record_id"] for item in journal] == ["c1"]
    assert journal[0]["status"] == "system_violation"
    terminal_path = root / journal[0]["terminal_record"]
    assert json.loads(terminal_path.read_text())["loss_count"] == 1
    assert hashlib.sha256(terminal_path.read_bytes()).hexdigest() == (
        journal[0]["terminal_record_sha256"]
    )
    assert final["terminal_unit_count"] == 1
    assert final["all_planned_units_terminal"]
    assert json.loads((root / "result.json").read_text())["status"] == (
        "completed_with_system_violations"
    )

    with pytest.raises(systems.SystemsHarnessError, match="immutable"):
        systems.AttemptRecorder(root, {"plan": []})
    with pytest.raises(systems.SystemsHarnessError, match="more than once"):
        recorder.record("matrix", "c1", "terminal", {"status": "replacement"})

    second = systems.AttemptRecorder(
        tmp_path / "formal-attempt-002",
        {"plan": [{"condition_id": "c2"}]},
    )
    with pytest.raises(systems.SystemsHarnessError, match="before start"):
        second.record("matrix", "c2", "terminal", {"status": "completed"})


def test_attempt_recorder_started_abort_inherits_abort_class(tmp_path):
    recorder = systems.AttemptRecorder(
        tmp_path / "aborted",
        {"plan": [{"condition_id": "started"}, {"condition_id": "never"}]},
    )
    recorder.record("matrix", "started", "started", {"phase": "started"})
    final = recorder.finalize(
        {
            "status": "incomplete_infrastructure_error",
            "abort": {"status": "infrastructure_error"},
        }
    )

    assert [item["status"] for item in final["unit_index"]] == [
        "infrastructure_error",
        "not_started_after_abort",
    ]
    assert final["plan_completion"]["started_without_terminal"] == 1
    assert final["terminal_unit_count"] == 0


def test_attempt_recorder_retains_abort_system_violation_after_all_terminals(tmp_path):
    recorder = systems.AttemptRecorder(
        tmp_path / "post-terminal-abort", {"plan": [{"condition_id": "done"}]}
    )
    recorder.record("matrix", "done", "started", {"phase": "started"})
    recorder.record(
        "matrix", "done", "terminal", {"status": "completed"}
    )
    final = recorder.finalize(
        {
            "status": "incomplete_unclassified_failure",
            "primary_numeric_eligible": False,
            "abort": {
                "status": "unclassified_failure",
                "original_abort_classification": {"status": "system_violation"},
            },
        }
    )
    assert final["complete_plan"]
    assert not final["primary_numeric_eligible"]
    assert final["abort_system_violation"]
    assert final["system_violation_units"] == 0


def test_attempt_recorder_does_not_double_count_started_system_abort(tmp_path):
    recorder = systems.AttemptRecorder(
        tmp_path / "started-system-abort",
        {"plan": [{"condition_id": "started"}, {"condition_id": "never"}]},
    )
    recorder.record("matrix", "started", "started", {"phase": "started"})
    final = recorder.finalize(
        {
            "status": "incomplete_unclassified_failure",
            "primary_numeric_eligible": False,
            "abort": {"status": "system_violation"},
        }
    )
    assert final["unit_status_histogram"] == {
        "not_started_after_abort": 1,
        "system_violation": 1,
    }
    assert final["abort_system_violation"]
    assert final["system_violation_units"] == 1


def test_exact_finding_accounting_reconciles_evaluation_linkage(tmp_path):
    project = (tmp_path / "project").resolve()
    project.mkdir()
    artifact = _artifact("systemstest00001", "Finding rule")
    input_hash = "c" * 64
    expected = [
        systems.ExpectedEvaluation("case", str(project), input_hash, artifact.rule_id)
    ]
    evaluation = _row(project, input_hash, artifact)
    finding = {
        "finding_id": 1,
        "rule_id": artifact.rule_id,
        "severity": "WARNING",
        "evaluation": {
            "evaluation_id": evaluation["evaluation_id"],
            "input": {"sha256": input_hash},
        },
    }

    clean = systems.account_findings(
        {str(project): [finding]}, {str(project): [evaluation]}, expected
    )
    assert clean["findings_expected"] == 1
    assert clean["loss_count"] == 0
    assert clean["unexpected_count"] == 0

    wrong = {**finding, "finding_id": 99}
    broken = systems.account_findings(
        {str(project): [finding, wrong]}, {str(project): [evaluation]}, expected
    )
    assert broken["duplicate_count"] == 1
    assert broken["finding_id_mismatch_count"] == 1

    ok_evaluation = _row(project, input_hash, artifact)
    ok_evaluation["result"] = "OK"
    ok_evaluation["outcome"] = {
        "type": "evaluation_completed",
        "result": "OK",
        "finding_id": None,
    }
    unexpected = systems.account_findings(
        {str(project): [finding]}, {str(project): [ok_evaluation]}, expected
    )
    assert unexpected["findings_expected"] == 0
    assert unexpected["unexpected_count"] == 1


def test_censored_latency_rss_slope_and_hotspot_fairness_are_explicit():
    samples = [
        {
            "event_to_all_query_visible_evaluations_ms": 12.0,
            "latency_censored_at_ms": None,
        },
        {
            "event_to_all_query_visible_evaluations_ms": None,
            "latency_censored_at_ms": 30_000.0,
        },
    ]
    summary = systems._latency_summary(
        samples, "event_to_all_query_visible_evaluations_ms"
    )
    assert summary["right_censored_count"] == 1
    assert summary["percentiles_are_lower_bounds"]
    assert summary["maximum"] == 30_000.0

    slope = systems._rss_slope(
        [
            {"observed_monotonic_ns": 1_000_000_000, "rss_bytes": 100},
            {"observed_monotonic_ns": 2_000_000_000, "rss_bytes": 160},
            {"observed_monotonic_ns": 3_000_000_000, "rss_bytes": 220},
        ]
    )
    assert slope["available"]
    assert slope["slope"] == 60.0
    assert slope["unit"] == "bytes_per_second"

    hotspot = systems._fairness_summary(
        "one_project_hotspot", 8, {"project-0": [10.0, 20.0]}
    )
    assert not hotspot["applicable"]
    assert hotspot["range_ms"] is None
    assert hotspot["idle_projects"] == 7


def test_persistence_projection_order_is_query_order_invariant():
    rows = [{"id": 2, "value": "b"}, {"id": 1, "value": "a"}]

    assert systems._canonical_projection_order(rows) == (
        systems._canonical_projection_order(list(reversed(rows)))
    )


def test_immutable_evidence_receipt_is_attempt_relative(tmp_path):
    attempt = tmp_path / "attempt-r01"
    attempt.mkdir()
    (attempt / "launch.json").write_text("{}\n")
    path = attempt / "runtime" / "soak" / "projection.json"
    receipt = systems._write_immutable_evidence(path, b'{"value":1}')

    assert receipt["attempt_relative_path"] == "runtime/soak/projection.json"
    assert receipt["bytes"] == len(b'{"value":1}')
    assert receipt["sha256"] == hashlib.sha256(b'{"value":1}').hexdigest()
    assert path.read_bytes() == b'{"value":1}'
    with pytest.raises(FileExistsError):
        systems._write_immutable_evidence(path, b"replacement")


def test_soak_journal_tailer_survives_rename_rotation_without_reread(tmp_path):
    project_root = (tmp_path / "project").resolve()
    project_root.mkdir()
    journal = systems.rap_config.project_evaluation_log_file(str(project_root))
    journal.parent.mkdir(parents=True)
    journal.write_bytes(b"")
    project = systems.InstalledProject(0, project_root, tmp_path / "hook", tmp_path / "hooks")
    first_hash = "a" * 64
    second_hash = "b" * 64

    def record(record_type, evaluation_id, input_hash):
        return json.dumps(
            {
                "type": record_type,
                "evaluation_id": evaluation_id,
                "input": {"sha256": input_hash},
                "rule": {"id": "rule-a"},
            }
        ).encode() + b"\n"

    with systems._EvaluationJournalTailer(
        [project], tmp_path / "tailer-progress.jsonl"
    ) as tailer:
        with journal.open("ab") as handle:
            handle.write(record("evaluation_started", "eval-1", first_hash))
        journal.replace(journal.with_name(f"{journal.name}.1"))
        journal.write_bytes(
            record("evaluation_completed", "eval-1", first_hash)
            + record("evaluation_started", "eval-2", second_hash)
            + record("evaluation_completed", "eval-2", second_hash)
        )
        first = tailer.poll()
        assert first["new_terminal_keys"] == 2
        assert tailer.terminal_keys == {
            (str(project_root), first_hash, "rule-a"),
            (str(project_root), second_hash, "rule-a"),
        }
        second = tailer.poll()
        assert second["new_terminal_keys"] == 0
        assert second["records_read"] == 0
        assert tailer.named_inode_reachability()[
            "all_discovered_inodes_still_named"
        ]
        journal.with_name(f"{journal.name}.1").unlink()
        reachability = tailer.named_inode_reachability()
        assert not reachability["all_discovered_inodes_still_named"]
        assert len(reachability["unreachable_inodes"]) == 1


def test_soak_history_checkpoint_rejects_visibility_after_deadline(
    monkeypatch, tmp_path
):
    project_root = (tmp_path / "project").resolve()
    project_root.mkdir()
    project = systems.InstalledProject(0, project_root, tmp_path / "hook", tmp_path / "hooks")
    expected = [
        systems.ExpectedEvaluation("case", str(project_root), "a" * 64, "rule-a")
    ]
    row = {
        "project_root": str(project_root),
        "status": "completed",
        "input": {"sha256": "a" * 64},
        "rule": {"id": "rule-a"},
    }
    monkeypatch.setattr(
        systems,
        "_timed_evaluation_history",
        lambda _root: ([row], {"latency_ns": 1}),
    )
    monkeypatch.setattr(systems.time, "perf_counter_ns", lambda: 101)
    with systems._IncrementalJsonlWriter(tmp_path / "checkpoints.jsonl") as writer:
        _rows, checkpoint = systems._soak_history_checkpoint(
            [project],
            expected,
            batch_id="soak-r1-p1-offset0",
            deadline_ns=100,
            writer=writer,
        )

    assert not checkpoint["complete"]
    assert checkpoint["timed_out"]
    assert checkpoint["complete_after_deadline"]
    assert checkpoint["visible_monotonic_ns"] == 101


def test_matrix_wait_does_not_promote_query_crossing_deadline(monkeypatch, tmp_path):
    project_root = (tmp_path / "project").resolve()
    project_root.mkdir()
    project = systems.InstalledProject(0, project_root, tmp_path / "hook", tmp_path / "hooks")
    expected = [
        systems.ExpectedEvaluation("case", str(project_root), "a" * 64, "rule-a")
    ]
    row = {
        "project_root": str(project_root),
        "status": "completed",
        "input": {"sha256": "a" * 64},
        "rule": {"id": "rule-a"},
    }
    clock = iter((99, 101))
    monkeypatch.setattr(systems.time, "perf_counter_ns", lambda: next(clock))
    monkeypatch.setattr(
        systems,
        "_timed_evaluation_history",
        lambda _root: ([row], {"latency_ns": 2}),
    )
    _rows, _first, all_visible, wait = systems._wait_for_expected(
        [project], expected, {"a" * 64: 0}, timeout=1.0, deadline_ns=100
    )

    assert wait["timed_out"]
    assert all_visible == {}
    assert wait["after_deadline_visible_input_sha256"] == ["a" * 64]


def test_matrix_incremental_wait_keeps_confirmed_latency_but_fails_quiescence(
    monkeypatch, tmp_path
):
    project_root = (tmp_path / "project").resolve()
    project_root.mkdir()
    project = systems.InstalledProject(0, project_root, tmp_path / "hook", tmp_path / "hooks")
    expected = [
        systems.ExpectedEvaluation("case", str(project_root), "a" * 64, "rule-a")
    ]
    key = expected[0].key

    class FakeTailer:
        terminal_keys = {key}
        started = {}
        outcomes_before_start = set()
        polls = 0

        def poll(self):
            self.polls += 1
            if self.polls == 2:
                self.started = {"late-duplicate": key}
            return {
                "observed_monotonic_ns": 10 * self.polls,
                "inflight_evaluations": len(self.started),
                "outcomes_without_observed_start": 0,
            }

    row = {
        "project_root": str(project_root),
        "status": "completed",
        "input": {"sha256": "a" * 64},
        "rule": {"id": "rule-a"},
    }
    monkeypatch.setattr(systems.time, "perf_counter_ns", lambda: 0)
    monkeypatch.setattr(systems.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        systems,
        "_timed_evaluation_history",
        lambda _root, *, limit: (
            [row],
            {
                "project_root": str(project_root),
                "started_monotonic_ns": 11,
                "finished_monotonic_ns": 12,
                "latency_ns": 1,
                "rows": 1,
            },
        ),
    )
    with systems._IncrementalJsonlWriter(tmp_path / "matrix-checkpoints.jsonl") as writer:
        _rows, first, complete, wait = systems._wait_for_expected_incremental(
            [project],
            expected,
            {"a" * 64: 0},
            timeout=1.0,
            tailer=FakeTailer(),
            checkpoint_writer=writer,
            history_limits={str(project_root): 65},
            deadline_ns=100,
        )

    assert first["a" * 64] == 12
    assert complete["a" * 64] == 12
    assert not wait["timed_out"]
    assert wait["integrity_violation"]
    assert not wait["settle"]["complete"]
    assert len(wait["query_samples"]) == 1


def test_matrix_incremental_history_crossing_deadline_is_not_promoted(
    monkeypatch, tmp_path
):
    project_root = (tmp_path / "project").resolve()
    project_root.mkdir()
    project = systems.InstalledProject(0, project_root, tmp_path / "hook", tmp_path / "hooks")
    expected = [
        systems.ExpectedEvaluation("case", str(project_root), "a" * 64, "rule-a")
    ]
    key = expected[0].key

    class FakeTailer:
        terminal_keys = {key}
        started = {}
        outcomes_before_start = set()
        polls = 0

        def poll(self):
            self.polls += 1
            return {
                "observed_monotonic_ns": 90 if self.polls == 1 else 102,
                "inflight_evaluations": 0,
                "outcomes_without_observed_start": 0,
            }

    row = {
        "project_root": str(project_root),
        "status": "completed",
        "input": {"sha256": "a" * 64},
        "rule": {"id": "rule-a"},
    }
    clock = {"now": 0}
    monkeypatch.setattr(systems.time, "perf_counter_ns", lambda: clock["now"])
    monkeypatch.setattr(systems.time, "sleep", lambda _seconds: None)

    def late_history(_root, *, limit):
        clock["now"] = 101
        return [row], {
            "project_root": str(project_root),
            "started_monotonic_ns": 91,
            "finished_monotonic_ns": 101,
            "latency_ns": 10,
            "rows": 1,
        }

    monkeypatch.setattr(systems, "_timed_evaluation_history", late_history)
    with systems._IncrementalJsonlWriter(tmp_path / "matrix-late.jsonl") as writer:
        _rows, first, complete, wait = systems._wait_for_expected_incremental(
            [project],
            expected,
            {"a" * 64: 0},
            timeout=1.0,
            tailer=FakeTailer(),
            checkpoint_writer=writer,
            history_limits={str(project_root): 65},
            deadline_ns=100,
        )

    assert first == {}
    assert complete == {}
    assert wait["timed_out"]
    assert wait["after_deadline_visible_input_sha256"] == ["a" * 64]


def test_resource_sampler_surfaces_background_failure(monkeypatch, tmp_path):
    def broken(_pid):
        raise OSError("synthetic sampler failure")

    monkeypatch.setattr(systems, "_process_tree_snapshot", broken)
    sampler = systems._ResourceSampler(
        123,
        interval=0.001,
        journal_path=tmp_path / "resources.jsonl",
    )
    with pytest.raises(systems.SystemViolationError, match="sampler failed"):
        with sampler:
            sampler._thread.join(timeout=1.0)


def test_worker_timeout_injection_confirms_stopped_state_before_dispatch():
    class FakeProcess:
        def __init__(self):
            self.statuses = iter(
                (systems.psutil.STATUS_RUNNING, systems.psutil.STATUS_STOPPED)
            )

        def status(self):
            return next(self.statuses)

    observation = systems._wait_for_process_stopped(
        FakeProcess(), timeout_seconds=1.0
    )
    assert observation["confirmed"]
    assert [item["status"] for item in observation["observations"]] == [
        systems.psutil.STATUS_RUNNING,
        systems.psutil.STATUS_STOPPED,
    ]
    assert observation["finished_monotonic_ns"] <= observation[
        "deadline_monotonic_ns"
    ]

    source = inspect.getsource(systems._fault_worker_timeout)
    assert source.index("_wait_for_process_stopped(worker)") < source.index(
        "_invoke_raw(project.wrapper"
    )
    gate = inspect.getsource(systems._fault_passed)
    assert 'result.get("old_worker_confirmed_stopped_before_dispatch") is True' in gate


def test_malformed_fault_uses_final_exact_quiescence_not_early_count(
    monkeypatch, tmp_path
):
    project = tmp_path.resolve()

    def row(evaluation_id, input_hash):
        return {
            "evaluation_id": evaluation_id,
            "project_root": str(project),
            "status": "completed",
            "input": {"sha256": input_hash},
            "rule": {"id": "rule-a"},
            "outcome": {"type": "evaluation_completed", "result": "OK"},
        }

    expected = ("a" * 64, "b" * 64)
    exact_rows = [row("one", expected[0]), row("two", expected[1])]
    delayed_rows = [*exact_rows, row("late-malformed", "c" * 64)]
    scans = iter((exact_rows, delayed_rows))
    monkeypatch.setattr(
        systems, "_full_evaluation_history", lambda _root: next(scans)
    )
    monkeypatch.setattr(systems.time, "sleep", lambda _seconds: None)

    proof = systems._fault_evaluation_quiescence(
        project,
        baseline_evaluation_ids=set(),
        expected_input_sha256=expected,
    )
    assert not proof["complete"]
    assert not proof["stable_across_settle"]
    assert proof["before_settle"]["count"] == 2
    assert proof["after_settle"]["count"] == 3


def test_formal_main_captures_cache_end_after_run_study_abort(monkeypatch, tmp_path):
    attempts = tmp_path / "attempts"
    attempts.mkdir(mode=0o700)
    attempt = attempts / "abort-001"
    terminal_order = []
    monkeypatch.setattr(systems, "FORMAL_RAW_ATTEMPT_ROOT", attempts)
    monkeypatch.setattr(systems, "_validate_formal_config", lambda *_a, **_k: None)
    monkeypatch.setattr(
        systems,
        "_formal_contract",
        lambda: {
            "formal_runtime_profile": {
                "cache_and_dependency_receipt": {
                    "formal_attempt_root": str(attempts)
                }
            }
        },
    )
    monkeypatch.setattr(systems, "load_external_artifacts", lambda: object())
    monkeypatch.setattr(
        systems,
        "_launch_manifest",
        lambda attempt_dir, _config, plan, _bundle, *, formal: {
            "identity": {
                "attempt_id": attempt_dir.name,
                "study_mode": "formal",
                "git": {"commit": "a" * 40, "dirty": False},
            },
            "plan": list(plan),
        },
    )
    monkeypatch.setattr(
        systems,
        "run_study",
        lambda *_a, **_k: (_ for _ in ()).throw(
            systems.SystemsHarnessError("synthetic orchestrator abort")
        ),
    )
    def capture_cache_end(_bundle, _recorder):
        terminal_order.append("cache_end")
        return {"status": "completed", "sentinel": True}

    def capture_source_end(_attempt):
        terminal_order.append("source_end")
        return {"commit": "a" * 40, "dirty": False}

    monkeypatch.setattr(systems, "_capture_formal_cache_end", capture_cache_end)
    monkeypatch.setattr(systems, "_git_state_allowing_attempt", capture_source_end)
    real_recorder = systems.AttemptRecorder

    class TrackingRecorder(real_recorder):
        def __init__(self, root, manifest, *, capture_process_streams):
            super().__init__(root, manifest, capture_process_streams=False)

        def finalize(self, result):
            terminal_order.append("finalize")
            return super().finalize(result)

    monkeypatch.setattr(systems, "AttemptRecorder", TrackingRecorder)
    monkeypatch.setattr(
        systems.sys,
        "argv",
        [
            "run_scaling_faults.py",
            "--formal",
            "--attempt-dir",
            str(attempt),
            "--soak-events",
            str(systems.DEFAULT_SOAK_EVENTS),
        ],
    )

    assert systems.main() == 2
    result = json.loads((attempt / "result.json").read_text())
    assert result["global_outcomes"]["cache_end_receipt"]["sentinel"]
    assert result["status"] == "incomplete_harness_error"
    assert result["git"]["unchanged_during_attempt"]
    assert terminal_order == ["cache_end", "source_end", "finalize"]


def test_terminal_source_change_makes_completed_attempt_ineligible(monkeypatch):
    monkeypatch.setattr(
        systems,
        "_git_state_allowing_attempt",
        lambda _attempt: {"commit": "b" * 40, "dirty": False},
    )

    result = systems._finalize_source_state(
        {
            "status": "completed",
            "primary_numeric_eligible": True,
            "git": {
                "start": {"commit": "a" * 40, "dirty": False},
                "end": None,
                "unchanged_during_attempt": None,
                "end_receipt_pending": True,
            },
        },
        None,
    )

    assert result["status"] == "incomplete_unclassified_failure"
    assert result["primary_numeric_eligible"] is False
    assert result["git"]["end"]["commit"] == "b" * 40
    assert result["git"]["unchanged_during_attempt"] is False
    assert result["git"]["end_receipt_pending"] is False
    assert result["source_integrity_failure"]["rerun_eligible"] is False


def test_offline_daemon_start_failure_retains_completed_online_arm(
    monkeypatch, tmp_path
):
    artifact = _artifact("systemstest00001", "Offline fixture")
    attempt = (tmp_path / "formal-r02").resolve()
    retained_root = attempt / "runtime" / "offline"
    (attempt / "runtime").mkdir(parents=True)
    (attempt / "launch.json").write_text("{}\n", encoding="utf-8")
    job_id = str(
        int(hashlib.sha256((str(tmp_path) + "-offline").encode()).hexdigest()[:14], 16)
    )
    socket_root = Path("/tmp") / f"rf3-{job_id}"
    socket_root.mkdir(mode=0o700)
    monkeypatch.setenv("RAP_EACL_SOCKET_ROOT", str(socket_root))
    monkeypatch.setenv("SLURM_JOB_ID", job_id)
    monkeypatch.setenv("SLURM_JOB_PARTITION", "ALL")
    monkeypatch.setenv("SLURM_JOB_NODELIST", "watgpu108")
    projects = []
    for index in range(2):
        root = (tmp_path / f"project-{index}").resolve()
        root.mkdir()
        projects.append(
            systems.InstalledProject(
                index, root, tmp_path / f"hook-{index}", tmp_path / f"hooks-{index}"
            )
        )

    @systems.contextmanager
    def isolated(_root):
        yield dict(os.environ)

    starts = {"count": 0, "socket_paths": []}

    class FakeDaemon:
        pid = 123

    def start(_environment, diagnostics, _timeout):
        starts["count"] += 1
        starts["socket_paths"].append(_environment.get("RAP_SOCKET_PATH"))
        diagnostics.write_text(f"start-{starts['count']}\n")
        if starts["count"] == 2:
            raise RuntimeError("offline daemon blocked during startup")
        return FakeDaemon(), {"pid": 123, "instance": "online"}

    retained_rows = {"rows": []}

    def invoke(fixture, events, **_kwargs):
        expected = systems._expected_for_events(events, fixture.artifacts)
        input_hash = events[0][3]
        row = _row(fixture.projects[0].root, input_hash, artifact)
        retained_rows["rows"] = [row]
        return (
            [
                {
                    "input_sha256": input_hash,
                    "event_to_all_query_visible_evaluations_ns": 12,
                    "hook": {"contract_preserved": True},
                }
            ],
            expected,
            {str(fixture.projects[0].root): [row]},
            {"timed_out": False, "query_samples": []},
        )

    monkeypatch.setattr(systems.integrated, "_isolated_environment", isolated)
    monkeypatch.setattr(systems, "_install_projects", lambda *_a, **_k: projects)
    monkeypatch.setattr(systems.integrated, "_start_daemon", start)
    monkeypatch.setattr(systems.integrated, "_stop_daemon", lambda _daemon: None)
    monkeypatch.setattr(systems, "_warm_fixture", lambda *_a, **_k: None)
    monkeypatch.setattr(
        systems, "_full_evaluation_history", lambda _root: retained_rows["rows"]
    )
    monkeypatch.setattr(systems, "_full_findings", lambda _root: [])
    monkeypatch.setattr(systems, "_invoke_event_group", invoke)
    monkeypatch.setattr(
        systems,
        "_fixture_evidence",
        lambda *_a, **_k: {"retained": "online-evidence"},
    )

    try:
        result = systems.run_offline_after_prepare(
            (artifact,),
            rule_count=1,
            timeout=1.0,
            retained_root=retained_root,
        )
    finally:
        socket_root.rmdir()

    assert result["status"] == "system_violation"
    assert result["online"]["sample"]["event_to_all_query_visible_evaluations_ns"] == 12
    assert result["online"]["evidence"] == {"retained": "online-evidence"}
    assert result["offline"]["status"] == "system_violation"
    assert result["offline"]["stage"] == "daemon_start_under_socket_boundary"
    assert "offline daemon blocked" in result["offline"]["error"]["message"]
    assert result["offline"]["sample"] is None
    assert result["paired_event_to_all_latency"]["offline_ns"] is None
    assert starts["socket_paths"][0] == starts["socket_paths"][1]
    assert starts["socket_paths"][0].startswith(str(socket_root) + os.sep)
    assert (retained_root / "socket-endpoint.json").is_file()


def test_soak_post_settle_snapshot_precedes_global_journal_scan():
    source = inspect.getsource(systems.run_soak)

    snapshot = source.index(
        "post_drain_resources = _process_tree_snapshot(fixture.daemon.pid)"
    )
    reachability = source.index(
        "journal_reachability = tailer.named_inode_reachability()"
    )
    full_scan = source.index("final_journal_rows = {")
    assert snapshot < reachability < full_scan
    assert "true_drain_finished_ns = drain_observation_finished_ns" in source
    assert '"journal_scan_excluded_from_rss_window"' in source
    assert '"after": post_drain_resources' in source
    assert '"post_scan_diagnostic_not_used_for_claims": post_scan_resources' in source


def test_soak_rss_per_event_denominator_is_actual_submissions():
    source = inspect.getsource(systems.run_soak)
    metric = source.split('"rss_change_bytes_per_event":', 1)[1].split(
        '"rss_slope":', 1
    )[0]
    assert "/ offset" in metric
    assert "if offset" in metric
    assert '"field": "events_submitted"' in metric
    assert "/ event_count" not in metric


def test_soak_restart_gate_requires_installed_hook_contract():
    source = inspect.getsource(systems.run_soak)
    restart_gate = source.split("restart_failure = (", 1)[1].split(
        "system_violation =", 1
    )[0]
    assert 'restart_persistence.get("post_restart_event")' in restart_gate
    assert '"contract_preserved"' in restart_gate


def test_persisted_prediction_comparison_is_exact_and_detects_missing_rules():
    online = {
        "rule-a": {
            "status": "completed",
            "terminal_rows": 1,
            "error_code": None,
            "persisted_prediction_utf8_present": True,
            "persisted_prediction_utf8_hex": b"WARNING".hex(),
            "persisted_prediction_utf8_sha256": hashlib.sha256(b"WARNING").hexdigest(),
        }
    }
    assert systems.compare_persisted_predictions(online, dict(online))["exactly_equal"]

    changed = {"rule-a": {**online["rule-a"], "persisted_prediction_utf8_hex": b"OK".hex()}}
    mismatch = systems.compare_persisted_predictions(online, changed)
    assert not mismatch["exactly_equal"]
    assert mismatch["mismatches"][0]["rule_id"] == "rule-a"

    missing = systems.compare_persisted_predictions(online, {})
    assert not missing["exactly_equal"]

    absent_on_both = {
        "rule-a": {
            **online["rule-a"],
            "persisted_prediction_utf8_present": False,
            "persisted_prediction_utf8_hex": None,
            "persisted_prediction_utf8_sha256": None,
        }
    }
    comparison = systems.compare_persisted_predictions(
        absent_on_both, dict(absent_on_both)
    )
    assert not comparison["exactly_equal"]
    assert "online.persisted_prediction_utf8_present" in (
        comparison["first_difference"]["differing_fields"]
    )


@pytest.mark.parametrize("arm", ["online", "offline"])
def test_offline_comparison_gates_both_installed_hook_contracts(arm):
    clean_accounting = {name: 0 for name in systems.ACCOUNTING_FAILURE_KEYS}
    clean_accounting["findings"] = {
        "loss_count": 0,
        "duplicate_count": 0,
        "unexpected_count": 0,
        "cross_project_contamination_count": 0,
        "provenance_mismatch_count": 0,
    }
    samples = {
        "online": {"hook": {"contract_preserved": True}},
        "offline": {"hook": {"contract_preserved": True}},
    }
    samples[arm]["hook"]["contract_preserved"] = False
    assert systems._offline_arm_system_violation(
        {"timed_out": False}, clean_accounting, samples[arm]
    )
    other = "offline" if arm == "online" else "online"
    assert not systems._offline_arm_system_violation(
        {"timed_out": False}, clean_accounting, samples[other]
    )


def test_failed_persisted_prediction_has_absent_bytes(tmp_path):
    project = tmp_path.resolve()
    values = systems._persisted_predictions(
        {
            str(project): [
                {
                    "status": "failed",
                    "input": {"sha256": "a" * 64},
                    "rule": {"id": "rule-a"},
                    "outcome": {"error_code": "inference_timeout"},
                    "result": "",
                }
            ]
        },
        project=project,
        input_sha256="a" * 64,
        rule_ids=["rule-a"],
    )

    assert values["rule-a"]["persisted_prediction_utf8_present"] is False
    assert values["rule-a"]["persisted_prediction_utf8_hex"] is None


def test_named_python_socket_boundary_is_precise():
    boundary = systems._python_socket_boundary()
    assert boundary["id"] == "cpython_socket_api_inet_v1"
    assert boundary["blocked_families"] == ["AF_INET", "AF_INET6"]
    assert "socket.socket.sendto" in boundary["blocked_apis"]
    assert boundary["allowed"] == ["AF_UNIX local sockets"]


def test_fault_suite_retains_every_repetition_and_continues_after_errors(monkeypatch):
    artifact = _artifact("systemstest00001", "Fault fixture")

    def broken(*_args, **_kwargs):
        raise systems.SystemsHarnessError("synthetic injection failure")

    def logical_failure(*_args, **_kwargs):
        return {
            "persistent_state_integrity": {"ok": True},
            "worker_replaced": False,
            "recovery": {"accounting": {}},
        }

    monkeypatch.setattr(systems, "_fault_daemon_crash", broken)
    monkeypatch.setattr(systems, "_fault_worker_exit", logical_failure)
    result = systems.run_fault_suite(
        (artifact,),
        ("daemon_crash", "worker_exit"),
        timeout=0.01,
        repetitions=2,
        strict=True,
    )

    assert len(result["daemon_crash"]["attempts"]) == 2
    assert result["daemon_crash"]["repetitions_harness_error"] == 2
    assert len(result["worker_exit"]["attempts"]) == 2
    assert result["worker_exit"]["repetitions_system_violation"] == 2


def test_fault_cleanup_settle_waits_for_respawned_daemon_exit(monkeypatch, tmp_path):
    clock = iter((0, 1, 2, 3, 4))
    observations = iter(
        (
            [{"pid": 42, "cmdline": ["python", "-m", "rules_as_programs.daemon"]}],
            [],
        )
    )
    monkeypatch.setattr(systems.time, "perf_counter_ns", lambda: next(clock))
    monkeypatch.setattr(systems.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        systems, "_orphan_processes", lambda _root: next(observations)
    )

    settle = systems._wait_for_fault_process_cleanup(tmp_path, timeout=1.0)

    assert settle["status"] == "complete"
    assert settle["completed_within_deadline"] is True
    assert settle["final_orphan_processes"] == []
    assert [len(item["processes"]) for item in settle["observations"]] == [1, 0]


def test_fault_cleanup_observed_only_after_deadline_does_not_pass(monkeypatch, tmp_path):
    clock = iter((0, 1, 2, 9, 11))
    observations = iter(
        (
            [{"pid": 42, "cmdline": ["python", "-m", "rules_as_programs.daemon"]}],
            [],
        )
    )
    monkeypatch.setattr(systems.time, "perf_counter_ns", lambda: next(clock))
    monkeypatch.setattr(systems.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        systems, "_orphan_processes", lambda _root: next(observations)
    )

    settle = systems._wait_for_fault_process_cleanup(tmp_path, timeout=1e-8)
    result = {
        "persistent_state_integrity": {"ok": True},
        "orphan_process_count": 0,
        "post_shutdown_process_settle": settle,
        "hook_contracts_preserved": True,
        "evaluations": 1,
        "findings": 1,
        "ingress_duplicate_counter_delta": 1,
        "exactly_once_within_live_daemon_window": True,
    }

    assert settle["status"] == "timed_out"
    assert settle["completed_within_deadline"] is False
    assert systems._fault_passed("duplicate_delivery", result) is False


def test_fault_cleanup_access_denied_is_measurement_unknown(monkeypatch, tmp_path):
    class OwnUids:
        effective = systems.os.geteuid()

    class UnreadableProcess:
        pid = 77
        info = {"pid": 77, "uids": OwnUids()}

        @staticmethod
        def environ():
            raise systems.psutil.AccessDenied(pid=77)

    monkeypatch.setattr(
        systems.psutil, "process_iter", lambda _attrs: [UnreadableProcess()]
    )
    scan = systems._orphan_processes(tmp_path)
    assert scan["processes"] == []
    assert scan["scan_errors"][0]["pid"] == 77
    assert scan["scan_errors"][0]["type"] == "AccessDenied"

    clock = iter((0, 1, 11))
    monkeypatch.setattr(systems.time, "perf_counter_ns", lambda: next(clock))
    settle = systems._wait_for_fault_process_cleanup(tmp_path, timeout=1e-8)

    assert settle["status"] == "timed_out"
    assert settle["completed_within_deadline"] is False
    assert settle["final_orphan_processes"] == []
    assert settle["final_scan_errors"][0]["pid"] == 77

    class ForeignUids:
        effective = systems.os.geteuid() + 1

    class ForeignProcess:
        pid = 88
        info = {"pid": 88, "uids": ForeignUids()}

        @staticmethod
        def environ():
            raise AssertionError("foreign process environment must not be read")

    monkeypatch.setattr(
        systems.psutil, "process_iter", lambda _attrs: [ForeignProcess()]
    )
    foreign_scan = systems._orphan_processes(tmp_path)
    assert foreign_scan == {
        "processes": [],
        "scan_errors": [],
        "race_diagnostics": [],
    }


def test_force_cleanup_kills_only_exact_retained_process_identity(
    monkeypatch, tmp_path
):
    killed = []
    expected_state = str(tmp_path / "state")

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def create_time(self):
            return {10: 1.5, 11: 2.5}[self.pid]

        def environ(self):
            return {"RAP_STATE_DIR": expected_state}

        def cmdline(self):
            return ["python", "-m", "rules_as_programs.daemon"]

        def kill(self):
            killed.append(self.pid)

    monkeypatch.setattr(systems.psutil, "Process", Process)

    receipt = systems._force_terminate_fault_processes(
        tmp_path,
        [
            {"pid": 10, "create_time": 1.5, "cmdline": ["daemon"]},
            {"pid": 11, "create_time": 99.0, "cmdline": ["daemon"]},
        ],
    )

    assert killed == [10]
    assert [item["action"] for item in receipt["actions"]] == [
        "sigkill_sent",
        "skipped_identity_mismatch",
    ]
    assert receipt["actions"][0]["ownership_confirmed"] is True
    assert receipt["actions"][1]["ownership_confirmed"] is False


def test_failed_initial_settle_forces_exact_processes_and_rechecks(
    monkeypatch, tmp_path
):
    orphan = {"pid": 10, "create_time": 1.5, "cmdline": ["daemon"]}
    settles = iter(
        (
            {
                "status": "timed_out",
                "completed_within_deadline": False,
                "final_orphan_processes": [orphan],
            },
            {
                "status": "complete",
                "completed_within_deadline": True,
                "final_orphan_processes": [],
            },
        )
    )
    force_calls = []
    monkeypatch.setattr(
        systems, "_wait_for_fault_process_cleanup", lambda *_a: next(settles)
    )

    def force(root, processes):
        force_calls.append((root, processes))
        return {"status": "completed", "actions": [{"pid": 10}]}

    monkeypatch.setattr(systems, "_force_terminate_fault_processes", force)

    cleanup = systems._settle_and_force_fault_cleanup(tmp_path, 0.25)

    assert force_calls == [(tmp_path, [orphan])]
    assert cleanup["forced_actions"]["status"] == "completed"
    assert cleanup["final_settle"]["status"] == "complete"
    assert cleanup["safe_to_continue"] is True


def test_fault_exception_still_retains_cleanup_evidence(monkeypatch):
    artifact = _artifact("systemstest00001", "Fault fixture")
    calls = []
    settle = {
        "status": "not_measured_without_retained_runtime_root",
        "completed_within_deadline": False,
        "final_orphan_processes": None,
    }
    cleanup = {
        "initial_settle": settle,
        "forced_actions": None,
        "final_settle": settle,
        "measurable": False,
        "safe_to_continue": True,
        "final_orphan_processes": None,
    }

    def broken(*_args, **_kwargs):
        raise systems.SystemsHarnessError("synthetic probe error")

    def cleanup_probe(root, timeout):
        calls.append((root, timeout))
        return cleanup

    monkeypatch.setattr(systems, "_fault_daemon_crash", broken)
    monkeypatch.setattr(systems, "_settle_and_force_fault_cleanup", cleanup_probe)

    result = systems.run_fault_suite(
        (artifact,), ("daemon_crash",), timeout=0.25, repetitions=1
    )
    attempt = result["daemon_crash"]["attempts"][0]

    assert calls == [(None, 0.25)]
    assert attempt["status"] == "harness_error"
    assert attempt["probe_specific"]["post_shutdown_process_cleanup"] == cleanup
    assert (
        attempt["standardized_outcomes"]["post_shutdown_process_cleanup"]
        == cleanup
    )


def test_failed_forced_cleanup_records_violation_and_stops_subsequent_units(
    monkeypatch, tmp_path
):
    artifact = _artifact("systemstest00001", "Fault fixture")
    calls = []
    records = []

    class Recorder:
        root = tmp_path

        @staticmethod
        def record(component, unit_id, phase, value):
            records.append((component, unit_id, phase, value))

    def probe(*_args, **_kwargs):
        calls.append("probe")
        return {"persistent_state_integrity": {"ok": True}}

    timed_out = {
        "status": "timed_out",
        "completed_within_deadline": False,
        "final_orphan_processes": [
            {"pid": 42, "create_time": 1.5, "cmdline": ["daemon"]}
        ],
    }
    cleanup = {
        "initial_settle": timed_out,
        "forced_actions": {
            "status": "completed_with_errors",
            "actions": [{"pid": 42, "action": "kill_error"}],
        },
        "final_settle": timed_out,
        "measurable": True,
        "safe_to_continue": False,
        "final_orphan_processes": timed_out["final_orphan_processes"],
    }
    monkeypatch.setattr(systems, "_fault_daemon_crash", probe)
    monkeypatch.setattr(
        systems, "_settle_and_force_fault_cleanup", lambda *_a, **_k: cleanup
    )

    with pytest.raises(systems.SystemViolationError, match="subsequent units"):
        systems.run_fault_suite(
            (artifact,),
            ("daemon_crash",),
            timeout=0.25,
            repetitions=2,
            recorder=Recorder(),
        )

    assert calls == ["probe"]
    terminal = [item for item in records if item[2] == "terminal"]
    assert len(terminal) == 1
    assert terminal[0][3]["status"] == "system_violation"
    assert terminal[0][3]["cleanup_system_violation"]["cleanup"] == cleanup


def test_reducer_retains_missing_and_censored_attempts_and_standalone_matches(tmp_path):
    plan = [
        {
            "condition_id": "r1-p1-round_robin_across_projects-burst24-rep0",
            "rule_count": 1,
            "project_count": 1,
            "schedule": "round_robin_across_projects",
            "mode": "burst",
            "events": 24,
            "repeat": 0,
        },
        {
            "condition_id": "r1-p1-round_robin_across_projects-burst24-rep1",
            "rule_count": 1,
            "project_count": 1,
            "schedule": "round_robin_across_projects",
            "mode": "burst",
            "events": 24,
            "repeat": 1,
        },
    ]
    matrix = [
        {
            **plan[0],
            "event_count": 24,
            "status": "system_violation",
            "samples": [
                {
                    "event_to_all_query_visible_evaluations_ns": None,
                    "latency_censored_at_ns": 30_000_000_000,
                }
            ],
            "accounting": {"loss_count": 1},
        }
    ]
    reduced = systems.reduce_matrix_attempts(plan, matrix)
    assert reduced["plan_accounting"]["missing"] == [plan[1]["condition_id"]]
    cell = reduced["cells"][0]
    assert cell["failed_or_incomplete_attempts"] == 2
    assert cell["event_to_all_query_visible_evaluations"]["right_censored_count"] == 1
    assert cell["event_to_all_query_visible_evaluations"]["maximum_ns"] == (
        30_000_000_000
    )

def test_formal_gate_pins_every_latency_affecting_config_field(monkeypatch):
    feasible = tuple(
        name
        for name, capability in systems.FAULT_CAPABILITIES.items()
        if capability["feasible"]
    )
    monkeypatch.setenv("SLURM_JOB_PARTITION", "ALL")
    contract = json.loads(systems.FORMAL_AMENDMENT.read_text())
    contract["freeze_state"] = "frozen_outcome_aware_repair"
    contract["frozen_utc"] = "2026-08-30T17:45:00Z"
    monkeypatch.setattr(systems, "_formal_contract", lambda: contract)
    systems._validate_formal_config(
        systems.MatrixConfig(soak_events=systems.DEFAULT_SOAK_EVENTS),
        fault_names=feasible,
        run_offline_probe=True,
        strict=True,
        require_partition=True,
    )
    with pytest.raises(systems.SystemsHarnessError, match="warmups_per_project"):
        systems._validate_formal_config(
            systems.MatrixConfig(
                soak_events=systems.DEFAULT_SOAK_EVENTS,
                warmups_per_project=2,
            ),
            fault_names=feasible,
            run_offline_probe=True,
            strict=True,
            require_partition=True,
        )


def test_formal_contract_refuses_draft_even_when_hash_matches(monkeypatch, tmp_path):
    draft = json.loads(systems.FORMAL_AMENDMENT.read_text(encoding="utf-8"))
    draft["freeze_state"] = "draft_outcome_aware_repair"
    draft["frozen_utc"] = None
    draft_path = tmp_path / "draft-amendment.json"
    draft_path.write_text(json.dumps(draft, sort_keys=True) + "\n", encoding="utf-8")
    monkeypatch.setattr(systems, "FORMAL_AMENDMENT", draft_path)
    monkeypatch.setattr(
        systems,
        "FORMAL_AMENDMENT_SHA256",
        hashlib.sha256(draft_path.read_bytes()).hexdigest(),
    )
    with pytest.raises(systems.SystemsHarnessError, match="not frozen"):
        systems._formal_contract()


def test_formal_git_topology_requires_exact_three_commit_path_partition(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=repo, check=True, capture_output=True, text=True
        ).stdout.strip()

    git("init")
    git("config", "user.name", "Test Author")
    git("config", "user.email", "test@example.com")

    def commit(path, contents, message):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents)
        git("add", path)
        git("commit", "-m", message)
        return git("rev-parse", "HEAD")

    base = commit("base.txt", "base\n", "base")
    protocol = commit("protocol.json", "{}\n", "protocol")
    implementation = commit("runner.py", "print('runner')\n", "implementation")
    runtime_lock = commit("runtime-lock.json", "{}\n", "runtime lock")
    required = {
        "protocol_commit_parent_must_equal": base,
        "protocol_commit_diff_paths_exactly": ["protocol.json"],
        "implementation_commit_parent_must_equal_protocol_commit": True,
        "implementation_commit_diff_paths_exactly": ["runner.py"],
        "runtime_lock_commit_parent_must_equal_implementation_commit": True,
        "runtime_lock_commit_diff_paths_exactly": ["runtime-lock.json"],
        "head_must_equal_runtime_lock_commit": True,
    }
    monkeypatch.setattr(systems, "REPO_ROOT", repo)
    topology = systems._validate_formal_git_topology(runtime_lock, required)
    assert topology == {
        "protocol_parent": base,
        "protocol_commit": protocol,
        "implementation_commit": implementation,
        "runtime_lock_commit": runtime_lock,
        "head_equals_runtime_lock_commit": True,
        "commit_diff_paths": {
            "protocol": ["protocol.json"],
            "implementation": ["runner.py"],
            "runtime_lock": ["runtime-lock.json"],
        },
    }

    descendant = commit("extra.txt", "late change\n", "late descendant")
    with pytest.raises(systems.SystemsHarnessError, match="three-commit chronology"):
        systems._validate_formal_git_topology(descendant, required)


def test_replacement_launch_binding_requires_verified_immediate_predecessor(tmp_path):
    attempts = tmp_path / "attempts"
    predecessor = attempts / "formal-study-r01"
    predecessor.mkdir(parents=True)
    for name, value in (
        ("launch.json", {"identity": {"attempt_id": predecessor.name}}),
        ("plan.json", [{"component": "matrix", "unit_id": "c1"}]),
        (
            "publication.json",
            {
                "schema_version": 1,
                "destination": str(predecessor),
                "method": "native_no_replace",
                "native_primitive": "renameat2_RENAME_NOREPLACE",
                "native_unsupported": None,
                "claim": None,
            },
        ),
        ("result.json", {"status": "incomplete_harness_error"}),
    ):
        (predecessor / name).write_text(json.dumps(value) + "\n")
    (predecessor / "streams.json").write_text(
        json.dumps(
            {
                "stdout": "stdout.log",
                "stderr": "stderr.log",
                "capture": "synthetic",
                "lossless_from_launch": True,
            }
        )
        + "\n"
    )
    (predecessor / "stdout.log").write_text("")
    (predecessor / "stderr.log").write_text("")
    (predecessor / "units.jsonl").write_text("")
    evidence_path = tmp_path / "harness-traceback.txt"
    evidence_path.write_text("proven runner assertion failure\n")

    def receipt(path):
        resolved = path.resolve()
        return {
            "path": str(resolved),
            "bytes": resolved.stat().st_size,
            "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        }

    successor = attempts / "formal-study-r02"
    replacement = {
        "schema_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "successor_raw_attempt_id": successor.name,
        "predecessor_raw_attempt_id": predecessor.name,
        "classification": "harness_error",
        "original_status": "incomplete_harness_error",
        "reason": "proven assertion defect before the measurement boundary",
        "affected_boundary": "runner plan assertion",
        "predecessor_artifacts": {
            name: receipt(predecessor / name)
            for name in attempts_contract._PREDECESSOR_ARTIFACT_NAMES
        },
        "predecessor_tree": attempts_contract._predecessor_tree_receipts(predecessor),
        "evidence_receipts": [
            {"kind": "harness_traceback", **receipt(evidence_path)}
        ],
        "scheduler_adjudication": None,
    }
    replacement_path = tmp_path / "replacement.json"
    replacement_path.write_text(json.dumps(replacement, sort_keys=True) + "\n")

    initial = systems.replacement_launch_binding(
        attempts / "formal-study-r01", None
    )
    assert initial == {
        "kind": "initial_attempt",
        "raw_attempt_ordinal": 1,
        "successor_raw_attempt_id": "formal-study-r01",
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
    binding = systems.replacement_launch_binding(successor, str(replacement_path))
    assert binding["kind"] == "replacement_attempt"
    assert binding["predecessor_raw_attempt_id"] == predecessor.name
    assert binding["classification"] == "harness_error"
    assert binding["reason"] == replacement["reason"]
    assert binding["receipt_sha256"] == hashlib.sha256(
        replacement_path.read_bytes()
    ).hexdigest()
    retention, copy_specs = systems._replacement_retention_plan(binding)
    systems.AttemptRecorder(
        successor,
        {
            "identity": {"replacement_retention": retention},
            "plan": [],
            "_prelaunch_copy_specs": copy_specs,
        },
    )
    launch = json.loads((successor / "launch.json").read_text())
    assert "_prelaunch_copy_specs" not in launch
    for retained in retention["copies"]:
        copied = successor / retained["retained_path"]
        assert copied.is_file()
        assert hashlib.sha256(copied.read_bytes()).hexdigest() == retained["sha256"]

    replacement["classification"] = "system_violation"
    replacement_path.unlink()
    replacement_path.write_text(json.dumps(replacement, sort_keys=True) + "\n")
    with pytest.raises(systems.SystemsHarnessError, match="classification"):
        systems.replacement_launch_binding(successor, str(replacement_path))

    replacement["classification"] = "harness_error"
    replacement["original_status"] = "incomplete_unclassified_failure"
    (predecessor / "result.json").write_text(
        json.dumps({"status": "incomplete_unclassified_failure"}) + "\n"
    )
    replacement["predecessor_artifacts"]["result.json"] = receipt(
        predecessor / "result.json"
    )
    replacement["predecessor_tree"] = (
        attempts_contract._predecessor_tree_receipts(predecessor)
    )
    replacement_path.write_text(json.dumps(replacement, sort_keys=True) + "\n")
    with pytest.raises(systems.SystemsHarnessError, match="not eligible"):
        systems.replacement_launch_binding(successor, str(replacement_path))

    replacement["original_status"] = "completed_with_system_violations"
    (predecessor / "result.json").write_text(
        json.dumps({"status": "completed_with_system_violations"}) + "\n"
    )
    replacement["predecessor_artifacts"]["result.json"] = receipt(
        predecessor / "result.json"
    )
    replacement["predecessor_tree"] = (
        attempts_contract._predecessor_tree_receipts(predecessor)
    )
    replacement_path.write_text(json.dumps(replacement, sort_keys=True) + "\n")
    with pytest.raises(systems.SystemsHarnessError, match="not eligible"):
        systems.replacement_launch_binding(successor, str(replacement_path))


def test_replacement_binding_rejects_symlinked_attempt_ancestor(tmp_path):
    real_attempts = tmp_path / "real-attempts"
    real_attempts.mkdir()
    linked_attempts = tmp_path / "linked-attempts"
    linked_attempts.symlink_to(real_attempts, target_is_directory=True)

    with pytest.raises(systems.SystemsHarnessError, match="symlink path component"):
        systems.replacement_launch_binding(
            linked_attempts / "formal-study-r01", None
        )


def test_publication_fsync_warning_aborts_before_measurement(tmp_path):
    recorder = attempts_contract.AttemptRecorder(
        tmp_path / "formal-study-r01",
        {
            "identity": {"git": {"commit": "a" * 40, "dirty": False}},
            "plan": [],
        },
    )
    recorder._initialization_warnings.append("synthetic parent fsync failure")

    result = systems._artifact_initialization_abort_result(
        recorder,
        config=systems.MatrixConfig(),
        plan=[],
        formal=True,
    )

    assert result is not None
    assert result["status"] == "incomplete_infrastructure_error"
    assert result["abort"]["status"] == "infrastructure_error"
    assert result["terminal_unit_count"] == 0


def test_runtime_preflight_retention_is_self_contained(tmp_path):
    receipt = tmp_path / "setup-receipt.json"
    log = tmp_path / "setup.log"
    receipt.write_text('{"schema_version":1}\n')
    log.write_text("offline setup complete\n")

    def file_value(path):
        return {
            "path": str(path),
            "resolved_path": str(path.resolve()),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    retention, copies = systems._runtime_preflight_retention_plan(
        {
            "setup_preflight_receipt": {"file": file_value(receipt)},
            "setup_preflight_log": file_value(log),
        }
    )
    assert retention["self_contained"]
    assert [item["retained_path"] for item in retention["copies"]] == [
        "runtime/preflight/setup-receipt.json",
        "runtime/preflight/setup.log",
    ]
    attempt = tmp_path / "attempt"
    systems.AttemptRecorder(
        attempt,
        {
            "identity": {"runtime_preflight_retention": retention},
            "plan": [],
            "_prelaunch_copy_specs": copies,
        },
    )
    assert (attempt / "runtime/preflight/setup-receipt.json").read_bytes() == (
        receipt.read_bytes()
    )
    assert (attempt / "runtime/preflight/setup.log").read_bytes() == log.read_bytes()


def test_runtime_setup_chain_is_the_same_object_bound_by_launch_identity():
    launch_source = inspect.getsource(systems._launch_manifest)
    runtime_source = inspect.getsource(systems_runtime.formal_runtime_receipt)
    assert "expected_replacement_chain=replacement" in launch_source
    assert '"attempt_replacement": replacement' in launch_source
    assert '"replacement_chain": dict(expected_replacement_chain)' in runtime_source


def test_runtime_lock_rejects_any_external_inventory_change(tmp_path):
    wheelhouse = {
        "root": "/runtime/wheelhouse",
        "files": [{"path": "a.whl", "bytes": 1, "sha256": "a" * 64}],
    }
    cache = {
        "root": "/runtime/cache",
        "complete_tree": {
            "files": [{"path": "model", "bytes": 2, "sha256": "b" * 64}]
        },
    }
    lock_path = tmp_path / "formal-runtime-lock-v3.json"
    lock_path.write_text(
        json.dumps(
            {"schema_version": 1, "wheelhouse": wheelhouse, "paw_cache": cache}
        )
    )

    receipt = systems_runtime.validate_runtime_lock(
        lock_path, wheelhouse=wheelhouse, paw_cache=cache
    )
    assert receipt["content"]["schema_version"] == 1
    with pytest.raises(systems_runtime.RuntimeContractError, match="lock mismatch"):
        systems_runtime.validate_runtime_lock(
            lock_path,
            wheelhouse={**wheelhouse, "files": []},
            paw_cache=cache,
        )


def test_cache_receipt_uses_nested_cache_and_gates_n_ctx(tmp_path):
    cache = tmp_path / "cache"
    content = cache / "programasweights"
    program_id = "program-1"
    program = content / "programs" / program_id
    program.mkdir(parents=True)
    runtime = {
        "runtime_id": "runtime-1",
        "local_sdk": {
            "n_ctx": 2048,
            "base_model": {"file": "model.gguf", "size_bytes": 5},
        },
    }
    (program / "adapter.gguf").write_bytes(b"adapter")
    (program / "prompt_template.txt").write_text("prompt")
    (program / "meta.json").write_text(
        json.dumps({"program_id": program_id, "runtime": runtime})
    )
    (content / "runtimes").mkdir()
    (content / "runtimes" / "runtime-1.json").write_text(json.dumps(runtime))
    (content / "base_models").mkdir()
    (content / "base_models" / "model.gguf").write_bytes(b"model")

    receipt = systems_runtime.cache_receipt(
        cache, [program_id], required_n_ctx=2048
    )
    assert receipt["programasweights_subtree"] == str(content.resolve())
    assert receipt["runtime_manifests"]["runtime-1"]["canonical_json_equal"]
    assert receipt["complete_tree"]["file_count"] == 5
    with pytest.raises(systems_runtime.RuntimeContractError, match="n_ctx mismatch"):
        systems_runtime.cache_receipt(cache, [program_id], required_n_ctx=4096)

    (program / "meta.json").write_text("{corrupt")
    outside = tmp_path / "outside-model"
    outside.write_bytes(b"outside")
    model_path = content / "base_models" / "model.gguf"
    model_path.unlink()
    os.symlink(outside, model_path)
    end = systems_runtime.retain_cache_end_receipt(
        {
            "cache_and_dependency_receipt": {"formal_cache_dir": str(cache)},
            "cpu_and_inference": {"paw_function_n_ctx": 2048},
        },
        [program_id],
        launch_receipt=receipt,
        changed_files_root=tmp_path / "changed-cache-files",
    )
    assert end["status"] == "system_violation"
    assert end["strict_validation_error"] is not None
    assert "programs/program-1/meta.json" in end["changed_or_new"]
    assert "base_models/model.gguf" in end["deleted"]
    assert "base_models/model.gguf" in end["non_regular_or_symlink"]
    assert (tmp_path / "changed-cache-files/programs/program-1/meta.json").is_file()


def test_scheduler_receipt_rejects_cuda_visible_device(monkeypatch):
    profile = {
        "scheduler": {
            "partition": "ALL",
            "node_list": "watgpu108",
            "cpus_per_task": 8,
            "minimum_memory_mib": 16000,
            "minimum_time_limit_seconds": 604800,
        },
        "cpu_and_inference": {"affinity_cardinality": 8},
    }
    environment = {
        "SLURM_JOB_ID": "12345",
        "SLURM_JOB_PARTITION": "ALL",
        "SLURM_JOB_NODELIST": "watgpu108",
        "SLURM_CPUS_PER_TASK": "8",
        "SLURM_MEM_PER_NODE": "16G",
        "CUDA_VISIBLE_DEVICES": "",
    }
    scontrol = (
        "JobId=12345 JobState=RUNNING Partition=ALL NodeList=watgpu108 "
        "NumCPUs=8 AllocTRES=cpu=8,mem=16G TimeLimit=7-00:00:00"
    )
    monkeypatch.setattr(systems_runtime.platform, "node", lambda: "watgpu108")

    receipt = systems_runtime.scheduler_receipt(
        profile,
        environ=environment,
        affinity=range(8),
        scontrol_raw=scontrol,
    )
    assert receipt["time_limit_seconds"] == 604800
    with pytest.raises(systems_runtime.RuntimeContractError, match="CUDA_VISIBLE"):
        systems_runtime.scheduler_receipt(
            profile,
            environ={**environment, "CUDA_VISIBLE_DEVICES": "0"},
            affinity=range(8),
            scontrol_raw=scontrol,
        )


def test_deterministic_production_path_smoke_has_exact_multi_project_accounting():
    artifacts = (
        _artifact("systemstest00001", "First system rule"),
        _artifact("systemstest00002", "Second system rule"),
    )

    result = systems.run_condition(
        artifacts,
        rule_count=2,
        project_count=2,
        mode="burst",
        event_count=4,
        repeat=0,
        warmups_per_project=0,
        timeout=10.0,
        max_hook_workers=4,
    )

    accounting = result["accounting"]
    assert accounting["evaluations_expected"] == 8
    assert accounting["evaluations_observed_for_expected_keys"] == 8
    assert accounting["loss_count"] == 0
    assert accounting["duplicate_count"] == 0
    assert accounting["cross_project_contamination_count"] == 0
    assert accounting["failed_count"] == 0
    assert accounting["provenance_mismatch_count"] == 0
    assert result["resources"]["peak_sampled_rss_bytes"] > 0
    assert result["storage"]["delta"]["total_runtime_bytes"] > 0


def test_node_local_socket_override_runs_real_production_path(monkeypatch, tmp_path):
    artifact = _artifact("systemstest00001", "Short socket production rule")
    attempt = (tmp_path / "formal-r02").resolve()
    unit_id = "r1-p1-round_robin_across_projects-sequential1-rep0"
    retained = attempt / "runtime" / "matrix" / unit_id
    retained.parent.mkdir(parents=True)
    (attempt / "launch.json").write_text("{}\n", encoding="utf-8")
    job_id = str(
        int(hashlib.sha256((str(tmp_path) + "-real").encode()).hexdigest()[:14], 16)
    )
    socket_root = Path("/tmp") / f"rf3-{job_id}"
    socket_root.mkdir(mode=0o700)
    monkeypatch.setenv("RAP_EACL_SOCKET_ROOT", str(socket_root))
    monkeypatch.setenv("SLURM_JOB_ID", job_id)
    monkeypatch.setenv("SLURM_JOB_PARTITION", "ALL")
    monkeypatch.setenv("SLURM_JOB_NODELIST", "watgpu108")
    try:
        result = systems.run_condition(
            (artifact,),
            rule_count=1,
            project_count=1,
            mode="sequential",
            event_count=1,
            repeat=0,
            warmups_per_project=0,
            timeout=10.0,
            max_hook_workers=1,
            retained_root=retained,
        )
        receipt = json.loads((retained / "socket-endpoint.json").read_text())
        assert result["status"] == "completed"
        assert result["accounting"]["evaluations_expected"] == 1
        assert result["accounting"]["loss_count"] == 0
        assert receipt["endpoint"].startswith(str(socket_root) + os.sep)
        assert receipt["encoded_pathname_bytes"] <= 107
        assert not os.path.lexists(receipt["endpoint"])
    finally:
        socket_root.rmdir()
