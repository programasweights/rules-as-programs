from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import pytest

from experiments.eacl2027 import run_scaling_faults as systems


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

    assert len(plan) == 4 * 3 * 3 * 5 * 2
    assert len({item["condition_id"] for item in plan}) == len(plan)
    assert {item["rule_count"] for item in plan} == {1, 2, 4, 8}
    assert {item["project_count"] for item in plan} == {1, 4, 8}
    assert {(item["mode"], item["events"]) for item in plan} == {
        ("sequential", 250),
        ("burst", 24),
        ("burst", 64),
    }
    assert {item["schedule"] for item in plan} == set(systems.TRAFFIC_PATTERNS)
    assert all(item["fresh_daemon"] and item["fresh_state"] for item in plan)


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
