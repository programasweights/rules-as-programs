from __future__ import annotations

import json
import time
from pathlib import Path

import psutil
import pytest

from experiments.eacl2027 import run_integrated as integrated
from experiments.eacl2027.run_integrated import (
    IntegratedExperimentError,
    _finding_accounting,
    _nearest_rank,
    _process_tree_resources,
    _program_id,
    _require_frozen_configuration,
    _start_daemon,
    _summary,
    _wait_for_finding,
)


def test_integrated_nearest_rank_summary_is_explicit():
    values = [1.0, 2.0, 3.0, 4.0, 100.0]

    assert _nearest_rank(values, 50) == 3.0
    assert _nearest_rank(values, 95) == 100.0
    assert _summary(values) == {
        "unit": "ms",
        "count": 5,
        "minimum": 1.0,
        "mean": 22.0,
        "p50_nearest_rank": 3.0,
        "p95_nearest_rank": 100.0,
        "p99_nearest_rank": 100.0,
        "maximum": 100.0,
    }


def test_integrated_program_is_pinned_by_frozen_manifest():
    assert _program_id() == "b619825b8bc23bab4c07"


def test_integrated_program_rejects_stale_rule_source(monkeypatch, tmp_path):
    rule_path = tmp_path / "rule.py"
    dataset_path = tmp_path / "controlled.jsonl"
    output_path = tmp_path / "paw.jsonl"
    manifest_path = tmp_path / "paw.jsonl.manifest.json"
    old_source_hash = integrated.hashlib.sha256(b"old source").hexdigest()
    rule_path.write_text("new source", encoding="utf-8")
    case = {
        "rule_id": integrated.RULE_ID,
        "source_hash": old_source_hash,
        "program_id": "program-id",
    }
    dataset_path.write_text(json.dumps(case) + "\n", encoding="utf-8")
    output_path.write_text(json.dumps(case) + "\n", encoding="utf-8")
    manifest = {
        "program_ids": {integrated.RULE_ID: "program-id"},
        "compiler": integrated.COMPILER,
        "compiler_info": {
            integrated.RULE_ID: {"latest_snapshot": integrated.COMPILER_SNAPSHOT}
        },
        "dataset": dataset_path.name,
        "dataset_sha256": integrated._sha256_file(dataset_path),
        "output_sha256": integrated._sha256_file(output_path),
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(integrated, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(integrated, "RULE_PATH", rule_path)
    monkeypatch.setattr(integrated, "PAW_MANIFEST", manifest_path)
    monkeypatch.setattr(integrated, "PAW_OUTPUT", output_path)

    with pytest.raises(IntegratedExperimentError, match="current rule source"):
        _program_id()


def _finding(text: str) -> dict:
    return {"evaluation": {"input": {"text": text}}}


def test_integrated_accounting_distinguishes_loss_duplicate_and_unexpected():
    accounting = _finding_accounting(
        [_finding("one"), _finding("one"), _finding("other")],
        ["one", "two"],
    )

    assert accounting == {
        "findings_expected": 2,
        "findings_observed": 3,
        "expected_inputs_observed": 1,
        "loss_count": 1,
        "duplicate_findings": 1,
        "unexpected_findings": 1,
    }


def test_integrated_accounting_rejects_duplicate_expected_inputs():
    with pytest.raises(
        IntegratedExperimentError,
        match="duplicate expected inputs",
    ):
        _finding_accounting([], ["same", "same"])


def test_integrated_startup_failure_terminates_process_and_closes_log(
    monkeypatch, tmp_path
):
    class FakeProcess:
        pid = 4242

    process = FakeProcess()
    terminated = []

    monkeypatch.setattr(integrated.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        integrated,
        "_wait_for_daemon",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            IntegratedExperimentError("startup timeout")
        ),
    )
    monkeypatch.setattr(
        integrated,
        "_force_terminate_process",
        lambda candidate: terminated.append(candidate),
    )

    with pytest.raises(IntegratedExperimentError, match="startup timeout"):
        _start_daemon({}, tmp_path / "daemon.log", 0.01)

    assert terminated == [process]
    assert process._rap_diagnostics_handle.closed


def test_integrated_resource_probe_tolerates_process_exit(monkeypatch):
    def missing_process(_pid):
        raise psutil.NoSuchProcess(_pid)

    monkeypatch.setattr(integrated.psutil, "Process", missing_process)

    assert _process_tree_resources(12345) == {
        "processes": 0,
        "rss_bytes": 0,
        "cpu_seconds": 0.0,
    }


def test_integrated_frozen_output_requires_protocol_parameters_and_clean_git(
    monkeypatch, tmp_path
):
    frozen = tmp_path / "integrated.json"
    monkeypatch.setattr(integrated, "FROZEN_OUTPUT", frozen)
    monkeypatch.setattr(
        integrated,
        "_git_state",
        lambda: {"commit": "a" * 40, "dirty": False, "scope": []},
    )

    clean = _require_frozen_configuration(
        integrated.DEFAULT_SEQUENTIAL_REPETITIONS,
        integrated.DEFAULT_BURST_SIZE,
        integrated.DEFAULT_WARMUPS,
        integrated.DEFAULT_TIMEOUT_SECONDS,
    )
    assert clean == {"commit": "a" * 40, "dirty": False, "scope": []}

    with pytest.raises(IntegratedExperimentError, match="differ from protocol"):
        _require_frozen_configuration(
            integrated.DEFAULT_SEQUENTIAL_REPETITIONS - 1,
            integrated.DEFAULT_BURST_SIZE,
            integrated.DEFAULT_WARMUPS,
            integrated.DEFAULT_TIMEOUT_SECONDS,
        )

    monkeypatch.setattr(
        integrated,
        "_git_state",
        lambda: {"commit": "a" * 40, "dirty": True, "scope": []},
    )
    with pytest.raises(IntegratedExperimentError, match="clean scoped Git commit"):
        _require_frozen_configuration(
            integrated.DEFAULT_SEQUENTIAL_REPETITIONS,
            integrated.DEFAULT_BURST_SIZE,
            integrated.DEFAULT_WARMUPS,
            integrated.DEFAULT_TIMEOUT_SECONDS,
        )

    monkeypatch.setattr(
        integrated,
        "_git_state",
        lambda: {"commit": "a" * 40, "dirty": False, "scope": []},
    )
    frozen.write_text("existing\n", encoding="utf-8")
    with pytest.raises(IntegratedExperimentError, match="already exists"):
        _require_frozen_configuration(
            integrated.DEFAULT_SEQUENTIAL_REPETITIONS,
            integrated.DEFAULT_BURST_SIZE,
            integrated.DEFAULT_WARMUPS,
            integrated.DEFAULT_TIMEOUT_SECONDS,
        )


def test_integrated_finding_timeout_is_measured_from_hook_launch(monkeypatch):
    monkeypatch.setattr(
        integrated,
        "_finding_for_input",
        lambda *args, **kwargs: pytest.fail("expired probe should not query"),
    )
    started_ns = time.perf_counter_ns() - 2_000_000_000

    with pytest.raises(IntegratedExperimentError, match="did not become query-visible"):
        _wait_for_finding(Path("/tmp"), "input", started_ns, 1.0)
