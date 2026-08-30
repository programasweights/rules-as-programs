from __future__ import annotations

import json
import random
import shutil
from collections import defaultdict
from pathlib import Path

import pytest

from experiments.eacl2027 import analyze_paired


EXPERIMENT_ROOT = Path(__file__).resolve().parents[1] / "experiments" / "eacl2027"


def _rows(predictions: dict[str, str], system: str) -> list[dict]:
    rows = []
    for case_id, prediction in predictions.items():
        pair_id = case_id.rsplit("-", 1)[0]
        expected = "WARNING"
        rows.append(
            {
                "case_id": case_id,
                "pair_id": pair_id,
                "rule_id": "rule",
                "hook": "Stop",
                "input": case_id,
                "expected": expected,
                "prediction": prediction,
                "correct": prediction == expected,
                "latency_ms": 1.0,
                "system": system,
            }
        )
    return rows


def test_paired_bootstrap_reuses_identical_cluster_draws_for_both_systems():
    predictions = {
        "pair-1-a": "WARNING",
        "pair-1-b": "OK",
        "pair-2-a": "WARNING",
        "pair-2-b": "WARNING",
    }
    focal = _rows(predictions, "focal")
    comparator = _rows(predictions, "comparator")

    intervals = analyze_paired._paired_bootstrap(focal, comparator, 100, 7)

    assert intervals == {
        "exact_accuracy_delta": {"low": 0.0, "high": 0.0},
        "macro_f1_delta": {"low": 0.0, "high": 0.0},
    }


def test_optimized_bootstrap_matches_naive_shared_cluster_resampling():
    frozen = EXPERIMENT_ROOT / "outputs" / "frozen"
    focal = analyze_paired._load_jsonl(frozen / "paw-finetuned.jsonl")
    comparator = analyze_paired._load_jsonl(frozen / "qwen3-4b.jsonl")
    samples = 100
    seed = 19

    actual = analyze_paired._paired_bootstrap(focal, comparator, samples, seed)

    focal_by_case = {row["case_id"]: row for row in focal}
    comparator_by_case = {row["case_id"]: row for row in comparator}
    pairs = analyze_paired._pair_case_ids(focal)
    pair_ids = sorted(pairs)
    rng = random.Random(seed)
    draws = defaultdict(list)
    for _ in range(samples):
        sampled_focal = []
        sampled_comparator = []
        for pair_id in rng.choices(pair_ids, k=len(pair_ids)):
            for case_id in pairs[pair_id]:
                sampled_focal.append(focal_by_case[case_id])
                sampled_comparator.append(comparator_by_case[case_id])
        focal_metrics = analyze_paired._selected_metrics(sampled_focal)
        comparator_metrics = analyze_paired._selected_metrics(sampled_comparator)
        for metric in ("macro_f1", "exact_accuracy"):
            draws[metric].append(focal_metrics[metric] - comparator_metrics[metric])
    expected = {
        f"{metric}_delta": {
            "low": analyze_paired._percentile(values, 0.025),
            "high": analyze_paired._percentile(values, 0.975),
        }
        for metric, values in sorted(draws.items())
    }

    assert actual == expected


def test_exact_randomization_keeps_each_two_case_pair_intact():
    focal_predictions = {}
    comparator_predictions = {}
    for index in range(3):
        focal_predictions[f"pair-{index}-a"] = "WARNING"
        focal_predictions[f"pair-{index}-b"] = "WARNING"
        comparator_predictions[f"pair-{index}-a"] = "WARNING"
        comparator_predictions[f"pair-{index}-b"] = "OK"
    focal_rows = _rows(focal_predictions, "focal")
    comparator_rows = _rows(comparator_predictions, "comparator")
    focal = {row["case_id"]: row for row in focal_rows}
    comparator = {row["case_id"]: row for row in comparator_rows}
    pairs = analyze_paired._pair_case_ids(focal_rows)

    result = analyze_paired._exact_paired_cluster_randomization(
        focal, comparator, pairs, analyze_paired._exact_correct
    )

    assert result["observed_correct_case_difference"] == 3
    assert result["nonzero_pair_contributions"] == 3
    assert result["exact_fraction"] == {
        "extreme_assignments": "2",
        "effective_assignments": "8",
    }
    assert result["p_value"] == 0.25


def test_holm_adjustment_is_monotone_across_declared_comparators():
    comparisons = {
        "first": {"exact_label_correctness": {"exact_paired_test": {"p_value": 0.01}}},
        "second": {"exact_label_correctness": {"exact_paired_test": {"p_value": 0.03}}},
    }

    analyze_paired._add_holm_adjustment(comparisons, "exact_label_correctness")

    first = comparisons["first"]["exact_label_correctness"]["exact_paired_test"]
    second = comparisons["second"]["exact_label_correctness"]["exact_paired_test"]
    assert first["holm_adjusted_p_value"] == 0.02
    assert second["holm_adjusted_p_value"] == 0.03
    assert first["holm_family"] == ["first", "second"]
    assert second["reject_at_0.05_after_holm"] is True


def test_inventory_contains_disagreements_and_shared_errors():
    cases = {
        "pair-1-a": {
            "paw_finetuned": "WARNING",
            "qwen3_4b": "WARNING",
            "lexical": "WARNING",
        },
        "pair-1-b": {
            "paw_finetuned": "WARNING",
            "qwen3_4b": "OK",
            "lexical": "OK",
        },
        "pair-2-a": {
            "paw_finetuned": "OK",
            "qwen3_4b": "OK",
            "lexical": "OK",
        },
        "pair-2-b": {
            "paw_finetuned": "WARNING",
            "qwen3_4b": "WARNING",
            "lexical": "WARNING",
        },
    }
    # _rows fixes every expected label to WARNING, so pair-2-a is a shared error.
    runs = {}
    for key in analyze_paired.RUN_SPECS:
        rows = _rows(
            {case_id: predictions[key] for case_id, predictions in cases.items()},
            key,
        )
        runs[key] = {"by_case": {row["case_id"]: row for row in rows}}

    inventory = analyze_paired._inventory_rows(runs)

    assert [row["case_id"] for row in inventory] == ["pair-1-b", "pair-2-a"]
    assert inventory[0]["has_prediction_disagreement"] is True
    assert inventory[0]["comparisons"]["qwen3_4b"]["focal_advantage_exact"]
    assert inventory[1]["has_prediction_disagreement"] is False
    assert inventory[1]["has_any_exact_error"] is True


def test_frozen_run_validation_rejects_dirty_provenance(tmp_path):
    source = EXPERIMENT_ROOT / "outputs" / "frozen"
    copied = tmp_path / "frozen"
    copied.mkdir()
    for spec in analyze_paired.RUN_SPECS.values():
        run = source / str(spec["filename"])
        manifest = run.with_suffix(run.suffix + ".manifest.json")
        shutil.copy2(run, copied / run.name)
        shutil.copy2(manifest, copied / manifest.name)
    qwen_manifest = copied / "qwen3-4b.jsonl.manifest.json"
    value = json.loads(qwen_manifest.read_text(encoding="utf-8"))
    value["git"]["dirty"] = True
    qwen_manifest.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    dataset_rows = analyze_paired._load_jsonl(analyze_paired.DATASET)

    with pytest.raises(SystemExit, match="frozen run is not clean"):
        analyze_paired._validate_frozen_runs(
            copied,
            analyze_paired._sha256(analyze_paired.DATASET),
            len(dataset_rows),
            analyze_paired._dataset_signatures(dataset_rows),
        )


def test_versioned_output_preflight_refuses_different_existing_file(tmp_path):
    output = tmp_path / "paired-v1.json"
    output.write_bytes(b"old\n")

    with pytest.raises(SystemExit, match="refusing to overwrite"):
        analyze_paired._preflight_outputs({output: b"new\n"})


def test_frozen_paired_outputs_reproduce_byte_for_byte_when_present():
    summary_path = analyze_paired.DEFAULT_OUTPUT
    inventory_path = analyze_paired.DEFAULT_INVENTORY
    if not summary_path.is_file() or not inventory_path.is_file():
        pytest.skip("versioned paired outputs have not been generated yet")

    summary, inventory = analyze_paired.build_outputs()

    assert summary == summary_path.read_bytes()
    assert inventory == inventory_path.read_bytes()
    value = json.loads(summary)
    snapshots = value["provenance"]["inputs"]["paw_finetuned"]["compiler_snapshots"]
    assert set(snapshots.values()) == {"paw-ft-bs48-20260530"}
