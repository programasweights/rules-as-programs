from __future__ import annotations

import random

import pytest

from experiments.eacl2027 import analyze_matched_backbone as analysis


def _rows(predictions: dict[str, str]) -> list[dict]:
    rows = []
    for rule in ("rule-a", "rule-b"):
        for pair in ("pair-1", "pair-2"):
            for expected in ("WARNING", "OK"):
                case_id = f"{rule}-{pair}-{expected}"
                prediction = predictions.get(case_id, expected)
                rows.append(
                    {
                        "case_id": case_id,
                        "pair_id": f"{rule}-{pair}",
                        "rule_id": rule,
                        "hook": "Stop",
                        "input": case_id,
                        "expected": expected,
                        "prediction": prediction,
                        "correct": prediction == expected,
                    }
                )
    return rows


def test_metrics_are_rule_macro_positive_f1_and_full_label_exact():
    rows = _rows(
        {
            "rule-a-pair-1-WARNING": "OK",
            "rule-a-pair-2-WARNING": "OK",
        }
    )

    result = analysis.metrics(rows)

    assert result["per_rule"]["rule-a"]["f1"] == 0.0
    assert result["per_rule"]["rule-b"]["f1"] == 1.0
    assert result["macro_f1"] == 0.5
    assert result["exact_accuracy"] == 0.75
    assert result["invalid_rate"] == 0.0


def test_fresh_run_check_ignores_latency_but_requires_raw_bytes():
    first = [
        {
            "sequence": 0,
            "case_id": "case-1",
            "raw_output": "WARNING",
            "prediction": "WARNING",
            "repeat_raw_output_sha256": "abc",
            "latency_ms": 1.0,
        }
    ]
    analysis.require_fresh_runs_identical(
        first, [{**first[0], "latency_ms": 999.0}]
    )

    with pytest.raises(SystemExit, match="claim gate is not evaluable"):
        analysis.require_fresh_runs_identical(
            first, [{**first[0], "raw_output": "WARNING\n"}]
        )


def test_paired_draw_uses_identical_rule_pair_case_indices_for_all_systems():
    dataset = _rows({})
    systems = {
        name: {row["case_id"]: {**row, "system_marker": name} for row in dataset}
        for name in ("matched_base", "paw_standard", "paw_finetuned")
    }

    draw = analysis._paired_draw(dataset, systems, random.Random(7))

    sampled_ids = {
        name: [row["case_id"] for row in rows] for name, rows in draw.items()
    }
    assert sampled_ids["matched_base"] == sampled_ids["paw_standard"]
    assert sampled_ids["matched_base"] == sampled_ids["paw_finetuned"]
    assert all("_bootstrap_rule_instance" in row for row in draw["matched_base"])


def test_paired_bootstrap_reports_exact_known_delta_and_is_deterministic():
    dataset = _rows({})
    matched = _rows(
        {
            row["case_id"]: "OK"
            for row in dataset
            if row["expected"] == "WARNING"
        }
    )
    perfect = _rows({})
    systems = {
        "matched_base": matched,
        "paw_standard": perfect,
        "paw_finetuned": perfect,
    }

    first = analysis.paired_bootstrap(dataset, systems, samples=20, seed=19)
    second = analysis.paired_bootstrap(dataset, systems, samples=20, seed=19)

    assert first == second
    for system in analysis.PAW_SYSTEMS:
        assert first[system]["macro_f1"] == {"low": 1.0, "high": 1.0}
        assert first[system]["exact_accuracy"] == {"low": 0.5, "high": 0.5}


def test_percentile_interpolates_frozen_percentile_definition():
    assert analysis._percentile([0.0, 10.0], 0.25) == 2.5
    with pytest.raises(ValueError, match="no values"):
        analysis._percentile([], 0.5)


def test_bootstrap_rejects_zero_samples():
    with pytest.raises(ValueError, match="positive"):
        analysis.paired_bootstrap([], {}, samples=0, seed=1)
