#!/usr/bin/env python3
"""Analyze the frozen direct Qwen3-0.6B matched-backbone experiment.

The runner validates dataset and run provenance, requires the two fresh model
constructions to agree byte-for-byte, and then applies the outcome-blind
paired hierarchical bootstrap frozen in matched-analysis-plan-v1.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / "matched-analysis-plan-v1.json"
MODEL_SHA256 = "9a16ed5cacba959e63b62e2b6840c3eca2b51c3c3e51d31367ef8e4aafeae33c"
MATCHED_SYSTEM = "open-judge-matched-base:Qwen/Qwen3-0.6B:qwen3-0.6b-q6_k"
PAW_SYSTEMS = {
    "paw_standard": "paw:paw-4b-qwen3-0.6b",
    "paw_finetuned": "paw:paw-ft-bs48",
}
LABELS = {"OK", "INFO", "WARNING", "CRITICAL", "INVALID"}
POSITIVE = {"INFO", "WARNING", "CRITICAL"}
METRICS = ("macro_f1", "exact_accuracy")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: expected a JSON object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise SystemExit(f"{path}:{line_number}: expected an object")
        rows.append(value)
    return rows


def _case_signature(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("pair_id"),
        row.get("rule_id"),
        row.get("hook"),
        row.get("input"),
        row.get("expected"),
        row.get("source_hash", ""),
    )


def _validate_dataset(
    path: Path, *, expected_sha256: str, expected_cases: int
) -> tuple[list[dict[str, Any]], dict[str, tuple[Any, ...]]]:
    actual_sha256 = _sha256(path)
    if actual_sha256 != expected_sha256:
        raise SystemExit(
            f"dataset SHA-256 mismatch: {actual_sha256} != {expected_sha256}"
        )
    rows = _load_jsonl(path)
    if len(rows) != expected_cases:
        raise SystemExit(f"dataset has {len(rows)} rows, expected {expected_cases}")
    by_case: dict[str, tuple[Any, ...]] = {}
    by_pair: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, row in enumerate(rows, 1):
        required = {"case_id", "pair_id", "rule_id", "hook", "input", "expected"}
        missing = required - set(row)
        if missing:
            raise SystemExit(f"{path}:{index}: missing {sorted(missing)}")
        case_id = str(row["case_id"])
        if case_id in by_case:
            raise SystemExit(f"duplicate dataset case_id {case_id}")
        if row["expected"] not in LABELS - {"INVALID"}:
            raise SystemExit(f"{path}:{index}: invalid expected label")
        by_case[case_id] = _case_signature(row)
        by_pair[str(row["pair_id"])].append(row)
    bad_pairs = [
        pair_id
        for pair_id, pair_rows in by_pair.items()
        if len(pair_rows) != 2
        or len({str(row["rule_id"]) for row in pair_rows}) != 1
        or sum(row["expected"] == "OK" for row in pair_rows) != 1
    ]
    if bad_pairs:
        raise SystemExit(f"dataset has invalid contrast pairs: {bad_pairs[:5]}")
    return rows, by_case


def _validate_run(
    path: Path,
    *,
    dataset_sha256: str,
    dataset_signatures: Mapping[str, tuple[Any, ...]],
    expected_system: str,
    matched: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = _load_jsonl(path)
    manifest_path = path.with_suffix(path.suffix + ".manifest.json")
    manifest = _load_object(manifest_path)
    checks = {
        "system": (manifest.get("system"), expected_system),
        "cases": (manifest.get("cases"), len(dataset_signatures)),
        "dataset_sha256": (manifest.get("dataset_sha256"), dataset_sha256),
        "output_sha256": (manifest.get("output_sha256"), _sha256(path)),
        "row_count": (len(rows), len(dataset_signatures)),
    }
    mismatches = {
        name: {"observed": observed, "expected": expected}
        for name, (observed, expected) in checks.items()
        if observed != expected
    }
    if mismatches:
        raise SystemExit(
            f"{manifest_path}: provenance mismatch "
            + json.dumps(mismatches, sort_keys=True)
        )

    seen: dict[str, tuple[Any, ...]] = {}
    for index, row in enumerate(rows, 1):
        case_id = str(row.get("case_id", ""))
        if not case_id or case_id in seen:
            raise SystemExit(f"{path}:{index}: missing or duplicate case_id")
        if row.get("system") != expected_system:
            raise SystemExit(f"{path}:{index}: unexpected row system")
        prediction = row.get("prediction")
        if prediction not in LABELS:
            raise SystemExit(f"{path}:{index}: invalid prediction {prediction!r}")
        if row.get("correct") is not (prediction == row.get("expected")):
            raise SystemExit(f"{path}:{index}: inconsistent correct flag")
        seen[case_id] = _case_signature(row)
    if seen != dataset_signatures:
        raise SystemExit(f"{path}: case signatures differ from dataset")

    if matched:
        identity = manifest.get("matched_base")
        decoding = manifest.get("decoding")
        if not isinstance(identity, dict) or not isinstance(decoding, dict):
            raise SystemExit(f"{manifest_path}: missing matched-base identity")
        matched_checks = {
            "content_sha256": (identity.get("content_sha256"), MODEL_SHA256),
            "adapter_applied": (identity.get("adapter_applied"), False),
            "greedy": (decoding.get("greedy"), True),
            "max_new_tokens": (decoding.get("max_new_tokens"), 8),
            "repeat_count_per_case": (decoding.get("repeat_count_per_case"), 2),
            "all_within_run_raw_outputs_identical": (
                decoding.get("all_within_run_raw_outputs_identical"),
                True,
            ),
        }
        bad = {
            name: {"observed": observed, "expected": expected}
            for name, (observed, expected) in matched_checks.items()
            if observed != expected
        }
        if bad:
            raise SystemExit(
                f"{manifest_path}: matched-base contract mismatch "
                + json.dumps(bad, sort_keys=True)
            )
    return rows, manifest


def _repeat_signature(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("sequence"),
        row.get("case_id"),
        row.get("raw_output"),
        row.get("prediction"),
        row.get("repeat_raw_output_sha256"),
    )


def require_fresh_runs_identical(
    first: Sequence[Mapping[str, Any]], second: Sequence[Mapping[str, Any]]
) -> None:
    first_signatures = [_repeat_signature(row) for row in first]
    second_signatures = [_repeat_signature(row) for row in second]
    if first_signatures != second_signatures:
        changed = [
            str(a[1] if len(a) > 1 else b[1])
            for a, b in zip(first_signatures, second_signatures)
            if a != b
        ][:5]
        if len(first_signatures) != len(second_signatures):
            changed.append("row-count")
        raise SystemExit(
            "fresh matched-base runs differ; claim gate is not evaluable: "
            f"{changed}"
        )


def _binary(rows: Sequence[Mapping[str, Any]]) -> tuple[float, float, float]:
    tp = sum(
        row["expected"] in POSITIVE and row["prediction"] in POSITIVE
        for row in rows
    )
    fp = sum(
        row["expected"] == "OK" and row["prediction"] in POSITIVE for row in rows
    )
    fn = sum(
        row["expected"] in POSITIVE and row["prediction"] not in POSITIVE
        for row in rows
    )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    group_field = (
        "_bootstrap_rule_instance"
        if any("_bootstrap_rule_instance" in row for row in rows)
        else "rule_id"
    )
    per_rule = {}
    for rule_id in sorted({str(row[group_field]) for row in rows}):
        subset = [row for row in rows if str(row[group_field]) == rule_id]
        precision, recall, f1 = _binary(subset)
        per_rule[rule_id] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "exact_accuracy": sum(
                row["prediction"] == row["expected"] for row in subset
            )
            / len(subset),
        }
    precision, recall, _ = _binary(rows)
    return {
        "precision": precision,
        "recall": recall,
        "macro_f1": sum(value["f1"] for value in per_rule.values())
        / len(per_rule),
        "exact_accuracy": sum(
            row["prediction"] == row["expected"] for row in rows
        )
        / len(rows),
        "invalid_rate": sum(row["prediction"] == "INVALID" for row in rows)
        / len(rows),
        "per_rule": per_rule,
    }


def _paired_draw(
    dataset_rows: Sequence[Mapping[str, Any]],
    systems: Mapping[str, Mapping[str, Mapping[str, Any]]],
    rng: random.Random,
) -> dict[str, list[dict[str, Any]]]:
    by_rule: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in dataset_rows:
        by_rule[str(row["rule_id"])].append(row)
    rule_ids = sorted(by_rule)
    sampled = {name: [] for name in systems}
    for draw_index, rule_id in enumerate(rng.choices(rule_ids, k=len(rule_ids))):
        by_pair: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for row in by_rule[rule_id]:
            by_pair[str(row["pair_id"])].append(row)
        pair_ids = sorted(by_pair)
        for pair_id in rng.choices(pair_ids, k=len(pair_ids)):
            for dataset_row in by_pair[pair_id]:
                case_id = str(dataset_row["case_id"])
                for name, by_case in systems.items():
                    sampled[name].append(
                        {
                            **by_case[case_id],
                            "_bootstrap_rule_instance": f"{draw_index}:{rule_id}",
                        }
                    )
    return sampled


def _percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot take a percentile of no values")
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def paired_bootstrap(
    dataset_rows: Sequence[Mapping[str, Any]],
    systems: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    samples: int,
    seed: int,
) -> dict[str, Any]:
    if samples < 1:
        raise ValueError("samples must be positive")
    indexed = {
        name: {str(row["case_id"]): row for row in rows}
        for name, rows in systems.items()
    }
    rng = random.Random(seed)
    draws: dict[str, dict[str, list[float]]] = {
        key: {metric: [] for metric in METRICS} for key in PAW_SYSTEMS
    }
    for _ in range(samples):
        sampled = _paired_draw(dataset_rows, indexed, rng)
        sampled_metrics = {name: metrics(rows) for name, rows in sampled.items()}
        for key in PAW_SYSTEMS:
            for metric in METRICS:
                draws[key][metric].append(
                    sampled_metrics[key][metric]
                    - sampled_metrics["matched_base"][metric]
                )
    output = {}
    for key, metric_draws in draws.items():
        output[key] = {}
        for metric, values in metric_draws.items():
            output[key][metric] = {
                "low": _percentile(values, 0.025),
                "high": _percentile(values, 0.975),
            }
    return output


def analyze(
    *,
    dataset_kind: str,
    dataset_path: Path,
    matched_run1: Path,
    matched_run2: Path,
    paw_standard: Path,
    paw_finetuned: Path,
    samples: int,
    seed: int,
) -> dict[str, Any]:
    plan = _load_object(PLAN_PATH)
    dataset_plan = plan.get("datasets", {}).get(dataset_kind)
    if not isinstance(dataset_plan, dict):
        raise SystemExit(f"unknown dataset kind {dataset_kind!r}")
    dataset_rows, signatures = _validate_dataset(
        dataset_path,
        expected_sha256=str(dataset_plan["sha256"]),
        expected_cases=int(dataset_plan["cases"]),
    )
    runs: dict[str, list[dict[str, Any]]] = {}
    manifests = {}
    first, manifests["matched_run1"] = _validate_run(
        matched_run1,
        dataset_sha256=str(dataset_plan["sha256"]),
        dataset_signatures=signatures,
        expected_system=MATCHED_SYSTEM,
        matched=True,
    )
    second, manifests["matched_run2"] = _validate_run(
        matched_run2,
        dataset_sha256=str(dataset_plan["sha256"]),
        dataset_signatures=signatures,
        expected_system=MATCHED_SYSTEM,
        matched=True,
    )
    require_fresh_runs_identical(first, second)
    runs["matched_base"] = first
    for key, path in (
        ("paw_standard", paw_standard),
        ("paw_finetuned", paw_finetuned),
    ):
        runs[key], manifests[key] = _validate_run(
            path,
            dataset_sha256=str(dataset_plan["sha256"]),
            dataset_signatures=signatures,
            expected_system=PAW_SYSTEMS[key],
            matched=False,
        )

    point = {key: metrics(rows) for key, rows in runs.items()}
    intervals = paired_bootstrap(
        dataset_rows, runs, samples=samples, seed=seed
    )
    contrasts = {}
    for key in PAW_SYSTEMS:
        deltas = {
            metric: point[key][metric] - point["matched_base"][metric]
            for metric in METRICS
        }
        contrasts[key] = {
            "delta": deltas,
            "confidence_95": intervals[key],
            "macro_f1_gain_gate_supported": intervals[key]["macro_f1"]["low"] > 0,
        }
    paths = {
        "dataset": dataset_path,
        "matched_run1": matched_run1,
        "matched_run2": matched_run2,
        "paw_standard": paw_standard,
        "paw_finetuned": paw_finetuned,
    }
    return {
        "analysis_id": str(plan["analysis_id"]),
        "dataset_kind": dataset_kind,
        "dataset_sha256": str(dataset_plan["sha256"]),
        "cases": len(dataset_rows),
        "fresh_matched_runs_exactly_identical": True,
        "systems": point,
        "contrasts": contrasts,
        "bootstrap": {
            "samples": samples,
            "seed": seed,
            "method": plan["uncertainty"]["method"],
        },
        "provenance": {
            name: {
                "path": str(path),
                "sha256": _sha256(path),
                "manifest_path": str(path.with_suffix(path.suffix + ".manifest.json")),
                "manifest_sha256": _sha256(
                    path.with_suffix(path.suffix + ".manifest.json")
                ),
            }
            for name, path in paths.items()
            if name != "dataset"
        }
        | {"dataset": {"path": str(dataset_path), "sha256": _sha256(dataset_path)}},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-kind", choices=("controlled", "external"), required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--matched-run1", type=Path, required=True)
    parser.add_argument("--matched-run2", type=Path, required=True)
    parser.add_argument("--paw-standard", type=Path, required=True)
    parser.add_argument("--paw-finetuned", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20270903)
    args = parser.parse_args()
    result = analyze(
        dataset_kind=args.dataset_kind,
        dataset_path=args.dataset,
        matched_run1=args.matched_run1,
        matched_run2=args.matched_run2,
        paw_standard=args.paw_standard,
        paw_finetuned=args.paw_finetuned,
        samples=args.bootstrap_samples,
        seed=args.seed,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
