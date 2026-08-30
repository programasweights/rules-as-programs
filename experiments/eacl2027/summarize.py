#!/usr/bin/env python3
"""Summarize strict benchmark outputs with paired-cluster bootstrap CIs."""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from statistics import median


POSITIVE = {"INFO", "WARNING", "CRITICAL"}
PREDICTIONS = {"OK", *POSITIVE, "INVALID"}


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _binary(rows: list[dict]) -> tuple[float, float, float]:
    tp = sum(
        row["expected"] in POSITIVE and row["prediction"] in POSITIVE for row in rows
    )
    fp = sum(row["expected"] == "OK" and row["prediction"] in POSITIVE for row in rows)
    fn = sum(
        row["expected"] in POSITIVE and row["prediction"] not in POSITIVE
        for row in rows
    )
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def _metrics(rows: list[dict]) -> dict:
    per_rule = {}
    group_field = (
        "_bootstrap_rule_instance"
        if any("_bootstrap_rule_instance" in row for row in rows)
        else "rule_id"
    )
    for rule_id in sorted({row[group_field] for row in rows}):
        subset = [row for row in rows if row[group_field] == rule_id]
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
    precision, recall, _pooled_f1 = _binary(rows)
    latencies = [float(row["latency_ms"]) for row in rows]
    return {
        "precision": precision,
        "recall": recall,
        "macro_f1": sum(value["f1"] for value in per_rule.values()) / len(per_rule),
        "exact_accuracy": sum(row["prediction"] == row["expected"] for row in rows)
        / len(rows),
        "invalid_rate": sum(row["prediction"] == "INVALID" for row in rows) / len(rows),
        "latency_ms": {
            "median": median(latencies),
            "p95": _percentile(latencies, 0.95),
            "p99": _percentile(latencies, 0.99),
        },
        "per_rule": per_rule,
    }


def _resample_pair_clusters(rows: list[dict], rng: random.Random) -> list[dict]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["pair_id"]].append(row)
    keys = sorted(grouped)
    sampled = []
    for key in rng.choices(keys, k=len(keys)):
        sampled.extend(grouped[key])
    return sampled


def _resample_rule_then_pair_clusters(
    rows: list[dict], rng: random.Random
) -> list[dict]:
    """Resample rule/repository clusters, then complete pairs within each draw.

    The synthetic external challenge set contains one rule per repository. A
    private draw-instance key keeps repeated rule draws distinct when macro-F1
    is recomputed; it is never written into benchmark rows.
    """

    by_rule = defaultdict(list)
    for row in rows:
        by_rule[row["rule_id"]].append(row)
    rule_ids = sorted(by_rule)
    sampled = []
    for draw_index, rule_id in enumerate(rng.choices(rule_ids, k=len(rule_ids))):
        by_pair = defaultdict(list)
        for row in by_rule[rule_id]:
            by_pair[row["pair_id"]].append(row)
        pair_ids = sorted(by_pair)
        for pair_id in rng.choices(pair_ids, k=len(pair_ids)):
            for row in by_pair[pair_id]:
                sampled.append(
                    {
                        **row,
                        "_bootstrap_rule_instance": f"{draw_index}:{rule_id}",
                    }
                )
    return sampled


def _resample_pairs_within_each_rule(
    rows: list[dict], rng: random.Random
) -> list[dict]:
    """Keep the selected rules fixed and resample complete pairs per rule."""

    by_rule = defaultdict(list)
    for row in rows:
        by_rule[row["rule_id"]].append(row)
    sampled = []
    for rule_id in sorted(by_rule):
        by_pair = defaultdict(list)
        for row in by_rule[rule_id]:
            by_pair[row["pair_id"]].append(row)
        pair_ids = sorted(by_pair)
        for pair_id in rng.choices(pair_ids, k=len(pair_ids)):
            sampled.extend(by_pair[pair_id])
    return sampled


def _bootstrap(
    rows: list[dict], samples: int, seed: int, resampling: str = "pair"
) -> dict:
    if samples < 1:
        raise ValueError("bootstrap samples must be positive")
    samplers = {
        "pair": _resample_pair_clusters,
        "stratified-rule-pair": _resample_pairs_within_each_rule,
        "hierarchical-rule-pair": _resample_rule_then_pair_clusters,
    }
    if resampling not in samplers:
        raise ValueError(f"unknown bootstrap resampling scheme: {resampling}")
    rng = random.Random(seed)
    draws = defaultdict(list)
    for _ in range(samples):
        sampled = samplers[resampling](rows, rng)
        metrics = _metrics(sampled)
        for name in ("precision", "recall", "macro_f1", "exact_accuracy"):
            draws[name].append(metrics[name])
    return {
        name: {
            "low": _percentile(values, 0.025),
            "high": _percentile(values, 0.975),
        }
        for name, values in draws.items()
    }


def _validate_run_rows(
    path: Path,
    rows: list[dict],
    expected_cases: dict[str, tuple] | None = None,
) -> tuple[str, dict[str, tuple]]:
    if not rows:
        raise SystemExit(f"{path}: run is empty")
    systems = {row.get("system") for row in rows}
    if len(systems) != 1 or not next(iter(systems)):
        raise SystemExit(f"{path}: expected one system, found {sorted(systems)}")
    signatures = {}
    pairs = defaultdict(list)
    for index, row in enumerate(rows, 1):
        required = {
            "case_id",
            "pair_id",
            "rule_id",
            "hook",
            "input",
            "expected",
            "prediction",
            "correct",
            "latency_ms",
        }
        missing = required - set(row)
        if missing:
            raise SystemExit(f"{path}:{index}: missing {sorted(missing)}")
        case_id = str(row["case_id"])
        if case_id in signatures:
            raise SystemExit(f"{path}: duplicate case_id {case_id}")
        if row["expected"] not in {"OK", *POSITIVE}:
            raise SystemExit(f"{path}:{index}: invalid expected label")
        if row["prediction"] not in PREDICTIONS:
            raise SystemExit(f"{path}:{index}: invalid prediction")
        if not isinstance(row["correct"], bool) or row["correct"] != (
            row["prediction"] == row["expected"]
        ):
            raise SystemExit(f"{path}:{index}: inconsistent correct flag")
        try:
            latency = float(row["latency_ms"])
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"{path}:{index}: invalid latency") from exc
        if not math.isfinite(latency) or latency < 0:
            raise SystemExit(f"{path}:{index}: invalid latency")
        signatures[case_id] = (
            row["pair_id"],
            row["rule_id"],
            row["hook"],
            row["input"],
            row["expected"],
            row.get("source_hash", ""),
        )
        pairs[row["pair_id"]].append(row)
    invalid_pairs = [
        pair_id
        for pair_id, pair_rows in pairs.items()
        if len(pair_rows) != 2
        or len({row["rule_id"] for row in pair_rows}) != 1
        or sum(row["expected"] == "OK" for row in pair_rows) != 1
    ]
    if invalid_pairs:
        raise SystemExit(f"{path}: invalid pairs {sorted(invalid_pairs)[:5]}")
    if expected_cases is not None and signatures != expected_cases:
        missing = sorted(set(expected_cases) - set(signatures))[:5]
        extra = sorted(set(signatures) - set(expected_cases))[:5]
        changed = sorted(
            case_id
            for case_id in set(signatures) & set(expected_cases)
            if signatures[case_id] != expected_cases[case_id]
        )[:5]
        raise SystemExit(
            f"{path}: cases differ from the first run; "
            f"missing={missing}, extra={extra}, changed={changed}"
        )
    return str(next(iter(systems))), signatures


def _format(value: float) -> str:
    return f"{value:.3f}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("runs", nargs="+", type=Path)
    parser.add_argument("--json", required=True, type=Path)
    parser.add_argument("--latex", required=True, type=Path)
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20270830)
    parser.add_argument(
        "--resampling",
        choices=("pair", "stratified-rule-pair", "hierarchical-rule-pair"),
        default="pair",
    )
    args = parser.parse_args()
    if args.bootstrap_samples < 1:
        raise SystemExit("--bootstrap-samples must be at least 1")

    summaries = []
    expected_cases = None
    for path in args.runs:
        rows = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        system, signatures = _validate_run_rows(path, rows, expected_cases)
        if expected_cases is None:
            expected_cases = signatures
        metrics = _metrics(rows)
        summaries.append(
            {
                "system": system,
                "path": str(path),
                "cases": len(rows),
                **metrics,
                "confidence_95": _bootstrap(
                    rows,
                    args.bootstrap_samples,
                    args.seed,
                    args.resampling,
                ),
                "bootstrap": {
                    "samples": args.bootstrap_samples,
                    "seed": args.seed,
                    "resampling": args.resampling,
                },
            }
        )

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(
        json.dumps({"runs": summaries}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"System & Precision & Recall & Macro-F1 & Exact \\",
        r"\midrule",
    ]
    for row in summaries:
        name = row["system"].replace("_", r"\_")
        lines.append(
            f"{name} & {_format(row['precision'])} & {_format(row['recall'])} & "
            f"{_format(row['macro_f1'])} & {_format(row['exact_accuracy'])} \\\\"
        )
    lines.extend((r"\bottomrule", r"\end{tabular}"))
    args.latex.parent.mkdir(parents=True, exist_ok=True)
    args.latex.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"runs": summaries}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
