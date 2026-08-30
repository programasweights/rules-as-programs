#!/usr/bin/env python3
"""Post-hoc paired comparison analysis over the frozen EACL predictions.

The analysis is deliberately separate from the frozen protocol and primary
summary.  It verifies every input hash and manifest before computing paired
cluster-bootstrap deltas or writing a new versioned artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
FROZEN_DIR = ROOT / "outputs" / "frozen"
DATASET = ROOT / "data" / "public" / "controlled.jsonl"
DATASET_MANIFEST = ROOT / "data" / "public" / "controlled-manifest.json"
DEFAULT_OUTPUT = FROZEN_DIR / "paired-comparisons-v1.json"
DEFAULT_INVENTORY = FROZEN_DIR / "paired-disagreements-v1.jsonl"
ANALYSIS_ID = "eacl2027-paired-comparisons-v1"
SOURCE_PROTOCOL_VERSION = "1.1.0"
SOURCE_PROTOCOL_SHA256 = (
    "01c6ebc1c597f1b59242fd7cdee92e53398f7d5cbe8151ef9fc1e8106e5445fb"
)
SOURCE_PROTOCOL_ARTIFACT_COMMIT = "543dd90991a3848a6d6a53011f36106cdead9ad2"
SOURCE_PROTOCOL_HISTORICAL_PATH = "experiments/eacl2027/protocol.json"
DEFAULT_BOOTSTRAP_SAMPLES = 5000
DEFAULT_SEED = 20270830

if str(REPO_ROOT) not in os.sys.path:
    os.sys.path.insert(0, str(REPO_ROOT))

from experiments.eacl2027.summarize import (  # noqa: E402
    POSITIVE,
    _metrics,
    _percentile,
    _validate_run_rows,
)


RUN_SPECS = {
    "paw_finetuned": {
        "filename": "paw-finetuned.jsonl",
        "system": "paw:paw-ft-bs48",
        "compiler": "paw-ft-bs48",
    },
    "qwen3_4b": {
        "filename": "qwen3-4b.jsonl",
        "system": "open-judge:Qwen/Qwen3-4B-Instruct-2507",
        "model": "Qwen/Qwen3-4B-Instruct-2507",
    },
    "lexical": {
        "filename": "lexical.jsonl",
        "system": "lexical",
    },
}
FOCAL_KEY = "paw_finetuned"
COMPARATOR_KEYS = ("qwen3_4b", "lexical")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _repo_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(resolved)


def _load_json_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"invalid JSON object {path}: expected an object")
    return value


def _load_jsonl(path: Path) -> list[dict]:
    rows = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise SystemExit(f"{path}:{line_number}: expected an object")
        rows.append(row)
    return rows


def _require_tracked_inputs_match_head(paths: list[Path]) -> list[str]:
    relative_paths = []
    for path in paths:
        try:
            relative = path.resolve().relative_to(REPO_ROOT.resolve())
        except ValueError as exc:
            raise SystemExit(
                f"provenance input is outside the repository: {path}"
            ) from exc
        relative_paths.append(str(relative))
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", *relative_paths],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if tracked.returncode != 0:
        raise SystemExit(
            "frozen provenance input is not tracked: " + tracked.stderr.strip()
        )
    changed = subprocess.run(
        [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            *relative_paths,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if changed:
        raise SystemExit(f"frozen provenance input differs from HEAD: {changed}")
    return sorted(relative_paths)


def _dataset_signatures(rows: list[dict]) -> dict[str, tuple]:
    return {
        str(row["case_id"]): (
            row["pair_id"],
            row["rule_id"],
            row["hook"],
            row["input"],
            row["expected"],
            row.get("source_hash", ""),
        )
        for row in rows
    }


def _validate_controlled_dataset() -> tuple[dict, list[dict], dict]:
    dataset_manifest = _load_json_object(DATASET_MANIFEST)
    if dataset_manifest.get("protocol_version") != SOURCE_PROTOCOL_VERSION:
        raise SystemExit(
            "controlled dataset does not belong to source protocol "
            f"{SOURCE_PROTOCOL_VERSION}"
        )
    dataset_sha256 = _sha256(DATASET)
    if dataset_manifest.get("sha256") != dataset_sha256:
        raise SystemExit("controlled dataset hash differs from its manifest")
    rows = _load_jsonl(DATASET)
    required = {
        "case_id",
        "pair_id",
        "rule_id",
        "hook",
        "input",
        "expected",
        "source_hash",
    }
    for index, row in enumerate(rows, 1):
        missing = required - set(row)
        if missing:
            raise SystemExit(f"{DATASET}:{index}: missing {sorted(missing)}")
        if row["expected"] not in {"OK", *POSITIVE}:
            raise SystemExit(f"{DATASET}:{index}: invalid expected label")
    signatures = _dataset_signatures(rows)
    if len(signatures) != len(rows):
        raise SystemExit("controlled dataset contains duplicate case IDs")
    pairs = defaultdict(list)
    source_hashes = defaultdict(set)
    for row in rows:
        pairs[str(row["pair_id"])].append(row)
        source_hashes[str(row["rule_id"])].add(str(row["source_hash"]))
    invalid_pairs = [
        pair_id
        for pair_id, pair_rows in pairs.items()
        if len(pair_rows) != 2
        or len({row["rule_id"] for row in pair_rows}) != 1
        or sum(row["expected"] == "OK" for row in pair_rows) != 1
    ]
    if invalid_pairs:
        raise SystemExit(f"controlled dataset has invalid pairs: {invalid_pairs[:5]}")
    actual_source_hashes = {
        rule_id: next(iter(hashes))
        for rule_id, hashes in source_hashes.items()
        if len(hashes) == 1
    }
    checks = {
        "cases": (dataset_manifest.get("cases"), len(rows)),
        "pairs": (dataset_manifest.get("pairs"), len(pairs)),
        "rules": (dataset_manifest.get("rules"), len(source_hashes)),
        "rule_source_sha256": (
            dataset_manifest.get("rule_source_sha256"),
            actual_source_hashes,
        ),
    }
    mismatches = {
        name: {"manifest": actual, "expected": expected}
        for name, (actual, expected) in checks.items()
        if actual != expected
    }
    if len(actual_source_hashes) != len(source_hashes):
        mismatches["row_source_hashes"] = {
            "manifest": "multiple hashes for one or more rules",
            "expected": "one source hash per rule",
        }
    if mismatches:
        raise SystemExit(
            "controlled dataset provenance mismatch "
            + json.dumps(mismatches, sort_keys=True)
        )
    return dataset_manifest, rows, signatures


def _validate_frozen_runs(
    frozen_dir: Path,
    dataset_sha256: str,
    dataset_cases: int,
    expected_signatures: dict[str, tuple],
) -> tuple[dict[str, dict], dict[str, dict]]:
    loaded = {}
    provenance = {}
    commits = set()
    for key, spec in RUN_SPECS.items():
        run_path = frozen_dir / str(spec["filename"])
        manifest_path = run_path.with_suffix(run_path.suffix + ".manifest.json")
        manifest = _load_json_object(manifest_path)
        rows = _load_jsonl(run_path)
        system, signatures = _validate_run_rows(run_path, rows, expected_signatures)
        if signatures != expected_signatures:
            raise SystemExit(f"{run_path}: case signatures differ from the dataset")
        actual_output_sha256 = _sha256(run_path)
        checks = {
            "schema_version": (manifest.get("schema_version"), 1),
            "system": (manifest.get("system"), spec["system"]),
            "row_system": (system, spec["system"]),
            "cases": (manifest.get("cases"), dataset_cases),
            "row_count": (len(rows), dataset_cases),
            "dataset_sha256": (manifest.get("dataset_sha256"), dataset_sha256),
            "output_sha256": (
                manifest.get("output_sha256"),
                actual_output_sha256,
            ),
        }
        mismatches = {
            name: {"manifest": actual, "expected": expected}
            for name, (actual, expected) in checks.items()
            if actual != expected
        }
        if mismatches:
            raise SystemExit(
                f"{manifest_path}: provenance mismatch "
                f"{json.dumps(mismatches, sort_keys=True)}"
            )
        git = manifest.get("git")
        if not isinstance(git, dict) or git.get("dirty") is not False:
            raise SystemExit(f"{manifest_path}: frozen run is not clean")
        commit = str(git.get("commit", ""))
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise SystemExit(f"{manifest_path}: invalid source commit")
        commits.add(commit)
        compiler_snapshots = {}
        if key == FOCAL_KEY:
            if manifest.get("compiler") != spec["compiler"]:
                raise SystemExit(f"{manifest_path}: unexpected PAW compiler")
            program_ids = manifest.get("program_ids")
            compiler_info = manifest.get("compiler_info")
            rule_ids = {str(row["rule_id"]) for row in rows}
            if (
                not isinstance(program_ids, dict)
                or set(program_ids) != rule_ids
                or not all(str(value) for value in program_ids.values())
            ):
                raise SystemExit(f"{manifest_path}: invalid PAW program identities")
            if not isinstance(compiler_info, dict) or set(compiler_info) != rule_ids:
                raise SystemExit(f"{manifest_path}: invalid PAW compiler snapshots")
            for rule_id in sorted(rule_ids):
                info = compiler_info[rule_id]
                if (
                    not isinstance(info, dict)
                    or info.get("name") != spec["compiler"]
                    or not str(info.get("latest_snapshot", ""))
                ):
                    raise SystemExit(
                        f"{manifest_path}: invalid compiler identity for {rule_id}"
                    )
                compiler_snapshots[rule_id] = str(info["latest_snapshot"])
            invalid_program_rows = [
                row["case_id"]
                for row in rows
                if row.get("program_id") != program_ids[str(row["rule_id"])]
            ]
            if invalid_program_rows:
                raise SystemExit(
                    f"{run_path}: program identity mismatch {invalid_program_rows[:5]}"
                )
        if key == "qwen3_4b":
            requested = str(manifest.get("model_revision_requested", ""))
            resolved = str(manifest.get("model_commit", ""))
            if manifest.get("model") != spec["model"] or requested != resolved:
                raise SystemExit(f"{manifest_path}: unpinned Qwen model identity")
            if not re.fullmatch(r"[0-9a-f]{40,64}", resolved):
                raise SystemExit(f"{manifest_path}: invalid Qwen model commit")
        loaded[key] = {
            "path": run_path,
            "manifest_path": manifest_path,
            "manifest": manifest,
            "rows": rows,
            "by_case": {str(row["case_id"]): row for row in rows},
        }
        identity = {
            "key": key,
            "system": spec["system"],
            "path": _repo_path(run_path),
            "output_sha256": actual_output_sha256,
            "manifest_path": _repo_path(manifest_path),
            "manifest_sha256": _sha256(manifest_path),
            "cases": len(rows),
            "source_commit": commit,
        }
        if key == FOCAL_KEY:
            identity["compiler"] = manifest["compiler"]
            identity["compiler_snapshots"] = compiler_snapshots
            identity["program_ids"] = dict(sorted(manifest["program_ids"].items()))
        elif key == "qwen3_4b":
            identity["model"] = manifest["model"]
            identity["model_commit"] = manifest["model_commit"]
        provenance[key] = identity
    if len(commits) != 1:
        raise SystemExit(f"frozen runs use different source commits: {sorted(commits)}")
    return loaded, provenance


def _selected_metrics(rows: list[dict]) -> dict[str, float]:
    metrics = _metrics(rows)
    return {
        "macro_f1": metrics["macro_f1"],
        "exact_accuracy": metrics["exact_accuracy"],
    }


def _pair_case_ids(rows: list[dict]) -> dict[str, tuple[str, ...]]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[str(row["pair_id"])].append(str(row["case_id"]))
    invalid = [pair_id for pair_id, case_ids in grouped.items() if len(case_ids) != 2]
    if invalid:
        raise ValueError(f"expected two cases per pair: {sorted(invalid)[:5]}")
    return {
        pair_id: tuple(sorted(case_ids))
        for pair_id, case_ids in sorted(grouped.items())
    }


def _paired_bootstrap(
    focal_rows: list[dict],
    comparator_rows: list[dict],
    samples: int,
    seed: int,
) -> dict:
    if samples < 1:
        raise ValueError("bootstrap samples must be positive")
    focal_by_case = {str(row["case_id"]): row for row in focal_rows}
    comparator_by_case = {str(row["case_id"]): row for row in comparator_rows}
    if set(focal_by_case) != set(comparator_by_case):
        raise ValueError("paired bootstrap requires identical cases")
    pairs = _pair_case_ids(focal_rows)
    pair_ids = sorted(pairs)
    pair_statistics = {
        pair_id: {
            "rule_id": str(focal_by_case[case_ids[0]]["rule_id"]),
            "focal": _pair_statistics([focal_by_case[case_id] for case_id in case_ids]),
            "comparator": _pair_statistics(
                [comparator_by_case[case_id] for case_id in case_ids]
            ),
        }
        for pair_id, case_ids in pairs.items()
    }
    rng = random.Random(seed)
    draws = defaultdict(list)
    for _ in range(samples):
        sampled_pair_ids = rng.choices(pair_ids, k=len(pair_ids))
        focal_by_rule = defaultdict(lambda: [0, 0, 0, 0, 0])
        comparator_by_rule = defaultdict(lambda: [0, 0, 0, 0, 0])
        for pair_id in sampled_pair_ids:
            statistics = pair_statistics[pair_id]
            rule_id = statistics["rule_id"]
            for destination, source in (
                (focal_by_rule[rule_id], statistics["focal"]),
                (comparator_by_rule[rule_id], statistics["comparator"]),
            ):
                for index, value in enumerate(source):
                    destination[index] += value
        focal_metrics = _metrics_from_sufficient_statistics(focal_by_rule)
        comparator_metrics = _metrics_from_sufficient_statistics(comparator_by_rule)
        for metric in ("macro_f1", "exact_accuracy"):
            draws[metric].append(focal_metrics[metric] - comparator_metrics[metric])
    return {
        f"{metric}_delta": {
            "low": _percentile(values, 0.025),
            "high": _percentile(values, 0.975),
        }
        for metric, values in sorted(draws.items())
    }


def _pair_statistics(rows: list[dict]) -> tuple[int, int, int, int, int]:
    true_positive = sum(
        row["expected"] in POSITIVE and row["prediction"] in POSITIVE for row in rows
    )
    false_positive = sum(
        row["expected"] == "OK" and row["prediction"] in POSITIVE for row in rows
    )
    false_negative = sum(
        row["expected"] in POSITIVE and row["prediction"] not in POSITIVE
        for row in rows
    )
    exact_correct = sum(_exact_correct(row) for row in rows)
    return true_positive, false_positive, false_negative, exact_correct, len(rows)


def _metrics_from_sufficient_statistics(
    by_rule: dict[str, list[int]],
) -> dict[str, float]:
    rule_f1 = []
    exact_correct = 0
    total = 0
    for (
        true_positive,
        false_positive,
        false_negative,
        correct,
        count,
    ) in by_rule.values():
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0
        )
        rule_f1.append(
            2 * precision * recall / (precision + recall) if precision + recall else 0.0
        )
        exact_correct += correct
        total += count
    return {
        "macro_f1": sum(rule_f1) / len(rule_f1),
        "exact_accuracy": exact_correct / total,
    }


def _exact_correct(row: dict) -> bool:
    return row["prediction"] == row["expected"]


def _binary_correct(row: dict) -> bool:
    prediction = row["prediction"]
    if prediction == "INVALID":
        return False
    return (prediction in POSITIVE) == (row["expected"] in POSITIVE)


def _exact_paired_cluster_randomization(
    focal_by_case: dict[str, dict],
    comparator_by_case: dict[str, dict],
    pairs: dict[str, tuple[str, ...]],
    correctness: Callable[[dict], bool],
) -> dict:
    """Exact two-sided sign-flip test with each contrast pair kept intact."""
    contributions = []
    for case_ids in pairs.values():
        focal_correct = sum(correctness(focal_by_case[case_id]) for case_id in case_ids)
        comparator_correct = sum(
            correctness(comparator_by_case[case_id]) for case_id in case_ids
        )
        contributions.append(focal_correct - comparator_correct)
    observed = sum(contributions)
    nonzero = [abs(value) for value in contributions if value]
    distribution = {0: 1}
    for contribution in nonzero:
        updated = defaultdict(int)
        for current, count in distribution.items():
            updated[current + contribution] += count
            updated[current - contribution] += count
        distribution = dict(updated)
    extreme = sum(
        count for value, count in distribution.items() if abs(value) >= abs(observed)
    )
    assignments = sum(distribution.values())
    return {
        "method": "two-sided exact paired cluster randomization",
        "cluster": "pair_id",
        "null": "exchangeable system labels within each complete contrast pair",
        "pairs": len(pairs),
        "nonzero_pair_contributions": len(nonzero),
        "pair_correct_count_difference_histogram": {
            str(value): count for value, count in sorted(Counter(contributions).items())
        },
        "observed_correct_case_difference": observed,
        "exact_fraction": {
            "extreme_assignments": str(extreme),
            "effective_assignments": str(assignments),
        },
        "p_value": extreme / assignments,
    }


def _discordance(
    focal_by_case: dict[str, dict],
    comparator_by_case: dict[str, dict],
    correctness: Callable[[dict], bool],
) -> dict:
    counts = Counter()
    for case_id in sorted(focal_by_case):
        focal_correct = correctness(focal_by_case[case_id])
        comparator_correct = correctness(comparator_by_case[case_id])
        if focal_correct and comparator_correct:
            counts["both_correct"] += 1
        elif focal_correct:
            counts["focal_only_correct"] += 1
        elif comparator_correct:
            counts["comparator_only_correct"] += 1
        else:
            counts["both_incorrect"] += 1
    return {
        key: counts[key]
        for key in (
            "both_correct",
            "focal_only_correct",
            "comparator_only_correct",
            "both_incorrect",
        )
    }


def _comparison(
    focal: dict,
    comparator: dict,
    bootstrap_samples: int,
    seed: int,
) -> dict:
    focal_metrics = _selected_metrics(focal["rows"])
    comparator_metrics = _selected_metrics(comparator["rows"])
    pairs = _pair_case_ids(focal["rows"])
    return {
        "focal_system": focal["manifest"]["system"],
        "comparator_system": comparator["manifest"]["system"],
        "point_estimates": {
            "focal": focal_metrics,
            "comparator": comparator_metrics,
            "delta_focal_minus_comparator": {
                metric: focal_metrics[metric] - comparator_metrics[metric]
                for metric in ("macro_f1", "exact_accuracy")
            },
        },
        "paired_cluster_bootstrap_95": _paired_bootstrap(
            focal["rows"], comparator["rows"], bootstrap_samples, seed
        ),
        "exact_label_correctness": {
            "case_discordance": _discordance(
                focal["by_case"], comparator["by_case"], _exact_correct
            ),
            "exact_paired_test": _exact_paired_cluster_randomization(
                focal["by_case"], comparator["by_case"], pairs, _exact_correct
            ),
        },
        "binary_detection_correctness": {
            "definition": "OK versus any non-OK prediction; INVALID is incorrect",
            "case_discordance": _discordance(
                focal["by_case"], comparator["by_case"], _binary_correct
            ),
            "exact_paired_test": _exact_paired_cluster_randomization(
                focal["by_case"], comparator["by_case"], pairs, _binary_correct
            ),
        },
        "macro_f1_exact_test": {
            "status": "not_run",
            "reason": (
                "macro-F1 is non-additive; the paired cluster-bootstrap interval "
                "is reported without a case-level McNemar test"
            ),
        },
    }


def _add_holm_adjustment(comparisons: dict[str, dict], outcome: str) -> None:
    """Attach Holm-adjusted p-values across the declared comparator family."""

    ordered = sorted(
        (
            comparison[outcome]["exact_paired_test"]["p_value"],
            key,
        )
        for key, comparison in comparisons.items()
    )
    running = 0.0
    family_size = len(ordered)
    for rank, (p_value, key) in enumerate(ordered):
        running = max(running, min(1.0, (family_size - rank) * p_value))
        test = comparisons[key][outcome]["exact_paired_test"]
        test["holm_adjusted_p_value"] = running
        test["holm_family"] = sorted(comparisons)
        test["reject_at_0.05_after_holm"] = running <= 0.05


def _inventory_rows(runs: dict[str, dict]) -> list[dict]:
    focal = runs[FOCAL_KEY]
    rows = []
    for case_id in sorted(focal["by_case"]):
        source = focal["by_case"][case_id]
        predictions = {
            key: run["by_case"][case_id]["prediction"]
            for key, run in sorted(runs.items())
        }
        exact = {
            key: _exact_correct(run["by_case"][case_id])
            for key, run in sorted(runs.items())
        }
        binary = {
            key: _binary_correct(run["by_case"][case_id])
            for key, run in sorted(runs.items())
        }
        prediction_disagreement = len(set(predictions.values())) > 1
        if not prediction_disagreement and all(exact.values()):
            continue
        comparisons = {}
        for key in COMPARATOR_KEYS:
            comparisons[key] = {
                "prediction_disagreement": (predictions[FOCAL_KEY] != predictions[key]),
                "exact_correctness_disagreement": exact[FOCAL_KEY] != exact[key],
                "focal_advantage_exact": exact[FOCAL_KEY] and not exact[key],
                "focal_disadvantage_exact": exact[key] and not exact[FOCAL_KEY],
                "binary_correctness_disagreement": binary[FOCAL_KEY] != binary[key],
            }
        rows.append(
            {
                "analysis_id": ANALYSIS_ID,
                "case_id": case_id,
                "pair_id": source["pair_id"],
                "rule_id": source["rule_id"],
                "hook": source["hook"],
                "input": source["input"],
                "expected": source["expected"],
                "source_hash": source.get("source_hash", ""),
                "has_prediction_disagreement": prediction_disagreement,
                "has_any_exact_error": not all(exact.values()),
                "has_any_binary_error": not all(binary.values()),
                "predictions": predictions,
                "exact_correct": exact,
                "binary_correct": binary,
                "comparisons": comparisons,
            }
        )
    return rows


def _json_bytes(value: dict) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _jsonl_bytes(rows: list[dict]) -> bytes:
    return (
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        )
    ).encode("utf-8")


def build_outputs(
    output_path: Path = DEFAULT_OUTPUT,
    inventory_path: Path = DEFAULT_INVENTORY,
    bootstrap_samples: int | None = None,
    seed: int | None = None,
) -> tuple[bytes, bytes]:
    dataset_manifest, dataset_rows, signatures = _validate_controlled_dataset()
    if bootstrap_samples is None:
        bootstrap_samples = DEFAULT_BOOTSTRAP_SAMPLES
    if seed is None:
        seed = DEFAULT_SEED
    if bootstrap_samples < 1:
        raise SystemExit("--bootstrap-samples must be at least 1")
    dataset_sha256 = _sha256(DATASET)
    tracked_inputs = [DATASET, DATASET_MANIFEST]
    for spec in RUN_SPECS.values():
        run_path = FROZEN_DIR / str(spec["filename"])
        tracked_inputs.extend(
            [run_path, run_path.with_suffix(run_path.suffix + ".manifest.json")]
        )
    tracked_input_paths = _require_tracked_inputs_match_head(tracked_inputs)
    runs, run_provenance = _validate_frozen_runs(
        FROZEN_DIR,
        dataset_sha256,
        len(dataset_rows),
        signatures,
    )
    inventory = _inventory_rows(runs)
    inventory_bytes = _jsonl_bytes(inventory)
    inventory_sha256 = hashlib.sha256(inventory_bytes).hexdigest()
    inventory_counts = {
        "rows": len(inventory),
        "prediction_disagreements": sum(
            row["has_prediction_disagreement"] for row in inventory
        ),
        "rows_with_any_exact_error": sum(
            row["has_any_exact_error"] for row in inventory
        ),
        "rows_with_any_binary_error": sum(
            row["has_any_binary_error"] for row in inventory
        ),
        "exact_errors_by_system": {
            key: sum(not row["exact_correct"][key] for row in inventory)
            for key in sorted(runs)
        },
    }
    comparisons = {
        key: _comparison(runs[FOCAL_KEY], runs[key], bootstrap_samples, seed)
        for key in COMPARATOR_KEYS
    }
    _add_holm_adjustment(comparisons, "exact_label_correctness")
    _add_holm_adjustment(comparisons, "binary_detection_correctness")
    common_commit = run_provenance[FOCAL_KEY]["source_commit"]
    analysis = {
        "analysis_id": ANALYSIS_ID,
        "schema_version": 1,
        "status": "post_hoc_comparison_of_previously_frozen_predictions",
        "frozen_predictions_changed": False,
        "comparisons": comparisons,
        "method": {
            "focal_system": RUN_SPECS[FOCAL_KEY]["system"],
            "comparators": [RUN_SPECS[key]["system"] for key in COMPARATOR_KEYS],
            "deltas": "focal minus comparator",
            "bootstrap": {
                "samples": bootstrap_samples,
                "seed": seed,
                "cluster": "pair_id",
                "paired_system_draws": True,
                "confidence": 0.95,
                "interval": "percentile",
            },
            "exact_test": (
                "two-sided exact sign-flip randomization of system labels within "
                "each complete contrast-pair cluster"
            ),
            "multiplicity": (
                "Holm adjustment across the two declared comparators, applied "
                "separately to exact-label and binary-detection correctness"
            ),
        },
        "provenance": {
            "validation": {
                "controlled_dataset_manifest": True,
                "run_output_hashes": True,
                "run_manifest_hashes_recorded": True,
                "run_case_signatures_match_dataset": True,
                "all_run_git_states_clean": True,
                "all_runs_share_source_commit": True,
                "tracked_inputs_match_head": True,
            },
            "tracked_inputs": tracked_input_paths,
            "source_protocol": {
                "version": SOURCE_PROTOCOL_VERSION,
                "historical_path": SOURCE_PROTOCOL_HISTORICAL_PATH,
                "sha256_at_artifact_commit": SOURCE_PROTOCOL_SHA256,
                "artifact_commit": SOURCE_PROTOCOL_ARTIFACT_COMMIT,
                "required_to_match_current_checkout": False,
            },
            "dataset_path": _repo_path(DATASET),
            "dataset_sha256": dataset_sha256,
            "dataset_manifest_path": _repo_path(DATASET_MANIFEST),
            "dataset_manifest_sha256": _sha256(DATASET_MANIFEST),
            "dataset_cases": dataset_manifest["cases"],
            "input_run_source_commit": common_commit,
            "inputs": run_provenance,
            "analysis_script_path": _repo_path(Path(__file__)),
            "analysis_script_sha256": _sha256(Path(__file__)),
        },
        "inventory": {
            "path": _repo_path(inventory_path),
            "sha256": inventory_sha256,
            "selection": (
                "all cases with any focal/comparator prediction disagreement or "
                "any exact-label error"
            ),
            **inventory_counts,
        },
        "interpretation_limits": [
            "This comparison was added after protocol 1.1.0 and all predictions were frozen.",
            "Intervals condition on the fixed author-constructed cases and do not capture author-sampling uncertainty.",
            "Exact tests concern paired correctness, not the non-additive macro-F1 metric.",
            "Exact-test p-values use Holm correction across the two declared comparator analyses.",
        ],
    }
    return _json_bytes(analysis), inventory_bytes


def _preflight_outputs(contents: dict[Path, bytes]) -> None:
    for path, expected in contents.items():
        if path.exists() and path.read_bytes() != expected:
            raise SystemExit(
                f"refusing to overwrite different versioned artifact: {path}"
            )


def _write_missing_outputs(contents: dict[Path, bytes]) -> list[str]:
    statuses = []
    for path, value in contents.items():
        if path.exists():
            statuses.append(f"verified:{_repo_path(path)}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
            ) as stream:
                stream.write(value)
                temporary_name = stream.name
            os.replace(temporary_name, path)
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)
        statuses.append(f"wrote:{_repo_path(path)}")
    return statuses


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--bootstrap-samples", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument(
        "--write",
        action="store_true",
        help="create missing versioned outputs after all provenance checks pass",
    )
    args = parser.parse_args()
    if args.output.resolve() == args.inventory.resolve():
        raise SystemExit("summary and inventory paths must differ")
    summary_bytes, inventory_bytes = build_outputs(
        args.output,
        args.inventory,
        args.bootstrap_samples,
        args.seed,
    )
    contents = {
        args.output: summary_bytes,
        args.inventory: inventory_bytes,
    }
    _preflight_outputs(contents)
    if args.write:
        statuses = _write_missing_outputs(contents)
    else:
        statuses = [
            (
                f"verified:{_repo_path(path)}"
                if path.exists()
                else f"computed-not-written:{_repo_path(path)}"
            )
            for path in contents
        ]
    report = {
        "analysis_id": ANALYSIS_ID,
        "status": statuses,
        "summary_sha256": hashlib.sha256(summary_bytes).hexdigest(),
        "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
