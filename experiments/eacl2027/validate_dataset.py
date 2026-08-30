#!/usr/bin/env python3
"""Validate benchmark structure, balance, hashes, and specification leakage."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from rules_as_programs import rules_api
from rules_as_programs.core.rule import load_rule_file


ALLOWED_LABELS = {"OK", "INFO", "WARNING", "CRITICAL"}
ROOT = Path(__file__).resolve().parent
DATASET_FIELDS = {
    "case_id",
    "pair_id",
    "rule_id",
    "hook",
    "input",
    "expected",
    "split",
    "provenance",
    "source_hash",
    "note",
}


def validate_dataset(dataset: Path, manifest_path: Path | None = None) -> dict:
    rows = []
    with dataset.open(encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, 1):
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"line {line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise SystemExit(f"line {line_number}: expected a JSON object")
            missing = {
                "case_id",
                "pair_id",
                "rule_id",
                "hook",
                "input",
                "expected",
                "split",
                "provenance",
            } - set(row)
            if missing:
                raise SystemExit(f"line {line_number}: missing {sorted(missing)}")
            extra = set(row) - DATASET_FIELDS
            if extra:
                raise SystemExit(f"line {line_number}: unexpected {sorted(extra)}")
            if row["expected"] not in ALLOWED_LABELS:
                raise SystemExit(f"line {line_number}: invalid label")
            if not isinstance(row["input"], str) or not row["input"].strip():
                raise SystemExit(f"line {line_number}: empty input")
            rows.append(row)

    if not rows:
        raise SystemExit("dataset is empty")

    ids = [row["case_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate case_id")
    keyed_inputs = [(row["rule_id"], row["input"]) for row in rows]
    if len(keyed_inputs) != len(set(keyed_inputs)):
        raise SystemExit("duplicate rule/input pair")

    pairs = defaultdict(list)
    for row in rows:
        pairs[row["pair_id"]].append(row)
    invalid_pairs = {
        key: values
        for key, values in pairs.items()
        if len(values) != 2
        or sum(value["expected"] == "OK" for value in values) != 1
        or len({value["rule_id"] for value in values}) != 1
    }
    if invalid_pairs:
        raise SystemExit(f"invalid contrastive pairs: {sorted(invalid_pairs)[:5]}")

    by_rule = Counter(row["rule_id"] for row in rows)
    labels = Counter((row["rule_id"], row["expected"]) for row in rows)
    source_hashes = {}
    for rule_id in by_rule:
        rule_path = ROOT / "rules" / rule_id / "rule.py"
        loaded = load_rule_file(rule_path, "experiment")
        if len(loaded) != 1:
            raise SystemExit(f"{rule_path}: expected exactly one rule")
        source_hash = hashlib.sha256(rule_path.read_bytes()).hexdigest()
        source_hashes[rule_id] = source_hash
        invalid_metadata = [
            row["case_id"]
            for row in rows
            if row["rule_id"] == rule_id
            and (
                row["hook"] != loaded[0].trigger
                or row.get("source_hash") != source_hash
            )
        ]
        if invalid_metadata:
            raise SystemExit(
                f"{rule_id}: hook/source metadata mismatch {invalid_metadata[:5]}"
            )
        cases = list(loaded[0].examples) or rules_api.spec_examples(
            loaded[0].spec or ""
        )
        examples = {value for value, _expected in cases}
        leaked = [
            row["case_id"]
            for row in rows
            if row["rule_id"] == rule_id and row["input"] in examples
        ]
        if leaked:
            raise SystemExit(f"{rule_id}: leaked specification cases {leaked}")

    manifest = None
    if manifest_path is None:
        candidate = dataset.with_name(f"{dataset.stem}-manifest.json")
        if candidate.is_file():
            manifest_path = candidate
    if manifest_path is not None:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"invalid manifest {manifest_path}: {exc}") from exc
        if not isinstance(manifest, dict):
            raise SystemExit(f"invalid manifest {manifest_path}: expected an object")
        actual_sha256 = hashlib.sha256(dataset.read_bytes()).hexdigest()
        expected = {
            "sha256": actual_sha256,
            "cases": len(rows),
            "pairs": len(pairs),
            "rules": len(by_rule),
            "rule_source_sha256": source_hashes,
        }
        protocol_path = ROOT / "protocol.json"
        if protocol_path.is_file():
            try:
                protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SystemExit(f"invalid protocol {protocol_path}: {exc}") from exc
            expected["protocol_version"] = protocol.get("protocol_version")
        mismatched = {
            key: {"manifest": manifest.get(key), "actual": value}
            for key, value in expected.items()
            if manifest.get(key) != value
        }
        cases_per_rule = set(by_rule.values())
        if len(cases_per_rule) == 1:
            actual_cases_per_rule = next(iter(cases_per_rule))
            if manifest.get("cases_per_rule") != actual_cases_per_rule:
                mismatched["cases_per_rule"] = {
                    "manifest": manifest.get("cases_per_rule"),
                    "actual": actual_cases_per_rule,
                }
        if mismatched:
            raise SystemExit(
                f"manifest mismatch: {json.dumps(mismatched, sort_keys=True)}"
            )

    report = {
        "cases": len(rows),
        "pairs": len(pairs),
        "rules": dict(sorted(by_rule.items())),
        "labels": {
            f"{rule_id}:{label}": count
            for (rule_id, label), count in sorted(labels.items())
        },
        "manifest": str(manifest_path) if manifest_path else "",
        "manifest_verified": manifest is not None,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    report = validate_dataset(args.dataset, args.manifest)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
