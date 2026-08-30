#!/usr/bin/env python3
"""Validate benchmark structure, balance, hashes, and specification leakage."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from rules_as_programs import rules_api
from rules_as_programs.core.rule import is_rule_id, load_rule_file


ALLOWED_LABELS = {"OK", "INFO", "WARNING", "CRITICAL"}
ALLOWED_HOOKS = {"Stop", "PreToolUse"}
ALLOWED_SPLITS = {"development", "test"}
ALLOWED_PROVENANCE = {
    "synthetic",
    "synthetic_for_external_instruction",
    "native_codex",
    "legacy_cursor",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
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


def _require_nonempty_string(row: dict, field: str, line_number: int) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"line {line_number}: invalid {field}")
    return value


def _load_json_object(path: Path, description: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid {description} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"invalid {description} {path}: expected an object")
    return value


def _validate_external_sources(
    manifest: dict,
    manifest_path: Path,
    dataset_rule_ids: set[str],
    dataset_provenance: set[str],
) -> None:
    snapshot_pointer = manifest.get("source_snapshot")
    if snapshot_pointer is None:
        if manifest.get("provenance") == "synthetic_for_external_instruction" or (
            "synthetic_for_external_instruction" in dataset_provenance
        ):
            raise SystemExit(
                "external dataset manifest must include a verified source snapshot"
            )
        return
    if not isinstance(snapshot_pointer, dict):
        raise SystemExit(f"invalid manifest {manifest_path}: source_snapshot")
    relative = snapshot_pointer.get("file")
    expected_sha256 = snapshot_pointer.get("sha256")
    if not isinstance(relative, str) or not relative:
        raise SystemExit(f"invalid manifest {manifest_path}: source_snapshot.file")
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise SystemExit(f"invalid manifest {manifest_path}: source_snapshot.sha256")
    snapshot_path = (ROOT / relative).resolve()
    try:
        snapshot_path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise SystemExit(
            f"invalid manifest {manifest_path}: source snapshot is outside study root"
        ) from exc
    try:
        actual_sha256 = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SystemExit(f"cannot read source snapshot {snapshot_path}: {exc}") from exc
    if actual_sha256 != expected_sha256:
        raise SystemExit(
            f"manifest source snapshot hash mismatch: "
            f"manifest={expected_sha256} actual={actual_sha256}"
        )
    snapshot = _load_json_object(snapshot_path, "source snapshot")
    source_corpus = snapshot.get("source_corpus")
    if source_corpus != manifest.get("source_corpus"):
        raise SystemExit("manifest source_corpus differs from source snapshot")
    if not isinstance(source_corpus, dict):
        raise SystemExit("source snapshot has invalid source_corpus")
    for field in ("repository", "commit", "file", "file_sha256", "license"):
        if not isinstance(source_corpus.get(field), str) or not source_corpus[field]:
            raise SystemExit(f"source snapshot has invalid source_corpus.{field}")
    if re.fullmatch(r"[0-9a-f]{40}", source_corpus["commit"]) is None:
        raise SystemExit("source snapshot has invalid source_corpus.commit")
    if SHA256_RE.fullmatch(source_corpus["file_sha256"]) is None:
        raise SystemExit("source snapshot has invalid source_corpus.file_sha256")

    records = snapshot.get("records")
    if not isinstance(records, list) or not records:
        raise SystemExit("source snapshot has no records")
    expected_sources = {}
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict):
            raise SystemExit(f"source snapshot record {index} is not an object")
        rule_id = record.get("rule_id")
        record_id = record.get("record_id")
        physical_line_end = record.get("physical_line_end")
        raw_record = record.get("raw_record")
        normalized = record.get("normalized_source")
        adaptation = record.get("adaptation")
        if not is_rule_id(rule_id):
            raise SystemExit(f"source snapshot record {index} has invalid rule_id")
        if rule_id in expected_sources:
            raise SystemExit(f"source snapshot has duplicate rule_id {rule_id}")
        if not isinstance(record_id, int) or record_id < 0:
            raise SystemExit(f"source snapshot record {index} has invalid record_id")
        if not isinstance(physical_line_end, int) or physical_line_end < 1:
            raise SystemExit(
                f"source snapshot record {index} has invalid physical_line_end"
            )
        if not isinstance(raw_record, dict):
            raise SystemExit(f"source snapshot record {index} has invalid raw_record")
        raw_fields = {
            "id",
            "project",
            "agent",
            "file_path",
            "line",
            "text",
            "tool_charge",
            "tool_modality",
            "tool_specificity",
        }
        if set(raw_record) != raw_fields or any(
            not isinstance(raw_record[field], str) for field in raw_fields
        ):
            raise SystemExit(
                f"source snapshot record {index} has invalid raw_record fields"
            )
        if raw_record["id"] != str(record_id):
            raise SystemExit(f"source snapshot record {index} has mismatched id")
        if not raw_record["text"].strip():
            raise SystemExit(f"source snapshot record {index} has empty instruction")
        if not isinstance(normalized, dict) or set(normalized) != {
            "repository",
            "repository_license",
            "file_path",
            "instruction_line",
        }:
            raise SystemExit(
                f"source snapshot record {index} has invalid normalized_source"
            )
        if any(
            not isinstance(normalized[field], str) or not normalized[field]
            for field in ("repository", "repository_license", "file_path")
        ) or not isinstance(normalized["instruction_line"], int):
            raise SystemExit(
                f"source snapshot record {index} has invalid normalized fields"
            )
        if raw_record["line"] != str(normalized["instruction_line"]):
            raise SystemExit(
                f"source snapshot record {index} has mismatched instruction line"
            )
        if not isinstance(adaptation, dict):
            raise SystemExit(f"source snapshot record {index} has invalid adaptation")
        if (
            adaptation.get("trigger") != "PreToolUse"
            or adaptation.get("input_field") != "/tool_input"
        ):
            raise SystemExit(
                f"source snapshot record {index} has invalid observable boundary"
            )
        if adaptation.get("coverage") not in {
            "full_instruction",
            "extracted_sub_rule",
        } or not isinstance(adaptation.get("covered_clause"), str):
            raise SystemExit(
                f"source snapshot record {index} has invalid coverage declaration"
            )
        if adaptation["coverage"] == "extracted_sub_rule" and not isinstance(
            adaptation.get("excluded_clause"), str
        ):
            raise SystemExit(
                f"source snapshot record {index} omits its excluded source clause"
            )
        source_url = (
            f"https://github.com/{source_corpus['repository']}/blob/"
            f"{source_corpus['commit']}/{source_corpus['file']}"
            f"#L{physical_line_end}"
        )
        expected_sources[rule_id] = {
            **record,
            "instruction_sha256": hashlib.sha256(
                raw_record["text"].encode("utf-8")
            ).hexdigest(),
            "corpus_record_url": source_url,
        }
    if manifest.get("sources") != expected_sources:
        raise SystemExit("manifest sources differ from the verified source snapshot")
    if set(expected_sources) != dataset_rule_ids:
        raise SystemExit("source snapshot rules differ from dataset rules")
    repositories = [
        source["normalized_source"]["repository"]
        for source in expected_sources.values()
    ]
    if len(repositories) != len(set(repositories)):
        raise SystemExit("source snapshot must contain one rule per repository")
    if manifest.get("provenance") != "synthetic_for_external_instruction" or (
        dataset_provenance != {"synthetic_for_external_instruction"}
    ):
        raise SystemExit("external dataset provenance is inconsistent")
    if manifest.get("exact_spec_example_reuse_forbidden") is not True:
        raise SystemExit(
            "external manifest must declare exact_spec_example_reuse_forbidden"
        )


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
            case_id = _require_nonempty_string(row, "case_id", line_number)
            pair_id = _require_nonempty_string(row, "pair_id", line_number)
            rule_id = _require_nonempty_string(row, "rule_id", line_number)
            hook = _require_nonempty_string(row, "hook", line_number)
            _require_nonempty_string(row, "input", line_number)
            expected = _require_nonempty_string(row, "expected", line_number)
            split = _require_nonempty_string(row, "split", line_number)
            provenance = _require_nonempty_string(row, "provenance", line_number)
            if len(case_id) < 8:
                raise SystemExit(f"line {line_number}: invalid case_id")
            if len(pair_id) < 8:
                raise SystemExit(f"line {line_number}: invalid pair_id")
            if not is_rule_id(rule_id):
                raise SystemExit(f"line {line_number}: invalid rule_id")
            if hook not in ALLOWED_HOOKS:
                raise SystemExit(f"line {line_number}: invalid hook")
            if expected not in ALLOWED_LABELS:
                raise SystemExit(f"line {line_number}: invalid label")
            if split not in ALLOWED_SPLITS:
                raise SystemExit(f"line {line_number}: invalid split")
            if provenance not in ALLOWED_PROVENANCE:
                raise SystemExit(f"line {line_number}: invalid provenance")
            source_hash = row.get("source_hash")
            if source_hash is not None and (
                not isinstance(source_hash, str)
                or SHA256_RE.fullmatch(source_hash) is None
            ):
                raise SystemExit(f"line {line_number}: invalid source_hash")
            note = row.get("note")
            if note is not None and not isinstance(note, str):
                raise SystemExit(f"line {line_number}: invalid note")
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
        manifest = _load_json_object(manifest_path, "manifest")
        for field in ("name", "protocol_version", "provenance", "sha256"):
            if not isinstance(manifest.get(field), str) or not manifest[field]:
                raise SystemExit(f"invalid manifest {manifest_path}: {field}")
        if SHA256_RE.fullmatch(manifest["sha256"]) is None:
            raise SystemExit(f"invalid manifest {manifest_path}: sha256")
        if not isinstance(manifest.get("seed"), int):
            raise SystemExit(f"invalid manifest {manifest_path}: seed")
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
            valid_protocol_versions = {
                str(protocol.get("protocol_version", "")),
                *{
                    str(item.get("version", ""))
                    for item in protocol.get("history", [])
                    if isinstance(item, dict)
                },
            }
            manifest_protocol = str(manifest.get("protocol_version", ""))
            if manifest_protocol not in valid_protocol_versions:
                expected["protocol_version"] = sorted(valid_protocol_versions)
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
        _validate_external_sources(
            manifest,
            manifest_path,
            set(by_rule),
            {str(row["provenance"]) for row in rows},
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
