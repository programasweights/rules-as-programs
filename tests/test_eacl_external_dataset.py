from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

import pytest

from experiments.eacl2027 import build_external_dataset


ROOT = Path(__file__).resolve().parents[1] / "experiments" / "eacl2027"
SNAPSHOT = ROOT / "data" / "public" / "external-source-records.json"
DATASET = ROOT / "data" / "public" / "external.jsonl"
MANIFEST = ROOT / "data" / "public" / "external-manifest.json"


def _write_test_corpus(tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer, fieldnames=sorted(build_external_dataset.CSV_FIELDS)
    )
    writer.writeheader()
    for physical_line, record in enumerate(snapshot["records"], 2):
        writer.writerow(record["raw_record"])
        record["physical_line_end"] = physical_line

    corpus_path = tmp_path / "validation_key.csv"
    corpus_path.write_text(buffer.getvalue(), encoding="utf-8", newline="")
    snapshot["source_corpus"]["file_sha256"] = hashlib.sha256(
        corpus_path.read_bytes()
    ).hexdigest()
    snapshot_path = tmp_path / "external-source-records.json"
    snapshot_path.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        build_external_dataset,
        "PINNED_SOURCE_CORPUS",
        snapshot["source_corpus"],
    )
    return corpus_path, snapshot_path


def test_source_csv_verifier_checks_hash_records_and_physical_lines(
    tmp_path, monkeypatch
):
    corpus_path, snapshot_path = _write_test_corpus(tmp_path, monkeypatch)

    report = build_external_dataset.verify_source_csv(corpus_path, snapshot_path)

    assert report["records_verified"] == 8
    assert report["record_ids"] == [130, 188, 308, 358, 411, 748, 1111, 1337]

    corpus_path.write_text(
        corpus_path.read_text(encoding="utf-8").replace(
            "Always use pnpm", "Sometimes use pnpm", 1
        ),
        encoding="utf-8",
        newline="",
    )
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        build_external_dataset.verify_source_csv(corpus_path, snapshot_path)


def test_source_snapshot_and_manifest_preserve_exact_provenance():
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    records = {record["rule_id"]: record for record in snapshot["records"]}

    assert len(records) == 8
    assert manifest["name"] == "rap-external-selected-rules-v1"
    assert manifest["source_corpus"] == snapshot["source_corpus"]
    assert manifest["source_snapshot"] == {
        "file": "data/public/external-source-records.json",
        "sha256": hashlib.sha256(SNAPSHOT.read_bytes()).hexdigest(),
    }
    assert {
        rule_id
        for rule_id, record in records.items()
        if record["adaptation"]["coverage"] == "extracted_sub_rule"
    } == {"3pcxewp5hggr1vsn", "sr09vpkt60y74r0q"}
    assert records["98z9wvr031840p4g"]["raw_record"]["file_path"].startswith("/home/")
    assert records["98z9wvr031840p4g"]["normalized_source"]["file_path"] == (
        ".cursor/rules/use-pnpm.mdc"
    )
    for rule_id, record in records.items():
        copied = {
            key: value
            for key, value in manifest["sources"][rule_id].items()
            if key not in {"instruction_sha256", "corpus_record_url"}
        }
        assert copied == record
        assert manifest["sources"][rule_id]["corpus_record_url"].endswith(
            f"#L{record['physical_line_end']}"
        )


def test_external_cases_are_synthetic_and_unambiguous():
    rows = [
        json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines()
    ]
    by_case = {row["case_id"]: json.loads(row["input"]) for row in rows}

    assert {row["provenance"] for row in rows} == {"synthetic_for_external_instruction"}
    assert by_case["external-e3m4bdwj6gqcwpnn-pair-09-positive"]["patch"] == (
        "See [guide](/guides/README.md)."
    )
    assert by_case["external-sr09vpkt60y74r0q-pair-09-positive"]["file_path"].endswith(
        ".cpp"
    )
    assert by_case["external-3pcxewp5hggr1vsn-pair-09-positive"]["command"] == (
        "git push origin :main"
    )
    assert by_case["external-xb24rc14cpcrsf4g-pair-05-positive"]["command"] == (
        "printf 'bundle' > dist/bundle.js"
    )
    for index in range(1, 11):
        value = by_case[f"external-qfh0h1cf4wt5aeg4-pair-{index:02d}-positive"]
        assert value["file_path"].startswith("docs/sources/")
        assert "---" in value.get("content", value.get("patch", ""))
