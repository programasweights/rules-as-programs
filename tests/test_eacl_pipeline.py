from __future__ import annotations

import ast
import hashlib
import json
import random
import subprocess
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.eacl2027 import (
    export_native,
    run_benchmark,
    run_open_judge,
    summarize,
)
from experiments.eacl2027.validate_dataset import validate_dataset
from rules_as_programs import paw_runtime


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT_ROOT = REPO_ROOT / "experiments" / "eacl2027"


def test_controlled_dataset_matches_manifest_and_rule_sources():
    dataset = EXPERIMENT_ROOT / "data" / "public" / "controlled.jsonl"
    manifest = EXPERIMENT_ROOT / "data" / "public" / "controlled-manifest.json"

    report = validate_dataset(dataset, manifest)

    assert report["cases"] == 192
    assert report["pairs"] == 96
    assert report["manifest_verified"]


def test_external_transfer_dataset_matches_manifest_and_rule_sources():
    dataset = EXPERIMENT_ROOT / "data" / "public" / "external.jsonl"
    manifest = EXPERIMENT_ROOT / "data" / "public" / "external-manifest.json"

    report = validate_dataset(dataset, manifest)

    assert report["cases"] == 160
    assert report["pairs"] == 80
    assert len(report["rules"]) == 8
    assert report["manifest_verified"]


def test_external_manifest_sources_must_match_pinned_snapshot(tmp_path):
    dataset = EXPERIMENT_ROOT / "data" / "public" / "external.jsonl"
    source_manifest = EXPERIMENT_ROOT / "data" / "public" / "external-manifest.json"
    manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
    first_rule = sorted(manifest["sources"])[0]
    manifest["sources"][first_rule]["raw_record"]["text"] += " tampered"
    tampered = tmp_path / "external-manifest.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="sources differ"):
        validate_dataset(dataset, tampered)


def test_external_manifest_snapshot_hash_is_verified(tmp_path):
    dataset = EXPERIMENT_ROOT / "data" / "public" / "external.jsonl"
    source_manifest = EXPERIMENT_ROOT / "data" / "public" / "external-manifest.json"
    manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
    manifest["source_snapshot"]["sha256"] = "0" * 64
    tampered = tmp_path / "external-manifest.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="snapshot hash mismatch"):
        validate_dataset(dataset, tampered)


def test_external_manifest_cannot_omit_source_provenance(tmp_path):
    dataset = EXPERIMENT_ROOT / "data" / "public" / "external.jsonl"
    source_manifest = EXPERIMENT_ROOT / "data" / "public" / "external-manifest.json"
    manifest = json.loads(source_manifest.read_text(encoding="utf-8"))
    for field in ("source_snapshot", "source_corpus", "sources"):
        manifest.pop(field)
    tampered = tmp_path / "external-manifest.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SystemExit, match="must include a verified source snapshot"):
        validate_dataset(dataset, tampered)


def test_validator_rejects_tampered_dataset_hash(tmp_path):
    dataset = EXPERIMENT_ROOT / "data" / "public" / "controlled.jsonl"
    manifest = EXPERIMENT_ROOT / "data" / "public" / "controlled-manifest.json"
    tampered = tmp_path / "controlled.jsonl"
    rows = dataset.read_text(encoding="utf-8").splitlines()
    first = json.loads(rows[0])
    first["input"] += " tampered"
    rows[0] = json.dumps(first, sort_keys=True)
    tampered.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="manifest mismatch"):
        validate_dataset(tampered, manifest)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("rule_id", "not-a-rule-id", "invalid rule_id"),
        ("hook", "BeforeShell", "invalid hook"),
        ("split", "holdout", "invalid split"),
        ("provenance", "external_instruction", "invalid provenance"),
        ("source_hash", "not-a-sha", "invalid source_hash"),
    ],
)
def test_validator_enforces_case_schema_fields(tmp_path, field, value, message):
    source = EXPERIMENT_ROOT / "data" / "public" / "controlled.jsonl"
    row = json.loads(source.read_text(encoding="utf-8").splitlines()[0])
    row[field] = value
    dataset = tmp_path / "invalid.jsonl"
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match=message):
        validate_dataset(dataset)


def test_private_export_inside_repo_must_be_untracked_and_ignored(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".gitignore").write_text("private/**\n", encoding="utf-8")
    ignored = repo / "private" / "native.jsonl"
    stageable = repo / "frozen" / "native.jsonl"

    export_native._require_git_ignored_private_output(ignored, repo)
    with pytest.raises(SystemExit, match="must be untracked and Git-ignored"):
        export_native._require_git_ignored_private_output(stageable, repo)

    ignored.parent.mkdir()
    ignored.write_text("private\n", encoding="utf-8")
    subprocess.run(["git", "add", "-f", str(ignored)], cwd=repo, check=True)
    with pytest.raises(SystemExit, match="must be untracked and Git-ignored"):
        export_native._require_git_ignored_private_output(ignored, repo)


def test_no_stageable_jsonl_contains_unreviewed_private_rows():
    paths = subprocess.check_output(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "experiments/eacl2027",
        ],
        cwd=REPO_ROOT,
        text=True,
    ).splitlines()

    for relative in paths:
        if not relative.endswith(".jsonl"):
            continue
        contents = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert '"privacy_status": "UNREVIEWED_PRIVATE"' not in contents, relative


def test_every_programasweights_compile_is_public_and_persistent():
    calls = []
    for path in (REPO_ROOT / "rules_as_programs").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        aliases = {
            imported.asname or imported.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for imported in node.names
            if imported.name == "programasweights"
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(
                node.func, ast.Attribute
            ):
                continue
            if (
                node.func.attr == "compile"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in aliases
            ):
                calls.append((path, node))

    assert calls, "expected at least one programasweights.compile call"
    for path, call in calls:
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert isinstance(keywords.get("public"), ast.Constant), path
        assert keywords["public"].value is True, path
        assert isinstance(keywords.get("ephemeral"), ast.Constant), path
        assert keywords["ephemeral"].value is False, path


def test_paw_runtime_compile_passes_only_spec_and_public_persistent_flags(monkeypatch):
    calls = []

    def fake_compile(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(id="program")

    monkeypatch.setattr(paw_runtime.paw, "compile", fake_compile)
    runtime = paw_runtime.PawRuntime.__new__(paw_runtime.PawRuntime)

    runtime._compile("exact specification", None)
    runtime._compile("compiler specification", "named-compiler")

    assert calls == [
        (("exact specification",), {"public": True, "ephemeral": False}),
        (
            ("compiler specification",),
            {
                "compiler": "named-compiler",
                "public": True,
                "ephemeral": False,
            },
        ),
    ]


def test_benchmark_compile_retries_are_serial_and_spec_scoped(monkeypatch):
    instances = []

    class FakeRuntime:
        def __init__(self, **_kwargs):
            self.compile_calls = []
            self.counts = Counter()
            self.warmed = []
            instances.append(self)

        def compiler_info(self, compiler):
            return {"name": compiler, "latest_snapshot": "snapshot"}

        def cached_program_id_for_spec(self, spec, compiler):
            assert compiler == "compiler"
            return ""

        def program_id_for_spec(self, spec, compiler, timeout=None):
            assert compiler == "compiler"
            assert timeout == 900.0
            self.compile_calls.append(spec)
            self.counts[spec] += 1
            return f"program-{spec}" if self.counts[spec] == 2 else ""

        def warm(self, program_id):
            self.warmed.append(program_id)
            return True

    monkeypatch.setattr(run_benchmark, "PawRuntime", FakeRuntime)
    monkeypatch.setattr(run_benchmark.time, "sleep", lambda _seconds: None)
    rules = {
        "rule-a": SimpleNamespace(spec="spec-a"),
        "rule-b": SimpleNamespace(spec="spec-b"),
    }

    _runtime, programs, _compiler_info = run_benchmark._prepare_paw(
        rules, "compiler", True, 2
    )

    assert instances[0].compile_calls == ["spec-a", "spec-a", "spec-b", "spec-b"]
    assert programs == {
        "rule-a": "program-spec-a",
        "rule-b": "program-spec-b",
    }


def test_benchmark_git_state_ignores_unrelated_repository_changes(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    experiment_root = repo / "experiments" / "eacl2027"
    package_root = repo / "rules_as_programs"
    unrelated = repo / "paper"
    experiment_root.mkdir(parents=True)
    package_root.mkdir()
    unrelated.mkdir()
    (experiment_root / "runner.py").write_text("clean\n", encoding="utf-8")
    (package_root / "module.py").write_text("clean\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("clean\n", encoding="utf-8")
    (unrelated / "draft.tex").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Experiment Test",
            "-c",
            "user.email=experiment@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=repo,
        check=True,
    )
    monkeypatch.setattr(run_benchmark, "ROOT", experiment_root)

    (unrelated / "draft.tex").write_text("unrelated change\n", encoding="utf-8")
    unrelated_state = run_benchmark._git_state()
    assert unrelated_state["dirty"] is False

    (experiment_root / "runner.py").write_text("scoped change\n", encoding="utf-8")
    scoped_state = run_benchmark._git_state()
    assert scoped_state["dirty"] is True
    assert scoped_state["scope"] == [
        "rules_as_programs",
        "experiments/eacl2027",
        "pyproject.toml",
    ]


def _summary_rows():
    rows = []
    for rule_id in ("rule-a", "rule-b"):
        for pair_index in range(2):
            pair_id = f"{rule_id}-pair-{pair_index}"
            for polarity, expected in (("positive", "WARNING"), ("negative", "OK")):
                rows.append(
                    {
                        "case_id": f"{pair_id}-{polarity}",
                        "pair_id": pair_id,
                        "rule_id": rule_id,
                        "hook": "Stop",
                        "input": f"{pair_id}-{polarity}",
                        "expected": expected,
                        "prediction": expected,
                        "correct": True,
                        "latency_ms": 1.0,
                        "system": "fixture",
                    }
                )
    return rows


def test_bootstrap_resamples_whole_contrastive_pair_clusters():
    rows = _summary_rows()
    sampled = summarize._resample_pair_clusters(rows, random.Random(7))
    source_counts = Counter(row["pair_id"] for row in rows)
    sampled_counts = Counter(row["pair_id"] for row in sampled)

    assert len(sampled) == len(rows)
    assert all(
        count % source_counts[pair_id] == 0 for pair_id, count in sampled_counts.items()
    )
    for pair_id in sampled_counts:
        polarities = Counter(
            row["expected"] for row in sampled if row["pair_id"] == pair_id
        )
        assert polarities["OK"] == polarities["WARNING"]


def test_external_bootstrap_resamples_rules_then_complete_pairs():
    rows = _summary_rows()

    class PlannedRng:
        def __init__(self):
            self.calls = 0

        def choices(self, population, k):
            self.calls += 1
            if self.calls == 1:
                assert population == ["rule-a", "rule-b"]
                assert k == 2
                return ["rule-a", "rule-a"]
            assert len(population) == 2
            assert k == 2
            return list(population)

    sampled = summarize._resample_rule_then_pair_clusters(rows, PlannedRng())
    instances = Counter(row["_bootstrap_rule_instance"] for row in sampled)

    assert len(sampled) == len(rows)
    assert instances == {"0:rule-a": 4, "1:rule-a": 4}
    assert len(summarize._metrics(sampled)["per_rule"]) == 2


def test_external_primary_bootstrap_keeps_every_selected_rule_fixed():
    rows = _summary_rows()

    class FirstPairRng:
        @staticmethod
        def choices(population, k):
            return [population[0]] * k

    sampled = summarize._resample_pairs_within_each_rule(rows, FirstPairRng())
    by_rule = Counter(row["rule_id"] for row in sampled)
    pairs_by_rule = {
        rule_id: {row["pair_id"] for row in sampled if row["rule_id"] == rule_id}
        for rule_id in by_rule
    }

    assert len(sampled) == len(rows)
    assert by_rule == {"rule-a": 4, "rule-b": 4}
    assert all(len(pair_ids) == 1 for pair_ids in pairs_by_rule.values())


def test_summary_rejects_case_drift_and_inconsistent_correct_flag(tmp_path):
    rows = _summary_rows()
    _system, signatures = summarize._validate_run_rows(tmp_path / "first.jsonl", rows)
    drifted = [dict(row) for row in rows]
    drifted[0]["input"] = "changed"
    with pytest.raises(SystemExit, match="cases differ"):
        summarize._validate_run_rows(tmp_path / "second.jsonl", drifted, signatures)

    inconsistent = [dict(row) for row in rows]
    inconsistent[0]["correct"] = False
    with pytest.raises(SystemExit, match="inconsistent correct flag"):
        summarize._validate_run_rows(tmp_path / "broken.jsonl", inconsistent)


def test_open_judge_refuses_prompt_truncation():
    class FakeTokenizer:
        def __call__(self, prompts, **kwargs):
            assert kwargs == {"padding": False, "truncation": False}
            return {"input_ids": [list(range(len(prompt))) for prompt in prompts]}

    tokenizer = FakeTokenizer()
    assert run_open_judge._require_exact_prompt_lengths(
        tokenizer, ["short"], ["case-short"], 5
    ) == [5]
    with pytest.raises(SystemExit, match="refusing to truncate"):
        run_open_judge._require_exact_prompt_lengths(
            tokenizer, ["too long"], ["case-long"], 5
        )


def test_open_judge_can_require_all_slurm_partition(monkeypatch):
    monkeypatch.setenv("SLURM_JOB_ID", "123")
    monkeypatch.setenv("SLURM_JOB_PARTITION", "ALL")
    monkeypatch.setenv("SLURM_JOB_NODELIST", "gpu001")

    assert run_open_judge._require_slurm_partition("ALL") == {
        "job_id": "123",
        "partition": "ALL",
        "node_list": "gpu001",
    }
    with pytest.raises(SystemExit, match="required Slurm partition 'other'"):
        run_open_judge._require_slurm_partition("other")


def test_existing_benchmark_manifests_match_outputs_when_present():
    manifests = sorted((EXPERIMENT_ROOT / "outputs").rglob("*.jsonl.manifest.json"))
    for manifest_path in manifests:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        output = Path(str(manifest_path).removesuffix(".manifest.json"))
        dataset = Path(manifest["dataset"])
        if not dataset.is_absolute():
            dataset = REPO_ROOT / dataset
        assert output.is_file()
        assert (
            hashlib.sha256(output.read_bytes()).hexdigest() == manifest["output_sha256"]
        )
        assert (
            hashlib.sha256(dataset.read_bytes()).hexdigest()
            == manifest["dataset_sha256"]
        )
        assert (
            sum(1 for line in output.read_text(encoding="utf-8").splitlines() if line)
            == manifest["cases"]
        )
        if "frozen" in manifest_path.parts:
            assert manifest["git"]["commit"]
            assert manifest["git"]["dirty"] is False
