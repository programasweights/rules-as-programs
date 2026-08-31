from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from experiments.eacl2027 import run_scaling_faults_analysis_bundle as bundle
from experiments.eacl2027.analyze_scaling_faults import REDUCER_CONFIG


REAL_FORMAL_RUNTIME_GATE = bundle._formal_runtime_gate
REAL_H3_SOURCE_SNAPSHOT_RECEIPT = bundle._h3_source_snapshot_receipt
REAL_RULES_ORIGIN_PROBE = bundle._rules_origin_probe


@pytest.fixture(autouse=True)
def _formal_runtime_fixture(monkeypatch):
    def fake_gate(environ, slurm, runtime):
        source_root = environ["RAP_ANALYSIS_H3_SOURCE_ROOT"]
        node_root = str(Path(source_root).parent)
        return {
            "version": "test-formal-runtime-gate",
            "job_id": slurm["job_id"],
            "venv": f"{node_root}/venv",
            "guard": {"path": f"{node_root}/network-guard/sitecustomize.py"},
            "h3_source_snapshot": {
                "root": source_root,
                "inventory_sha256": "test-h3-snapshot",
            },
        }

    monkeypatch.setattr(bundle, "_formal_runtime_gate", fake_gate)
    monkeypatch.setattr(
        bundle,
        "_rules_origin_probe",
        lambda environ, source_root, expected_venv: {
            "exit_code": 0,
            "cwd": str(source_root),
            "modules_sha256": "test-wheel-origins",
        },
    )
    monkeypatch.setattr(
        bundle,
        "_h3_source_snapshot_receipt",
        lambda root: {
            "root": str(root),
            "inventory_sha256": "test-h3-snapshot",
        },
    )


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _make_inputs(tmp_path: Path) -> tuple[Path, Path]:
    attempts = tmp_path / "attempts"
    attempts.mkdir(mode=0o700)
    (attempts / bundle.R01).mkdir(mode=0o700)
    (attempts / bundle.R02).mkdir(mode=0o700)
    output_parent = tmp_path / "analysis"
    output_parent.mkdir(mode=0o700)
    return attempts, output_parent


def _reduced(attempts: Path, analysis_id: str, *, complete: bool) -> bytes:
    r01 = {
        "raw_attempt_id": bundle.R01,
        "status": "completed_with_system_violations",
        "candidate_eligible": False,
        "validation_error": None,
        "replacement_authorized_by_successor": True,
        "adjudicated_status": "superseded_premeasurement_harness_error",
        "raw_status_preserved": "completed_with_system_violations",
        "numeric_aggregate_excluded": True,
    }
    r02 = {
        "raw_attempt_id": bundle.R02,
        "status": "completed" if complete else "incomplete_harness_error",
        "candidate_eligible": complete,
        "validation_error": None,
        "replacement_validation_error": None,
        "replacement_authorized_by_successor": False,
    }
    ledger = [r01, r02]
    reducer_config = REDUCER_CONFIG
    selected = bundle.R02 if complete else None
    blocked = None if complete else bundle.R02
    binding = {
        "analysis_id": analysis_id,
        "analysis_version": bundle.ANALYSIS_VERSION,
        "analysis_code": [
            {"path": path, "sha256": bundle.BOUND_H3_FILES[path]}
            for path in bundle.ANALYZER_CODE_PATHS
        ],
        "protocol_documents": [
            {"path": path, "sha256": bundle.BOUND_H3_FILES[path]}
            for path in bundle.PROTOCOL_PATHS
        ],
        "reducer_config": reducer_config,
        "reducer_config_sha256": hashlib.sha256(_canonical(reducer_config)).hexdigest(),
        "attempts_root": str(attempts.resolve()),
        "launch_ordered_attempts": ledger,
        "selected_primary_raw_attempt_id": selected,
        "selection_blocked_by": blocked,
        "chain_error": None,
    }
    value = {
        "schema_version": 1,
        "analysis_id": analysis_id,
        "generated_at": "2026-08-31T12:00:00+00:00",
        "analysis_binding": binding,
        "analysis_binding_sha256": hashlib.sha256(_canonical(binding)).hexdigest(),
        "attempt_ledger": ledger,
        "primary_numeric": {
            "promoted": complete,
            "selected_raw_attempt_id": selected,
            "selection_blocked_by": blocked,
            "selection_rule": bundle.SELECTION_RULE,
        },
        "endpoints": (
            {"matrix": {}, "soak": {}, "offline": {}, "faults": {}}
            if complete
            else None
        ),
        "sensitivity_endpoints": {},
    }
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _slurm_env() -> dict[str, str]:
    return {
        "HOME": "/private/tmp/fake-home",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SLURM_JOB_ID": "900001",
        "SLURM_JOB_PARTITION": "ALL",
        "SLURM_JOB_NODELIST": "watgpu108",
        "PYTHONNOUSERSITE": "1",
        "PIP_NO_INDEX": "1",
        "RAP_ANALYSIS_H3_SOURCE_ROOT": (
            "/private/tmp/rap-eacl-analysis-900001/h3-source"
        ),
        "RAP_ANALYSIS_NETWORK_GUARD": "python-inet-deny-v1",
    }


def _safe_rename(parent_fd, source_name, destination_name):
    os.rename(
        source_name,
        destination_name,
        src_dir_fd=parent_fd,
        dst_dir_fd=parent_fd,
    )
    return "test-exclusive-rename"


def _fake_analyzer(monkeypatch, payload: bytes, *, exit_code: int = 0, stderr=b""):
    def run(argv, environ):
        return subprocess.CompletedProcess(
            args=list(argv), returncode=exit_code, stdout=payload, stderr=stderr
        )

    monkeypatch.setattr(bundle, "_invoke_analyzer", run)
    monkeypatch.setattr(bundle, "_rename_noreplace", _safe_rename)
    monkeypatch.setattr(
        bundle, "_native_publication_method", lambda: "test-exclusive-rename"
    )


def _load(path: Path):
    return json.loads(path.read_text())


def test_complete_bundle_has_exact_receipts_and_immutable_files(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    analysis_id = "formal-v3-ledger-a01"
    _fake_analyzer(monkeypatch, _reduced(attempts, analysis_id, complete=True))
    destination = parent / analysis_id

    result = bundle.run_analysis_bundle(
        attempts, analysis_id, destination, environ=_slurm_env()
    )

    assert result["classification"] == "complete"
    assert destination.is_dir()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o500
    assert sorted(item.name for item in destination.iterdir()) == sorted(
        bundle.FINAL_FILE_NAMES
    )
    for path in destination.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
    gate = _load(destination / "gate.json")
    assert gate["complete"] is True
    assert gate["formal_numeric_publication_authorized"] is True
    receipt = _load(destination / "run-receipt.json")
    assert receipt["analyzer"]["argv"][:3] == [
        os.fsdecode(Path(os.sys.executable)),
        "-m",
        bundle.ANALYZER_MODULE,
    ]
    assert receipt["publication"]["method"] == "test-exclusive-rename"
    assert result["publication_method"] == receipt["publication"]["method"]
    for name in ("environment.json", "gate.json", "reduced.json"):
        data = (destination / name).read_bytes()
        recorded = receipt["files"][name]
        assert recorded["bytes"] == len(data)
        assert recorded["sha256"] == hashlib.sha256(data).hexdigest()
        assert recorded["mode"] == 0o444
    environment = _load(destination / "environment.json")
    assert environment["h3_commit"] == bundle.H3_COMMIT
    assert environment["slurm"]["required_partition"] == "ALL"
    assert environment["source_binding_sha256"] == bundle._binding_digest(
        environment["source_binding"]
    )
    assert environment["formal_runtime_gate"]["version"] == ("test-formal-runtime-gate")


def test_incomplete_analysis_is_preserved_but_not_authorized(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    analysis_id = "formal-v3-ledger-incomplete"
    raw = _reduced(attempts, analysis_id, complete=False)
    _fake_analyzer(monkeypatch, raw)
    destination = parent / analysis_id

    result = bundle.run_analysis_bundle(
        attempts, analysis_id, destination, environ=_slurm_env()
    )

    assert result["classification"] == "incomplete"
    assert (destination / "reduced.json").read_bytes() == raw
    gate = _load(destination / "gate.json")
    assert gate["complete"] is False
    assert gate["formal_numeric_publication_authorized"] is False
    assert "r02 is numeric eligible" in gate["incomplete_reasons"]


def test_analyzer_failure_publishes_lossless_failure_receipt(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    stdout = b"partial output\x00"
    stderr = b"traceback: reducer failed\n"
    _fake_analyzer(monkeypatch, stdout, exit_code=17, stderr=stderr)
    destination = parent / "analysis-failed"

    result = bundle.run_analysis_bundle(
        attempts, "analysis-failed", destination, environ=_slurm_env()
    )

    assert result["classification"] == "analyzer_failed"
    reduced = _load(destination / "reduced.json")
    assert reduced["status"] == "analyzer_failed"
    receipt = _load(destination / "run-receipt.json")
    assert receipt["analyzer"]["exit_code"] == 17
    assert receipt["analyzer"]["stdout"]["bytes"] == len(stdout)
    assert receipt["analyzer"]["stdout"]["base64"] == "cGFydGlhbCBvdXRwdXQA"
    assert receipt["analyzer"]["stderr"]["sha256"] == hashlib.sha256(stderr).hexdigest()
    assert (
        _load(destination / "gate.json")["formal_numeric_publication_authorized"]
        is False
    )


def test_analyzer_launch_error_is_published_as_failure_evidence(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)

    def fail_to_launch(argv, environ):
        raise OSError("injected exec failure")

    monkeypatch.setattr(bundle, "_invoke_analyzer", fail_to_launch)
    monkeypatch.setattr(bundle, "_rename_noreplace", _safe_rename)
    monkeypatch.setattr(
        bundle, "_native_publication_method", lambda: "test-exclusive-rename"
    )
    destination = parent / "analysis-launch-failed"
    result = bundle.run_analysis_bundle(
        attempts,
        "analysis-launch-failed",
        destination,
        environ=_slurm_env(),
    )
    receipt = _load(destination / "run-receipt.json")
    assert result["classification"] == "analyzer_failed"
    assert receipt["analyzer"]["exit_code"] == 127
    assert receipt["analyzer"]["invocation_error"] == {
        "type": "OSError",
        "message": "injected exec failure",
    }


def test_existing_output_is_never_replaced(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    destination = parent / "occupied"
    destination.mkdir(mode=0o700)
    marker = destination / "owner-data"
    marker.write_text("keep\n")
    called = False

    def should_not_run(argv, environ):
        nonlocal called
        called = True
        raise AssertionError("analyzer must not run")

    monkeypatch.setattr(bundle, "_invoke_analyzer", should_not_run)
    with pytest.raises(bundle.BundleCollisionError):
        bundle.run_analysis_bundle(
            attempts, "analysis-collision", destination, environ=_slurm_env()
        )
    assert called is False
    assert marker.read_text() == "keep\n"
    assert not list(parent.glob(".occupied.staging-*"))


def test_native_directory_publication_is_no_replace(tmp_path):
    parent = tmp_path / "native-publication"
    parent.mkdir(mode=0o700)
    (parent / "source-success").mkdir(mode=0o700)
    (parent / "source-collision").mkdir(mode=0o700)
    (parent / "occupied").mkdir(mode=0o700)
    marker = parent / "occupied" / "owner-data"
    marker.write_text("keep\n")
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        method = bundle._rename_noreplace(parent_fd, "source-success", "published")
        with pytest.raises(bundle.BundleCollisionError):
            bundle._rename_noreplace(parent_fd, "source-collision", "occupied")
    finally:
        os.close(parent_fd)
    assert "RENAME" in method
    assert (parent / "published").is_dir()
    assert (parent / "source-collision").is_dir()
    assert marker.read_text() == "keep\n"


def test_attempts_path_swap_aborts_without_publication(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    analysis_id = "analysis-path-swap"
    raw = _reduced(attempts, analysis_id, complete=True)

    def swap_then_return(argv, environ):
        moved = attempts.with_name("attempts-moved")
        attempts.rename(moved)
        attempts.symlink_to(moved, target_is_directory=True)
        return subprocess.CompletedProcess(argv, 0, raw, b"")

    monkeypatch.setattr(bundle, "_invoke_analyzer", swap_then_return)
    destination = parent / analysis_id
    with pytest.raises(bundle.AnalysisBundleError, match="swapped"):
        bundle.run_analysis_bundle(
            attempts, analysis_id, destination, environ=_slurm_env()
        )
    assert not destination.exists()
    assert not list(parent.glob(f".{analysis_id}.staging-*"))


def test_output_parent_path_swap_aborts_and_cleans_original_staging(
    tmp_path, monkeypatch
):
    attempts, parent = _make_inputs(tmp_path)
    analysis_id = "analysis-parent-swap"
    raw = _reduced(attempts, analysis_id, complete=True)
    moved = parent.with_name("analysis-moved")

    def swap_then_return(argv, environ):
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        return subprocess.CompletedProcess(argv, 0, raw, b"")

    monkeypatch.setattr(bundle, "_invoke_analyzer", swap_then_return)
    destination = parent / analysis_id
    with pytest.raises(bundle.AnalysisBundleError, match="swapped"):
        bundle.run_analysis_bundle(
            attempts, analysis_id, destination, environ=_slurm_env()
        )
    assert not destination.exists()
    assert not list(moved.glob(f".{analysis_id}.staging-*"))


def test_atomic_publication_failure_cleans_claim_and_staging(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    analysis_id = "analysis-atomic-failure"
    _fake_analyzer(monkeypatch, _reduced(attempts, analysis_id, complete=True))

    def fail_rename(parent_fd, source_name, destination_name):
        raise bundle.PublicationError("injected native rename failure")

    monkeypatch.setattr(bundle, "_rename_noreplace", fail_rename)
    destination = parent / analysis_id
    with pytest.raises(bundle.PublicationError, match="injected"):
        bundle.run_analysis_bundle(
            attempts, analysis_id, destination, environ=_slurm_env()
        )
    assert not destination.exists()
    assert not (parent / f".{analysis_id}.publication-claim").exists()
    assert not list(parent.glob(f".{analysis_id}.staging-*"))


def test_cleanup_does_not_unlink_a_substituted_staging_directory(tmp_path):
    parent = tmp_path / "cleanup-swap"
    parent.mkdir(mode=0o700)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    staging_fd = None
    try:
        name, info = bundle._create_staging_directory(parent_fd, "analysis")
        staging_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            dir_fd=parent_fd,
        )
        moved_name = f"{name}.moved"
        os.rename(name, moved_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        substitute = parent / name / "environment.json"
        substitute.write_text("owner data\n")

        bundle._cleanup_staging(parent_fd, name, info, staging_fd)

        assert substitute.read_text() == "owner data\n"
        assert (parent / moved_name).is_dir()
    finally:
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(parent_fd)


def test_partition_other_than_all_is_rejected_before_execution(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    environment = _slurm_env()
    environment["SLURM_JOB_PARTITION"] = "cpu"
    called = False

    def should_not_run(argv, environ):
        nonlocal called
        called = True
        raise AssertionError("analyzer must not run")

    monkeypatch.setattr(bundle, "_invoke_analyzer", should_not_run)
    with pytest.raises(bundle.EnvironmentGateError, match="SLURM_JOB_PARTITION"):
        bundle.run_analysis_bundle(
            attempts, "analysis-partition", parent / "result", environ=environment
        )
    assert called is False


def test_formal_runtime_gate_rejects_non_job_local_python():
    environment = _slurm_env()
    slurm = bundle._slurm_receipt(environment)
    runtime = bundle._runtime_receipt(environment)
    with pytest.raises(bundle.EnvironmentGateError, match="environment|venv"):
        REAL_FORMAL_RUNTIME_GATE(environment, slurm, runtime)


def test_exact_h3_file_hash_mismatch_is_rejected(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    path = bundle.ANALYZER_CODE_PATHS[0]
    monkeypatch.setitem(bundle.BOUND_H3_FILES, path, "0" * 64)
    called = False

    def should_not_run(argv, environ):
        nonlocal called
        called = True
        raise AssertionError("analyzer must not run")

    monkeypatch.setattr(bundle, "_invoke_analyzer", should_not_run)
    with pytest.raises(bundle.SourceBindingError, match="hash mismatch"):
        bundle.run_analysis_bundle(
            attempts, "analysis-hash", parent / "result", environ=_slurm_env()
        )
    assert called is False


@pytest.mark.parametrize(
    "parent_selector",
    [
        lambda attempts: attempts,
        lambda attempts: attempts / bundle.R01,
    ],
)
def test_bundle_output_cannot_overlap_raw_attempts(
    tmp_path, monkeypatch, parent_selector
):
    attempts, _parent = _make_inputs(tmp_path)
    called = False

    def should_not_run(argv, environ):
        nonlocal called
        called = True
        raise AssertionError("analyzer must not run")

    monkeypatch.setattr(bundle, "_invoke_analyzer", should_not_run)
    output = parent_selector(attempts) / "forbidden-analysis"
    with pytest.raises(bundle.AnalysisBundleError, match="attempts"):
        bundle.run_analysis_bundle(
            attempts, "analysis-overlap", output, environ=_slurm_env()
        )
    assert called is False
    assert not output.exists()
    assert not list(output.parent.glob(".forbidden-analysis.staging-*"))


def test_complete_result_with_blocker_is_rejected_losslessly(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    analysis_id = "analysis-bad-blocker"
    value = json.loads(_reduced(attempts, analysis_id, complete=True))
    value["primary_numeric"]["selection_blocked_by"] = bundle.R01
    value["analysis_binding"]["selection_blocked_by"] = bundle.R01
    value["analysis_binding_sha256"] = hashlib.sha256(
        _canonical(value["analysis_binding"])
    ).hexdigest()
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    _fake_analyzer(monkeypatch, raw)
    destination = parent / analysis_id
    result = bundle.run_analysis_bundle(
        attempts, analysis_id, destination, environ=_slurm_env()
    )
    assert result["classification"] == "analyzer_invalid_output"
    receipt = _load(destination / "run-receipt.json")
    assert receipt["analyzer"]["stdout"]["sha256"] == hashlib.sha256(raw).hexdigest()


def test_transitive_integrated_code_hash_is_bound(tmp_path, monkeypatch):
    attempts, parent = _make_inputs(tmp_path)
    path = "experiments/eacl2027/run_integrated.py"
    monkeypatch.setitem(bundle.BOUND_H3_FILES, path, "0" * 64)
    with pytest.raises(bundle.SourceBindingError, match="run_integrated"):
        bundle.run_analysis_bundle(
            attempts,
            "analysis-integrated-hash",
            parent / "result",
            environ=_slurm_env(),
        )


def test_h3_experiments_inventory_constants_match_exact_commit():
    assert (
        subprocess.check_output(
            ["git", "rev-parse", f"{bundle.H3_COMMIT}^{{tree}}"],
            cwd=bundle.REPO_ROOT,
            text=True,
        ).strip()
        == bundle.H3_ROOT_TREE_GIT_SHA1
    )
    assert (
        subprocess.check_output(
            ["git", "rev-parse", f"{bundle.H3_COMMIT}:experiments"],
            cwd=bundle.REPO_ROOT,
            text=True,
        ).strip()
        == bundle.H3_EXPERIMENTS_TREE_GIT_SHA1
    )
    raw_tree = subprocess.check_output(
        ["git", "ls-tree", "-r", "-z", bundle.H3_COMMIT, "experiments"],
        cwd=bundle.REPO_ROOT,
    )
    receipts = []
    for entry in raw_tree.rstrip(b"\0").split(b"\0"):
        metadata, raw_path = entry.split(b"\t", 1)
        _mode, kind, object_id = metadata.decode().split()
        assert kind == "blob"
        data = subprocess.check_output(
            ["git", "cat-file", "blob", object_id], cwd=bundle.REPO_ROOT
        )
        receipts.append(
            {
                "path": raw_path.decode(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    assert len(receipts) == bundle.H3_EXPERIMENTS_FILE_COUNT
    assert sum(item["bytes"] for item in receipts) == (
        bundle.H3_EXPERIMENTS_TOTAL_BYTES
    )
    assert hashlib.sha256(_canonical(receipts)).hexdigest() == (
        bundle.H3_EXPERIMENTS_INVENTORY_SHA256
    )


def test_added_working_tree_rap_module_cannot_enter_h3_source_snapshot(
    tmp_path, monkeypatch
):
    source = tmp_path / "h3-source"
    analyzer = source / "experiments/eacl2027/analyze_scaling_faults.py"
    analyzer.parent.mkdir(parents=True, mode=0o700)
    analyzer.write_bytes(b"# exact fake analyzer\n")
    analyzer.chmod(0o400)
    for directory in (analyzer.parent, analyzer.parent.parent, source):
        directory.chmod(0o500)
    clean_receipts = [
        {
            "path": "experiments/eacl2027/analyze_scaling_faults.py",
            "bytes": len(analyzer.read_bytes()),
            "sha256": hashlib.sha256(analyzer.read_bytes()).hexdigest(),
        }
    ]
    monkeypatch.setattr(
        bundle,
        "BOUND_H3_FILES",
        {clean_receipts[0]["path"]: clean_receipts[0]["sha256"]},
    )
    monkeypatch.setattr(bundle, "H3_EXPERIMENTS_FILE_COUNT", 1)
    monkeypatch.setattr(
        bundle, "H3_EXPERIMENTS_TOTAL_BYTES", clean_receipts[0]["bytes"]
    )
    monkeypatch.setattr(
        bundle,
        "H3_EXPERIMENTS_INVENTORY_SHA256",
        hashlib.sha256(_canonical(clean_receipts)).hexdigest(),
    )
    assert REAL_H3_SOURCE_SNAPSHOT_RECEIPT(source)["rules_as_programs_present"] is False

    source.chmod(0o700)
    injected = source / "rules_as_programs/injected.py"
    injected.parent.mkdir(mode=0o700)
    injected.write_bytes(b"raise RuntimeError('working-tree injection')\n")
    injected.chmod(0o400)
    injected.parent.chmod(0o500)
    source.chmod(0o500)
    with pytest.raises(bundle.EnvironmentGateError, match="only the experiments"):
        REAL_H3_SOURCE_SNAPSHOT_RECEIPT(source)


def test_analyzer_environment_excludes_checkout_and_binds_snapshot():
    environment = _slurm_env()
    source_root = Path(environment["RAP_ANALYSIS_H3_SOURCE_ROOT"])
    gate = {
        "guard": {"path": str(source_root.parent / "network-guard/sitecustomize.py")},
        "h3_source_snapshot": {"root": str(source_root)},
    }
    isolated, cwd = bundle._analyzer_environment(environment, gate)
    assert cwd == source_root
    assert isolated["PYTHONPATH"].split(os.pathsep) == [
        str(source_root.parent / "network-guard"),
        str(source_root),
    ]
    assert str(bundle.REPO_ROOT) not in isolated["PYTHONPATH"].split(os.pathsep)
    assert isolated["PYTHONDONTWRITEBYTECODE"] == "1"


def test_rules_origin_probe_rejects_working_tree_module(tmp_path, monkeypatch):
    source_root = tmp_path / "h3-source"
    source_root.mkdir(mode=0o700)
    venv = tmp_path / "venv"
    site_packages = (
        venv
        / "lib"
        / f"python{os.sys.version_info.major}.{os.sys.version_info.minor}"
        / "site-packages"
    )
    site_packages.mkdir(parents=True)
    injected = tmp_path / "checkout/rules_as_programs/__init__.py"
    injected.parent.mkdir(parents=True)
    injected.write_text("# injected\n")
    response = {
        name: {"file": str(injected), "spec_origin": str(injected)}
        for name in bundle.RULES_ORIGIN_MODULES
    }

    def fake_probe(argv, environ, cwd):
        return subprocess.CompletedProcess(
            argv, 0, _canonical(response) + b"\n", b""
        )

    monkeypatch.setattr(bundle, "_invoke_origin_probe", fake_probe)
    with pytest.raises(bundle.EnvironmentGateError, match="outside the locked venv"):
        REAL_RULES_ORIGIN_PROBE({}, source_root, venv)


def test_sbatch_binds_same_h3_snapshot_and_all_partition():
    script = (
        bundle.REPO_ROOT
        / "experiments/eacl2027/run_scaling_faults_analysis_watgpu.sbatch"
    ).read_text()
    assert "#SBATCH --partition=ALL" in script
    assert f'readonly H3_COMMIT="{bundle.H3_COMMIT}"' in script
    assert bundle.H3_ROOT_TREE_GIT_SHA1 in script
    assert bundle.H3_EXPERIMENTS_TREE_GIT_SHA1 in script
    assert bundle.H3_EXPERIMENTS_INVENTORY_SHA256 in script
    assert 'archive --format=tar "${H3_COMMIT}" experiments' in script
    assert 'export RAP_ANALYSIS_H3_SOURCE_ROOT="${H3_SOURCE_ROOT}"' in script
