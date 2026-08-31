import errno
import json
import os
from hashlib import sha256
from pathlib import Path

import pytest

from experiments.eacl2027 import analyze_scaling_faults as analyzer
from experiments.eacl2027.scaling_faults_attempts import AttemptRecorder


_LINUX_UNSUPPORTED_ERRNOS = {
    "EINVAL": 22,
    "ENOSYS": 38,
    "ENOTSUP": 95,
    "EOPNOTSUPP": 95,
}


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _protocol_documents():
    return [
        {
            "path": relative,
            "sha256": sha256((analyzer.REPO_ROOT / relative).read_bytes()).hexdigest(),
        }
        for relative in analyzer.PROTOCOL_PATHS
    ]


def _force_fallback_publication(root: Path, *, error_name="EINVAL") -> Path:
    publication_path = root / "publication.json"
    claim_path = analyzer._expected_publication_claim_path(root)
    claim_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if claim_path.exists() or claim_path.is_symlink():
        claim_path.unlink()
    os.link(root / "launch.json", claim_path)
    launch_bytes = (root / "launch.json").read_bytes()
    receipt = {
        "schema_version": 1,
        "destination": str(root),
        "method": "hardlink_claim_then_posix_rename",
        "native_primitive": analyzer._FORMAL_NATIVE_PUBLICATION_PRIMITIVE,
        "native_unsupported": {
            "errno": _LINUX_UNSUPPORTED_ERRNOS[error_name],
            "name": error_name,
        },
        "claim": {
            "path": str(claim_path),
            "artifact": "launch.json",
            "bytes": len(launch_bytes),
            "sha256": sha256(launch_bytes).hexdigest(),
        },
    }
    publication_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    )
    return claim_path


def _cache_outcome(launch_cache, *, status="completed"):
    raw_end = json.loads(json.dumps(launch_cache["raw_tree"]))
    end = {"raw_tree": raw_end, "complete_tree": {"files": []}}
    return {
        "status": status,
        "unchanged": status == "completed",
        "launch_receipt_sha256": sha256(_canonical(launch_cache)).hexdigest(),
        "end_receipt_sha256": sha256(_canonical(end)).hexdigest(),
        "changed_or_new": [],
        "deleted": [],
        "non_regular_or_symlink": [],
        "entry_changes": [],
        "deleted_entries": [],
        "special_entries": [],
        "prelaunch_raw_tree_missing": False,
        "prelaunch_raw_tree_errors": [],
        "comparison_errors": [],
        "raw_end_tree": raw_end,
        "strict_validation_error": None if status == "completed" else {"type": "x"},
        "retained_changed_files_root": None,
        "retained_changed_files_root_relative": None,
        "retained_changed_files": [],
        "retained_copy_errors": [],
        "end_receipt": end,
    }


def _jsonl_receipt(path, values):
    path.write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in values))
    return {
        "path": str(path),
        "records": len(values),
        "bytes": path.stat().st_size,
        "sha256": sha256(path.read_bytes()).hexdigest(),
    }


def _standardized(cleanup):
    return {
        "schema_version": 1,
        "injected_boundary": "synthetic",
        "fail_open_hook_contract_and_latency": None,
        "current_event_survival": None,
        "loss_and_duplication": None,
        "healthy_recovery": None,
        "previous_deployment_continuity": None,
        "orphan_process_count": 0,
        "orphan_process_count_status": (
            "measured after bounded post-shutdown fixture cleanup and forced recheck"
        ),
        "post_shutdown_process_cleanup": cleanup,
        "persistent_state_integrity": {"ok": True},
        "operator_visible_incident_records": [],
    }


def _fault_value(*, status="completed", passed=True, orphan_count=0):
    retained_root = "/synthetic/runtime/faults/synthetic-rep0"
    process = {"pid": 42, "create_time": 1.5, "cmdline": ["daemon"]}
    initial_processes = [process] if orphan_count else []
    initial = {
        "status": "timed_out" if orphan_count else "complete",
        "started_monotonic_ns": 0,
        "deadline_monotonic_ns": 10,
        "finished_monotonic_ns": 10 if orphan_count else 3,
        "poll_interval_seconds": analyzer.systems.QUERY_POLL_INTERVAL_SECONDS,
        "completed_within_deadline": not bool(orphan_count),
        "observations": [
            {
                "query_started_monotonic_ns": 1,
                "query_finished_monotonic_ns": 10 if orphan_count else 3,
                "within_deadline": True,
                "processes": initial_processes,
                "scan_errors": [],
                "race_diagnostics": [],
            }
        ],
        "final_orphan_processes": initial_processes,
        "final_scan_errors": [],
    }
    if orphan_count:
        forced = {
            "status": "completed",
            "started_monotonic_ns": 11,
            "finished_monotonic_ns": 12,
            "expected_rap_state_dir": f"{retained_root}/state",
            "actions": [
                {
                    "pid": 42,
                    "captured_create_time": 1.5,
                    "captured_cmdline": ["daemon"],
                    "expected_rap_state_dir": f"{retained_root}/state",
                    "ownership_confirmed": True,
                    "action": "sigkill_sent",
                    "observed_create_time": 1.5,
                    "observed_rap_state_dir": f"{retained_root}/state",
                    "observed_cmdline": ["daemon"],
                }
            ],
        }
        final = {
            "status": "complete",
            "started_monotonic_ns": 13,
            "deadline_monotonic_ns": 23,
            "finished_monotonic_ns": 15,
            "poll_interval_seconds": analyzer.systems.QUERY_POLL_INTERVAL_SECONDS,
            "completed_within_deadline": True,
            "observations": [
                {
                    "query_started_monotonic_ns": 14,
                    "query_finished_monotonic_ns": 15,
                    "within_deadline": True,
                    "processes": [],
                    "scan_errors": [],
                    "race_diagnostics": [],
                }
            ],
            "final_orphan_processes": [],
            "final_scan_errors": [],
        }
    else:
        forced = None
        final = initial
    cleanup = {
        "initial_settle": initial,
        "forced_actions": forced,
        "final_settle": final,
        "measurable": True,
        "safe_to_continue": True,
        "final_orphan_processes": [],
        "final_scan_errors": [],
    }
    return {
        "fault": "synthetic",
        "repetition": 0,
        "status": status,
        "passed": passed,
        "duration_ns": 1,
        "standardized_outcomes": _standardized(cleanup),
        "probe_specific": {
            "runtime_evidence": {"retained_runtime_root": retained_root},
            "post_shutdown_process_cleanup": cleanup,
            "post_shutdown_process_settle": initial,
            "forced_process_cleanup": forced,
            "post_force_process_settle": final,
            "orphan_processes_after_cleanup": [],
            "orphan_process_count": 0,
            "orphan_process_count_status": (
                "measured after bounded post-shutdown fixture cleanup and forced recheck"
            ),
            "persistent_state_integrity": {"ok": True},
        },
        "error": None,
    }


def _hook_sample():
    hook = {
        "started_monotonic_ns": 10,
        "exited_monotonic_ns": 20,
        "latency_ns": 10,
        "latency_ms": 0.0,
        "returncode": 0,
        "stdout": "{}",
        "stderr": "",
        "timed_out": False,
        "contract_preserved": True,
        "contract_error": "",
    }
    return {
        "submitted_monotonic_ns": 5,
        "hook_started_monotonic_ns": 10,
        "hook_exited_monotonic_ns": 20,
        "hook_exit_ns": 10,
        "hook_exit_ms": 0.0,
        "executor_queue_ns": 5,
        "executor_queue_ms": 0.0,
        "submission_to_hook_exit_ns": 15,
        "submission_to_hook_exit_ms": 0.0,
        "hook": hook,
    }


def _evaluation_accounting(expected=2):
    return {
        "evaluations_expected": expected,
        "evaluations_observed_for_expected_keys": expected + 1,
        "expected_keys_observed": expected,
        "loss_count": 0,
        "duplicate_count": 1,
        "unexpected_count": 1,
        "cross_project_contamination_count": 1,
        "failed_count": 1,
        "running_count": 0,
        "provenance_mismatch_count": 1,
        "result_counts": {"OK": expected, "failed": 1},
        "missing": [],
        "duplicates": [{"key": {}, "count": 2}],
        "unexpected": [{}],
        "cross_project_contamination": [{}],
        "failed": [{}],
        "running": [],
        "provenance_mismatches": [{}],
    }


def _make_attempt(
    parent: Path,
    attempt_id: str,
    *,
    component="faults",
    value=None,
    terminal=True,
    started=True,
    abort_status="harness_error",
    source_changed=False,
    created_utc="2026-08-30T00:00:00+00:00",
    attempt_replacement=None,
    replacement_retention=None,
    plan_fault="synthetic",
):
    if value is None and terminal:
        value = _fault_value()
    unit_id = "synthetic-rep0" if component == "faults" else f"{component}-unit"
    if component == "faults" and value is not None:
        retained_root = parent / attempt_id / "runtime" / "faults" / unit_id
        value = json.loads(
            json.dumps(value).replace(
                "/synthetic/runtime/faults/synthetic-rep0", str(retained_root)
            )
        )
    plan_item = {"component": component, "unit_id": unit_id}
    if component == "faults":
        plan_item.update({"fault": plan_fault, "repetition": 0})
    plan = [plan_item]
    raw_tree = {
        "declared_root": "/cache/programasweights",
        "root_type": "directory",
        "root_entry": {"path": ".", "type": "directory", "mode": 448},
        "entries": [],
        "errors": [],
    }
    raw_tree["inventory_sha256"] = sha256(
        _canonical(
            {"root_entry": raw_tree["root_entry"], "entries": raw_tree["entries"]}
        )
    ).hexdigest()
    launch_cache = {"raw_tree": raw_tree, "complete_tree": {"files": []}}
    git_start = {"commit": "a" * 40, "dirty": False, "scope": ["test"]}
    identity = {
        "attempt_id": attempt_id,
        "study_mode": "formal",
        "git": git_start,
        "runner": {
            "path": str(Path(analyzer.systems.__file__).resolve().relative_to(analyzer.REPO_ROOT)),
            "sha256": sha256(Path(analyzer.systems.__file__).read_bytes()).hexdigest(),
            "git_blob": analyzer.systems._git_blob_sha1(
                Path(analyzer.systems.__file__)
            ),
        },
        "protocol_documents": _protocol_documents(),
        "plan_sha256": sha256(_canonical(plan)).hexdigest(),
        "formal_runtime": {"paw_cache": launch_cache},
    }
    if attempt_replacement is not None:
        identity["attempt_replacement"] = attempt_replacement
    if replacement_retention is not None:
        identity["replacement_retention"] = replacement_retention
    manifest = {
        "schema_version": 1,
        "created_utc": created_utc,
        "identity": identity,
        "identity_sha256": sha256(_canonical(identity)).hexdigest(),
        "plan": plan,
    }
    recorder = AttemptRecorder(parent / attempt_id, manifest)
    # The synthetic attempt models the pinned Linux formal runtime even when
    # the reducer tests themselves run on macOS.
    publication_path = recorder.root / "publication.json"
    publication = json.loads(publication_path.read_text(encoding="utf-8"))
    publication["native_primitive"] = (
        analyzer._FORMAL_NATIVE_PUBLICATION_PRIMITIVE
    )
    publication_path.write_text(
        json.dumps(publication, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if component == "faults" and value is not None:
        (recorder.root / "runtime" / "faults" / unit_id).mkdir(parents=True)
    if started:
        recorder.record(component, unit_id, "started", {"status": "started"})
    unit_status = abort_status
    if terminal:
        assert started
        unit_status = value["status"]
        recorder.record(component, unit_id, "terminal", value)
    source_end = dict(git_start)
    if source_changed:
        source_end["commit"] = "b" * 40
    complete = terminal
    eligible = bool(
        complete
        and unit_status in analyzer.PRIMARY_ELIGIBLE_STATUSES
        and not source_changed
    )
    if not complete:
        status = {
            "harness_error": "incomplete_harness_error",
            "infrastructure_error": "incomplete_infrastructure_error",
        }.get(abort_status, "incomplete_unclassified_failure")
    elif source_changed:
        status = "incomplete_unclassified_failure"
    elif unit_status == "system_violation":
        status = "completed_with_system_violations"
    elif unit_status == "harness_error":
        status = "incomplete_harness_error"
    elif unit_status == "infrastructure_error":
        status = "incomplete_infrastructure_error"
    elif unit_status == "unclassified_failure":
        status = "incomplete_unclassified_failure"
    else:
        status = "completed"
    result = {
        "schema_version": 2,
        "status": status,
        "primary_numeric_eligible": eligible,
        "protocol_status": "formal_protocol_v3_amendment_006",
        "study_mode": "formal",
        "git": {
            "start": git_start,
            "end": source_end,
            "unchanged_during_attempt": not source_changed,
        },
        "global_outcomes": {
            "statuses": [],
            "cache_end_receipt": _cache_outcome(launch_cache),
        },
    }
    if not complete:
        result["abort"] = {
            "status": abort_status,
            "classification_basis": "synthetic positive evidence",
            "error": {"type": "Synthetic", "message": "stopped"},
        }
    recorder.finalize(result)
    return recorder.root


def test_compact_journal_pointer_and_sha_are_authoritative(tmp_path):
    root = _make_attempt(tmp_path, "attempt-a")
    report = analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})
    assert report["eligible"] is True
    assert report["publication"]["method"] == "native_no_replace"
    assert "publication.json" in report["input_hashes"]
    assert analyzer._loose_hashes(root)["publication.json"] == sha256(
        (root / "publication.json").read_bytes()
    ).hexdigest()
    terminal = next((root / "faults").glob("*.terminal.json"))
    terminal.write_text(terminal.read_text() + " ")
    with pytest.raises(analyzer.AnalysisValidationError, match="receipt mismatch"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_publication_receipt_is_required(tmp_path):
    root = _make_attempt(tmp_path, "attempt-missing-publication")
    (root / "publication.json").unlink()

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="publication.json is missing",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_fallback_publication_requires_exact_live_launch_hardlink(tmp_path):
    root = _make_attempt(tmp_path, "attempt-fallback")
    claim_path = _force_fallback_publication(root)

    report = analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})

    assert report["publication"]["method"] == (
        "hardlink_claim_then_posix_rename"
    )
    assert claim_path.read_bytes() == (root / "launch.json").read_bytes()
    assert claim_path.stat().st_ino == (root / "launch.json").stat().st_ino


def test_fallback_publication_uses_linux_errno_mapping_on_any_reducer_host(
    tmp_path,
):
    root = _make_attempt(tmp_path, "attempt-linux-enosys")
    _force_fallback_publication(root, error_name="ENOSYS")

    report = analyzer.validate_attempt(
        root, _expected_component_counts={"faults": 1}
    )

    assert report["publication"]["native_unsupported"] == {
        "errno": 38,
        "name": "ENOSYS",
    }


def test_formal_publication_rejects_non_linux_native_primitive(tmp_path):
    root = _make_attempt(tmp_path, "attempt-macos-primitive")
    publication_path = root / "publication.json"
    publication = json.loads(publication_path.read_text())
    publication["native_primitive"] = "renamex_np_RENAME_EXCL"
    publication_path.write_text(json.dumps(publication) + "\n")

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="pinned Linux renameat2 primitive",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_fallback_publication_rejects_noncanonical_claim_path(tmp_path):
    root = _make_attempt(tmp_path, "attempt-wrong-claim-path")
    _force_fallback_publication(root)
    publication_path = root / "publication.json"
    publication = json.loads(publication_path.read_text())
    publication["claim"]["path"] = str(
        analyzer._expected_publication_claim_path(root).with_name("other.json")
    )
    publication_path.write_text(json.dumps(publication) + "\n")

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="differs from the derived path",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_fallback_publication_rejects_symlink_claim(tmp_path):
    root = _make_attempt(tmp_path, "attempt-symlink-claim")
    claim_path = _force_fallback_publication(root)
    claim_path.unlink()
    claim_path.symlink_to(root / "launch.json")

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="claim path contains a symlink",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_fallback_publication_rejects_equal_bytes_without_same_inode(tmp_path):
    root = _make_attempt(tmp_path, "attempt-copied-claim")
    claim_path = _force_fallback_publication(root)
    launch_bytes = (root / "launch.json").read_bytes()
    claim_path.unlink()
    claim_path.write_bytes(launch_bytes)
    assert claim_path.stat().st_ino != (root / "launch.json").stat().st_ino

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="not a hard link",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_publication_method_and_fallback_fields_cannot_be_mixed(tmp_path):
    root = _make_attempt(tmp_path, "attempt-mixed-publication")
    publication_path = root / "publication.json"
    publication = json.loads(publication_path.read_text())
    publication["native_unsupported"] = {
        "errno": errno.EINVAL,
        "name": "EINVAL",
    }
    publication_path.write_text(json.dumps(publication) + "\n")

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="native publication must not declare fallback evidence",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_native_publication_rejects_unexpected_fallback_claim(tmp_path):
    root = _make_attempt(tmp_path, "attempt-native-with-claim")
    claim_path = analyzer._expected_publication_claim_path(root)
    claim_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.link(root / "launch.json", claim_path)

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="unexpected fallback claim",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_fallback_publication_requires_owner_exclusive_claim_namespace(tmp_path):
    root = _make_attempt(tmp_path, "attempt-publication-mode")
    claim_path = _force_fallback_publication(root)
    claim_path.parent.chmod(0o755)

    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="owner-exclusive mode 0700",
    ):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_absolute_terminal_path_fails_without_parent_walk(tmp_path):
    with pytest.raises(analyzer.AnalysisValidationError, match="must be relative"):
        analyzer._checked_file(tmp_path, "/tmp/not-an-attempt-record")


def test_incremental_receipt_rejects_lexical_symlink(tmp_path):
    target = tmp_path / "target.jsonl"
    target.write_text("{}\n")
    link = tmp_path / "linked.jsonl"
    link.symlink_to(target)
    receipt = {
        "path": str(link),
        "records": 1,
        "bytes": target.stat().st_size,
        "sha256": sha256(target.read_bytes()).hexdigest(),
    }
    with pytest.raises(analyzer.AnalysisValidationError, match="symlink"):
        analyzer._validate_jsonl_receipt(tmp_path, receipt, "test receipt")


def test_incremental_receipt_is_relocatable_by_attempt_relative_path(tmp_path):
    original = tmp_path / "original" / "runtime" / "evidence.jsonl"
    original.parent.mkdir(parents=True)
    original.write_text('{"value":1}\n')
    relocated = tmp_path / "relocated"
    (relocated / "runtime").mkdir(parents=True)
    (relocated / "runtime" / "evidence.jsonl").write_bytes(original.read_bytes())
    receipt = {
        "path": "/u4/original/formal-v3-r01/runtime/evidence.jsonl",
        "attempt_relative_path": "runtime/evidence.jsonl",
        "records": 1,
        "bytes": original.stat().st_size,
        "sha256": sha256(original.read_bytes()).hexdigest(),
    }
    summary = analyzer._validate_jsonl_receipt(relocated, receipt, "relocated")
    assert summary["path"] == "runtime/evidence.jsonl"
    assert summary["original_path"] == receipt["path"]


def test_started_aborted_unit_is_valid_but_not_numeric(tmp_path):
    root = _make_attempt(
        tmp_path, "attempt-aborted", terminal=False, abort_status="harness_error"
    )
    report = analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})
    assert report["plan_accounting"]["started_without_terminal"] == 1
    assert report["eligible"] is False


def test_amendment_007_socket_endpoint_receipt_is_recomputed(tmp_path):
    root = tmp_path / "formal-v3-r02"
    retained = root / "runtime" / "faults" / "synthetic-rep0"
    retained.mkdir(parents=True)
    identity = {
        "attempt_id": root.name,
        "slurm": {"job_id": "1524435", "partition": "ALL", "node_list": "watgpu108"},
        "formal_runtime": {
            "setup_preflight_receipt": {
                "content": {"socket_preflight": {"socket_root": {
                    "path": "/tmp/rf3-1524435",
                    "owner_uid": 1000,
                    "mode": 0o700,
                    "device": 123,
                }}}
            }
        },
    }
    unit = {
        "component": "faults",
        "unit_id": "synthetic-rep0",
        "started": True,
    }
    socket_root = {
        "path": "/tmp/rf3-1524435",
        "owner_uid": 1000,
        "mode": 0o700,
        "device": 123,
    }
    receipt = analyzer._socket_endpoint_receipt_expected(
        root=root,
        component="faults",
        unit_id="synthetic-rep0",
        raw_attempt_id=root.name,
        slurm=identity["slurm"],
        socket_root=socket_root,
        retained_runtime_root=retained,
    )
    (retained / "socket-endpoint.json").write_text(json.dumps(receipt))

    analyzer._validate_socket_endpoint_receipts(root, identity, [unit])

    receipt["endpoint"] = "/tmp/forged.sock"
    (retained / "socket-endpoint.json").write_text(json.dumps(receipt))
    with pytest.raises(analyzer.AnalysisValidationError, match="recomputed runner schema"):
        analyzer._validate_socket_endpoint_receipts(root, identity, [unit])

    receipt["endpoint"] = analyzer._socket_endpoint_receipt_expected(
        root=root,
        component="faults",
        unit_id="synthetic-rep0",
        raw_attempt_id=root.name,
        slurm=identity["slurm"],
        socket_root=socket_root,
        retained_runtime_root=retained,
    )["endpoint"]
    receipt["socket_root"]["device"] = 999
    (retained / "socket-endpoint.json").write_text(json.dumps(receipt))
    with pytest.raises(analyzer.AnalysisValidationError, match="recomputed runner schema"):
        analyzer._validate_socket_endpoint_receipts(root, identity, [unit])


def test_amendment_007_socket_cleanup_failure_receipt_rejects_attempt(tmp_path):
    root = tmp_path / "formal-v3-r02"
    failure = root / "runtime" / "faults" / "synthetic-rep0" / "socket-cleanup-failure-daemon.json"
    failure.parent.mkdir(parents=True)
    failure.write_text("{}")

    with pytest.raises(analyzer.AnalysisValidationError, match="socket cleanup failure receipt"):
        analyzer._validate_socket_endpoint_receipts(
            root,
            {"attempt_id": root.name, "slurm": {"job_id": "1524435"}},
            [],
        )


def test_amendment_007_setup_socket_preflight_is_recomputed(tmp_path):
    root = tmp_path / "formal-v3-r02"
    identity = {"attempt_id": root.name, "slurm": {"job_id": "1524435"}}
    retained = root / "runtime" / "preflight"
    digest_input = {
        "schema_version": 1,
        "raw_attempt_id": root.name,
        "component": "preflight",
        "unit_id": "socket-canary",
        "retained_runtime_root": str(retained),
    }
    digest = sha256(_canonical(digest_input)).hexdigest()
    endpoint = f"/tmp/rf3-1524435/{digest}.sock"
    root_receipt = {
        "path": "/tmp/rf3-1524435",
        "owner_uid": 1000,
        "mode": 0o700,
        "device": 123,
    }
    setup = {
        "socket_root": root_receipt["path"],
        "socket_preflight": {
            "schema_version": 1,
            "digest_input": digest_input,
            "endpoint_digest": digest,
            "endpoint": endpoint,
            "encoded_pathname_bytes": len(os.fsencode(endpoint)),
            "maximum_encoded_pathname_bytes": 107,
            "socket_root": root_receipt,
            "bind_connect_accept_payload_equal": True,
            "endpoint_removed_after_probe": True,
        },
    }

    analyzer._validate_setup_socket_preflight(root, identity, setup)

    setup["socket_preflight"]["endpoint_removed_after_probe"] = False
    with pytest.raises(analyzer.AnalysisValidationError, match="preflight receipt mismatch"):
        analyzer._validate_setup_socket_preflight(root, identity, setup)


def test_anchored_r01_uses_repair_raw_result_and_core_artifact_hashes(tmp_path):
    root = tmp_path / "formal-v3-20260831t051023z-r01"
    root.mkdir()
    launch_path = root / "launch.json"
    result_path = root / "result.json"
    launch_path.write_text("anchored launch\n")
    result_path.write_text("anchored result\n")
    core = {
        name: {"bytes": path.stat().st_size, "sha256": sha256(path.read_bytes()).hexdigest()}
        for name, path in (("launch.json", launch_path), ("result.json", result_path))
    }
    anchor = {
        "identity_sha256": "a" * 64,
        "git_commit": "b" * 40,
        "slurm": {"job_id": "1524424", "partition": "ALL", "node_list": "watgpu108"},
    }
    identity = {
        "git": {"commit": anchor["git_commit"]},
        "slurm": anchor["slurm"],
    }
    result = {"status": "completed_with_system_violations", "primary_numeric_eligible": True}
    launch = {"identity_sha256": anchor["identity_sha256"]}
    contract = {
        "outcome_aware_repair": {
            "raw_result": {
                "status": result["status"],
                "raw_primary_numeric_eligible": True,
            },
            "core_artifacts": core,
        }
    }

    analyzer._validate_anchored_r01(identity, result, launch, anchor, contract, root)

    result_path.write_text("mutated\n")
    with pytest.raises(analyzer.AnalysisValidationError, match="core artifact differs"):
        analyzer._validate_anchored_r01(identity, result, launch, anchor, contract, root)


def test_anchored_r01_alone_cannot_be_promoted(monkeypatch, tmp_path):
    raw_attempt_id = "formal-v3-20260831t051023z-r01"
    attempt = tmp_path / raw_attempt_id
    attempt.mkdir()
    (attempt / "launch.json").write_text(
        json.dumps({"created_utc": "2026-08-31T05:10:23+00:00"})
    )

    def anchored_report(*_args, **_kwargs):
        return {
            "numeric_candidate": {"candidate_eligible": False},
            "raw_attempt": {
                "status": "completed_with_system_violations",
                "input_sha256": {},
            },
            "analysis_binding_sha256": "a" * 64,
            "endpoints": None,
        }

    monkeypatch.setattr(analyzer, "analyze", anchored_report)
    report = analyzer.analyze_attempts_root(
        tmp_path, "r01-alone", _expected_component_counts={"faults": 1}
    )

    assert report["primary_numeric"]["promoted"] is False
    assert report["primary_numeric"]["selection_blocked_by"] == raw_attempt_id


def test_terminal_unit_must_be_marked_started(tmp_path):
    root = _make_attempt(tmp_path, "attempt-terminal-not-started")
    path = root / "result.json"
    result = json.loads(path.read_text())
    result["unit_index"][0]["started"] = False
    result["plan_completion"]["started"] = 0
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with pytest.raises(analyzer.AnalysisValidationError, match="not marked started"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_preunit_infrastructure_abort_uses_abort_class_not_placeholder(tmp_path):
    root = _make_attempt(
        tmp_path,
        "attempt-infra-before-unit",
        terminal=False,
        started=False,
        abort_status="infrastructure_error",
    )
    report = analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})
    assert report["result"]["status"] == "incomplete_infrastructure_error"
    assert report["plan_accounting"]["not_started_after_abort"] == 1


def test_source_mutation_is_global_ineligibility(tmp_path):
    root = _make_attempt(tmp_path, "attempt-mutated", source_changed=True)
    report = analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})
    assert report["source_unchanged"] is False
    assert report["eligible"] is False


def test_caught_soak_system_violation_does_not_require_success_artifacts(tmp_path):
    value = {
        "status": "system_violation",
        "classification_basis": "explicit measured drain failure",
        "error": {"type": "SystemViolationError", "message": "drain failed"},
    }
    root = _make_attempt(
        tmp_path, "attempt-soak-error", component="soak", value=value
    )
    report = analyzer.validate_attempt(root, _expected_component_counts={"soak": 1})
    assert report["eligible"] is True


def test_fault_passed_boolean_is_recomputed(tmp_path):
    root = _make_attempt(
        tmp_path,
        "attempt-false-pass",
        value=_fault_value(passed=True, orphan_count=1),
    )
    with pytest.raises(analyzer.AnalysisValidationError, match="passed gate mismatch"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_forced_fault_cleanup_is_semantically_validated(tmp_path):
    value = _fault_value(
        status="system_violation", passed=False, orphan_count=1
    )
    root = _make_attempt(tmp_path, "attempt-forced-cleanup", value=value)
    report = analyzer.validate_attempt(
        root, _expected_component_counts={"faults": 1}
    )
    assert report["result"]["status"] == "completed_with_system_violations"

    tampered = _fault_value(
        status="system_violation", passed=False, orphan_count=1
    )
    tampered["probe_specific"]["post_shutdown_process_cleanup"][
        "forced_actions"
    ]["actions"][0]["expected_rap_state_dir"] = "/forged/state"
    root = _make_attempt(tmp_path, "attempt-forged-owner", value=tampered)
    with pytest.raises(analyzer.AnalysisValidationError, match="captured process"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_fault_cleanup_deadline_flags_are_recomputed(tmp_path):
    value = _fault_value()
    value["probe_specific"]["post_shutdown_process_cleanup"]["initial_settle"][
        "observations"
    ][0]["within_deadline"] = False
    root = _make_attempt(tmp_path, "attempt-bad-cleanup-clock", value=value)
    with pytest.raises(analyzer.AnalysisValidationError, match="timing is invalid"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_caught_fault_exception_cleanup_matches_standardized_projection(tmp_path):
    value = _fault_value(status="harness_error", passed=False)
    value["fault"] = "daemon_crash"
    value["classification_basis"] = "explicit runner invariant failure"
    value["error"] = {
        "type": "SystemsHarnessError",
        "message": "synthetic",
        "traceback": "synthetic traceback",
        "retained_runtime_root": "/synthetic/runtime/faults/synthetic-rep0",
    }
    probe = value["probe_specific"]
    standardized = analyzer.systems._unknown_standardized_fault_outcomes(
        "daemon_crash"
    )
    standardized["orphan_process_count"] = probe["orphan_process_count"]
    standardized["orphan_process_count_status"] = probe[
        "orphan_process_count_status"
    ]
    standardized["post_shutdown_process_cleanup"] = probe[
        "post_shutdown_process_cleanup"
    ]
    value["standardized_outcomes"] = standardized
    root = _make_attempt(
        tmp_path,
        "attempt-caught-fault",
        value=value,
        plan_fault="daemon_crash",
    )
    report = analyzer.validate_attempt(
        root, _expected_component_counts={"faults": 1}
    )
    assert report["result"]["status"] == "incomplete_harness_error"


def test_fault_terminal_fields_are_bound_to_plan(tmp_path):
    value = _fault_value()
    value["fault"] = "different"
    root = _make_attempt(tmp_path, "attempt-fault-plan-mismatch", value=value)
    with pytest.raises(analyzer.AnalysisValidationError, match="terminal/plan binding"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_error_payload_cannot_have_completed_status(tmp_path):
    value = _fault_value(status="completed", passed=False)
    value["classification_basis"] = "synthetic classified error"
    value["error"] = {"type": "Synthetic", "message": "failed"}
    root = _make_attempt(tmp_path, "attempt-error-success", value=value)
    with pytest.raises(analyzer.AnalysisValidationError, match="success status"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


@pytest.mark.parametrize(
    ("field", "tampered"),
    [
        ("returncode", 1),
        ("stdout", "{}\n"),
        ("stderr", "diagnostic"),
        ("timed_out", True),
        ("contract_preserved", False),
        ("latency_ns", 11),
        ("latency_ms", 0.001),
    ],
)
def test_recursive_hook_projection_uses_authoritative_process_fields(
    field, tampered
):
    sample = _hook_sample()
    analyzer._validate_embedded_hook_projections(
        {"nested": [{"sample": sample}]}, "synthetic terminal"
    )

    sample["hook"][field] = tampered
    with pytest.raises(analyzer.AnalysisValidationError, match="hook|contract"):
        analyzer._validate_embedded_hook_projections(
            {"nested": [{"sample": sample}]}, "synthetic terminal"
        )


def test_validate_attempt_finds_deeply_nested_hook_tampering(tmp_path):
    value = _fault_value()
    value["probe_specific"]["nested"] = {"recovery": [_hook_sample()]}
    root = _make_attempt(tmp_path, "attempt-hook-valid", value=value)
    analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})

    tampered = _fault_value()
    tampered["probe_specific"]["nested"] = {"recovery": [_hook_sample()]}
    tampered["probe_specific"]["nested"]["recovery"][0]["hook"]["stdout"] = ""
    root = _make_attempt(tmp_path, "attempt-hook-tampered", value=tampered)
    with pytest.raises(analyzer.AnalysisValidationError, match="hook contract"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_accounting_counts_are_reconstructed_from_detail_lists():
    accounting = _evaluation_accounting()
    analyzer._validate_accounting_projection(accounting, "synthetic accounting")

    accounting["duplicate_count"] = 0
    with pytest.raises(analyzer.AnalysisValidationError, match="duplicate_count"):
        analyzer._validate_accounting_projection(accounting, "synthetic accounting")


def test_soak_batch_diagnostic_accounting_is_recomputed():
    accounting = _evaluation_accounting()
    fields = (
        "evaluations_expected",
        "evaluations_observed_for_expected_keys",
        "loss_count",
        "duplicate_count",
        "unexpected_count",
        "cross_project_contamination_count",
        "failed_count",
        "running_count",
        "provenance_mismatch_count",
    )
    value = {
        "events": 2,
        "events_submitted": 2,
        "events_not_submitted_after_drain_timeout": 0,
        "rule_count": 1,
        "batches": [{"events": 2, "accounting": accounting}],
        "batch_accounting_diagnostic_sums_not_global": {
            name: accounting[name] for name in fields
        },
        "global_accounting": accounting,
        "post_drain": {
            "final_drain_wait": {
                "full_journal_accounting": {"accounting": accounting}
            }
        },
    }
    unit = {"component": "soak", "unit_id": "soak", "value": value}
    analyzer._validate_component_internal_consistency(unit)

    value["batch_accounting_diagnostic_sums_not_global"]["loss_count"] = 1
    with pytest.raises(analyzer.AnalysisValidationError, match="diagnostic sums"):
        analyzer._validate_component_internal_consistency(unit)


def test_missing_predictions_cannot_be_promoted_as_equal():
    record = {
        "status": "missing",
        "terminal_rows": 0,
        "error_code": None,
        "persisted_prediction_utf8_present": False,
        "persisted_prediction_utf8_hex": None,
        "persisted_prediction_utf8_sha256": None,
    }
    predictions = {analyzer.systems.EXTERNAL_RULE_ORDER[0]: record}
    comparison = analyzer.systems.compare_persisted_predictions(
        predictions, predictions
    )
    comparison.update(
        {
            "prediction_records_exactly_equal": False,
            "input_identity_equal": True,
            "exactly_equal": False,
        }
    )
    raw = b"same input"
    blocker_source = analyzer.systems._network_blocker_source().encode()
    online_identity = {
        "ok": True,
        "pid": 101,
        "paw": True,
        "protocol": 1,
        "version": "test",
        "started_at": 1.0,
    }
    offline_identity = {
        "ok": True,
        "pid": 102,
        "paw": True,
        "protocol": 1,
        "version": "test",
        "started_at": 2.0,
    }
    value = {
        "prepared_online": True,
        "fresh_offline_daemon": True,
        "online_daemon_identity": online_identity,
        "offline_daemon_identity": offline_identity,
        "network_boundary": analyzer.systems._python_socket_boundary(),
        "boundary_source_receipt": {
            "path": "/synthetic/offline-python/sitecustomize.py",
            "bytes": len(blocker_source),
            "sha256": sha256(blocker_source).hexdigest(),
        },
        "boundary_activation_records": [
            {"kind": "sitecustomize_loaded", "pid": 102, "time": 2.1}
        ],
        "offline_daemon_boundary_activated": True,
        "blocked_internet_attempts": 0,
        "blocked_attempt_records": [],
        "exact_declared_input": {
            "encoding": "UTF-8 rendered as lowercase hexadecimal",
            "online_utf8_hex": raw.hex(),
            "offline_utf8_hex": raw.hex(),
            "online_sha256": sha256(raw).hexdigest(),
            "offline_sha256": sha256(raw).hexdigest(),
            "identical": True,
        },
        "online": {
            "status": "completed",
            "wait": {"timed_out": False},
            "sample": {"hook": {"contract_preserved": True}},
            "accounting": {},
            "persisted_predictions": predictions,
            "evidence": {"daemon_identity": online_identity},
            "envelope": {
                "session_id": "session",
                "turn_id": "turn",
                "tool_use_id": "tool-use",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "cwd": "/synthetic/project-0",
            },
        },
        "offline": {
            "status": "completed",
            "wait": {"timed_out": False},
            "sample": {"hook": {"contract_preserved": True}},
            "accounting": {},
            "persisted_predictions": predictions,
            "evidence": {"daemon_identity": offline_identity},
            "envelope": {
                "session_id": "session-offline",
                "turn_id": "turn-offline",
                "tool_use_id": "tool-use-offline",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "cwd": "/synthetic/project-1",
            },
        },
        "comparison": comparison,
    }
    unit = {"component": "offline", "plan": {"rules": 1}, "value": value}
    assert analyzer._normal_unit_expected_status(unit) == "system_violation"

    bad_count = json.loads(json.dumps(unit))
    bad_count["value"]["blocked_internet_attempts"] = 1
    with pytest.raises(analyzer.AnalysisValidationError, match="blocked-attempt count"):
        analyzer._normal_unit_expected_status(bad_count)

    bad_boundary = json.loads(json.dumps(unit))
    bad_boundary["value"]["network_boundary"]["id"] = "unbound"
    with pytest.raises(analyzer.AnalysisValidationError, match="network-boundary"):
        analyzer._normal_unit_expected_status(bad_boundary)

    reused_daemon = json.loads(json.dumps(unit))
    reused_daemon["value"]["offline_daemon_identity"] = online_identity
    reused_daemon["value"]["offline"]["evidence"]["daemon_identity"] = online_identity
    with pytest.raises(analyzer.AnalysisValidationError, match="fresh-daemon"):
        analyzer._normal_unit_expected_status(reused_daemon)

    startup_failure = json.loads(json.dumps(unit))
    startup_failure["value"]["fresh_offline_daemon"] = False
    startup_failure["value"]["offline_daemon_identity"] = None
    startup_failure["value"]["boundary_activation_records"] = []
    startup_failure["value"]["offline_daemon_boundary_activated"] = False
    startup_failure["value"]["offline"].update(
        {
            "status": "system_violation",
            "sample": None,
            "accounting": None,
            "wait": {"status": "not_applicable"},
            "evidence": {
                "blocked_attempt_records": [],
                "boundary_activation_records": [],
            },
        }
    )
    assert (
        analyzer._normal_unit_expected_status(startup_failure)
        == "system_violation"
    )

    bad_source = json.loads(json.dumps(unit))
    bad_source["value"]["boundary_source_receipt"]["sha256"] = "0" * 64
    with pytest.raises(analyzer.AnalysisValidationError, match="frozen blocker"):
        analyzer._normal_unit_expected_status(bad_source)


def test_matrix_endpoint_timestamp_is_bound_to_incremental_confirmation(tmp_path):
    input_hash = "a" * 64
    journal = _jsonl_receipt(
        tmp_path / "journal.jsonl", [{"observed_monotonic_ns": 15}]
    )
    checkpoint_values = [
            {
                "kind": "journal_transition_confirmation",
                "observed_monotonic_ns": 20,
                "within_deadline": True,
                "limit": 10,
                "rows": 1,
                "query_latency_ns": 1,
                "trigger_input_sha256": [input_hash],
                "first_visible_confirmed": [input_hash],
                "all_visible_confirmed": [input_hash],
            },
            {
                "kind": "condition_quiescence",
                "started_monotonic_ns": 20,
                "observed_monotonic_ns": 21,
                "within_deadline": True,
                "complete": True,
                "inflight_evaluations": 0,
                "outcomes_without_observed_start": 0,
            },
        ]
    checkpoints = _jsonl_receipt(tmp_path / "history.jsonl", checkpoint_values)
    deadline = 10 + 30_000_000_000
    value = {
        "mode": "sequential",
        "event_count": 1,
        "evaluation_history_query": analyzer.systems._summary_ns([1]),
        "wait": {
            "timed_out": False,
            "integrity_violation": False,
            "history_limit_saturated": False,
            "missing_input_sha256": [],
            "per_event_wait": [
                {
                    "input_sha256": input_hash,
                    "timed_out": False,
                    "integrity_violation": False,
                    "history_limit_saturated": False,
                    "missing_input_sha256": [],
                    "deadline_monotonic_ns": deadline,
                    "settle": {
                        "started_monotonic_ns": 20,
                        "finished_monotonic_ns": 21,
                        "complete": True,
                    },
                }
            ],
        },
        "incremental_evidence": {
            "journal_progress": journal,
            "history_checkpoints": checkpoints,
        },
        "samples": [
            {
                "input_sha256": input_hash,
                "submitted_monotonic_ns": 10,
                "censor_deadline_monotonic_ns": deadline,
                "first_visible_monotonic_ns": 20,
                "all_visible_monotonic_ns": 20,
                "event_to_first_query_visible_evaluation_ns": 10,
                "event_to_all_query_visible_evaluations_ns": 10,
                "latency_censored_at_ns": None,
            }
        ],
    }
    for field in (
        "event_to_first_query_visible_evaluation",
        "event_to_all_query_visible_evaluations",
    ):
        value[field] = analyzer.systems._latency_summary(
            value["samples"], f"{field}_ms"
        )
    unit = {"component": "matrix", "unit_id": "matrix", "value": value}
    analyzer._validate_matrix_evidence(tmp_path, [unit])
    value["event_to_all_query_visible_evaluations"]["p95_nearest_rank_ns"] = 9
    with pytest.raises(analyzer.AnalysisValidationError, match="summary"):
        analyzer._validate_matrix_evidence(tmp_path, [unit])
    value["event_to_all_query_visible_evaluations"] = (
        analyzer.systems._latency_summary(
            value["samples"], "event_to_all_query_visible_evaluations_ms"
        )
    )
    value["samples"][0]["all_visible_monotonic_ns"] = 19
    with pytest.raises(analyzer.AnalysisValidationError, match="endpoint/deadline"):
        analyzer._validate_matrix_evidence(tmp_path, [unit])
    value["samples"][0]["all_visible_monotonic_ns"] = 20
    checkpoint_values[1]["complete"] = False
    value["incremental_evidence"]["history_checkpoints"] = _jsonl_receipt(
        tmp_path / "history.jsonl", checkpoint_values
    )
    with pytest.raises(analyzer.AnalysisValidationError, match="quiescence completion"):
        analyzer._validate_matrix_evidence(tmp_path, [unit])


def test_soak_checkpoint_chain_blocks_advance_and_recomputes_restart(tmp_path):
    batch_id = "soak-r1-p1-offset0"
    expected_keys = [
        {
            "project_root": "/synthetic/project",
            "input_sha256": input_sha256,
            "rule_id": analyzer.systems.EXTERNAL_RULE_ORDER[0],
        }
        for input_sha256 in ("a" * 64, "b" * 64)
    ]
    expected_key_set_sha256 = sha256(_canonical(expected_keys)).hexdigest()
    batch_query = {
        "project_root": "/synthetic/project",
        "started_monotonic_ns": 10,
        "finished_monotonic_ns": 11,
        "latency_ns": 1,
        "latency_ms": 0.0,
        "rows": 2,
    }
    restart_query = {
        "project_root": "/synthetic/project",
        "started_monotonic_ns": 30,
        "finished_monotonic_ns": 31,
        "latency_ns": 1,
        "latency_ms": 0.0,
        "rows": 2,
    }
    checkpoint = {
        "batch_id": batch_id,
        "expected_key_set_sha256": expected_key_set_sha256,
        "attempt": 1,
        "observed_monotonic_ns": 12,
        "expected_terminal_tuples": 2,
        "visible_terminal_tuples": 2,
        "missing_count": 0,
        "within_deadline": True,
        "per_project_queries": [batch_query],
    }
    batch = {
        "batch_id": batch_id,
        "expected_key_set_sha256": expected_key_set_sha256,
        "offset": 0,
        "events": 2,
        "wait": {
            "batch_id": batch_id,
            "expected_key_set_sha256": expected_key_set_sha256,
            "timed_out": False,
            "deadline_monotonic_ns": 20,
            "settle": {"complete": True},
            "history_checkpoint": {
                "batch_id": batch_id,
                "expected_key_set_sha256": expected_key_set_sha256,
                "complete": True,
                "timed_out": False,
                "attempts": 1,
                "visible_monotonic_ns": 12,
                "missing": [],
            },
        },
        "evaluation_history_query": analyzer.systems._summary_ns([1]),
    }
    projection = _canonical({"evaluations": {}, "findings": {}})
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_bytes(projection)
    after.write_bytes(projection)

    def projection_receipt(path):
        return {
            "path": str(path),
            "bytes": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }

    projection_sha256 = sha256(projection).hexdigest()
    value = {
        "project_count": 1,
        "rule_count": 1,
        "batches": [batch],
        "evaluation_history_query": analyzer.systems._summary_ns([1, 1]),
        "post_drain": {"final_drain_wait": {"timed_out": False}},
        "restart_persistence": {
            "status": "completed",
            "persisted_projection_sha256_before": projection_sha256,
            "persisted_projection_sha256_after": projection_sha256,
            "persisted_projection_before_receipt": projection_receipt(before),
            "persisted_projection_after_receipt": projection_receipt(after),
            "exact_projection_bytes_preserved": True,
            "first_project_history_rows_query_visible": 2,
            "history_query": restart_query,
        },
    }
    analyzer._validate_soak_checkpoint_chain(
        tmp_path,
        value,
        [checkpoint],
        [restart_query],
        {batch_id: expected_keys},
    )
    analyzer._validate_soak_query_summaries(
        value, [checkpoint], [restart_query]
    )

    bad_query_summary = json.loads(json.dumps(value))
    bad_query_summary["batches"][0]["evaluation_history_query"][
        "maximum_ns"
    ] = 2
    with pytest.raises(analyzer.AnalysisValidationError, match="History summary"):
        analyzer._validate_soak_query_summaries(
            bad_query_summary, [checkpoint], [restart_query]
        )

    timed_value = json.loads(json.dumps(value))
    timed_checkpoint = dict(checkpoint)
    timed_checkpoint.update(
        {"visible_terminal_tuples": 1, "missing_count": 1}
    )
    timed_summary = timed_value["batches"][0]["wait"]["history_checkpoint"]
    timed_summary.update(
        {
            "complete": False,
            "timed_out": True,
            "visible_monotonic_ns": None,
            "missing": [expected_keys[0]],
        }
    )
    timed_value["batches"][0]["wait"]["timed_out"] = True
    timed_value["batches"].append(
        {**json.loads(json.dumps(batch)), "offset": 2}
    )
    with pytest.raises(analyzer.AnalysisValidationError, match="later batch"):
        analyzer._validate_soak_checkpoint_chain(
            tmp_path,
            timed_value,
            [timed_checkpoint],
            [restart_query],
            {batch_id: expected_keys},
        )

    missing_final_checkpoint = json.loads(json.dumps(timed_value))
    missing_final_checkpoint["batches"] = missing_final_checkpoint["batches"][:1]
    missing_final_checkpoint["post_drain"]["final_drain_wait"]["timed_out"] = True
    with pytest.raises(analyzer.AnalysisValidationError, match="checkpoint presence"):
        analyzer._validate_soak_checkpoint_chain(
            tmp_path,
            missing_final_checkpoint,
            [timed_checkpoint],
            [restart_query],
            {batch_id: expected_keys},
        )

    unequal = json.loads(json.dumps(value))
    unequal["restart_persistence"]["persisted_projection_sha256_after"] = "b" * 64
    with pytest.raises(analyzer.AnalysisValidationError, match="projection"):
        analyzer._validate_soak_checkpoint_chain(
            tmp_path,
            unequal,
            [checkpoint],
            [restart_query],
            {batch_id: expected_keys},
        )


def test_cache_diff_lists_and_retention_are_cross_checked(tmp_path):
    root = _make_attempt(tmp_path, "attempt-cache-tamper")
    path = root / "result.json"
    result = json.loads(path.read_text())
    result["global_outcomes"]["cache_end_receipt"]["changed_or_new"] = ["hidden"]
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with pytest.raises(analyzer.AnalysisValidationError, match="changed_or_new"):
        analyzer.validate_attempt(root, _expected_component_counts={"faults": 1})


def test_process_stream_artifacts_are_required_and_bound(tmp_path):
    missing = _make_attempt(tmp_path, "attempt-missing-stream")
    (missing / "streams.json").unlink()
    with pytest.raises(analyzer.AnalysisValidationError, match="process-stream artifact"):
        analyzer.validate_attempt(missing, _expected_component_counts={"faults": 1})

    tampered = _make_attempt(tmp_path, "attempt-tampered-stream")
    index_path = tampered / "streams.json"
    index = json.loads(index_path.read_text())
    index["lossless_from_launch"] = True
    index_path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    with pytest.raises(analyzer.AnalysisValidationError, match="capture declaration"):
        analyzer.validate_attempt(tampered, _expected_component_counts={"faults": 1})

    symlinked = _make_attempt(tmp_path, "attempt-symlinked-stream")
    stdout = symlinked / "stdout.log"
    stdout.unlink()
    outside = tmp_path / "outside-stdout.log"
    outside.write_text("outside\n")
    stdout.symlink_to(outside)
    with pytest.raises(analyzer.AnalysisValidationError, match="process-stream artifact"):
        analyzer.validate_attempt(symlinked, _expected_component_counts={"faults": 1})


def test_process_stream_hashing_never_materializes_unbounded_logs(
    tmp_path, monkeypatch
):
    root = _make_attempt(tmp_path, "attempt-streaming-hash")
    (root / "stdout.log").write_bytes(b"x" * (2 * 1024 * 1024 + 17))
    original = Path.read_bytes

    def forbid_log_read_bytes(path):
        if path.name in {"stdout.log", "stderr.log"}:
            raise AssertionError("unbounded process log was materialized")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", forbid_log_read_bytes)
    receipts = analyzer._validate_process_streams(
        root,
        {"process_streams": {"index": "streams.json", "stdout": "stdout.log", "stderr": "stderr.log"}},
        require_lossless=False,
    )

    assert receipts["stdout.log"]["bytes"] == 2 * 1024 * 1024 + 17


def test_unclassified_earlier_attempt_blocks_later_primary(tmp_path):
    _make_attempt(
        tmp_path,
        "formal-v3-r01",
        terminal=False,
        abort_status="unclassified_failure",
        created_utc="2026-08-30T00:00:01+00:00",
    )
    _make_attempt(
        tmp_path,
        "formal-v3-r02",
        created_utc="2026-08-30T00:00:02+00:00",
    )
    report = analyzer.analyze_attempts_root(
        tmp_path, "analysis-a", _expected_component_counts={"faults": 1}
    )
    assert report["primary_numeric"]["promoted"] is False
    assert report["primary_numeric"]["selection_blocked_by"] == "formal-v3-r01"


def test_unauthorized_later_edge_blocks_earlier_eligible_primary(tmp_path):
    _make_attempt(
        tmp_path,
        "formal-v3-r01",
        created_utc="2026-08-30T00:00:01+00:00",
    )
    _make_attempt(
        tmp_path,
        "formal-v3-r02",
        created_utc="2026-08-30T00:00:02+00:00",
    )
    report = analyzer.analyze_attempts_root(
        tmp_path,
        "analysis-unauthorized-later-edge",
        _expected_component_counts={"faults": 1},
    )
    assert report["primary_numeric"]["promoted"] is False
    assert report["primary_numeric"]["selected_raw_attempt_id"] is None
    assert report["primary_numeric"]["selection_blocked_by"] == "formal-v3-r01"
    assert report["analysis_binding"]["chain_error"].endswith("formal-v3-r02")
    assert report["attempt_ledger"][1]["replacement_validation_error"]
    assert report["sensitivity_endpoints"] == {}


def test_bound_replacement_chain_promotes_successor(tmp_path):
    first = _make_attempt(
        tmp_path,
        "formal-v3-r01",
        terminal=False,
        abort_status="harness_error",
        created_utc="2026-08-30T00:00:01+00:00",
    )
    evidence_root = tmp_path.parent / f"{tmp_path.name}-replacement-evidence"
    evidence_root.mkdir()
    evidence = evidence_root / "harness-assertion.txt"
    evidence.write_text("synthetic harness assertion\n")

    def receipt(path):
        return {
            "path": str(path.resolve()),
            "bytes": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest(),
        }

    replacement_path = evidence_root / "replacement.json"
    replacement_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "created_utc": "2026-08-30T00:00:01.500000+00:00",
                "successor_raw_attempt_id": "formal-v3-r02",
                "predecessor_raw_attempt_id": "formal-v3-r01",
                "classification": "harness_error",
                "original_status": "incomplete_harness_error",
                "reason": "synthetic predeclared harness failure",
                "affected_boundary": "synthetic test harness",
                "predecessor_artifacts": {
                    name: receipt(first / name)
                    for name in analyzer.attempts_contract._PREDECESSOR_ARTIFACT_NAMES
                },
                "predecessor_tree": (
                    analyzer.attempts_contract._predecessor_tree_receipts(first)
                ),
                "evidence_receipts": [
                    {"kind": "harness_assertion", **receipt(evidence)}
                ],
                "scheduler_adjudication": None,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    binding = analyzer.systems.replacement_launch_binding(
        tmp_path / "formal-v3-r02", str(replacement_path)
    )
    retention, copy_specs = analyzer.systems._replacement_retention_plan(binding)
    successor = _make_attempt(
        tmp_path,
        "formal-v3-r02",
        created_utc="2026-08-30T00:00:02+00:00",
        attempt_replacement=binding,
        replacement_retention=retention,
    )
    for spec in copy_specs:
        source = Path(spec["source_path"])
        destination = successor / spec["retained_path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    analyzer._validate_replacement_retention(
        successor,
        {
            "attempt_replacement": binding,
            "replacement_retention": retention,
        },
    )
    replacement_path.unlink()
    evidence.unlink()
    analyzer._validate_replacement_retention(
        successor,
        {
            "attempt_replacement": binding,
            "replacement_retention": retention,
        },
    )
    report = analyzer.analyze_attempts_root(
        tmp_path, "analysis-replacement", _expected_component_counts={"faults": 1}
    )
    assert report["primary_numeric"]["promoted"] is True
    assert report["primary_numeric"]["selected_raw_attempt_id"] == "formal-v3-r02"
    assert report["attempt_ledger"][0]["replacement_authorized_by_successor"] is True

    predecessor_result = first / "result.json"
    original_result = predecessor_result.read_bytes()
    predecessor_units = first / "units.jsonl"
    original_units = predecessor_units.read_bytes()
    predecessor_result.write_text('{"status":"completed"}\n')
    mutated = analyzer.analyze_attempts_root(
        tmp_path,
        "analysis-mutated-predecessor",
        _expected_component_counts={"faults": 1},
    )
    assert mutated["primary_numeric"]["promoted"] is False
    assert mutated["analysis_binding"]["chain_error"].endswith("formal-v3-r02")
    assert "predecessor" in mutated["attempt_ledger"][1][
        "replacement_validation_error"
    ]

    predecessor_result.write_bytes(original_result)
    predecessor_units.unlink()
    deleted = analyzer.analyze_attempts_root(
        tmp_path,
        "analysis-deleted-predecessor",
        _expected_component_counts={"faults": 1},
    )
    assert deleted["primary_numeric"]["promoted"] is False
    assert "predecessor" in deleted["attempt_ledger"][1][
        "replacement_validation_error"
    ]

    predecessor_units.write_bytes(original_units)
    predecessor_stdout = first / "stdout.log"
    predecessor_stdout.write_text("mutated after successor launch\n")
    stream_mutated = analyzer.analyze_attempts_root(
        tmp_path,
        "analysis-mutated-predecessor-stream",
        _expected_component_counts={"faults": 1},
    )
    assert stream_mutated["primary_numeric"]["promoted"] is False
    assert "differs from replacement binding" in stream_mutated["attempt_ledger"][1][
        "replacement_validation_error"
    ]

    predecessor_stdout.write_bytes(b"")
    started_payload = next((first / "faults").glob("*.started.json"))
    original_started = started_payload.read_bytes()
    started_payload.write_bytes(original_started + b" ")
    payload_mutated = analyzer.analyze_attempts_root(
        tmp_path,
        "analysis-mutated-predecessor-payload",
        _expected_component_counts={"faults": 1},
    )
    assert payload_mutated["primary_numeric"]["promoted"] is False
    assert "predecessor" in payload_mutated["attempt_ledger"][1][
        "replacement_validation_error"
    ]

    started_payload.unlink()
    payload_deleted = analyzer.analyze_attempts_root(
        tmp_path,
        "analysis-deleted-predecessor-payload",
        _expected_component_counts={"faults": 1},
    )
    assert payload_deleted["primary_numeric"]["promoted"] is False
    assert "predecessor" in payload_deleted["attempt_ledger"][1][
        "replacement_validation_error"
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "omit-core",
        "duplicate-path",
        "noncanonical-order",
        "wrong-type",
        "bad-hash",
        "mixed-root",
    ],
)
def test_self_contained_replacement_tree_requires_canonical_core_binding(mutation):
    digest = "a" * 64
    names = list(analyzer.attempts_contract._PREDECESSOR_ARTIFACT_NAMES)
    binding = {
        "predecessor_artifacts": {
            name: {"path": f"/original/formal-r01/{name}", "bytes": 1, "sha256": digest}
            for name in names
        },
        "predecessor_tree": [
            {
                "relative_path": name,
                "type": "regular_file",
                "mode": 0o600,
                "bytes": 1,
                "sha256": digest,
            }
            for name in sorted(names)
        ],
    }
    if mutation == "omit-core":
        binding["predecessor_tree"] = [
            item for item in binding["predecessor_tree"] if item["relative_path"] != "plan.json"
        ]
    elif mutation == "duplicate-path":
        binding["predecessor_tree"].append(dict(binding["predecessor_tree"][0]))
    elif mutation == "noncanonical-order":
        binding["predecessor_tree"].reverse()
    elif mutation == "wrong-type":
        item = next(
            value
            for value in binding["predecessor_tree"]
            if value["relative_path"] == "plan.json"
        )
        item.update({"type": "directory", "bytes": None, "sha256": None})
    elif mutation == "bad-hash":
        binding["predecessor_tree"][0]["sha256"] = "not-a-digest"
    else:
        binding["predecessor_artifacts"]["plan.json"]["path"] = (
            "/different/formal-r01/plan.json"
        )

    with pytest.raises(analyzer.AnalysisValidationError):
        analyzer._validate_predecessor_tree_binding(binding)


@pytest.mark.parametrize(
    "mutation", ["classification", "empty-evidence", "extra-evidence-field"]
)
def test_self_contained_replacement_revalidates_receipt_semantics(tmp_path, mutation):
    root = tmp_path / "formal-v3-r02"
    root.mkdir()
    (root / "launch.json").write_text(
        json.dumps({"created_utc": "2026-08-30T00:00:02+00:00"}) + "\n"
    )
    digest = "a" * 64
    names = list(analyzer.attempts_contract._PREDECESSOR_ARTIFACT_NAMES)
    replacement = {
        "kind": "replacement_attempt",
        "raw_attempt_ordinal": 2,
        "receipt_path": "/evidence/replacement.json",
        "receipt_bytes": 1,
        "receipt_sha256": digest,
        "canonical_receipt_sha256": digest,
        "classification": "harness_error",
        "original_status": "incomplete_harness_error",
        "successor_raw_attempt_id": "formal-v3-r02",
        "predecessor_raw_attempt_id": "formal-v3-r01",
        "created_utc": "2026-08-30T00:00:01+00:00",
        "reason": "positive synthetic harness evidence",
        "affected_boundary": "synthetic pre-measurement boundary",
        "scheduler_adjudication": None,
        "predecessor_artifacts": {
            name: {
                "path": f"/original/formal-v3-r01/{name}",
                "bytes": 1,
                "sha256": digest,
            }
            for name in names
        },
        "predecessor_tree": [
            {
                "relative_path": name,
                "type": "regular_file",
                "mode": 0o600,
                "bytes": 1,
                "sha256": digest,
            }
            for name in sorted(names)
        ],
        "evidence_receipts": [
            {
                "kind": "harness_traceback",
                "path": "/evidence/traceback.txt",
                "bytes": 1,
                "sha256": digest,
            }
        ],
    }
    if mutation == "classification":
        replacement["classification"] = "foo"
    elif mutation == "empty-evidence":
        replacement["evidence_receipts"] = []
    else:
        replacement["evidence_receipts"][0]["extra"] = True

    with pytest.raises(analyzer.AnalysisValidationError):
        analyzer._validate_retained_replacement_semantics(root, replacement)


def test_root_binding_keeps_code_and_protocol_when_every_attempt_is_invalid(tmp_path):
    (tmp_path / "formal-v3-r01").mkdir()
    report = analyzer.analyze_attempts_root(
        tmp_path, "analysis-empty", _expected_component_counts={"faults": 1}
    )
    binding = report["analysis_binding"]
    assert binding["analysis_code"]
    assert [item["path"] for item in binding["protocol_documents"]] == list(
        analyzer.PROTOCOL_PATHS
    )
    assert report["primary_numeric"]["promoted"] is False


def test_symlinked_attempt_entry_is_a_ledger_blocker(tmp_path):
    target = tmp_path.parent / "outside-attempt"
    target.mkdir()
    (tmp_path / "formal-v3-r01").symlink_to(target, target_is_directory=True)
    _make_attempt(
        tmp_path,
        "formal-v3-r02",
        created_utc="2026-08-30T00:00:02+00:00",
    )
    report = analyzer.analyze_attempts_root(
        tmp_path, "analysis-symlink", _expected_component_counts={"faults": 1}
    )
    assert report["primary_numeric"]["promoted"] is False
    assert report["primary_numeric"]["selection_blocked_by"] == "formal-v3-r01"


def test_whole_attempt_uses_all_r03_rows_and_retains_r02_partial_sensitivity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    r01_id = "formal-v3-20260831t051023z-r01"
    r02_id = analyzer.attempts_contract._COMPONENT_PREDECESSOR_ID
    r03_id = analyzer.attempts_contract._COMPONENT_SUCCESSOR_ID
    for attempt_id in (r01_id, r02_id, r03_id):
        (tmp_path / attempt_id).mkdir()

    full_plan = [
        {"component": "matrix", "unit_id": f"row-{position:03d}"}
        for position in range(430)
    ]

    def unit(item: dict, position: int, *, source: str) -> dict:
        return {
            "component": item["component"],
            "unit_id": item["unit_id"],
            "plan": item,
            "started": True,
            "status": "completed",
            "terminal_record": f"{source}/{position}.terminal.json",
            "terminal_sha256": f"{position + 1:064x}"[-64:],
            "value": {"source": source, "position": position},
        }

    r03_units = [unit(item, position, source="r03") for position, item in enumerate(full_plan)]
    ordered_partial = [
        {
            "plan_index": position,
            "component": item["component"],
            "unit_id": item["unit_id"],
            "primary_source_attempt_id": r03_id,
            "r02_raw_state": "terminal" if position < 279 else "never_started",
        }
        for position, item in enumerate(full_plan)
    ]
    r03_report = {
        "component_r03": True,
        "identity": {
            "attempt_id": r03_id,
            "attempt_replacement": {
                "classification": analyzer.attempts_contract._COMPONENT_CLASSIFICATION,
                "predecessor_raw_attempt_id": r02_id,
                "successor_raw_attempt_id": r03_id,
                "whole_attempt_protocol_correction": {
                    "primary_source_attempt_id": r03_id
                },
                "r02_partial_terminal_forensics": {
                    "receipt_type": "r02_partial_terminal_forensics",
                    "payload_sha256": "c" * 64,
                    "receipt": {"sha256": "d" * 64},
                    "counts": {"terminal": 279, "never_started": 150},
                    "digests": {"ordered_units_sha256": "e" * 64},
                    "ordered_units": ordered_partial,
                },
            },
        },
        "result": {"status": "completed"},
        "result_sha256": "3" * 64,
        "input_receipts": {},
        "plan": full_plan,
        "units": r03_units,
        "source_unchanged": True,
        "eligible": True,
    }

    monkeypatch.setattr(
        analyzer,
        "validate_attempt",
        lambda path: r03_report if path.name == r03_id else None,
    )
    monkeypatch.setattr(
        analyzer,
        "_reduce_endpoints",
        lambda plan, units: {"planned": len(plan), "observed": len(units)},
    )
    monkeypatch.setattr(
        analyzer,
        "_component_static_analysis_binding",
        lambda analysis_id: {
            "analysis_id": analysis_id,
            "reducer_config": analyzer.COMPONENT_REDUCER_CONFIG,
        },
    )
    report = analyzer.analyze_whole_attempt(
        tmp_path, analyzer.COMPONENT_ANALYSIS_ID
    )

    assert report["primary_r03"] == {
        "promoted": True,
        "unit_count": 430,
        "source_attempt_id": r03_id,
        "reason": "all exact whole-attempt promotion gates passed",
    }
    assert len(report["primary_unit_ledger"]) == 430
    assert {row["source_attempt_id"] for row in report["primary_unit_ledger"]} == {
        r03_id
    }
    sensitivity = report["r02_partial_sensitivity"]
    assert sensitivity["primary_selection_effect"] == "none"
    assert len(sensitivity["ordered_units"]) == 430

    ordered_partial[350]["primary_source_attempt_id"] = r02_id
    with pytest.raises(
        analyzer.AnalysisValidationError,
        match="role ledger differs",
    ):
        analyzer.analyze_whole_attempt(
            tmp_path, analyzer.COMPONENT_ANALYSIS_ID
        )
