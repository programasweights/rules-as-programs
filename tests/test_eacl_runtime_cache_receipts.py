from __future__ import annotations

import hashlib
import json
import os
import stat as stat_module
from pathlib import Path

import pytest

from experiments.eacl2027 import scaling_faults_runtime as runtime


def _socket_preflight_fixture(tmp_path: Path) -> tuple[Path, str, Path, dict]:
    job_id = str(int(hashlib.sha256(str(tmp_path).encode()).hexdigest()[:14], 16))
    socket_root = Path("/tmp") / f"rf3-{job_id}"
    socket_root.mkdir(mode=0o700)
    retained = (tmp_path / "attempts" / "formal-r02" / "runtime" / "preflight").resolve()
    digest_input = {
        "schema_version": 1,
        "raw_attempt_id": "formal-r02",
        "component": "preflight",
        "unit_id": "socket-canary",
        "retained_runtime_root": str(retained),
    }
    digest = hashlib.sha256(
        json.dumps(
            digest_input,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    endpoint = socket_root / f"{digest}.sock"
    root_stat = socket_root.lstat()
    receipt = {
        "schema_version": 1,
        "digest_input": digest_input,
        "endpoint_digest": digest,
        "endpoint": str(endpoint),
        "encoded_pathname_bytes": len(os.fsencode(endpoint)),
        "maximum_encoded_pathname_bytes": 107,
        "socket_root": {
            "path": str(socket_root),
            "owner_uid": os.geteuid(),
            "mode": 0o700,
            "device": root_stat.st_dev,
        },
        "bind_connect_accept_payload_equal": True,
        "endpoint_removed_after_probe": True,
    }
    return socket_root, job_id, retained, receipt


def test_socket_preflight_receipt_recomputes_exact_capability_binding(tmp_path):
    socket_root, job_id, retained, receipt = _socket_preflight_fixture(tmp_path)
    try:
        assert runtime.validate_socket_preflight_receipt(
            receipt,
            socket_root=socket_root,
            raw_attempt_id="formal-r02",
            job_id=job_id,
            retained_runtime_root=retained,
        ) == receipt
    finally:
        socket_root.rmdir()


def test_socket_preflight_receipt_rejects_tampering_and_live_endpoint(tmp_path):
    socket_root, job_id, retained, receipt = _socket_preflight_fixture(tmp_path)
    endpoint = Path(receipt["endpoint"])
    try:
        tampered = json.loads(json.dumps(receipt))
        tampered["endpoint_digest"] = "0" * 64
        with pytest.raises(runtime.RuntimeContractError, match="receipt mismatch"):
            runtime.validate_socket_preflight_receipt(
                tampered,
                socket_root=socket_root,
                raw_attempt_id="formal-r02",
                job_id=job_id,
                retained_runtime_root=retained,
            )
        endpoint.write_bytes(b"stale")
        with pytest.raises(runtime.RuntimeContractError, match="still exists"):
            runtime.validate_socket_preflight_receipt(
                receipt,
                socket_root=socket_root,
                raw_attempt_id="formal-r02",
                job_id=job_id,
                retained_runtime_root=retained,
            )
    finally:
        endpoint.unlink(missing_ok=True)
        socket_root.rmdir()


def _cache_fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    cache = tmp_path / "cache"
    content = cache / "programasweights"
    program_id = "program-1"
    program = content / "programs" / program_id
    program.mkdir(parents=True)
    runtime_manifest = {
        "runtime_id": "runtime-1",
        "local_sdk": {
            "n_ctx": 2048,
            "base_model": {"file": "model.gguf", "size_bytes": 5},
        },
    }
    (program / "adapter.gguf").write_bytes(b"adapter")
    (program / "prompt_template.txt").write_text("prompt", encoding="utf-8")
    (program / "meta.json").write_text(
        json.dumps({"program_id": program_id, "runtime": runtime_manifest}),
        encoding="utf-8",
    )
    (content / "runtimes").mkdir()
    (content / "runtimes" / "runtime-1.json").write_text(
        json.dumps(runtime_manifest), encoding="utf-8"
    )
    (content / "base_models").mkdir()
    (content / "base_models" / "model.gguf").write_bytes(b"model")
    return cache, content, program_id


def _cache_receipt(cache: Path, program_id: str) -> dict:
    return runtime.cache_receipt(cache, [program_id], required_n_ctx=2048)


def _end_receipt(
    cache: Path,
    program_id: str,
    launch: dict,
    retained_root: Path,
) -> dict:
    return runtime.retain_cache_end_receipt(
        {
            "cache_and_dependency_receipt": {"formal_cache_dir": str(cache)},
            "cpu_and_inference": {"paw_function_n_ctx": 2048},
        },
        [program_id],
        launch_receipt=launch,
        changed_files_root=retained_root,
    )


def test_lstat_entry_type_has_an_explicit_label_for_every_file_kind():
    expected = {
        stat_module.S_IFREG: "regular",
        stat_module.S_IFDIR: "directory",
        stat_module.S_IFLNK: "symlink",
        stat_module.S_IFIFO: "fifo",
        stat_module.S_IFSOCK: "socket",
        stat_module.S_IFBLK: "block_device",
        stat_module.S_IFCHR: "character_device",
        0: "other",
    }

    for mode, label in expected.items():
        assert runtime._lstat_entry_type(mode | 0o640) == label


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="requires Unix filesystem entry types",
)
def test_raw_tree_receipt_records_directories_links_and_fifos(tmp_path):
    root = tmp_path / "tree"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "regular").write_bytes(b"contents")
    os.symlink("nested/regular", root / "link")
    os.mkfifo(root / "fifo")
    receipt = runtime.raw_tree_receipt(root)

    entries = {item["path"]: item for item in receipt["entries"]}
    assert receipt["root_entry"]["type"] == "directory"
    assert entries["nested"]["type"] == "directory"
    assert entries["nested/regular"]["type"] == "regular"
    assert entries["link"] == {
        "path": "link",
        "type": "symlink",
        "mode": entries["link"]["mode"],
        "target": "nested/regular",
    }
    assert entries["fifo"]["type"] == "fifo"
    assert not receipt["errors"]


def test_raw_tree_keeps_lstat_evidence_when_regular_bytes_cannot_be_hashed(
    tmp_path, monkeypatch
):
    root = tmp_path / "tree"
    root.mkdir()
    unreadable = root / "unreadable"
    unreadable.write_bytes(b"evidence")
    original = runtime.sha256_file

    def fail_one_hash(path: Path) -> str:
        if path == unreadable:
            raise PermissionError("synthetic read denial")
        return original(path)

    monkeypatch.setattr(runtime, "sha256_file", fail_one_hash)
    receipt = runtime.raw_tree_receipt(root)

    entry = next(item for item in receipt["entries"] if item["path"] == "unreadable")
    assert entry["type"] == "regular"
    assert entry["bytes"] == len(b"evidence")
    assert entry["sha256"] is None
    assert receipt["errors"][0]["path"] == "unreadable"
    assert receipt["errors"][0]["type"] == "PermissionError"


def test_cache_receipt_binds_raw_prelaunch_tree_and_unchanged_end(tmp_path):
    cache, content, program_id = _cache_fixture(tmp_path)
    (content / "empty-directory").mkdir()

    launch = _cache_receipt(cache, program_id)
    raw_entries = {item["path"]: item for item in launch["raw_tree"]["entries"]}
    assert raw_entries["empty-directory"]["type"] == "directory"

    end = _end_receipt(cache, program_id, launch, tmp_path / "retained")
    assert end["status"] == "completed"
    assert end["unchanged"] is True
    assert end["entry_changes"] == []
    assert end["deleted_entries"] == []
    assert end["special_entries"] == []
    assert end["changed_or_new"] == []
    assert end["deleted"] == []


def test_cache_end_reports_added_and_deleted_empty_directories(tmp_path):
    cache, content, program_id = _cache_fixture(tmp_path)
    (content / "deleted-empty-directory").mkdir()
    launch = _cache_receipt(cache, program_id)

    (content / "deleted-empty-directory").rmdir()
    (content / "added-empty-directory").mkdir()
    end = _end_receipt(cache, program_id, launch, tmp_path / "retained")

    assert end["status"] == "system_violation"
    assert end["changed_or_new"] == []
    assert end["deleted"] == []
    assert [item["path"] for item in end["entry_changes"]] == [
        "added-empty-directory"
    ]
    assert end["entry_changes"][0]["change"] == "added"
    assert [item["path"] for item in end["deleted_entries"]] == [
        "deleted-empty-directory"
    ]
    assert end["retained_changed_files_root"] is None


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="requires Unix filesystem entry types",
)
def test_cache_end_reports_special_entry_type_changes(tmp_path):
    cache, content, program_id = _cache_fixture(tmp_path)
    special = content / "special"
    special.mkdir()
    launch = _cache_receipt(cache, program_id)

    special.rmdir()
    os.mkfifo(special)
    end = _end_receipt(cache, program_id, launch, tmp_path / "retained")

    change = next(item for item in end["entry_changes"] if item["path"] == "special")
    assert end["status"] == "system_violation"
    assert change["change"] == "type_changed"
    assert change["before"]["type"] == "directory"
    assert change["after"]["type"] == "fifo"
    assert [item["path"] for item in end["special_entries"]] == ["special"]
    assert end["non_regular_or_symlink"] == ["special"]


def test_retained_changed_file_root_has_attempt_relative_locator(tmp_path):
    cache, content, program_id = _cache_fixture(tmp_path)
    launch = _cache_receipt(cache, program_id)
    changed = content / "programs" / program_id / "prompt_template.txt"
    changed.write_text("changed prompt", encoding="utf-8")
    retained_root = (
        tmp_path / "attempt" / "runtime" / "cache-end-changed-files"
    )

    end = _end_receipt(cache, program_id, launch, retained_root)

    relative = f"programs/{program_id}/prompt_template.txt"
    assert end["changed_or_new"] == [relative]
    assert end["retained_changed_files_root"] == str(retained_root)
    assert end["retained_changed_files_root_relative"] == {
        "base": "attempt_root",
        "path": "runtime/cache-end-changed-files",
    }
    assert (retained_root / relative).read_text(encoding="utf-8") == "changed prompt"
