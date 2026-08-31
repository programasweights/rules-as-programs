from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from experiments.eacl2027 import build_scaling_faults_publication as publisher


R01, R02 = publisher.EXPECTED_ATTEMPT_IDS
GITHUB_OWNER = "programasweights"
GITHUB_REPOSITORY = "rules-as-programs"
GITHUB_RELEASE_TAG = "eacl2027-test-v1"


def _github_coordinates():
    return {
        "github_owner": GITHUB_OWNER,
        "github_repository": GITHUB_REPOSITORY,
        "github_release_tag": GITHUB_RELEASE_TAG,
    }


def _github_asset_uri(asset_name: str) -> str:
    return (
        f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPOSITORY}/releases/"
        f"download/{GITHUB_RELEASE_TAG}/{asset_name}"
    )


def _report():
    primary = {
        "promoted": True,
        "selected_raw_attempt_id": R02,
        "selection_blocked_by": None,
        "selection_rule": "synthetic exact selection",
    }
    return {
        "schema_version": 1,
        "analysis_id": "formal-final-v1",
        "generated_at": "2026-08-31T12:00:00+00:00",
        "analysis_binding": {
            "chain_error": None,
            "analysis_version": publisher.analyzer.ANALYSIS_VERSION,
            "protocol_documents": [
                {
                    "path": "experiments/eacl2027/protocol-v3-amendment-007.json",
                    "sha256": "a" * 64,
                }
            ],
        },
        "analysis_binding_sha256": "b" * 64,
        "attempt_ledger": [
            {
                "raw_attempt_id": R01,
                "status": "completed_with_system_violations",
                "candidate_eligible": False,
                "created_utc": "2026-08-31T10:00:00+00:00",
                "validation_error": None,
                "launch_order_valid": True,
                "launch_order_key": "2026-08-31T10:00:00+00:00",
                "replacement_authorized_by_successor": True,
                "adjudicated_status": "superseded_premeasurement_harness_error",
                "raw_status_preserved": "completed_with_system_violations",
                "numeric_aggregate_excluded": True,
                "input_sha256": {},
                "analysis_binding_sha256": "c" * 64,
                "attempt_id_valid": True,
                "chain_prefix": "formal-v3-20260831t051023z",
                "raw_attempt_ordinal": 1,
                "rerun_eligible_status": False,
            },
            {
                "raw_attempt_id": R02,
                "status": "completed",
                "candidate_eligible": True,
                "created_utc": "2026-08-31T11:00:00+00:00",
                "validation_error": None,
                "launch_order_valid": True,
                "launch_order_key": "2026-08-31T11:00:00+00:00",
                "replacement_authorized_by_successor": False,
                "replacement_validation_error": None,
                "validated_replacement_binding": {"kind": "replacement_attempt"},
                "input_sha256": {},
                "analysis_binding_sha256": "d" * 64,
                "attempt_id_valid": True,
                "chain_prefix": "formal-v3-20260831t051023z",
                "raw_attempt_ordinal": 2,
                "rerun_eligible_status": False,
            },
        ],
        "primary_numeric": primary,
        "endpoints": {"matrix": {"synthetic": True}},
        "sensitivity_endpoints": {},
    }


def _make_fixture(tmp_path: Path, monkeypatch):
    ledger_parent = tmp_path / "raw"
    attempts = ledger_parent / "attempts"
    attempts.mkdir(parents=True, mode=0o700)
    attempts.chmod(0o700)
    staging = ledger_parent / ".attempts.staging"
    staging.mkdir(mode=0o700)
    staging.chmod(0o700)
    claims = staging / ".publication-claims"
    claims.mkdir(mode=0o700)
    claims.chmod(0o700)
    payloads = {}
    for raw_id in (R01, R02):
        root = attempts / raw_id
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        nested = root / "runtime"
        nested.mkdir(mode=0o700)
        nested.chmod(0o700)
        payload = nested / "evidence.bin"
        payload.write_bytes((raw_id + "\n").encode() * 3)
        payload.chmod(0o600)
        payloads[raw_id] = payload
        launch = root / "launch.json"
        launch.write_text(json.dumps({"attempt_id": raw_id}) + "\n")
        launch.chmod(0o600)
        claim = claims / f"{raw_id}.launch.json"
        os.link(launch, claim)
        launch_bytes = launch.read_bytes()
        publication = {
            "schema_version": 1,
            "destination": str(root),
            "method": "hardlink_claim_then_posix_rename",
            "native_primitive": publisher.analyzer._FORMAL_NATIVE_PUBLICATION_PRIMITIVE,
            "native_unsupported": {"errno": 22, "name": "EINVAL"},
            "claim": {
                "path": str(claim),
                "artifact": "launch.json",
                "bytes": len(launch_bytes),
                "sha256": hashlib.sha256(launch_bytes).hexdigest(),
            },
        }
        (root / "publication.json").write_text(
            json.dumps(publication, indent=2, sort_keys=True) + "\n"
        )
    report = _report()
    reduced = tmp_path / "formal-reduced.json"
    reduced.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    def fresh(_path, analysis_id):
        assert analysis_id == report["analysis_id"]
        value = copy.deepcopy(report)
        value["generated_at"] = "2026-08-31T12:01:00+00:00"
        return value

    monkeypatch.setattr(publisher.analyzer, "analyze_attempts_root", fresh)

    def github_metadata(coordinates, expected_assets):
        return {
            "schema_version": 1,
            "verification_kind": "github_release_api_metadata_v1",
            "verified_utc": "2026-08-31T12:01:30+00:00",
            "github_release": dict(coordinates),
            "api_response": {
                "api_version": publisher.GITHUB_API_VERSION,
                "endpoint_host": "api.github.com",
                "endpoint_path": (
                    f"/repos/{GITHUB_OWNER}/{GITHUB_REPOSITORY}/releases/tags/"
                    f"{GITHUB_RELEASE_TAG}"
                ),
                "http_status": 200,
                "content_encoding": None,
                "response_content_length": 2,
                "bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            },
            "release": {
                "id": 123,
                "tag_name": GITHUB_RELEASE_TAG,
                "draft": False,
                "immutable_field_present": True,
                "immutable": True,
                "asset_count": len(expected_assets),
            },
            "assets": [
                {
                    "id": 1000 + index,
                    "name": asset["name"],
                    "state": "uploaded",
                    "size": asset["bytes"],
                    "digest": f"sha256:{asset['sha256']}",
                    "browser_download_url": _github_asset_uri(asset["name"]),
                }
                for index, asset in enumerate(expected_assets)
            ],
        }

    monkeypatch.setattr(publisher, "_fetch_github_release_metadata", github_metadata)
    r01_tree = publisher.attempts_contract._predecessor_tree_receipts(attempts / R01)
    r01_regular = [item for item in r01_tree if item["type"] == "regular_file"]
    monkeypatch.setattr(
        publisher,
        "R01_TREE_ANCHOR",
        {
            "entries_excluding_root": len(r01_tree),
            "regular_file_count": len(r01_regular),
            "regular_file_bytes": sum(item["bytes"] for item in r01_regular),
            "sha256": hashlib.sha256(
                publisher._canonical_json_bytes(r01_tree)
            ).hexdigest(),
        },
    )
    r01_claim = claims / f"{R01}.launch.json"
    monkeypatch.setattr(
        publisher,
        "R01_CLAIM_ANCHOR",
        {
            "bytes": r01_claim.stat().st_size,
            "sha256": hashlib.sha256(r01_claim.read_bytes()).hexdigest(),
        },
    )
    snapshots = publisher._snapshot_ledger(attempts)
    scans = publisher._scan_ledger(snapshots)
    privacy_review = {
        "schema_version": 1,
        "receipt_kind": publisher.PRIVACY_REVIEW_KIND,
        "publication_version": publisher.PUBLICATION_VERSION,
        "scope": publisher.PRIVACY_REVIEW_SCOPE,
        "decision": "approved",
        "reviewer": "synthetic-test-reviewer",
        "reviewed_utc": "2026-08-31T12:00:00+00:00",
        "attempts": [
            publisher._privacy_attempt_binding(snapshot, scans[snapshot.raw_attempt_id])
            for snapshot in snapshots
        ],
    }
    privacy_path = tmp_path / "privacy-review.json"
    privacy_path.write_text(json.dumps(privacy_review, indent=2, sort_keys=True) + "\n")
    privacy_path.chmod(0o444)
    out = tmp_path / "publication"
    out.mkdir(mode=0o700)
    out.chmod(0o700)
    names = {R01: f"{R01}.tar.zst", R02: f"{R02}.tar.zst"}
    archives = {raw_id: out / name for raw_id, name in names.items()}
    uris = {raw_id: _github_asset_uri(name) for raw_id, name in names.items()}
    return attempts, reduced, payloads, archives, uris, out / "draft.json"


def _privacy_receipt(draft: Path) -> Path:
    return draft.parent.parent / "privacy-review.json"


def _build(tmp_path, monkeypatch):
    fixture = _make_fixture(tmp_path, monkeypatch)
    attempts, reduced, _, archives, uris, draft = fixture
    zstd = shutil.which("zstd")
    if zstd is None:
        pytest.skip("zstd CLI is unavailable")
    value = publisher.build_archives(
        attempts_root=attempts,
        reduced_json=reduced,
        archive_outputs=archives,
        durable_uris=uris,
        draft_receipt_output=draft,
        privacy_review_receipt=_privacy_receipt(draft),
        **_github_coordinates(),
        zstd_executable=Path(zstd),
    )
    return fixture, value


def _tar_members(archive: Path):
    zstd = shutil.which("zstd")
    assert zstd is not None
    completed = subprocess.run(
        [zstd, "-q", "-d", "-c", str(archive)],
        check=True,
        stdout=subprocess.PIPE,
    )
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:") as tar:
        values = {}
        for member in tar:
            extracted = tar.extractfile(member) if member.isfile() else None
            values[member.name] = {
                "type": member.type,
                "linkname": member.linkname,
                "pax_headers": dict(member.pax_headers),
                "data": extracted.read() if extracted is not None else None,
            }
        return values


def _append_archive_member(archive: Path, name: str, value: bytes) -> None:
    zstd = shutil.which("zstd")
    assert zstd is not None
    unpacked = subprocess.run(
        [zstd, "-q", "-d", "-c", str(archive)],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    rewritten = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as source:
        with tarfile.open(
            fileobj=rewritten, mode="w:", format=tarfile.PAX_FORMAT
        ) as destination:
            for member in source:
                payload = source.extractfile(member) if member.isfile() else None
                destination.addfile(member, payload)
            extra = publisher._tar_info(name, mode=0o444, size=len(value))
            destination.addfile(extra, io.BytesIO(value))
    packed = subprocess.run(
        [zstd, "-q", "-19", "-T1", "-c"],
        check=True,
        input=rewritten.getvalue(),
        stdout=subprocess.PIPE,
    ).stdout
    archive.chmod(0o600)
    archive.write_bytes(packed)
    archive.chmod(0o444)


def _rewrite_archive(
    archive: Path,
    *,
    mutate_member=None,
    decompressed_suffix: bytes = b"",
) -> None:
    zstd = shutil.which("zstd")
    assert zstd is not None
    unpacked = subprocess.run(
        [zstd, "-q", "-d", "-c", str(archive)],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    if mutate_member is not None:
        rewritten = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as source:
            with tarfile.open(
                fileobj=rewritten, mode="w:", format=tarfile.PAX_FORMAT
            ) as destination:
                for index, member in enumerate(source):
                    payload = source.extractfile(member) if member.isfile() else None
                    if index == 0:
                        mutate_member(member)
                    destination.addfile(member, payload)
        unpacked = rewritten.getvalue()
    packed = subprocess.run(
        [zstd, "-q", "-19", "-T1", "-c"],
        check=True,
        input=unpacked + decompressed_suffix,
        stdout=subprocess.PIPE,
    ).stdout
    archive.chmod(0o600)
    archive.write_bytes(packed)
    archive.chmod(0o444)


def _refresh_draft_archive_receipt(
    draft: Path, archive: Path, attempt_index: int
) -> None:
    draft.chmod(0o600)
    value = json.loads(draft.read_text())
    byte_count, digest = publisher._stream_file_identity(archive)
    value["attempts"][attempt_index]["archive"]["bytes"] = byte_count
    value["attempts"][attempt_index]["archive"]["sha256"] = digest
    draft.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    draft.chmod(0o444)


def _seed_bundle_transaction(directory: publisher.SecureOutputDirectory):
    payloads = {
        "r01.tar.zst": b"synthetic r01 archive\n",
        "r02.tar.zst": b"synthetic r02 archive\n",
        "draft.json": b'{"receipt_kind":"synthetic marker"}\n',
    }
    temporaries = {}
    for destination, payload in payloads.items():
        descriptor, temporary = directory.create_temporary(destination)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporaries[destination] = temporary
    archives = [
        (temporaries["r01.tar.zst"], "r01.tar.zst"),
        (temporaries["r02.tar.zst"], "r02.tar.zst"),
    ]
    marker = (temporaries["draft.json"], "draft.json")
    return archives, marker, payloads


def test_builds_one_complete_archive_per_attempt_and_finalize_is_remote_gated(
    tmp_path, monkeypatch
):
    (attempts, reduced, _, archives, uris, draft), built = _build(tmp_path, monkeypatch)
    assert built["receipt_kind"] == "unpublished_archive_build"
    assert built["privacy_review"]["authorization"]["decision"] == "approved"
    assert "do not commit" in built["publication_gate"]
    for raw_id in (R01, R02):
        archive = archives[raw_id]
        assert stat.S_IMODE(archive.stat().st_mode) == 0o444
        members = _tar_members(archive)
        root = publisher._archive_root(raw_id)
        manifest_name = f"{root}/MANIFEST.json"
        claim_name = publisher._claim_archive_path(raw_id)
        launch_name = publisher._tree_archive_path(raw_id, "launch.json")
        assert manifest_name in members
        assert claim_name in members
        assert members[claim_name]["type"] == tarfile.LNKTYPE
        assert members[claim_name]["linkname"] == launch_name
        if len(claim_name) > tarfile.LENGTH_NAME:
            assert members[claim_name]["pax_headers"] == {"path": claim_name}
        assert members[launch_name]["data"] == (
            (attempts / raw_id / "launch.json").read_bytes()
        )
        manifest = json.loads(members[manifest_name]["data"])
        assert manifest["attempt"]["raw_attempt_id"] == raw_id
        assert manifest["durable_uri"] == uris[raw_id]
        assert manifest["attempt"]["tree"]["inventory"]
        assert manifest["attempt"]["claim"]["tar_member_type"] == "hardlink"
        assert manifest["attempt"]["claim"]["hardlink_target"] == launch_name
        assert manifest["privacy_review"] == built["privacy_review"]
        other = R02 if raw_id == R01 else R01
        assert all(other not in name for name in members)

    calls = []

    def verify(uri, *, expected_bytes, expected_sha256):
        calls.append(uri)
        return {
            "verified_utc": "2026-08-31T12:02:00+00:00",
            "http_status": 200,
            "response_content_length": expected_bytes,
            "content_encoding": None,
            "bytes": expected_bytes,
            "sha256": expected_sha256,
            "exact_match": True,
        }

    monkeypatch.setattr(publisher, "_stream_remote_identity", verify)
    index = tmp_path / "formal-publication-index.json"
    value = publisher.finalize_publication(
        attempts_root=attempts,
        reduced_json=reduced,
        draft_receipt=draft,
        durable_uris=uris,
        index_output=index,
        privacy_review_receipt=_privacy_receipt(draft),
        **_github_coordinates(),
    )
    assert calls == [uris[R01], uris[R02]]
    assert value["receipt_kind"] == "verified_attempt_publication_index"
    assert value["privacy_review"] == built["privacy_review"]
    assert value["github_release_verification"]["release"]["id"] == 123
    assert [item["archive"]["github_asset"]["id"] for item in value["attempts"]] == [
        1000,
        1001,
    ]
    assert stat.S_IMODE(index.stat().st_mode) == 0o444
    assert all("local_path" not in item["archive"] for item in value["attempts"])
    assert all(
        item["archive"]["remote_verification"]["exact_match"] is True
        for item in value["attempts"]
    )


def test_build_rejects_claim_copy_that_is_not_the_launch_hard_link(
    tmp_path, monkeypatch
):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    claim = publisher.analyzer._expected_publication_claim_path(attempts / R02)
    value = claim.read_bytes()
    claim.unlink()
    claim.write_bytes(value)
    with pytest.raises(publisher.PublicationError, match="hard link"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert not any(path.exists() for path in archives.values())
    assert not draft.exists()


def test_tree_mutation_after_archive_fails_before_any_output_is_published(
    tmp_path, monkeypatch
):
    attempts, reduced, payloads, archives, uris, draft = _make_fixture(
        tmp_path, monkeypatch
    )
    zstd = shutil.which("zstd")
    if zstd is None:
        pytest.skip("zstd CLI is unavailable")
    original = publisher._write_attempt_archive

    def mutate_after_first(*args, **kwargs):
        value = original(*args, **kwargs)
        if kwargs["snapshot"].raw_attempt_id == R01:
            payloads[R02].write_bytes(b"mutated after first archive\n")
        return value

    monkeypatch.setattr(publisher, "_write_attempt_archive", mutate_after_first)
    with pytest.raises(publisher.PublicationError, match="changed while archiving"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(zstd),
        )
    assert not any(path.exists() for path in archives.values())
    assert not draft.exists()
    assert not list(draft.parent.glob("*.partial"))


def test_second_remote_mismatch_leaves_no_committable_index(tmp_path, monkeypatch):
    (attempts, reduced, _, _, uris, draft), _ = _build(tmp_path, monkeypatch)
    calls = 0

    def fail_second(uri, *, expected_bytes, expected_sha256):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise publisher.PublicationError("remote bytes mismatch")
        return {
            "verified_utc": "2026-08-31T12:02:00+00:00",
            "http_status": 200,
            "response_content_length": expected_bytes,
            "content_encoding": None,
            "bytes": expected_bytes,
            "sha256": expected_sha256,
            "exact_match": True,
        }

    monkeypatch.setattr(publisher, "_stream_remote_identity", fail_second)
    index = tmp_path / "formal-publication-index.json"
    with pytest.raises(publisher.PublicationError, match="remote bytes mismatch"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=index,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    assert calls == 2
    assert not index.exists()


@pytest.mark.parametrize(
    "secret",
    [
        b'{"password":"0123456789abcdef"}\n',
        b"sk-proj-" + b"A" * 48,
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
        b"AWS_SECRET_ACCESS_KEY=abcdEFGH0123456789+/abcdEFGH\n",
    ],
)
def test_sensitive_prescan_blocks_before_archive_creation(
    tmp_path, monkeypatch, secret
):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    secret_path = attempts / R02 / "runtime" / "credential.bin"
    secret_path.write_bytes(secret)
    with pytest.raises(publisher.PublicationError, match="sensitive-data prescan"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert not any(path.exists() for path in archives.values())
    assert not draft.exists()


def test_sensitive_scan_receipt_is_exact_and_clean_fixtures_do_not_trigger(
    tmp_path, monkeypatch
):
    for clean in (
        b'{"password":"missing"}',
        b'{"codex_api_key_present":false}',
        b"password is missing",
        b"a" * 64,
        b"secrets.txt",
        b"\x00password unavailable\x00",
    ):
        publisher._scan_bytes_for_sensitive(clean, label="clean")
    (_, _, _, _, _, _), built = _build(tmp_path, monkeypatch)
    for attempt in built["attempts"]:
        receipt = attempt["sensitive_data_scan"]
        core = dict(receipt)
        result_sha256 = core.pop("result_sha256")
        assert (
            result_sha256
            == hashlib.sha256(publisher._canonical_json_bytes(core)).hexdigest()
        )
        assert receipt["detector_config"] == publisher.SENSITIVE_SCAN_CONFIG
        assert (
            receipt["detector_config_sha256"] == publisher.SENSITIVE_SCAN_CONFIG_SHA256
        )
        assert receipt["match_count"] == 0
        assert receipt["matching_bytes_retained"] is False


def test_sensitive_scan_detects_token_across_chunk_boundary(tmp_path):
    chunk_size = int(publisher.SENSITIVE_SCAN_CONFIG["chunk_bytes"])
    token = b"sk-proj-" + b"B" * 48
    value = b"x" * (chunk_size - 5) + token
    path = tmp_path / "boundary.bin"
    path.write_bytes(value)
    with pytest.raises(publisher.PublicationError, match="openai_token"):
        publisher._scan_regular_file(
            path,
            label="boundary.bin",
            expected_mode=stat.S_IMODE(path.stat().st_mode),
            expected_bytes=len(value),
            expected_sha256=hashlib.sha256(value).hexdigest(),
        )


def test_sensitive_filename_and_unsafe_mode_fail_closed(tmp_path, monkeypatch):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    sensitive_name = attempts / R02 / "runtime" / ".env"
    sensitive_name.write_text("benign=true\n")
    with pytest.raises(publisher.PublicationError, match="sensitive_path_basename"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    sensitive_name.unlink()
    real_inventory = publisher.attempts_contract._predecessor_tree_receipts

    def unsafe_inventory(root):
        values = real_inventory(root)
        if root.name == R02:
            values[0] = dict(values[0], mode=int(values[0]["mode"]) | 0o4000)
        return values

    monkeypatch.setattr(
        publisher.attempts_contract,
        "_predecessor_tree_receipts",
        unsafe_inventory,
    )
    with pytest.raises(publisher.PublicationError, match="setuid"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )


@pytest.mark.parametrize("falsify", ["manifest", "compressor"])
def test_finalize_rejects_falsified_archive_metadata(tmp_path, monkeypatch, falsify):
    (attempts, reduced, _, _, uris, draft), _ = _build(tmp_path, monkeypatch)
    draft.chmod(0o600)
    value = json.loads(draft.read_text())
    if falsify == "manifest":
        value["attempts"][0]["archive"]["manifest"]["sha256"] = "f" * 64
    else:
        value["attempts"][0]["archive"]["compressor"]["version"] = "falsified"
    draft.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    draft.chmod(0o444)
    index = tmp_path / "index.json"
    with pytest.raises(publisher.PublicationError, match="falsified|authentic"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=index,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    assert not index.exists()


def test_finalize_rehashes_reduced_json_after_both_remote_downloads(
    tmp_path, monkeypatch
):
    (attempts, reduced, _, _, uris, draft), _ = _build(tmp_path, monkeypatch)
    calls = 0

    def mutate_reduced(uri, *, expected_bytes, expected_sha256):
        nonlocal calls
        calls += 1
        if calls == 2:
            reduced.write_bytes(reduced.read_bytes() + b" ")
        return {
            "verified_utc": "2026-08-31T12:02:00+00:00",
            "http_status": 200,
            "response_content_length": expected_bytes,
            "content_encoding": None,
            "bytes": expected_bytes,
            "sha256": expected_sha256,
            "exact_match": True,
        }

    monkeypatch.setattr(publisher, "_stream_remote_identity", mutate_reduced)
    index = tmp_path / "index.json"
    with pytest.raises(
        publisher.PublicationError, match="reduced systems result changed"
    ):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=index,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    assert calls == 2
    assert not index.exists()


def test_startup_recovery_after_sigkill_during_journal_write(tmp_path, monkeypatch):
    bundle = tmp_path / "crash-journal-write"
    bundle.mkdir(mode=0o700)
    bundle.chmod(0o700)

    class SyntheticPowerLoss(BaseException):
        pass

    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        archives, marker, _payloads = _seed_bundle_transaction(directory)
        expected_destinations = [
            destination for _source, destination in [*archives, marker]
        ]
        temporary_names = [source for source, _destination in [*archives, marker]]
        journal_name = publisher._transaction_journal_name(marker[1])
        staging_pattern = publisher._transaction_journal_staging_pattern(marker[1])
        foreign_staging_name = f".{journal_name}.{'e' * 24}.partial"
        foreign_output_name = f".{marker[1]}.{'d' * 24}.partial"
        (bundle / foreign_staging_name).write_bytes(b"foreign journal-shaped file")
        (bundle / foreign_staging_name).chmod(0o444)
        (bundle / foreign_output_name).write_bytes(b"foreign output-shaped file")
        (bundle / foreign_output_name).chmod(0o444)
        original_write = publisher.os.write

        def die_mid_write(descriptor, value):
            original_write(descriptor, bytes(value[:17]))
            raise SyntheticPowerLoss("simulated power loss during journal write")

        with monkeypatch.context() as context:
            context.setattr(publisher.os, "write", die_mid_write)
            with pytest.raises(SyntheticPowerLoss, match="journal write"):
                publisher._create_bundle_journal(directory, archives, marker)

    assert not (bundle / journal_name).exists()
    staging_names = sorted(
        path.name for path in bundle.iterdir() if staging_pattern.fullmatch(path.name)
    )
    assert foreign_staging_name in staging_names
    orphan_staging_names = [
        name for name in staging_names if name != foreign_staging_name
    ]
    assert len(orphan_staging_names) == 1
    assert stat.S_IMODE((bundle / orphan_staging_names[0]).stat().st_mode) == 0o600
    assert all((bundle / name).exists() for name in temporary_names)
    assert all(
        stat.S_IMODE((bundle / name).stat().st_mode) == 0o444
        for name in temporary_names
    )
    assert all(not (bundle / name).exists() for name in expected_destinations)

    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        outcome = publisher._recover_bundle_transaction(
            directory,
            marker_destination=marker[1],
            expected_destinations=expected_destinations,
        )

    assert outcome == "none"
    assert all((bundle / name).exists() for name in staging_names)
    assert (bundle / foreign_output_name).read_bytes() == b"foreign output-shaped file"
    assert not (bundle / journal_name).exists()
    assert all((bundle / name).exists() for name in temporary_names)

    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        publisher._create_bundle_journal(directory, archives, marker)
        outcome = publisher._recover_bundle_transaction(
            directory,
            marker_destination=marker[1],
            expected_destinations=expected_destinations,
        )

    assert outcome == "rolled_back"
    assert all((bundle / name).exists() for name in staging_names)
    assert (bundle / foreign_output_name).read_bytes() == b"foreign output-shaped file"
    assert all(not (bundle / name).exists() for name in temporary_names)


def test_startup_recovery_reconciles_linked_journal_staging(tmp_path, monkeypatch):
    bundle = tmp_path / "crash-journal-link"
    bundle.mkdir(mode=0o700)
    bundle.chmod(0o700)

    class SyntheticPowerLoss(BaseException):
        pass

    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        archives, marker, _payloads = _seed_bundle_transaction(directory)
        expected_destinations = [
            destination for _source, destination in [*archives, marker]
        ]
        temporary_names = [source for source, _destination in [*archives, marker]]
        journal_name = publisher._transaction_journal_name(marker[1])
        staging_pattern = publisher._transaction_journal_staging_pattern(marker[1])
        foreign_staging_name = f".{journal_name}.{'f' * 24}.partial"
        (bundle / foreign_staging_name).write_bytes(b"foreign journal-shaped file")
        (bundle / foreign_staging_name).chmod(0o444)
        original_cleanup = publisher.SecureOutputDirectory.cleanup_if_same

        def die_before_staging_unlink(self, name, identity):
            if staging_pattern.fullmatch(name) and name != foreign_staging_name:
                raise SyntheticPowerLoss("simulated power loss after journal link")
            return original_cleanup(self, name, identity)

        with monkeypatch.context() as context:
            context.setattr(
                publisher.SecureOutputDirectory,
                "cleanup_if_same",
                die_before_staging_unlink,
            )
            with pytest.raises(SyntheticPowerLoss, match="after journal link"):
                publisher._create_bundle_journal(directory, archives, marker)

    journal_stat = (bundle / journal_name).stat()
    staging_names = sorted(
        path.name for path in bundle.iterdir() if staging_pattern.fullmatch(path.name)
    )
    matching_staging_names = [
        name
        for name in staging_names
        if (bundle / name).stat().st_ino == journal_stat.st_ino
        and (bundle / name).stat().st_dev == journal_stat.st_dev
    ]
    assert len(matching_staging_names) == 1
    staging_stat = (bundle / matching_staging_names[0]).stat()
    assert (journal_stat.st_dev, journal_stat.st_ino) == (
        staging_stat.st_dev,
        staging_stat.st_ino,
    )
    assert journal_stat.st_nlink == 2

    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        outcome = publisher._recover_bundle_transaction(
            directory,
            marker_destination=marker[1],
            expected_destinations=expected_destinations,
        )

    assert outcome == "rolled_back"
    assert not (bundle / matching_staging_names[0]).exists()
    assert (
        bundle / foreign_staging_name
    ).read_bytes() == b"foreign journal-shaped file"
    assert not (bundle / journal_name).exists()
    assert all(not (bundle / name).exists() for name in temporary_names)


def test_startup_recovery_after_sigkill_rolls_back_partial_bundle(tmp_path):
    bundle = tmp_path / "crash-partial"
    bundle.mkdir(mode=0o700)
    bundle.chmod(0o700)
    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        archives, marker, _payloads = _seed_bundle_transaction(directory)
        journal_name, _journal = publisher._create_bundle_journal(
            directory, archives, marker
        )
        directory.link(*archives[0])
        directory.fsync()
        temporary_names = [source for source, _destination in [*archives, marker]]
        expected_destinations = [
            destination for _source, destination in [*archives, marker]
        ]

    assert (bundle / journal_name).exists()
    assert (bundle / archives[0][1]).exists()
    assert not (bundle / archives[1][1]).exists()
    assert not (bundle / marker[1]).exists()

    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        outcome = publisher._recover_bundle_transaction(
            directory,
            marker_destination=marker[1],
            expected_destinations=expected_destinations,
        )

    assert outcome == "rolled_back"
    assert all(not (bundle / name).exists() for name in expected_destinations)
    assert all(not (bundle / name).exists() for name in temporary_names)
    assert not (bundle / journal_name).exists()


def test_startup_recovery_after_sigkill_retains_committed_bundle(tmp_path):
    bundle = tmp_path / "crash-committed"
    bundle.mkdir(mode=0o700)
    bundle.chmod(0o700)
    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        archives, marker, payloads = _seed_bundle_transaction(directory)
        journal_name, _journal = publisher._create_bundle_journal(
            directory, archives, marker
        )
        for source, destination in archives:
            directory.link(source, destination)
        directory.fsync()
        directory.link(*marker)
        directory.fsync()
        temporary_names = [source for source, _destination in [*archives, marker]]
        expected_destinations = [
            destination for _source, destination in [*archives, marker]
        ]

    assert (bundle / journal_name).exists()
    assert all((bundle / name).exists() for name in expected_destinations)

    with publisher.SecureOutputDirectory(
        bundle, private=True, label="synthetic crash bundle"
    ) as directory:
        outcome = publisher._recover_bundle_transaction(
            directory,
            marker_destination=marker[1],
            expected_destinations=expected_destinations,
        )

    assert outcome == "committed"
    for destination, payload in payloads.items():
        published = bundle / destination
        assert published.read_bytes() == payload
        assert stat.S_IMODE(published.stat().st_mode) == 0o444
    assert all(not (bundle / name).exists() for name in temporary_names)
    assert not (bundle / journal_name).exists()


def test_bundle_failure_before_marker_rolls_back_only_new_outputs(
    tmp_path, monkeypatch
):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    original_link = publisher.os.link

    def fail_r02(source, destination, *args, **kwargs):
        if Path(destination).name == archives[R02].name:
            raise OSError("synthetic r02 publication failure")
        return original_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(publisher.os, "link", fail_r02)
    with pytest.raises(publisher.PublicationError, match="publish|transaction"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert not any(path.exists() for path in archives.values())
    assert not draft.exists()


def test_attempts_root_symlink_component_is_rejected_before_resolution(
    tmp_path, monkeypatch
):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    alias = tmp_path / "attempts-alias"
    alias.symlink_to(attempts, target_is_directory=True)
    with pytest.raises(publisher.PublicationError, match="symlink path component"):
        publisher.build_archives(
            attempts_root=alias,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )


def test_finalize_rejects_extra_archive_member_before_remote_verification(
    tmp_path, monkeypatch
):
    (attempts, reduced, _, archives, uris, draft), _ = _build(tmp_path, monkeypatch)
    archive = archives[R01]
    _append_archive_member(
        archive,
        f"{publisher._archive_root(R01)}/unexpected.bin",
        b"unexpected\n",
    )
    draft.chmod(0o600)
    value = json.loads(draft.read_text())
    byte_count, digest = publisher._stream_file_identity(archive)
    value["attempts"][0]["archive"]["bytes"] = byte_count
    value["attempts"][0]["archive"]["sha256"] = digest
    draft.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    draft.chmod(0o444)

    def remote_must_not_run(*_args, **_kwargs):
        raise AssertionError(
            "remote verification ran before local archive verification"
        )

    monkeypatch.setattr(publisher, "_stream_remote_identity", remote_must_not_run)
    index = tmp_path / "index.json"
    with pytest.raises(publisher.PublicationError, match="extra member"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=index,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    assert not index.exists()


def test_remote_verifier_requests_identity_and_rejects_content_encoding(monkeypatch):
    value = b"archive bytes"
    observed_request = None
    durable_uri = _github_asset_uri("archive.tar.zst")

    class Response:
        status = 200
        headers = {
            "Content-Length": str(len(value)),
            "Content-Encoding": "gzip",
        }

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

        def geturl(self):
            return durable_uri

        def read(self, _size=-1):
            return value

    def open_request(request, *, timeout):
        nonlocal observed_request
        observed_request = request
        assert timeout == publisher.REMOTE_CONNECT_TIMEOUT_SECONDS
        return Response()

    monkeypatch.setattr(publisher, "_open_without_redirect", open_request)
    with pytest.raises(publisher.PublicationError, match="content encoding"):
        publisher._stream_remote_identity_direct(
            durable_uri,
            expected_bytes=len(value),
            expected_sha256=hashlib.sha256(value).hexdigest(),
        )
    assert observed_request is not None
    assert dict(observed_request.header_items())["Accept-encoding"] == "identity"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["attempt_ledger"][1].update(
                {"unexpected_posthoc_field": True}
            ),
            "unexpected attempt fields",
        ),
        (
            lambda value: value["primary_numeric"].update({"promoted": False}),
            "did not promote",
        ),
    ],
)
def test_reducer_submission_gate_rejects_posthoc_or_unpromoted_reports(
    tmp_path, monkeypatch, mutate, message
):
    attempts, reduced, _, _, _, _ = _make_fixture(tmp_path, monkeypatch)
    value = json.loads(reduced.read_text())
    mutate(value)
    reduced.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def fresh(_path, analysis_id):
        assert analysis_id == value["analysis_id"]
        result = copy.deepcopy(value)
        result["generated_at"] = "2026-08-31T12:03:00+00:00"
        return result

    monkeypatch.setattr(publisher.analyzer, "analyze_attempts_root", fresh)
    with pytest.raises(publisher.PublicationError, match=message):
        publisher._validate_reduced_result(attempts, reduced)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":NaN}',
        b'{"schema_version":Infinity}',
    ],
)
def test_strict_json_loader_rejects_duplicate_keys_and_nonfinite_numbers(tmp_path, raw):
    path = tmp_path / "invalid.json"
    path.write_bytes(raw)
    with pytest.raises(publisher.PublicationError, match="not readable JSON"):
        publisher._load_json(path, label="strict fixture")
    with pytest.raises(ValueError):
        publisher._canonical_json_bytes({"value": float("nan")})


def test_build_rechecks_reduced_json_before_publishing(tmp_path, monkeypatch):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    original = publisher._write_attempt_archive

    def mutate_after_r02(*args, **kwargs):
        result = original(*args, **kwargs)
        if kwargs["snapshot"].raw_attempt_id == R02:
            reduced.write_bytes(reduced.read_bytes() + b" ")
        return result

    monkeypatch.setattr(publisher, "_write_attempt_archive", mutate_after_r02)
    with pytest.raises(publisher.PublicationError, match="changed while building"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert not any(path.exists() for path in archives.values())
    assert not draft.exists()


def test_reduced_generated_at_must_be_timezone_aware(tmp_path, monkeypatch):
    attempts, reduced, _, _, _, _ = _make_fixture(tmp_path, monkeypatch)
    value = json.loads(reduced.read_text())
    value["generated_at"] = "2026-08-31T12:00:00"
    reduced.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    with pytest.raises(publisher.PublicationError, match="timezone-aware"):
        publisher._validate_reduced_result(attempts, reduced)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"publication_gate": "approved"}), "bound inputs"),
        (
            lambda value: value["attempts"][0].update({"unexpected": True}),
            "attempt binding",
        ),
        (lambda value: value.update({"created_utc": "2026-08-31"}), "timezone-aware"),
    ],
)
def test_finalize_rejects_nonexact_draft_shape(
    tmp_path, monkeypatch, mutation, message
):
    (attempts, reduced, _, _, uris, draft), _ = _build(tmp_path, monkeypatch)
    draft.chmod(0o600)
    value = json.loads(draft.read_text())
    mutation(value)
    draft.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    draft.chmod(0o444)
    with pytest.raises(publisher.PublicationError, match=message):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=tmp_path / "index.json",
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )


@pytest.mark.parametrize("mutation", ["decision", "tree"])
def test_external_privacy_authorization_is_exact_and_required(
    tmp_path, monkeypatch, mutation
):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    privacy = _privacy_receipt(draft)
    privacy.chmod(0o600)
    value = json.loads(privacy.read_text())
    if mutation == "decision":
        value["decision"] = "pending"
    else:
        value["attempts"][0]["tree_sha256"] = "f" * 64
    privacy.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    privacy.chmod(0o444)
    with pytest.raises(publisher.PublicationError, match="privacy review"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=privacy,
            **_github_coordinates(),
        )
    assert not any(path.exists() for path in archives.values())


def test_finalize_rejects_changed_privacy_authorization(tmp_path, monkeypatch):
    (attempts, reduced, _, _, uris, draft), _ = _build(tmp_path, monkeypatch)
    privacy = _privacy_receipt(draft)
    privacy.chmod(0o600)
    value = json.loads(privacy.read_text())
    value["reviewer"] = "different-reviewer"
    privacy.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    privacy.chmod(0o444)
    with pytest.raises(publisher.PublicationError, match="draft receipt|bound inputs"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=tmp_path / "index.json",
            privacy_review_receipt=privacy,
            **_github_coordinates(),
        )


@pytest.mark.parametrize("corruption", ["unexpected_pax", "malformed_pax"])
def test_finalize_rejects_noncanonical_or_malformed_pax_before_remote(
    tmp_path, monkeypatch, corruption
):
    (attempts, reduced, _, archives, uris, draft), _ = _build(tmp_path, monkeypatch)

    def mutate(member):
        if corruption == "unexpected_pax":
            member.pax_headers["comment"] = "not canonical"
        else:
            member.pax_headers["GNU.sparse.map"] = "not-an-int"

    _rewrite_archive(archives[R01], mutate_member=mutate)
    _refresh_draft_archive_receipt(draft, archives[R01], 0)

    def remote_must_not_run(*_args, **_kwargs):
        raise AssertionError("remote verification ran before rejecting PAX metadata")

    monkeypatch.setattr(publisher, "_stream_remote_identity", remote_must_not_run)
    message = "canonical|malformed"
    with pytest.raises(publisher.PublicationError, match=message):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=tmp_path / "index.json",
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )


def test_finalize_rejects_large_decompressed_suffix_without_hanging(
    tmp_path, monkeypatch
):
    (attempts, reduced, _, archives, uris, draft), _ = _build(tmp_path, monkeypatch)
    _rewrite_archive(archives[R01], decompressed_suffix=b"X" * (2 * 1024 * 1024))
    _refresh_draft_archive_receipt(draft, archives[R01], 0)
    started = time.monotonic()
    with pytest.raises(publisher.PublicationError, match="canonical tar stream size"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=tmp_path / "index.json",
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("exception_type", [KeyboardInterrupt, SystemExit])
def test_archive_verifier_always_kills_and_waits_on_baseexception(
    tmp_path, monkeypatch, exception_type
):
    (attempts, _, _, archives, _, _), built = _build(tmp_path, monkeypatch)
    snapshot = publisher._snapshot_ledger(attempts)[0]
    archive_value = built["attempts"][0]["archive"]
    root = publisher._archive_root(R01)
    manifest_bytes = _tar_members(archives[R01])[f"{root}/MANIFEST.json"]["data"]
    state = {"kill": 0, "wait": 0}

    class Process:
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def kill(self):
            state["kill"] += 1

        def wait(self):
            state["wait"] += 1
            return 0

    monkeypatch.setattr(
        publisher, "_zstd_identity", lambda _path: archive_value["compressor"]
    )
    monkeypatch.setattr(
        publisher.subprocess, "Popen", lambda *_args, **_kwargs: Process()
    )

    def interrupt(*_args, **_kwargs):
        raise exception_type("synthetic verifier interruption")

    monkeypatch.setattr(publisher.tarfile, "open", interrupt)
    with pytest.raises(exception_type, match="synthetic verifier interruption"):
        publisher._verify_attempt_archive(
            archives[R01],
            snapshot=snapshot,
            manifest_bytes=manifest_bytes,
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
            expected_compressor=archive_value["compressor"],
            expected_archive=archive_value,
        )
    assert state == {"kill": 1, "wait": 1}


class _FakeSocket:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class _FakeRaw:
    def __init__(self, socket):
        self._sock = socket


class _FakeFp:
    def __init__(self, socket):
        self.raw = _FakeRaw(socket)


def test_remote_verifier_accepts_safe_signed_redirect_without_recording_query(
    monkeypatch,
):
    payload = b"exact archive"
    socket = _FakeSocket()
    durable_uri = _github_asset_uri("archive.tar.zst")
    signed_url = (
        "https://release-assets.githubusercontent.com/archive-blob"
        "?expiring-secret=do-not-record"
    )

    class Response:
        def __init__(self, status, url, headers):
            self.status = status
            self.url = url
            self.headers = headers
            self.fp = _FakeFp(socket)
            self.returned = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

        def geturl(self):
            return self.url

        def read(self, _size=-1):
            raise AssertionError("bounded verifier must use read1")

        def read1(self, _size=-1):
            if self.returned:
                return b""
            self.returned = True
            self.fp = None
            return payload

    requests = []

    def open_hop(request, *, timeout):
        requests.append((request.full_url, timeout))
        if request.full_url == durable_uri:
            return Response(302, request.full_url, {"Location": signed_url})
        return Response(
            200,
            signed_url,
            {"Content-Length": str(len(payload))},
        )

    monkeypatch.setattr(publisher, "_open_without_redirect", open_hop)
    receipt = publisher._stream_remote_identity_direct(
        durable_uri,
        expected_bytes=len(payload),
        expected_sha256=hashlib.sha256(payload).hexdigest(),
    )
    assert receipt["final_host"] == "release-assets.githubusercontent.com"
    assert receipt["redirected"] is True
    assert receipt["redirect_count"] == 1
    assert receipt["redirect_chain"] == [
        {
            "http_status": 302,
            "from_host": "github.com",
            "to_host": "release-assets.githubusercontent.com",
        }
    ]
    assert "expiring-secret" not in json.dumps(receipt)
    assert socket.timeouts
    assert [item[0] for item in requests] == [
        durable_uri,
        signed_url,
    ]


def test_remote_verifier_rejects_intermediate_https_to_http_downgrade(monkeypatch):
    durable_uri = _github_asset_uri("archive.tar.zst")

    class Response:
        status = 302
        headers = {"Location": "http://unsafe.example/intermediate"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

        def geturl(self):
            return durable_uri

        def read1(self, _size=-1):
            raise AssertionError("unsafe final URL was read")

    calls = []

    def open_hop(request, *, timeout):
        calls.append((request.full_url, timeout))
        return Response()

    monkeypatch.setattr(publisher, "_open_without_redirect", open_hop)
    with pytest.raises(publisher.PublicationError, match="redirect hop is unsafe"):
        publisher._stream_remote_identity_direct(
            durable_uri,
            expected_bytes=0,
            expected_sha256=hashlib.sha256(b"").hexdigest(),
        )
    assert [item[0] for item in calls] == [durable_uri]


def test_remote_verifier_enforces_cumulative_deadline_across_redirects(monkeypatch):
    instants = iter([0.0, 1.0, 4.0, 6.0, 11.0])
    durable_uri = _github_asset_uri("archive.tar.zst")

    class Response:
        status = 302

        def __init__(self, url, next_url):
            self.url = url
            self.headers = {"Location": next_url}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

        def geturl(self):
            return self.url

    timeouts = []

    def open_hop(request, *, timeout):
        timeouts.append(timeout)
        return Response(
            request.full_url,
            "https://objects.githubusercontent.com/archive.tar.zst",
        )

    monkeypatch.setattr(publisher, "REMOTE_TOTAL_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(publisher.time, "monotonic", lambda: next(instants))
    monkeypatch.setattr(publisher, "_open_without_redirect", open_hop)
    with pytest.raises(publisher.PublicationError, match="exceeded total time"):
        publisher._stream_remote_identity_direct(
            durable_uri,
            expected_bytes=1,
            expected_sha256=hashlib.sha256(b"x").hexdigest(),
        )
    assert timeouts == [9.0, 4.0]


def test_hard_https_deadline_kills_worker_stuck_before_headers(monkeypatch):
    state = {"killed": False, "communicates": 0}

    class BlockingResolverWorker:
        args = ["synthetic-https-worker"]
        returncode = None

        def communicate(self, input=None, timeout=None):
            state["communicates"] += 1
            if not state["killed"]:
                assert input is not None
                assert 0 < timeout <= publisher.REMOTE_TOTAL_TIMEOUT_SECONDS
                raise subprocess.TimeoutExpired(self.args, timeout)
            self.returncode = -9
            return b"", b""

        def kill(self):
            state["killed"] = True

        def poll(self):
            return self.returncode

    observed = {}

    def popen(*args, **kwargs):
        observed.update(kwargs)
        return BlockingResolverWorker()

    monkeypatch.setattr(publisher.subprocess, "Popen", popen)
    with pytest.raises(publisher.PublicationError, match="hard total deadline"):
        publisher._run_https_worker(
            {
                "schema_version": 1,
                "operation": "download_identity",
                "uri": _github_asset_uri("archive.tar.zst"),
                "expected_bytes": 0,
                "expected_sha256": hashlib.sha256(b"").hexdigest(),
            }
        )
    assert state == {"killed": True, "communicates": 2}
    assert observed["env"] == {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(publisher.REPO_ROOT),
    }


def test_github_release_api_binds_release_and_asset_identity(monkeypatch):
    coordinates = publisher._github_release_coordinates(
        owner=GITHUB_OWNER,
        repository=GITHUB_REPOSITORY,
        tag=GITHUB_RELEASE_TAG,
    )
    payload = b"archive bytes"
    expected_assets = [
        {
            "name": "archive.tar.zst",
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    ]
    api_body = {
        "id": 987,
        "tag_name": GITHUB_RELEASE_TAG,
        "draft": False,
        "immutable": True,
        "assets": [
            {
                "id": 654,
                "name": "archive.tar.zst",
                "state": "uploaded",
                "size": len(payload),
                "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
                "browser_download_url": _github_asset_uri("archive.tar.zst"),
            }
        ],
    }
    body = json.dumps(api_body, separators=(",", ":")).encode()
    socket = _FakeSocket()
    endpoint = (
        f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPOSITORY}/"
        f"releases/tags/{GITHUB_RELEASE_TAG}"
    )

    class Response:
        status = 200
        headers = {"Content-Length": str(len(body))}

        def __init__(self):
            self.fp = _FakeFp(socket)
            self.returned = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

        def geturl(self):
            return endpoint

        def read1(self, _size=-1):
            if self.returned:
                return b""
            self.returned = True
            return body

    observed_request = None

    def open_request(request, *, timeout):
        nonlocal observed_request
        observed_request = request
        assert timeout <= publisher.REMOTE_CONNECT_TIMEOUT_SECONDS
        return Response()

    monkeypatch.setattr(publisher, "_open_without_redirect", open_request)
    value = publisher._github_release_metadata_direct(
        coordinates,
        expected_assets,
    )
    assert value["release"] == {
        "id": 987,
        "tag_name": GITHUB_RELEASE_TAG,
        "draft": False,
        "immutable_field_present": True,
        "immutable": True,
        "asset_count": 1,
    }
    assert value["assets"][0]["id"] == 654
    assert value["assets"][0]["digest"] == (
        f"sha256:{hashlib.sha256(payload).hexdigest()}"
    )
    assert value["api_response"]["sha256"] == hashlib.sha256(body).hexdigest()
    headers = dict(observed_request.header_items())
    assert headers["X-github-api-version"] == publisher.GITHUB_API_VERSION
    assert headers["Accept-encoding"] == "identity"
    assert socket.timeouts


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"immutable": False}), "publication-ready"),
        (
            lambda value: value["assets"][0].update({"digest": "sha256:" + "0" * 64}),
            "differs from local archive",
        ),
        (
            lambda value: value["assets"][0].update(
                {"browser_download_url": "https://github.com/other/release"}
            ),
            "differs from local archive",
        ),
    ],
)
def test_github_release_metadata_rejects_mutable_or_mismatched_assets(
    monkeypatch, mutation, message
):
    coordinates = publisher._github_release_coordinates(
        owner=GITHUB_OWNER,
        repository=GITHUB_REPOSITORY,
        tag=GITHUB_RELEASE_TAG,
    )
    expected = {"name": "archive.tar.zst", "bytes": 3, "sha256": "a" * 64}
    body = {
        "id": 1,
        "tag_name": GITHUB_RELEASE_TAG,
        "draft": False,
        "immutable": True,
        "assets": [
            {
                "id": 2,
                "name": expected["name"],
                "state": "uploaded",
                "size": expected["bytes"],
                "digest": f"sha256:{expected['sha256']}",
                "browser_download_url": _github_asset_uri(expected["name"]),
            }
        ],
    }
    mutation(body)
    monkeypatch.setattr(
        publisher,
        "_fetch_github_api_json_direct",
        lambda _coordinates: (
            body,
            {
                "api_version": publisher.GITHUB_API_VERSION,
                "endpoint_host": "api.github.com",
                "endpoint_path": (
                    f"/repos/{GITHUB_OWNER}/{GITHUB_REPOSITORY}/releases/tags/"
                    f"{GITHUB_RELEASE_TAG}"
                ),
                "http_status": 200,
                "content_encoding": None,
                "response_content_length": 2,
                "bytes": 2,
                "sha256": hashlib.sha256(b"{}").hexdigest(),
            },
        ),
    )
    with pytest.raises(publisher.PublicationError, match=message):
        publisher._github_release_metadata_direct(coordinates, [expected])


def test_remote_verifier_rejects_unapproved_https_redirect_host(monkeypatch):
    durable_uri = _github_asset_uri("archive.tar.zst")

    class Response:
        status = 302
        headers = {"Location": "https://unapproved.example/archive.tar.zst"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def getcode(self):
            return self.status

        def geturl(self):
            return durable_uri

    monkeypatch.setattr(
        publisher,
        "_open_without_redirect",
        lambda _request, *, timeout: Response(),
    )
    with pytest.raises(publisher.PublicationError, match="host is not approved"):
        publisher._stream_remote_identity_direct(
            durable_uri,
            expected_bytes=0,
            expected_sha256=hashlib.sha256(b"").hexdigest(),
        )


def test_bundle_rolls_back_on_baseexception(tmp_path, monkeypatch):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    original = publisher.SecureOutputDirectory.link

    def interrupt_r02(self, source, destination):
        if destination == archives[R02].name:
            raise KeyboardInterrupt("synthetic interruption")
        return original(self, source, destination)

    monkeypatch.setattr(publisher.SecureOutputDirectory, "link", interrupt_r02)
    with pytest.raises(KeyboardInterrupt, match="synthetic interruption"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert not any(path.exists() for path in archives.values())
    assert not draft.exists()
    assert not list(draft.parent.glob("*.partial"))


def test_rollback_never_unlinks_foreign_destination(tmp_path, monkeypatch):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    original = publisher.SecureOutputDirectory.link
    foreign = b"foreign concurrent output\n"

    def collide_r02(self, source, destination):
        if destination == archives[R02].name:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=self.fd,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(foreign)
            raise KeyboardInterrupt("synthetic post-collision interruption")
        return original(self, source, destination)

    monkeypatch.setattr(publisher.SecureOutputDirectory, "link", collide_r02)
    with pytest.raises(KeyboardInterrupt):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert not archives[R01].exists()
    assert archives[R02].read_bytes() == foreign
    assert not draft.exists()


def test_archive_post_link_stat_interrupt_rolls_back_candidate(tmp_path, monkeypatch):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    original = publisher.SecureOutputDirectory.stat

    def interrupt_after_link(self, path_or_name):
        if (
            self.label == "archive bundle directory"
            and str(path_or_name) == archives[R01].name
        ):
            raise KeyboardInterrupt("post-link archive stat interrupted")
        return original(self, path_or_name)

    monkeypatch.setattr(publisher.SecureOutputDirectory, "stat", interrupt_after_link)
    with pytest.raises(KeyboardInterrupt, match="post-link archive stat"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert not any(path.exists() for path in archives.values())
    assert not draft.exists()


def test_marker_post_link_stat_interrupt_preserves_durable_committed_bundle(
    tmp_path, monkeypatch
):
    attempts, reduced, _, archives, uris, draft = _make_fixture(tmp_path, monkeypatch)
    original = publisher.SecureOutputDirectory.stat
    interrupted = False

    def interrupt_after_marker(self, path_or_name):
        nonlocal interrupted
        if (
            self.label == "archive bundle directory"
            and str(path_or_name) == draft.name
            and not interrupted
        ):
            interrupted = True
            raise KeyboardInterrupt("post-link marker stat interrupted")
        return original(self, path_or_name)

    monkeypatch.setattr(publisher.SecureOutputDirectory, "stat", interrupt_after_marker)
    with pytest.raises(KeyboardInterrupt, match="post-link marker stat"):
        publisher.build_archives(
            attempts_root=attempts,
            reduced_json=reduced,
            archive_outputs=archives,
            durable_uris=uris,
            draft_receipt_output=draft,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
            zstd_executable=Path(shutil.which("zstd") or "/missing/zstd"),
        )
    assert all(path.exists() for path in archives.values())
    assert draft.exists()
    assert stat.S_IMODE(draft.stat().st_mode) == 0o444


def test_index_post_link_stat_baseexception_cannot_leave_untracked_link(
    tmp_path, monkeypatch
):
    (attempts, reduced, _, _, uris, draft), _ = _build(tmp_path, monkeypatch)
    index_parent = tmp_path / "index-output"
    index_parent.mkdir()
    index = index_parent / "index.json"
    original = publisher.SecureOutputDirectory.stat

    class SyntheticBaseException(BaseException):
        pass

    interrupted = False

    def interrupt_after_index(self, path_or_name):
        nonlocal interrupted
        if (
            self.label == "publication index directory"
            and str(path_or_name) == index.name
            and not interrupted
        ):
            interrupted = True
            raise SyntheticBaseException("post-link index stat interrupted")
        return original(self, path_or_name)

    def verify(_uri, *, expected_bytes, expected_sha256):
        return {
            "bytes": expected_bytes,
            "sha256": expected_sha256,
            "exact_match": True,
        }

    monkeypatch.setattr(publisher.SecureOutputDirectory, "stat", interrupt_after_index)
    monkeypatch.setattr(publisher, "_stream_remote_identity", verify)
    with pytest.raises(publisher.PublicationError, match="output transaction"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=index,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    assert index.exists()
    assert stat.S_IMODE(index.stat().st_mode) == 0o444


@pytest.mark.parametrize("violation", ["nonprivate", "archive_elsewhere"])
def test_finalize_requires_one_external_owner_private_bundle(
    tmp_path, monkeypatch, violation
):
    (attempts, reduced, _, archives, uris, draft), _ = _build(tmp_path, monkeypatch)
    if violation == "nonprivate":
        draft.parent.chmod(0o755)
    else:
        other = tmp_path / "other-private"
        other.mkdir(mode=0o700)
        moved = other / archives[R01].name
        archives[R01].rename(moved)
        draft.chmod(0o600)
        value = json.loads(draft.read_text())
        value["attempts"][0]["archive"]["local_path"] = str(moved)
        draft.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        draft.chmod(0o444)
    with pytest.raises(publisher.PublicationError, match="bundle|mode 0700"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=tmp_path / "index.json",
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )


def test_index_parent_symlink_swap_cannot_redirect_into_attempt_tree(
    tmp_path, monkeypatch
):
    (attempts, reduced, _, _, uris, draft), _ = _build(tmp_path, monkeypatch)
    index_parent = tmp_path / "index-parent"
    index_parent.mkdir()
    index = index_parent / "index.json"
    moved_parent = tmp_path / "index-parent-pinned"
    attack_target = attempts / R02 / "runtime"
    original = publisher.SecureOutputDirectory.create_temporary
    swapped = False

    def swap_before_temp(self, destination_name):
        nonlocal swapped
        if self.label == "publication index directory" and not swapped:
            swapped = True
            index_parent.rename(moved_parent)
            index_parent.symlink_to(attack_target, target_is_directory=True)
        return original(self, destination_name)

    def verify(_uri, *, expected_bytes, expected_sha256):
        return {
            "bytes": expected_bytes,
            "sha256": expected_sha256,
            "exact_match": True,
        }

    monkeypatch.setattr(
        publisher.SecureOutputDirectory, "create_temporary", swap_before_temp
    )
    monkeypatch.setattr(publisher, "_stream_remote_identity", verify)
    with pytest.raises(publisher.PublicationError, match="path binding"):
        publisher.finalize_publication(
            attempts_root=attempts,
            reduced_json=reduced,
            draft_receipt=draft,
            durable_uris=uris,
            index_output=index,
            privacy_review_receipt=_privacy_receipt(draft),
            **_github_coordinates(),
        )
    assert swapped is True
    assert not (attack_target / "index.json").exists()
    assert not index.exists()
