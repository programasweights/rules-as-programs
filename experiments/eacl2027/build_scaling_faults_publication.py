#!/usr/bin/env python3
"""Build and remotely verify amendment-007 formal-attempt archives."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Mapping, Sequence
from urllib.parse import quote, unquote, urljoin, urlsplit

from experiments.eacl2027 import analyze_scaling_faults as analyzer
from experiments.eacl2027 import scaling_faults_attempts as attempts_contract


REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLICATION_VERSION = "protocol-v3-amendment-007-publication-v1"
PRIVACY_REVIEW_KIND = "external_exact_tree_privacy_review"
PRIVACY_REVIEW_SCOPE = "public release of complete unredacted raw attempt archives"
EXPECTED_ATTEMPT_IDS = (
    "formal-v3-20260831t051023z-r01",
    "formal-v3-20260831t051023z-r02",
)
MAX_TREE_ENTRIES = 250_000
MAX_TREE_REGULAR_BYTES = 8 * 1024**3
REMOTE_CONNECT_TIMEOUT_SECONDS = 30.0
REMOTE_READ_TIMEOUT_SECONDS = 30.0
REMOTE_TOTAL_TIMEOUT_SECONDS = 300.0
REMOTE_MAX_REDIRECTS = 10
GITHUB_API_VERSION = "2022-11-28"
GITHUB_NAME_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})")
GITHUB_TAG_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,254})")
GITHUB_DOWNLOAD_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
R01_TREE_ANCHOR = {
    "entries_excluding_root": 34_670,
    "regular_file_count": 16_744,
    "regular_file_bytes": 56_010_761,
    "sha256": "2b9b5751750dbaf7146b43d88ae5612e54e9b9ea057a4df65c5b037fb9344c95",
}
R01_CLAIM_ANCHOR = {
    "bytes": 310_922,
    "sha256": "9c1352dcea9b76e0c1adb2d64f606710ae6563c1f0ebe0a559529136804995e1",
}
_BASE_LEDGER_FIELDS = {
    "raw_attempt_id",
    "created_utc",
    "candidate_eligible",
    "status",
    "input_sha256",
    "analysis_binding_sha256",
    "validation_error",
    "attempt_id_valid",
    "chain_prefix",
    "raw_attempt_ordinal",
    "launch_order_valid",
    "launch_order_key",
    "rerun_eligible_status",
    "replacement_authorized_by_successor",
}
_R01_LEDGER_FIELDS = _BASE_LEDGER_FIELDS | {
    "adjudicated_status",
    "raw_status_preserved",
    "numeric_aggregate_excluded",
}
_R02_LEDGER_FIELDS = _BASE_LEDGER_FIELDS | {
    "replacement_validation_error",
    "validated_replacement_binding",
}
_SENSITIVE_PATTERNS = (
    (
        "private_key_pem",
        rb"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) PRIVATE KEY|"
        rb"PGP PRIVATE KEY BLOCK|PRIVATE KEY)-----",
    ),
    (
        "github_token",
        rb"(?:gh[pousr]_[A-Za-z0-9]{32,255}|github_pat_[A-Za-z0-9_]{40,255})",
    ),
    ("aws_access_key", rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    ("slack_token", rb"xox[baprs]-[A-Za-z0-9-]{20,255}"),
    ("huggingface_token", rb"hf_[A-Za-z0-9]{30,255}"),
    ("openai_token", rb"sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255}"),
    ("anthropic_token", rb"sk-ant-[A-Za-z0-9_-]{20,255}"),
    ("google_api_key", rb"AIza[0-9A-Za-z_-]{35}"),
    ("stripe_live_secret", rb"sk_live_[0-9A-Za-z]{16,255}"),
    (
        "jwt",
        rb"eyJ[A-Za-z0-9_-]{16,1024}\.[A-Za-z0-9_-]{16,1024}\."
        rb"[A-Za-z0-9_-]{16,1024}",
    ),
    (
        "authorization_credential",
        rb"(?i)(?:authorization\s*:\s*(?:bearer|basic)|proxy-authorization\s*:)[ \t]+[^\s]{8,2048}",
    ),
    (
        "assigned_secret",
        rb"(?i)['\"]?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
        rb"secret[_-]?access[_-]?key|password|passwd)['\"]?[ \t]{0,8}(?::|=)"
        rb"[ \t]{0,8}['\"]?(?!(?:null|none|false|true|missing|absent|unset|redacted|"
        rb"<redacted>|\*{3}|example|dummy|placeholder)(?:['\"\s,}\]]|$))"
        rb"[A-Za-z0-9_./+=:@-]{12,512}",
    ),
    (
        "credential_url",
        rb"[A-Za-z][A-Za-z0-9+.-]{1,15}://[^/@\s:]{1,128}:[^/@\s]{1,256}@",
    ),
)
_SENSITIVE_PATH_BASENAMES = (
    ".env",
    ".git-credentials",
    ".netrc",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
)
SENSITIVE_SCAN_CONFIG = {
    "schema_version": 1,
    "detector_version": "eacl2027-public-archive-sensitive-scan-v1",
    "chunk_bytes": 1024 * 1024,
    "overlap_bytes": 4096,
    "maximum_pattern_span_bytes": 3077,
    "scope": "high-confidence credentials; not a general PII or manual privacy review",
    "match_policy": "any match blocks archival; raw matching bytes are never retained",
    "sensitive_path_basenames": list(_SENSITIVE_PATH_BASENAMES),
    "detectors": [
        {
            "id": detector_id,
            "pattern": pattern.decode("ascii"),
            "pattern_sha256": hashlib.sha256(pattern).hexdigest(),
        }
        for detector_id, pattern in _SENSITIVE_PATTERNS
    ],
}
SENSITIVE_SCAN_CONFIG_SHA256 = hashlib.sha256(
    json.dumps(
        SENSITIVE_SCAN_CONFIG,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
).hexdigest()
_COMPILED_SENSITIVE_PATTERNS = tuple(
    (detector_id, re.compile(pattern)) for detector_id, pattern in _SENSITIVE_PATTERNS
)


class PublicationError(RuntimeError):
    """A post-run archive or publication invariant failed."""


@dataclass(frozen=True)
class AttemptSnapshot:
    raw_attempt_id: str
    root: Path
    tree: tuple[dict[str, Any], ...]
    tree_sha256: str
    regular_file_count: int
    regular_file_bytes: int
    publication: dict[str, Any]
    claim_path: Path | None
    claim_receipt: dict[str, Any] | None


class _HashingReader:
    def __init__(self, handle: BinaryIO):
        self._handle = handle
        self.bytes_read = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        value = self._handle.read(size)
        self.bytes_read += len(value)
        self.digest.update(value)
        return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _render_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _stream_file_identity(path: Path) -> tuple[int, str]:
    try:
        return analyzer._stream_file_identity(path)
    except analyzer.AnalysisValidationError as exc:
        raise PublicationError(str(exc)) from exc


def _file_receipt(path: Path, *, logical_path: str | None = None) -> dict[str, Any]:
    byte_count, digest = _stream_file_identity(path)
    return {
        "path": logical_path if logical_path is not None else path.name,
        "bytes": byte_count,
        "sha256": digest,
    }


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _logical_path(path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def _reject_symlink_components(path: Path, *, label: str) -> None:
    try:
        attempts_contract._reject_symlink_components(path, label=label)
    except attempts_contract.SystemsHarnessError as exc:
        raise PublicationError(str(exc)) from exc


def _require_regular(path: Path, *, label: str) -> Path:
    _reject_symlink_components(path, label=label)
    if path.is_symlink() or not path.is_file():
        raise PublicationError(f"{label} must be a regular non-symlink file: {path}")
    return path.resolve(strict=True)


def _require_private_directory(path: Path, *, label: str, owner_uid: int) -> None:
    _reject_symlink_components(path, label=label)
    if path.is_symlink() or not path.is_dir():
        raise PublicationError(f"{label} must be a regular directory: {path}")
    observed = path.stat(follow_symlinks=False)
    if observed.st_uid != owner_uid or stat.S_IMODE(observed.st_mode) != 0o700:
        raise PublicationError(
            f"{label} must have the ledger owner and mode 0700: {path}"
        )


def _require_new_output(
    path: Path,
    *,
    suffix: str,
    label: str,
    defer_absence_to_transaction_recovery: bool = False,
) -> Path:
    output = path.expanduser().absolute()
    if not output.name.endswith(suffix):
        raise PublicationError(f"{label} must end in {suffix}: {output}")
    _reject_symlink_components(output.parent, label=f"{label} parent")
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise PublicationError(f"{label} parent must already be a directory")
    if not defer_absence_to_transaction_recovery and (
        output.exists() or output.is_symlink()
    ):
        raise PublicationError(f"refusing to replace immutable {label}: {output}")
    return output


def _require_outside_repo(path: Path, *, label: str) -> None:
    try:
        path.resolve(strict=False).relative_to(REPO_ROOT)
    except ValueError:
        return
    raise PublicationError(f"{label} must remain outside Git")


def _validate_durable_uri(uri: str, archive_name: str) -> str:
    parsed = urlsplit(uri)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise PublicationError(
            "durable URI must be a credential-free HTTPS URL without query or fragment"
        )
    if unquote(Path(parsed.path).name) != archive_name:
        raise PublicationError("durable URI basename must equal the archive filename")
    return uri


def _github_release_coordinates(
    *, owner: str, repository: str, tag: str
) -> dict[str, Any]:
    if (
        GITHUB_NAME_PATTERN.fullmatch(owner) is None
        or GITHUB_NAME_PATTERN.fullmatch(repository) is None
        or not isinstance(tag, str)
        or GITHUB_TAG_PATTERN.fullmatch(tag) is None
    ):
        raise PublicationError("GitHub release owner, repository, or tag is invalid")
    return {
        "provider": "github_release",
        "owner": owner,
        "repository": repository,
        "tag": tag,
        "api_version": GITHUB_API_VERSION,
    }


def _canonical_github_asset_uri(coordinates: Mapping[str, Any], asset_name: str) -> str:
    return (
        f"https://github.com/{coordinates['owner']}/{coordinates['repository']}"
        f"/releases/download/{quote(str(coordinates['tag']), safe='')}"
        f"/{quote(asset_name, safe='')}"
    )


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _read_stable_file(
    path: Path, *, label: str, logical_path: str | None = None
) -> tuple[bytes, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicationError(f"{label} could not be opened securely: {path}") from exc
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    byte_count = 0
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise PublicationError(f"{label} must be a regular file: {path}")
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            chunks.append(chunk)
            digest.update(chunk)
            byte_count += len(chunk)
        closed_over = os.fstat(handle.fileno())
    try:
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise PublicationError(f"{label} changed while it was read: {path}") from exc
    if (
        _stat_identity(opened) != _stat_identity(closed_over)
        or _stat_identity(opened) != _stat_identity(current)
        or byte_count != opened.st_size
    ):
        raise PublicationError(f"{label} changed while it was read: {path}")
    return b"".join(chunks), {
        "path": logical_path if logical_path is not None else path.name,
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
    }


def _load_json_with_receipt(
    path: Path, *, label: str, logical_path: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw, receipt = _read_stable_file(path, label=label, logical_path=logical_path)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PublicationError(f"{label} is not readable JSON: {path}") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"{label} must contain a JSON object")
    return value, receipt


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    return _load_json_with_receipt(path, label=label)[0]


def _validate_aware_timestamp(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PublicationError(f"{label} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PublicationError(
            f"{label} must be a timezone-aware ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PublicationError(f"{label} must be a timezone-aware ISO-8601 timestamp")
    return value


def _without_generated_at(value: Mapping[str, Any]) -> dict[str, Any]:
    comparable = dict(value)
    comparable.pop("generated_at", None)
    return comparable


def _validate_reduced_result(
    attempts_root: Path, reduced_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    reduced, reduced_receipt = _load_json_with_receipt(
        reduced_path,
        label="reduced systems result",
        logical_path=_logical_path(reduced_path),
    )
    expected_top_level = {
        "schema_version",
        "analysis_id",
        "generated_at",
        "analysis_binding",
        "analysis_binding_sha256",
        "attempt_ledger",
        "primary_numeric",
        "endpoints",
        "sensitivity_endpoints",
    }
    if set(reduced) != expected_top_level or reduced.get("schema_version") != 1:
        raise PublicationError("reduced systems result has an unexpected schema")
    _validate_aware_timestamp(
        reduced.get("generated_at"), label="reduced systems generated_at"
    )
    analysis_id = reduced.get("analysis_id")
    if (
        not isinstance(analysis_id, str)
        or analyzer.ANALYSIS_ID_PATTERN.fullmatch(analysis_id) is None
    ):
        raise PublicationError("reduced systems result has an invalid analysis_id")
    try:
        fresh = analyzer.analyze_attempts_root(attempts_root, analysis_id)
    except analyzer.AnalysisValidationError as exc:
        raise PublicationError(f"fresh attempt-ledger reduction failed: {exc}") from exc
    if _without_generated_at(reduced) != _without_generated_at(fresh):
        raise PublicationError(
            "reduced systems result differs from a fresh amendment-007 reduction"
        )
    _validate_aware_timestamp(
        fresh.get("generated_at"), label="fresh reduction generated_at"
    )
    ledger = fresh.get("attempt_ledger")
    ids = [
        item.get("raw_attempt_id") if isinstance(item, dict) else None
        for item in ledger or []
    ]
    if ids != list(EXPECTED_ATTEMPT_IDS):
        raise PublicationError("publication requires exactly the amendment-007 r01/r02")
    binding = fresh.get("analysis_binding")
    if (
        not isinstance(binding, dict)
        or binding.get("chain_error") is not None
        or binding.get("analysis_version") != analyzer.ANALYSIS_VERSION
    ):
        raise PublicationError("attempt ledger has an invalid replacement chain")
    if not isinstance(ledger, list):
        raise PublicationError("attempt ledger is not a list")
    r01, r02 = ledger
    if set(r01) != _R01_LEDGER_FIELDS or set(r02) != _R02_LEDGER_FIELDS:
        raise PublicationError("attempt ledger has unexpected attempt fields")
    if (
        r01.get("validation_error") is not None
        or r02.get("validation_error") is not None
        or r01.get("launch_order_valid") is not True
        or r02.get("launch_order_valid") is not True
        or r01.get("status") != "completed_with_system_violations"
        or r01.get("raw_status_preserved") != "completed_with_system_violations"
        or r01.get("candidate_eligible") is not False
        or r01.get("numeric_aggregate_excluded") is not True
        or r01.get("replacement_authorized_by_successor") is not True
        or r01.get("adjudicated_status") != "superseded_premeasurement_harness_error"
        or r02.get("status") not in {"completed", "completed_with_system_violations"}
        or r02.get("candidate_eligible") is not True
        or r02.get("replacement_validation_error") is not None
    ):
        raise PublicationError("attempt ledger is not submission-ready")
    primary = fresh.get("primary_numeric")
    if (
        not isinstance(primary, dict)
        or primary.get("promoted") is not True
        or primary.get("selected_raw_attempt_id") != EXPECTED_ATTEMPT_IDS[1]
        or primary.get("selection_blocked_by") is not None
        or fresh.get("endpoints") is None
        or fresh.get("sensitivity_endpoints") != {}
    ):
        raise PublicationError("reducer did not promote the exact complete r02 result")
    return reduced, fresh, reduced_receipt


def _snapshot_attempt(root: Path, owner_uid: int) -> AttemptSnapshot:
    _require_private_directory(root, label=f"attempt {root.name}", owner_uid=owner_uid)
    try:
        publication = analyzer._validate_publication(root)
        tree_value = attempts_contract._predecessor_tree_receipts(root)
    except (
        analyzer.AnalysisValidationError,
        attempts_contract.SystemsHarnessError,
    ) as exc:
        raise PublicationError(f"could not inventory {root.name}: {exc}") from exc
    tree = tuple(tree_value)
    if len(tree) > MAX_TREE_ENTRIES:
        raise PublicationError(f"attempt tree exceeds {MAX_TREE_ENTRIES} entries")
    special = next(
        (
            item
            for item in tree
            if item.get("type") not in {"directory", "regular_file"}
        ),
        None,
    )
    if special is not None:
        raise PublicationError(
            "attempt archive forbids post-run special entry: "
            f"{special.get('relative_path')}"
        )
    unsafe_mode = next(
        (item for item in tree if int(item.get("mode", 0)) & 0o7000), None
    )
    if unsafe_mode is not None:
        raise PublicationError(
            "attempt archive forbids setuid, setgid, or sticky source modes: "
            f"{unsafe_mode.get('relative_path')}"
        )
    regular = [item for item in tree if item.get("type") == "regular_file"]
    regular_bytes = sum(int(item["bytes"]) for item in regular)
    if regular_bytes > MAX_TREE_REGULAR_BYTES:
        raise PublicationError(
            f"attempt tree exceeds {MAX_TREE_REGULAR_BYTES} regular-file bytes"
        )
    claim_value = publication.get("claim")
    claim_path: Path | None = None
    claim_receipt: dict[str, Any] | None = None
    if claim_value is not None:
        if not isinstance(claim_value, dict):
            raise PublicationError(f"{root.name} publication claim is malformed")
        claim_path = _require_regular(
            Path(str(claim_value.get("path", ""))),
            label=f"{root.name} publication claim",
        )
        claim_receipt = {
            "bytes": claim_value.get("bytes"),
            "sha256": claim_value.get("sha256"),
        }
        if (
            type(claim_receipt["bytes"]) is not int
            or not isinstance(claim_receipt["sha256"], str)
            or SHA256_PATTERN.fullmatch(claim_receipt["sha256"]) is None
        ):
            raise PublicationError(f"{root.name} publication claim receipt is invalid")
        if stat.S_IMODE(claim_path.stat(follow_symlinks=False).st_mode) & 0o7000:
            raise PublicationError("publication claim has an unsafe special mode")
    return AttemptSnapshot(
        raw_attempt_id=root.name,
        root=root,
        tree=tree,
        tree_sha256=hashlib.sha256(_canonical_json_bytes(tree)).hexdigest(),
        regular_file_count=len(regular),
        regular_file_bytes=regular_bytes,
        publication=publication,
        claim_path=claim_path,
        claim_receipt=claim_receipt,
    )


def _snapshot_ledger(attempts_root: Path) -> tuple[AttemptSnapshot, ...]:
    expanded = attempts_root.expanduser().absolute()
    _reject_symlink_components(expanded, label="attempts root")
    if expanded.is_symlink() or not expanded.is_dir():
        raise PublicationError("attempts root must be a regular directory")
    root = expanded.resolve(strict=True)
    _require_outside_repo(root, label="raw attempt ledger")
    owner_uid = root.stat(follow_symlinks=False).st_uid
    _require_private_directory(root, label="attempts root", owner_uid=owner_uid)
    children = sorted(root.iterdir(), key=lambda item: item.name)
    if [item.name for item in children] != list(EXPECTED_ATTEMPT_IDS):
        raise PublicationError("attempts root must contain exactly r01 and r02")
    snapshots = tuple(_snapshot_attempt(item, owner_uid) for item in children)
    claims_root = analyzer._expected_publication_claim_path(children[0]).parent
    _require_private_directory(
        claims_root, label="publication claims root", owner_uid=owner_uid
    )
    expected_claims = {
        snapshot.claim_path for snapshot in snapshots if snapshot.claim_path is not None
    }
    if set(claims_root.iterdir()) != expected_claims:
        raise PublicationError("claims ledger contains a missing or unindexed claim")
    r01 = snapshots[0]
    observed_anchor = {
        "entries_excluding_root": len(r01.tree),
        "regular_file_count": r01.regular_file_count,
        "regular_file_bytes": r01.regular_file_bytes,
        "sha256": r01.tree_sha256,
    }
    if observed_anchor != R01_TREE_ANCHOR:
        raise PublicationError("r01 tree differs from the frozen amendment-007 anchor")
    if r01.claim_receipt != R01_CLAIM_ANCHOR:
        raise PublicationError("r01 claim differs from the frozen amendment-007 anchor")
    return snapshots


def _validated_attempts_root(path: Path) -> Path:
    lexical = path.expanduser().absolute()
    _reject_symlink_components(lexical, label="attempts root")
    if lexical.is_symlink() or not lexical.is_dir():
        raise PublicationError("attempts root must be a regular directory")
    return lexical.resolve(strict=True)


def _scan_regular_file(
    path: Path,
    *,
    label: str,
    expected_mode: int,
    expected_bytes: int,
    expected_sha256: str,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicationError(
            f"sensitive-data scanner could not open {label}"
        ) from exc
    digest = hashlib.sha256()
    byte_count = 0
    tail = b""
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or expected_mode & 0o7000
            or opened.st_size != expected_bytes
        ):
            raise PublicationError(
                f"sensitive-data scan input metadata changed: {label}"
            )
        while True:
            chunk = handle.read(int(SENSITIVE_SCAN_CONFIG["chunk_bytes"]))
            if not chunk:
                break
            window = tail + chunk
            window_start = byte_count - len(tail)
            _scan_bytes_for_sensitive(window, label=label, base_offset=window_start)
            digest.update(chunk)
            byte_count += len(chunk)
            tail = window[-int(SENSITIVE_SCAN_CONFIG["overlap_bytes"]) :]
        closed_over = os.fstat(handle.fileno())
    if (
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (
            closed_over.st_dev,
            closed_over.st_ino,
            closed_over.st_size,
            closed_over.st_mtime_ns,
        )
        or byte_count != expected_bytes
        or digest.hexdigest() != expected_sha256
    ):
        raise PublicationError(f"sensitive-data scan input changed: {label}")


def _scan_bytes_for_sensitive(
    value: bytes, *, label: str, base_offset: int = 0
) -> None:
    for detector_id, detector in _COMPILED_SENSITIVE_PATTERNS:
        match = detector.search(value)
        if match is not None:
            raise PublicationError(
                "sensitive-data prescan blocked public archival: "
                f"detector={detector_id} path={label} "
                f"byte_offset={base_offset + match.start()}"
            )


def _scan_snapshot(snapshot: AttemptSnapshot) -> dict[str, Any]:
    tree_files_scanned = 0
    tree_bytes_scanned = 0
    paths_scanned = 0
    path_bytes_scanned = 0
    for entry in snapshot.tree:
        relative = str(entry["relative_path"])
        relative_bytes = relative.encode("utf-8")
        if any(
            part in _SENSITIVE_PATH_BASENAMES for part in PurePosixPath(relative).parts
        ):
            raise PublicationError(
                "sensitive-data prescan blocked public archival: "
                f"detector=sensitive_path_basename path={snapshot.raw_attempt_id}/{relative}"
            )
        _scan_bytes_for_sensitive(
            relative_bytes, label=f"archive-path/{snapshot.raw_attempt_id}/{relative}"
        )
        paths_scanned += 1
        path_bytes_scanned += len(relative_bytes)
        if entry["type"] != "regular_file":
            continue
        _scan_regular_file(
            snapshot.root / relative,
            label=f"{snapshot.raw_attempt_id}/{relative}",
            expected_mode=int(entry["mode"]),
            expected_bytes=int(entry["bytes"]),
            expected_sha256=str(entry["sha256"]),
        )
        tree_files_scanned += 1
        tree_bytes_scanned += int(entry["bytes"])
    claim_scanned = snapshot.claim_path is not None
    if snapshot.claim_path is not None and snapshot.claim_receipt is not None:
        claim_mode = stat.S_IMODE(
            snapshot.claim_path.stat(follow_symlinks=False).st_mode
        )
        _scan_regular_file(
            snapshot.claim_path,
            label=f"publication-claim/{snapshot.raw_attempt_id}.launch.json",
            expected_mode=claim_mode,
            expected_bytes=int(snapshot.claim_receipt["bytes"]),
            expected_sha256=str(snapshot.claim_receipt["sha256"]),
        )
    core = {
        "schema_version": 1,
        "status": "passed",
        "detector_config": SENSITIVE_SCAN_CONFIG,
        "detector_config_sha256": SENSITIVE_SCAN_CONFIG_SHA256,
        "source_tree_sha256": snapshot.tree_sha256,
        "tree_regular_files_scanned": tree_files_scanned,
        "tree_regular_bytes_scanned": tree_bytes_scanned,
        "entry_paths_scanned": paths_scanned,
        "entry_path_bytes_scanned": path_bytes_scanned,
        "claim": {
            "scanned": claim_scanned,
            "bytes": (
                int(snapshot.claim_receipt["bytes"])
                if snapshot.claim_receipt is not None
                else 0
            ),
        },
        "match_count": 0,
        "scan_error_count": 0,
        "matching_bytes_retained": False,
        "raw_evidence_redacted": False,
    }
    return {
        **core,
        "result_sha256": hashlib.sha256(_canonical_json_bytes(core)).hexdigest(),
    }


def _scan_ledger(
    snapshots: Sequence[AttemptSnapshot],
) -> dict[str, dict[str, Any]]:
    return {snapshot.raw_attempt_id: _scan_snapshot(snapshot) for snapshot in snapshots}


def _privacy_attempt_binding(
    snapshot: AttemptSnapshot, sensitive_scan: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "raw_attempt_id": snapshot.raw_attempt_id,
        "tree_sha256": snapshot.tree_sha256,
        "entries_excluding_root": len(snapshot.tree),
        "regular_file_count": snapshot.regular_file_count,
        "regular_file_bytes": snapshot.regular_file_bytes,
        "sensitive_scan_result_sha256": sensitive_scan.get("result_sha256"),
    }


def _validate_privacy_review(
    path: Path,
    *,
    snapshots: Sequence[AttemptSnapshot],
    sensitive_scans: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    lexical = path.expanduser().absolute()
    _require_outside_repo(lexical, label="privacy review receipt")
    receipt_path = _require_regular(lexical, label="privacy review receipt")
    observed = receipt_path.stat(follow_symlinks=False)
    if observed.st_uid != os.geteuid() or stat.S_IMODE(observed.st_mode) != 0o444:
        raise PublicationError(
            "privacy review receipt must be owner-held and immutable mode 0444"
        )
    authorization, file_receipt = _load_json_with_receipt(
        receipt_path,
        label="privacy review receipt",
        logical_path=receipt_path.name,
    )
    if set(authorization) != {
        "schema_version",
        "receipt_kind",
        "publication_version",
        "scope",
        "decision",
        "reviewer",
        "reviewed_utc",
        "attempts",
    }:
        raise PublicationError("privacy review receipt has unexpected fields")
    reviewer = authorization.get("reviewer")
    if (
        authorization.get("schema_version") != 1
        or authorization.get("receipt_kind") != PRIVACY_REVIEW_KIND
        or authorization.get("publication_version") != PUBLICATION_VERSION
        or authorization.get("scope") != PRIVACY_REVIEW_SCOPE
        or authorization.get("decision") != "approved"
        or not isinstance(reviewer, str)
        or not reviewer.strip()
        or len(reviewer) > 512
    ):
        raise PublicationError("privacy review receipt does not approve public release")
    _validate_aware_timestamp(
        authorization.get("reviewed_utc"), label="privacy review reviewed_utc"
    )
    expected_attempts = [
        _privacy_attempt_binding(snapshot, sensitive_scans[snapshot.raw_attempt_id])
        for snapshot in snapshots
    ]
    if authorization.get("attempts") != expected_attempts:
        raise PublicationError(
            "privacy review receipt does not bind the exact attempt trees and scans"
        )
    return {
        "receipt": file_receipt,
        "authorization": authorization,
    }


def _archive_root(raw_attempt_id: str) -> str:
    return f"rules-as-programs-eacl2027-{raw_attempt_id}"


def _tree_archive_path(raw_attempt_id: str, relative: str = "") -> str:
    base = f"{_archive_root(raw_attempt_id)}/attempt"
    return f"{base}/{relative}" if relative else base


def _claim_archive_path(raw_attempt_id: str) -> str:
    return f"{_archive_root(raw_attempt_id)}/publication-claim/{raw_attempt_id}.launch.json"


def _attempt_compact(
    snapshot: AttemptSnapshot, sensitive_scan: Mapping[str, Any]
) -> dict[str, Any]:
    claim = (
        None
        if snapshot.claim_receipt is None
        else {
            "archive_path": _claim_archive_path(snapshot.raw_attempt_id),
            "bytes": snapshot.claim_receipt["bytes"],
            "sha256": snapshot.claim_receipt["sha256"],
            "tar_member_type": "hardlink",
            "hardlink_target": _tree_archive_path(
                snapshot.raw_attempt_id, "launch.json"
            ),
            "inode_identical_to_attempt_launch_at_archive_time": True,
        }
    )
    return {
        "raw_attempt_id": snapshot.raw_attempt_id,
        "archive_path": _tree_archive_path(snapshot.raw_attempt_id),
        "tree": {
            "hash_definition": "sha256(canonical-json(tree_inventory))",
            "sha256": snapshot.tree_sha256,
            "entries_excluding_root": len(snapshot.tree),
            "regular_file_count": snapshot.regular_file_count,
            "regular_file_bytes": snapshot.regular_file_bytes,
        },
        "claim": claim,
        "sensitive_data_scan": dict(sensitive_scan),
    }


def _attempt_manifest(
    snapshot: AttemptSnapshot,
    *,
    builder: Mapping[str, Any],
    reduced: Mapping[str, Any],
    fresh: Mapping[str, Any],
    durable_uri: str,
    sensitive_scan: Mapping[str, Any],
    privacy_review: Mapping[str, Any],
    github_release: Mapping[str, Any],
) -> dict[str, Any]:
    compact = _attempt_compact(snapshot, sensitive_scan)
    compact["tree"] = {**compact["tree"], "inventory": list(snapshot.tree)}
    return {
        "schema_version": 1,
        "publication_version": PUBLICATION_VERSION,
        "protocol_amendment": "protocol-v3-amendment-007",
        "durable_uri": durable_uri,
        "builder": dict(builder),
        "reduced_json": dict(reduced),
        "analysis_id": fresh["analysis_id"],
        "analysis_binding_sha256": fresh["analysis_binding_sha256"],
        "protocol_documents": fresh["analysis_binding"]["protocol_documents"],
        "privacy_review": dict(privacy_review),
        "github_release": {
            **dict(github_release),
            "asset_name": unquote(Path(urlsplit(durable_uri).path).name),
        },
        "attempt": compact,
    }


def _tar_info(name: str, *, mode: int, size: int = 0, directory: bool = False):
    if directory and not name.endswith("/"):
        name += "/"
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = mode
    info.size = 0 if directory else size
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.pax_headers = {}
    return info


def _add_bytes(tar: tarfile.TarFile, name: str, value: bytes) -> None:
    tar.addfile(_tar_info(name, mode=0o444, size=len(value)), io.BytesIO(value))


def _add_directory(tar: tarfile.TarFile, name: str, *, mode: int) -> None:
    tar.addfile(_tar_info(name, mode=mode, directory=True))


def _add_verified_claim_hardlink(
    tar: tarfile.TarFile, snapshot: AttemptSnapshot
) -> None:
    if snapshot.claim_path is None or snapshot.claim_receipt is None:
        return
    launch = snapshot.root / "launch.json"
    claim_stat = snapshot.claim_path.stat(follow_symlinks=False)
    launch_stat = launch.stat(follow_symlinks=False)
    claim_bytes, claim_sha256 = _stream_file_identity(snapshot.claim_path)
    if (
        not os.path.samestat(claim_stat, launch_stat)
        or claim_bytes != snapshot.claim_receipt["bytes"]
        or claim_sha256 != snapshot.claim_receipt["sha256"]
    ):
        raise PublicationError("publication claim lost its launch hard-link identity")
    info = _tar_info(
        _claim_archive_path(snapshot.raw_attempt_id),
        mode=stat.S_IMODE(claim_stat.st_mode),
    )
    info.type = tarfile.LNKTYPE
    info.linkname = _tree_archive_path(snapshot.raw_attempt_id, "launch.json")
    info.size = 0
    tar.addfile(info)


def _add_verified_file(
    tar: tarfile.TarFile,
    source: Path,
    archive_path: str,
    *,
    expected_mode: int,
    expected_bytes: int,
    expected_sha256: str,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise PublicationError(
            f"could not securely open archive input: {source}"
        ) from exc
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or opened.st_size != expected_bytes
        ):
            raise PublicationError(f"archive input metadata changed: {source}")
        reader = _HashingReader(handle)
        tar.addfile(
            _tar_info(archive_path, mode=expected_mode, size=expected_bytes), reader
        )
        closed_over = os.fstat(handle.fileno())
    if (
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (
            closed_over.st_dev,
            closed_over.st_ino,
            closed_over.st_size,
            closed_over.st_mtime_ns,
        )
        or reader.bytes_read != expected_bytes
        or reader.digest.hexdigest() != expected_sha256
    ):
        raise PublicationError(f"archive input changed while streaming: {source}")


def _zstd_identity(executable: Path) -> dict[str, Any]:
    binary = _require_regular(executable, label="zstd executable")
    if not os.access(binary, os.X_OK):
        raise PublicationError(f"zstd executable is not executable: {binary}")
    try:
        completed = subprocess.run(
            [str(binary), "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PublicationError("could not identify zstd") from exc
    version = completed.stdout.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0 or not version or len(version) > 4096:
        raise PublicationError("zstd --version failed or returned invalid output")
    return {
        "executable": _file_receipt(binary, logical_path=binary.name),
        "version": version,
        "arguments": ["-q", "-19", "-T1", "-c"],
    }


def _write_attempt_archive(
    output: BinaryIO,
    *,
    snapshot: AttemptSnapshot,
    manifest_bytes: bytes,
    zstd_executable: Path,
) -> dict[str, Any]:
    compressor = _zstd_identity(zstd_executable)
    try:
        process = subprocess.Popen(
            [str(zstd_executable.resolve(strict=True)), *compressor["arguments"]],
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise PublicationError("could not start zstd") from exc
    if process.stdin is None or process.stderr is None:
        process.kill()
        process.wait()
        raise PublicationError("zstd did not expose its required pipes")
    try:
        with tarfile.open(
            fileobj=process.stdin, mode="w|", format=tarfile.PAX_FORMAT
        ) as tar:
            root_name = _archive_root(snapshot.raw_attempt_id)
            _add_directory(tar, root_name, mode=0o755)
            _add_bytes(tar, f"{root_name}/MANIFEST.json", manifest_bytes)
            _add_directory(tar, _tree_archive_path(snapshot.raw_attempt_id), mode=0o700)
            for entry in snapshot.tree:
                relative = str(entry["relative_path"])
                archive_path = _tree_archive_path(snapshot.raw_attempt_id, relative)
                if entry["type"] == "directory":
                    _add_directory(tar, archive_path, mode=int(entry["mode"]))
                else:
                    _add_verified_file(
                        tar,
                        snapshot.root / relative,
                        archive_path,
                        expected_mode=int(entry["mode"]),
                        expected_bytes=int(entry["bytes"]),
                        expected_sha256=str(entry["sha256"]),
                    )
            _add_directory(tar, f"{root_name}/publication-claim", mode=0o700)
            _add_verified_claim_hardlink(tar, snapshot)
        process.stdin.close()
        stderr = process.stderr.read()
        returncode = process.wait()
    except BaseException:
        try:
            process.stdin.close()
        except OSError:
            pass
        process.kill()
        process.wait()
        raise
    if returncode != 0:
        message = stderr.decode("utf-8", errors="replace")[-4096:]
        raise PublicationError(f"zstd failed with exit {returncode}: {message}")
    if _zstd_identity(zstd_executable) != compressor:
        raise PublicationError("zstd changed while building an archive")
    return compressor


def _expected_archive_members(
    snapshot: AttemptSnapshot, manifest_bytes: bytes
) -> list[dict[str, Any]]:
    root_name = _archive_root(snapshot.raw_attempt_id)
    members: list[dict[str, Any]] = [
        {"name": root_name, "type": "directory", "mode": 0o755},
        {
            "name": f"{root_name}/MANIFEST.json",
            "type": "regular_file",
            "mode": 0o444,
            "bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        {
            "name": _tree_archive_path(snapshot.raw_attempt_id),
            "type": "directory",
            "mode": 0o700,
        },
    ]
    for entry in snapshot.tree:
        name = _tree_archive_path(snapshot.raw_attempt_id, str(entry["relative_path"]))
        if entry["type"] == "directory":
            members.append(
                {
                    "name": name,
                    "type": "directory",
                    "mode": int(entry["mode"]),
                }
            )
        else:
            members.append(
                {
                    "name": name,
                    "type": "regular_file",
                    "mode": int(entry["mode"]),
                    "bytes": int(entry["bytes"]),
                    "sha256": str(entry["sha256"]),
                }
            )
    members.append(
        {
            "name": f"{root_name}/publication-claim",
            "type": "directory",
            "mode": 0o700,
        }
    )
    if snapshot.claim_path is not None and snapshot.claim_receipt is not None:
        members.append(
            {
                "name": _claim_archive_path(snapshot.raw_attempt_id),
                "type": "hardlink",
                "mode": stat.S_IMODE(
                    snapshot.claim_path.stat(follow_symlinks=False).st_mode
                ),
                "linkname": _tree_archive_path(snapshot.raw_attempt_id, "launch.json"),
                "source_bytes": int(snapshot.claim_receipt["bytes"]),
                "source_sha256": str(snapshot.claim_receipt["sha256"]),
            }
        )
    for member in members:
        raw_name = (
            f"{member['name']}/"
            if member["type"] == "directory"
            else str(member["name"])
        )
        pax_headers: dict[str, str] = {}
        try:
            raw_name.encode("ascii", "strict")
        except UnicodeEncodeError:
            pax_headers["path"] = raw_name
        else:
            if len(raw_name) > tarfile.LENGTH_NAME:
                pax_headers["path"] = raw_name
        linkname = str(member.get("linkname", ""))
        if linkname:
            try:
                linkname.encode("ascii", "strict")
            except UnicodeEncodeError:
                pax_headers["linkpath"] = linkname
            else:
                if len(linkname) > tarfile.LENGTH_LINK:
                    pax_headers["linkpath"] = linkname
        if int(member.get("bytes", 0)) >= 8**11:
            pax_headers["size"] = str(member["bytes"])
        member["pax_headers"] = pax_headers
    return members


def _expected_tar_stream_size(
    expected_members: Sequence[Mapping[str, Any]],
) -> tuple[int, int]:
    content_bytes = 0
    for expected in expected_members:
        info = _tar_info(
            str(expected["name"]),
            mode=int(expected["mode"]),
            size=int(expected.get("bytes", 0)),
            directory=expected["type"] == "directory",
        )
        if expected["type"] == "hardlink":
            info.type = tarfile.LNKTYPE
            info.linkname = str(expected["linkname"])
            info.size = 0
        header = info.tobuf(
            format=tarfile.PAX_FORMAT,
            encoding="utf-8",
            errors="surrogateescape",
        )
        content_bytes += len(header)
        content_bytes += (
            (int(info.size) + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
        ) * tarfile.BLOCKSIZE
    with_end_markers = content_bytes + 2 * tarfile.BLOCKSIZE
    stream_bytes = (
        (with_end_markers + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE
    ) * tarfile.RECORDSIZE
    return content_bytes, stream_bytes


class _TrackedTarStream:
    def __init__(self, handle: BinaryIO, *, trailing_start: int, maximum_bytes: int):
        self.handle = handle
        self.trailing_start = trailing_start
        self.maximum_bytes = maximum_bytes
        self.bytes_read = 0
        self.trailing_nonzero = False

    def read(self, size: int = -1) -> bytes:
        value = self.handle.read(size)
        start = self.bytes_read
        self.bytes_read += len(value)
        if self.bytes_read > self.maximum_bytes:
            raise PublicationError("archive exceeds its canonical tar stream size")
        if value and self.bytes_read > self.trailing_start:
            offset = max(0, self.trailing_start - start)
            if any(value[offset:]):
                self.trailing_nonzero = True
        return value


def _safe_archive_member_name(name: str) -> bool:
    stripped = name[:-1] if name.endswith("/") else name
    pure = PurePosixPath(stripped)
    return bool(stripped) and not pure.is_absolute() and ".." not in pure.parts


def _verify_attempt_archive(
    archive: Path,
    *,
    snapshot: AttemptSnapshot,
    manifest_bytes: bytes,
    zstd_executable: Path,
    expected_compressor: Mapping[str, Any],
    expected_archive: Mapping[str, Any],
    archive_directory: SecureOutputDirectory | None = None,
) -> dict[str, Any]:
    logical_archive_path = str(expected_archive.get("path", ""))
    observed_archive = (
        archive_directory.file_receipt(archive.name, logical_path=logical_archive_path)
        if archive_directory is not None
        else _file_receipt(archive, logical_path=logical_archive_path)
    )
    if {
        key: expected_archive.get(key) for key in ("path", "bytes", "sha256")
    } != observed_archive:
        raise PublicationError("archive bytes differ from their bound receipt")
    compressor = _zstd_identity(zstd_executable)
    if dict(expected_compressor) != compressor:
        raise PublicationError("archive compressor metadata is not authentic")
    expected_members = _expected_archive_members(snapshot, manifest_bytes)
    content_bytes, expected_stream_bytes = _expected_tar_stream_size(expected_members)
    command = [str(zstd_executable.resolve(strict=True)), "-q", "-d", "-c"]
    archive_handle = (
        archive_directory.open_read(archive.name)
        if archive_directory is not None
        else open(archive, "rb")
    )
    try:
        process = subprocess.Popen(
            command,
            stdin=archive_handle,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        archive_handle.close()
        raise PublicationError("could not start zstd archive verifier") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        archive_handle.close()
        raise PublicationError("zstd verifier did not expose required pipes")
    seen: set[str] = set()
    observed_bindings: list[dict[str, Any]] = []
    index = 0
    tracked = _TrackedTarStream(
        process.stdout,
        trailing_start=content_bytes,
        maximum_bytes=expected_stream_bytes,
    )
    try:
        with tarfile.open(fileobj=tracked, mode="r|*") as tar:
            for member in tar:
                if index >= len(expected_members):
                    raise PublicationError("archive contains an extra member")
                expected = expected_members[index]
                index += 1
                if (
                    not _safe_archive_member_name(member.name)
                    or member.name in seen
                    or member.name != expected["name"]
                ):
                    raise PublicationError(
                        "archive member order, uniqueness, or path safety failed"
                    )
                seen.add(member.name)
                if (
                    member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or int(member.mtime) != 0
                    or stat.S_IMODE(member.mode) != expected["mode"]
                    or stat.S_IMODE(member.mode) & 0o7000
                    or member.pax_headers != expected["pax_headers"]
                ):
                    raise PublicationError("archive member metadata is not canonical")
                if expected["type"] == "directory":
                    if not member.isdir() or member.size != 0:
                        raise PublicationError("archive directory member is invalid")
                    observed_bindings.append(dict(expected))
                    continue
                if expected["type"] == "hardlink":
                    if (
                        not member.islnk()
                        or member.issym()
                        or member.size != 0
                        or member.linkname != expected["linkname"]
                        or not _safe_archive_member_name(member.linkname)
                    ):
                        raise PublicationError(
                            "archive claim hard-link member is invalid"
                        )
                    observed_bindings.append(dict(expected))
                    continue
                if not member.isfile() or member.issym() or member.islnk():
                    raise PublicationError(
                        "archive regular-file member has invalid type"
                    )
                if member.size != expected["bytes"]:
                    raise PublicationError("archive regular-file size mismatch")
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise PublicationError(
                        "archive regular-file payload is unavailable"
                    )
                digest = hashlib.sha256()
                byte_count = 0
                for chunk in iter(lambda: extracted.read(1024 * 1024), b""):
                    byte_count += len(chunk)
                    digest.update(chunk)
                if (
                    byte_count != expected["bytes"]
                    or digest.hexdigest() != expected["sha256"]
                ):
                    raise PublicationError("archive regular-file hash mismatch")
                observed_bindings.append(dict(expected))
            if tar.pax_headers:
                raise PublicationError(
                    "archive contains noncanonical global PAX metadata"
                )
        for _chunk in iter(lambda: tracked.read(1024 * 1024), b""):
            pass
        stderr = process.stderr.read()
        returncode = process.wait()
    except BaseException as exc:
        try:
            process.kill()
        finally:
            process.wait()
        if isinstance(exc, (KeyboardInterrupt, SystemExit, PublicationError)):
            raise
        if isinstance(exc, (tarfile.TarError, OSError, EOFError, ValueError)):
            raise PublicationError("archive tar/zstd stream is malformed") from exc
        raise PublicationError("archive verification failed unexpectedly") from exc
    finally:
        archive_handle.close()
    if index != len(expected_members):
        raise PublicationError("archive is missing an expected member")
    if returncode != 0:
        message = stderr.decode("utf-8", errors="replace")[-4096:]
        raise PublicationError(f"zstd archive verification failed: {message}")
    if tracked.bytes_read != expected_stream_bytes or tracked.trailing_nonzero:
        raise PublicationError("archive has noncanonical trailing tar bytes")
    if _zstd_identity(zstd_executable) != compressor:
        raise PublicationError("zstd changed while verifying the archive")
    binding = {
        "schema_version": 1,
        "verifier_version": PUBLICATION_VERSION,
        "status": "passed",
        "archive": observed_archive,
        "manifest": {
            "bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "ordered_member_count": len(observed_bindings),
        "ordered_member_binding_sha256": hashlib.sha256(
            _canonical_json_bytes(observed_bindings)
        ).hexdigest(),
        "claim_hardlink_verified": snapshot.claim_path is not None,
        "compressor": compressor,
    }
    return {
        **binding,
        "verification_sha256": hashlib.sha256(
            _canonical_json_bytes(binding)
        ).hexdigest(),
    }


class SecureOutputDirectory:
    """Pin an output directory and perform every mutation relative to its fd."""

    def __init__(self, path: Path, *, private: bool, label: str):
        self.path = path.expanduser().absolute()
        self.private = private
        self.label = label
        self._fd: int | None = None
        self._identity: tuple[int, int] | None = None

    def __enter__(self):
        _reject_symlink_components(self.path, label=self.label)
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(self.path, flags)
        except OSError as exc:
            raise PublicationError(
                f"{self.label} could not be opened as a pinned directory"
            ) from exc
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode):
            os.close(descriptor)
            raise PublicationError(f"{self.label} must be a directory")
        if observed.st_uid != os.geteuid() or (
            self.private and stat.S_IMODE(observed.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise PublicationError(
                f"{self.label} must be owner-held"
                + (" and mode 0700" if self.private else "")
            )
        self._fd = descriptor
        self._identity = (observed.st_dev, observed.st_ino)
        self.verify_path_binding()
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise PublicationError(f"{self.label} is not open")
        return self._fd

    def verify_path_binding(self) -> None:
        try:
            observed = self.path.stat(follow_symlinks=False)
        except OSError as exc:
            raise PublicationError(f"{self.label} path binding changed") from exc
        if (
            not stat.S_ISDIR(observed.st_mode)
            or (observed.st_dev, observed.st_ino) != self._identity
        ):
            raise PublicationError(f"{self.label} path binding changed")

    def _name(self, path_or_name: Path | str) -> str:
        value = Path(path_or_name)
        if value.is_absolute():
            if value.parent != self.path:
                raise PublicationError(f"output is outside pinned {self.label}")
            name = value.name
        else:
            name = str(path_or_name)
        if not name or name in {".", ".."} or Path(name).name != name:
            raise PublicationError(f"invalid output name in {self.label}")
        return name

    def require_absent(self, path_or_name: Path | str, *, label: str) -> str:
        name = self._name(path_or_name)
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return name
        except OSError as exc:
            raise PublicationError(f"could not inspect {label}") from exc
        raise PublicationError(f"refusing to replace immutable {label}: {name}")

    def create_temporary(self, destination_name: str) -> tuple[int, str]:
        destination = self._name(destination_name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        for _ in range(128):
            name = f".{destination}.{secrets.token_hex(12)}.partial"
            try:
                return os.open(name, flags, 0o600, dir_fd=self.fd), name
            except FileExistsError:
                continue
            except OSError as exc:
                raise PublicationError(
                    f"could not create temporary output in {self.label}"
                ) from exc
        raise PublicationError(f"could not allocate temporary output in {self.label}")

    def write_atomic_exclusive_bytes(
        self,
        destination_name: str,
        value: bytes,
        *,
        mode: int,
    ) -> tuple[int, int]:
        destination = self._name(destination_name)
        descriptor, staging = self.create_temporary(destination)
        try:
            remaining = memoryview(value)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise PublicationError(
                        "short write for atomic publication transaction file"
                    )
                remaining = remaining[written:]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            observed_staging = os.fstat(descriptor)
            identity = (observed_staging.st_dev, observed_staging.st_ino)
        finally:
            os.close(descriptor)
        self.link(staging, destination)
        observed = self.stat(destination)
        receipt = self.file_receipt(destination, logical_path=destination)
        if (
            (observed.st_dev, observed.st_ino) != identity
            or not stat.S_ISREG(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != mode
            or receipt
            != {
                "path": destination,
                "bytes": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }
        ):
            raise PublicationError("atomic transaction file binding is invalid")
        self.fsync()
        self.cleanup_if_same(staging, identity)
        self.fsync()
        self.verify_path_binding()
        return identity

    def list_names(self) -> list[str]:
        try:
            return sorted(os.listdir(self.fd))
        except OSError as exc:
            raise PublicationError(f"could not list pinned {self.label}") from exc

    def stat_optional(self, path_or_name: Path | str):
        name = self._name(path_or_name)
        try:
            return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PublicationError(f"could not stat {name} in {self.label}") from exc

    def stat(self, path_or_name: Path | str):
        name = self._name(path_or_name)
        try:
            return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except OSError as exc:
            raise PublicationError(f"could not stat {name} in {self.label}") from exc

    def open_read(self, path_or_name: Path | str) -> BinaryIO:
        name = self._name(path_or_name)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=self.fd)
        except OSError as exc:
            raise PublicationError(f"could not open {name} in {self.label}") from exc
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            os.close(descriptor)
            raise PublicationError(f"{name} in {self.label} is not a regular file")
        return os.fdopen(descriptor, "rb")

    def file_receipt(
        self, path_or_name: Path | str, *, logical_path: str
    ) -> dict[str, Any]:
        name = self._name(path_or_name)
        digest = hashlib.sha256()
        byte_count = 0
        with self.open_read(name) as handle:
            opened = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                byte_count += len(chunk)
                digest.update(chunk)
            closed_over = os.fstat(handle.fileno())
        current = self.stat(name)
        before = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        after = (
            closed_over.st_dev,
            closed_over.st_ino,
            closed_over.st_mode,
            closed_over.st_size,
            closed_over.st_mtime_ns,
            closed_over.st_ctime_ns,
        )
        current_identity = (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        )
        if (
            before != after
            or before != current_identity
            or byte_count != opened.st_size
        ):
            raise PublicationError(f"{name} changed while it was read")
        return {
            "path": logical_path,
            "bytes": byte_count,
            "sha256": digest.hexdigest(),
        }

    def read_bytes_receipt(
        self,
        path_or_name: Path | str,
        *,
        label: str,
        logical_path: str,
    ) -> tuple[bytes, dict[str, Any]]:
        name = self._name(path_or_name)
        digest = hashlib.sha256()
        byte_count = 0
        chunks: list[bytes] = []
        with self.open_read(name) as handle:
            opened = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                chunks.append(chunk)
                byte_count += len(chunk)
                digest.update(chunk)
            closed_over = os.fstat(handle.fileno())
        current = self.stat(name)
        if (
            _stat_identity(opened) != _stat_identity(closed_over)
            or _stat_identity(opened) != _stat_identity(current)
            or byte_count != opened.st_size
        ):
            raise PublicationError(f"{label} changed while it was read")
        return b"".join(chunks), {
            "path": logical_path,
            "bytes": byte_count,
            "sha256": digest.hexdigest(),
        }

    def load_json_with_receipt(
        self, path_or_name: Path | str, *, label: str, logical_path: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        raw, receipt = self.read_bytes_receipt(
            path_or_name, label=label, logical_path=logical_path
        )
        try:
            value = json.loads(
                raw,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise PublicationError(f"{label} is not readable JSON") from exc
        if not isinstance(value, dict):
            raise PublicationError(f"{label} must contain a JSON object")
        return value, receipt

    def chmod_and_identity(
        self, path_or_name: Path | str, mode: int
    ) -> tuple[int, int]:
        name = self._name(path_or_name)
        with self.open_read(name) as handle:
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
            observed = os.fstat(handle.fileno())
        return observed.st_dev, observed.st_ino

    def link(self, source: str, destination: str) -> None:
        try:
            os.link(
                self._name(source),
                self._name(destination),
                src_dir_fd=self.fd,
                dst_dir_fd=self.fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise PublicationError(
                f"immutable output collision: {destination}"
            ) from exc
        except OSError as exc:
            raise PublicationError(f"could not publish {destination}") from exc

    def unlink_if_same(self, name: str, identity: tuple[int, int]) -> None:
        observed = self.stat(name)
        if (observed.st_dev, observed.st_ino) != identity:
            raise PublicationError(
                f"refusing to unlink replaced transaction path: {name}"
            )
        try:
            os.unlink(self._name(name), dir_fd=self.fd)
        except OSError as exc:
            raise PublicationError(
                f"could not unlink transaction path: {name}"
            ) from exc

    def cleanup_if_same(self, name: str, identity: tuple[int, int]) -> None:
        try:
            observed = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise PublicationError(
                f"could not inspect transaction path: {name}"
            ) from exc
        if (observed.st_dev, observed.st_ino) != identity:
            raise PublicationError(
                f"refusing to clean replaced transaction path: {name}"
            )
        try:
            os.unlink(name, dir_fd=self.fd)
        except OSError as exc:
            raise PublicationError(f"could not clean transaction path: {name}") from exc

    def rollback_if_same(self, name: str, identity: tuple[int, int]) -> None:
        try:
            observed = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise PublicationError(f"could not inspect rollback path: {name}") from exc
        if (observed.st_dev, observed.st_ino) != identity:
            return
        try:
            os.unlink(name, dir_fd=self.fd)
        except OSError as exc:
            raise PublicationError(f"could not unlink rollback path: {name}") from exc

    def fsync(self) -> None:
        try:
            os.fsync(self.fd)
        except OSError as exc:
            raise PublicationError(f"could not fsync {self.label}") from exc


TRANSACTION_JOURNAL_KIND = "exclusive_link_bundle_transaction_v1"


def _transaction_journal_name(marker_destination: str) -> str:
    return f".{marker_destination}.publication-transaction.json"


def _transaction_journal_staging_pattern(
    marker_destination: str,
) -> re.Pattern[str]:
    journal_name = _transaction_journal_name(marker_destination)
    return re.compile(rf"\.{re.escape(journal_name)}\.[0-9a-f]{{24}}\.partial")


def _recover_atomic_journal_staging(
    directory: SecureOutputDirectory,
    *,
    marker_destination: str,
    expected_destinations: Sequence[str],
) -> None:
    journal_name = _transaction_journal_name(marker_destination)
    final = directory.stat_optional(journal_name)
    if final is None:
        return
    final_identity = (final.st_dev, final.st_ino)
    pattern = _transaction_journal_staging_pattern(marker_destination)
    matching_links: list[str] = []
    for name in directory.list_names():
        if pattern.fullmatch(name) is None:
            continue
        observed = directory.stat(name)
        if (observed.st_dev, observed.st_ino) == final_identity:
            matching_links.append(name)
    expected_link_count = 1 + len(matching_links)
    if final.st_nlink != expected_link_count:
        raise PublicationError("transaction journal has an unbound hard link")
    validated = _validated_bundle_journal(
        directory,
        marker_destination=marker_destination,
        expected_destinations=expected_destinations,
        expected_link_count=expected_link_count,
    )
    if validated is None:
        raise PublicationError("transaction journal changed during staging recovery")
    for staging_name in matching_links:
        directory.unlink_if_same(staging_name, final_identity)
    if not matching_links:
        return
    directory.fsync()
    directory.verify_path_binding()


def _create_bundle_journal(
    directory: SecureOutputDirectory,
    archives: Sequence[tuple[str, str]],
    marker: tuple[str, str],
) -> tuple[str, dict[str, Any]]:
    members: list[dict[str, Any]] = []
    for role, (temporary, destination) in [
        *[("archive", item) for item in archives],
        ("marker", marker),
    ]:
        identity = directory.chmod_and_identity(temporary, 0o444)
        observed = directory.stat(temporary)
        receipt = directory.file_receipt(temporary, logical_path=destination)
        if (
            not stat.S_ISREG(observed.st_mode)
            or stat.S_IMODE(observed.st_mode) != 0o444
            or (observed.st_dev, observed.st_ino) != identity
        ):
            raise PublicationError("transaction temporary is not immutable and stable")
        members.append(
            {
                "role": role,
                "temporary": temporary,
                "destination": destination,
                "device": observed.st_dev,
                "inode": observed.st_ino,
                "mode": 0o444,
                "bytes": receipt["bytes"],
                "sha256": receipt["sha256"],
            }
        )
    directory_stat = os.fstat(directory.fd)
    journal = {
        "schema_version": 1,
        "transaction_kind": TRANSACTION_JOURNAL_KIND,
        "publication_version": PUBLICATION_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "directory": {
            "device": directory_stat.st_dev,
            "inode": directory_stat.st_ino,
        },
        "marker_destination": marker[1],
        "members": members,
    }
    name = _transaction_journal_name(marker[1])
    directory.write_atomic_exclusive_bytes(
        name,
        _render_json(journal),
        mode=0o444,
    )
    return name, journal


def _validated_bundle_journal(
    directory: SecureOutputDirectory,
    *,
    marker_destination: str,
    expected_destinations: Sequence[str],
    expected_link_count: int = 1,
) -> tuple[str, tuple[int, int], dict[str, Any]] | None:
    journal_name = _transaction_journal_name(marker_destination)
    journal_stat = directory.stat_optional(journal_name)
    if journal_stat is None:
        return None
    journal_identity = (journal_stat.st_dev, journal_stat.st_ino)
    if (
        not stat.S_ISREG(journal_stat.st_mode)
        or journal_stat.st_uid != os.geteuid()
        or journal_stat.st_nlink != expected_link_count
        or stat.S_IMODE(journal_stat.st_mode) != 0o444
    ):
        raise PublicationError("transaction journal is not immutable and owner-held")
    journal, _receipt = directory.load_json_with_receipt(
        journal_name,
        label="publication transaction journal",
        logical_path=journal_name,
    )
    if set(journal) != {
        "schema_version",
        "transaction_kind",
        "publication_version",
        "created_utc",
        "directory",
        "marker_destination",
        "members",
    }:
        raise PublicationError("transaction journal has unexpected fields")
    directory_binding = journal.get("directory")
    members = journal.get("members")
    if (
        journal.get("schema_version") != 1
        or journal.get("transaction_kind") != TRANSACTION_JOURNAL_KIND
        or journal.get("publication_version") != PUBLICATION_VERSION
        or journal.get("marker_destination") != marker_destination
        or not isinstance(directory_binding, dict)
        or set(directory_binding) != {"device", "inode"}
        or not isinstance(members, list)
        or len(members) != len(expected_destinations)
    ):
        raise PublicationError("transaction journal binding is invalid")
    _validate_aware_timestamp(
        journal.get("created_utc"), label="transaction journal created_utc"
    )
    observed_directory = os.fstat(directory.fd)
    if directory_binding != {
        "device": observed_directory.st_dev,
        "inode": observed_directory.st_ino,
    }:
        raise PublicationError("transaction journal names a different directory")
    observed_destinations: list[str] = []
    for index, member in enumerate(members):
        expected_role = "marker" if index == len(members) - 1 else "archive"
        if not isinstance(member, dict) or set(member) != {
            "role",
            "temporary",
            "destination",
            "device",
            "inode",
            "mode",
            "bytes",
            "sha256",
        }:
            raise PublicationError("transaction journal member is malformed")
        temporary = member.get("temporary")
        destination = member.get("destination")
        if not isinstance(temporary, str) or not isinstance(destination, str):
            raise PublicationError("transaction journal paths are malformed")
        directory._name(temporary)
        directory._name(destination)
        if (
            member.get("role") != expected_role
            or type(member.get("device")) is not int
            or type(member.get("inode")) is not int
            or member.get("mode") != 0o444
            or type(member.get("bytes")) is not int
            or int(member["bytes"]) < 0
            or not isinstance(member.get("sha256"), str)
            or SHA256_PATTERN.fullmatch(str(member["sha256"])) is None
        ):
            raise PublicationError("transaction journal member binding is invalid")
        observed_destinations.append(destination)
    if observed_destinations != list(expected_destinations):
        raise PublicationError(
            "transaction journal destinations differ from invocation"
        )
    return journal_name, journal_identity, journal


def _verify_journal_member(
    directory: SecureOutputDirectory,
    member: Mapping[str, Any],
    *,
    path_key: str,
) -> None:
    name = str(member[path_key])
    observed = directory.stat_optional(name)
    if observed is None:
        raise PublicationError(f"committed transaction member is missing: {name}")
    expected_identity = (int(member["device"]), int(member["inode"]))
    if (
        not stat.S_ISREG(observed.st_mode)
        or (observed.st_dev, observed.st_ino) != expected_identity
        or stat.S_IMODE(observed.st_mode) != int(member["mode"])
    ):
        raise PublicationError(f"transaction member identity differs: {name}")
    receipt = directory.file_receipt(name, logical_path=str(member["destination"]))
    if receipt != {
        "path": str(member["destination"]),
        "bytes": int(member["bytes"]),
        "sha256": str(member["sha256"]),
    }:
        raise PublicationError(f"transaction member bytes differ: {name}")


def _recover_bundle_transaction(
    directory: SecureOutputDirectory,
    *,
    marker_destination: str,
    expected_destinations: Sequence[str],
) -> str:
    _recover_atomic_journal_staging(
        directory,
        marker_destination=marker_destination,
        expected_destinations=expected_destinations,
    )
    validated = _validated_bundle_journal(
        directory,
        marker_destination=marker_destination,
        expected_destinations=expected_destinations,
    )
    if validated is None:
        return "none"
    journal_name, journal_identity, journal = validated
    members = list(journal["members"])
    marker_member = members[-1]
    marker_stat = directory.stat_optional(marker_destination)
    marker_expected = (
        int(marker_member["device"]),
        int(marker_member["inode"]),
    )
    if marker_stat is None:
        for member in reversed(members):
            directory.rollback_if_same(
                str(member["destination"]),
                (int(member["device"]), int(member["inode"])),
            )
        outcome = "rolled_back"
    else:
        if (marker_stat.st_dev, marker_stat.st_ino) != marker_expected:
            raise PublicationError("transaction marker is foreign or replaced")
        for member in members:
            _verify_journal_member(directory, member, path_key="destination")
        outcome = "committed"
    for member in members:
        directory.rollback_if_same(
            str(member["temporary"]),
            (int(member["device"]), int(member["inode"])),
        )
    directory.unlink_if_same(journal_name, journal_identity)
    directory.fsync()
    directory.verify_path_binding()
    return outcome


def _publish_bundle(
    directory: SecureOutputDirectory,
    archives: Sequence[tuple[str, str]],
    marker: tuple[str, str],
) -> None:
    all_outputs = [*archives, marker]
    expected_destinations = [destination for _, destination in all_outputs]
    journal_created = False
    try:
        _journal_name, journal = _create_bundle_journal(directory, archives, marker)
        journal_created = True
        members = list(journal["members"])
        for (temporary, destination), member in zip(archives, members[:-1]):
            directory.link(temporary, destination)
            _verify_journal_member(directory, member, path_key="destination")
        directory.fsync()
        directory.verify_path_binding()
        directory.link(marker[0], marker[1])
        _verify_journal_member(directory, members[-1], path_key="destination")
        directory.fsync()
        directory.verify_path_binding()
        if (
            _recover_bundle_transaction(
                directory,
                marker_destination=marker[1],
                expected_destinations=expected_destinations,
            )
            != "committed"
        ):
            raise PublicationError(
                "committed publication transaction was not recovered"
            )
    except BaseException as exc:
        recovery_errors: list[str] = []
        if journal_created:
            try:
                _recover_bundle_transaction(
                    directory,
                    marker_destination=marker[1],
                    expected_destinations=expected_destinations,
                )
            except BaseException as recovery_exc:
                recovery_errors.append(str(recovery_exc))
        if recovery_errors:
            raise PublicationError(
                "publication failed and journal recovery was incomplete: "
                + "; ".join(recovery_errors)
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(exc, PublicationError):
            raise
        raise PublicationError(
            "could not publish immutable output transaction"
        ) from exc


def _post_archive_validate(
    before: Sequence[AttemptSnapshot], attempts_root: Path
) -> None:
    try:
        after = _snapshot_ledger(attempts_root)
    except PublicationError as exc:
        raise PublicationError("attempt ledger changed while archiving") from exc
    if len(before) != len(after):
        raise PublicationError("attempt ledger changed while archiving")
    for old, new in zip(before, after):
        if (
            old.raw_attempt_id != new.raw_attempt_id
            or old.tree != new.tree
            or old.publication != new.publication
            or old.claim_receipt != new.claim_receipt
        ):
            raise PublicationError(
                f"attempt {old.raw_attempt_id} changed while archiving"
            )


def _ledger_projection(
    snapshot: AttemptSnapshot,
    ledger_item: Mapping[str, Any],
    selected: str | None,
    sensitive_scan: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        **_attempt_compact(snapshot, sensitive_scan),
        "raw_status": ledger_item.get("status"),
        "adjudicated_status": ledger_item.get("adjudicated_status"),
        "candidate_eligible": ledger_item.get("candidate_eligible"),
        "primary_selected": snapshot.raw_attempt_id == selected,
        "replacement_authorized_by_successor": ledger_item.get(
            "replacement_authorized_by_successor"
        ),
    }


def build_archives(
    *,
    attempts_root: Path,
    reduced_json: Path,
    archive_outputs: Mapping[str, Path],
    durable_uris: Mapping[str, str],
    draft_receipt_output: Path,
    privacy_review_receipt: Path,
    github_owner: str,
    github_repository: str,
    github_release_tag: str,
    zstd_executable: Path | None = None,
) -> dict[str, Any]:
    """Build two archives and a non-committable draft receipt, all exclusively."""

    if set(archive_outputs) != set(EXPECTED_ATTEMPT_IDS) or set(durable_uris) != set(
        EXPECTED_ATTEMPT_IDS
    ):
        raise PublicationError("archive outputs and durable URIs must name r01/r02")
    github_release = _github_release_coordinates(
        owner=github_owner,
        repository=github_repository,
        tag=github_release_tag,
    )
    archives = {
        raw_id: _require_new_output(
            archive_outputs[raw_id],
            suffix=".tar.zst",
            label=f"{raw_id} archive",
            defer_absence_to_transaction_recovery=True,
        )
        for raw_id in EXPECTED_ATTEMPT_IDS
    }
    if len(set(archives.values())) != len(archives):
        raise PublicationError("r01 and r02 archive outputs must differ")
    bound_uris = {
        raw_id: _validate_durable_uri(durable_uris[raw_id], archives[raw_id].name)
        for raw_id in EXPECTED_ATTEMPT_IDS
    }
    for raw_id in EXPECTED_ATTEMPT_IDS:
        if bound_uris[raw_id] != _canonical_github_asset_uri(
            github_release, archives[raw_id].name
        ):
            raise PublicationError(
                "durable URI must be the canonical bound GitHub release asset URL"
            )
    if len({path.name for path in archives.values()}) != len(archives) or len(
        set(bound_uris.values())
    ) != len(bound_uris):
        raise PublicationError("each attempt requires a distinct archive asset and URI")
    draft = _require_new_output(
        draft_receipt_output,
        suffix=".json",
        label="draft receipt",
        defer_absence_to_transaction_recovery=True,
    )
    bundle_parents = {path.parent for path in [*archives.values(), draft]}
    if len(bundle_parents) != 1:
        raise PublicationError(
            "r01, r02, and draft must use one private bundle directory"
        )
    bundle_parent = next(iter(bundle_parents))
    _require_private_directory(
        bundle_parent,
        label="archive bundle directory",
        owner_uid=os.geteuid(),
    )
    for path in [*archives.values(), draft]:
        _require_outside_repo(path, label="archive build output")
    reduced_path = _require_regular(
        reduced_json.expanduser().absolute(), label="reduced systems result"
    )
    attempts_path = _validated_attempts_root(attempts_root)
    if any(path.is_relative_to(attempts_path) for path in [*archives.values(), draft]):
        raise PublicationError("archive outputs must be outside the raw attempt ledger")
    expected_bundle_destinations = [
        *[archives[raw_id].name for raw_id in EXPECTED_ATTEMPT_IDS],
        draft.name,
    ]
    with SecureOutputDirectory(
        bundle_parent, private=True, label="archive bundle directory"
    ) as recovery_directory:
        recovered = _recover_bundle_transaction(
            recovery_directory,
            marker_destination=draft.name,
            expected_destinations=expected_bundle_destinations,
        )
        if recovered == "committed":
            raise PublicationError(
                "a prior archive bundle transaction already committed; outputs retained"
            )
    reduced, fresh, reduced_receipt = _validate_reduced_result(
        attempts_path, reduced_path
    )
    snapshots = _snapshot_ledger(attempts_path)
    sensitive_scans = _scan_ledger(snapshots)
    privacy_review = _validate_privacy_review(
        privacy_review_receipt,
        snapshots=snapshots,
        sensitive_scans=sensitive_scans,
    )
    executable_value = str(zstd_executable) if zstd_executable else shutil.which("zstd")
    if not executable_value:
        raise PublicationError("zstd is required to build tar.zst archives")
    executable = Path(executable_value).expanduser().absolute()
    builder_path = Path(__file__).resolve(strict=True)
    builder_receipt = _file_receipt(
        builder_path, logical_path=_logical_path(builder_path)
    )

    with SecureOutputDirectory(
        bundle_parent, private=True, label="archive bundle directory"
    ) as output_directory:
        _require_outside_repo(output_directory.path, label="archive bundle directory")
        resolved_bundle = output_directory.path.resolve(strict=True)
        if resolved_bundle == attempts_path or resolved_bundle.is_relative_to(
            attempts_path
        ):
            raise PublicationError(
                "archive bundle directory must be outside the raw attempt ledger"
            )
        output_directory.verify_path_binding()
        recovered = _recover_bundle_transaction(
            output_directory,
            marker_destination=draft.name,
            expected_destinations=expected_bundle_destinations,
        )
        if recovered == "committed":
            raise PublicationError(
                "a prior archive bundle transaction already committed; outputs retained"
            )
        for raw_id, path in archives.items():
            output_directory.require_absent(path, label=f"{raw_id} archive")
        output_directory.require_absent(draft, label="draft receipt")
        temporary_archives: dict[str, str] = {}
        temporary_identities: dict[str, tuple[int, int]] = {}
        draft_temporary: str | None = None
        try:
            built: dict[str, dict[str, Any]] = {}
            for snapshot in snapshots:
                manifest = _attempt_manifest(
                    snapshot,
                    builder=builder_receipt,
                    reduced=reduced_receipt,
                    fresh=fresh,
                    durable_uri=bound_uris[snapshot.raw_attempt_id],
                    sensitive_scan=sensitive_scans[snapshot.raw_attempt_id],
                    privacy_review=privacy_review,
                    github_release=github_release,
                )
                manifest_bytes = _render_json(manifest)
                descriptor, temporary = output_directory.create_temporary(
                    archives[snapshot.raw_attempt_id].name
                )
                temporary_archives[snapshot.raw_attempt_id] = temporary
                temporary_identities[temporary] = (
                    os.fstat(descriptor).st_dev,
                    os.fstat(descriptor).st_ino,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    compressor = _write_attempt_archive(
                        handle,
                        snapshot=snapshot,
                        manifest_bytes=manifest_bytes,
                        zstd_executable=executable,
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
                archive_receipt = output_directory.file_receipt(
                    temporary,
                    logical_path=archives[snapshot.raw_attempt_id].name,
                )
                archive_verification = _verify_attempt_archive(
                    Path(temporary),
                    snapshot=snapshot,
                    manifest_bytes=manifest_bytes,
                    zstd_executable=executable,
                    expected_compressor=compressor,
                    expected_archive=archive_receipt,
                    archive_directory=output_directory,
                )
                _post_archive_validate(snapshots, attempts_path)
                built[snapshot.raw_attempt_id] = {
                    **archive_receipt,
                    "local_path": str(archives[snapshot.raw_attempt_id]),
                    "format": "tar+zstd",
                    "media_type": "application/zstd",
                    "durable_uri": bound_uris[snapshot.raw_attempt_id],
                    "manifest": {
                        "archive_path": (
                            f"{_archive_root(snapshot.raw_attempt_id)}/MANIFEST.json"
                        ),
                        "bytes": len(manifest_bytes),
                        "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                    },
                    "compressor": compressor,
                    "build_archive_verification": archive_verification,
                }
            if (
                _file_receipt(builder_path, logical_path=_logical_path(builder_path))
                != builder_receipt
            ):
                raise PublicationError("publication builder changed while running")
            if (
                _file_receipt(reduced_path, logical_path=_logical_path(reduced_path))
                != reduced_receipt
            ):
                raise PublicationError("reduced systems result changed while building")
            if (
                _validate_privacy_review(
                    privacy_review_receipt,
                    snapshots=snapshots,
                    sensitive_scans=sensitive_scans,
                )
                != privacy_review
            ):
                raise PublicationError("privacy review receipt changed while building")
            selected = fresh["primary_numeric"].get("selected_raw_attempt_id")
            draft_value = {
                "schema_version": 1,
                "receipt_kind": "unpublished_archive_build",
                "publication_version": PUBLICATION_VERSION,
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "builder": builder_receipt,
                "reduced_json": reduced_receipt,
                "privacy_review": privacy_review,
                "github_release": github_release,
                "analysis_id": reduced["analysis_id"],
                "analysis_binding_sha256": fresh["analysis_binding_sha256"],
                "primary_numeric": fresh["primary_numeric"],
                "attempts": [
                    {
                        **_ledger_projection(
                            snapshot,
                            ledger_item,
                            selected,
                            sensitive_scans[snapshot.raw_attempt_id],
                        ),
                        "archive": built[snapshot.raw_attempt_id],
                    }
                    for snapshot, ledger_item in zip(snapshots, fresh["attempt_ledger"])
                ],
                "publication_gate": (
                    "not remotely verified; do not commit this draft receipt"
                ),
            }
            draft_descriptor, draft_temporary = output_directory.create_temporary(
                draft.name
            )
            draft_stat = os.fstat(draft_descriptor)
            temporary_identities[draft_temporary] = (
                draft_stat.st_dev,
                draft_stat.st_ino,
            )
            with os.fdopen(draft_descriptor, "wb") as handle:
                handle.write(_render_json(draft_value))
                handle.flush()
                os.fsync(handle.fileno())
            if (
                _file_receipt(reduced_path, logical_path=_logical_path(reduced_path))
                != reduced_receipt
            ):
                raise PublicationError("reduced systems result changed while building")
            if (
                _file_receipt(builder_path, logical_path=_logical_path(builder_path))
                != builder_receipt
            ):
                raise PublicationError("publication builder changed while running")
            if (
                _validate_privacy_review(
                    privacy_review_receipt,
                    snapshots=snapshots,
                    sensitive_scans=sensitive_scans,
                )
                != privacy_review
            ):
                raise PublicationError("privacy review receipt changed while building")
            _publish_bundle(
                output_directory,
                [
                    (temporary_archives[raw_id], archives[raw_id].name)
                    for raw_id in EXPECTED_ATTEMPT_IDS
                ],
                (draft_temporary, draft.name),
            )
            return draft_value
        finally:
            cleanup_errors: list[str] = []
            for temporary, identity in temporary_identities.items():
                try:
                    output_directory.cleanup_if_same(temporary, identity)
                except BaseException as exc:
                    cleanup_errors.append(str(exc))
            try:
                output_directory.fsync()
            except BaseException as exc:
                cleanup_errors.append(str(exc))
            if cleanup_errors:
                raise PublicationError(
                    "archive transaction temporary cleanup failed: "
                    + "; ".join(cleanup_errors)
                )


_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class _NoAutomaticRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_without_redirect(request: urllib.request.Request, *, timeout: float):
    opener = urllib.request.build_opener(_NoAutomaticRedirect())
    try:
        return opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code in _REDIRECT_STATUS_CODES:
            return exc
        raise


def _validate_https_hop(uri: str, *, allowed_hosts: set[str] | None = None) -> str:
    parsed = urlsplit(uri)
    try:
        port = parsed.port
    except ValueError as exc:
        raise PublicationError("durable URI redirect hop is unsafe") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise PublicationError("durable URI redirect hop is unsafe")
    if allowed_hosts is not None and parsed.hostname not in allowed_hosts:
        raise PublicationError("durable URI redirect host is not approved")
    return uri


def _stream_remote_identity_direct(
    uri: str, *, expected_bytes: int, expected_sha256: str
) -> dict[str, Any]:
    digest = hashlib.sha256()
    byte_count = 0
    started = time.monotonic()
    deadline = started + REMOTE_TOTAL_TIMEOUT_SECONDS
    current_uri = _validate_https_hop(uri, allowed_hosts={"github.com"})
    visited = {current_uri}
    redirect_count = 0
    redirect_chain: list[dict[str, Any]] = []
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PublicationError("durable URI verification exceeded total time")
            request = urllib.request.Request(
                current_uri,
                headers={
                    "User-Agent": ("rules-as-programs-eacl2027-publication-verifier/1"),
                    "Accept": "application/octet-stream",
                    "Accept-Encoding": "identity",
                },
            )
            response = _open_without_redirect(
                request,
                timeout=min(REMOTE_CONNECT_TIMEOUT_SECONDS, remaining),
            )
            with response:
                if time.monotonic() > deadline:
                    raise PublicationError(
                        "durable URI verification exceeded total time"
                    )
                status = int(getattr(response, "status", response.getcode()))
                response_uri = _validate_https_hop(
                    str(response.geturl()), allowed_hosts=GITHUB_DOWNLOAD_HOSTS
                )
                if response_uri != current_uri:
                    raise PublicationError(
                        "nonredirect response URL differs from the requested hop"
                    )
                if status in _REDIRECT_STATUS_CODES:
                    get_all = getattr(response.headers, "get_all", None)
                    locations = (
                        get_all("Location", [])
                        if get_all is not None
                        else [response.headers.get("Location")]
                    )
                    locations = [item for item in locations if item is not None]
                    if len(locations) != 1:
                        raise PublicationError(
                            "durable URI redirect must have exactly one Location"
                        )
                    next_uri = _validate_https_hop(
                        urljoin(current_uri, str(locations[0])),
                        allowed_hosts=GITHUB_DOWNLOAD_HOSTS,
                    )
                    current_host = urlsplit(current_uri).hostname
                    next_host = urlsplit(next_uri).hostname
                    allowed_transitions = {
                        "github.com": GITHUB_DOWNLOAD_HOSTS,
                        "objects.githubusercontent.com": {
                            "objects.githubusercontent.com",
                            "release-assets.githubusercontent.com",
                        },
                        "release-assets.githubusercontent.com": {
                            "release-assets.githubusercontent.com"
                        },
                    }
                    if next_host not in allowed_transitions.get(
                        str(current_host), set()
                    ):
                        raise PublicationError(
                            "durable URI redirect transition is not approved"
                        )
                    redirect_chain.append(
                        {
                            "http_status": status,
                            "from_host": current_host,
                            "to_host": next_host,
                        }
                    )
                    redirect_count += 1
                    if redirect_count > REMOTE_MAX_REDIRECTS or next_uri in visited:
                        raise PublicationError(
                            "durable URI redirect chain is cyclic or too long"
                        )
                    visited.add(next_uri)
                    current_uri = next_uri
                    continue
                if status != 200:
                    raise PublicationError(f"durable URI returned HTTP {status}: {uri}")
                final_url = response_uri
                final_parsed = urlsplit(final_url)
                length_value = response.headers.get("Content-Length")
                content_length = int(length_value) if length_value is not None else None
                content_encoding = response.headers.get("Content-Encoding")
                if content_encoding is not None and content_encoding.lower() not in {
                    "",
                    "identity",
                }:
                    raise PublicationError(f"durable URI used content encoding: {uri}")
                if content_length is not None and content_length != expected_bytes:
                    raise PublicationError(
                        f"durable URI Content-Length mismatch: {uri}"
                    )
                while True:
                    if getattr(response, "fp", object()) is None:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise PublicationError(
                            "durable URI verification exceeded total time"
                        )
                    read_timeout = min(REMOTE_READ_TIMEOUT_SECONDS, remaining)
                    sockets = (
                        getattr(
                            getattr(getattr(response, "fp", None), "raw", None),
                            "_sock",
                            None,
                        ),
                        getattr(getattr(response, "fp", None), "_sock", None),
                        getattr(response, "_sock", None),
                    )
                    active_socket = next(
                        (item for item in sockets if hasattr(item, "settimeout")),
                        None,
                    )
                    if active_socket is None:
                        raise PublicationError(
                            "durable URI response cannot enforce a bounded read timeout"
                        )
                    active_socket.settimeout(read_timeout)
                    read_once = getattr(response, "read1", None)
                    if read_once is None:
                        raise PublicationError(
                            "durable URI response does not support bounded single reads"
                        )
                    chunk = read_once(1024 * 1024)
                    if time.monotonic() > deadline:
                        raise PublicationError(
                            "durable URI verification exceeded total time"
                        )
                    if not chunk:
                        break
                    byte_count += len(chunk)
                    if byte_count > expected_bytes:
                        raise PublicationError(
                            f"durable URI exceeds archive size: {uri}"
                        )
                    digest.update(chunk)
                break
    except PublicationError:
        raise
    except (
        OSError,
        ValueError,
        urllib.error.URLError,
        http.client.HTTPException,
    ) as exc:
        raise PublicationError(f"could not verify durable URI: {uri}") from exc
    observed_sha256 = digest.hexdigest()
    if byte_count != expected_bytes or observed_sha256 != expected_sha256:
        raise PublicationError(f"durable URI bytes differ from local archive: {uri}")
    return {
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "http_status": 200,
        "requested_host": urlsplit(uri).hostname,
        "final_host": final_parsed.hostname,
        "redirected": redirect_count > 0,
        "redirect_count": redirect_count,
        "redirect_chain": redirect_chain,
        "response_content_length": content_length,
        "content_encoding": content_encoding,
        "bytes": byte_count,
        "sha256": observed_sha256,
        "exact_match": True,
        "elapsed_seconds": time.monotonic() - started,
        "connect_timeout_seconds": REMOTE_CONNECT_TIMEOUT_SECONDS,
        "read_timeout_seconds": REMOTE_READ_TIMEOUT_SECONDS,
        "total_timeout_seconds": REMOTE_TOTAL_TIMEOUT_SECONDS,
    }


_HTTPS_WORKER_MAX_INPUT_BYTES = 64 * 1024
_HTTPS_WORKER_MAX_OUTPUT_BYTES = 1024 * 1024
_GITHUB_API_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _strict_json_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PublicationError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"{label} must be a JSON object")
    return value


def _response_socket(response: Any):
    candidates = (
        getattr(
            getattr(getattr(response, "fp", None), "raw", None),
            "_sock",
            None,
        ),
        getattr(getattr(response, "fp", None), "_sock", None),
        getattr(response, "_sock", None),
    )
    return next(
        (candidate for candidate in candidates if hasattr(candidate, "settimeout")),
        None,
    )


def _fetch_github_api_json_direct(
    coordinates: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_coordinates = _github_release_coordinates(
        owner=str(coordinates.get("owner", "")),
        repository=str(coordinates.get("repository", "")),
        tag=str(coordinates.get("tag", "")),
    )
    if dict(coordinates) != expected_coordinates:
        raise PublicationError("GitHub release coordinates have unexpected fields")
    endpoint_path = (
        f"/repos/{quote(expected_coordinates['owner'], safe='')}"
        f"/{quote(expected_coordinates['repository'], safe='')}"
        f"/releases/tags/{quote(expected_coordinates['tag'], safe='')}"
    )
    endpoint = f"https://api.github.com{endpoint_path}"
    started = time.monotonic()
    deadline = started + REMOTE_TOTAL_TIMEOUT_SECONDS
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    byte_count = 0
    try:
        request = urllib.request.Request(
            endpoint,
            headers={
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "User-Agent": "rules-as-programs-eacl2027-publication-verifier/1",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        response = _open_without_redirect(
            request,
            timeout=min(
                REMOTE_CONNECT_TIMEOUT_SECONDS,
                max(0.001, deadline - time.monotonic()),
            ),
        )
        with response:
            status = int(getattr(response, "status", response.getcode()))
            if status in _REDIRECT_STATUS_CODES:
                raise PublicationError("GitHub release API unexpectedly redirected")
            if status != 200:
                raise PublicationError(f"GitHub release API returned HTTP {status}")
            parsed_response = urlsplit(str(response.geturl()))
            if (
                parsed_response.scheme != "https"
                or parsed_response.hostname != "api.github.com"
                or parsed_response.port not in {None, 443}
                or parsed_response.username is not None
                or parsed_response.password is not None
                or parsed_response.query
                or parsed_response.fragment
                or parsed_response.path != endpoint_path
            ):
                raise PublicationError("GitHub release API response URL changed")
            content_encoding = response.headers.get("Content-Encoding")
            if content_encoding is not None and content_encoding.lower() not in {
                "",
                "identity",
            }:
                raise PublicationError("GitHub release API used content encoding")
            length_value = response.headers.get("Content-Length")
            content_length = int(length_value) if length_value is not None else None
            if content_length is not None and (
                content_length < 0 or content_length > _GITHUB_API_MAX_RESPONSE_BYTES
            ):
                raise PublicationError("GitHub release API response is too large")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PublicationError("GitHub release API exceeded total time")
                active_socket = _response_socket(response)
                if active_socket is None:
                    raise PublicationError(
                        "GitHub release API cannot enforce a bounded read timeout"
                    )
                active_socket.settimeout(min(REMOTE_READ_TIMEOUT_SECONDS, remaining))
                read_once = getattr(response, "read1", None)
                if read_once is None:
                    raise PublicationError(
                        "GitHub release API does not support bounded single reads"
                    )
                chunk = read_once(1024 * 1024)
                if time.monotonic() > deadline:
                    raise PublicationError("GitHub release API exceeded total time")
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > _GITHUB_API_MAX_RESPONSE_BYTES:
                    raise PublicationError("GitHub release API response is too large")
                chunks.append(chunk)
                digest.update(chunk)
    except PublicationError:
        raise
    except (
        OSError,
        ValueError,
        urllib.error.URLError,
        http.client.HTTPException,
    ) as exc:
        raise PublicationError("could not verify GitHub release API metadata") from exc
    if content_length is not None and byte_count != content_length:
        raise PublicationError("GitHub release API Content-Length mismatch")
    body = _strict_json_bytes(b"".join(chunks), label="GitHub release API response")
    return body, {
        "api_version": GITHUB_API_VERSION,
        "endpoint_host": "api.github.com",
        "endpoint_path": endpoint_path,
        "http_status": 200,
        "content_encoding": content_encoding,
        "response_content_length": content_length,
        "bytes": byte_count,
        "sha256": digest.hexdigest(),
    }


def _normalize_expected_assets(
    expected_assets: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in expected_assets:
        if not isinstance(item, Mapping) or set(item) != {"name", "bytes", "sha256"}:
            raise PublicationError("expected GitHub asset binding is malformed")
        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or name in names
            or type(byte_count) is not int
            or byte_count < 0
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise PublicationError("expected GitHub asset binding is invalid")
        names.add(name)
        normalized.append({"name": name, "bytes": byte_count, "sha256": digest})
    if not normalized:
        raise PublicationError("at least one GitHub release asset is required")
    return normalized


def _github_release_metadata_direct(
    coordinates: Mapping[str, Any],
    expected_assets: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    normalized_assets = _normalize_expected_assets(expected_assets)
    body, response_receipt = _fetch_github_api_json_direct(coordinates)
    release_id = body.get("id")
    tag_name = body.get("tag_name")
    draft = body.get("draft")
    immutable_present = "immutable" in body
    immutable = body.get("immutable") if immutable_present else None
    assets = body.get("assets")
    if (
        type(release_id) is not int
        or release_id <= 0
        or tag_name != coordinates["tag"]
        or draft is not False
        or (immutable_present and immutable is not True)
        or not isinstance(assets, list)
    ):
        raise PublicationError("GitHub release API metadata is not publication-ready")
    assets_by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            raise PublicationError("GitHub release API returned a malformed asset")
        name = asset.get("name")
        if isinstance(name, str) and name in {
            item["name"] for item in normalized_assets
        }:
            if name in assets_by_name:
                raise PublicationError(
                    "GitHub release API returned duplicate asset names"
                )
            assets_by_name[name] = asset
    selected_assets: list[dict[str, Any]] = []
    for expected in normalized_assets:
        asset = assets_by_name.get(expected["name"])
        if asset is None:
            raise PublicationError(
                f"GitHub release asset is missing: {expected['name']}"
            )
        canonical_uri = _canonical_github_asset_uri(coordinates, expected["name"])
        asset_id = asset.get("id")
        projected = {
            "id": asset_id,
            "name": asset.get("name"),
            "state": asset.get("state"),
            "size": asset.get("size"),
            "digest": asset.get("digest"),
            "browser_download_url": asset.get("browser_download_url"),
        }
        if (
            type(asset_id) is not int
            or asset_id <= 0
            or projected["state"] != "uploaded"
            or type(projected["size"]) is not int
            or projected["size"] != expected["bytes"]
            or projected["digest"] != f"sha256:{expected['sha256']}"
            or projected["browser_download_url"] != canonical_uri
        ):
            raise PublicationError(
                f"GitHub release asset metadata differs from local archive: {expected['name']}"
            )
        selected_assets.append(projected)
    verification = {
        "schema_version": 1,
        "verification_kind": "github_release_api_metadata_v1",
        "verified_utc": datetime.now(timezone.utc).isoformat(),
        "github_release": dict(coordinates),
        "api_response": response_receipt,
        "release": {
            "id": release_id,
            "tag_name": tag_name,
            "draft": draft,
            "immutable_field_present": immutable_present,
            "immutable": immutable,
            "asset_count": len(assets),
        },
        "assets": selected_assets,
    }
    return _validate_github_release_verification(
        verification,
        coordinates=coordinates,
        expected_assets=normalized_assets,
    )


def _validate_github_release_verification(
    value: Mapping[str, Any],
    *,
    coordinates: Mapping[str, Any],
    expected_assets: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    normalized_assets = _normalize_expected_assets(expected_assets)
    if set(value) != {
        "schema_version",
        "verification_kind",
        "verified_utc",
        "github_release",
        "api_response",
        "release",
        "assets",
    }:
        raise PublicationError("GitHub release verification has unexpected fields")
    _validate_aware_timestamp(
        value.get("verified_utc"), label="GitHub release verified_utc"
    )
    if (
        value.get("schema_version") != 1
        or value.get("verification_kind") != "github_release_api_metadata_v1"
        or value.get("github_release") != dict(coordinates)
    ):
        raise PublicationError("GitHub release verification binding is invalid")
    response = value.get("api_response")
    expected_endpoint_path = (
        f"/repos/{quote(str(coordinates['owner']), safe='')}"
        f"/{quote(str(coordinates['repository']), safe='')}"
        f"/releases/tags/{quote(str(coordinates['tag']), safe='')}"
    )
    if (
        not isinstance(response, dict)
        or set(response)
        != {
            "api_version",
            "endpoint_host",
            "endpoint_path",
            "http_status",
            "content_encoding",
            "response_content_length",
            "bytes",
            "sha256",
        }
        or response.get("api_version") != GITHUB_API_VERSION
        or response.get("endpoint_host") != "api.github.com"
        or response.get("endpoint_path") != expected_endpoint_path
        or response.get("http_status") != 200
        or response.get("content_encoding") not in {None, "", "identity"}
        or type(response.get("bytes")) is not int
        or int(response["bytes"]) < 0
        or type(response.get("response_content_length")) not in {int, type(None)}
        or (
            response.get("response_content_length") is not None
            and response.get("response_content_length") != response.get("bytes")
        )
        or not isinstance(response.get("sha256"), str)
        or SHA256_PATTERN.fullmatch(str(response["sha256"])) is None
    ):
        raise PublicationError("GitHub release API response receipt is invalid")
    release = value.get("release")
    if (
        not isinstance(release, dict)
        or set(release)
        != {
            "id",
            "tag_name",
            "draft",
            "immutable_field_present",
            "immutable",
            "asset_count",
        }
        or type(release.get("id")) is not int
        or int(release["id"]) <= 0
        or release.get("tag_name") != coordinates["tag"]
        or release.get("draft") is not False
        or type(release.get("immutable_field_present")) is not bool
        or (
            release.get("immutable_field_present") is True
            and release.get("immutable") is not True
        )
        or (
            release.get("immutable_field_present") is False
            and release.get("immutable") is not None
        )
        or type(release.get("asset_count")) is not int
        or int(release["asset_count"]) < len(normalized_assets)
    ):
        raise PublicationError("GitHub release projection is invalid")
    assets = value.get("assets")
    if not isinstance(assets, list) or len(assets) != len(normalized_assets):
        raise PublicationError("GitHub release asset projection is incomplete")
    validated_assets: list[dict[str, Any]] = []
    for observed, expected in zip(assets, normalized_assets):
        canonical_uri = _canonical_github_asset_uri(coordinates, expected["name"])
        if (
            not isinstance(observed, dict)
            or set(observed)
            != {"id", "name", "state", "size", "digest", "browser_download_url"}
            or type(observed.get("id")) is not int
            or int(observed["id"]) <= 0
            or observed.get("name") != expected["name"]
            or observed.get("state") != "uploaded"
            or type(observed.get("size")) is not int
            or observed.get("size") != expected["bytes"]
            or observed.get("digest") != f"sha256:{expected['sha256']}"
            or observed.get("browser_download_url") != canonical_uri
        ):
            raise PublicationError("GitHub release asset projection is invalid")
        validated_assets.append(dict(observed))
    return {
        **dict(value),
        "api_response": dict(response),
        "release": dict(release),
        "assets": validated_assets,
    }


def _run_https_worker(request: Mapping[str, Any]) -> dict[str, Any]:
    request_bytes = _canonical_json_bytes(dict(request))
    if len(request_bytes) > _HTTPS_WORKER_MAX_INPUT_BYTES:
        raise PublicationError("HTTPS verification request is too large")
    started = time.monotonic()
    deadline = started + REMOTE_TOTAL_TIMEOUT_SECONDS
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(REPO_ROOT),
    }
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "experiments.eacl2027.build_scaling_faults_publication",
                "_https-worker",
            ],
            cwd=REPO_ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, REMOTE_TOTAL_TIMEOUT_SECONDS)
        stdout, _stderr = process.communicate(input=request_bytes, timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        if process is not None:
            process.kill()
            process.communicate()
        raise PublicationError(
            "HTTPS verification exceeded its hard total deadline"
        ) from exc
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        raise
    if process.returncode != 0:
        raise PublicationError("isolated HTTPS verification worker failed")
    if len(stdout) > _HTTPS_WORKER_MAX_OUTPUT_BYTES:
        raise PublicationError("isolated HTTPS verification result is too large")
    envelope = _strict_json_bytes(stdout, label="HTTPS verification worker result")
    if set(envelope) == {"schema_version", "ok", "error"}:
        if (
            envelope.get("schema_version") != 1
            or envelope.get("ok") is not False
            or not isinstance(envelope.get("error"), str)
            or not envelope["error"]
        ):
            raise PublicationError("HTTPS verification worker error is malformed")
        raise PublicationError(str(envelope["error"]))
    if (
        set(envelope) != {"schema_version", "ok", "result"}
        or envelope.get("schema_version") != 1
        or envelope.get("ok") is not True
        or not isinstance(envelope.get("result"), dict)
    ):
        raise PublicationError("HTTPS verification worker result is malformed")
    return dict(envelope["result"])


def _validate_remote_verification(
    value: Mapping[str, Any],
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> dict[str, Any]:
    if set(value) != {
        "verified_utc",
        "http_status",
        "requested_host",
        "final_host",
        "redirected",
        "redirect_count",
        "redirect_chain",
        "response_content_length",
        "content_encoding",
        "bytes",
        "sha256",
        "exact_match",
        "elapsed_seconds",
        "connect_timeout_seconds",
        "read_timeout_seconds",
        "total_timeout_seconds",
    }:
        raise PublicationError("remote archive verification has unexpected fields")
    _validate_aware_timestamp(
        value.get("verified_utc"), label="remote archive verified_utc"
    )
    redirect_count = value.get("redirect_count")
    redirect_chain = value.get("redirect_chain")
    if (
        value.get("http_status") != 200
        or value.get("requested_host") != "github.com"
        or value.get("final_host") not in GITHUB_DOWNLOAD_HOSTS
        or type(value.get("redirected")) is not bool
        or type(redirect_count) is not int
        or redirect_count < 0
        or redirect_count > REMOTE_MAX_REDIRECTS
        or value.get("redirected") != (redirect_count > 0)
        or not isinstance(redirect_chain, list)
        or len(redirect_chain) != redirect_count
        or type(value.get("response_content_length")) not in {int, type(None)}
        or value.get("content_encoding") not in {None, "", "identity"}
        or value.get("bytes") != expected_bytes
        or value.get("sha256") != expected_sha256
        or value.get("exact_match") is not True
        or type(value.get("elapsed_seconds")) not in {int, float}
        or float(value["elapsed_seconds"]) < 0
        or value.get("connect_timeout_seconds") != REMOTE_CONNECT_TIMEOUT_SECONDS
        or value.get("read_timeout_seconds") != REMOTE_READ_TIMEOUT_SECONDS
        or value.get("total_timeout_seconds") != REMOTE_TOTAL_TIMEOUT_SECONDS
    ):
        raise PublicationError("remote archive verification binding is invalid")
    previous_host = "github.com"
    allowed_transitions = {
        "github.com": GITHUB_DOWNLOAD_HOSTS,
        "objects.githubusercontent.com": {
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        },
        "release-assets.githubusercontent.com": {
            "release-assets.githubusercontent.com"
        },
    }
    for hop in redirect_chain:
        if (
            not isinstance(hop, dict)
            or set(hop) != {"http_status", "from_host", "to_host"}
            or hop.get("http_status") not in _REDIRECT_STATUS_CODES
            or hop.get("from_host") != previous_host
            or hop.get("to_host") not in allowed_transitions.get(previous_host, set())
        ):
            raise PublicationError("remote archive redirect audit is invalid")
        previous_host = str(hop["to_host"])
    if previous_host != value.get("final_host"):
        raise PublicationError("remote archive final host differs from redirect audit")
    content_length = value.get("response_content_length")
    if content_length is not None and content_length != expected_bytes:
        raise PublicationError("remote archive Content-Length binding is invalid")
    return dict(value)


def _stream_remote_identity(
    uri: str, *, expected_bytes: int, expected_sha256: str
) -> dict[str, Any]:
    result = _run_https_worker(
        {
            "schema_version": 1,
            "operation": "download_identity",
            "uri": uri,
            "expected_bytes": expected_bytes,
            "expected_sha256": expected_sha256,
        }
    )
    return _validate_remote_verification(
        result,
        expected_bytes=expected_bytes,
        expected_sha256=expected_sha256,
    )


def _fetch_github_release_metadata(
    coordinates: Mapping[str, Any],
    expected_assets: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    normalized_assets = _normalize_expected_assets(expected_assets)
    result = _run_https_worker(
        {
            "schema_version": 1,
            "operation": "github_release_metadata",
            "github_release": dict(coordinates),
            "expected_assets": normalized_assets,
        }
    )
    return _validate_github_release_verification(
        result,
        coordinates=coordinates,
        expected_assets=normalized_assets,
    )


def _https_worker_main() -> int:
    raw = sys.stdin.buffer.read(_HTTPS_WORKER_MAX_INPUT_BYTES + 1)
    try:
        if len(raw) > _HTTPS_WORKER_MAX_INPUT_BYTES:
            raise PublicationError("HTTPS verification request is too large")
        request = _strict_json_bytes(raw, label="HTTPS verification request")
        operation = request.get("operation")
        if operation == "download_identity":
            if set(request) != {
                "schema_version",
                "operation",
                "uri",
                "expected_bytes",
                "expected_sha256",
            }:
                raise PublicationError("download verification request is malformed")
            uri = request.get("uri")
            expected_bytes = request.get("expected_bytes")
            expected_sha256 = request.get("expected_sha256")
            parsed = urlsplit(str(uri))
            if (
                request.get("schema_version") != 1
                or not isinstance(uri, str)
                or parsed.scheme != "https"
                or parsed.hostname != "github.com"
                or parsed.port not in {None, 443}
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
                or type(expected_bytes) is not int
                or expected_bytes < 0
                or not isinstance(expected_sha256, str)
                or SHA256_PATTERN.fullmatch(expected_sha256) is None
            ):
                raise PublicationError("download verification request is invalid")
            result = _stream_remote_identity_direct(
                uri,
                expected_bytes=expected_bytes,
                expected_sha256=expected_sha256,
            )
        elif operation == "github_release_metadata":
            if (
                set(request)
                != {
                    "schema_version",
                    "operation",
                    "github_release",
                    "expected_assets",
                }
                or request.get("schema_version") != 1
            ):
                raise PublicationError("GitHub metadata request is malformed")
            coordinates = request.get("github_release")
            expected_assets = request.get("expected_assets")
            if not isinstance(coordinates, dict) or not isinstance(
                expected_assets, list
            ):
                raise PublicationError("GitHub metadata request is invalid")
            result = _github_release_metadata_direct(coordinates, expected_assets)
        else:
            raise PublicationError("HTTPS verification operation is unsupported")
        envelope = {"schema_version": 1, "ok": True, "result": result}
    except PublicationError as exc:
        envelope = {"schema_version": 1, "ok": False, "error": str(exc)}
    sys.stdout.buffer.write(_canonical_json_bytes(envelope))
    sys.stdout.buffer.flush()
    return 0


def _validate_draft(
    draft: Mapping[str, Any],
    *,
    builder_receipt: Mapping[str, Any],
    reduced_receipt: Mapping[str, Any],
    fresh: Mapping[str, Any],
    snapshots: Sequence[AttemptSnapshot],
    sensitive_scans: Mapping[str, Mapping[str, Any]],
    privacy_review: Mapping[str, Any],
    github_release: Mapping[str, Any],
    zstd_executable: Path,
    archive_directory: SecureOutputDirectory,
) -> list[dict[str, Any]]:
    if set(draft) != {
        "schema_version",
        "receipt_kind",
        "publication_version",
        "created_utc",
        "builder",
        "reduced_json",
        "privacy_review",
        "github_release",
        "analysis_id",
        "analysis_binding_sha256",
        "primary_numeric",
        "attempts",
        "publication_gate",
    }:
        raise PublicationError("draft receipt has unexpected fields")
    if (
        draft.get("schema_version") != 1
        or draft.get("receipt_kind") != "unpublished_archive_build"
        or draft.get("publication_version") != PUBLICATION_VERSION
        or draft.get("builder") != builder_receipt
        or draft.get("reduced_json") != reduced_receipt
        or draft.get("privacy_review") != privacy_review
        or draft.get("github_release") != github_release
        or draft.get("analysis_id") != fresh["analysis_id"]
        or draft.get("analysis_binding_sha256") != fresh["analysis_binding_sha256"]
        or draft.get("primary_numeric") != fresh["primary_numeric"]
        or draft.get("publication_gate")
        != "not remotely verified; do not commit this draft receipt"
    ):
        raise PublicationError("draft receipt differs from current bound inputs")
    _validate_aware_timestamp(draft.get("created_utc"), label="draft created_utc")
    attempts = draft.get("attempts")
    if not isinstance(attempts, list) or len(attempts) != len(snapshots):
        raise PublicationError("draft receipt has an invalid attempt list")
    selected = fresh["primary_numeric"].get("selected_raw_attempt_id")
    for item, snapshot, ledger_item in zip(
        attempts, snapshots, fresh["attempt_ledger"]
    ):
        if not isinstance(item, dict):
            raise PublicationError("draft attempt entry must be an object")
        archive = item.get("archive")
        projection = _ledger_projection(
            snapshot,
            ledger_item,
            selected,
            sensitive_scans[snapshot.raw_attempt_id],
        )
        if (
            set(item) != set(projection) | {"archive"}
            or {key: item.get(key) for key in projection} != projection
        ):
            raise PublicationError(
                f"draft attempt binding changed: {snapshot.raw_attempt_id}"
            )
        if not isinstance(archive, dict) or set(archive) != {
            "path",
            "bytes",
            "sha256",
            "local_path",
            "format",
            "media_type",
            "durable_uri",
            "manifest",
            "compressor",
            "build_archive_verification",
        }:
            raise PublicationError("draft archive receipt has unexpected fields")
        local_path = Path(str(archive.get("local_path", "")))
        if (
            not local_path.is_absolute()
            or local_path.parent != archive_directory.path
            or local_path.name != archive.get("path")
        ):
            raise PublicationError("local archive is outside its private bundle")
        _require_outside_repo(local_path, label="local archive")
        local_stat = archive_directory.stat(local_path.name)
        if (
            not stat.S_ISREG(local_stat.st_mode)
            or local_stat.st_uid != os.geteuid()
            or stat.S_IMODE(local_stat.st_mode) != 0o444
        ):
            raise PublicationError("local archive must retain immutable mode 0444")
        observed = archive_directory.file_receipt(
            local_path.name, logical_path=local_path.name
        )
        if {key: archive.get(key) for key in ("path", "bytes", "sha256")} != observed:
            raise PublicationError("local archive differs from its draft receipt")
        if (
            archive.get("format") != "tar+zstd"
            or archive.get("media_type") != "application/zstd"
        ):
            raise PublicationError("draft archive format is invalid")
        durable_uri = _validate_durable_uri(
            str(archive.get("durable_uri", "")), local_path.name
        )
        expected_manifest = _attempt_manifest(
            snapshot,
            builder=builder_receipt,
            reduced=reduced_receipt,
            fresh=fresh,
            durable_uri=durable_uri,
            sensitive_scan=sensitive_scans[snapshot.raw_attempt_id],
            privacy_review=privacy_review,
            github_release=github_release,
        )
        manifest_bytes = _render_json(expected_manifest)
        expected_manifest_receipt = {
            "archive_path": f"{_archive_root(snapshot.raw_attempt_id)}/MANIFEST.json",
            "bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        }
        if archive.get("manifest") != expected_manifest_receipt:
            raise PublicationError("draft archive manifest metadata is falsified")
        verification = _verify_attempt_archive(
            local_path,
            snapshot=snapshot,
            manifest_bytes=manifest_bytes,
            zstd_executable=zstd_executable,
            expected_compressor=archive.get("compressor") or {},
            expected_archive=archive,
            archive_directory=archive_directory,
        )
        if archive.get("build_archive_verification") != verification:
            raise PublicationError("draft archive verification metadata is falsified")
        archive["finalize_archive_verification"] = verification
        item["archive"] = archive
    return [dict(item) for item in attempts]


def finalize_publication(
    *,
    attempts_root: Path,
    reduced_json: Path,
    draft_receipt: Path,
    durable_uris: Mapping[str, str],
    index_output: Path,
    privacy_review_receipt: Path,
    github_owner: str,
    github_repository: str,
    github_release_tag: str,
    zstd_executable: Path | None = None,
) -> dict[str, Any]:
    """Verify both remote archives byte-for-byte, then publish the Git index."""

    if set(durable_uris) != set(EXPECTED_ATTEMPT_IDS):
        raise PublicationError("durable URIs must name exactly r01 and r02")
    github_release = _github_release_coordinates(
        owner=github_owner,
        repository=github_repository,
        tag=github_release_tag,
    )
    index = _require_new_output(
        index_output,
        suffix=".json",
        label="publication index",
        defer_absence_to_transaction_recovery=True,
    )
    attempts_path = _validated_attempts_root(attempts_root)
    if index.is_relative_to(attempts_path):
        raise PublicationError(
            "publication index must be outside the raw attempt ledger"
        )
    with SecureOutputDirectory(
        index.parent, private=False, label="publication index directory"
    ) as recovery_directory:
        recovered = _recover_bundle_transaction(
            recovery_directory,
            marker_destination=index.name,
            expected_destinations=[index.name],
        )
        if recovered == "committed":
            raise PublicationError(
                "a prior publication index transaction already committed; output retained"
            )
    reduced_path = _require_regular(
        reduced_json.expanduser().absolute(), label="reduced systems result"
    )
    draft_path = _require_regular(
        draft_receipt.expanduser().absolute(), label="draft receipt"
    )
    _require_outside_repo(draft_path, label="draft receipt")
    reduced, fresh, reduced_receipt = _validate_reduced_result(
        attempts_path, reduced_path
    )
    snapshots = _snapshot_ledger(attempts_path)
    sensitive_scans = _scan_ledger(snapshots)
    privacy_review = _validate_privacy_review(
        privacy_review_receipt,
        snapshots=snapshots,
        sensitive_scans=sensitive_scans,
    )
    executable_value = str(zstd_executable) if zstd_executable else shutil.which("zstd")
    if not executable_value:
        raise PublicationError("zstd is required to verify tar.zst archives")
    executable = Path(executable_value).expanduser().absolute()
    builder_path = Path(__file__).resolve(strict=True)
    builder_receipt = _file_receipt(
        builder_path, logical_path=_logical_path(builder_path)
    )
    with SecureOutputDirectory(
        draft_path.parent, private=True, label="archive bundle directory"
    ) as archive_directory:
        _require_outside_repo(archive_directory.path, label="archive bundle directory")
        archive_directory.verify_path_binding()
        draft_stat = archive_directory.stat(draft_path.name)
        if (
            not stat.S_ISREG(draft_stat.st_mode)
            or draft_stat.st_uid != os.geteuid()
            or stat.S_IMODE(draft_stat.st_mode) != 0o444
        ):
            raise PublicationError("draft receipt must retain immutable mode 0444")
        draft, draft_file_receipt = archive_directory.load_json_with_receipt(
            draft_path.name,
            label="draft receipt",
            logical_path=draft_path.name,
        )
        attempts = _validate_draft(
            draft,
            builder_receipt=builder_receipt,
            reduced_receipt=reduced_receipt,
            fresh=fresh,
            snapshots=snapshots,
            sensitive_scans=sensitive_scans,
            privacy_review=privacy_review,
            github_release=github_release,
            zstd_executable=executable,
            archive_directory=archive_directory,
        )

        expected_assets = [
            {
                "name": str(item["archive"]["path"]),
                "bytes": int(item["archive"]["bytes"]),
                "sha256": str(item["archive"]["sha256"]),
            }
            for item in attempts
        ]
        github_release_verification = _fetch_github_release_metadata(
            github_release,
            expected_assets,
        )
        github_assets_by_name = {
            str(asset["name"]): dict(asset)
            for asset in github_release_verification["assets"]
        }

        finalized_attempts: list[dict[str, Any]] = []
        local_archives: list[tuple[str, dict[str, Any]]] = []
        for raw_id, item in zip(EXPECTED_ATTEMPT_IDS, attempts):
            archive = dict(item.pop("archive"))
            local_path = Path(str(archive.pop("local_path")))
            local_archives.append((local_path.name, dict(archive)))
            uri = _validate_durable_uri(durable_uris[raw_id], str(archive["path"]))
            if uri != _canonical_github_asset_uri(github_release, str(archive["path"])):
                raise PublicationError(
                    "final URI is not the canonical bound GitHub release asset URL"
                )
            if archive.get("durable_uri") != uri:
                raise PublicationError(
                    "final URI differs from the archive manifest binding"
                )
            archive["github_asset"] = github_assets_by_name[str(archive["path"])]
            archive["remote_verification"] = _stream_remote_identity(
                uri,
                expected_bytes=int(archive["bytes"]),
                expected_sha256=str(archive["sha256"]),
            )
            item["archive"] = archive
            finalized_attempts.append(item)
        _post_archive_validate(snapshots, attempts_path)
        if (
            _file_receipt(builder_path, logical_path=_logical_path(builder_path))
            != builder_receipt
        ):
            raise PublicationError("publication finalizer changed while running")
        if (
            _file_receipt(reduced_path, logical_path=_logical_path(reduced_path))
            != reduced_receipt
        ):
            raise PublicationError(
                "reduced systems result changed during remote verification"
            )
        if (
            archive_directory.file_receipt(
                draft_path.name, logical_path=draft_path.name
            )
            != draft_file_receipt
        ):
            raise PublicationError("draft receipt changed during remote verification")
        for local_name, archive in local_archives:
            observed = archive_directory.file_receipt(
                local_name, logical_path=local_name
            )
            if {
                key: archive.get(key) for key in ("path", "bytes", "sha256")
            } != observed:
                raise PublicationError(
                    "local archive changed during remote verification"
                )
        if (
            _validate_privacy_review(
                privacy_review_receipt,
                snapshots=snapshots,
                sensitive_scans=sensitive_scans,
            )
            != privacy_review
        ):
            raise PublicationError(
                "privacy review receipt changed during remote verification"
            )
        archive_directory.verify_path_binding()

        index_value = {
            "schema_version": 1,
            "receipt_kind": "verified_attempt_publication_index",
            "publication_version": PUBLICATION_VERSION,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "protocol_amendment": "protocol-v3-amendment-007",
            "builder": builder_receipt,
            "archive_build_receipt": draft_file_receipt,
            "reduced_json": reduced_receipt,
            "privacy_review": privacy_review,
            "github_release": github_release,
            "github_release_verification": github_release_verification,
            "analysis_id": reduced["analysis_id"],
            "analysis_binding_sha256": fresh["analysis_binding_sha256"],
            "primary_numeric": fresh["primary_numeric"],
            "attempts": finalized_attempts,
            "publication_scope": {
                "raw_attempt_trees": list(EXPECTED_ATTEMPT_IDS),
                "publication_claims": [
                    snapshot.raw_attempt_id
                    for snapshot in snapshots
                    if snapshot.claim_path is not None
                ],
                "one_archive_per_attempt": True,
                "raw_attempts_claims_and_archives_outside_git": True,
                "remote_bytes_verified_before_index_publication": True,
                "committable_artifacts": [
                    _logical_path(reduced_path),
                    _logical_path(index),
                ],
            },
        }

    with SecureOutputDirectory(
        index.parent, private=False, label="publication index directory"
    ) as index_directory:
        index_parent = index_directory.path.resolve(strict=True)
        if index_parent == attempts_path or index_parent.is_relative_to(attempts_path):
            raise PublicationError(
                "publication index directory must be outside the raw attempt ledger"
            )
        index_directory.verify_path_binding()
        recovered = _recover_bundle_transaction(
            index_directory,
            marker_destination=index.name,
            expected_destinations=[index.name],
        )
        if recovered == "committed":
            raise PublicationError(
                "a prior publication index transaction already committed; output retained"
            )
        index_directory.require_absent(index, label="publication index")
        descriptor, temporary = index_directory.create_temporary(index.name)
        temporary_stat = os.fstat(descriptor)
        temporary_identity = (temporary_stat.st_dev, temporary_stat.st_ino)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(_render_json(index_value))
                handle.flush()
                os.fsync(handle.fileno())
            _publish_bundle(index_directory, [], (temporary, index.name))
        finally:
            cleanup_errors: list[str] = []
            try:
                index_directory.cleanup_if_same(temporary, temporary_identity)
            except BaseException as exc:
                cleanup_errors.append(str(exc))
            try:
                index_directory.fsync()
            except BaseException as exc:
                cleanup_errors.append(str(exc))
            if cleanup_errors:
                raise PublicationError(
                    "index transaction temporary cleanup failed: "
                    + "; ".join(cleanup_errors)
                )
    return index_value


def main() -> int:
    if sys.argv[1:] == ["_https-worker"]:
        return _https_worker_main()
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build two local immutable archives")
    build.add_argument("--attempts-root", type=Path, required=True)
    build.add_argument("--reduced-json", type=Path, required=True)
    build.add_argument("--r01-archive-output", type=Path, required=True)
    build.add_argument("--r02-archive-output", type=Path, required=True)
    build.add_argument("--r01-durable-uri", required=True)
    build.add_argument("--r02-durable-uri", required=True)
    build.add_argument("--draft-receipt-output", type=Path, required=True)
    build.add_argument("--privacy-review-receipt", type=Path, required=True)
    build.add_argument("--github-owner", required=True)
    build.add_argument("--github-repository", required=True)
    build.add_argument("--github-release-tag", required=True)
    build.add_argument("--zstd", type=Path)
    finalize = subparsers.add_parser(
        "finalize", help="verify durable URIs and write the committable index"
    )
    finalize.add_argument("--attempts-root", type=Path, required=True)
    finalize.add_argument("--reduced-json", type=Path, required=True)
    finalize.add_argument("--draft-receipt", type=Path, required=True)
    finalize.add_argument("--r01-durable-uri", required=True)
    finalize.add_argument("--r02-durable-uri", required=True)
    finalize.add_argument("--index-output", type=Path, required=True)
    finalize.add_argument("--privacy-review-receipt", type=Path, required=True)
    finalize.add_argument("--github-owner", required=True)
    finalize.add_argument("--github-repository", required=True)
    finalize.add_argument("--github-release-tag", required=True)
    finalize.add_argument("--zstd", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "build":
            value = build_archives(
                attempts_root=args.attempts_root,
                reduced_json=args.reduced_json,
                archive_outputs={
                    EXPECTED_ATTEMPT_IDS[0]: args.r01_archive_output,
                    EXPECTED_ATTEMPT_IDS[1]: args.r02_archive_output,
                },
                durable_uris={
                    EXPECTED_ATTEMPT_IDS[0]: args.r01_durable_uri,
                    EXPECTED_ATTEMPT_IDS[1]: args.r02_durable_uri,
                },
                draft_receipt_output=args.draft_receipt_output,
                privacy_review_receipt=args.privacy_review_receipt,
                github_owner=args.github_owner,
                github_repository=args.github_repository,
                github_release_tag=args.github_release_tag,
                zstd_executable=args.zstd,
            )
        else:
            value = finalize_publication(
                attempts_root=args.attempts_root,
                reduced_json=args.reduced_json,
                draft_receipt=args.draft_receipt,
                durable_uris={
                    EXPECTED_ATTEMPT_IDS[0]: args.r01_durable_uri,
                    EXPECTED_ATTEMPT_IDS[1]: args.r02_durable_uri,
                },
                index_output=args.index_output,
                privacy_review_receipt=args.privacy_review_receipt,
                github_owner=args.github_owner,
                github_repository=args.github_repository,
                github_release_tag=args.github_release_tag,
                zstd_executable=args.zstd,
            )
    except PublicationError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
