#!/usr/bin/env python3
"""Scaffold the repository-uniform, independently authored held-out study.

This module creates study packets and cryptographic phase receipts.  It does
not author specifications, cases, labels, deterministic baselines, or model
predictions.  Substantive disagreements and failed intended contrasts are
retained in validation reports rather than filtered from the study.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent
STUDY_ID = "rap-reporails-repository-uniform-heldout-v1"
PACKET_VERSION = 1
SEED = 20270902
SCREENING_BATCH_SIZE = 80
TARGET_ELIGIBLE_RULES = 24
PINNED_SOURCE_RECORDS = 2814
PINNED_PROJECT_VALUES = 399
SCREENERS_PER_RECORD = 2
LABELERS_PER_CASE = 2
INTENDED_PAIRS_PER_RULE = 8

PINNED_SOURCE_CORPUS = {
    "repository": "reporails/30k-corpus",
    "commit": "00272e946b95765654ef06fe1e7f8ae7aa7e0535",
    "file": "validation_key.csv",
    "file_sha256": "82dd3d2f1c02ae3e4045f4312e4c0b39c5d8f92b427b9e9da842a3e075676130",
    "license": "CC-BY-4.0",
}

CSV_FIELDS = {
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

SUPPORTED_CONTRACTS = {
    "Stop": "/last_assistant_message",
    "PreToolUse": "/tool_input",
    "PostToolUse": "/tool_response",
    "UserPromptSubmit": "/prompt",
}

EXCLUSION_TAXONOMY = (
    {
        "code": "cross_reference_or_incomplete_fragment",
        "description": "The record depends on missing text or is not independently interpretable.",
    },
    {
        "code": "multiple_obligations_not_safely_separable",
        "description": "No single obligation can be extracted without changing meaning.",
    },
    {
        "code": "requires_multiple_events_or_order",
        "description": "Judgment requires multiple events, turns, or their order.",
    },
    {
        "code": "requires_filesystem_or_artifact_state",
        "description": "Judgment requires filesystem, repository, or artifact state.",
    },
    {
        "code": "requires_task_outcome",
        "description": "Judgment requires knowing task success or another outcome.",
    },
    {
        "code": "unsupported_or_no_scalar_trigger_field",
        "description": "No supported trigger exposes the complete signal in one scalar field.",
    },
    {
        "code": "not_behavioral_or_no_contrast",
        "description": "The record is not behavioral or lacks plausible compliant/violating values.",
    },
    {
        "code": "ambiguous_normative_target",
        "description": "The expected behavior cannot be labeled reproducibly.",
    },
    {
        "code": "sensitive_content",
        "description": "The record or extracted atom contains secret or personal data.",
    },
    {
        "code": "other_with_required_explanation",
        "description": "A protocol-level exclusion not captured above; explanation is required.",
    },
)
EXCLUSION_CODES = frozenset(item["code"] for item in EXCLUSION_TAXONOMY)

AUTHORSHIP_KINDS = frozenset(
    {"human", "human_with_agent_assistance", "agent_generated"}
)
OUTCOME_LABELS = frozenset({"OK", "INFO", "WARNING", "CRITICAL", "UNSURE"})

SCREENING_TASK = {
    "unit": (
        "one independent behavioral obligation from the source record; an atom may "
        "be extracted only without changing its meaning"
    ),
    "question": (
        "Can the record's complete normative behavior be judged from exactly one "
        "supported Codex trigger field without hidden, repository, or cross-event context?"
    ),
    "decisions": ["include", "exclude", "uncertain"],
    "eligibility": [
        "one independent obligation exists or one atom is safely separable",
        "the complete signal is one scalar field of exactly one supported trigger",
        "no hidden transcript, filesystem, artifact, task-outcome, or multi-event state is needed",
        "both a compliant and violating field value are plausible",
        "the source and extracted atom contain no secret or personal data",
    ],
    "supported_contracts": SUPPORTED_CONTRACTS,
    "exclusion_taxonomy": EXCLUSION_TAXONOMY,
    "requirements": [
        "Decide independently and do not inspect another screener's response.",
        "For include, supply the whole-record or extracted rule atom plus one trigger and fixed JSON Pointer.",
        "For exclude, select a primary exclusion code; do not silently drop the record.",
        "For uncertain, explain what additional evidence would be needed.",
        "Record authorship provenance exactly; agent-generated work is not human-authored.",
    ],
}

SPEC_TASK = {
    "role": "spec_author",
    "visible": ["source_atom", "observable_contract"],
    "forbidden": [
        "case packets or case responses",
        "label packets or label responses",
        "deterministic baseline source",
        "model predictions",
    ],
    "output": (
        "one RAP specification with exactly four visible examples (two OK and "
        "two finding-level), plus a pre-hidden-case deterministic-or-PAW routing choice"
    ),
    "requirements": [
        "Judge only the declared input field.",
        "Do not seek or use held-out cases or labels.",
        "Record authorship provenance exactly.",
    ],
}

CASE_TASK = {
    "role": "case_author",
    "visible": ["source_atom", "observable_contract"],
    "forbidden": [
        "specification text or embedded examples",
        "label packets or label responses",
        "deterministic baseline source",
        "model predictions",
    ],
    "output": f"exactly {INTENDED_PAIRS_PER_RULE} intended contrast pairs",
    "requirements": [
        "Each pair contains one intended violation and one intended OK input.",
        "Inputs must be exact serialized values for the declared field.",
        "Intended polarity is hidden from labelers and is not a final human label.",
        "Record authorship provenance exactly.",
    ],
}

LABEL_TASK = {
    "role": "labeler",
    "visible": ["source_atom", "observable_contract", "one observed input"],
    "forbidden": [
        "specification text or embedded examples",
        "case-author intent, pair membership, or paired input",
        "other labelers' responses",
        "deterministic baseline source",
        "model predictions",
    ],
    "labels": ["OK", "INFO", "WARNING", "CRITICAL", "UNSURE"],
    "requirements": [
        "Label independently from the source instruction and observed input.",
        "Use UNSURE rather than inventing missing context.",
        "Record authorship provenance exactly.",
    ],
}

BASELINE_TASK = {
    "role": "deterministic_baseline_author",
    "visible": ["source_atom", "observable_contract", "frozen_specification"],
    "forbidden": [
        "case packets or case responses",
        "label packets or label responses",
        "model predictions",
    ],
    "output": "one deterministic baseline implementation, which may abstain",
    "requirements": [
        "Use at most 20 active authoring minutes for this rule.",
        "Freeze exact source bytes before held-out data are unblinded.",
        "Record authorship provenance exactly.",
    ],
}


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation used by every study hash."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _domain_hash(domain: str, *parts: str, seed: int = SEED) -> str:
    encoded = "\0".join((STUDY_ID, str(seed), domain, *parts)).encode("utf-8")
    return sha256_bytes(encoded)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _project_identity(project: str) -> str:
    """Return the protocol's exact, byte-preserving project identity."""

    if project == "":
        raise ValueError("source record has an empty repository/project")
    return project


def _selection_hash(
    kind: str, project: str, record_id: str | None = None, *, seed: int = SEED
) -> str:
    """Implement the frozen v3 selection byte formula exactly."""

    if kind == "record":
        if record_id is None:
            raise ValueError("record selection hash requires record_id")
        parts = (str(seed), "record", project, record_id)
    elif kind == "project":
        if record_id is not None:
            raise ValueError("project selection hash does not accept record_id")
        parts = (str(seed), "project", project)
    else:
        raise ValueError(f"unknown selection hash kind {kind!r}")
    return sha256_bytes("\0".join(parts).encode("utf-8"))


def _packet(role: str, packet_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
    packet = {
        "study_id": STUDY_ID,
        "packet_version": PACKET_VERSION,
        "role": role,
        "packet_id": packet_id,
        **body,
    }
    packet["packet_sha256"] = sha256_json(packet)
    return packet


def _verify_packet(packet: Mapping[str, Any], *, role: str | None = None) -> None:
    if packet.get("study_id") != STUDY_ID:
        raise ValueError(f"packet {packet.get('packet_id')!r} has wrong study_id")
    if packet.get("packet_version") != PACKET_VERSION:
        raise ValueError(f"packet {packet.get('packet_id')!r} has wrong version")
    if role is not None and packet.get("role") != role:
        raise ValueError(f"packet {packet.get('packet_id')!r} has wrong role")
    expected = packet.get("packet_sha256")
    unhashed = {key: value for key, value in packet.items() if key != "packet_sha256"}
    if expected != sha256_json(unhashed):
        raise ValueError(f"packet {packet.get('packet_id')!r} hash mismatch")


def _validate_authorship(value: Any, *, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where}.authorship must be an object")
    kind = value.get("kind")
    actor_id = value.get("actor_id")
    tools = value.get("tools", [])
    if kind not in AUTHORSHIP_KINDS:
        raise ValueError(
            f"{where}.authorship.kind must be one of {sorted(AUTHORSHIP_KINDS)}"
        )
    if not isinstance(actor_id, str) or not actor_id.strip():
        raise ValueError(f"{where}.authorship.actor_id must be non-empty")
    if not isinstance(tools, list) or not all(
        isinstance(item, str) and item.strip() for item in tools
    ):
        raise ValueError(f"{where}.authorship.tools must be a string list")
    if kind == "human" and tools:
        raise ValueError(
            f"{where} cannot be marked human while declaring agent/tool assistance"
        )
    if kind != "human" and not tools:
        raise ValueError(f"{where} must name tools for assisted/generated authorship")
    return {"kind": kind, "actor_id": actor_id.strip(), "tools": list(tools)}


def _require_private_or_external(path: Path, *, purpose: str) -> None:
    """Refuse hidden study content in a normally stageable repository path."""

    resolved = path.resolve()
    repository_root = ROOT.parents[1].resolve()
    private_root = (ROOT / "data" / "private").resolve()
    if resolved.is_relative_to(repository_root) and not resolved.is_relative_to(
        private_root
    ):
        raise ValueError(
            f"{purpose} must be outside the repository or under {private_root}"
        )


def read_pinned_source(
    path: Path, *, expected_sha256: str | None = None
) -> dict[str, Any]:
    """Verify and parse the exact pinned RepoRails validation CSV."""

    raw = path.read_bytes()
    actual_sha256 = sha256_bytes(raw)
    strict_pinned = expected_sha256 is None
    expected = expected_sha256 or str(PINNED_SOURCE_CORPUS["file_sha256"])
    if actual_sha256 != expected:
        raise ValueError(
            f"source CSV SHA-256 mismatch: got {actual_sha256}, expected {expected}"
        )

    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or set(reader.fieldnames) != CSV_FIELDS:
            raise ValueError(
                f"source CSV fields differ: got {reader.fieldnames}, "
                f"expected {sorted(CSV_FIELDS)}"
            )
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(
                    f"malformed CSV record ending on line {reader.line_num}"
                )
            clean = {key: str(row[key]) for key in reader.fieldnames}
            record_id = clean["id"].strip()
            if not record_id:
                raise ValueError(f"empty record id ending on line {reader.line_num}")
            if record_id in seen_ids:
                raise ValueError(f"duplicate source record id {record_id}")
            seen_ids.add(record_id)
            _project_identity(clean["project"])
            rows.append(
                {
                    "source_record": clean,
                    "source_physical_line_end": reader.line_num,
                }
            )
    if not rows:
        raise ValueError("source CSV contains no records")
    if strict_pinned:
        projects = {str(row["source_record"]["project"]) for row in rows}
        if len(rows) != PINNED_SOURCE_RECORDS:
            raise ValueError(
                f"pinned source has {len(rows)} records, expected {PINNED_SOURCE_RECORDS}"
            )
        if len(projects) != PINNED_PROJECT_VALUES:
            raise ValueError(
                f"pinned source has {len(projects)} project values, "
                f"expected {PINNED_PROJECT_VALUES}"
            )
    return {"file_sha256": actual_sha256, "rows": rows}


def select_repository_uniform(
    source_rows: Sequence[Mapping[str, Any]],
    *,
    limit: int | None = None,
    seed: int = SEED,
) -> list[dict[str, Any]]:
    """Choose one record per repository, then uniformly hash-order repositories.

    Within-repository record choice and repository ordering use independent hash
    domains.  Consequently, repositories with many records do not receive a
    lower minimum hash and therefore no selection advantage.
    """

    if limit is not None and limit <= 0:
        raise ValueError("limit must be positive")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for wrapped in source_rows:
        record = wrapped.get("source_record")
        if not isinstance(record, dict):
            raise ValueError("every source row must contain source_record")
        project = _project_identity(str(record.get("project", "")))
        candidate = dict(wrapped)
        candidate["project"] = project
        candidate["within_repository_record_sha256"] = _selection_hash(
            "record",
            project,
            str(record["id"]),
            seed=seed,
        )
        grouped[project].append(candidate)

    representatives: list[dict[str, Any]] = []
    for project, candidates in grouped.items():
        candidates.sort(
            key=lambda item: (
                item["within_repository_record_sha256"],
                str(item["source_record"]["id"]),
            )
        )
        chosen = dict(candidates[0])
        chosen["records_in_repository"] = len(candidates)
        chosen["repository_order_sha256"] = _selection_hash(
            "project", project, seed=seed
        )
        representatives.append(chosen)

    representatives.sort(
        key=lambda item: (item["repository_order_sha256"], item["project"])
    )
    if limit is not None and len(representatives) < limit:
        raise ValueError(
            f"source has only {len(representatives)} repositories; need {limit}"
        )
    selected = representatives if limit is None else representatives[:limit]
    for rank, item in enumerate(selected, 1):
        item["selection_rank"] = rank
    return selected


def build_screening_packets(
    selected: Sequence[Mapping[str, Any]], *, source_sha256: str
) -> list[dict[str, Any]]:
    packets = []
    task_sha256 = sha256_json(SCREENING_TASK)
    for item in selected:
        record = item["source_record"]
        packet_id = f"screen-{int(item['selection_rank']):04d}-{record['id']}"
        packets.append(
            _packet(
                "screener",
                packet_id,
                {
                    "selection_rank": int(item["selection_rank"]),
                    "screening_batch": (
                        (int(item["selection_rank"]) - 1) // SCREENING_BATCH_SIZE + 1
                    ),
                    "rank_within_batch": (
                        (int(item["selection_rank"]) - 1) % SCREENING_BATCH_SIZE + 1
                    ),
                    "selection": {
                        "seed": SEED,
                        "project": item["project"],
                        "repository_order_sha256": item["repository_order_sha256"],
                        "within_repository_record_sha256": item[
                            "within_repository_record_sha256"
                        ],
                        "records_in_repository": item["records_in_repository"],
                    },
                    "source_corpus": {
                        **PINNED_SOURCE_CORPUS,
                        "file_sha256": source_sha256,
                    },
                    "source_physical_line_end": item["source_physical_line_end"],
                    "source_record": record,
                    "task_sha256": task_sha256,
                    "task": SCREENING_TASK,
                },
            )
        )
    return packets


def selection_manifest(
    source: Mapping[str, Any],
    selected: Sequence[Mapping[str, Any]],
    packets_jsonl: bytes,
) -> dict[str, Any]:
    repositories = {
        _project_identity(str(row["source_record"]["project"]))
        for row in source["rows"]
    }
    manifest = {
        "study_id": STUDY_ID,
        "kind": "repository_uniform_selection",
        "source_corpus": PINNED_SOURCE_CORPUS,
        "source_records": len(source["rows"]),
        "source_repositories": len(repositories),
        "seed": SEED,
        "fixed_project_order_count": len(selected),
        "screening_batches": (
            len(selected) + SCREENING_BATCH_SIZE - 1
        )
        // SCREENING_BATCH_SIZE,
        "screening_batch_size": SCREENING_BATCH_SIZE,
        "target_eligible_rules": TARGET_ELIGIBLE_RULES,
        "stopping_rule": (
            "screen complete fixed-order batches until at least 24 adjudicated "
            "eligible records exist; select the first 24 eligible in project order"
        ),
        "selection_algorithm": {
            "repository_identity": "exact source project field; whitespace and case preserved",
            "within_repository": (
                "minimum SHA256(seed + NUL + 'record' + NUL + project + NUL + id)"
            ),
            "repository_order": ("SHA256(seed + NUL + 'project' + NUL + project)"),
            "domains_are_independent": True,
        },
        "screening_task_sha256": sha256_json(SCREENING_TASK),
        "screening_packets_sha256": sha256_bytes(packets_jsonl),
    }
    manifest["manifest_sha256"] = sha256_json(manifest)
    return manifest


def encode_jsonl(rows: Iterable[Mapping[str, Any]]) -> bytes:
    return b"".join((canonical_json(dict(row)) + "\n").encode("utf-8") for row in rows)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: expected JSON object")
        rows.append(value)
    return rows


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode_jsonl(rows))


def _contract(response: Mapping[str, Any], *, where: str) -> dict[str, str]:
    contract = response.get("observable_contract")
    if not isinstance(contract, dict):
        raise ValueError(f"{where}.observable_contract must be an object")
    trigger = contract.get("trigger")
    pointer = contract.get("json_pointer")
    if trigger not in SUPPORTED_CONTRACTS:
        raise ValueError(f"{where} has unsupported trigger {trigger!r}")
    if pointer != SUPPORTED_CONTRACTS[trigger]:
        raise ValueError(
            f"{where} pointer {pointer!r} does not match trigger {trigger!r}"
        )
    return {"trigger": str(trigger), "json_pointer": str(pointer)}


def validate_screening_responses(
    packets: Sequence[Mapping[str, Any]],
    responses: Sequence[Mapping[str, Any]],
    *,
    expected_per_packet: int = SCREENERS_PER_RECORD,
) -> dict[str, Any]:
    """Validate screening without treating disagreement as invalid or dropping it."""

    packet_by_id: dict[str, Mapping[str, Any]] = {}
    structural_errors: list[str] = []
    for packet in packets:
        try:
            _verify_packet(packet, role="screener")
            packet_id = str(packet["packet_id"])
            if packet_id in packet_by_id:
                raise ValueError(f"duplicate packet id {packet_id}")
            packet_by_id[packet_id] = packet
        except (KeyError, TypeError, ValueError) as exc:
            structural_errors.append(str(exc))

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    orphaned: list[dict[str, Any]] = []
    for index, raw in enumerate(responses):
        response = dict(raw)
        where = f"response[{index}]"
        errors: list[str] = []
        packet_id = str(response.get("packet_id", ""))
        try:
            authorship = _validate_authorship(response.get("authorship"), where=where)
            response["authorship"] = authorship
            decision = response.get("decision")
            if decision not in {"include", "exclude", "uncertain"}:
                raise ValueError(f"{where}.decision is invalid")
            if decision == "include":
                response["observable_contract"] = _contract(response, where=where)
                source_atom = response.get("source_atom")
                if not isinstance(source_atom, str) or not source_atom.strip():
                    raise ValueError(f"{where}.source_atom must be non-empty")
                response["source_atom"] = source_atom.strip()
                if response.get("primary_exclusion") not in {None, ""}:
                    raise ValueError(f"{where} include response has an exclusion")
            elif decision == "exclude":
                exclusion = response.get("primary_exclusion")
                if exclusion not in EXCLUSION_CODES:
                    raise ValueError(f"{where}.primary_exclusion is invalid")
                if (
                    exclusion == "other_with_required_explanation"
                    and not str(response.get("rationale", "")).strip()
                ):
                    raise ValueError(f"{where} other exclusion requires rationale")
                if (
                    response.get("observable_contract") is not None
                    and response.get("observable_contract") != ""
                ):
                    raise ValueError(f"{where} exclude response has a contract")
            else:
                if not str(response.get("rationale", "")).strip():
                    raise ValueError(f"{where} uncertain response requires rationale")
            if packet_id not in packet_by_id:
                raise ValueError(f"{where} references unknown packet {packet_id!r}")
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
        response["validation_errors"] = errors
        structural_errors.extend(errors)
        if packet_id in packet_by_id:
            grouped[packet_id].append(response)
        else:
            orphaned.append(response)

    records = []
    for packet_id, packet in sorted(
        packet_by_id.items(), key=lambda item: int(item[1]["selection_rank"])
    ):
        packet_responses = grouped.get(packet_id, [])
        actors = [
            response.get("authorship", {}).get("actor_id")
            for response in packet_responses
            if not response["validation_errors"]
        ]
        if len(actors) != len(set(actors)):
            structural_errors.append(f"{packet_id} has duplicate screener actor ids")
        valid = [r for r in packet_responses if not r["validation_errors"]]
        decisions = [r["decision"] for r in valid]
        if len(valid) < expected_per_packet:
            status = "incomplete"
            structural_errors.append(
                f"{packet_id} has {len(valid)} valid responses, expected {expected_per_packet}"
            )
        elif len(valid) > expected_per_packet:
            status = "overcomplete"
            structural_errors.append(
                f"{packet_id} has {len(valid)} valid responses, expected {expected_per_packet}"
            )
        elif len(set(decisions)) != 1:
            status = "decision_disagreement"
        elif decisions[0] == "include":
            contracts = {canonical_json(r["observable_contract"]) for r in valid}
            atoms = {r["source_atom"] for r in valid}
            if len(contracts) == 1 and len(atoms) == 1:
                status = "agreement_include"
            elif len(contracts) != 1 and len(atoms) != 1:
                status = "atom_and_contract_disagreement"
            elif len(contracts) != 1:
                status = "contract_disagreement"
            else:
                status = "atom_disagreement"
        elif decisions[0] == "exclude":
            exclusion_reasons = {r["primary_exclusion"] for r in valid}
            status = (
                "agreement_exclude"
                if len(exclusion_reasons) == 1
                else "exclusion_reason_disagreement"
            )
        else:
            status = "agreement_uncertain"
        provisional_decision = None
        observable_contract = None
        source_atom = None
        primary_exclusion = None
        if status == "agreement_include":
            provisional_decision = "include"
            observable_contract = valid[0]["observable_contract"]
            source_atom = valid[0]["source_atom"]
        elif status == "agreement_exclude":
            provisional_decision = "exclude"
            primary_exclusion = valid[0]["primary_exclusion"]
        records.append(
            {
                "packet_id": packet_id,
                "selection_rank": int(packet["selection_rank"]),
                "screening_batch": int(packet["screening_batch"]),
                "source_record": packet["source_record"],
                "status": status,
                "provisional_decision": provisional_decision,
                "observable_contract": observable_contract,
                "source_atom": source_atom,
                "primary_exclusion": primary_exclusion,
                "responses": packet_responses,
                "all_responses_unassisted_human": len(valid) == expected_per_packet
                and all(r["authorship"]["kind"] == "human" for r in valid),
                "retained": True,
            }
        )
    counts: dict[str, int] = defaultdict(int)
    for record in records:
        counts[record["status"]] += 1
    return {
        "study_id": STUDY_ID,
        "kind": "screening_validation",
        "expected_responses_per_packet": expected_per_packet,
        "valid": not structural_errors and not orphaned,
        "structural_errors": structural_errors,
        "orphaned_responses": orphaned,
        "status_counts": dict(sorted(counts.items())),
        "records": records,
        "retention_policy": "all packets, responses, and disagreements are retained",
    }


def finalize_screening(
    screening_report: Mapping[str, Any],
    adjudications: Sequence[Mapping[str, Any]] = (),
    *,
    target_eligible: int = TARGET_ELIGIBLE_RULES,
    screening_batch_size: int = SCREENING_BATCH_SIZE,
    source_project_values: int = PINNED_PROJECT_VALUES,
) -> dict[str, Any]:
    """Apply explicit adjudications while retaining the underlying disagreement."""

    if target_eligible < 1 or screening_batch_size < 1 or source_project_values < 1:
        raise ValueError("screening stopping-rule counts must be positive")

    adjudication_by_packet: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for index, raw in enumerate(adjudications):
        item = dict(raw)
        where = f"adjudication[{index}]"
        try:
            item["authorship"] = _validate_authorship(
                item.get("authorship"), where=where
            )
            packet_id = str(item.get("packet_id", ""))
            if not packet_id:
                raise ValueError(f"{where}.packet_id is required")
            if packet_id in adjudication_by_packet:
                raise ValueError(f"duplicate adjudication for {packet_id}")
            decision = item.get("final_decision")
            if decision not in {"include", "exclude"}:
                raise ValueError(f"{where}.final_decision is invalid")
            if decision == "include":
                item["observable_contract"] = _contract(item, where=where)
                source_atom = item.get("source_atom")
                if not isinstance(source_atom, str) or not source_atom.strip():
                    raise ValueError(f"{where}.source_atom must be non-empty")
                item["source_atom"] = source_atom.strip()
            else:
                exclusion = item.get("primary_exclusion")
                if exclusion not in EXCLUSION_CODES:
                    raise ValueError(f"{where}.primary_exclusion is invalid")
                if (
                    exclusion == "other_with_required_explanation"
                    and not str(item.get("rationale", "")).strip()
                ):
                    raise ValueError(f"{where} other exclusion requires rationale")
            adjudication_by_packet[packet_id] = item
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))

    finalized = []
    known = set()
    for original in screening_report.get("records", []):
        record = dict(original)
        packet_id = str(record["packet_id"])
        known.add(packet_id)
        adjudication = adjudication_by_packet.get(packet_id)
        if record.get("provisional_decision") in {"include", "exclude"}:
            if adjudication is not None:
                errors.append(
                    f"{packet_id} has an adjudication despite independent agreement"
                )
            record["final_decision"] = record["provisional_decision"]
            record["final_contract"] = record.get("observable_contract")
            record["final_source_atom"] = record.get("source_atom")
            record["final_primary_exclusion"] = record.get("primary_exclusion")
            record["resolution"] = "independent_screening_agreement"
        elif adjudication is not None:
            record["final_decision"] = adjudication["final_decision"]
            record["final_contract"] = adjudication.get("observable_contract")
            record["final_source_atom"] = adjudication.get("source_atom")
            record["final_primary_exclusion"] = adjudication.get("primary_exclusion")
            record["resolution"] = "explicit_adjudication"
            record["adjudication"] = adjudication
        else:
            record["final_decision"] = None
            record["final_contract"] = None
            record["final_source_atom"] = None
            record["final_primary_exclusion"] = None
            record["resolution"] = "unresolved"
        record["retained"] = True
        finalized.append(record)
    unknown = sorted(set(adjudication_by_packet) - known)
    if unknown:
        errors.append(f"adjudications reference unknown packets {unknown}")
    finalized.sort(key=lambda item: int(item["selection_rank"]))
    ranks = [int(item["selection_rank"]) for item in finalized]
    if ranks != list(range(1, len(finalized) + 1)):
        errors.append("screened packets are not a contiguous prefix of project order")
    unresolved = [
        str(item["packet_id"])
        for item in finalized
        if item["final_decision"] not in {"include", "exclude"}
    ]
    if unresolved:
        errors.append(f"screening records remain unresolved: {unresolved[:5]}")
    complete_batch_prefix = (
        len(finalized) % screening_batch_size == 0
        or len(finalized) == source_project_values
    )
    if not complete_batch_prefix:
        errors.append(
            "screened records do not end on a complete batch or corpus exhaustion"
        )
    eligible = [item for item in finalized if item["final_decision"] == "include"]
    if len(eligible) >= target_eligible:
        selected = eligible[:target_eligible]
        ready_for_authoring = True
        stopping_reason = "target_reached_after_complete_batch"
    elif len(finalized) == source_project_values and not unresolved:
        selected = eligible
        ready_for_authoring = True
        stopping_reason = "source_exhausted_below_target"
    else:
        selected = []
        ready_for_authoring = False
        stopping_reason = "continue_with_next_complete_batch"
    selected_ids = {str(item["packet_id"]) for item in selected}
    for item in finalized:
        item["selected_for_study"] = str(item["packet_id"]) in selected_ids
    return {
        "study_id": STUDY_ID,
        "kind": "screening_finalization",
        "valid": not errors and bool(screening_report.get("valid", False)),
        "structural_errors": errors,
        "records": finalized,
        "screened_records": len(finalized),
        "eligible_records": len(eligible),
        "selected_records": len(selected),
        "selected_packet_ids": [str(item["packet_id"]) for item in selected],
        "ready_for_authoring": ready_for_authoring and not errors,
        "stopping_reason": stopping_reason,
        "retention_policy": "screening disagreements remain embedded after adjudication",
    }


def build_authoring_packets(
    screening_packets: Sequence[Mapping[str, Any]],
    finalization: Mapping[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Create role-separated packets for records explicitly finalized as included."""

    if not finalization.get("valid", False):
        raise ValueError("screening finalization is not structurally valid")
    if not finalization.get("ready_for_authoring", False):
        raise ValueError("screening stopping rule has not reached authoring")

    source_by_id = {}
    for packet in screening_packets:
        _verify_packet(packet, role="screener")
        source_by_id[str(packet["packet_id"])] = packet
    result = {"spec": [], "case": [], "baseline": []}
    task_by_role = {
        "spec": ("spec_author", SPEC_TASK),
        "case": ("case_author", CASE_TASK),
        "baseline": ("deterministic_baseline_author", BASELINE_TASK),
    }
    for record in finalization.get("records", []):
        if not record.get("selected_for_study", False):
            continue
        source_packet = source_by_id.get(str(record["packet_id"]))
        if source_packet is None:
            raise ValueError(f"missing source packet {record['packet_id']}")
        contract = record.get("final_contract")
        if not isinstance(contract, dict):
            raise ValueError(f"included packet {record['packet_id']} lacks contract")
        _contract({"observable_contract": contract}, where=str(record["packet_id"]))
        subject_id = _domain_hash("subject", str(record["packet_id"]), seed=SEED)[:20]
        screening_history_sha256 = sha256_json(record)
        common = {
            "subject_id": subject_id,
            "source_packet_id": record["packet_id"],
            "source_record": source_packet["source_record"],
            "source_atom": record["final_source_atom"],
            "observable_contract": contract,
            "screening_history_sha256": screening_history_sha256,
        }
        for key, (role, task) in task_by_role.items():
            result[key].append(
                _packet(
                    role,
                    f"{key}-{subject_id}",
                    {**common, "task_sha256": sha256_json(task), "task": task},
                )
            )
    return result


def validate_case_responses(
    case_packets: Sequence[Mapping[str, Any]],
    responses: Sequence[Mapping[str, Any]],
    *,
    pairs_per_rule: int = INTENDED_PAIRS_PER_RULE,
) -> dict[str, Any]:
    """Validate independent case authoring and build a private intent index."""

    packet_by_id = {}
    for packet in case_packets:
        _verify_packet(packet, role="case_author")
        packet_id = str(packet["packet_id"])
        if packet_id in packet_by_id:
            raise ValueError(f"duplicate case packet id {packet_id}")
        packet_by_id[packet_id] = packet
    seen_packets: set[str] = set()
    subjects = []
    structural_errors = []
    all_cases = []
    for index, raw in enumerate(responses):
        response = dict(raw)
        where = f"case_response[{index}]"
        response_errors = []
        packet_id = str(response.get("packet_id", ""))
        packet = packet_by_id.get(packet_id)
        try:
            if packet is None:
                raise ValueError(f"{where} references unknown packet {packet_id!r}")
            if packet_id in seen_packets:
                raise ValueError(f"duplicate case response for {packet_id}")
            seen_packets.add(packet_id)
            response["authorship"] = _validate_authorship(
                response.get("authorship"), where=where
            )
            pairs = response.get("pairs")
            if not isinstance(pairs, list) or len(pairs) != pairs_per_rule:
                raise ValueError(
                    f"{where}.pairs must contain exactly {pairs_per_rule} pairs"
                )
            pair_ids = set()
            observed_inputs = set()
            parsed_pairs = []
            for pair_index, pair in enumerate(pairs, 1):
                if not isinstance(pair, dict):
                    raise ValueError(f"{where}.pairs[{pair_index}] must be an object")
                pair_id = pair.get("pair_id")
                if not isinstance(pair_id, str) or not pair_id.strip():
                    raise ValueError(f"{where}.pairs[{pair_index}].pair_id is required")
                if pair_id in pair_ids:
                    raise ValueError(f"{where} has duplicate pair id {pair_id}")
                pair_ids.add(pair_id)
                violation = pair.get("intended_violation_input")
                compliant = pair.get("intended_ok_input")
                if not isinstance(violation, str) or not violation:
                    raise ValueError(f"{where}.{pair_id} has empty violation input")
                if not isinstance(compliant, str) or not compliant:
                    raise ValueError(f"{where}.{pair_id} has empty OK input")
                if violation == compliant:
                    raise ValueError(f"{where}.{pair_id} uses identical inputs")
                for value in (violation, compliant):
                    if value in observed_inputs:
                        raise ValueError(f"{where} reuses an input across pairs")
                    observed_inputs.add(value)
                parsed_pairs.append(
                    {
                        "pair_id": pair_id,
                        "intended_violation_input": violation,
                        "intended_ok_input": compliant,
                        "rationale": str(pair.get("rationale", "")),
                    }
                )
            response["pairs"] = parsed_pairs
        except (TypeError, ValueError) as exc:
            response_errors.append(str(exc))
        response["validation_errors"] = response_errors
        subjects.append(
            {"packet_id": packet_id, "response": response, "retained": True}
        )
        if response_errors:
            structural_errors.extend(response_errors)
            continue
        assert packet is not None
        for pair in response["pairs"]:
            for intended_expected, input_key, side in (
                ("FINDING", "intended_violation_input", "intended_violation"),
                ("OK", "intended_ok_input", "intended_ok"),
            ):
                opaque_case_id = _domain_hash(
                    "heldout_case",
                    str(packet["subject_id"]),
                    str(pair["pair_id"]),
                    side,
                    seed=SEED,
                )[:24]
                all_cases.append(
                    {
                        "case_id": opaque_case_id,
                        "subject_id": packet["subject_id"],
                        "case_packet_id": packet_id,
                        "pair_id": pair["pair_id"],
                        "side": side,
                        "input": pair[input_key],
                        "intended_expected": intended_expected,
                        "case_authorship": response["authorship"],
                        "retained": True,
                    }
                )
    missing = sorted(set(packet_by_id) - seen_packets)
    if missing:
        structural_errors.append(f"missing case responses for {missing}")
    return {
        "study_id": STUDY_ID,
        "kind": "case_validation_private",
        "valid": not structural_errors,
        "structural_errors": structural_errors,
        "subjects": subjects,
        "cases": all_cases,
        "retention_policy": (
            "case-author intent is retained as intent and never represented as a human label"
        ),
    }


def build_label_packets(
    case_packets: Sequence[Mapping[str, Any]],
    case_report: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Blind case intent and pair membership from independent labelers."""

    if not case_report.get("valid", False):
        raise ValueError("case report is not structurally valid")

    packet_by_id = {}
    for packet in case_packets:
        _verify_packet(packet, role="case_author")
        packet_by_id[str(packet["packet_id"])] = packet
    packets = []
    for case in case_report.get("cases", []):
        source = packet_by_id.get(str(case["case_packet_id"]))
        if source is None:
            raise ValueError(f"case {case['case_id']} has no source packet")
        packet_id = f"label-{case['case_id']}"
        packets.append(
            _packet(
                "labeler",
                packet_id,
                {
                    "subject_id": source["subject_id"],
                    "source_record": source["source_record"],
                    "observable_contract": source["observable_contract"],
                    "input": case["input"],
                    "task_sha256": sha256_json(LABEL_TASK),
                    "task": LABEL_TASK,
                },
            )
        )
    packets.sort(
        key=lambda item: _domain_hash(
            "label_packet_order", str(item["packet_id"]), seed=SEED
        )
    )
    return packets


def validate_label_responses(
    label_packets: Sequence[Mapping[str, Any]],
    case_report: Mapping[str, Any],
    responses: Sequence[Mapping[str, Any]],
    adjudications: Sequence[Mapping[str, Any]] = (),
    *,
    expected_per_case: int = LABELERS_PER_CASE,
) -> dict[str, Any]:
    """Retain every label, disagreement, and failed intended contrast."""

    if not case_report.get("valid", False):
        raise ValueError("case report is not structurally valid")

    packet_by_id = {}
    for packet in label_packets:
        _verify_packet(packet, role="labeler")
        packet_by_id[str(packet["packet_id"])] = packet
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    structural_errors = []
    orphaned = []
    for index, raw in enumerate(responses):
        response = dict(raw)
        where = f"label_response[{index}]"
        errors = []
        packet_id = str(response.get("packet_id", ""))
        try:
            response["authorship"] = _validate_authorship(
                response.get("authorship"), where=where
            )
            if response.get("expected") not in OUTCOME_LABELS:
                raise ValueError(f"{where}.expected is invalid")
            if packet_id not in packet_by_id:
                raise ValueError(f"{where} references unknown packet {packet_id!r}")
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
        response["validation_errors"] = errors
        structural_errors.extend(errors)
        if packet_id in packet_by_id:
            grouped[packet_id].append(response)
        else:
            orphaned.append(response)

    adjudication_by_packet = {}
    for index, raw in enumerate(adjudications):
        item = dict(raw)
        where = f"label_adjudication[{index}]"
        try:
            item["authorship"] = _validate_authorship(
                item.get("authorship"), where=where
            )
            packet_id = str(item.get("packet_id", ""))
            if packet_id not in packet_by_id:
                raise ValueError(f"{where} references unknown packet {packet_id!r}")
            if packet_id in adjudication_by_packet:
                raise ValueError(f"duplicate label adjudication for {packet_id}")
            if item.get("expected") not in OUTCOME_LABELS:
                raise ValueError(f"{where}.expected is invalid")
            adjudication_by_packet[packet_id] = item
        except (TypeError, ValueError) as exc:
            structural_errors.append(str(exc))

    case_by_packet = {
        f"label-{case['case_id']}": case for case in case_report.get("cases", [])
    }
    cases = []
    for packet_id in sorted(packet_by_id):
        annotations = grouped.get(packet_id, [])
        valid = [r for r in annotations if not r["validation_errors"]]
        actors = [r["authorship"]["actor_id"] for r in valid]
        if len(actors) != len(set(actors)):
            structural_errors.append(f"{packet_id} has duplicate labeler actor ids")
        labels = [r["expected"] for r in valid]
        if len(valid) < expected_per_case:
            status = "incomplete"
            structural_errors.append(
                f"{packet_id} has {len(valid)} valid labels, expected {expected_per_case}"
            )
        elif len(valid) > expected_per_case:
            status = "overcomplete"
            structural_errors.append(
                f"{packet_id} has {len(valid)} valid labels, expected {expected_per_case}"
            )
        elif "UNSURE" in labels:
            status = "uncertain"
        elif len(set(labels)) == 1:
            status = "agreement"
        else:
            status = "disagreement"
        adjudication = adjudication_by_packet.get(packet_id)
        if (
            adjudication is not None
            and adjudication["authorship"]["actor_id"] in actors
        ):
            structural_errors.append(
                f"{packet_id} adjudicator must differ from its labelers"
            )
        if status == "agreement" and adjudication is not None:
            structural_errors.append(
                f"{packet_id} has an adjudication despite independent agreement"
            )
        if status == "agreement":
            final_label = labels[0]
            resolution = "independent_label_agreement"
        elif adjudication is not None and adjudication["expected"] != "UNSURE":
            final_label = adjudication["expected"]
            resolution = "explicit_adjudication"
        else:
            final_label = None
            resolution = "unresolved"
        if final_label is None:
            final_label_authorship = "unresolved"
        elif resolution == "independent_label_agreement" and all(
            r["authorship"]["kind"] == "human" for r in valid
        ):
            final_label_authorship = "unassisted_human"
        elif (
            resolution == "explicit_adjudication"
            and adjudication is not None
            and adjudication["authorship"]["kind"] == "human"
            and all(r["authorship"]["kind"] == "human" for r in valid)
        ):
            final_label_authorship = "unassisted_human"
        else:
            final_label_authorship = "mixed_or_nonhuman"
        original_case = case_by_packet.get(packet_id)
        if original_case is None:
            structural_errors.append(f"{packet_id} has no private case index entry")
            original_case = {}
        cases.append(
            {
                **original_case,
                "label_packet_id": packet_id,
                "annotation_status": status,
                "annotations": annotations,
                "adjudication": adjudication,
                "final_label": final_label,
                "final_label_authorship": final_label_authorship,
                "resolution": resolution,
                "all_annotations_unassisted_human": len(valid) == expected_per_case
                and all(r["authorship"]["kind"] == "human" for r in valid),
                "retained": True,
            }
        )

    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        if "subject_id" in case and "pair_id" in case:
            by_pair[(str(case["subject_id"]), str(case["pair_id"]))].append(case)
    pairs = []
    for (subject_id, pair_id), pair_cases in sorted(by_pair.items()):
        side_map = {str(case["side"]): case for case in pair_cases}
        violation = side_map.get("intended_violation")
        compliant = side_map.get("intended_ok")
        if violation is None or compliant is None:
            contrast_status = "structurally_incomplete"
            structural_errors.append(
                f"{subject_id}/{pair_id} lacks both intended sides"
            )
        else:
            violation_label = violation.get("final_label")
            compliant_label = compliant.get("final_label")
            if violation_label is None or compliant_label is None:
                contrast_status = "unresolved_annotation"
            elif violation_label == "OK" and compliant_label != "OK":
                contrast_status = "reversed"
            elif violation_label == "OK" and compliant_label == "OK":
                contrast_status = "failed_both_ok"
            elif violation_label != "OK" and compliant_label != "OK":
                contrast_status = "failed_both_findings"
            else:
                contrast_status = "confirmed"
        pairs.append(
            {
                "subject_id": subject_id,
                "pair_id": pair_id,
                "intended_contrast_status": contrast_status,
                "cases": pair_cases,
                "retained": True,
            }
        )
    counts: dict[str, int] = defaultdict(int)
    for pair in pairs:
        counts[pair["intended_contrast_status"]] += 1
    return {
        "study_id": STUDY_ID,
        "kind": "heldout_label_validation_private",
        "valid": not structural_errors and not orphaned,
        "structural_errors": structural_errors,
        "orphaned_responses": orphaned,
        "cases": cases,
        "pairs": pairs,
        "intended_contrast_counts": dict(sorted(counts.items())),
        "retention_policy": (
            "all annotations, disagreements, unresolved cases, reversed pairs, and "
            "failed intended contrasts are retained"
        ),
    }


def validate_role_separation(
    role_responses: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, Any]:
    """Check that spec, case, label, and baseline authors occupy distinct roles."""

    allowed_roles = {"spec", "case", "label", "baseline"}
    unknown = sorted(set(role_responses) - allowed_roles)
    if unknown:
        raise ValueError(f"unknown study roles {unknown}")
    entries = []
    actor_roles: dict[str, set[str]] = defaultdict(set)
    structural_errors = [
        f"role {role!r} has no completed responses"
        for role in sorted(allowed_roles)
        if not role_responses.get(role)
    ]
    for role in sorted(role_responses):
        for index, raw in enumerate(role_responses[role]):
            response = dict(raw)
            where = f"{role}[{index}]"
            try:
                authorship = _validate_authorship(
                    response.get("authorship"), where=where
                )
                actor_roles[authorship["actor_id"]].add(role)
                entries.append(
                    {
                        "role": role,
                        "authorship": authorship,
                        "source_response_sha256": sha256_json(response),
                    }
                )
            except (TypeError, ValueError) as exc:
                structural_errors.append(str(exc))
                entries.append(
                    {
                        "role": role,
                        "raw_authorship": response.get("authorship"),
                        "source_response_sha256": sha256_json(response),
                        "validation_error": str(exc),
                    }
                )
    overlaps = {
        actor_id: sorted(roles)
        for actor_id, roles in sorted(actor_roles.items())
        if len(roles) > 1
    }
    for actor_id, roles in overlaps.items():
        structural_errors.append(
            f"actor {actor_id!r} appears in separated roles {roles}"
        )
    return {
        "study_id": STUDY_ID,
        "kind": "role_separation_validation",
        "valid": not structural_errors,
        "structural_errors": structural_errors,
        "role_overlap": overlaps,
        "entries": entries,
        "authorship_policy": (
            "authorship kinds are preserved; agent-generated or assisted work is never "
            "reported as unassisted human work"
        ),
    }


def freeze_hidden_files(
    files: Mapping[str, Path], *, frozen_at_utc: str | None = None
) -> dict[str, Any]:
    """Create a content-free public hash receipt for private held-out files."""

    if not files:
        raise ValueError("at least one hidden file is required")
    frozen_at = frozen_at_utc or _utc_now()
    _parse_utc(frozen_at)
    entries = []
    for logical_name, path in sorted(files.items()):
        if not logical_name or "/" in logical_name or "\\" in logical_name:
            raise ValueError(f"invalid hidden logical name {logical_name!r}")
        _require_private_or_external(path, purpose=f"hidden file {logical_name}")
        raw = path.read_bytes()
        entries.append(
            {
                "logical_name": logical_name,
                "sha256": sha256_bytes(raw),
                "bytes": len(raw),
                "nonempty_lines": sum(1 for line in raw.splitlines() if line.strip()),
            }
        )
    manifest = {
        "study_id": STUDY_ID,
        "kind": "hidden_data_hash_freeze",
        "frozen_at_utc": frozen_at,
        "contains_hidden_content": False,
        "files": entries,
    }
    manifest["manifest_sha256"] = sha256_json(manifest)
    return manifest


def verify_hash_manifest(manifest: Mapping[str, Any]) -> None:
    expected = manifest.get("manifest_sha256")
    unhashed = {
        key: value for key, value in manifest.items() if key != "manifest_sha256"
    }
    if expected != sha256_json(unhashed):
        raise ValueError("manifest hash mismatch")


def check_hidden_freeze(
    manifest: Mapping[str, Any], files: Mapping[str, Path]
) -> dict[str, Any]:
    verify_hash_manifest(manifest)
    if manifest.get("kind") != "hidden_data_hash_freeze":
        raise ValueError("not a hidden data freeze manifest")
    expected = {str(item["logical_name"]): item for item in manifest["files"]}
    if set(expected) != set(files):
        raise ValueError("hidden file names differ from freeze manifest")
    for logical_name, path in files.items():
        _require_private_or_external(path, purpose=f"hidden file {logical_name}")
        raw = path.read_bytes()
        if sha256_bytes(raw) != expected[logical_name]["sha256"]:
            raise ValueError(f"hidden file {logical_name} changed after hash freeze")
        if len(raw) != expected[logical_name]["bytes"]:
            raise ValueError(f"hidden file {logical_name} size changed")
    return {
        "study_id": STUDY_ID,
        "kind": "hidden_data_freeze_check",
        "manifest_sha256": manifest["manifest_sha256"],
        "files_verified": len(expected),
        "valid": True,
    }


def freeze_deterministic_baselines(
    artifacts: Mapping[str, Path],
    *,
    authoring_packets_sha256: str,
    hidden_manifest_sha256: str,
    authorship: Mapping[str, Any],
    attestation: Mapping[str, Any],
    frozen_at_utc: str | None = None,
) -> dict[str, Any]:
    """Freeze deterministic source before unblinding, with an explicit attestation."""

    if not artifacts:
        raise ValueError("at least one deterministic baseline artifact is required")
    validated_authorship = _validate_authorship(
        dict(authorship), where="deterministic_baseline"
    )
    required_attestation = {
        "authored_from_baseline_packets_only": True,
        "heldout_inputs_seen": False,
        "heldout_labels_seen": False,
    }
    if dict(attestation) != required_attestation:
        raise ValueError(
            "deterministic baseline attestation must exactly assert packet-only "
            "authoring and no held-out input/label access"
        )
    frozen_at = frozen_at_utc or _utc_now()
    _parse_utc(frozen_at)
    entries = []
    for logical_name, path in sorted(artifacts.items()):
        raw = path.read_bytes()
        entries.append(
            {
                "logical_name": logical_name,
                "sha256": sha256_bytes(raw),
                "bytes": len(raw),
            }
        )
    manifest = {
        "study_id": STUDY_ID,
        "kind": "deterministic_baseline_freeze",
        "frozen_at_utc": frozen_at,
        "authoring_packets_sha256": authoring_packets_sha256,
        "hidden_manifest_sha256": hidden_manifest_sha256,
        "authorship": validated_authorship,
        "attestation": required_attestation,
        "artifacts": entries,
    }
    manifest["manifest_sha256"] = sha256_json(manifest)
    return manifest


def check_deterministic_baseline_freeze(
    manifest: Mapping[str, Any], artifacts: Mapping[str, Path]
) -> dict[str, Any]:
    verify_hash_manifest(manifest)
    if manifest.get("kind") != "deterministic_baseline_freeze":
        raise ValueError("not a deterministic baseline freeze manifest")
    expected = {str(item["logical_name"]): item for item in manifest["artifacts"]}
    if set(expected) != set(artifacts):
        raise ValueError("baseline artifact names differ from freeze manifest")
    for logical_name, path in artifacts.items():
        raw = path.read_bytes()
        if sha256_bytes(raw) != expected[logical_name]["sha256"]:
            raise ValueError(
                f"deterministic baseline {logical_name} changed after freeze"
            )
        if len(raw) != expected[logical_name]["bytes"]:
            raise ValueError(f"deterministic baseline {logical_name} size changed")
    return {
        "study_id": STUDY_ID,
        "kind": "deterministic_baseline_freeze_check",
        "manifest_sha256": manifest["manifest_sha256"],
        "artifacts_verified": len(expected),
        "valid": True,
    }


def build_unblinding_receipt(
    hidden_manifest: Mapping[str, Any],
    baseline_manifest: Mapping[str, Any],
    hidden_files: Mapping[str, Path],
    baseline_artifacts: Mapping[str, Path],
    *,
    unblinded_at_utc: str | None = None,
) -> dict[str, Any]:
    """Record and verify declared hash/baseline ordering before unblinding."""

    hidden_check = check_hidden_freeze(hidden_manifest, hidden_files)
    baseline_check = check_deterministic_baseline_freeze(
        baseline_manifest, baseline_artifacts
    )
    if hidden_manifest.get("kind") != "hidden_data_hash_freeze":
        raise ValueError("wrong hidden data manifest kind")
    if baseline_manifest.get("kind") != "deterministic_baseline_freeze":
        raise ValueError("wrong deterministic baseline manifest kind")
    if baseline_manifest.get("hidden_manifest_sha256") != hidden_manifest.get(
        "manifest_sha256"
    ):
        raise ValueError("baseline freeze references a different hidden-data freeze")
    unblinded_at = unblinded_at_utc or _utc_now()
    unblinded_time = _parse_utc(unblinded_at)
    if _parse_utc(str(hidden_manifest["frozen_at_utc"])) > unblinded_time:
        raise ValueError("hidden data hash was frozen after unblinding")
    if _parse_utc(str(baseline_manifest["frozen_at_utc"])) > unblinded_time:
        raise ValueError("deterministic baseline was frozen after unblinding")
    receipt = {
        "study_id": STUDY_ID,
        "kind": "heldout_unblinding_receipt",
        "unblinded_at_utc": unblinded_at,
        "hidden_manifest_sha256": hidden_manifest["manifest_sha256"],
        "baseline_manifest_sha256": baseline_manifest["manifest_sha256"],
        "hidden_files_verified": hidden_check["files_verified"],
        "baseline_artifacts_verified": baseline_check["artifacts_verified"],
        "phase_order_valid": True,
    }
    receipt["receipt_sha256"] = sha256_json(receipt)
    return receipt


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _parse_named_paths(values: Sequence[str]) -> dict[str, Path]:
    parsed = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"expected NAME=PATH, got {value!r}")
        name, raw_path = value.split("=", 1)
        if name in parsed:
            raise ValueError(f"duplicate logical name {name!r}")
        parsed[name] = Path(raw_path)
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    select_parser = subparsers.add_parser("select")
    select_parser.add_argument("--source-csv", type=Path, required=True)
    select_parser.add_argument("--output-dir", type=Path, required=True)

    screen_parser = subparsers.add_parser("validate-screening")
    screen_parser.add_argument("--packets", type=Path, required=True)
    screen_parser.add_argument("--responses", type=Path, required=True)
    screen_parser.add_argument("--output", type=Path, required=True)
    screen_parser.add_argument(
        "--max-batch",
        type=int,
        help="validate a cumulative prefix ending at this complete batch",
    )

    finalize_parser = subparsers.add_parser("finalize-screening")
    finalize_parser.add_argument("--screening-report", type=Path, required=True)
    finalize_parser.add_argument("--adjudications", type=Path)
    finalize_parser.add_argument("--output", type=Path, required=True)

    author_parser = subparsers.add_parser("make-authoring-packets")
    author_parser.add_argument("--screening-packets", type=Path, required=True)
    author_parser.add_argument("--finalization", type=Path, required=True)
    author_parser.add_argument("--output-dir", type=Path, required=True)

    cases_parser = subparsers.add_parser("validate-cases")
    cases_parser.add_argument("--packets", type=Path, required=True)
    cases_parser.add_argument("--responses", type=Path, required=True)
    cases_parser.add_argument("--output", type=Path, required=True)

    labels_parser = subparsers.add_parser("make-label-packets")
    labels_parser.add_argument("--case-packets", type=Path, required=True)
    labels_parser.add_argument("--case-report", type=Path, required=True)
    labels_parser.add_argument("--output", type=Path, required=True)

    validate_labels_parser = subparsers.add_parser("validate-labels")
    validate_labels_parser.add_argument("--packets", type=Path, required=True)
    validate_labels_parser.add_argument("--case-report", type=Path, required=True)
    validate_labels_parser.add_argument("--responses", type=Path, required=True)
    validate_labels_parser.add_argument("--adjudications", type=Path)
    validate_labels_parser.add_argument("--output", type=Path, required=True)

    roles_parser = subparsers.add_parser("validate-role-separation")
    roles_parser.add_argument("--spec-responses", type=Path, required=True)
    roles_parser.add_argument("--case-responses", type=Path, required=True)
    roles_parser.add_argument("--label-responses", type=Path, required=True)
    roles_parser.add_argument("--baseline-responses", type=Path, required=True)
    roles_parser.add_argument("--output", type=Path, required=True)

    hidden_parser = subparsers.add_parser("freeze-hidden")
    hidden_parser.add_argument("--file", action="append", required=True)
    hidden_parser.add_argument("--output", type=Path, required=True)

    baseline_parser = subparsers.add_parser("freeze-baseline")
    baseline_parser.add_argument("--artifact", action="append", required=True)
    baseline_parser.add_argument("--authoring-packets", type=Path, required=True)
    baseline_parser.add_argument("--hidden-manifest", type=Path, required=True)
    baseline_parser.add_argument("--authorship", type=Path, required=True)
    baseline_parser.add_argument("--attestation", type=Path, required=True)
    baseline_parser.add_argument("--output", type=Path, required=True)

    check_parser = subparsers.add_parser("check-baseline")
    check_parser.add_argument("--manifest", type=Path, required=True)
    check_parser.add_argument("--artifact", action="append", required=True)

    unblind_parser = subparsers.add_parser("record-unblinding")
    unblind_parser.add_argument("--hidden-manifest", type=Path, required=True)
    unblind_parser.add_argument("--baseline-manifest", type=Path, required=True)
    unblind_parser.add_argument("--hidden-file", action="append", required=True)
    unblind_parser.add_argument("--artifact", action="append", required=True)
    unblind_parser.add_argument("--output", type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == "select":
        source = read_pinned_source(args.source_csv)
        selected = select_repository_uniform(source["rows"])
        packets = build_screening_packets(
            selected, source_sha256=str(source["file_sha256"])
        )
        packet_bytes = encode_jsonl(packets)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "screening-packets.jsonl").write_bytes(packet_bytes)
        batches: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for packet in packets:
            batches[int(packet["screening_batch"])].append(packet)
        for batch_number, batch_packets in sorted(batches.items()):
            write_jsonl(
                args.output_dir / f"screening-batch-{batch_number:02d}.jsonl",
                batch_packets,
            )
        write_json(
            args.output_dir / "selection-manifest.json",
            selection_manifest(source, selected, packet_bytes),
        )
        return 0
    if args.command == "validate-screening":
        _require_private_or_external(args.responses, purpose="screening responses")
        _require_private_or_external(args.output, purpose="screening report")
        packets = read_jsonl(args.packets)
        if args.max_batch is not None:
            if args.max_batch < 1:
                raise ValueError("--max-batch must be positive")
            packets = [
                packet
                for packet in packets
                if int(packet["screening_batch"]) <= args.max_batch
            ]
            if not packets:
                raise ValueError("--max-batch selected no screening packets")
        report = validate_screening_responses(packets, read_jsonl(args.responses))
        write_json(args.output, report)
        return 0 if report["valid"] else 1
    if args.command == "finalize-screening":
        _require_private_or_external(args.screening_report, purpose="screening report")
        _require_private_or_external(args.output, purpose="screening finalization")
        if args.adjudications is not None:
            _require_private_or_external(
                args.adjudications, purpose="screening adjudications"
            )
        adjudications = (
            read_jsonl(args.adjudications) if args.adjudications is not None else []
        )
        report = finalize_screening(_load_json(args.screening_report), adjudications)
        write_json(args.output, report)
        return 0 if report["valid"] else 1
    if args.command == "make-authoring-packets":
        result = build_authoring_packets(
            read_jsonl(args.screening_packets), _load_json(args.finalization)
        )
        for role, packets in result.items():
            write_jsonl(args.output_dir / f"{role}-packets.jsonl", packets)
        return 0
    if args.command == "validate-cases":
        _require_private_or_external(args.responses, purpose="case responses")
        _require_private_or_external(args.output, purpose="private case report")
        report = validate_case_responses(
            read_jsonl(args.packets), read_jsonl(args.responses)
        )
        write_json(args.output, report)
        return 0 if report["valid"] else 1
    if args.command == "make-label-packets":
        _require_private_or_external(args.case_report, purpose="private case report")
        _require_private_or_external(args.output, purpose="hidden label packets")
        packets = build_label_packets(
            read_jsonl(args.case_packets), _load_json(args.case_report)
        )
        write_jsonl(args.output, packets)
        return 0
    if args.command == "validate-labels":
        _require_private_or_external(args.case_report, purpose="private case report")
        _require_private_or_external(args.responses, purpose="hidden label responses")
        _require_private_or_external(args.output, purpose="private label report")
        if args.adjudications is not None:
            _require_private_or_external(
                args.adjudications, purpose="hidden label adjudications"
            )
        adjudications = (
            read_jsonl(args.adjudications) if args.adjudications is not None else []
        )
        report = validate_label_responses(
            read_jsonl(args.packets),
            _load_json(args.case_report),
            read_jsonl(args.responses),
            adjudications,
        )
        write_json(args.output, report)
        return 0 if report["valid"] else 1
    if args.command == "validate-role-separation":
        _require_private_or_external(
            args.spec_responses, purpose="specification responses"
        )
        _require_private_or_external(args.case_responses, purpose="case responses")
        _require_private_or_external(args.label_responses, purpose="label responses")
        _require_private_or_external(
            args.baseline_responses, purpose="baseline responses"
        )
        _require_private_or_external(args.output, purpose="role separation report")
        report = validate_role_separation(
            {
                "spec": read_jsonl(args.spec_responses),
                "case": read_jsonl(args.case_responses),
                "label": read_jsonl(args.label_responses),
                "baseline": read_jsonl(args.baseline_responses),
            }
        )
        write_json(args.output, report)
        return 0 if report["valid"] else 1
    if args.command == "freeze-hidden":
        manifest = freeze_hidden_files(_parse_named_paths(args.file))
        write_json(args.output, manifest)
        return 0
    if args.command == "freeze-baseline":
        hidden_manifest = _load_json(args.hidden_manifest)
        verify_hash_manifest(hidden_manifest)
        manifest = freeze_deterministic_baselines(
            _parse_named_paths(args.artifact),
            authoring_packets_sha256=sha256_bytes(args.authoring_packets.read_bytes()),
            hidden_manifest_sha256=str(hidden_manifest["manifest_sha256"]),
            authorship=_load_json(args.authorship),
            attestation=_load_json(args.attestation),
        )
        write_json(args.output, manifest)
        return 0
    if args.command == "check-baseline":
        report = check_deterministic_baseline_freeze(
            _load_json(args.manifest), _parse_named_paths(args.artifact)
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if args.command == "record-unblinding":
        receipt = build_unblinding_receipt(
            _load_json(args.hidden_manifest),
            _load_json(args.baseline_manifest),
            _parse_named_paths(args.hidden_file),
            _parse_named_paths(args.artifact),
        )
        write_json(args.output, receipt)
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
