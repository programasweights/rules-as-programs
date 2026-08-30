from __future__ import annotations

import csv
import hashlib
from pathlib import Path

import pytest

from experiments.eacl2027 import uniform_heldout


def _record(record_id: str, project: str, text: str) -> dict[str, object]:
    return {
        "source_record": {
            "id": record_id,
            "project": project,
            "agent": "codex",
            "file_path": "AGENTS.md",
            "line": record_id,
            "text": text,
            "tool_charge": "required",
            "tool_modality": "shell",
            "tool_specificity": "specific",
        },
        "source_physical_line_end": int(record_id) + 1,
    }


def _authorship(actor_id: str, kind: str = "human") -> dict[str, object]:
    tools = [] if kind == "human" else ["fixture-agent"]
    return {"kind": kind, "actor_id": actor_id, "tools": tools}


def _contract() -> dict[str, str]:
    return {"trigger": "PreToolUse", "json_pointer": "/tool_input"}


def _one_included_subject() -> tuple[list[dict], dict[str, list[dict]]]:
    selected = uniform_heldout.select_repository_uniform(
        [_record("1", "alpha", "Never run npm.")], limit=1
    )
    packets = uniform_heldout.build_screening_packets(selected, source_sha256="0" * 64)
    responses = [
        {
            "packet_id": packets[0]["packet_id"],
            "decision": "include",
            "source_atom": "Never run npm.",
            "observable_contract": _contract(),
            "authorship": _authorship("screen-a"),
        },
        {
            "packet_id": packets[0]["packet_id"],
            "decision": "include",
            "source_atom": "Never run npm.",
            "observable_contract": _contract(),
            "authorship": _authorship("screen-b"),
        },
    ]
    report = uniform_heldout.validate_screening_responses(packets, responses)
    finalization = uniform_heldout.finalize_screening(
        report, target_eligible=1, screening_batch_size=1, source_project_values=1
    )
    return packets, uniform_heldout.build_authoring_packets(packets, finalization)


def test_pinned_csv_reader_checks_hash_and_exact_fields(tmp_path: Path):
    path = tmp_path / "validation_key.csv"
    fields = sorted(uniform_heldout.CSV_FIELDS)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(_record("1", "alpha", "Never run npm.")["source_record"])
    digest = hashlib.sha256(path.read_bytes()).hexdigest()

    source = uniform_heldout.read_pinned_source(path, expected_sha256=digest)

    assert source["file_sha256"] == digest
    assert source["rows"][0]["source_record"]["text"] == "Never run npm."
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        uniform_heldout.read_pinned_source(path, expected_sha256="f" * 64)


def test_repository_uniform_order_is_input_order_independent_and_domain_separated():
    rows = [
        _record("1", "Alpha", "alpha one"),
        _record("2", "Alpha", "alpha two"),
        _record("3", "Beta", "beta one"),
        _record("4", "Gamma", "gamma one"),
    ]

    first = uniform_heldout.select_repository_uniform(rows, limit=3)
    second = uniform_heldout.select_repository_uniform(list(reversed(rows)), limit=3)
    without_extra_alpha = uniform_heldout.select_repository_uniform(
        [rows[0], rows[2], rows[3]], limit=3
    )

    assert [item["source_record"]["id"] for item in first] == [
        item["source_record"]["id"] for item in second
    ]
    assert len({item["project"] for item in first}) == 3
    assert [item["project"] for item in first] == [
        item["project"] for item in without_extra_alpha
    ]
    assert all(item["selection_rank"] >= 1 for item in first)


def test_selection_hashes_match_frozen_v3_golden_vectors_and_preserve_case():
    assert uniform_heldout._selection_hash("record", "Alpha Repo", "17") == (
        "a6decd715fbbda36dcb281b0cdc9ec6d4cfbd8ce9f3e6b131d88c2e3e0c718e6"
    )
    assert uniform_heldout._selection_hash("project", "Alpha Repo") == (
        "95a72b9a2ded5b0614ce8560fc18d0d0e00fef2a7a512a4b8a4c8af9d9272c16"
    )
    assert uniform_heldout._selection_hash("record", "alpha repo", "17") == (
        "7fb857ca900fd8d7a47ebb7be2ea28c4d45cdb2dc3c945a30b679e6330730d7c"
    )
    assert uniform_heldout._selection_hash("project", "alpha repo") == (
        "98365f63afd3ae3a8fde173b01f2917b0ac87e57db9853087a9da7e8e62ec4cf"
    )
    selected = uniform_heldout.select_repository_uniform(
        [
            _record("17", "Alpha Repo", "upper-case project"),
            _record("18", "alpha repo", "lower-case project"),
        ],
        limit=2,
    )
    assert {item["project"] for item in selected} == {
        "Alpha Repo",
        "alpha repo",
    }
    alpha = next(item for item in selected if item["project"] == "Alpha Repo")
    assert alpha["within_repository_record_sha256"] == (
        "a6decd715fbbda36dcb281b0cdc9ec6d4cfbd8ce9f3e6b131d88c2e3e0c718e6"
    )
    assert alpha["repository_order_sha256"] == (
        "95a72b9a2ded5b0614ce8560fc18d0d0e00fef2a7a512a4b8a4c8af9d9272c16"
    )


def test_screening_disagreement_is_retained_and_requires_explicit_adjudication():
    selected = uniform_heldout.select_repository_uniform(
        [_record("1", "alpha", "Never run npm.")], limit=1
    )
    packets = uniform_heldout.build_screening_packets(selected, source_sha256="0" * 64)
    packet_id = packets[0]["packet_id"]
    responses = [
        {
            "packet_id": packet_id,
            "decision": "include",
            "source_atom": "Never run npm.",
            "observable_contract": _contract(),
            "authorship": _authorship("screen-a"),
        },
        {
            "packet_id": packet_id,
            "decision": "exclude",
            "primary_exclusion": "requires_multiple_events_or_order",
            "rationale": "The wording may require earlier commands.",
            "authorship": _authorship("screen-b", "agent_generated"),
        },
    ]

    report = uniform_heldout.validate_screening_responses(packets, responses)

    assert report["valid"] is True
    assert report["records"][0]["status"] == "decision_disagreement"
    assert report["records"][0]["retained"] is True
    assert report["records"][0]["all_responses_unassisted_human"] is False
    assert report["records"][0]["responses"][1]["authorship"]["kind"] == (
        "agent_generated"
    )

    unresolved = uniform_heldout.finalize_screening(
        report, target_eligible=1, screening_batch_size=1, source_project_values=1
    )
    assert unresolved["records"][0]["final_decision"] is None
    adjudicated = uniform_heldout.finalize_screening(
        report,
        [
            {
                "packet_id": packet_id,
                "final_decision": "include",
                "source_atom": "Never run npm.",
                "observable_contract": _contract(),
                "authorship": _authorship("adjudicator"),
            }
        ],
        target_eligible=1,
        screening_batch_size=1,
        source_project_values=1,
    )
    assert adjudicated["records"][0]["status"] == "decision_disagreement"
    assert adjudicated["records"][0]["resolution"] == "explicit_adjudication"


def test_screening_requires_and_compares_the_extracted_source_atom():
    selected = uniform_heldout.select_repository_uniform(
        [_record("1", "alpha", "Never run npm; always run tests.")], limit=1
    )
    packets = uniform_heldout.build_screening_packets(selected, source_sha256="0" * 64)
    packet_id = packets[0]["packet_id"]
    responses = [
        {
            "packet_id": packet_id,
            "decision": "include",
            "source_atom": atom,
            "observable_contract": _contract(),
            "authorship": _authorship(actor),
        }
        for actor, atom in (
            ("screen-a", "Never run npm."),
            ("screen-b", "Always run tests."),
        )
    ]

    disagreement = uniform_heldout.validate_screening_responses(packets, responses)

    assert disagreement["valid"] is True
    assert disagreement["records"][0]["status"] == "atom_disagreement"
    missing_atom = uniform_heldout.validate_screening_responses(
        packets,
        [
            {key: value for key, value in response.items() if key != "source_atom"}
            for response in responses
        ],
    )
    assert missing_atom["valid"] is False
    assert any("source_atom" in error for error in missing_atom["structural_errors"])


def test_finalization_applies_complete_batch_stopping_and_first_eligible_order():
    selected = uniform_heldout.select_repository_uniform(
        [
            _record(str(index), f"project-{index}", f"rule {index}")
            for index in range(1, 5)
        ],
        limit=4,
    )
    packets = uniform_heldout.build_screening_packets(selected, source_sha256="0" * 64)
    responses = []
    for packet in packets:
        for actor_suffix in ("a", "b"):
            responses.append(
                {
                    "packet_id": packet["packet_id"],
                    "decision": "include",
                    "source_atom": packet["source_record"]["text"],
                    "observable_contract": _contract(),
                    "authorship": _authorship(
                        f"{packet['packet_id']}-{actor_suffix}"
                    ),
                }
            )
    report = uniform_heldout.validate_screening_responses(packets, responses)

    finalized = uniform_heldout.finalize_screening(
        report, target_eligible=2, screening_batch_size=2, source_project_values=4
    )

    assert finalized["valid"] is True
    assert finalized["ready_for_authoring"] is True
    assert finalized["selected_records"] == 2
    expected_ids = [record["packet_id"] for record in report["records"][:2]]
    assert finalized["selected_packet_ids"] == expected_ids
    authoring = uniform_heldout.build_authoring_packets(packets, finalized)
    assert len(authoring["spec"]) == 2
    assert {packet["source_atom"] for packet in authoring["case"]} == {
        report["records"][0]["source_atom"],
        report["records"][1]["source_atom"],
    }


def test_role_packets_exclude_other_roles_hidden_material():
    _, packets = _one_included_subject()

    assert uniform_heldout.INTENDED_PAIRS_PER_RULE == 8
    assert packets["case"][0]["task"]["output"] == "exactly 8 intended contrast pairs"
    assert set(packets) == {"spec", "case", "baseline"}
    assert all(len(role_packets) == 1 for role_packets in packets.values())
    assert packets["spec"][0]["role"] == "spec_author"
    assert packets["case"][0]["role"] == "case_author"
    assert packets["baseline"][0]["role"] == "deterministic_baseline_author"
    assert "specification" not in packets["case"][0]
    assert "pairs" not in packets["spec"][0]
    assert "model predictions" in packets["spec"][0]["task"]["forbidden"]

    tampered = dict(packets["spec"][0])
    tampered["source_record"] = {**tampered["source_record"], "text": "changed"}
    with pytest.raises(ValueError, match="hash mismatch"):
        uniform_heldout._verify_packet(tampered, role="spec_author")


def test_failed_contrasts_and_label_disagreements_are_retained():
    _, authoring = _one_included_subject()
    case_packet = authoring["case"][0]
    case_response = {
        "packet_id": case_packet["packet_id"],
        "authorship": _authorship("case-author"),
        "pairs": [
            {
                "pair_id": "p1",
                "intended_violation_input": '{"command":"npm test"}',
                "intended_ok_input": '{"command":"pnpm test"}',
            },
            {
                "pair_id": "p2",
                "intended_violation_input": '{"command":"npm lint"}',
                "intended_ok_input": '{"command":"pnpm lint"}',
            },
            {
                "pair_id": "p3",
                "intended_violation_input": '{"command":"npm build"}',
                "intended_ok_input": '{"command":"pnpm build"}',
            },
        ],
    }
    case_report = uniform_heldout.validate_case_responses(
        authoring["case"], [case_response], pairs_per_rule=3
    )
    label_packets = uniform_heldout.build_label_packets(authoring["case"], case_report)
    case_by_packet = {f"label-{case['case_id']}": case for case in case_report["cases"]}
    responses = []
    for packet in label_packets:
        case = case_by_packet[packet["packet_id"]]
        if case["pair_id"] == "p1":
            labels = (
                ["WARNING", "WARNING"]
                if case["side"] == "intended_violation"
                else ["OK", "OK"]
            )
        elif case["pair_id"] == "p2":
            labels = ["OK", "OK"]
        elif case["side"] == "intended_violation":
            labels = ["WARNING", "WARNING"]
        else:
            labels = ["OK", "WARNING"]
        for actor, expected in zip(("label-a", "label-b"), labels):
            responses.append(
                {
                    "packet_id": packet["packet_id"],
                    "expected": expected,
                    "authorship": _authorship(actor),
                }
            )

    report = uniform_heldout.validate_label_responses(
        label_packets, case_report, responses
    )

    assert report["valid"] is True
    assert report["intended_contrast_counts"] == {
        "confirmed": 1,
        "failed_both_ok": 1,
        "unresolved_annotation": 1,
    }
    unresolved = next(pair for pair in report["pairs"] if pair["pair_id"] == "p3")
    assert unresolved["retained"] is True
    assert any(
        case["annotation_status"] == "disagreement" for case in unresolved["cases"]
    )
    assert len(report["cases"]) == 6


def test_role_separation_detects_actor_overlap_without_relabeling_authorship():
    separated = uniform_heldout.validate_role_separation(
        {
            "spec": [{"authorship": _authorship("spec-author")}],
            "case": [{"authorship": _authorship("case-author")}],
            "label": [{"authorship": _authorship("labeler")}],
            "baseline": [
                {"authorship": _authorship("baseline-agent", "agent_generated")}
            ],
        }
    )
    assert separated["valid"] is True
    baseline_entry = next(
        entry for entry in separated["entries"] if entry["role"] == "baseline"
    )
    assert baseline_entry["authorship"]["kind"] == "agent_generated"

    overlap = uniform_heldout.validate_role_separation(
        {
            "spec": [{"authorship": _authorship("same-person")}],
            "case": [{"authorship": _authorship("same-person")}],
            "label": [],
            "baseline": [],
        }
    )
    assert overlap["valid"] is False
    assert overlap["role_overlap"] == {"same-person": ["case", "spec"]}

    misstated = uniform_heldout.validate_role_separation(
        {
            "spec": [
                {
                    "authorship": {
                        "kind": "human",
                        "actor_id": "misstated",
                        "tools": ["an-agent"],
                    }
                }
            ]
        }
    )
    assert misstated["valid"] is False
    assert any(
        "cannot be marked human" in error for error in misstated["structural_errors"]
    )


def test_hidden_and_deterministic_freezes_detect_changes_and_enforce_phase_order(
    tmp_path: Path,
):
    hidden = tmp_path / "heldout.jsonl"
    hidden.write_text('{"private":"case"}\n', encoding="utf-8")
    baseline = tmp_path / "baseline.py"
    baseline.write_text("def judge(value):\n    return 'OK'\n", encoding="utf-8")
    hidden_manifest = uniform_heldout.freeze_hidden_files(
        {"heldout": hidden}, frozen_at_utc="2026-09-02T10:00:00+00:00"
    )
    baseline_manifest = uniform_heldout.freeze_deterministic_baselines(
        {"rule-a": baseline},
        authoring_packets_sha256="a" * 64,
        hidden_manifest_sha256=hidden_manifest["manifest_sha256"],
        authorship=_authorship("baseline-author"),
        attestation={
            "authored_from_baseline_packets_only": True,
            "heldout_inputs_seen": False,
            "heldout_labels_seen": False,
        },
        frozen_at_utc="2026-09-02T11:00:00+00:00",
    )

    receipt = uniform_heldout.build_unblinding_receipt(
        hidden_manifest,
        baseline_manifest,
        {"heldout": hidden},
        {"rule-a": baseline},
        unblinded_at_utc="2026-09-02T12:00:00+00:00",
    )

    assert receipt["phase_order_valid"] is True
    assert receipt["hidden_files_verified"] == 1
    assert receipt["baseline_artifacts_verified"] == 1

    baseline.write_text("def judge(value):\n    return 'WARNING'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed after freeze"):
        uniform_heldout.build_unblinding_receipt(
            hidden_manifest,
            baseline_manifest,
            {"heldout": hidden},
            {"rule-a": baseline},
            unblinded_at_utc="2026-09-02T12:00:00+00:00",
        )

    with pytest.raises(ValueError, match="attestation"):
        uniform_heldout.freeze_deterministic_baselines(
            {"rule-a": baseline},
            authoring_packets_sha256="a" * 64,
            hidden_manifest_sha256=hidden_manifest["manifest_sha256"],
            authorship=_authorship("baseline-author"),
            attestation={
                "authored_from_baseline_packets_only": True,
                "heldout_inputs_seen": True,
                "heldout_labels_seen": False,
            },
        )
