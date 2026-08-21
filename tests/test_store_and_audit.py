from __future__ import annotations

import sqlite3

from rules_as_programs.core import audit
from rules_as_programs.core.store import (
    FINDING_SCHEMA_VERSION,
    Verdict,
    VerdictStore,
    reset_development_finding_history,
)


def _evaluation(name: str = "Verify claims") -> dict:
    return {
        "schema_version": 4,
        "rule": {
            "id": "verify",
            "name": name,
            "source": "# rule\n",
            "source_hash": "revision",
        },
        "input": {
            "text": "## Latest message\nclaim",
            "format": "rap-evidence-v1",
            "event_ids": ["event"],
        },
        "severity": "critical",
        "trigger": {"event_id": "event", "kind": "message"},
        "context_through_seq": 1,
    }


def _verdict(project: str, *, suppressed: bool = False) -> Verdict:
    return Verdict(
        rule_id="verify",
        rule_title="Verify claims",
        severity="critical",
        conversation_id="conversation",
        project_root=project,
        evaluation=_evaluation(),
        source_hash="revision",
        behavior_hash="behavior",
        suppressed=suppressed,
        suppression_reason="rule muted" if suppressed else "",
    )


def test_old_database_is_replaced_by_strict_schema(tmp_path):
    path = tmp_path / "verdicts.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE verdicts (id INTEGER PRIMARY KEY, message TEXT)")
        connection.execute("INSERT INTO verdicts VALUES (1, 'old')")
    store = VerdictStore(path)

    with sqlite3.connect(path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(verdicts)")}
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert version == FINDING_SCHEMA_VERSION
    assert "evaluation_json" in columns
    assert "message" not in columns
    assert store.recent(include_acknowledged=True) == []


def test_group_projects_only_latest_occurrence(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    first = store.record(_verdict(str(tmp_path)))
    second = store.record(_verdict(str(tmp_path)))
    group = store.by_project()[str(tmp_path)][0]

    assert group["id"] == second
    assert group["id"] != first
    assert "occurrences" not in group
    assert group["evaluation"]["schema_version"] == 4


def test_suppressed_findings_stay_out_of_inbox_but_in_history(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    finding_id = store.record(_verdict(str(tmp_path), suppressed=True))
    assert store.by_project() == {}
    history = store.history_grouped()
    assert history[0]["id"] == finding_id
    assert history[0]["suppressed"] == 1
    assert history[0]["behavior_hash"] == "behavior"


def test_legacy_findings_backfill_behavior_identity(tmp_path):
    path = tmp_path / "verdicts.db"
    store = VerdictStore(path)
    verdict = _verdict(str(tmp_path))
    verdict.behavior_hash = ""
    store.record(verdict)

    reopened = VerdictStore(path)
    group = reopened.by_project()[str(tmp_path)][0]

    assert group["behavior_hash"]
    assert group["fingerprint"] != ""


def test_deleted_rule_findings_move_to_reviewed_history(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    project = str(tmp_path)
    finding_id = store.record(_verdict(project))

    assert store.acknowledge_rule("verify", project) == 1
    assert store.by_project() == {}
    history = store.history_grouped()
    assert history[0]["id"] == finding_id
    assert history[0]["review_reason"] == "rule_deleted"


def test_audit_lookup_requires_exact_finding_id(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    common = dict(
        project_root=str(project), rule_id="verify", title="Verify",
        severity="warn", message="", conversation_id="conversation")
    audit.log_violation(
        finding_id=11, trace=[], evaluation=_evaluation(), **common)
    audit.log_violation(
        finding_id=12, trace=[], evaluation=_evaluation(), **common)

    assert audit.read_finding(str(project), 11)["finding_id"] == 11
    assert audit.read_finding(str(project), 99) is None


def test_audit_preserves_large_exact_input(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    evaluation = _evaluation()
    evaluation["input"]["text"] = "😀" * 70000
    audit.log_violation(
        str(project), 7, "verify", "Verify", "warn", "", [],
        evaluation=evaluation)

    recorded = audit.read_finding(str(project), 7)["evaluation"]
    assert recorded["schema_version"] == 4
    assert recorded["input"]["text"] == "😀" * 70000


def test_review_by_fingerprint_handles_all_hidden_occurrences(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    project = str(tmp_path)
    for _ in range(125):
        store.record(_verdict(project))
    group = store.by_project()[project][0]

    assert group["occurrence_count"] == 125
    assert store.occurrence_count(group["fingerprint"]) == 125
    assert store.acknowledge(
        fingerprint=group["fingerprint"], reason="reviewed") == 125
    assert store.by_project() == {}


def test_reviewing_one_occurrence_keeps_group_until_all_are_reviewed(
    tmp_path
):
    store = VerdictStore(tmp_path / "verdicts.db")
    project = str(tmp_path)
    first = store.record(_verdict(project))
    second = store.record(_verdict(project))
    group = store.by_project()[project][0]
    assert group["occurrence_count"] == 2
    assert group["id"] == second

    assert store.acknowledge(ids=[second], reason="reviewed") == 1
    remaining = store.by_project()[project][0]
    assert remaining["occurrence_count"] == 1
    assert remaining["id"] == first

    assert store.acknowledge(ids=[first], reason="reviewed") == 1
    assert store.by_project() == {}


def test_development_reset_removes_db_ledgers_and_audits(monkeypatch, tmp_path):
    state = tmp_path / "state"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("RAP_STATE_DIR", str(state))
    state.mkdir()
    with sqlite3.connect(state / "verdicts.db") as connection:
        connection.execute(
            "CREATE TABLE verdicts (project_root TEXT)")
        connection.execute(
            "INSERT INTO verdicts VALUES (?)", (str(project),))
    ledgers = state / "ledgers"
    ledgers.mkdir()
    (ledgers / "conversation.jsonl").write_text("{}\n")
    log = project / ".cursor/rules-as-programs/log"
    log.mkdir(parents=True)
    (log / "audit.jsonl").write_text("{}\n")
    (log / "evaluations.jsonl").write_text("{}\n")

    reset_development_finding_history()

    assert not (state / "verdicts.db").exists()
    assert not ledgers.exists()
    assert not (log / "audit.jsonl").exists()
    assert not (log / "evaluations.jsonl").exists()
    assert (state / "finding-schema").read_text().strip() == "4"
