from __future__ import annotations

import hashlib
import sqlite3

from rules_as_programs.core import audit
from rules_as_programs.core.store import Verdict, VerdictStore


def _legacy_db(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_title TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            project_root TEXT NOT NULL,
            label TEXT,
            evidence TEXT,
            fuzzy INTEGER DEFAULT 1,
            ts REAL NOT NULL
        );
        INSERT INTO verdicts
            (rule_id, rule_title, severity, message, conversation_id,
             project_root, label, evidence, fuzzy, ts)
        VALUES ('legacy', 'Legacy', 'warn', 'old finding', 'c', '/tmp/p',
                '', '', 1, 1);
        """
    )
    connection.commit()
    connection.close()


def _verdict(project: str, *, suppressed: bool = False) -> Verdict:
    return Verdict(
        rule_id="verify",
        rule_title="Verify claims",
        severity="critical",
        message="Claim lacks evidence",
        conversation_id="conversation",
        project_root=project,
        label="UNVERIFIED",
        suppressed=suppressed,
        suppression_reason="rule muted" if suppressed else "",
    )


def test_migrates_old_database_and_groups_recurrences(tmp_path):
    path = tmp_path / "verdicts.db"
    _legacy_db(path)
    store = VerdictStore(path)

    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(verdicts)")}
    assert {
        "acknowledged", "reviewed_at", "review_reason", "suppressed",
        "fingerprint", "trigger_event_id", "trigger_kind",
    } <= columns

    first = store.record(_verdict(str(tmp_path)))
    second = store.record(_verdict(str(tmp_path)))
    group = store.by_project()[str(tmp_path)][0]
    assert group["ids"] == [second, first]
    assert group["occurrences"] == 2

    assert store.acknowledge(
        fingerprint=group["fingerprint"], reason="false_positive") == 2
    assert str(tmp_path) not in store.by_project()

    # A later occurrence is a new actionable row and reopens the issue-like group.
    third = store.record(_verdict(str(tmp_path)))
    reopened = store.by_project()[str(tmp_path)][0]
    assert reopened["ids"] == [third]
    assert reopened["occurrences"] == 1


def test_suppressed_findings_stay_out_of_inbox_but_in_history(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    finding_id = store.record(_verdict(str(tmp_path), suppressed=True))
    assert store.by_project() == {}
    history = store.history_grouped()
    assert history[0]["ids"] == [finding_id]
    assert history[0]["suppressed"] == 1


def test_deleted_rule_findings_move_to_reviewed_history(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    project = str(tmp_path)
    finding_id = store.record(_verdict(project))

    assert store.acknowledge_rule("verify", project) == 1
    assert store.by_project() == {}
    history = store.history_grouped()
    assert history[0]["ids"] == [finding_id]
    assert history[0]["review_reason"] == "rule_deleted"


def test_audit_lookup_uses_exact_finding_id(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    common = dict(
        project_root=str(project),
        rule_id="verify",
        title="Verify",
        severity="warn",
        message="message",
        conversation_id="conversation",
    )
    audit.log_violation(
        finding_id=11,
        trace=[{"type": "paw", "input": "old", "output": "BAD"}],
        **common,
    )
    audit.log_violation(
        finding_id=12,
        trace=[{"type": "paw", "input": "new", "output": "BAD"}],
        **common,
    )
    entry = audit.read_finding(str(project), 11)
    assert entry is not None
    assert entry["finding_id"] == 11
    assert entry["trace"][0]["input"] == "old"


def test_audit_marks_over_limit_evaluation_input_incomplete(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    text = "😀" * 70000
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    audit.log_violation(
        str(project), 7, "rule", "Rule", "warn", "message", [],
        evaluation={
            "schema_version": 2,
            "input": {
                "text": text,
                "sha256": digest,
                "char_count": len(text),
                "byte_count": len(text.encode("utf-8")),
                "recording_complete": True,
            },
            "output": {"raw": "WARNING", "recording_complete": True},
        },
    )
    recorded = audit.read_finding(str(project), 7)["evaluation"]["input"]
    assert len(recorded["text"]) == audit.MAX_EVALUATED_INPUT
    assert not recorded["recording_complete"]
    assert recorded["sha256"] == digest
    assert recorded["char_count"] == 70000


def test_group_uses_highest_open_severity_not_latest(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    base = dict(
        rule_id="rule",
        rule_title="Rule",
        message="same finding",
        conversation_id="conversation",
        project_root="/project",
        source_hash="revision",
    )
    store.record(Verdict(severity="critical", **base))
    store.record(Verdict(severity="info", **base))
    group = store.by_project()["/project"][0]
    assert group["severity"] == "critical"
    assert group["latest_severity"] == "info"


def test_review_by_fingerprint_handles_more_than_occurrence_page(tmp_path):
    store = VerdictStore(tmp_path / "verdicts.db")
    project = str(tmp_path)
    for _ in range(125):
        store.record(_verdict(project))
    group = store.by_project()[project][0]

    assert store.occurrence_count(group["fingerprint"]) == 125
    assert store.acknowledge(
        fingerprint=group["fingerprint"], reason="reviewed") == 125
    assert store.by_project() == {}
