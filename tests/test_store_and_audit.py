from __future__ import annotations

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
        severity="high",
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
