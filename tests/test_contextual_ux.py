from __future__ import annotations

import json
from pathlib import Path

from rules_as_programs import config, rules_api
from rules_as_programs.adapters.cursor.adapter import normalize
from rules_as_programs.core.attention import AttentionStore
from rules_as_programs.core import attention as attention_module
from rules_as_programs.core.events import (
    Event, MESSAGE, QUESTION_REQUEST, USER_PROMPT,
)
from rules_as_programs.core.ledger import Ledger
from rules_as_programs.core.rule import (
    RULE_ID_ALPHABET, is_rule_id, new_rule_id,
)
from rules_as_programs.core import revisions
from rules_as_programs.core.store import finding_fingerprint
from rules_as_programs.ui.model import UISnapshot
from rules_as_programs.ui.status import status_presentation
from rules_as_programs.ui.layout import (
    fit_popover_layout,
    fit_rule_editor_layout,
)


def _snapshot(*, findings=None, attention=None, status="ready", health="ready"):
    findings = findings or {}
    attention = attention or []
    return UISnapshot(status, {
        "open_count": sum(len(rows) for rows in findings.values()),
        "findings_by_project": findings,
        "attention": attention,
        "attention_count": len(attention),
        "daemon": {"health": health},
        "projects": [],
    })


def test_status_presentation_prioritizes_operations_then_severity_and_attention():
    critical = {"/p": [{"severity": "critical"}]}
    presentation = status_presentation(_snapshot(
        findings=critical, attention=[{"id": 1}]))
    assert presentation.kind == "finding"
    assert presentation.severity == "critical"
    assert presentation.badge_text == "1"
    assert presentation.attention_count == 1

    unavailable = status_presentation(_snapshot(
        findings=critical, status="unavailable"))
    assert unavailable.kind == "finding"
    assert unavailable.badge_text == "1"
    assert unavailable.unavailable

    degraded = status_presentation(_snapshot(
        findings=critical, health="degraded"))
    assert degraded.kind == "finding"
    assert degraded.badge_text == "1"
    assert degraded.incident_count == 1
    issue_snapshot = _snapshot(findings=critical)
    issue_snapshot.data["health_issues"] = [{
        "summary": "GitHub synchronization check failing",
    }]
    issue = status_presentation(issue_snapshot)
    assert issue.badge_text == "1"
    assert issue.incident_count == 1
    assert "GitHub synchronization" in issue.tooltip

    attention = status_presentation(_snapshot(attention=[{"id": 1}]))
    assert attention.kind == "attention"
    assert attention.badge_text == "?"
    many = status_presentation(_snapshot(findings={
        "/p": [{"severity": "warn"} for _ in range(100)]
    }))
    assert many.badge_text == "99+"


def test_paw_draft_is_in_memory_and_examples_are_parsed(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id)
    assert "WARNING" in source
    assert "public/logo.png" in source
    assert "EXAMPLES =" not in source
    projection = rules_api.source_projection(source)
    assert projection["inputs"] == ["shell_exec", "message"]
    assert len(rules_api.spec_examples(projection["spec"])) == 3
    assert not config.project_rules_dir(project).exists()


def test_source_projection_round_trips_and_custom_metadata_falls_back():
    source = rules_api.draft_rule_source(new_rule_id())
    projection = rules_api.source_projection(source)
    ok, patched, error = rules_api.patch_source_projection(
        source,
        on=["message"],
        inputs=["message"],
        severity="critical",
        function_source=projection["function_source"].replace(
            "ctx.result(decision)", "ctx.result(decision)", 1),
        spec=projection["spec"],
    )
    assert ok, error
    updated = rules_api.source_projection(patched)
    assert updated["on"] == ["message"]
    assert updated["inputs"] == ["message"]
    assert updated["severity"] == "critical"

    custom = source.replace("severity='warn'", "severity=DEFAULT_SEVERITY")
    assert rules_api.source_projection(custom)["custom"]
    structurally_custom = source.replace(
        "    decision = ctx.paw(SPEC)(ctx.input())",
        "    evidence = ctx.input()\n"
        "    decision = ctx.paw(SPEC)(evidence)",
    )
    assert not rules_api.source_projection(structurally_custom)["managed_fuzzy"]

    custom_source = """from rules_as_programs import rule
@rule(on=["message"], severity="warn")
def custom_rule(ctx):
    evidence = ctx.evidence(latest=["message"], include=["shell_exec", "file_edit"])
    return None
"""
    inferred = rules_api.source_projection(custom_source)
    assert inferred["inputs_inferred"]
    assert inferred["inputs"] == ["message", "shell_exec", "file_edit"]

    builtin = (
        Path(__file__).parents[1]
        / "rules_as_programs" / "builtin_rules" / "github-sync.py"
    ).read_text()
    builtin_projection = rules_api.source_projection(builtin)
    assert builtin_projection["simple_fuzzy"]
    assert builtin_projection["managed_fuzzy"]
    assert builtin_projection["allowed_label"] == "OK"


def test_plain_python_draft_uses_strict_result_contract():
    source = rules_api.draft_plain_rule_source(
        new_rule_id(), "Flag unsafe phrase")
    assert 'ctx.result("WARNING")' in source
    assert "return \"The agent used" not in source


def test_compact_identity_uses_stable_folder_and_safe_name_updates(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Original Name")
    saved = rules_api.save_rule(rule_id, source, "project", str(project))
    assert saved["ok"]
    path = project / ".cursor" / "rules-as-programs" / "rules" / rule_id / "rule.py"
    assert Path(saved["path"]) == path
    assert path.exists()

    ok, renamed, error = rules_api.patch_rule_identity(
        saved["source"], rule_id, "Renamed Rule")
    assert ok, error
    saved_again = rules_api.save_rule(rule_id, renamed, "project", str(project))
    assert saved_again["ok"]
    assert Path(saved_again["path"]) == path
    assert rules_api.source_projection(path.read_text())["name"] == "Renamed Rule"
    renamed_result = rules_api.rename_rule(
        rule_id, "Final Rule Name", project_root=str(project))
    assert renamed_result["ok"]
    assert Path(renamed_result["rule"]["path"]) == path
    projection = rules_api.source_projection(path.read_text())
    assert projection["id"] == rule_id
    assert projection["name"] == "Final Rule Name"
    assert projection["function_name"] == "final_rule_name"

    malicious = source.replace(rule_id, "../escaped")
    escaped = rules_api.save_rule("../escaped", malicious, "project", str(project))
    assert not escaped["ok"]
    assert not (project / ".cursor" / "rules-as-programs" / "escaped").exists()


def test_compact_rule_ids_are_80_bit_filesystem_safe_tokens():
    values = {new_rule_id() for _ in range(5000)}
    assert len(values) == 5000
    assert all(is_rule_id(value) for value in values)
    assert all(len(value) == 16 for value in values)
    assert all(set(value) <= set(RULE_ID_ALPHABET) for value in values)


def test_ledger_window_centers_trigger(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    ledger = Ledger("conversation", str(tmp_path))
    events = []
    for index in range(9):
        event = Event(
            kind=MESSAGE,
            conversation_id="conversation",
            project_root=str(tmp_path),
            generation_id="generation",
            payload={"text": f"message {index}"},
        )
        ledger.append(event)
        events.append(event)
    window = ledger.context_window(events[4].id, before=2, after=2)
    assert [row["text"] for row in window["events"]] == [
        "message 2", "message 3", "message 4", "message 5", "message 6"]
    assert window["events"][2]["is_trigger"]
    assert window["has_earlier"] and window["has_later"]
    frozen = ledger.context_window(
        events[2].id, before=10, after=10, through_seq=4)
    assert frozen["total"] == 4
    assert frozen["through_seq"] == 4
    assert [row["seq"] for row in frozen["events"]] == [1, 2, 3, 4]


def test_attention_lifecycle_and_cursor_prompt_events(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    store = AttentionStore()
    attention_id = store.set(
        project_root="/project",
        conversation_id="conversation",
        generation_id="generation",
        message="Which database should I use?",
        confidence="inferred",
        source="agent-needs-reply",
    )
    assert store.active()[0]["id"] == attention_id
    assert store.clear(conversation_id="conversation") == 1
    assert store.active() == []

    prompt = normalize({
        "hook_event_name": "beforeSubmitPrompt",
        "conversation_id": "conversation",
        "generation_id": "generation-2",
        "workspace_roots": ["/project"],
        "prompt": "Use staging.",
    })[0]
    assert prompt.kind == USER_PROMPT
    assert prompt.generation_id == "generation-2"

    question = normalize({
        "hook_event_name": "preToolUse",
        "conversation_id": "conversation",
        "generation_id": "generation-1",
        "workspace_roots": ["/project"],
        "tool_name": "AskQuestion",
        "tool_input": {"question": "Which database?"},
    })[0]
    assert question.kind == QUESTION_REQUEST


def test_attention_expires(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    now = {"value": 100.0}
    monkeypatch.setattr(attention_module.time, "time", lambda: now["value"])
    store = AttentionStore()
    store.set(
        project_root="/project",
        conversation_id="conversation",
        generation_id="generation",
        message="Need input",
        confidence="inferred",
        source="detector",
    )
    now["value"] = 200.0
    assert store.active(ttl_seconds=50) == []


def test_last_good_revision_and_revision_aware_fingerprints(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    rule_id = new_rule_id()
    source_path = tmp_path / "rule.py"
    source_path.write_text("value = 1\n")
    active = revisions.activate(rule_id, source_path, "value = 1\n")
    assert revisions.active_info(rule_id, source_path)["source_hash"] == active["source_hash"]

    source_path.write_text("value = 2\n")
    status = revisions.working_status(
        rule_id, source_path, source_path.read_text())
    assert status["draft_changes"]
    assert status["active_hash"] == active["source_hash"]

    first = finding_fingerprint("/project", rule_id, "violation", active["source_hash"])
    second_hash = revisions.hash_source("value = 2\n")
    second = finding_fingerprint("/project", rule_id, "violation", second_hash)
    assert first != second

    snapshot = _snapshot(findings={
        "/project": [
            {"severity": "critical", "stale": True},
            {"severity": "warn", "stale": False},
        ]
    })
    presentation = status_presentation(snapshot)
    assert presentation.severity == "warn"


def test_promote_customize_and_revert_shared_rule(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    global_rules = tmp_path / "global-rules"
    monkeypatch.setattr(config, "global_rules_dir", lambda: global_rules)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Reusable Rule")
    saved = rules_api.save_rule(rule_id, source, "project", str(project))
    assert saved["ok"]

    promoted = rules_api.promote_to_shared(rule_id, str(project))
    assert promoted["ok"]
    assert (global_rules / rule_id / "rule.py").exists()
    assert not (project / ".cursor" / "rules-as-programs" / "rules"
                / rule_id / "rule.py").exists()
    assert rules_api.is_enabled(rule_id, str(project))
    assert not rules_api.is_enabled(rule_id, None)

    customized = rules_api.customize_for_project(rule_id, str(project))
    assert customized["ok"]
    assert (project / ".cursor" / "rules-as-programs" / "rules"
            / rule_id / "rule.py").exists()
    project_info = rules_api.get_rule(rule_id, str(project))
    reverted = rules_api.revert_to_shared(
        rule_id,
        str(project),
        project_info["definition"]["source_path"],
        project_info["definition"]["source_hash"],
    )
    assert reverted["ok"]
    assert reverted["assignment_preserved"]
    assert rules_api.is_enabled(rule_id, str(project))
    assert not (project / ".cursor" / "rules-as-programs" / "rules"
                / rule_id / "rule.py").exists()
    shared_info = rules_api.get_rule(rule_id, None)
    deleted = rules_api.delete_rule_definition(
        rule_id,
        "global",
        None,
        shared_info["definition"]["source_path"],
        shared_info["definition"]["source_hash"],
        project_roots=[str(project)],
    )
    assert deleted["ok"]
    assert not (global_rules / rule_id / "rule.py").exists()
    assert json.loads(
        config.project_rules_config_path(project).read_text()
    )["rules"][rule_id]["enabled"] is True


def test_all_builtins_use_managed_fuzzy_format():
    builtin_dir = Path(__file__).parents[1] / "rules_as_programs" / "builtin_rules"
    projections = {}
    for path in builtin_dir.glob("*.py"):
        source = path.read_text()
        projection = rules_api.source_projection(source)
        assert projection["managed_fuzzy"], path.name
        assert projection["managed_version"] == 2
        assert projection["id_persisted"], path.name
        assert is_rule_id(projection["id"]), path.name
        assert "EXAMPLES =" not in source
        assert projection["output_labels"] == [
            "OK", "INFO", "WARNING", "CRITICAL"]
        projections[path.stem] = projection
    assert projections["github-sync"]["probes"]["git_status"]
    assert projections["deployment-checklist"]["probes"]["git_status"]


def test_popover_height_fits_content_and_caps_scroll():
    compact = fit_popover_layout(60, show_status=False)
    normal = fit_popover_layout(220, show_status=False)
    status = fit_popover_layout(220, show_status=True)
    capped = fit_popover_layout(5000, show_status=False, max_height=520)
    assert compact.height == 170
    assert compact.height < normal.height < capped.height
    assert status.height > normal.height
    assert capped.height == 520


def test_rule_editor_layout_fits_mode_and_visible_screen():
    managed = fit_rule_editor_layout(
        advanced=False, available_width=1400, available_height=900)
    advanced = fit_rule_editor_layout(
        advanced=True, available_width=1400, available_height=900)
    compact = fit_rule_editor_layout(
        advanced=False, available_width=700, available_height=560)
    with_callout = fit_rule_editor_layout(
        advanced=False, optional_height=72,
        available_width=1400, available_height=900)

    assert (managed.width, managed.height) == (760, 600)
    assert advanced.width > managed.width
    assert advanced.height > managed.height
    assert compact.width == 680
    assert compact.height == 520
    assert compact.stacked_metadata
    assert with_callout.height > managed.height


def test_timed_snooze_api_is_not_part_of_finding_workflow():
    assert not hasattr(rules_api, "snooze")
