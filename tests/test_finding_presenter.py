from rules_as_programs.ui.finding_presenter import (
    classify_text,
    evidence_sections,
    present_finding,
    utf16_range,
)


def test_classifies_json_jsonl_evidence_and_plain_text():
    assert classify_text('{"a": 1}').format == "json"
    assert classify_text('{"a": 1}\n{"b": 2}').format == "jsonl"
    assert classify_text('{"a": 1}\nnot json').format == "plain"
    assert classify_text("42").format == "plain"
    evidence = "## Latest message\nhello\n\n## Recent activity\n- command"
    assert classify_text(evidence).format == "rap-evidence-v1"
    assert [item["label"] for item in evidence_sections(evidence)] == [
        "Latest message", "Recent activity"]
    assert utf16_range("a😀bc", 1, 3) == (1, 3)


def test_present_finding_keeps_exact_source_separate_from_formatting():
    exact = '{"message":"hello","nested":{"value":1}}'
    detail = {
        "finding": {
            "rule_title": "Rule",
            "severity": "warn",
            "message": "Finding",
            "project_root": "/project",
            "ts": 2,
        },
        "evaluation": {
            "kind": "paw",
            "input": {
                "text": exact,
                "recording_complete": True,
                "char_count": len(exact),
            },
            "output": {
                "raw": "WARNING",
                "severity": "warn",
                "message": "Finding",
            },
            "trigger": {"event_id": "trigger"},
        },
        "ledger": {
            "events": [
                {"id": "before", "text": "before"},
                {"id": "trigger", "text": "trigger", "is_trigger": True},
                {"id": "after", "text": "after"},
            ],
        },
        "occurrence_count": 125,
        "current_rule": {"definition": {"source_path": "/rule.py"}},
    }
    presented = present_finding(detail)
    assert presented["input_text"] == exact
    assert presented["input_presentation"].source == exact
    assert '"nested": {' in presented["input_presentation"].formatted
    assert presented["output_raw"] == "WARNING"
    assert presented["occurrences"] == 125
    assert [event["id"] for event in presented["context_preview"]] == [
        "before", "trigger", "after"]


def test_legacy_incomplete_input_is_not_claimed_exact():
    presented = present_finding({
        "finding": {"rule_title": "Legacy", "evidence": "preview"},
        "evaluation": {
            "kind": "deterministic",
            "input": {
                "text": "preview",
                "recording_complete": False,
                "truncation_reason": "legacy_audit_record",
            },
            "output": {"severity": "warn", "message": "finding"},
        },
    })
    assert not presented["input"]["recording_complete"]


def test_trigger_snapshot_survives_missing_ledger():
    presented = present_finding({
        "finding": {"rule_title": "Rule"},
        "evaluation": {
            "kind": "paw",
            "input": {"text": "input", "recording_complete": True},
            "output": {"raw": "WARNING", "severity": "warn"},
            "trigger": {
                "event_id": "event",
                "event": {
                    "id": "event",
                    "kind": "message",
                    "text": "recorded trigger",
                },
            },
        },
        "ledger": {"events": []},
    })
    assert presented["context_preview"][0]["is_trigger"]
    assert presented["context_preview"][0]["from_snapshot"]


def test_context_page_without_trigger_is_not_replaced_by_snapshot():
    detail = {
        "finding": {"rule_title": "Rule"},
        "evaluation": {
            "kind": "paw",
            "input": {"text": "input", "recording_complete": True},
            "output": {"raw": "WARNING", "severity": "warn"},
            "trigger": {
                "event_id": "trigger",
                "event": {
                    "id": "trigger", "kind": "message", "text": "trigger"},
            },
        },
        "ledger": {
            "events": [
                {"id": "page-1", "kind": "shell_exec", "text": "one"},
                {"id": "page-2", "kind": "shell_exec", "text": "two"},
            ],
        },
    }
    presented = present_finding(detail)
    assert [event["id"] for event in presented["context_events"]] == [
        "page-1", "page-2"]


def test_recorded_plain_format_prevents_false_evidence_projection():
    text = "## Latest message\nThis is custom input, not RAP evidence."
    presented = present_finding({
        "finding": {"rule_title": "Custom"},
        "evaluation": {
            "kind": "paw",
            "input": {
                "text": text,
                "format": "plain",
                "recording_complete": True,
            },
            "output": {"raw": "WARNING", "severity": "warn"},
        },
    })
    assert presented["input_presentation"].format == "plain"
    assert presented["input_sections"] == []
