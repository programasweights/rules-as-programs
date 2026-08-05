from rules_as_programs.ui.finding_presenter import (
    classify_text,
    evidence_sections,
    present_finding,
    utf16_range,
)


def _detail(input_text='{"message":"hello","nested":{"value":1}}'):
    return {
        "finding": {
            "id": 1,
            "rule_id": "rule",
            "rule_title": "User rule name",
            "severity": "warn",
            "project_root": "/project",
            "ts": 2,
        },
        "evaluation": {
            "schema_version": 4,
            "rule": {
                "id": "rule",
                "name": "User rule name",
                "source": "# source\n",
            },
            "input": {
                "text": input_text,
                "format": "plain",
                "json_pointer": "/text",
                "pointer_source": "default",
                "value_type": "string",
                "event_ids": ["trigger"],
            },
            "severity": "warn",
            "trigger": {
                "event_id": "trigger",
                "hook": "afterAgentResponse",
                "event": {
                    "id": "trigger", "kind": "message", "text": "trigger"},
            },
            "context_through_seq": 3,
        },
        "ledger": {
            "events": [
                {"id": "before", "kind": "message", "text": "before"},
                {
                    "id": "trigger", "kind": "message", "text": "trigger",
                    "is_trigger": True,
                },
                {"id": "after", "kind": "message", "text": "after"},
            ],
        },
        "current_rule": {"definition": {"source_path": "/rule.py"}},
    }


def test_classifies_json_jsonl_evidence_and_plain_text():
    assert classify_text('{"a": 1}').format == "json"
    assert classify_text('{"a": 1}\n{"b": 2}').format == "jsonl"
    assert classify_text('{"a": 1}\nnot json').format == "plain"
    evidence = "## Latest message\nhello\n\n## Recent activity\n- command"
    assert classify_text(evidence).format == "rap-evidence-v1"
    assert [item["label"] for item in evidence_sections(evidence)] == [
        "Latest message", "Recent activity"]
    assert utf16_range("a😀bc", 1, 3) == (1, 3)


def test_presenter_keeps_exact_source_separate_from_formatting():
    detail = _detail()
    presented = present_finding(detail)

    assert presented["rule_name"] == "User rule name"
    assert presented["severity"] == "warn"
    assert presented["input_text"] == detail["evaluation"]["input"]["text"]
    assert '"nested": {' in presented["input_presentation"].formatted
    assert [event["id"] for event in presented["context_preview"]] == [
        "before", "trigger", "after"]
    assert "occurrences" not in presented
    assert "finding_message" not in presented
    assert "output_raw" not in presented


def test_recorded_plain_format_prevents_false_evidence_projection():
    text = "## Latest message\nThis is custom input, not RAP evidence."
    presented = present_finding(_detail(text))
    assert presented["input_presentation"].format == "plain"
    assert presented["input_text"] == text


def test_trigger_snapshot_is_used_only_when_ledger_is_empty():
    detail = _detail("input")
    detail["ledger"] = {"events": []}
    presented = present_finding(detail)
    assert presented["context_events"][0]["from_snapshot"]

    detail = _detail("input")
    detail["ledger"] = {
        "events": [
            {"id": "page-1", "kind": "shell_exec", "text": "one"},
            {"id": "page-2", "kind": "shell_exec", "text": "two"},
        ],
    }
    presented = present_finding(detail)
    assert [event["id"] for event in presented["context_events"]] == [
        "page-1", "page-2"]


def test_presenter_rejects_noncurrent_schema():
    detail = _detail()
    detail["evaluation"]["schema_version"] = 2
    try:
        present_finding(detail)
    except ValueError as error:
        assert "unsupported finding schema" in str(error)
    else:
        raise AssertionError("schema 2 should not be rendered")
