import pytest

from rules_as_programs.adapters.cursor.adapter import normalize
from rules_as_programs.core.triggers import (
    COMMON_TRIGGERS,
    InputPointerError,
    ORDERED_TRIGGERS,
    TRIGGERS,
    extract_input,
    resolve_pointer,
)


def test_common_trigger_ranking_and_default_fields_are_explicit():
    assert [item.hook for item in COMMON_TRIGGERS] == [
        "afterShellExecution",
        "afterAgentThought",
        "preToolUse",
        "afterAgentResponse",
        "postToolUseFailure",
        "afterFileEdit",
    ]
    assert TRIGGERS["afterShellExecution"].input_pointer == "/command"
    assert TRIGGERS["afterAgentThought"].input_pointer == "/text"
    assert len(ORDERED_TRIGGERS) == 20


def test_default_and_override_json_pointers_resolve_exact_input():
    raw = {
        "hook_event_name": "postToolUse",
        "tool_name": "Browser",
        "tool_output": "done",
        "tool_input": {"url": "https://example.com", "a/b": {"~key": 3}},
    }
    text, pointer, value_type, overridden = extract_input(
        "postToolUse", raw)
    assert (text, pointer, value_type, overridden) == (
        "done", "/tool_output", "string", False)
    text, pointer, value_type, overridden = extract_input(
        "postToolUse", raw, "/tool_input/url")
    assert (text, pointer, value_type, overridden) == (
        "https://example.com", "/tool_input/url", "string", True)
    assert resolve_pointer(raw, "/tool_input/a~1b/~0key") == 3


def test_object_override_serialization_is_deterministic():
    raw = {"hook_event_name": "preToolUse", "tool_input": {"z": 1, "a": 2}}
    text, _pointer, value_type, _overridden = extract_input(
        "preToolUse", raw, "/tool_input")
    assert value_type == "object"
    assert text == '{\n  "a": 2,\n  "z": 1\n}'


def test_missing_pointer_fails_instead_of_returning_empty_input():
    with pytest.raises(InputPointerError, match="input field missing"):
        extract_input(
            "afterShellExecution",
            {"hook_event_name": "afterShellExecution"},
        )


def test_cursor_adapter_preserves_complete_raw_payload():
    raw = {
        "hook_event_name": "afterAgentResponse",
        "conversation_id": "conversation",
        "generation_id": "generation",
        "workspace_roots": ["/project"],
        "model": "model",
        "cursor_version": "3.11.0",
        "user_email": "dev@example.com",
        "transcript_path": "/tmp/transcript.jsonl",
        "unknown_future_field": {"kept": True},
        "text": "response",
    }
    event = normalize(raw)[0]
    assert event.hook_name == "afterAgentResponse"
    assert event.raw_payload == raw
    assert event.raw_payload["unknown_future_field"] == {"kept": True}


def test_tool_failure_uses_current_cursor_error_message_field():
    event = normalize({
        "hook_event_name": "postToolUseFailure",
        "workspace_roots": ["/project"],
        "tool_name": "Shell",
        "error_message": "Command timed out",
        "failure_type": "timeout",
    })[0]
    assert event.payload["error"] == "Command timed out"
    assert extract_input(
        "postToolUseFailure", event.raw_payload)[0] == "Command timed out"


def test_successful_tool_result_keeps_output_in_session_activity():
    event = normalize({
        "hook_event_name": "postToolUse",
        "workspace_roots": ["/project"],
        "tool_name": "Browser",
        "tool_input": {"url": "https://example.com"},
        "tool_output": "status 200",
    })[0]
    assert event.kind == "tool_result"
    assert "status 200" in event.text()
