import pytest

from rules_as_programs.adapters.codex.adapter import normalize
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
        "Stop",
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "SubagentStop",
        "PermissionRequest",
    ]
    assert TRIGGERS["Stop"].input_pointer == "/last_assistant_message"
    assert TRIGGERS["PreToolUse"].input_pointer == "/tool_input"
    assert len(ORDERED_TRIGGERS) == 11


def test_default_and_override_json_pointers_resolve_exact_input():
    raw = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Browser",
        "tool_response": "done",
        "tool_input": {"url": "https://example.com", "a/b": {"~key": 3}},
    }
    text, pointer, value_type, overridden = extract_input(
        "PostToolUse", raw)
    assert (text, pointer, value_type, overridden) == (
        "done", "/tool_response", "string", False)
    text, pointer, value_type, overridden = extract_input(
        "PostToolUse", raw, "/tool_input/url")
    assert (text, pointer, value_type, overridden) == (
        "https://example.com", "/tool_input/url", "string", True)
    assert resolve_pointer(raw, "/tool_input/a~1b/~0key") == 3


def test_object_override_serialization_is_deterministic():
    raw = {"hook_event_name": "PreToolUse", "tool_input": {"z": 1, "a": 2}}
    text, _pointer, value_type, _overridden = extract_input(
        "PreToolUse", raw)
    assert value_type == "object"
    assert text == '{\n  "a": 2,\n  "z": 1\n}'


def test_missing_pointer_fails_instead_of_returning_empty_input():
    with pytest.raises(InputPointerError, match="input field missing"):
        extract_input(
            "Stop",
            {"hook_event_name": "Stop"},
        )


def test_codex_adapter_preserves_complete_raw_payload(tmp_path):
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "hooks.json").write_text("{}")
    raw = {
        "hook_event_name": "Stop",
        "session_id": "conversation",
        "turn_id": "generation",
        "cwd": str(tmp_path),
        "model": "model",
        "permission_mode": "default",
        "transcript_path": "/tmp/transcript.jsonl",
        "unknown_future_field": {"kept": True},
        "last_assistant_message": "response",
    }
    event = normalize(raw)[0]
    assert event.hook_name == "Stop"
    assert event.conversation_id == "conversation"
    assert event.generation_id == "generation"
    assert event.project_root == str(tmp_path)
    assert event.raw_payload == raw
    assert event.raw_payload["unknown_future_field"] == {"kept": True}


def test_tool_failure_uses_codex_tool_response():
    event = normalize({
        "hook_event_name": "PostToolUse",
        "cwd": "/project",
        "tool_name": "Shell",
        "tool_response": {"isError": True, "message": "Command timed out"},
    })[0]
    assert event.kind == "tool_failure"
    assert event.payload["error"]["message"] == "Command timed out"
    assert extract_input(
        "PostToolUse", event.raw_payload)[0] == (
            '{\n  "isError": true,\n  "message": "Command timed out"\n}'
        )


def test_successful_tool_result_keeps_output_in_session_activity():
    event = normalize({
        "hook_event_name": "PostToolUse",
        "cwd": "/project",
        "tool_name": "Browser",
        "tool_input": {"url": "https://example.com"},
        "tool_response": "status 200",
    })[0]
    assert event.kind == "tool_result"
    assert "status 200" in event.text()


def test_stop_records_response_and_internal_turn_checkpoint():
    events = normalize({
        "hook_event_name": "Stop",
        "session_id": "session",
        "turn_id": "turn",
        "cwd": "/project",
        "last_assistant_message": "Finished and verified.",
        "stop_hook_active": False,
    })

    assert [event.kind for event in events] == ["message", "session_stop"]
    assert events[0].hook_name == "Stop"
    assert events[0].payload["text"] == "Finished and verified."
    assert events[1].hook_name == ""


def test_request_user_input_creates_explicit_attention_event():
    events = normalize({
        "hook_event_name": "PreToolUse",
        "cwd": "/project",
        "tool_name": "request_user_input",
        "tool_input": {"questions": [{"question": "Which environment?"}]},
    })

    assert [event.kind for event in events] == ["tool_use", "question_request"]
    assert events[1].hook_name == ""
    assert events[1].payload["question"] == "Which environment?"
