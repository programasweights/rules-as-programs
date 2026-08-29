"""One-trigger/one-input contracts for transparent monitoring rules."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TriggerDefinition:
    hook: str
    event_kind: str
    label: str
    input_pointer: str
    input_label: str
    category: str
    rank: int
    common: bool = False
    typography: str = "proportional"
    availability: str = "all"


_DEFINITIONS = (
    TriggerDefinition(
        "Stop", "message", "Assistant response",
        "/last_assistant_message", "Assistant response", "Agent", 1, True),
    TriggerDefinition(
        "PreToolUse", "tool_use", "Tool invocation",
        "/tool_input", "Tool input", "Shell & tools", 2, True, "monospace"),
    TriggerDefinition(
        "PostToolUse", "tool_result", "Tool result",
        "/tool_response", "Tool result", "Shell & tools", 3, True, "monospace"),
    TriggerDefinition(
        "UserPromptSubmit", "user_prompt", "User prompt",
        "/prompt", "User prompt", "Agent", 4, True),
    TriggerDefinition(
        "SubagentStop", "subagent_stop", "Subagent response",
        "/last_assistant_message", "Subagent response", "Agent", 5, True),
    TriggerDefinition(
        "PermissionRequest", "permission_request", "Approval request",
        "/tool_name", "Tool name", "Shell & tools", 6, True, "monospace"),
    TriggerDefinition(
        "SubagentStart", "subagent_start", "Subagent start",
        "/agent_type", "Subagent type", "Agent", 7),
    TriggerDefinition(
        "PreCompact", "pre_compact", "Before context compaction",
        "/trigger", "Compaction trigger", "Session", 8),
    TriggerDefinition(
        "PostCompact", "post_compact", "After context compaction",
        "/trigger", "Compaction trigger", "Session", 9),
    TriggerDefinition(
        "SessionStart", "session_start", "Session start",
        "/source", "Start source", "Session", 10),
    TriggerDefinition(
        "SessionEnd", "session_end", "Session end",
        "/reason", "End reason", "Session", 11),
)

TRIGGERS = {definition.hook: definition for definition in _DEFINITIONS}
ORDERED_TRIGGERS = tuple(sorted(_DEFINITIONS, key=lambda item: item.rank))
COMMON_TRIGGERS = tuple(item for item in ORDERED_TRIGGERS if item.common)


class InputPointerError(ValueError):
    pass


def resolve_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise InputPointerError("JSON Pointer must be empty or start with '/'")
    current = document
    for encoded in pointer.split("/")[1:]:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise InputPointerError(f"input field missing at {pointer}")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
                current = current[index]
            except (ValueError, IndexError):
                raise InputPointerError(f"input field missing at {pointer}") from None
        else:
            raise InputPointerError(f"input field missing at {pointer}")
    return current


def serialize_input(value: Any) -> tuple[str, str]:
    if isinstance(value, str):
        return value, "string"
    if value is None:
        return "null", "null"
    if isinstance(value, bool):
        return ("true" if value else "false"), "boolean"
    if isinstance(value, (int, float)):
        return json.dumps(value, ensure_ascii=False), "number"
    if isinstance(value, (dict, list)):
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, indent=2), (
                "object" if isinstance(value, dict) else "array")
    raise InputPointerError(
        f"unsupported input value type: {type(value).__name__}")


def extract_input(
    hook: str, raw_payload: dict[str, Any], override: str = ""
) -> tuple[str, str, str, bool]:
    definition = TRIGGERS.get(hook)
    if definition is None:
        raise InputPointerError(f"unsupported trigger: {hook}")
    pointer = override or definition.input_pointer
    value = resolve_pointer(raw_payload, pointer)
    text, value_type = serialize_input(value)
    return text, pointer, value_type, bool(override)
