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
        "afterShellExecution", "shell_exec", "Executed shell command",
        "/command", "Command", "Shell & tools", 1, True, "monospace"),
    TriggerDefinition(
        "afterAgentThought", "thought", "Agent thought",
        "/text", "Agent thought", "Agent", 2, True),
    TriggerDefinition(
        "preToolUse", "tool_use", "Tool invocation",
        "/tool_name", "Tool name", "Shell & tools", 3, True, "monospace"),
    TriggerDefinition(
        "afterAgentResponse", "message", "Assistant response",
        "/text", "Assistant response", "Agent", 4, True),
    TriggerDefinition(
        "postToolUseFailure", "tool_failure", "Tool failure",
        "/error_message", "Failure message", "Shell & tools", 5, True),
    TriggerDefinition(
        "afterFileEdit", "file_edit", "Edited file",
        "/file_path", "File path", "Files", 6, True, "path"),
    TriggerDefinition(
        "beforeShellExecution", "shell_attempt", "Attempted shell command",
        "/command", "Command", "Shell & tools", 7, typography="monospace"),
    TriggerDefinition(
        "subagentStop", "subagent_stop", "Subagent result",
        "/summary", "Subagent summary", "Agent", 8),
    TriggerDefinition(
        "subagentStart", "subagent_start", "Subagent task",
        "/task", "Subagent task", "Agent", 9),
    TriggerDefinition(
        "beforeReadFile", "file_read", "Read file",
        "/file_path", "File path", "Files", 10, typography="path"),
    TriggerDefinition(
        "postToolUse", "tool_result", "Tool result",
        "/tool_output", "Tool output", "Shell & tools", 11, typography="monospace"),
    TriggerDefinition(
        "beforeMCPExecution", "mcp_attempt", "MCP invocation",
        "/tool_name", "MCP tool name", "MCP", 12,
        typography="monospace", availability="desktop"),
    TriggerDefinition(
        "afterMCPExecution", "mcp_result", "MCP result",
        "/result_json", "MCP result", "MCP", 13,
        typography="monospace", availability="desktop"),
    TriggerDefinition(
        "stop", "session_stop", "Agent stop",
        "/status", "Stop status", "Session", 14),
    TriggerDefinition(
        "preCompact", "pre_compact", "Context compaction",
        "/trigger", "Compaction trigger", "Session", 15),
    TriggerDefinition(
        "sessionEnd", "session_end", "Session end",
        "/final_status", "Final status", "Session", 16,
        availability="desktop"),
    TriggerDefinition(
        "sessionStart", "session_start", "Session start",
        "/composer_mode", "Composer mode", "Session", 17,
        availability="desktop"),
    TriggerDefinition(
        "beforeSubmitPrompt", "user_prompt", "User prompt",
        "/prompt", "User prompt", "Agent", 18),
    TriggerDefinition(
        "afterTabFileEdit", "tab_file_edit", "Tab edited file",
        "/file_path", "File path", "Tab / IDE", 19,
        typography="path", availability="ide"),
    TriggerDefinition(
        "beforeTabFileRead", "tab_file_read", "Tab read file",
        "/file_path", "File path", "Tab / IDE", 20,
        typography="path", availability="ide"),
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
