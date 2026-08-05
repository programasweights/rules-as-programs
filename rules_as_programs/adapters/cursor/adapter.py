"""Cursor Agent Hook <-> normalized Event mapping, plus hook installation.

V1 subscribes to observation hooks only (plus ``stop`` as a per-turn
checkpoint), so nothing here ever blocks or corrects the agent -- it only
observes. The full blocking set (``beforeShellExecution`` etc.) is intentionally
left unregistered for a later enforcement phase.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from ... import config
from ...core.events import (
    Event,
    FILE_EDIT,
    MESSAGE,
    SESSION_START,
    SESSION_STOP,
    SHELL_EXEC,
    THOUGHT,
    TOOL_FAILURE,
    QUESTION_REQUEST,
    TOOL_RESULT,
    TOOL_USE,
    USER_PROMPT,
)
from ...core.triggers import ORDERED_TRIGGERS
from ..base import Adapter

# Cursor hook event -> we register a single client for all of these.
SUBSCRIBED_HOOKS = [definition.hook for definition in ORDERED_TRIGGERS]


def _project_root(raw: dict[str, Any]) -> str:
    roots = raw.get("workspace_roots")
    if isinstance(roots, list) and roots:
        return str(roots[0])
    return os.environ.get("CURSOR_PROJECT_DIR") or os.getcwd()


def _conversation_id(raw: dict[str, Any]) -> str:
    return (
        raw.get("conversation_id")
        or raw.get("session_id")
        or raw.get("generation_id")
        or "unknown"
    )


def normalize(raw: dict[str, Any]) -> list[Event]:
    """Map one Cursor hook payload to zero or more normalized events."""
    name = raw.get("hook_event_name", "")
    conv = _conversation_id(raw)
    proj = _project_root(raw)

    def mk(
        kind: str,
        payload: dict[str, Any],
        *,
        hook_name: str = name,
    ) -> Event:
        return Event(
            kind=kind,
            conversation_id=conv,
            project_root=proj,
            generation_id=str(raw.get("generation_id", "")),
            hook_name=hook_name,
            raw_payload=dict(raw),
            payload=payload,
        )

    if name == "beforeSubmitPrompt":
        return [mk(USER_PROMPT, {
            "text": raw.get("prompt", ""),
            "attachments": raw.get("attachments", []),
        })]

    if name == "afterAgentThought":
        return [mk(THOUGHT, {"text": raw.get("text", ""),
                             "duration_ms": raw.get("duration_ms")})]
    if name == "afterAgentResponse":
        return [mk(MESSAGE, {"text": raw.get("text", "")})]
    if name == "beforeShellExecution":
        return [mk("shell_attempt", {
            "command": raw.get("command", ""),
            "cwd": raw.get("cwd", ""),
            "sandbox": raw.get("sandbox"),
        })]
    if name == "afterShellExecution":
        return [mk(SHELL_EXEC, {
            "command": raw.get("command", ""),
            "output": raw.get("output", ""),
            "duration": raw.get("duration"),
            "sandbox": raw.get("sandbox"),
        })]
    if name == "afterFileEdit":
        return [mk(FILE_EDIT, {
            "file_path": raw.get("file_path", ""),
            "edits": raw.get("edits", []),
        })]
    if name == "afterMCPExecution":
        return [mk("mcp_result", {
            "tool_name": raw.get("tool_name", ""),
            "output": raw.get("result_json", ""),
        })]
    if name == "beforeMCPExecution":
        return [mk("mcp_attempt", {
            "tool_name": raw.get("tool_name", ""),
            "tool_input": raw.get("tool_input", ""),
        })]
    if name == "postToolUse":
        return [mk(TOOL_RESULT, {
            "tool_name": raw.get("tool_name", ""),
            "output": raw.get("tool_output", ""),
        })]
    if name == "preToolUse":
        tool_name = str(raw.get("tool_name", ""))
        normalized = tool_name.lower().replace("-", "").replace("_", "").replace(" ", "")
        events = [mk(TOOL_USE, {
            "tool_name": tool_name,
            "tool_input": raw.get("tool_input", ""),
        })]
        if "askquestion" in normalized:
            tool_input = raw.get("tool_input", "")
            question = ""
            if isinstance(tool_input, dict):
                question = str(tool_input.get("question", ""))
                if not question and isinstance(tool_input.get("questions"), list):
                    prompts = [
                        str(item.get("prompt", ""))
                        for item in tool_input["questions"] if isinstance(item, dict)
                    ]
                    question = " ".join(prompt for prompt in prompts if prompt)
            events.append(mk(QUESTION_REQUEST, {
                "tool_name": tool_name,
                "tool_input": tool_input,
                "question": question or str(tool_input),
            }, hook_name=""))
        return events
    if name == "postToolUseFailure":
        return [mk(TOOL_FAILURE, {
            "tool_name": raw.get("tool_name", ""),
            "tool_input": raw.get("tool_input", ""),
            "error": raw.get(
                "error_message",
                raw.get("error", raw.get("failure_message", ""))),
            "failure_type": raw.get("failure_type", ""),
        })]
    if name == "sessionStart":
        return [mk(SESSION_START, {
            "composer_mode": raw.get("composer_mode"),
            "is_background_agent": raw.get("is_background_agent"),
        })]
    if name == "sessionEnd":
        return [mk("session_end", {
            "final_status": raw.get("final_status", ""),
            "reason": raw.get("reason", ""),
            "error_message": raw.get("error_message", ""),
        })]
    if name == "subagentStart":
        return [mk("subagent_start", {
            "task": raw.get("task", ""),
            "subagent_type": raw.get("subagent_type", ""),
        })]
    if name == "subagentStop":
        return [mk("subagent_stop", {
            "summary": raw.get("summary", ""),
            "status": raw.get("status", ""),
        })]
    if name == "beforeReadFile":
        return [mk("file_read", {
            "file_path": raw.get("file_path", ""),
        })]
    if name == "preCompact":
        return [mk("pre_compact", {
            "trigger": raw.get("trigger", ""),
        })]
    if name == "beforeTabFileRead":
        return [mk("tab_file_read", {
            "file_path": raw.get("file_path", ""),
        })]
    if name == "afterTabFileEdit":
        return [mk("tab_file_edit", {
            "file_path": raw.get("file_path", ""),
            "edits": raw.get("edits", []),
        })]
    if name == "stop":
        return [mk(SESSION_STOP, {"status": raw.get("status", "completed")})]
    return []


# --- installation ----------------------------------------------------------

_WRAPPER_NAME = "rap-hook.sh"


def _hooks_dir(scope: str, project_root: str | None) -> Path:
    if scope == "global":
        return Path.home() / ".cursor" / "hooks"
    return Path(project_root or os.getcwd()) / ".cursor" / "hooks"


def _write_wrapper(scope: str, project_root: str | None) -> Path:
    """Write a tiny shell wrapper that execs the hook client with *this*
    Python interpreter, so hooks work regardless of Cursor's PATH."""
    hooks_dir = _hooks_dir(scope, project_root)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    wrapper = hooks_dir / _WRAPPER_NAME
    body = (
        "#!/bin/sh\n"
        "# Auto-generated by `rap init`. Feeds Cursor hook events to the\n"
        "# Rules-as-Programs daemon. Fail-open and near-instant.\n"
        f'exec "{sys.executable}" -m rules_as_programs.adapters.cursor.hook_client "$@"\n'
    )
    wrapper.write_text(body)
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper


def _merge_hooks_json(path: Path, command: str) -> None:
    data: dict[str, Any] = {"version": 1, "hooks": {}}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (json.JSONDecodeError, OSError):
            pass
    data.setdefault("version", 1)
    hooks = data.setdefault("hooks", {})
    for event in SUBSCRIBED_HOOKS:
        arr = hooks.setdefault(event, [])
        if not any(isinstance(h, dict) and h.get("command") == command for h in arr):
            arr.append({"command": command})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class CursorAdapter(Adapter):
    name = "cursor"

    def normalize(self, raw: dict[str, Any]) -> list[Event]:
        return normalize(raw)

    def install(self, scope: str, project_root: str | None = None) -> list[str]:
        notes: list[str] = []
        wrapper = _write_wrapper(scope, project_root)
        # Project hooks run from the project root; reference via relative path
        # so the config is portable. Global hooks use an absolute path.
        if scope == "project":
            root = Path(project_root or os.getcwd())
            command = os.path.relpath(wrapper, root)
        else:
            command = str(wrapper)
        hooks_json = config.cursor_hooks_path(scope, project_root)
        _merge_hooks_json(hooks_json, command)
        notes.append(f"wrote hook wrapper: {wrapper}")
        notes.append(f"registered {len(SUBSCRIBED_HOOKS)} hooks in {hooks_json}")
        return notes
