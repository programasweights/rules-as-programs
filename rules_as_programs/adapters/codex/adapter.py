"""Codex lifecycle hooks <-> normalized events, plus hook installation.

Rules as Programs is observation-only. Installed command handlers therefore run
as background hooks and the hook client always returns an empty JSON object.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

from ... import config
from ...core.events import (
    Event,
    MESSAGE,
    QUESTION_REQUEST,
    SESSION_START,
    SESSION_STOP,
    TOOL_FAILURE,
    TOOL_RESULT,
    TOOL_USE,
    USER_PROMPT,
)
from ...core.triggers import ORDERED_TRIGGERS
from ..base import Adapter

# One lightweight client observes every event that can carry a rule input or
# useful session context. These names are the public Codex hook names.
SUBSCRIBED_HOOKS = tuple(definition.hook for definition in ORDERED_TRIGGERS)


def event_identity(event: Event) -> str:
    """Return a stable identity for duplicate deliveries of one Codex hook.

    Codex can invoke both a global and a project-local RAP handler for the same
    lifecycle event.  Normalization intentionally gives each in-memory Event a
    fresh id and timestamp, so neither field belongs in the ingress identity.
    The normalized kind remains part of the key because one raw hook can emit
    multiple meaningful events (for example, Stop emits a message and a
    session checkpoint).
    """
    raw = event.raw_payload
    if not isinstance(raw, dict) or not raw:
        return ""
    session_id = str(raw.get("session_id") or event.conversation_id)
    turn_id = str(raw.get("turn_id") or event.generation_id)
    hook_name = str(raw.get("hook_event_name") or event.hook_name)
    if not hook_name:
        return ""
    tool_use_id = str(raw.get("tool_use_id") or "")
    if tool_use_id:
        source_identity = f"tool:{tool_use_id}"
    else:
        canonical = json.dumps(
            event.payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        source_identity = (
            "payload:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )
    return "\x00".join((session_id, turn_id, hook_name, event.kind, source_identity))


def _project_root(raw: dict[str, Any]) -> str:
    """Resolve a stable project root from Codex's event ``cwd``.

    Codex exposes the active working directory rather than a separate workspace
    root. Prefer the nearest project-local Codex layer, then a Git worktree root,
    and finally the working directory itself.
    """
    value = str(raw.get("cwd") or os.getcwd())
    try:
        cwd = Path(value).expanduser().resolve()
    except OSError:
        return value
    current = cwd if cwd.is_dir() else cwd.parent
    parents = (current, *current.parents)
    for candidate in parents:
        codex_dir = candidate / ".codex"
        if (codex_dir / "hooks.json").exists() or (
            codex_dir / config.APP_NAME
        ).exists():
            return str(candidate)
    for candidate in parents:
        if (candidate / ".git").exists():
            return str(candidate)
    return str(current)


def _question_text(tool_input: Any) -> str:
    if not isinstance(tool_input, dict):
        return str(tool_input or "")
    direct = tool_input.get("question") or tool_input.get("prompt")
    if direct:
        return str(direct)
    questions = tool_input.get("questions")
    if isinstance(questions, list):
        prompts = []
        for item in questions:
            if not isinstance(item, dict):
                continue
            text = item.get("question") or item.get("prompt")
            if text:
                prompts.append(str(text))
        if prompts:
            return " ".join(prompts)
    return json.dumps(tool_input, ensure_ascii=False, sort_keys=True)


def _tool_failed(response: Any) -> bool:
    if not isinstance(response, dict):
        return False
    return bool(
        response.get("isError")
        or response.get("is_error")
        or response.get("error")
        or response.get("success") is False
    )


def normalize(raw: dict[str, Any]) -> list[Event]:
    """Map one documented Codex hook payload to normalized events."""
    name = str(raw.get("hook_event_name") or "")
    conversation = str(raw.get("session_id") or "unknown")
    project = _project_root(raw)
    turn_id = str(raw.get("turn_id") or "")

    def event(
        kind: str,
        payload: dict[str, Any],
        *,
        hook_name: str = name,
    ) -> Event:
        return Event(
            kind=kind,
            conversation_id=conversation,
            project_root=project,
            generation_id=turn_id,
            hook_name=hook_name,
            raw_payload=dict(raw),
            payload=payload,
        )

    if name == "UserPromptSubmit":
        return [event(USER_PROMPT, {"text": raw.get("prompt", "")})]

    if name == "PreToolUse":
        tool_name = str(raw.get("tool_name") or "")
        tool_input = raw.get("tool_input")
        events = [
            event(
                TOOL_USE,
                {
                    "tool_name": tool_name,
                    "tool_input": tool_input,
                    "tool_use_id": raw.get("tool_use_id", ""),
                },
            )
        ]
        normalized_name = "".join(char for char in tool_name.lower() if char.isalnum())
        if "askquestion" in normalized_name or "requestuserinput" in normalized_name:
            events.append(
                event(
                    QUESTION_REQUEST,
                    {
                        "tool_name": tool_name,
                        "tool_input": tool_input,
                        "question": _question_text(tool_input),
                    },
                    hook_name="",
                )
            )
        return events

    if name == "PermissionRequest":
        return [
            event(
                "permission_request",
                {
                    "tool_name": raw.get("tool_name", ""),
                    "tool_input": raw.get("tool_input"),
                },
            )
        ]

    if name == "PostToolUse":
        tool_name = str(raw.get("tool_name") or "")
        response = raw.get("tool_response")
        kind = TOOL_FAILURE if _tool_failed(response) else TOOL_RESULT
        payload = {
            "tool_name": tool_name,
            "tool_input": raw.get("tool_input"),
            "tool_use_id": raw.get("tool_use_id", ""),
        }
        if kind == TOOL_FAILURE:
            payload["error"] = response
        else:
            payload["output"] = response
        return [event(kind, payload)]

    if name == "Stop":
        # The first event is the rule trigger and preserves the final response in
        # Session Activity. The second is an internal lifecycle checkpoint with
        # no hook name, so Stop rules evaluate exactly once.
        return [
            event(MESSAGE, {"text": raw.get("last_assistant_message")}),
            event(
                SESSION_STOP,
                {
                    "status": "completed",
                    "stop_hook_active": bool(raw.get("stop_hook_active")),
                },
                hook_name="",
            ),
        ]

    if name == "SessionStart":
        return [event(SESSION_START, {"source": raw.get("source", "")})]
    if name == "SessionEnd":
        return [event("session_end", {"reason": raw.get("reason", "")})]
    if name == "SubagentStart":
        return [
            event(
                "subagent_start",
                {
                    "agent_id": raw.get("agent_id", ""),
                    "agent_type": raw.get("agent_type", ""),
                },
            )
        ]
    if name == "SubagentStop":
        return [
            event(
                "subagent_stop",
                {
                    "agent_id": raw.get("agent_id", ""),
                    "agent_type": raw.get("agent_type", ""),
                    "summary": raw.get("last_assistant_message"),
                },
            )
        ]
    if name == "PreCompact":
        return [event("pre_compact", {"trigger": raw.get("trigger", "")})]
    if name == "PostCompact":
        return [event("post_compact", {"trigger": raw.get("trigger", "")})]
    return []


_WRAPPER_NAME = "rap-hook.sh"


def _hooks_dir(scope: str, project_root: str | None) -> Path:
    if scope == "global":
        return config.codex_home() / "hooks"
    return Path(project_root or os.getcwd()) / ".codex" / "hooks"


def _write_wrapper(scope: str, project_root: str | None) -> Path:
    """Pin the interpreter used at install time for reliable hook launches."""
    hooks_dir = _hooks_dir(scope, project_root)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    wrapper = hooks_dir / _WRAPPER_NAME
    body = (
        "#!/bin/sh\n"
        "# Auto-generated by `rap init`. Feeds Codex lifecycle events to the\n"
        "# Rules-as-Programs daemon. Observation-only and fail-open.\n"
        f"exec {shlex.quote(sys.executable)} "
        '-m rules_as_programs.adapters.codex.hook_client "$@"\n'
    )
    wrapper.write_text(body, encoding="utf-8")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return wrapper


def _handler(command: str, hook_name: str) -> dict[str, Any]:
    handler: dict[str, Any] = {
        "type": "command",
        "command": command,
    }
    if hook_name == "SessionEnd":
        # Codex always runs SessionEnd synchronously and caps its timeout at 3s.
        handler["timeout"] = 1
    else:
        handler.update({"async": True, "timeout": 5})
    return handler


def _is_rap_handler(item: Any) -> bool:
    """Recognize current and legacy spellings of the installed RAP wrapper."""
    return isinstance(item, dict) and _WRAPPER_NAME in str(item.get("command", ""))


def _consolidate_rap_handlers(
    groups: list[Any], command: str, hook_name: str
) -> tuple[list[Any], bool]:
    """Keep exactly one upgraded RAP handler while preserving other hooks."""
    found = False
    consolidated: list[Any] = []
    for group in groups:
        if not isinstance(group, dict):
            consolidated.append(group)
            continue
        handlers = group.get("hooks")
        if not isinstance(handlers, list):
            consolidated.append(group)
            continue
        kept_handlers: list[Any] = []
        for item in handlers:
            if not _is_rap_handler(item):
                kept_handlers.append(item)
                continue
            if found:
                continue
            # Preserve harmless display metadata on the first existing entry,
            # but replace execution fields and command quoting.  Older builds
            # sometimes stored an extra quoted absolute path, which otherwise
            # evades exact-string matching and creates duplicate deliveries.
            updated = dict(item)
            updated.pop("async", None)
            updated.pop("timeout", None)
            updated.update(_handler(command, hook_name))
            kept_handlers.append(updated)
            found = True
        if kept_handlers:
            updated_group = dict(group)
            updated_group["hooks"] = kept_handlers
            consolidated.append(updated_group)
    return consolidated, found


def _merge_hooks_json(path: Path, command: str) -> None:
    data: dict[str, Any] = {"hooks": {}}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (json.JSONDecodeError, OSError):
            pass
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        data["hooks"] = hooks
    for hook_name in SUBSCRIBED_HOOKS:
        groups = hooks.setdefault(hook_name, [])
        if not isinstance(groups, list):
            groups = []
        groups, found = _consolidate_rap_handlers(groups, command, hook_name)
        if not found:
            groups.append({"hooks": [_handler(command, hook_name)]})
        hooks[hook_name] = groups
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def remove_installed_hooks(path: Path) -> bool:
    """Remove RAP handlers from one Codex hook file while preserving others."""
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    changed = False
    for hook_name in tuple(hooks):
        groups = hooks.get(hook_name)
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            if not isinstance(group, dict):
                kept_groups.append(group)
                continue
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                kept_groups.append(group)
                continue
            kept_handlers = [item for item in handlers if not (_is_rap_handler(item))]
            if len(kept_handlers) != len(handlers):
                changed = True
            if kept_handlers:
                updated = dict(group)
                updated["hooks"] = kept_handlers
                kept_groups.append(updated)
        if kept_groups:
            hooks[hook_name] = kept_groups
        else:
            hooks.pop(hook_name, None)
    if changed:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return changed


class CodexAdapter(Adapter):
    name = "codex"

    def normalize(self, raw: dict[str, Any]) -> list[Event]:
        return normalize(raw)

    def install(self, scope: str, project_root: str | None = None) -> list[str]:
        wrapper = _write_wrapper(scope, project_root)
        if scope == "project" and (Path(project_root or os.getcwd()) / ".git").exists():
            command = '"$(git rev-parse --show-toplevel)/.codex/hooks/rap-hook.sh"'
        else:
            command = shlex.quote(str(wrapper))
        hooks_json = config.codex_hooks_path(scope, project_root)
        _merge_hooks_json(hooks_json, command)
        return [
            f"wrote hook wrapper: {wrapper}",
            f"registered {len(SUBSCRIBED_HOOKS)} hooks in {hooks_json}",
        ]
