"""Normalized event schema.

Every coding-agent integration (Cursor today, others later) maps its raw hook
payloads into these agent-agnostic :class:`Event` objects. The rest of the
system only ever sees ``Event``s, which is what keeps the core reusable.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


# Canonical event kinds. Adapters must map their raw events onto these.
THOUGHT = "thought"            # agent's visible reasoning text
MESSAGE = "message"            # assistant message text
SHELL_EXEC = "shell_exec"      # a shell command finished (command + output)
FILE_EDIT = "file_edit"        # agent edited a file (old/new strings)
TOOL_USE = "tool_use"          # a generic tool call was made
TOOL_RESULT = "tool_result"    # a tool call returned
TOOL_FAILURE = "tool_failure"  # a tool call failed
QUESTION_REQUEST = "question_request"  # explicit Ask Question, when exposed
USER_PROMPT = "user_prompt"    # user submitted a new prompt/reply
SESSION_START = "session_start"
SESSION_STOP = "session_stop"  # the agent turn ended (natural checkpoint)

ALL_KINDS = {
    THOUGHT,
    MESSAGE,
    SHELL_EXEC,
    FILE_EDIT,
    TOOL_USE,
    TOOL_RESULT,
    TOOL_FAILURE,
    QUESTION_REQUEST,
    USER_PROMPT,
    SESSION_START,
    SESSION_STOP,
}


@dataclass
class Event:
    """A single observed thing the agent thought or did.

    ``payload`` carries kind-specific fields, e.g.:
        thought/message -> {"text": str}
        shell_exec       -> {"command": str, "output": str, "duration": int}
        file_edit        -> {"file_path": str, "edits": [{"old_string","new_string"}]}
        tool_use         -> {"tool_name": str, "tool_input": Any}
        tool_result      -> {"tool_name": str, "output": str}
        session_stop     -> {"status": str}
    """

    kind: str
    conversation_id: str
    project_root: str
    generation_id: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        return cls(
            kind=d["kind"],
            conversation_id=d.get("conversation_id", "unknown"),
            project_root=d.get("project_root", ""),
            generation_id=d.get("generation_id", ""),
            payload=d.get("payload", {}),
            ts=d.get("ts", time.time()),
            id=d.get("id", uuid.uuid4().hex),
        )

    def text(self) -> str:
        """Best-effort human-readable text of this event, for PAW inputs."""
        p = self.payload
        if self.kind in (THOUGHT, MESSAGE):
            return str(p.get("text", ""))
        if self.kind == SHELL_EXEC:
            return f"$ {p.get('command','')}\n{p.get('output','')}"
        if self.kind == FILE_EDIT:
            edits = p.get("edits", [])
            body = "\n".join(
                f"- {e.get('old_string','')!r} -> {e.get('new_string','')!r}"
                for e in edits
            )
            return f"edit {p.get('file_path','')}\n{body}"
        if self.kind == TOOL_USE:
            return f"tool {p.get('tool_name','')}: {p.get('tool_input','')}"
        if self.kind == TOOL_RESULT:
            return f"tool {p.get('tool_name','')} -> {p.get('output','')}"
        if self.kind == TOOL_FAILURE:
            return f"tool {p.get('tool_name','')} failed: {p.get('error','')}"
        if self.kind == QUESTION_REQUEST:
            return f"question requested: {p.get('question','') or p.get('tool_input','')}"
        if self.kind == USER_PROMPT:
            return str(p.get("text", ""))
        return str(p)
