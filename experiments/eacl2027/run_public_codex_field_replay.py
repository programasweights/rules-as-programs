#!/usr/bin/env python3
"""Capture exact RAP-observable fields from pinned public Codex sessions.

The runner gives ``codex exec --json`` an isolated temporary ``CODEX_HOME``
containing one harness-owned lifecycle hook.  That hook records the exact raw
Codex payload for the rule's declared trigger.  The main process then uses the
production RAP adapter and trigger serializer to extract the scalar field; it
never tries to reconstruct ``tool_input`` or ``tool_response`` from flattened
Codex JSONL items.

Formal runs require a complete protocol-v3 plan.  Smaller plans must be marked
``pilot_non_study`` and every resulting row and manifest remains ineligible for
study claims.  This file's unit tests use synthetic hook and Codex streams; they
do not launch a model session.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rules_as_programs.adapters.codex.adapter import (  # noqa: E402
    event_identity,
    normalize,
)
from rules_as_programs.core.rule import (  # noqa: E402
    is_rule_id,
    load_rule_file_with_error,
)
from rules_as_programs.core.revisions import behavior_hash  # noqa: E402
from rules_as_programs.core.triggers import (  # noqa: E402
    TRIGGERS,
    InputPointerError,
    extract_input,
)


PROTOCOL_PATH = ROOT / "protocol-v3.json"
PROTOCOL_VERSION = "3.0.0"
PROTOCOL_SHA256 = (
    "9509153c7afe3620c3ed847d9531554bf9111819d7dd4ec0612053d13333db62"
)
STUDY_NAME = "public_codex_field_replay"
FORMAL = "formal"
PILOT = "pilot_non_study"
CONDITIONS = {
    "source instruction present",
    "source instruction removed",
}
MAX_EVENTS_PER_SESSION = 30
HEX64 = re.compile(r"[0-9a-f]{64}")
COMMIT40 = re.compile(r"[0-9a-f]{40}")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SUPPORTED_FIELDS = {
    "Stop": "/last_assistant_message",
    "PreToolUse": "/tool_input",
    "PostToolUse": "/tool_response",
    "UserPromptSubmit": "/prompt",
}
TOOL_ITEM_TYPES = {
    "command_execution",
    "computer_tool_call",
    "file_change",
    "mcp_tool_call",
    "tool_call",
    "web_search",
}


class HarnessFailure(RuntimeError):
    """A named plan, schema, eligibility, or infrastructure failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": str(self),
            "details": self.details,
        }


@dataclass(frozen=True)
class ValidatedSession:
    raw: dict[str, Any]
    rule_source: Path
    task_prompt_path: Path
    task_prompt: str
    rule_max_input_bytes: int


@dataclass(frozen=True)
class ValidatedPlan:
    raw: dict[str, Any]
    path: Path
    sha256: str
    protocol_sha256: str
    sessions: dict[str, ValidatedSession]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_json_sha256(value: Any) -> str:
    return _sha256_text(_canonical_json(value))


def _read_json_object(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HarnessFailure(code, f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise HarnessFailure(code, f"{path}: expected a JSON object")
    return value


def _require_exact_keys(
    value: dict[str, Any],
    required: set[str],
    *,
    where: str,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing or unknown:
        raise HarnessFailure(
            "plan_schema_invalid",
            f"{where} has missing or unknown keys",
            details={"where": where, "missing": missing, "unknown": unknown},
        )


def _resolve_study_file(study_root: Path, relative_value: Any, where: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value:
        raise HarnessFailure("plan_schema_invalid", f"{where} must be a path string")
    relative = Path(relative_value)
    if relative.is_absolute():
        raise HarnessFailure("plan_schema_invalid", f"{where} must be relative")
    root = study_root.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise HarnessFailure(
            "plan_schema_invalid", f"{where} escapes the study root"
        ) from exc
    if not resolved.is_file():
        raise HarnessFailure("pinned_file_missing", f"{where} does not exist: {resolved}")
    return resolved


def _validate_public_repository_url(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise HarnessFailure("plan_schema_invalid", f"{where} must be a URL string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise HarnessFailure(
            "repository_not_public_https",
            f"{where} must be a credential-free HTTPS URL without query or fragment",
        )
    return value


def _validate_protocol(protocol_path: Path) -> tuple[dict[str, Any], str]:
    observed_sha = _sha256_file(protocol_path)
    if observed_sha != PROTOCOL_SHA256:
        raise HarnessFailure(
            "protocol_hash_mismatch",
            "protocol-v3 bytes differ from the runner's frozen protocol",
            details={"expected": PROTOCOL_SHA256, "observed": observed_sha},
        )
    protocol = _read_json_object(protocol_path, "protocol_schema_invalid")
    if protocol.get("protocol_version") != PROTOCOL_VERSION:
        raise HarnessFailure(
            "protocol_version_mismatch",
            f"expected protocol {PROTOCOL_VERSION}",
        )
    try:
        declared = protocol["studies"][STUDY_NAME]
        cap_text = str(declared["sampling"])
        trigger_fields = protocol["studies"]["repository_uniform_heldout"][
            "selection"
        ]["supported_trigger_fields"]
    except (KeyError, TypeError) as exc:
        raise HarnessFailure(
            "protocol_schema_invalid", "protocol-v3 replay declarations are missing"
        ) from exc
    if trigger_fields != SUPPORTED_FIELDS:
        raise HarnessFailure(
            "protocol_adapter_contract_mismatch",
            "protocol trigger fields differ from the harness contract",
            details={"protocol": trigger_fields, "harness": SUPPORTED_FIELDS},
        )
    for trigger, pointer in SUPPORTED_FIELDS.items():
        definition = TRIGGERS.get(trigger)
        if definition is None or definition.input_pointer != pointer:
            raise HarnessFailure(
                "protocol_adapter_contract_mismatch",
                f"RAP trigger {trigger} no longer exposes {pointer}",
            )
    if "30" not in cap_text or "SHA-256" not in cap_text:
        raise HarnessFailure(
            "protocol_schema_invalid", "protocol sampling declaration has changed"
        )
    return protocol, observed_sha


def _validate_codex_settings(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessFailure("plan_schema_invalid", "codex must be an object")
    required = {
        "approval_policy",
        "ephemeral",
        "executable_sha256",
        "ignore_rules",
        "isolated_codex_home",
        "model",
        "network_access",
        "reasoning_effort",
        "sandbox",
        "service_tier",
        "shell_environment_inherit",
        "strict_config",
        "timeout_seconds",
        "version",
        "web_search",
    }
    _require_exact_keys(value, required, where="codex")
    if not HEX64.fullmatch(str(value["executable_sha256"])):
        raise HarnessFailure(
            "plan_schema_invalid", "codex.executable_sha256 must be lowercase SHA-256"
        )
    for key in ("model", "reasoning_effort", "service_tier"):
        if not isinstance(value[key], str) or not value[key]:
            raise HarnessFailure("plan_schema_invalid", f"codex.{key} must be nonempty")
    if value["sandbox"] not in {"read-only", "workspace-write"}:
        raise HarnessFailure(
            "plan_schema_invalid", "codex.sandbox must be read-only or workspace-write"
        )
    if value["approval_policy"] not in {"never", "untrusted", "on-request"}:
        raise HarnessFailure("plan_schema_invalid", "invalid codex.approval_policy")
    if value["web_search"] not in {"disabled", "cached", "indexed", "live"}:
        raise HarnessFailure("plan_schema_invalid", "invalid codex.web_search")
    if value["shell_environment_inherit"] not in {"core", "none"}:
        raise HarnessFailure(
            "plan_schema_invalid",
            "codex.shell_environment_inherit must be core or none",
        )
    for key in (
        "ephemeral",
        "ignore_rules",
        "isolated_codex_home",
        "network_access",
        "strict_config",
    ):
        if not isinstance(value[key], bool):
            raise HarnessFailure("plan_schema_invalid", f"codex.{key} must be boolean")
    if value["ephemeral"] is not True:
        raise HarnessFailure("unsafe_codex_setting", "codex.ephemeral must be true")
    if value["isolated_codex_home"] is not True:
        raise HarnessFailure(
            "unsafe_codex_setting", "codex.isolated_codex_home must be true"
        )
    if value["strict_config"] is not True:
        raise HarnessFailure("unsafe_codex_setting", "codex.strict_config must be true")
    timeout = value["timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
        raise HarnessFailure(
            "plan_schema_invalid", "codex.timeout_seconds must be a positive integer"
        )
    return value


def _validate_session(
    value: Any,
    *,
    index: int,
    study_root: Path,
) -> ValidatedSession:
    if not isinstance(value, dict):
        raise HarnessFailure(
            "plan_schema_invalid", f"sessions[{index}] must be an object"
        )
    required = {
        "instruction_condition",
        "input_pointer",
        "repository_commit",
        "repository_url",
        "rule_behavior_sha256",
        "rule_id",
        "rule_revision_id",
        "rule_source_path",
        "rule_source_sha256",
        "session_id",
        "task_id",
        "task_prompt_path",
        "task_prompt_sha256",
        "trigger",
    }
    _require_exact_keys(value, required, where=f"sessions[{index}]")
    session_id = value["session_id"]
    if not isinstance(session_id, str) or not SAFE_ID.fullmatch(session_id):
        raise HarnessFailure(
            "plan_schema_invalid", f"sessions[{index}].session_id is unsafe"
        )
    rule_id = value["rule_id"]
    if not is_rule_id(rule_id):
        raise HarnessFailure(
            "plan_schema_invalid", f"session {session_id} has invalid rule_id"
        )
    trigger = value["trigger"]
    pointer = value["input_pointer"]
    if trigger not in SUPPORTED_FIELDS or pointer != SUPPORTED_FIELDS.get(trigger):
        raise HarnessFailure(
            "ineligible_trigger_field",
            f"session {session_id} does not use a protocol-v3 trigger field",
            details={"trigger": trigger, "input_pointer": pointer},
        )
    for key in (
        "rule_source_sha256",
        "rule_behavior_sha256",
        "task_prompt_sha256",
    ):
        if not HEX64.fullmatch(str(value[key])):
            raise HarnessFailure(
                "plan_schema_invalid", f"session {session_id} has invalid {key}"
            )
    if not COMMIT40.fullmatch(str(value["repository_commit"])):
        raise HarnessFailure(
            "plan_schema_invalid",
            f"session {session_id} repository_commit must be lowercase 40-hex",
        )
    _validate_public_repository_url(
        value["repository_url"], f"session {session_id} repository_url"
    )
    for key in ("task_id", "rule_revision_id"):
        if not isinstance(value[key], str) or not value[key]:
            raise HarnessFailure(
                "plan_schema_invalid", f"session {session_id} has empty {key}"
            )
    if value["instruction_condition"] not in CONDITIONS:
        raise HarnessFailure(
            "plan_schema_invalid",
            f"session {session_id} has invalid instruction_condition",
        )

    rule_source = _resolve_study_file(
        study_root,
        value["rule_source_path"],
        f"session {session_id} rule_source_path",
    )
    observed_rule_sha = _sha256_file(rule_source)
    if observed_rule_sha != value["rule_source_sha256"]:
        raise HarnessFailure(
            "rule_source_hash_mismatch",
            f"session {session_id} rule source differs from its pin",
            details={
                "expected": value["rule_source_sha256"],
                "observed": observed_rule_sha,
            },
        )
    rules, load_error = load_rule_file_with_error(rule_source, "experiment")
    if load_error is not None or len(rules) != 1:
        raise HarnessFailure(
            "rule_source_invalid",
            f"session {session_id} rule source is not one loadable rule",
            details={"error": "" if load_error is None else load_error.error},
        )
    rule = rules[0]
    try:
        observed_behavior_sha = behavior_hash(rule_source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise HarnessFailure(
            "rule_source_invalid",
            f"session {session_id} rule source is not UTF-8",
        ) from exc
    if observed_behavior_sha != value["rule_behavior_sha256"]:
        raise HarnessFailure(
            "rule_behavior_hash_mismatch",
            f"session {session_id} rule behavior differs from its pin",
            details={
                "expected": value["rule_behavior_sha256"],
                "observed": observed_behavior_sha,
            },
        )
    effective_pointer = rule.input_pointer or SUPPORTED_FIELDS.get(rule.trigger, "")
    if (
        rule.id != rule_id
        or rule.trigger != trigger
        or effective_pointer != pointer
    ):
        raise HarnessFailure(
            "rule_contract_mismatch",
            f"session {session_id} plan differs from loaded rule metadata",
            details={
                "planned": [rule_id, trigger, pointer],
                "loaded": [rule.id, rule.trigger, effective_pointer],
            },
        )

    prompt_path = _resolve_study_file(
        study_root,
        value["task_prompt_path"],
        f"session {session_id} task_prompt_path",
    )
    observed_prompt_sha = _sha256_file(prompt_path)
    if observed_prompt_sha != value["task_prompt_sha256"]:
        raise HarnessFailure(
            "task_prompt_hash_mismatch",
            f"session {session_id} task prompt differs from its pin",
            details={
                "expected": value["task_prompt_sha256"],
                "observed": observed_prompt_sha,
            },
        )
    try:
        prompt = prompt_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise HarnessFailure(
            "task_prompt_invalid", f"session {session_id} prompt is not UTF-8"
        ) from exc
    if not prompt:
        raise HarnessFailure(
            "task_prompt_invalid", f"session {session_id} prompt is empty"
        )
    return ValidatedSession(
        raw=value,
        rule_source=rule_source,
        task_prompt_path=prompt_path,
        task_prompt=prompt,
        rule_max_input_bytes=rule.max_input_bytes,
    )


def _validate_formal_design(sessions: list[ValidatedSession]) -> None:
    if len(sessions) != 48:
        raise HarnessFailure(
            "formal_design_incomplete",
            "a formal replay plan must contain exactly 48 sessions",
            details={"observed_sessions": len(sessions)},
        )
    rules = sorted({item.raw["rule_id"] for item in sessions})
    if len(rules) != 8:
        raise HarnessFailure(
            "formal_design_incomplete",
            "a formal replay plan must contain exactly eight rules",
            details={"observed_rules": len(rules)},
        )
    for rule_id in rules:
        subset = [item.raw for item in sessions if item.raw["rule_id"] == rule_id]
        task_ids = sorted({item["task_id"] for item in subset})
        if len(subset) != 6 or len(task_ids) != 3:
            raise HarnessFailure(
                "formal_design_incomplete",
                f"rule {rule_id} must have three paired tasks and six sessions",
            )
        for task_id in task_ids:
            pair = [item for item in subset if item["task_id"] == task_id]
            observed_conditions = {item["instruction_condition"] for item in pair}
            if len(pair) != 2 or observed_conditions != CONDITIONS:
                raise HarnessFailure(
                    "formal_design_incomplete",
                    f"rule {rule_id} task {task_id} is not a complete condition pair",
                )
            by_condition = {
                str(item["instruction_condition"]): item for item in pair
            }
            present = by_condition["source instruction present"]
            removed = by_condition["source instruction removed"]
            shared_fields = (
                "repository_url",
                "task_prompt_sha256",
                "rule_id",
                "trigger",
                "input_pointer",
                "rule_source_sha256",
                "rule_revision_id",
                "rule_behavior_sha256",
            )
            changed = [
                field
                for field in shared_fields
                if present[field] != removed[field]
            ]
            if changed:
                raise HarnessFailure(
                    "formal_pair_pin_mismatch",
                    f"rule {rule_id} task {task_id} condition pair changes shared pins",
                    details={"changed_fields": changed},
                )
            if present["repository_commit"] == removed["repository_commit"]:
                raise HarnessFailure(
                    "formal_condition_commits_identical",
                    f"rule {rule_id} task {task_id} must pin distinct present/removed commits",
                )


def validate_plan(
    plan_path: Path,
    *,
    study_root: Path,
    protocol_path: Path = PROTOCOL_PATH,
) -> ValidatedPlan:
    _protocol, protocol_sha = _validate_protocol(protocol_path)
    plan = _read_json_object(plan_path, "plan_schema_invalid")
    required = {
        "codex",
        "protocol_sha256",
        "protocol_version",
        "schema_version",
        "sessions",
        "study",
        "study_mode",
    }
    _require_exact_keys(plan, required, where="plan")
    if plan["schema_version"] != 1:
        raise HarnessFailure("plan_schema_invalid", "plan.schema_version must be 1")
    if plan["protocol_version"] != PROTOCOL_VERSION:
        raise HarnessFailure(
            "plan_protocol_mismatch", f"plan must target protocol {PROTOCOL_VERSION}"
        )
    if plan["protocol_sha256"] != protocol_sha:
        raise HarnessFailure(
            "plan_protocol_mismatch", "plan protocol SHA-256 is not the frozen file"
        )
    if plan["study"] != STUDY_NAME:
        raise HarnessFailure("plan_schema_invalid", f"plan.study must be {STUDY_NAME}")
    if plan["study_mode"] not in {FORMAL, PILOT}:
        raise HarnessFailure(
            "plan_schema_invalid", "plan.study_mode must be formal or pilot_non_study"
        )
    settings = _validate_codex_settings(plan["codex"])
    if not isinstance(plan["sessions"], list) or not plan["sessions"]:
        raise HarnessFailure("plan_schema_invalid", "plan.sessions must be nonempty")
    validated = [
        _validate_session(item, index=index, study_root=study_root)
        for index, item in enumerate(plan["sessions"])
    ]
    session_ids = [item.raw["session_id"] for item in validated]
    if len(set(session_ids)) != len(session_ids):
        raise HarnessFailure("plan_schema_invalid", "session_id values must be unique")
    if plan["study_mode"] == FORMAL:
        if settings["ignore_rules"] is not False:
            raise HarnessFailure(
                "formal_rules_disabled",
                "formal instruction-present sessions require codex.ignore_rules=false",
            )
        _validate_formal_design(validated)
    sessions = {item.raw["session_id"]: item for item in validated}
    return ValidatedPlan(
        raw=plan,
        path=plan_path.resolve(),
        sha256=_sha256_file(plan_path),
        protocol_sha256=protocol_sha,
        sessions=sessions,
    )


def reservoir_rank(session_id: str, event_id: str) -> str:
    """Protocol-v3 bottom-k rank for one session event."""
    return _sha256_text(f"{session_id}\x00{event_id}")


def apply_reservoir_cap(
    rows: list[dict[str, Any]],
    *,
    session_id: str,
    cap: int = MAX_EVENTS_PER_SESSION,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if cap < 1:
        raise ValueError("cap must be positive")
    seen = set()
    ranked = []
    for row in rows:
        event_id = str(row.get("event_id") or "")
        if not event_id:
            raise HarnessFailure("event_id_missing", "captured event has no event_id")
        if event_id in seen:
            raise HarnessFailure(
                "duplicate_event_id",
                f"captured event id is duplicated: {event_id}",
            )
        seen.add(event_id)
        rank = reservoir_rank(session_id, event_id)
        ranked.append({**row, "reservoir_rank_sha256": rank})
    selected_ids = {
        row["event_id"]
        for row in sorted(
            ranked,
            key=lambda item: (
                item["reservoir_rank_sha256"],
                item["event_id"],
            ),
        )[:cap]
    }
    selected = [row for row in ranked if row["event_id"] in selected_ids]
    selected.sort(key=lambda item: item["sequence"])
    total = len(rows)
    retained = len(selected)
    return selected, {
        "algorithm": (
            "retain the 30 smallest lowercase SHA-256 ranks of "
            "session_id + NUL + event_id"
        ),
        "cap": cap,
        "matching_events": total,
        "retained_events": retained,
        "sampling_fraction": 1.0 if total == 0 else retained / total,
        "rank_threshold_sha256": (
            max(row["reservoir_rank_sha256"] for row in selected)
            if selected
            else None
        ),
    }


def _atomic_write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write_bytes(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )


def _atomic_write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    text = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
    )
    _atomic_write_bytes(path, text.encode("utf-8"))


def capture_hook(capture_dir: Path, raw_text: str) -> dict[str, Any]:
    """Persist one exact hook stdin payload without affecting the Codex turn."""
    captured_ns = time.time_ns()
    record: dict[str, Any] = {
        "schema_version": 1,
        "captured_time_ns": captured_ns,
        "pid": os.getpid(),
        "raw_text": raw_text,
        "raw_text_sha256": _sha256_text(raw_text),
        "capture_ok": False,
    }
    try:
        raw = json.loads(raw_text)
        if not isinstance(raw, dict):
            raise ValueError("hook payload must be a JSON object")
        hook = raw.get("hook_event_name")
        if hook not in SUPPORTED_FIELDS:
            raise ValueError(f"unsupported hook_event_name: {hook!r}")
        record["capture_ok"] = True
        record["hook_event_name"] = hook
    except (json.JSONDecodeError, ValueError) as exc:
        record["capture_error"] = f"{type(exc).__name__}: {exc}"
    capture_dir.mkdir(parents=True, exist_ok=True)
    name = f"{captured_ns:020d}-{os.getpid()}-{uuid.uuid4().hex}.json"
    _atomic_write_json(capture_dir / name, record)
    return record


def _load_capture_records(capture_dir: Path) -> list[dict[str, Any]]:
    records = []
    for path in sorted(capture_dir.glob("*.json")):
        record = _read_json_object(path, "hook_capture_schema_invalid")
        raw_text = record.get("raw_text")
        if not isinstance(raw_text, str):
            raise HarnessFailure(
                "hook_capture_schema_invalid", f"{path.name} lacks raw_text"
            )
        if record.get("raw_text_sha256") != _sha256_text(raw_text):
            raise HarnessFailure(
                "hook_capture_hash_mismatch", f"{path.name} raw hook text was modified"
            )
        record = {**record, "capture_file": path.name}
        records.append(record)
    records.sort(
        key=lambda item: (
            int(item.get("captured_time_ns") or 0),
            str(item["capture_file"]),
        )
    )
    return records


def _parse_codex_jsonl(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HarnessFailure(
            "codex_stdout_not_utf8", "codex --json stdout is not UTF-8"
        ) from exc
    events = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HarnessFailure(
                "codex_jsonl_invalid",
                f"codex stdout line {line_number} is not JSON",
            ) from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise HarnessFailure(
                "codex_jsonl_schema_invalid",
                f"codex stdout line {line_number} lacks an event type",
            )
        events.append(event)
    if not events:
        raise HarnessFailure("codex_jsonl_empty", "codex --json emitted no events")
    started = [item for item in events if item.get("type") == "thread.started"]
    if len(started) != 1 or not isinstance(started[0].get("thread_id"), str):
        raise HarnessFailure(
            "codex_jsonl_schema_invalid",
            "expected exactly one thread.started event with thread_id",
        )
    terminals = [
        item
        for item in events
        if item.get("type") in {"turn.completed", "turn.failed"}
    ]
    if len(terminals) != 1:
        raise HarnessFailure(
            "codex_jsonl_schema_invalid", "expected exactly one terminal turn event"
        )
    item_types: dict[str, int] = {}
    tool_item_ids = set()
    for event in events:
        item = event.get("item")
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "")
        item_types[item_type] = item_types.get(item_type, 0) + 1
        if item_type in TOOL_ITEM_TYPES and item.get("id"):
            tool_item_ids.add(str(item["id"]))
    errors = [
        item
        for item in events
        if item.get("type") in {"error", "turn.failed"}
    ]
    return {
        "events": events,
        "event_count": len(events),
        "thread_id": started[0]["thread_id"],
        "terminal_type": terminals[0]["type"],
        "item_types": item_types,
        "tool_item_count": len(tool_item_ids),
        "errors": errors,
    }


def _hook_event_id(raw: dict[str, Any], identity: str) -> tuple[str, str]:
    for key in ("event_id", "tool_use_id"):
        value = raw.get(key)
        if value not in {None, ""}:
            return str(value), f"raw_payload.{key}"
    if not identity:
        raise HarnessFailure(
            "event_id_missing", "RAP could not derive a stable hook event identity"
        )
    return _sha256_text(identity), "sha256(rules_as_programs.event_identity)"


def extract_fields(
    capture_records: list[dict[str, Any]],
    *,
    session: ValidatedSession,
    study_mode: str,
    codex_thread_id: str,
) -> list[dict[str, Any]]:
    trigger = session.raw["trigger"]
    pointer = session.raw["input_pointer"]
    rows = []
    for sequence, capture in enumerate(capture_records):
        if capture.get("capture_ok") is not True:
            raise HarnessFailure(
                "hook_capture_schema_invalid",
                "a hook capture helper rejected its payload",
                details={
                    "capture_file": capture.get("capture_file"),
                    "capture_error": capture.get("capture_error"),
                },
            )
        try:
            raw = json.loads(capture["raw_text"])
        except json.JSONDecodeError as exc:
            raise HarnessFailure(
                "hook_capture_schema_invalid", "captured raw_text is not JSON"
            ) from exc
        if not isinstance(raw, dict) or raw.get("hook_event_name") != trigger:
            raise HarnessFailure(
                "unexpected_hook_capture",
                "capture contains a hook other than the session's declared trigger",
            )
        raw_session_id = str(raw.get("session_id") or "")
        if raw_session_id and raw_session_id != codex_thread_id:
            raise HarnessFailure(
                "codex_hook_session_mismatch",
                "hook session_id differs from codex --json thread_id",
                details={
                    "hook_session_id": raw_session_id,
                    "codex_thread_id": codex_thread_id,
                },
            )
        events = [
            event
            for event in normalize(raw)
            if event.hook_name == trigger
            and event.kind == TRIGGERS[trigger].event_kind
        ]
        if len(events) != 1:
            raise HarnessFailure(
                "adapter_normalization_mismatch",
                f"RAP adapter produced {len(events)} matching events for {trigger}",
            )
        event = events[0]
        try:
            input_text, observed_pointer, value_type, overridden = extract_input(
                trigger, raw
            )
        except InputPointerError as exc:
            raise HarnessFailure(
                "declared_field_unavailable",
                f"captured {trigger} payload does not contain {pointer}",
            ) from exc
        if observed_pointer != pointer or overridden:
            raise HarnessFailure(
                "adapter_trigger_contract_mismatch",
                "RAP extracted a different field than the protocol declared",
            )
        input_bytes = len(input_text.encode("utf-8"))
        if input_bytes > session.rule_max_input_bytes:
            raise HarnessFailure(
                "field_exceeds_rule_input_limit",
                "exact field exceeds the frozen rule's max_input_bytes",
                details={
                    "field_bytes": input_bytes,
                    "max_input_bytes": session.rule_max_input_bytes,
                },
            )
        identity = event_identity(event)
        event_id, event_id_source = _hook_event_id(raw, identity)
        rows.append(
            {
                "schema_version": 1,
                "study": STUDY_NAME,
                "study_mode": study_mode,
                "study_eligible": study_mode == FORMAL,
                "session_id": session.raw["session_id"],
                "codex_thread_id": codex_thread_id,
                "sequence": sequence,
                "event_id": event_id,
                "event_id_source": event_id_source,
                "event_identity_sha256": _sha256_text(identity),
                "trigger": trigger,
                "json_pointer": pointer,
                "value_type": value_type,
                "field": input_text,
                "field_utf8_bytes": input_bytes,
                "field_sha256": _sha256_text(input_text),
                "rule_id": session.raw["rule_id"],
                "rule_source_sha256": session.raw["rule_source_sha256"],
                "rule_revision_id": session.raw["rule_revision_id"],
                "rule_behavior_sha256": session.raw["rule_behavior_sha256"],
                "task_id": session.raw["task_id"],
                "instruction_condition": session.raw["instruction_condition"],
                "capture_file": capture["capture_file"],
            }
        )
    return rows


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_isolated_codex_config(settings: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"model = {_toml_string(settings['model'])}",
            (
                "model_reasoning_effort = "
                f"{_toml_string(settings['reasoning_effort'])}"
            ),
            f"service_tier = {_toml_string(settings['service_tier'])}",
            f"approval_policy = {_toml_string(settings['approval_policy'])}",
            f"sandbox_mode = {_toml_string(settings['sandbox'])}",
            f"web_search = {_toml_string(settings['web_search'])}",
            "history.persistence = \"none\"",
            "feedback.enabled = false",
            "check_for_update_on_startup = false",
            (
                "sandbox_workspace_write.network_access = "
                + ("true" if settings["network_access"] else "false")
            ),
            (
                "shell_environment_policy.inherit = "
                f"{_toml_string(settings['shell_environment_inherit'])}"
            ),
            "shell_environment_policy.ignore_default_excludes = false",
            "",
        ]
    )


def render_capture_hooks(trigger: str, capture_dir: Path) -> dict[str, Any]:
    command = " ".join(
        shlex.quote(value)
        for value in (
            sys.executable,
            str(Path(__file__).resolve()),
            "capture-hook",
            "--capture-dir",
            str(capture_dir),
        )
    )
    return {
        "hooks": {
            trigger: [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": command,
                            "async": False,
                            "timeout": 5,
                        }
                    ]
                }
            ]
        }
    }


def build_codex_command(
    codex_binary: Path,
    *,
    checkout: Path,
    session: ValidatedSession,
    settings: dict[str, Any],
) -> list[str]:
    command = [
        str(codex_binary),
        "exec",
        "--json",
        "--ephemeral",
        "--strict-config",
        "--dangerously-bypass-hook-trust",
        "--model",
        settings["model"],
        "--sandbox",
        settings["sandbox"],
        "--cd",
        str(checkout),
    ]
    if settings["ignore_rules"]:
        command.append("--ignore-rules")
    command.append(session.task_prompt)
    return command


def _codex_environment(codex_home: Path) -> tuple[dict[str, str], dict[str, Any]]:
    environment = dict(os.environ)
    removed = []
    for key in sorted(list(environment)):
        if key.startswith("CODEX_") and key not in {"CODEX_API_KEY"}:
            removed.append(key)
            environment.pop(key, None)
    environment["CODEX_HOME"] = str(codex_home)
    return environment, {
        "removed_codex_environment_keys": removed,
        "codex_api_key_present": bool(environment.get("CODEX_API_KEY")),
        "openai_api_key_present": bool(environment.get("OPENAI_API_KEY")),
    }


def _copy_auth(source: Path | None, codex_home: Path) -> bool:
    if source is None or not source.is_file():
        return False
    destination = codex_home / "auth.json"
    shutil.copyfile(source, destination)
    destination.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return True


def verify_codex_binary(
    codex_binary: Path,
    settings: dict[str, Any],
    *,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict[str, Any]:
    resolved = codex_binary.resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise HarnessFailure("codex_binary_missing", f"not executable: {resolved}")
    observed_sha = _sha256_file(resolved)
    if observed_sha != settings["executable_sha256"]:
        raise HarnessFailure(
            "codex_binary_hash_mismatch",
            "Codex executable differs from the study pin",
            details={
                "expected": settings["executable_sha256"],
                "observed": observed_sha,
            },
        )
    result = run(
        [str(resolved), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    combined = f"{result.stdout}\n{result.stderr}"
    versions = [line.strip() for line in combined.splitlines() if "codex-cli " in line]
    if result.returncode != 0 or len(versions) != 1:
        raise HarnessFailure(
            "codex_version_unavailable", "could not identify one Codex CLI version"
        )
    if versions[0] != settings.get("version"):
        raise HarnessFailure(
            "codex_version_mismatch",
            "Codex CLI version differs from the study pin",
            details={"expected": settings.get("version"), "observed": versions[0]},
        )
    return {
        "path_basename": resolved.name,
        "sha256": observed_sha,
        "version": versions[0],
        "version_stderr_sha256": _sha256_text(result.stderr),
    }


def _run_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise HarnessFailure(
            "git_checkout_failed",
            f"git {' '.join(args[:2])} failed",
            details={"stderr_tail": result.stderr[-4000:]},
        )
    return result


def fresh_checkout(session: ValidatedSession, destination: Path) -> dict[str, Any]:
    destination.mkdir()
    _run_git(["init", "--quiet"], cwd=destination)
    _run_git(
        ["remote", "add", "origin", session.raw["repository_url"]],
        cwd=destination,
    )
    _run_git(
        ["fetch", "--quiet", "--depth", "1", "origin", session.raw["repository_commit"]],
        cwd=destination,
    )
    _run_git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=destination)
    head = _run_git(["rev-parse", "HEAD"], cwd=destination).stdout.strip().lower()
    if head != session.raw["repository_commit"]:
        raise HarnessFailure(
            "repository_commit_mismatch",
            "fresh checkout HEAD differs from the pinned commit",
            details={"expected": session.raw["repository_commit"], "observed": head},
        )
    status_text = _run_git(
        ["status", "--porcelain=v1", "--untracked-files=all"], cwd=destination
    ).stdout
    if status_text:
        raise HarnessFailure(
            "fresh_checkout_dirty", "fresh checkout is dirty before Codex starts"
        )
    return {
        "repository_url": session.raw["repository_url"],
        "commit": head,
        "pre_run_status_sha256": _sha256_text(status_text),
    }


def _artifact_paths(
    output_dir: Path, session_id: str, attempt_id: str
) -> dict[str, Path]:
    prefix = f"{session_id}.{attempt_id}"
    return {
        "codex_stdout": output_dir / f"{prefix}.codex.stdout.jsonl",
        "codex_stderr": output_dir / f"{prefix}.codex.stderr.txt",
        "raw_hooks": output_dir / f"{prefix}.hooks.raw.jsonl",
        "fields": output_dir / f"{prefix}.fields.jsonl",
        "manifest": output_dir / f"{prefix}.manifest.json",
    }


def _refuse_existing_artifacts(paths: dict[str, Path]) -> None:
    existing = [str(path) for path in paths.values() if path.exists()]
    if existing:
        raise HarnessFailure(
            "attempt_artifact_exists",
            "refusing to overwrite an existing replay attempt",
            details={"paths": existing},
        )


def _file_receipt(path: Path) -> dict[str, Any]:
    return {"file": path.name, "bytes": path.stat().st_size, "sha256": _sha256_file(path)}


def _failure_manifest(
    *,
    plan: ValidatedPlan,
    session: ValidatedSession,
    attempt_id: str,
    failure: HarnessFailure,
    paths: dict[str, Path],
    started_at: float,
) -> dict[str, Any]:
    artifacts = {
        key: _file_receipt(path)
        for key, path in paths.items()
        if key != "manifest" and path.is_file()
    }
    return {
        "schema_version": 1,
        "status": "failed",
        "failure": failure.to_dict(),
        "study": STUDY_NAME,
        "study_mode": plan.raw["study_mode"],
        "study_eligible": False,
        "session_id": session.raw["session_id"],
        "attempt_id": attempt_id,
        "plan_sha256": plan.sha256,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_sha256": plan.protocol_sha256,
        "started_unix": started_at,
        "finished_unix": time.time(),
        "artifacts": artifacts,
    }


def run_session(
    *,
    plan: ValidatedPlan,
    session_id: str,
    attempt_id: str,
    output_dir: Path,
    codex_binary: Path,
    auth_source: Path | None,
    work_root: Path | None = None,
) -> dict[str, Any]:
    if session_id not in plan.sessions:
        raise HarnessFailure("unknown_session_id", f"session not in plan: {session_id}")
    if not SAFE_ID.fullmatch(attempt_id):
        raise HarnessFailure("unsafe_attempt_id", "attempt_id contains unsafe characters")
    session = plan.sessions[session_id]
    settings = plan.raw["codex"]
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = _artifact_paths(output_dir, session_id, attempt_id)
    _refuse_existing_artifacts(paths)
    started_at = time.time()
    try:
        binary_receipt = verify_codex_binary(codex_binary, settings)
        with tempfile.TemporaryDirectory(
            prefix="rap-codex-field-replay-",
            dir=None if work_root is None else str(work_root),
        ) as temporary_name:
            temporary_root = Path(temporary_name)
            checkout = temporary_root / "checkout"
            checkout_receipt = fresh_checkout(session, checkout)
            codex_home = temporary_root / "codex-home"
            capture_dir = temporary_root / "hook-captures"
            codex_home.mkdir()
            capture_dir.mkdir()
            config_text = render_isolated_codex_config(settings)
            (codex_home / "config.toml").write_text(config_text, encoding="utf-8")
            hooks = render_capture_hooks(session.raw["trigger"], capture_dir)
            (codex_home / "hooks.json").write_text(
                json.dumps(hooks, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            auth_copied = _copy_auth(auth_source, codex_home)
            environment, environment_receipt = _codex_environment(codex_home)
            command = build_codex_command(
                codex_binary.resolve(),
                checkout=checkout,
                session=session,
                settings=settings,
            )
            stdout_tmp = output_dir / f".{session_id}.{attempt_id}.stdout.tmp"
            stderr_tmp = output_dir / f".{session_id}.{attempt_id}.stderr.tmp"
            try:
                with stdout_tmp.open("xb") as stdout_stream, stderr_tmp.open(
                    "xb"
                ) as stderr_stream:
                    result = subprocess.run(
                        command,
                        stdout=stdout_stream,
                        stderr=stderr_stream,
                        env=environment,
                        timeout=settings["timeout_seconds"],
                        check=False,
                    )
                os.replace(stdout_tmp, paths["codex_stdout"])
                os.replace(stderr_tmp, paths["codex_stderr"])
            except subprocess.TimeoutExpired as exc:
                if stdout_tmp.exists():
                    os.replace(stdout_tmp, paths["codex_stdout"])
                if stderr_tmp.exists():
                    os.replace(stderr_tmp, paths["codex_stderr"])
                raise HarnessFailure(
                    "codex_exec_timeout",
                    f"codex exec exceeded {settings['timeout_seconds']} seconds",
                ) from exc
            finally:
                stdout_tmp.unlink(missing_ok=True)
                stderr_tmp.unlink(missing_ok=True)

            parsed = _parse_codex_jsonl(paths["codex_stdout"].read_bytes())
            captures = _load_capture_records(capture_dir)
            raw_capture_rows = [
                {
                    **capture,
                    "study_session_id": session_id,
                    "study_mode": plan.raw["study_mode"],
                    "study_eligible": plan.raw["study_mode"] == FORMAL,
                }
                for capture in captures
            ]
            _atomic_write_jsonl(paths["raw_hooks"], raw_capture_rows)

            if result.returncode != 0:
                raise HarnessFailure(
                    "codex_exec_failed",
                    f"codex exec exited with status {result.returncode}",
                )
            if parsed["terminal_type"] != "turn.completed" or parsed["errors"]:
                raise HarnessFailure(
                    "codex_turn_failed",
                    "codex JSONL reports a failed turn or error event",
                )
            if session.raw["trigger"] in {"Stop", "UserPromptSubmit"} and not captures:
                raise HarnessFailure(
                    "required_hook_capture_missing",
                    f"completed session emitted no {session.raw['trigger']} capture",
                )
            if (
                session.raw["trigger"] in {"PreToolUse", "PostToolUse"}
                and parsed["tool_item_count"] > 0
                and not captures
            ):
                raise HarnessFailure(
                    "tool_hook_capture_missing",
                    "Codex JSONL exposes tool items but the declared hook captured none",
                )
            extracted = extract_fields(
                captures,
                session=session,
                study_mode=plan.raw["study_mode"],
                codex_thread_id=parsed["thread_id"],
            )
            selected, sampling = apply_reservoir_cap(
                extracted,
                session_id=session_id,
            )
            _atomic_write_jsonl(paths["fields"], selected)
            post_status = _run_git(
                ["status", "--porcelain=v1", "--untracked-files=all"], cwd=checkout
            ).stdout
            post_diff = _run_git(["diff", "--binary", "HEAD"], cwd=checkout).stdout
            manifest = {
                "schema_version": 1,
                "status": "complete",
                "study": STUDY_NAME,
                "study_mode": plan.raw["study_mode"],
                "study_eligible": plan.raw["study_mode"] == FORMAL,
                "pilot_label": (
                    "non-study interface/infrastructure pilot"
                    if plan.raw["study_mode"] == PILOT
                    else None
                ),
                "session_id": session_id,
                "attempt_id": attempt_id,
                "plan": {
                    "file": plan.path.name,
                    "sha256": plan.sha256,
                    "protocol_version": PROTOCOL_VERSION,
                    "protocol_sha256": plan.protocol_sha256,
                },
                "pins": {
                    "repository": checkout_receipt,
                    "task_id": session.raw["task_id"],
                    "task_prompt_file": session.task_prompt_path.name,
                    "task_prompt_sha256": session.raw["task_prompt_sha256"],
                    "instruction_condition": session.raw["instruction_condition"],
                    "rule_id": session.raw["rule_id"],
                    "trigger": session.raw["trigger"],
                    "input_pointer": session.raw["input_pointer"],
                    "rule_source_file": session.rule_source.name,
                    "rule_source_sha256": session.raw["rule_source_sha256"],
                    "rule_revision_id": session.raw["rule_revision_id"],
                    "rule_behavior_sha256": session.raw["rule_behavior_sha256"],
                    "codex": settings,
                },
                "codex_binary": binary_receipt,
                "isolated_runtime": {
                    "codex_home_is_temporary": True,
                    "auth_file_copied_to_isolated_home": auth_copied,
                    "config_sha256": _sha256_text(config_text),
                    "hooks_sha256": _canonical_json_sha256(hooks),
                    "hook_capture_is_synchronous": True,
                    "environment": environment_receipt,
                    "command_argv_sha256": _canonical_json_sha256(command),
                    "stdout_stderr_separated": True,
                },
                "codex_jsonl": {
                    key: parsed[key]
                    for key in (
                        "event_count",
                        "thread_id",
                        "terminal_type",
                        "item_types",
                        "tool_item_count",
                    )
                },
                "sampling": sampling,
                "linkage": {
                    "matching_fields_before_cap": len(extracted),
                    "retained_fields": len(selected),
                    "all_retained_rows_link_input_rule_revision": all(
                        row["field_sha256"]
                        and row["rule_source_sha256"]
                        and row["rule_revision_id"]
                        for row in selected
                    ),
                },
                "post_run_checkout": {
                    "status_sha256": _sha256_text(post_status),
                    "status_lines": len(post_status.splitlines()),
                    "git_diff_sha256": _sha256_text(post_diff),
                    "git_diff_bytes": len(post_diff.encode("utf-8")),
                },
                "artifacts": {
                    key: _file_receipt(path)
                    for key, path in paths.items()
                    if key != "manifest" and path.is_file()
                },
                "started_unix": started_at,
                "finished_unix": time.time(),
                "host": {
                    "python": sys.version,
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                },
            }
            _atomic_write_json(paths["manifest"], manifest)
            return manifest
    except HarnessFailure as failure:
        if not paths["raw_hooks"].exists():
            _atomic_write_jsonl(paths["raw_hooks"], [])
        if not paths["fields"].exists():
            _atomic_write_jsonl(paths["fields"], [])
        manifest = _failure_manifest(
            plan=plan,
            session=session,
            attempt_id=attempt_id,
            failure=failure,
            paths=paths,
            started_at=started_at,
        )
        _atomic_write_json(paths["manifest"], manifest)
        raise


def _default_auth_source() -> Path | None:
    root = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    candidate = root / "auth.json"
    return candidate if candidate.is_file() else None


def _main_capture(args: argparse.Namespace) -> int:
    raw_text = sys.stdin.read()
    try:
        capture_hook(args.capture_dir, raw_text)
    except BaseException:
        # Capture instrumentation must never change the Codex turn outcome.
        pass
    sys.stdout.write("{}")
    sys.stdout.flush()
    return 0


def _error_json(failure: HarnessFailure) -> str:
    return json.dumps(
        {"status": "failed", "failure": failure.to_dict()},
        ensure_ascii=False,
        sort_keys=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-plan")
    validate_parser.add_argument("--plan", required=True, type=Path)
    validate_parser.add_argument("--study-root", type=Path, default=REPO_ROOT)
    validate_parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--plan", required=True, type=Path)
    run_parser.add_argument("--study-root", type=Path, default=REPO_ROOT)
    run_parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    run_parser.add_argument("--session-id", required=True)
    run_parser.add_argument("--attempt-id", required=True)
    run_parser.add_argument("--output-dir", required=True, type=Path)
    run_parser.add_argument("--codex", required=True, type=Path)
    run_parser.add_argument("--auth-source", type=Path, default=_default_auth_source())
    run_parser.add_argument("--work-root", type=Path)

    capture_parser = subparsers.add_parser("capture-hook")
    capture_parser.add_argument("--capture-dir", required=True, type=Path)
    args = parser.parse_args()

    if args.command == "capture-hook":
        return _main_capture(args)
    try:
        plan = validate_plan(
            args.plan,
            study_root=args.study_root,
            protocol_path=args.protocol,
        )
        if args.command == "validate-plan":
            print(
                json.dumps(
                    {
                        "status": "valid",
                        "study_mode": plan.raw["study_mode"],
                        "sessions": len(plan.sessions),
                        "plan_sha256": plan.sha256,
                        "protocol_sha256": plan.protocol_sha256,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        manifest = run_session(
            plan=plan,
            session_id=args.session_id,
            attempt_id=args.attempt_id,
            output_dir=args.output_dir,
            codex_binary=args.codex,
            auth_source=args.auth_source,
            work_root=args.work_root,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    except HarnessFailure as failure:
        sys.stderr.write(_error_json(failure) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
