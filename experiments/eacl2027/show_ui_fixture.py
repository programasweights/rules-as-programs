#!/usr/bin/env python3
"""Open sanitized native RAP windows for paper and video capture.

The fixture uses the production AppKit views with synthetic records only.  It
does not connect to the daemon, read native ledgers, or modify rule state.
Close the windows or press Command-Q when capture is complete.
"""

from __future__ import annotations

import argparse
import hashlib
import time
from pathlib import Path
from typing import Any, Callable

from AppKit import (
    NSApplication,
    NSApplicationActivationPolicyRegular,
    NSScreen,
)

from rules_as_programs import rules_api
from rules_as_programs.core import revisions, validation_store
from rules_as_programs.ui.finding_inspector import FindingInspectorManager
from rules_as_programs.ui.rule_editor import RuleEditorManager


ROOT = Path(__file__).resolve().parent
RULE_PATH = ROOT / "rules" / "fdg0z9837mz4v0ka" / "rule.py"
PROJECT_ROOT = "/Users/developer/Projects/rap-demo"
RULE_ID = "fdg0z9837mz4v0ka"
COMPILER = "paw-ft-bs48"
COMPILER_SNAPSHOT = "paw-ft-bs48-20260530"
PROGRAM_ID = "3db9a70d1472e94ffc7f"
WARNING_INPUT = "Implemented the parser and everything works."
_EDITOR: RuleEditorManager | None = None
_INSPECTOR: FindingInspectorManager | None = None


class FixtureModel:
    """Minimal read-only model serving deterministic UI fixture responses."""

    def query(
        self,
        request: dict[str, Any],
        callback: Callable[[dict[str, Any]], None] | None = None,
        timeout: float = 4,
    ) -> None:
        self.perform(request, callback, timeout)

    def perform(
        self,
        request: dict[str, Any],
        callback: Callable[[dict[str, Any]], None] | None = None,
        timeout: float = 4,
    ) -> None:
        del timeout
        if callback is None:
            return
        kind = str(request.get("type", ""))
        if kind == "compiler_catalog":
            callback(
                {
                    "ok": True,
                    "cached": True,
                    "offline": False,
                    "fetched_at": time.time(),
                    "compilers": [
                        {
                            "name": "paw-4b-qwen3-0.6b",
                            "description": "Standard — fast local mapper",
                            "compiler_kind": "mapper_lora",
                            "default": True,
                            "supports_local_sdk": True,
                            "latest_snapshot": "paw-4b-qwen3-0.6b-20260407",
                        },
                        {
                            "name": COMPILER,
                            "description": "Finetuned Standard — higher accuracy",
                            "compiler_kind": "finetune_lora",
                            "supports_local_sdk": True,
                            "latest_snapshot": COMPILER_SNAPSHOT,
                        },
                    ],
                }
            )
            return
        if kind == "cached_validation_results":
            cases = list(request.get("validation_cases") or [])
            source = str(request.get("source", ""))
            spec = str(rules_api.source_projection(source).get("spec", ""))
            results = []
            for case in cases:
                result = dict(case)
                result.update(
                    {
                        "actual": case.get("expected"),
                        "ok": True,
                        "valid_output": True,
                        "spec_hash": validation_store.spec_fingerprint(spec),
                        "case_hash": validation_store.case_fingerprint(case),
                        "compiler": COMPILER,
                        "compiler_snapshot": COMPILER_SNAPSHOT,
                        "program_id": PROGRAM_ID,
                        "ran_at": 1,
                    }
                )
                results.append(result)
            callback(
                {
                    "ok": True,
                    "target": {
                        "compiler": COMPILER,
                        "compiler_snapshot": COMPILER_SNAPSHOT,
                        "program_id": PROGRAM_ID,
                    },
                    "validation": {"results": results},
                }
            )
            return
        callback({"ok": True})


def _editor_rule() -> dict[str, Any]:
    source = RULE_PATH.read_text(encoding="utf-8")
    source_hash = revisions.hash_source(source)
    behavior_hash = revisions.behavior_hash(source)
    cases = [
        {
            "id": "unsupported",
            "input": WARNING_INPUT,
            "expected": "WARNING",
            "note": "Unqualified success claim",
        },
        {
            "id": "uncertain",
            "input": "I changed the parser but could not run the tests.",
            "expected": "OK",
            "note": "Uncertainty is explicit",
        },
        {
            "id": "verified",
            "input": "I ran pytest; all 42 tests passed.",
            "expected": "OK",
            "note": "Named check and outcome",
        },
    ]
    return {
        "id": RULE_ID,
        "scope": "project",
        "path": f"{PROJECT_ROOT}/.codex/rules-as-programs/rules/{RULE_ID}/rule.py",
        "source": source,
        "projection": rules_api.source_projection(source),
        "working_hash": source_hash,
        "active_hash": source_hash,
        "active_behavior_hash": behavior_hash,
        "validation_cases": cases,
        "definition": {
            "scope": "project",
            "project_root": PROJECT_ROOT,
            "source_path": (
                f"{PROJECT_ROOT}/.codex/rules-as-programs/rules/{RULE_ID}/rule.py"
            ),
            "source_hash": source_hash,
        },
        "active": {
            "source_hash": source_hash,
            "behavior_hash": behavior_hash,
            "compiler": COMPILER,
            "compiler_snapshot": COMPILER_SNAPSHOT,
            "program_id": PROGRAM_ID,
            "compiler_mode": revisions.EXPLICIT_COMPILER_MODE,
        },
        "deployment": {
            "source_scope": "project",
            "coverage": {
                "mode": "selected",
                "selected_projects": [PROJECT_ROOT],
            },
            "projects": [{"path": PROJECT_ROOT, "name": "rap-demo"}],
        },
        "enabled": True,
        "muted": False,
        "new_draft": False,
    }


def _finding_detail() -> dict[str, Any]:
    source = RULE_PATH.read_text(encoding="utf-8")
    source_hash = revisions.hash_source(source)
    behavior_hash = revisions.behavior_hash(source)
    input_hash = hashlib.sha256(WARNING_INPUT.encode("utf-8")).hexdigest()
    event_id = "synthetic-stop-event"
    evaluation_id = "synthetic-evaluation"
    finding = {
        "id": 101,
        "rule_id": RULE_ID,
        "rule_title": "Do not claim success without evidence",
        "severity": "warn",
        "project_root": PROJECT_ROOT,
        "fingerprint": "synthetic-finding",
        "ts": time.time() - 18,
    }
    evaluation = {
        "schema_version": 4,
        "evaluation_id": evaluation_id,
        "rule": {
            "id": RULE_ID,
            "name": finding["rule_title"],
            "source": source,
            "source_hash": source_hash,
            "behavior_hash": behavior_hash,
            "compiler": COMPILER,
            "compiler_snapshot": COMPILER_SNAPSHOT,
            "program_id": PROGRAM_ID,
        },
        "input": {
            "text": WARNING_INPUT,
            "sha256": input_hash,
            "byte_count": len(WARNING_INPUT.encode("utf-8")),
            "char_count": len(WARNING_INPUT),
            "format": "plain",
            "json_pointer": "/last_assistant_message",
            "pointer_source": "default",
            "value_type": "string",
            "event_ids": [event_id],
        },
        "severity": "warn",
        "result": "WARNING",
        "trigger": {
            "event_id": event_id,
            "kind": "message",
            "hook": "Stop",
            "included_in_input": True,
            "event": {
                "id": event_id,
                "kind": "message",
                "text": WARNING_INPUT,
            },
        },
    }
    return {
        "ok": True,
        "finding": finding,
        "evaluation": evaluation,
        "audit": {"rule_source": source},
        "current_rule": {
            "id": RULE_ID,
            "source": source,
            "scope": "project",
            "trigger": "Stop",
            "definition": {
                "scope": "project",
                "project_root": PROJECT_ROOT,
                "source_path": (
                    f"{PROJECT_ROOT}/.codex/rules-as-programs/rules/{RULE_ID}/rule.py"
                ),
                "source_hash": source_hash,
            },
        },
        "recorded_rule_projection": rules_api.source_projection(source),
        "recorded_behavior_hash": behavior_hash,
        "current_behavior_hash": behavior_hash,
        "rule_changed": False,
        "ledger": {
            "events": [
                {
                    "id": "synthetic-tool-event",
                    "kind": "tool_result",
                    "text": "Edited src/parser.py",
                    "is_trigger": False,
                },
                {
                    "id": event_id,
                    "kind": "message",
                    "text": WARNING_INPUT,
                    "is_trigger": True,
                },
            ],
            "start": 0,
            "end": 2,
            "total": 2,
        },
        "trace": [],
    }


def _position_windows(
    editor: RuleEditorManager, inspector: FindingInspectorManager
) -> None:
    screen = NSScreen.mainScreen()
    if screen is None:
        return
    frame = screen.visibleFrame()
    editor_document = next(iter(editor.documents.values()), None)
    inspector_window = next(iter(inspector.inspectors.values()), None)
    if editor_document is not None:
        editor_document.window.setFrameOrigin_(
            (frame.origin.x + 36, frame.origin.y + 54)
        )
    if inspector_window is not None:
        width = inspector_window.window.frame().size.width
        inspector_window.window.setFrameOrigin_(
            (frame.origin.x + frame.size.width - width - 36, frame.origin.y + 92)
        )


def main() -> int:
    global _EDITOR, _INSPECTOR
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--window", choices=("both", "editor", "inspector"), default="both"
    )
    args = parser.parse_args()

    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)
    model = FixtureModel()
    editor = RuleEditorManager(model)
    inspector = FindingInspectorManager(
        model,
        lambda _rule: None,
        lambda _project: None,
    )
    if args.window in ("both", "editor"):
        editor.open(_editor_rule(), PROJECT_ROOT)
    if args.window in ("both", "inspector"):
        inspector.open(_finding_detail())
    _position_windows(editor, inspector)
    app.activateIgnoringOtherApps_(True)

    # Keep managers alive for the duration of the native application loop.
    _EDITOR = editor
    _INSPECTOR = inspector
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
