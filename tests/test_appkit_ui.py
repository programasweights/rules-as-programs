from __future__ import annotations

import sys
import uuid

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="AppKit-only")


def test_popover_and_structured_detail_construct(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    from AppKit import NSApplication, NSStatusBar
    from rules_as_programs.ui.macos_app import MacOSController, _status_image
    from rules_as_programs.ui.model import demo_snapshot
    from rules_as_programs.ui.status import status_presentation

    NSApplication.sharedApplication()
    controller = MacOSController.alloc().init()
    controller.demo = True
    controller.applicationDidFinishLaunching_(None)
    snapshot = demo_snapshot()
    controller._apply_snapshot(snapshot)
    icon = _status_image(status_presentation(snapshot))
    assert icon.size().height == 22
    assert icon.size().width > 22

    project = next(iter(snapshot.findings_by_project))
    group = snapshot.findings_by_project[project][0]
    controller.route = "finding"
    controller.selected_finding = group
    controller.detail_loading = False
    controller.finding_detail = {
        "finding": group,
        "occurrences": [group],
        "current_rule": {
            "source": "from rules_as_programs import rule\n",
            "scope": "project",
            "on": ["message"],
            "inputs": ["message"],
        },
        "audit": {"rule_source": "from rules_as_programs import rule\n"},
        "recorded_rule_projection": {
            "spec": "Decide whether evidence violates the rule.\\n"
                    "Return ONLY one of: OK, VIOLATION",
        },
        "ledger": {
            "events": [{
                "id": "event",
                "kind": "message",
                "text": "Agent response",
                "is_trigger": True,
            }],
            "start": 0,
            "end": 1,
            "total": 1,
            "path": str(tmp_path / "ledger.jsonl"),
        },
        "trace": [{
            "type": "evidence",
            "text": "evidence",
            "probes": [{"command": "git status", "output": " M file.py"}],
            "events": [{"kind": "shell_exec", "ts": group["ts"], "text": "pytest"}],
        }, {
            "type": "paw",
            "input": "evidence",
            "output": "UNVERIFIED_CLAIM",
        }],
    }
    controller._render()
    assert controller.content_controller.view() is not None
    from rules_as_programs.ui.finding_inspector import FindingInspectorManager
    inspectors = FindingInspectorManager(controller.model, lambda _rule: None)
    inspectors.open(controller.finding_detail)
    inspector = next(iter(inspectors.inspectors.values()))
    assert inspector.raw_view is not None
    assert not inspector.show_python
    inspector.window.close()
    controller.request_confirmation(
        "Disable?", "Stops evaluation.", "Disable", lambda: None)
    assert controller.confirmation
    controller.cancel_confirmation()

    controller.model.stop()
    NSStatusBar.systemStatusBar().removeStatusItem_(controller.status_item)


def test_rule_editor_constructs_function_and_full_python_views():
    from AppKit import NSApplication
    from rules_as_programs import rules_api
    from rules_as_programs.ui.rule_editor import RuleEditorManager

    class Model:
        def perform(self, _request, callback=None, timeout=4):
            if callback:
                callback({"ok": True})

        def set_rule_enabled(self, *_args, **_kwargs):
            return None

    NSApplication.sharedApplication()
    manager = RuleEditorManager(Model())
    rule_id = str(uuid.uuid4())
    source = rules_api.draft_rule_source(rule_id, "Example")
    manager.open({
        "id": rule_id,
        "scope": "project",
        "source": source,
        "projection": rules_api.source_projection(source),
        "path": "/tmp/example.py",
        "enabled": False,
        "muted": False,
        "new_draft": True,
    }, "/tmp/project")
    document = next(iter(manager.documents.values()))
    assert document.managed_fuzzy
    assert not document.show_full
    assert document.name_field is not None
    assert document.description_editor is not None
    assert document.spec
    document.name_field.setStringValue_("Renamed Example")
    document.editor_changed()
    assert document.window is not None
    ok, canonical, error = document._compose()
    assert ok, error
    assert "inputs=" in canonical
    projection = rules_api.source_projection(canonical)
    assert projection["name"] == "Renamed Example"
    assert projection["id"] == rule_id
    document._dirty = False
    document.window.close()
