from __future__ import annotations

import sys

import pytest
from rules_as_programs.core.rule import new_rule_id

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="AppKit-only")


def _walk(view):
    yield view
    for child in view.subviews():
        yield from _walk(child)


def test_popover_and_structured_detail_construct(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    from AppKit import (
        NSApplication,
        NSBitmapImageFileTypePNG,
        NSButton,
        NSSegmentedControl,
        NSStatusBar,
    )
    from rules_as_programs.ui.macos_app import MacOSController, _paw_template_image
    from rules_as_programs.ui.macos_controls import RAPInteractiveRow
    from rules_as_programs.ui.model import demo_snapshot

    NSApplication.sharedApplication()
    controller = MacOSController.alloc().init()
    controller.demo = True
    controller.applicationDidFinishLaunching_(None)
    snapshot = demo_snapshot()
    controller._apply_snapshot(snapshot)
    controller._render()
    assert controller.renderer._health_copy(snapshot)[0] == ""
    icon = _paw_template_image()
    assert icon.size().height == 22
    assert icon.size().width == 22
    assert icon.isTemplate()
    status_text = str(controller.status_item.button().attributedTitle().string())
    assert "●" not in status_text
    assert "2" in status_text
    assert controller.status_item.highlightMode()
    controls = list(_walk(controller.content_controller.view()))
    rows = [control for control in controls if isinstance(control, RAPInteractiveRow)]
    assert rows
    row = rows[0]
    assert row.frame().origin.x < 10
    assert row.frame().size.width > 300

    def rendered_png(view):
        bitmap = view.bitmapImageRepForCachingDisplayInRect_(view.bounds())
        view.cacheDisplayInRect_toBitmapImageRep_(view.bounds(), bitmap)
        return bytes(bitmap.representationUsingType_properties_(
            NSBitmapImageFileTypePNG, {}))

    resting_pixels = rendered_png(row)
    row.mouseEntered_(None)
    assert row.hovered()
    assert rendered_png(row) != resting_pixels
    row.mouseExited_(None)
    assert not row.hovered()
    navigation = [
        control for control in controls
        if isinstance(control, NSSegmentedControl)
        and control.segmentCount() == 3
    ]
    assert navigation
    assert navigation[0].selectedSegment() == 0

    project = next(iter(snapshot.findings_by_project))
    group = snapshot.findings_by_project[project][0]
    controller.route = "inbox"
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
                    "Return ONLY one of: OK, INFO, WARNING, CRITICAL",
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
    assert controller.popover.contentSize().height < 600
    from rules_as_programs.ui.finding_inspector import FindingInspectorManager
    inspectors = FindingInspectorManager(controller.model, lambda _rule: None)
    inspectors.open(controller.finding_detail)
    inspector = next(iter(inspectors.inspectors.values()))
    assert inspector.raw_view is not None
    assert not inspector.show_python
    source_button = next(
        control for control in _walk(inspector.window.contentView())
        if isinstance(control, NSButton)
        and str(control.title()) == "View Python")
    inspector.window.makeFirstResponder_(source_button)
    inspector.toggle_source()
    restored_source_button = next(
        control for control in _walk(inspector.window.contentView())
        if isinstance(control, NSButton)
        and str(control.title()) == "View PAW spec")
    assert inspector.window.firstResponder() == restored_source_button
    inspector.detail["ledger"]["has_earlier"] = True
    inspector._render()
    audit_button = next(
        control for control in _walk(inspector.window.contentView())
        if isinstance(control, NSButton)
        and str(control.title()) == "Open audit log")
    inspector.window.makeFirstResponder_(audit_button)
    inspector.detail["ledger"]["has_earlier"] = False
    inspector._render()
    restored_audit = next(
        control for control in _walk(inspector.window.contentView())
        if isinstance(control, NSButton)
        and str(control.title()) == "Open audit log")
    assert inspector.window.firstResponder() == restored_audit
    clip = inspector.content_scroll.contentView()
    clip.scrollToPoint_((0, 300))
    inspector.content_scroll.reflectScrolledClipView_(clip)
    inspector.window.makeFirstResponder_(inspector.raw_view)
    inspector.raw_view.setSelectedRange_((2, 3))
    inspector.toggle_raw()
    assert inspector.window.firstResponder() == inspector.raw_view
    assert inspector.raw_view.selectedRange().location == 2
    assert inspector.content_scroll.contentView().bounds().origin.y >= 250
    inspector.window.close()
    controller.request_confirmation(
        "Disable?", "Stops evaluation.", "Disable", lambda: None)
    assert controller.confirmation
    controller.cancel_confirmation()

    controller.rules_context = "library"
    controller.route = "rules"
    controller.rules_loading = False
    controller.rules_data = {
        "rules": [{
            "id": new_rule_id(),
            "name": "Shared example",
            "scope": "global",
            "source_origin": "global",
            "definition": {
                "scope": "global",
                "source_path": "/tmp/rule.py",
                "source_hash": "hash",
            },
        }],
        "errors": [],
        "builtins": [],
    }
    controller._render()
    titles = [
        str(control.title())
        for control in _walk(controller.content_controller.view())
        if isinstance(control, NSButton)
    ]
    assert "Actions…" in titles
    actions = next(
        control for control in _walk(controller.content_controller.view())
        if isinstance(control, NSButton)
        and str(control.title()) == "Actions…")
    assert actions.showsBorderOnlyWhileMouseInside()
    assert controller.rules_context == "library"
    controller._apply_snapshot(snapshot)
    assert controller.rules_context == "library"

    captured = []
    controller.renderer.popup_menu = lambda _sender, items: captured.extend(items)
    rule = controller.rules_data["rules"][0]
    controller.show_rule_menu(None, rule)
    assert "Delete shared rule…" in [item[0] for item in captured]

    controller.model.stop()
    NSStatusBar.systemStatusBar().removeStatusItem_(controller.status_item)


def test_rule_editor_constructs_function_and_full_python_views():
    from AppKit import (
        NSApplication,
        NSButton,
        NSEvent,
        NSEventModifierFlagCommand,
        NSEventModifierFlagControl,
        NSEventModifierFlagShift,
        NSKeyDown,
        NSMakeRange,
        NSSegmentedControl,
    )
    from rules_as_programs import rules_api
    from rules_as_programs.ui.macos_app import MacOSController
    from rules_as_programs.ui.rule_editor import RuleEditorManager

    class Model:
        def perform(self, _request, callback=None, timeout=4):
            if callback:
                callback({"ok": True})

        def set_rule_enabled(self, *_args, **_kwargs):
            return None

    app = NSApplication.sharedApplication()
    controller = MacOSController.alloc().init()
    controller._build_main_menu()
    edit_menu = app.mainMenu().itemWithTitle_("Edit").submenu()
    select_all = [
        item for item in edit_menu.itemArray()
        if str(item.action()) == "selectAll:"
    ]
    assert len(select_all) == 2
    assert all(item.target() is None for item in select_all)
    manager = RuleEditorManager(Model())
    rule_id = new_rule_id()
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
    assert document.name_field.nextKeyView() is not None
    initial_editor = document.name_field.currentEditor()
    assert document.window.firstResponder() == initial_editor
    assert initial_editor.selectedRange().length == len(
        str(document.name_field.stringValue()))

    description = document.description_editor
    document.window.makeFirstResponder_(description)
    description.setSelectedRange_((2, 0))

    def key_event(modifiers):
        return NSEvent.keyEventWithType_location_modifierFlags_timestamp_windowNumber_context_characters_charactersIgnoringModifiers_isARepeat_keyCode_(
            NSKeyDown,
            (0, 0),
            modifiers,
            0,
            document.window.windowNumber(),
            None,
            "a",
            "a",
            False,
            0,
        )

    assert document.window.performKeyEquivalent_(
        key_event(NSEventModifierFlagCommand))
    assert description.selectedRange().length == len(str(description.string()))
    description.setSelectedRange_((4, 3))
    assert document.window.performKeyEquivalent_(
        key_event(NSEventModifierFlagControl))
    assert description.selectedRange().length == len(str(description.string()))
    description.setSelectedRange_((2, 0))
    assert not document.window.performKeyEquivalent_(
        key_event(NSEventModifierFlagControl | NSEventModifierFlagShift))
    assert description.selectedRange().location == 2
    assert description.selectedRange().length == 0

    description.setString_("a😀bc")
    description.setSelectedRange_(NSMakeRange(1, 2))
    document.toggle_examples()
    assert document.window.firstResponder() == document.description_editor
    assert document.description_editor.selectedRange().location == 1
    assert document.description_editor.selectedRange().length == 2

    mode = next(
        view for view in document._key_views
        if isinstance(view, NSSegmentedControl))
    document.window.makeFirstResponder_(mode)
    document.toggle_examples()
    restored_mode = next(
        view for view in document._key_views
        if isinstance(view, NSSegmentedControl))
    assert document.window.firstResponder() == restored_mode
    examples_button = next(
        view for view in document._key_views
        if isinstance(view, NSButton)
        and "examples" in str(view.title()).lower())
    document.window.makeFirstResponder_(examples_button)
    document.toggle_examples()
    restored_examples = next(
        view for view in document._key_views
        if isinstance(view, NSButton)
        and "examples" in str(view.title()).lower())
    assert document.window.firstResponder() == restored_examples
    document._set_busy(True)
    assert not document.lifecycle_button.isEnabled()
    document.confirm_lifecycle_action()
    assert "Wait for" in str(document.results.string())
    document._set_busy(False)
    document.rule["definition"] = {
        "source_path": "/tmp/project/rules/example/rule.py",
    }
    manager.set_definition_pending(document.rule["definition"], True)
    assert document._busy
    assert not document.description_editor.isEditable()
    manager.open(dict(document.rule), "/tmp/other-project")
    later_document = next(
        value for value in manager.documents.values() if value is not document)
    assert later_document._busy
    assert not later_document.description_editor.isEditable()
    manager.set_definition_pending(document.rule["definition"], False)
    assert not document._busy
    assert document.description_editor.isEditable()
    assert not later_document._busy
    document.name_field.setStringValue_("Renamed Example")
    document.editor_changed()
    assert document.window is not None
    ok, canonical, error = document._compose()
    assert ok, error
    assert "inputs=" in canonical
    projection = rules_api.source_projection(canonical)
    assert projection["name"] == "Renamed Example"
    assert projection["id"] == rule_id
    button_titles = [
        str(control.title())
        for control in _walk(document.window.contentView())
        if hasattr(control, "title")
    ]
    assert "Discard Draft" in button_titles
    for value in list(manager.documents.values()):
        value._dirty = False
        value.window.close()
