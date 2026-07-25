from __future__ import annotations

import sys

import pytest
from rules_as_programs.core.rule import new_rule_id

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="AppKit-only")


def _walk(view):
    yield view
    for child in view.subviews():
        yield from _walk(child)


def test_action_menu_defers_until_tracking_ends():
    from AppKit import NSApplication
    from rules_as_programs.ui.native_popover import PersistentPopoverRenderer

    class Controller:
        content_view = None

        def __init__(self):
            self.deferred = []

        def defer_menu_action(self, callback):
            self.deferred.append(callback)

    NSApplication.sharedApplication()
    controller = Controller()
    renderer = PersistentPopoverRenderer(controller)
    called = []
    renderer.popup_menu(
        None, [("Remove rule…", lambda: called.append(True), True)])
    item = renderer._menus[-1].itemAtIndex_(0)
    renderer._menu_target.invoke_(item)

    assert not called
    assert len(controller.deferred) == 1
    controller.deferred[0]()
    assert called

    controller.deferred.clear()
    renderer.popup_menu(
        None, [("Remove another rule…", lambda: called.append(True), True)])
    second_item = renderer._menus[-1].itemAtIndex_(0)
    renderer._menu_target.invoke_(second_item)
    assert len(controller.deferred) == 1
    controller.deferred[0]()
    assert called == [True, True]


def test_sf_symbol_helper_keeps_accessible_fallback():
    from AppKit import NSApplication, NSButton
    from rules_as_programs.ui.macos_controls import set_button_symbol

    NSApplication.sharedApplication()
    button = NSButton.alloc().init()
    assert set_button_symbol(
        button, "info.circle", "Information", fallback="Info")
    assert button.image() is not None
    assert str(button.accessibilityLabel()) == "Information"


def test_table_mouse_activation_uses_clicked_not_stale_selected_row():
    from rules_as_programs.ui.native_popover import RAPTableAdapter

    class Table:
        @staticmethod
        def clickedRow():
            return 1

    class Owner:
        rows = [
            {"type": "section", "title": "Project"},
            {"type": "finding", "value": {"id": 7}},
        ]
        table = Table()

        def __init__(self):
            self.activated = []

        @staticmethod
        def row_is_actionable(row):
            return row.get("type") == "finding"

        def _activate_row(self, row):
            self.activated.append(row["value"]["id"])

        def activate_clicked_row(self):
            row = self.table.clickedRow()
            if self.row_is_actionable(self.rows[row]):
                self._activate_row(self.rows[row])

    owner = Owner()
    adapter = RAPTableAdapter.alloc().init()
    adapter.owner = owner
    adapter.activate_(None)
    assert owner.activated == [7]


def test_confirmation_schedules_popover_reopen(monkeypatch):
    from rules_as_programs.ui import macos_app

    scheduled = []
    monkeypatch.setattr(
        macos_app, "_on_main", lambda callback: scheduled.append(callback))
    controller = macos_app.MacOSController.alloc().init()
    controller.request_confirmation(
        "Delete?", "Exact source", "Delete", lambda: None,
        destructive=True)

    assert controller.confirmation
    assert scheduled
    assert scheduled[-1].__name__ == "_show_popover"


def test_popover_and_structured_detail_construct(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    from AppKit import (
        NSApplication,
        NSAppearance,
        NSBitmapImageFileTypePNG,
        NSButton,
        NSColor,
        NSMakeRect,
        NSSegmentedControl,
        NSStatusBar,
        NSTableView,
    )
    from rules_as_programs.ui.macos_app import MacOSController, _paw_template_image
    from rules_as_programs.ui.model import demo_snapshot
    from Foundation import NSIndexSet

    NSApplication.sharedApplication()
    controller = MacOSController.alloc().init()
    controller.demo = True
    controller.applicationDidFinishLaunching_(None)
    snapshot = demo_snapshot()
    controller._apply_snapshot(snapshot)
    controller._render()
    assert controller.renderer._health_copy(snapshot)[0] == ""
    icon = _paw_template_image()
    assert icon.size().height == 18
    assert icon.size().width == 18
    assert icon.isTemplate()
    status_text = str(controller.status_item.button().attributedTitle().string())
    assert "●" not in status_text
    assert "2" in status_text
    assert controller.status_item.highlightMode()
    controls = list(_walk(controller.content_controller.view()))
    tables = [
        control for control in controls if isinstance(control, NSTableView)]
    assert len(tables) == 1
    table = tables[0]
    assert table.backgroundColor().alphaComponent() == 0
    assert not controller.renderer.scroll.drawsBackground()
    assert not controller.renderer.scroll.hasVerticalScroller()
    root_identity = controller.content_controller.view()
    table_identity = controller.renderer.table
    project = next(iter(snapshot.findings_by_project))
    group = snapshot.findings_by_project[project][0]
    assert any(row["type"] == "finding" for row in controller.renderer.rows)
    from rules_as_programs.ui.native_popover import RAPTableRowView
    finding_index = next(
        index for index, row in enumerate(controller.renderer.rows)
        if row["type"] == "finding")
    finding_model = controller.renderer.rows[finding_index]
    hover_row = RAPTableRowView.alloc().initWithFrame_(
        NSMakeRect(0, 0, 420, 48))
    hover_row.configure(controller.renderer.row_key(finding_model), True)

    def rendered_png(view):
        bitmap = view.bitmapImageRepForCachingDisplayInRect_(view.bounds())
        view.cacheDisplayInRect_toBitmapImageRep_(view.bounds(), bitmap)
        return bytes(bitmap.representationUsingType_properties_(
            NSBitmapImageFileTypePNG, {}))

    resting = rendered_png(hover_row)
    hover_row.mouseEntered_(None)
    assert hover_row.hovered()
    assert rendered_png(hover_row) != resting
    finding_cell = controller.renderer.row_view(finding_model)
    finding_buttons = [
        control for control in _walk(finding_cell)
        if isinstance(control, NSButton)
    ]
    assert {
        str(button.accessibilityLabel() or "") for button in finding_buttons
    } >= {
        f"Mark {group['rule_title']} reviewed",
        f"Actions for {group['rule_title']}",
    }
    action_button = next(
        button for button in finding_buttons
        if str(button.accessibilityLabel() or "").startswith("Actions "))
    review_glyph = next(
        button for button in finding_buttons
        if str(button.accessibilityLabel() or "").startswith("Mark "))
    assert action_button.image() is not None
    assert str(review_glyph.title()) == "✓"
    assert review_glyph.font().pointSize() == 17
    title_field = next(
        control for control in _walk(finding_cell)
        if hasattr(control, "stringValue")
        and str(control.stringValue()).startswith(group["rule_title"]))
    severity_field = next(
        control for control in _walk(finding_cell)
        if hasattr(control, "stringValue")
        and str(control.stringValue()) in ("Critical", "Warning", "Info"))
    assert title_field.frame().origin.y == severity_field.frame().origin.y
    assert severity_field.textColor().isEqual_(NSColor.labelColor())
    first_button_x = min(button.frame().origin.x for button in finding_buttons)
    assert (
        title_field.frame().origin.x + title_field.frame().size.width
        <= first_button_x
    )
    section_index = next(
        index for index, row in enumerate(controller.renderer.rows)
        if row["type"] == "section")
    assert controller.renderer._adapter.tableView_isGroupRow_(
        table, section_index)
    assert not controller.renderer._adapter.tableView_shouldSelectRow_(
        table, section_index)
    assert controller.renderer.separator_config(section_index) == (True, 14)
    assert controller.renderer.separator_config(finding_index)[1] in (14, 94)
    project_section = next(
        row for row in controller.renderer.rows
        if row.get("type") == "section" and row.get("project_root") == project)
    project_section_cell = controller.renderer.row_view(project_section)
    section_buttons = [
        control for control in _walk(project_section_cell)
        if isinstance(control, NSButton)
    ]
    assert {str(button.title()) for button in section_buttons} >= {
        "+ Rule", "Rules", "✓ All"}
    assert any(
        str(button.accessibilityLabel() or "").startswith("Mark all findings")
        for button in section_buttons)
    review_button = next(
        button for button in finding_buttons
        if str(button.accessibilityLabel() or "").startswith("Mark "))
    assert review_button.contentTintColor().isEqual_(
        NSColor.systemGreenColor())
    project_heading = next(
        control for control in _walk(project_section_cell)
        if hasattr(control, "stringValue")
        and str(control.stringValue()) == project.split("/")[-1])
    assert project_heading.font().pointSize() > title_field.font().pointSize()
    add_rule_button = next(
        button for button in section_buttons
        if str(button.title()) == "+ Rule")
    from rules_as_programs.ui.macos_controls import RAPHoverButton
    assert isinstance(add_rule_button, RAPHoverButton)
    add_resting = rendered_png(add_rule_button)
    add_rule_button.mouseEntered_(None)
    assert rendered_png(add_rule_button) != add_resting
    project_frame = controller.renderer.project_popup.frame()
    mode_frame = controller.renderer.mode_control.frame()
    add_frame = controller.renderer.add_button.frame()
    assert project_frame.origin.x + project_frame.size.width <= mode_frame.origin.x
    assert mode_frame.origin.x + mode_frame.size.width <= add_frame.origin.x
    assert str(controller.renderer.table.action()) == "activate:"
    navigation = [
        control for control in controls
        if isinstance(control, NSSegmentedControl)
        and control.segmentCount() == 3
    ]
    assert navigation
    assert navigation[0].selectedSegment() == 0
    assert not controller.renderer.header_separator.isHidden()
    assert not controller.renderer.footer_separator.isHidden()
    for appearance_name in (
        "NSAppearanceNameAqua",
        "NSAppearanceNameDarkAqua",
        "NSAppearanceNameAccessibilityHighContrastAqua",
        "NSAppearanceNameAccessibilityHighContrastDarkAqua",
    ):
        appearance = NSAppearance.appearanceNamed_(appearance_name)
        if appearance:
            controller.renderer.root.setAppearance_(appearance)
            controller.renderer.root.displayIfNeeded()
    snapshot.data["health_issues"] = [{
        "code": "runtime_exception",
        "summary": "Rule check failed",
        "impact": "this rule check was skipped",
    }]
    controller._apply_snapshot(snapshot)
    controller._render()
    assert not any(
        row.get("type") == "issue" for row in controller.renderer.rows)
    snapshot.data["health_issues"] = []
    table.selectRowIndexes_byExtendingSelection_(
        NSIndexSet.indexSetWithIndex_(finding_index), False)
    controller.renderer.selection_changed()
    selected_key = controller.renderer.row_key(finding_model)
    controller._render()
    selected_after = int(table.selectedRow())
    assert controller.renderer.row_key(
        controller.renderer.rows[selected_after]) == selected_key
    assert controller.renderer.row_key({
        "type": "section", "title": "project",
        "project_root": "/one/project", "section_key": "project:/one/project",
    }) != controller.renderer.row_key({
        "type": "section", "title": "project",
        "project_root": "/two/project", "section_key": "project:/two/project",
    })
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
    assert controller.content_controller.view() is root_identity
    assert controller.renderer.table is table_identity
    assert controller.popover.contentSize().height < 600
    from rules_as_programs.ui.finding_inspector import FindingInspectorManager
    inspectors = FindingInspectorManager(controller.model, lambda _rule: None)
    inspectors.open(controller.finding_detail)
    inspector = next(iter(inspectors.inspectors.values()))
    assert not inspector.show_python
    inspector.select_tab(1)
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
    inspector.select_tab(3)
    assert inspector.raw_view is not None
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
    assert inspector.content_scroll.contentView().bounds().origin.y >= 5
    inspector.window.close()
    controller.request_confirmation(
        "Disable?", "Stops evaluation.", "Disable", lambda: None)
    assert controller.confirmation
    controller._render()
    assert not controller.renderer.confirmation_view.isHidden()
    assert controller.renderer.scroll.isHidden()
    assert controller.popover.contentSize().height >= 450
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
    rule_row = next(
        row for row in controller.renderer.rows if row["type"] == "rule")
    rule_cell = controller.renderer.row_view(rule_row)
    titles = [
        str(control.title())
        for control in _walk(rule_cell)
        if isinstance(control, NSButton)
    ]
    assert "Actions…" in titles
    assert controller.rules_context == "library"
    search_identity = controller.renderer.search
    search_identity.setStringValue_("Shared")
    controller.rules_filter = "Shared"
    controller.renderer.scroll.contentView().scrollToPoint_((0, 12))
    controller._apply_snapshot(snapshot)
    controller._render()
    assert controller.rules_context == "library"
    assert controller.renderer.search is search_identity
    assert str(search_identity.stringValue()) == "Shared"
    controller.rules_context = "project"
    controller.selected_project = project
    controller._render()
    project_rule_row = next(
        row for row in controller.renderer.rows if row["type"] == "rule")
    project_rule_cell = controller.renderer.row_view(project_rule_row)
    assert any(
        isinstance(control, NSButton)
        and str(control.title()) == "Runs here"
        for control in _walk(project_rule_cell)
    )
    controller.route = "projects"
    controller._render()
    project_model = next(
        row for row in controller.renderer.rows if row["type"] == "project")
    project_cell = controller.renderer.row_view(project_model)
    assert any(
        isinstance(control, NSButton)
        and str(control.title()) == "+ Rule"
        for control in _walk(project_cell)
    )

    captured = []
    controller.renderer.popup_menu = lambda _sender, items: captured.extend(items)
    rule = controller.rules_data["rules"][0]
    controller.show_rule_menu(None, rule)
    assert "Delete shared rule…" in [item[0] for item in captured]

    deleted_group = {
        "id": 99,
        "ids": [99],
        "rule_id": rule["id"],
        "rule_title": "Deleted example",
        "project_root": project,
        "severity": "warn",
        "review_reason": "rule_deleted",
        "ts": group["ts"],
    }
    captured.clear()
    controller.inbox_mode = "history"
    controller.show_finding_menu(None, deleted_group)
    history_actions = {title: enabled for title, _callback, enabled in captured}
    assert history_actions["Rule deleted — history only"] is False
    assert "Reopen finding" not in history_actions

    controller.model.stop()
    NSStatusBar.systemStatusBar().removeStatusItem_(controller.status_item)


def test_rule_editor_prioritizes_intent_and_adapts_without_rebuilds():
    from AppKit import (
        NSApplication,
        NSEvent,
        NSEventModifierFlagCommand,
        NSEventModifierFlagControl,
        NSEventModifierFlagShift,
        NSKeyDown,
    )
    from rules_as_programs import rules_api
    from rules_as_programs.ui.macos_app import MacOSController
    from rules_as_programs.ui.rule_editor import RuleEditorManager

    class Model:
        def __init__(self):
            self.requests = []

        def perform(self, request, callback=None, timeout=4):
            self.requests.append(request)

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
    model = Model()
    manager = RuleEditorManager(model)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Example")
    manager.open({
        "id": rule_id,
        "scope": "global",
        "source": source,
        "projection": rules_api.source_projection(source),
        "path": "",
        "enabled": False,
        "muted": False,
        "new_draft": True,
        "deployment": {
            "coverage": {
                "mode": "selected",
                "selected_projects": ["/tmp/project"],
            },
            "projects": [
                {"path": "/tmp/project", "name": "project"},
                {"path": "/tmp/other", "name": "other"},
            ],
        },
    }, "/tmp/project")
    document = next(iter(manager.documents.values()))
    assert document.managed_fuzzy
    assert document.name_field is not None
    assert document.description_editor is not None
    assert document.spec
    assert str(document.description_editor.string()) == rules_api.source_projection(
        source)["spec"]
    assert not document.spec_scroll.hasHorizontalScroller()
    assert document.description_editor.textContainer().widthTracksTextView()
    assert document.name_field.nextKeyView() == document.description_editor
    assert document.description_editor.nextKeyView() == document.all_projects_radio
    assert document.deploy_button.isEnabled()
    assert not document._scope_confirmed
    assert document.coverage_mode == "selected"
    assert "project" in str(document.scope_summary.stringValue())
    document.window.contentView().layoutSubtreeIfNeeded()
    toolbar_ids = {
        str(item.itemIdentifier()) for item in document.toolbar.items()}
    assert {"rule.actions", "rule.state", "rule.advanced", "rule.deploy"} <= toolbar_ids
    info_labels = [
        str(control.accessibilityLabel() or "")
        for control in _walk(document.window.contentView())
        if hasattr(control, "accessibilityLabel")
    ]
    assert "About Runs when" in info_labels
    assert "About Reads" in info_labels
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

    original_description = document.description_editor
    edited_spec = str(description.string()).replace(
        "Decide whether", "Carefully decide whether", 1)
    description.setString_(edited_spec)
    document.editor_changed()
    assert document.description_editor is original_description
    assert document.deploy_button.isEnabled()
    document._set_busy(True, "Deploying…")
    assert not document.rule_actions_button.isEnabled()
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
    assert projection["spec"] == edited_spec
    button_titles = {
        str(control.title())
        for control in _walk(document.window.contentView())
        if hasattr(control, "title")
    }
    assert "Improve with examples" not in button_titles
    assert "Save Draft" not in button_titles
    assert "Close" not in button_titles
    assert str(document.rule_actions_button.title()) == "Rule…"
    assert str(document.deploy_button.title()) == "Deploy"
    document.show_advanced()
    assert document._advanced_window is not None
    assert document._advanced_editor is not None
    assert rules_api.source_projection(
        str(document._advanced_editor.string()))["spec"] == edited_spec
    document._set_busy(True, "Deploying…")
    assert not document._advanced_editor.isEditable()
    assert not document._advanced_apply.isEnabled()
    document._set_busy(False)
    document._advanced_window.close()
    for value in list(manager.documents.values()):
        value._dirty = False
        value.window.close()


def test_rule_editor_deploys_through_prepare_and_commit(monkeypatch):
    from rules_as_programs import rules_api
    from rules_as_programs.core import revisions
    from rules_as_programs.ui import rule_editor

    monkeypatch.setattr(rule_editor, "_on_main", lambda callback: callback())
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Deploy Example")

    class Model:
        def __init__(self):
            self.requests = []

        def perform(self, request, callback=None, timeout=4):
            self.requests.append(request)
            if request["type"] == "prepare_deployment":
                callback({"ok": True, "token": "prepared"})
            elif request["type"] == "commit_deployment":
                callback({
                    "ok": True,
                    "rule": {
                        "id": rule_id,
                        "name": "Deploy Example",
                        "scope": "global",
                        "source": source,
                        "definition": {
                            "source_hash": revisions.hash_source(source),
                            "source_path": "/tmp/library/rule.py",
                        },
                        "working_hash": revisions.hash_source(source),
                    },
                    "active": {
                        "source_hash": revisions.hash_source(source),
                    },
                    "coverage": {
                        "mode": "selected",
                        "selected_projects": ["/tmp/project"],
                    },
                    "impact_count": 1,
                })
            elif request["type"] == "save_library_draft":
                saved_source = request["source"]
                saved_hash = revisions.hash_source(saved_source)
                callback({
                    "ok": True,
                    "id": rule_id,
                    "scope": "global",
                    "path": "/tmp/library/rule.py",
                    "source": saved_source,
                    "definition": {
                        "source_hash": saved_hash,
                        "source_path": "/tmp/library/rule.py",
                    },
                    "working_hash": saved_hash,
                })

    model = Model()
    manager = rule_editor.RuleEditorManager(model)
    manager.open({
        "id": rule_id,
        "scope": "global",
        "source": source,
        "projection": rules_api.source_projection(source),
        "new_draft": True,
        "deployment": {
            "coverage": {
                "mode": "selected",
                "selected_projects": ["/tmp/project"],
            },
            "projects": [{"path": "/tmp/project", "name": "project"}],
        },
    }, "/tmp/project")
    document = next(iter(manager.documents.values()))
    document._scope_confirmed = True
    document.deploy()

    assert [request["type"] for request in model.requests] == [
        "prepare_deployment", "commit_deployment"]
    assert not document._dirty
    assert not document.deploy_button.isEnabled()
    assert str(document.deploy_button.title()) == "Deployed"
    document.description_editor.setString_(
        str(document.description_editor.string()).replace(
            "Decide whether", "Carefully decide whether", 1))
    document.editor_changed()
    document.save_draft()
    assert document.deploy_button.isEnabled()
    assert str(document.state_label.stringValue()) == "Changes not deployed"
    document._dirty = False
    document.window.close()


def test_existing_clean_rule_shows_disabled_deployed_action():
    from AppKit import NSApplication
    from rules_as_programs import rules_api
    from rules_as_programs.core import revisions
    from rules_as_programs.ui.rule_editor import RuleEditorManager

    class Model:
        def perform(self, *_args, **_kwargs):
            return None

    NSApplication.sharedApplication()
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Already deployed")
    digest = revisions.hash_source(source)
    manager = RuleEditorManager(Model())
    manager.open({
        "id": rule_id,
        "scope": "global",
        "source": source,
        "projection": rules_api.source_projection(source),
        "definition": {
            "source_hash": digest,
            "source_path": "/tmp/library/rule.py",
        },
        "working_hash": digest,
        "active_hash": digest,
        "active": {"source_hash": digest},
        "new_draft": False,
        "deployment": {
            "coverage": {"mode": "all", "selected_projects": []},
            "projects": [],
        },
    }, "")
    document = next(iter(manager.documents.values()))

    assert str(document.deploy_button.title()) == "Deployed"
    assert not document.deploy_button.isEnabled()
    assert str(document.state_label.stringValue()) == "Deployed"
    document._dirty = False
    document.window.close()
