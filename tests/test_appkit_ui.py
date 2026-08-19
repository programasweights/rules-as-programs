from __future__ import annotations

import sys
import time
from types import SimpleNamespace

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


def test_primary_button_uses_accent_bezel_and_white_content():
    from AppKit import NSApplication, NSButton, NSColor
    from rules_as_programs.ui.macos_controls import style_button

    NSApplication.sharedApplication()
    button = NSButton.alloc().init()
    style_button(button, role="primary", accessibility="Deploy")
    assert button.bezelColor().isEqual_(NSColor.controlAccentColor())
    assert button.contentTintColor().isEqual_(NSColor.whiteColor())


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


def test_stale_findings_stay_with_project_and_are_reviewable():
    from AppKit import NSApplication, NSButton, NSTextField
    from rules_as_programs.ui.model import demo_snapshot
    from rules_as_programs.ui.native_popover import PersistentPopoverRenderer

    NSApplication.sharedApplication()
    snapshot = demo_snapshot()
    project = next(iter(snapshot.findings_by_project))
    current = dict(snapshot.findings_by_project[project][0])
    current["evaluation"] = {
        "input": {"text": "Current evaluated input"}}
    current["occurrence_count"] = 3
    stale = {
        **current,
        "id": int(current.get("id", 1)) + 1000,
        "fingerprint": "older-revision",
        "stale": True,
        "last_seen": float(current.get("last_seen", time.time())) - 60,
        "evaluation": {"input": {"text": "Older evaluated input"}},
    }
    snapshot.data["findings_by_project"][project] = [current, stale]
    controller = SimpleNamespace(
        route="inbox",
        inbox_mode="open",
        home_project="",
        history_groups=[],
        history_loading=False,
    )
    renderer = PersistentPopoverRenderer(controller)
    renderer.snapshot = snapshot
    rows = renderer._finding_models()

    assert not any(
        row.get("type") == "section"
        and row.get("section_key") == "stale"
        for row in rows
    )
    project_row = next(
        row for row in rows
        if row.get("type") == "section"
        and row.get("project_root") == project
    )
    assert project_row["count"] == 2
    finding_rows = [
        row for row in rows if row.get("type") == "finding"]
    assert finding_rows[1]["mode"] == "stale"
    assert finding_rows[1]["nested"]
    stale_cell = renderer.row_view(finding_rows[1])
    assert any(
        isinstance(control, NSButton)
        and str(control.accessibilityLabel() or "").startswith("Mark ")
        for control in _walk(stale_cell)
    )
    assert any(
        isinstance(control, NSTextField)
        and "Older revision" in str(control.stringValue())
        and "Older evaluated input" in str(control.stringValue())
        for control in _walk(stale_cell)
    )


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


def test_add_rule_scope_follows_project_filter():
    from rules_as_programs.ui.macos_app import MacOSController

    class Model:
        def __init__(self):
            self.requests = []

        def perform(self, request, callback=None, timeout=4):
            self.requests.append(request)

    controller = MacOSController.alloc().init()
    controller.model = Model()
    controller.rules_context = "project"
    controller.selected_project = "/previous/project"

    controller.begin_add_rule("", None)
    all_projects = controller.model.requests[-1]
    assert all_projects["project_root"] == ""
    assert all_projects["coverage_mode"] == "all"

    controller.begin_add_rule("/chosen/project", None)
    selected = controller.model.requests[-1]
    assert selected["project_root"] == "/chosen/project"
    assert selected["coverage_mode"] == "selected"


def test_popover_and_structured_detail_construct(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    from AppKit import (
        NSApplication,
        NSAppearance,
        NSBitmapImageFileTypePNG,
        NSButton,
        NSColor,
        NSImageView,
        NSMakeRect,
        NSSegmentedControl,
        NSScrollView,
        NSStatusBar,
        NSTableView,
        NSTextField,
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
    old_status_item = controller.status_item
    controller._repair_status_item("test", force=True)
    assert controller.status_item is not old_status_item
    assert controller.status_item.isVisible()
    assert controller._status_repair_count == 1
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
    attention_model = next(
        row for row in controller.renderer.rows
        if row["type"] == "attention")
    attention_cell = controller.renderer.row_view(attention_model)
    attention_buttons = [
        control for control in _walk(attention_cell)
        if isinstance(control, NSButton)]
    assert "Open Cursor" in {
        str(button.title()) for button in attention_buttons}
    assert "Clear" not in {
        str(button.title()) for button in attention_buttons}
    attention_done = next(
        button for button in attention_buttons
        if str(button.accessibilityLabel() or "") == "Mark no reply needed")
    assert str(attention_done.title()) == "✓"
    assert str(attention_done.toolTip()) == "Mark no reply needed"
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
    finding_text = [
        str(control.stringValue())
        for control in _walk(finding_cell)
        if isinstance(control, NSTextField)
    ]
    assert not any(text.startswith("×") for text in finding_text)
    finding_cell.layoutSubtreeIfNeeded()
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
    severity_image = next(
        control for control in _walk(finding_cell)
        if isinstance(control, NSImageView))
    assert not any(
        hasattr(control, "stringValue")
        and str(control.stringValue()) in ("Critical", "Warning", "Info")
        for control in _walk(finding_cell)
    )
    severity_center = (
        severity_image.frame().origin.y
        + severity_image.frame().size.height / 2)
    title_center = (
        title_field.frame().origin.y
        + title_field.frame().size.height / 2)
    assert abs(severity_center - title_center) <= 0.5
    first_button_x = min(button.frame().origin.x for button in finding_buttons)
    assert (
        title_field.frame().origin.x + title_field.frame().size.width
        <= first_button_x
    )
    section_index = next(
        index for index, row in enumerate(controller.renderer.rows)
        if row["type"] == "section")
    assert not controller.renderer._adapter.tableView_isGroupRow_(
        table, section_index)
    assert not controller.renderer._adapter.tableView_shouldSelectRow_(
        table, section_index)
    assert controller.renderer.separator_config(section_index) == (False, 14)
    assert controller.renderer.separator_config(finding_index) == (False, 14)
    project_section = next(
        row for row in controller.renderer.rows
        if row.get("type") == "section" and row.get("project_root") == project)
    assert project_section["count"] >= 1
    project_section_cell = controller.renderer.row_view(project_section)
    section_buttons = [
        control for control in _walk(project_section_cell)
        if isinstance(control, NSButton)
    ]
    assert {
        str(button.accessibilityLabel() or "")
        for button in section_buttons
    } == {f"Actions for {project.split('/')[-1]}"}
    review_button = next(
        button for button in finding_buttons
        if str(button.accessibilityLabel() or "").startswith("Mark "))
    assert review_button.contentTintColor().isEqual_(
        NSColor.controlAccentColor())
    controller.renderer._set_review_title(
        review_button, "✓", size=17, color=NSColor.systemGreenColor())
    assert review_button.contentTintColor().isEqual_(
        NSColor.systemGreenColor())
    project_heading = next(
        control for control in _walk(project_section_cell)
        if hasattr(control, "stringValue")
        and str(control.stringValue()) == project.split("/")[-1])
    assert project_heading.font().pointSize() > title_field.font().pointSize()
    add_rule_button = controller.renderer.add_button
    from rules_as_programs.ui.macos_controls import RAPHoverButton
    assert isinstance(add_rule_button, RAPHoverButton)
    assert str(add_rule_button.title()) == "+ Rule"
    assert str(add_rule_button.toolTip()) == "Add rule for all projects"
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
    controller.popoverDidClose_(None)
    assert int(table.selectedRow()) == -1
    assert controller.renderer._selected_key == ""
    assert "selected_key" not in controller.renderer._view_states[
        "inbox:open"]
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
        "current_rule": {
            "source": "from rules_as_programs import rule\n",
            "scope": "project",
            "trigger": "afterAgentResponse",
            "definition": {"source_path": "/tmp/rule.py"},
        },
        "audit": {"rule_source": "from rules_as_programs import rule\n"},
        "recorded_rule_projection": {
            "spec": "Decide whether evidence violates the rule.\\n"
                    "Return ONLY one of: OK, INFO, WARNING, CRITICAL",
        },
        "evaluation": {
            "schema_version": 4,
            "rule": {
                "id": group["rule_id"],
                "name": group["rule_title"],
                "source": "from rules_as_programs import rule\n",
                "source_hash": "sourcehash",
            },
            "input": {
                "text": "Agent response",
                "sha256": "inputhash",
                "char_count": 32,
                "format": "plain",
                "json_pointer": "/text",
                "pointer_source": "default",
                "value_type": "string",
                "event_ids": ["event"],
            },
            "severity": "warn",
            "trigger": {
                "event_id": "event",
                "kind": "message",
                "hook": "afterAgentResponse",
                "included_in_input": True,
                "raw_payload": {
                    "hook_event_name": "afterAgentResponse",
                    "text": "Agent response",
                },
            },
        },
        "ledger": {
            "events": [{
                "id": "thought",
                "kind": "thought",
                "text": "Earlier thought",
                "is_trigger": False,
            }, {
                "id": "event",
                "kind": "message",
                "text": "Agent response",
                "is_trigger": True,
            }],
            "start": 0,
            "end": 2,
            "total": 2,
            "path": str(tmp_path / "ledger.jsonl"),
        },
        "trace": [],
    }
    controller._render()
    assert controller.content_controller.view() is root_identity
    assert controller.renderer.table is table_identity
    assert controller.popover.contentSize().height < 600
    from rules_as_programs.ui.finding_inspector import FindingInspectorManager
    opened_projects = []
    inspectors = FindingInspectorManager(
        controller.model, lambda _rule: None,
        lambda path: opened_projects.append(path))
    inspectors.open(controller.finding_detail)
    inspector = next(iter(inspectors.inspectors.values()))
    assert str(inspector.rule_button.title()) == group["rule_title"]
    assert str(inspector.window.title()) == ""
    assert group["project_root"].split("/")[-1] in str(
        inspector.project_button.title())
    inspector.open_project()
    assert opened_projects == [group["project_root"]]
    assert not hasattr(inspector, "finding_label")
    assert not hasattr(inspector, "output_label")
    assert not hasattr(inspector, "copy_input_button")
    assert not any(
        isinstance(control, NSSegmentedControl)
        and control.segmentCount() == 2
        for control in _walk(inspector.window.contentView()))
    inspector_text = [
        str(control.stringValue())
        for control in _walk(inspector.window.contentView())
        if isinstance(control, NSTextField)
    ]
    assert "Evidence was insufficient." not in inspector_text
    assert not any("changed" in text.lower() for text in inspector_text)
    assert not inspector.detail_page.isHidden()
    assert inspector.context_page.isHidden()
    assert len([
        control for control in _walk(inspector.window.contentView())
        if isinstance(control, NSScrollView)
    ]) == 2
    assert str(inspector.input_heading.stringValue()) == "Assistant response"
    assert str(inspector.input_view.string()) == "Agent response"
    assert inspector.window.contentView().frame().size.height < 400
    inspector.set_wrap_mode("auto")
    assert inspector.input_should_wrap()
    assert not inspector.input_scroll.hasHorizontalScroller()
    assert inspector.input_view.textContainer().widthTracksTextView()
    inspector.set_wrap_mode("nowrap")
    assert inspector.input_scroll.hasHorizontalScroller()
    assert not inspector.input_view.textContainer().widthTracksTextView()
    inspector.presentation["input_typography"] = "monospace"
    inspector.set_wrap_mode("auto")
    assert not inspector.input_should_wrap()
    inspector.presentation["input_typography"] = "proportional"
    inspector.set_wrap_mode("auto")
    assert inspector.input_should_wrap()
    inspector.input_view.setString_("wrapped prose " * 120)
    wrapped_height = inspector._sync_input_text_layout()
    assert wrapped_height > 40
    assert inspector.input_view.frame().size.width <= (
        inspector.input_scroll.contentSize().width + 1)
    inspector._refresh_input()
    inspector.show_context()
    assert inspector.detail_page.isHidden()
    assert not inspector.context_page.isHidden()
    assert inspector.context_table.numberOfRows() == 2
    inspector.window.contentView().layoutSubtreeIfNeeded()
    assert 300 <= inspector.window.contentView().frame().size.height < 500
    assert inspector.context_scroll.frame().size.width >= (
        inspector.context_page.frame().size.width - 1)
    inspector.show_detail()
    assert not inspector.detail_page.isHidden()
    assert str(inspector.input_view.accessibilityLabel()) == "Exact rule input"
    inspector.window.setContentSize_((650, 520))
    inspector.window.contentView().layoutSubtreeIfNeeded()
    assert inspector.review_button.frame().origin.x >= 0
    assert inspector.input_scroll.frame().size.width > 600
    assert inspector.input_view.frame().size.width > 600
    edit_payloads = []
    edit_manager = FindingInspectorManager(
        controller.model, lambda payload: edit_payloads.append(payload),
        lambda _path: None)
    edit_manager.edit_rule(controller.finding_detail)
    assert edit_payloads[0]["_finding_context"]["evaluation"]["severity"] == "warn"
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
    assert controller.renderer.navigation.imageForSegment_(0) is not None
    assert str(controller.renderer.navigation.labelForSegment_(0)) == "Findings"
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

    captured.clear()
    controller.inbox_mode = "open"
    controller.show_finding_menu(None, group)
    finding_actions = {
        title: callback for title, callback, _enabled in captured}
    assert {"Open Finding", "Edit Rule…", "Review", "Developer"} <= set(
        finding_actions)
    assert [item[0] for item in finding_actions["Review"]] == [
        "Mark Reviewed", "False Positive", "Acceptable Risk"]
    assert any(
        title.startswith("Mute This Rule in ")
        for title in finding_actions)

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
        NSColor,
        NSEvent,
        NSEventModifierFlagCommand,
        NSEventModifierFlagControl,
        NSEventModifierFlagShift,
        NSKeyDown,
        NSTextField,
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
    assert str(document.name_field.stringValue()) == "Example"
    assert str(document.name_field.placeholderString()) == "Rule name"
    assert str(document.description_editor.string()) == (
        rules_api.DEFAULT_FUZZY_SPEC)
    assert not document.spec_scroll.hasHorizontalScroller()
    assert document.description_editor.textContainer().widthTracksTextView()
    assert document.name_field.nextKeyView() == document.trigger_popup
    assert document.trigger_popup.nextKeyView() == document.description_editor
    assert document.deploy_button.isEnabled()
    document.deploy()
    assert not document.trigger_error_label.isHidden()
    assert document.window.firstResponder() == document.trigger_popup
    assert not document._dirty
    assert document.windowShouldClose_(document.window)
    assert not document._scope_confirmed
    assert document.coverage_mode == "selected"
    assert document.scope_summary.isHidden()
    assert document.trigger == ""
    assert [
        str(document.trigger_popup.itemAtIndex_(index).representedObject())
        for index in range(7)
    ] == [
        "",
        "afterShellExecution",
        "afterAgentThought",
        "preToolUse",
        "afterAgentResponse",
        "postToolUseFailure",
        "afterFileEdit",
    ]
    assert str(document.input_contract_label.stringValue()) == (
        "Choose one supported trigger.")
    assert str(document.window.title()) == "Rule Editor"
    assert document.state_label.isHidden()
    assert document.advanced_button.isHidden()
    assert document.input_mapping_button.isHidden()
    assert not document.applies_row.isHidden()
    assert not document.validation_section.isHidden()
    assert not document.run_validation_button.isEnabled()
    assert document.run_validation_button.isHidden()
    assert document.validation_scroll.isHidden()
    assert document.validation_status.isHidden()
    assert "Optional" in str(
        document.validation_section.arrangedSubviews()[0]
        .arrangedSubviews()[0].stringValue())
    assert not document.observed_runs_button.isEnabled()
    assert not document.spec_guidance_label.isHidden()
    assert str(document.spec_guidance_label.stringValue()) == (
        "Detected outputs: OK, WARNING")
    assert not hasattr(document, "examples_section")
    assert "This project · project" == str(
        document.applies_summary.stringValue())
    assert document.spec_height_constraint.constant() <= 220
    document.window.contentView().layoutSubtreeIfNeeded()
    assert document.metadata_stack.frame().size.height < 140
    assert document.window.contentView().frame().size.height <= 510
    assert document.content_scroll.contentView().bounds().origin.y == 0
    document.trigger_popup.selectItemAtIndex_(1)
    document.trigger_changed(document.trigger_popup)
    assert document.trigger == "afterShellExecution"
    assert document.trigger_error_label.isHidden()
    assert str(document.input_contract_label.stringValue()) == "Command"
    assert document.deploy_button.isEnabled()
    assert document.deploy_button.bezelColor().isEqual_(
        NSColor.controlAccentColor())
    original_spec = document.spec
    document.add_validation_case()
    validation_input, validation_output = document.validation_controls[0]
    validation_input.setStringValue_("git push")
    validation_output.selectItemWithTitle_("OK")
    document.validation_changed()
    assert document.spec == original_spec
    assert document._validation_dirty
    document.remove_validation_case(0)
    assert not document.validation_cases
    manager.open({
        **document.rule,
        "_finding_context": {
            "finding": {
                "id": 42,
                "severity": "warn",
            },
            "evaluation": {
                    "schema_version": 4,
                "input": {
                    "text": "exact finding input",
                    "json_pointer": "/text",
                },
                    "severity": "warn",
            },
            "rule_changed": True,
        },
    }, "/tmp/project")
    assert not document.finding_callout.isHidden()
    assert "exact finding input" in str(document.finding_label.stringValue())
    document.name_field.setStringValue_("n" * 5000)
    document.window.contentView().layoutSubtreeIfNeeded()
    assert document.window.frame().size.width <= 1000
    document.name_field.setStringValue_("Project convention")
    assert not hasattr(document, "finding_case_button")
    document.window.contentView().layoutSubtreeIfNeeded()
    toolbar_ids = {
        str(item.itemIdentifier()) for item in document.toolbar.items()}
    assert {"rule.state", "rule.advanced", "rule.deploy"} <= toolbar_ids
    assert "rule.actions" not in toolbar_ids
    info_labels = [
        str(control.accessibilityLabel() or "")
        for control in _walk(document.window.contentView())
        if hasattr(control, "accessibilityLabel")
    ]
    assert "Trigger" in [
        str(control.stringValue()) for control in _walk(
            document.window.contentView())
        if isinstance(control, NSTextField)]
    document.window.makeFirstResponder_(document.name_field)
    initial_editor = document.name_field.currentEditor()
    assert document.window.firstResponder() == initial_editor
    assert initial_editor.selectedRange().length == len(
        str(document.name_field.stringValue()))

    description = document.description_editor
    description.setString_("Sample description")
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
    edited_description = (
        "Carefully decide whether the command violates this monitoring rule.")
    description.setString_(edited_description)
    document.editor_changed()
    assert document.description_editor is original_description
    assert document.deploy_button.isEnabled()
    assert "Include OK" in str(
        document.spec_guidance_label.stringValue())
    assert document.spec == edited_description
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
    assert "trigger='afterShellExecution'" in canonical
    assert "inputs=" not in canonical
    projection = rules_api.source_projection(canonical)
    assert projection["name"] == "Renamed Example"
    assert projection["id"] == rule_id
    assert projection["description"] == edited_description
    assert projection["spec"].startswith(edited_description)
    assert "Input:" not in document.spec
    document.show_compiled_spec()
    assert str(document._compiled_spec_editor.string()) == document.spec
    document._compiled_spec_window.close()
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
        str(document._advanced_editor.string()))["spec"] == document.spec
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
    scheduled = []
    monkeypatch.setattr(
        rule_editor, "_after_delay",
        lambda seconds, callback: scheduled.append((seconds, callback)))
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Deploy Example")

    class Model:
        def __init__(self):
            self.requests = []

        def perform(self, request, callback=None, timeout=4):
            self.requests.append(request)
            if request["type"] == "queue_deployment":
                callback({
                    "ok": True,
                    "queue": {
                        "id": request["deployment_id"],
                        "rule_id": rule_id,
                            "status": "checking",
                            "phase": "Checking draft",
                        "source_hash": revisions.hash_source(request["source"]),
                        "compiler": request["compiler"],
                        "created_at": time.time(),
                    },
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
    document.trigger_popup.selectItemAtIndex_(1)
    document.trigger_changed(document.trigger_popup)
    document.description_editor.setString_(
        "Surface commands that use rsync to synchronize source code.\n\n"
        "Return OK when the command does not use rsync.\n"
        "Return WARNING when the command uses rsync.")
    document.editor_changed()
    document.deploy()

    assert [request["type"] for request in model.requests] == [
        "compiler_catalog", "deployment_queue_status",
        "queue_deployment"]
    assert not document.window.isVisible()
    assert str(document.deploy_button.title()) == "Queued"
    queued_request = model.requests[-1]
    queued_source = queued_request["source"]
    queued_hash = revisions.hash_source(queued_source)
    document._notified_queue_terminal = (
        f"{queued_request['deployment_id']}:succeeded")
    document._apply_deployment_queue({
        "id": queued_request["deployment_id"],
        "status": "succeeded",
        "phase": "Deployed",
        "source_hash": queued_hash,
        "finished_at": 1,
        "result": {
            "ok": True,
            "rule": {
                "id": rule_id,
                "name": "Deploy Example",
                "scope": "global",
                "source": queued_source,
                "definition": {
                    "source_hash": queued_hash,
                    "source_path": "/tmp/library/rule.py",
                },
                "working_hash": queued_hash,
            },
            "active": {
                "source_hash": queued_hash,
                "compiler": queued_request["compiler"],
                "program_id": "program",
            },
            "coverage": {
                "mode": "selected",
                "selected_projects": ["/tmp/project"],
            },
            "impact_count": 1,
        },
    })
    document.show()
    assert str(document.diagnostics_label.stringValue()).startswith(
        "✓ Deployed")
    assert not document._dirty
    assert not document.deploy_button.isEnabled()
    assert str(document.deploy_button.title()) == "Deploy"
    document.description_editor.setString_(
        "Surface rsync commands, including those with unusual flags.")
    document.editor_changed()
    document.save_draft()
    assert document.deploy_button.isEnabled()
    assert str(document.state_label.stringValue()) == "Changes not deployed"
    recovered = []
    monkeypatch.setattr(
        rule_editor.ipc, "ensure_daemon", lambda wait=8.0: True)
    monkeypatch.setattr(
        rule_editor, "_on_main", lambda callback: callback())
    monkeypatch.setattr(
        rule_editor.ipc,
        "send_request",
        lambda request, timeout=10: {
            "ok": True,
            "queue": {
                "id": "recovered",
                "status": "checking",
                "phase": "Checking draft",
            },
        },
    )
    document._recover_deployment_after_disconnect(
        {"type": "queue_deployment"},
        "recovered",
        document._draft_generation,
        lambda result: recovered.append(result),
    )
    document._deployment_recovery_thread.join(timeout=2)
    assert recovered[0]["queue"]["id"] == "recovered"
    document._dirty = False
    document.window.close()
    assert not document.window.isVisible()


def test_rule_editor_grows_for_long_spec_and_caps_internal_editor():
    from AppKit import NSApplication, NSScreen
    from rules_as_programs import rules_api
    from rules_as_programs.ui.rule_editor import RuleEditorManager

    class Model:
        def __init__(self):
            self.requests = []

        def perform(self, request, *_args, **_kwargs):
            self.requests.append(request)
            return None

    NSApplication.sharedApplication()
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Long spec")
    model = Model()
    manager = RuleEditorManager(model)
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
    initial_height = document.window.contentView().frame().size.height
    document.description_editor.setString_("\n".join(
        f"Rule specification line {index}" for index in range(40)))
    document.editor_changed()
    document._fit_window_to_content()
    document.window.contentView().layoutSubtreeIfNeeded()
    screen = document.window.screen() or NSScreen.mainScreen()

    assert document.spec_height_constraint.constant() == 260
    assert document.window.contentView().frame().size.height > initial_height
    assert document.window.contentView().frame().size.height <= (
        screen.visibleFrame().size.height - 80)
    document._dirty = False
    document.window.close()


def test_existing_clean_rule_shows_disabled_deployed_action(monkeypatch):
    from AppKit import (
        NSAlert,
        NSApplication,
        NSToolbarItemVisibilityPriorityHigh,
        NSToolbarItemVisibilityPriorityLow,
    )
    from rules_as_programs import rules_api
    from rules_as_programs.core import revisions, validation_store
    from rules_as_programs.ui import rule_editor

    class Model:
        def __init__(self):
            self.requests = []

        def perform(self, request, *_args, **_kwargs):
            self.requests.append(request)
            return None

    NSApplication.sharedApplication()
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Already deployed")
    digest = revisions.hash_source(source)
    model = Model()
    manager = rule_editor.RuleEditorManager(model)
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
    document.compiler_catalog = [
        {
            "name": "future-standard",
            "description": "Future Standard",
            "default": True,
            "supports_local_sdk": True,
            "latest_snapshot": "standard-snapshot",
            "runtime_id": "runtime-large",
            "compiler_kind": "mapper_lora",
        },
        {
            "name": "future-compact",
            "description": "Future Compact",
            "supports_local_sdk": True,
            "latest_snapshot": "compact-snapshot",
            "runtime_id": "runtime-small",
            "compiler_kind": "mapper_lora",
        },
        {
            "name": "future-finetune",
            "description": "Future Finetuned",
            "compiler_kind": "finetune_lora",
            "supports_local_sdk": True,
            "latest_snapshot": "finetune-snapshot",
            "runtime_id": "runtime-large",
        },
    ]
    document._refresh_ui()
    compiler_rows = document.compiler_sheet_items({
        "source_hash": digest,
        "compiler": "future-standard",
    })
    compiler_alert = NSAlert.alloc().init()
    compiler_alert.addButtonWithTitle_("Close")
    compiler_accessory = document.compiler_catalog_accessory(
        compiler_alert,
        {"source_hash": digest, "compiler": "future-standard"},
        {"compiler": "", "refresh": False},
    )

    assert str(document.deploy_button.title()) == "Deploy"
    assert not document.deploy_button.isEnabled()
    assert str(document.state_label.stringValue()) == "Deployed"
    assert str(document.footer_status.stringValue()) == "Deployed"
    assert "Future Standard" in str(
        document.compiler_status_label.stringValue())
    assert str(document.compiler_action_button.title()) == "Choose…"
    toolbar_items = {
        str(item.itemIdentifier()): item
        for item in document.toolbar.items()
    }
    assert toolbar_items["rule.deploy"].visibilityPriority() == (
        NSToolbarItemVisibilityPriorityHigh)
    assert toolbar_items["rule.state"].visibilityPriority() == (
        NSToolbarItemVisibilityPriorityLow)
    document.window.setContentSize_((640, 500))
    document.window.contentView().layoutSubtreeIfNeeded()
    assert not document.deploy_button.isHidden()
    assert document.deploy_button.superview() is not None
    assert [row["name"] for row in compiler_rows] == [
        "future-standard", "future-finetune", "future-compact"]
    assert compiler_rows[0]["is_active"]
    assert not compiler_rows[0]["can_build"]
    assert compiler_rows[1]["can_build"]
    assert compiler_rows[1]["action"] == "build"
    assert compiler_rows[2]["can_build"]
    assert compiler_rows[2]["action"] == "select"
    assert compiler_accessory.frame().size.width == 560
    document._finetune_status = {
        "job": {
            "status": "building",
            "compiler": "future-finetune",
        }
    }
    document._dirty = True
    document._refresh_ui()
    assert document.deploy_button.isEnabled()
    assert "will be discarded" in str(document.deploy_button.toolTip())
    document._dirty = False
    document._finetune_status = {}
    document._refresh_ui()
    validation_cases = [
        {"id": "one", "input": "safe", "expected": "OK", "note": ""},
        {
            "id": "two",
            "input": "risky",
            "expected": "WARNING",
            "note": "",
        },
    ]
    spec_hash = validation_store.spec_fingerprint(document.spec)
    document.validation_cases = list(validation_cases)
    document._validation_target = {
        "compiler": "future-standard",
        "compiler_snapshot": "standard-snapshot",
    }
    document._cache_validation_results([
        {
            **case,
            "actual": case["expected"],
            "ok": True,
            "valid_output": True,
            "spec_hash": spec_hash,
            "compiler": "future-standard",
            "compiler_snapshot": "standard-snapshot",
            "case_hash": validation_store.case_fingerprint(case),
            "ran_at": 1,
        }
        for case in validation_cases
    ])
    document._reconcile_validation_results()
    document._render_validation_cases()
    assert set(document._validation_results) == {"one", "two"}
    first_validation_control = document.validation_controls[0][0]
    original_spec = document.spec
    edited_spec = original_spec + "\n\nTreat this as the current draft."
    document.description_editor.setString_(edited_spec)
    document.editor_changed()
    assert document.validation_controls[0][0] is first_validation_control
    document._set_draft_compiler("future-finetune", explicit=True)
    document._selected_build_compiler = "future-finetune"
    document._perform_finetune_action("start_finetune")
    build_request = model.requests[-1]
    assert build_request["type"] == "start_finetune"
    assert rules_api.source_projection(
        build_request["source"])["spec"] == edited_spec
    document._finetune_status = {
        "job": {
            "status": "building",
            "source_hash": document._current_source_hash,
            "compiler": "future-finetune",
            "started_at": time.time(),
        }
    }
    document._refresh_ui()
    assert str(document.deploy_button.title()) == "Deploy When Ready"
    assert document.deploy_button.isEnabled()
    document._allow_untested_validation_hash = (
        document._current_source_hash)
    document.deploy()
    assert model.requests[-1]["type"] == "queue_deployment"
    assert model.requests[-1]["validation_policy"] == "skip"
    document._apply_deployment_queue({
        "id": "queue",
        "rule_id": rule_id,
        "status": "waiting_for_build",
        "phase": "Building compiler",
        "compiler": "future-finetune",
        "source_hash": document._current_source_hash,
        "created_at": time.time(),
    })
    assert str(document.deploy_button.title()) == "Queued"
    assert not document.deploy_button.isEnabled()
    monkeypatch.setattr(
        rule_editor.ipc, "ensure_daemon", lambda wait=8.0: True)
    monkeypatch.setattr(
        rule_editor, "_on_main", lambda callback: callback())
    monkeypatch.setattr(
        rule_editor.ipc,
        "send_request",
        lambda request, timeout=10: {
            "ok": True,
            "queue": dict(document._deployment_queue),
        },
    )
    document._recover_deployment_queue_poll()
    document._deployment_queue_poll_recovery_thread.join(timeout=2)
    assert document._deployment_queue_poll_failures == 0
    assert document._queue_is_pending()
    document.description_editor.setString_(original_spec)
    document.editor_changed()
    assert model.requests[-1]["type"] == "cancel_queued_deployment"
    document._deployment_queue = {}
    document._finetune_status = {}
    document._set_draft_compiler("future-standard", explicit=True)
    document.validation_cases.pop(0)
    document._invalidate_validation_results()
    assert set(document._validation_results) == {"two"}
    assert document.observed_runs_button.isEnabled()
    document._set_draft_compiler("future-finetune", explicit=True)
    assert not document.deploy_button.isEnabled()
    document._set_compilation_message(
        "Previous compiler failed.", "old-build")
    document._apply_finetune_status({
        "ok": True,
        "active": {"source_hash": digest, "compiler": ""},
        "job": {
            "status": "ready",
            "source_hash": digest,
            "compiler": "future-finetune",
            "program_id": "finetuned-program",
        },
    })
    assert "Draft: Future Finetuned · ready" in str(
        document.compiler_status_label.stringValue())
    assert document.diagnostics_label.isHidden()
    assert document.deploy_button.isEnabled()
    assert str(document.compiler_action_button.title()) == "Choose…"
    document._dirty = False
    document.window.close()


def test_deployed_validation_cases_autosave_remove_and_undo(monkeypatch):
    from AppKit import NSApplication, NSButton, NSTextField
    from rules_as_programs import rules_api
    from rules_as_programs.core import revisions
    from rules_as_programs.ui import rule_editor

    monkeypatch.setattr(
        rule_editor, "_on_main", lambda callback: callback())

    class Model:
        def __init__(self):
            self.requests = []

        def perform(self, request, callback=None, timeout=4):
            self.requests.append(request)
            if request["type"] == "save_validation_cases":
                callback({
                    "ok": True,
                    "cases": list(request["validation_cases"]),
                })
            elif request["type"] == "validate_rule_cases":
                case = dict(request["validation_cases"][0])
                callback({
                    "ok": True,
                    "validation": {
                        "ok": False,
                        "passed": 0,
                        "total": 1,
                        "results": [{
                            **case,
                            "actual": "INFO",
                            "ok": False,
                        }],
                    },
                })

    NSApplication.sharedApplication()
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Autosave tests")
    digest = revisions.hash_source(source)
    model = Model()
    manager = rule_editor.RuleEditorManager(model)
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
        "validation_cases": [{
            "id": "case",
            "input": "git push",
            "expected": "OK",
            "note": "Added from observed evaluation",
        }],
        "deployment": {
            "coverage": {"mode": "all", "selected_projects": []},
            "projects": [],
        },
    }, "")
    document = next(iter(manager.documents.values()))
    document.window.contentView().layoutSubtreeIfNeeded()
    initial_width = document.window.frame().size.width
    document.validation_controls[0][0].setStringValue_(
        "python -m py_compile " + "very_long_path/" * 200)
    document.window.contentView().layoutSubtreeIfNeeded()
    assert document.window.frame().size.width <= initial_width + 1
    document.validation_controls[0][0].setStringValue_("git push")
    assert document.validation_height_constraint.constant() <= 180
    assert document.validation_scroll.hasVerticalScroller()
    assert not document.validation_scroll.autohidesScrollers()
    assert document.validation_controls[0][0].maximumNumberOfLines() == 1
    assert "(1)" == str(document.validation_count_label.stringValue())
    assert {
        str(control.stringValue())
        for control in _walk(document.validation_section)
        if isinstance(control, NSTextField)
    } >= {"Input", "Expected", "Last result"}
    assert "Not run" in [
        str(control.stringValue())
        for control in _walk(document.validation_stack)
        if isinstance(control, NSTextField)]
    trash = next(
        control for control in _walk(document.validation_stack)
        if isinstance(control, NSButton)
        and str(control.toolTip() or "") == "Remove validation case")
    assert trash.image() is not None

    document.run_validation_cases()
    assert "Actual INFO · Failed" in [
        str(control.stringValue())
        for control in _walk(document.validation_stack)
        if isinstance(control, NSTextField)]

    document.remove_validation_case(0)

    assert model.requests[-1]["type"] == "save_validation_cases"
    assert model.requests[-1]["validation_cases"] == []
    assert not document._dirty
    assert str(document.validation_status.stringValue()) == "Saved"
    assert not document.validation_undo_button.isHidden()

    document.undo_remove_validation_case()

    assert model.requests[-1]["validation_cases"][0]["input"] == "git push"
    assert len(document.validation_cases) == 1
    assert document.validation_undo_button.isHidden()
    document.validation_cases = [
        {
            "id": f"case-{index}",
            "input": f"command {index}",
            "expected": "OK",
            "note": "",
        }
        for index in range(9)
    ]
    document._render_validation_cases()
    assert str(document.validation_count_label.stringValue()) == (
        "(9) · showing 5")
    assert document.validation_height_constraint.constant() == 180
    assert document.validation_document.frame().size.height > (
        document.validation_scroll.contentView().bounds().size.height)
    document._scroll_validation_to_bottom()
    assert document.validation_scroll.contentView().bounds().origin.y > 0
    previous_origin = (
        document.validation_scroll.contentView().bounds().origin.y)
    document.add_validation_case()
    assert document.validation_scroll.contentView().bounds().origin.y >= (
        previous_origin)
    assert str(document.validation_count_label.stringValue()) == (
        "(10) · showing 5")
    document._dirty = False
    document.window.close()


def test_evaluation_history_filters_and_shows_exact_record(monkeypatch):
    from AppKit import (
        NSApplication, NSPasteboard, NSPasteboardTypeString)
    from rules_as_programs.ui import evaluation_history

    monkeypatch.setattr(
        evaluation_history, "_on_main", lambda callback: callback())

    class Model:
        def __init__(self):
            self.added = []

        def query(self, _request, callback=None, timeout=4):
            callback({
                "ok": True,
                "evaluations": [
                    {
                        "evaluation_id": "warning",
                        "timestamp": 2,
                        "status": "completed",
                        "result": "WARNING",
                        "duration_ms": 61,
                        "finding_id": 7,
                        "rule": {"id": "rule", "name": "Rule"},
                        "trigger": {"hook": "afterShellExecution"},
                        "input": {
                            "json_pointer": "/command",
                            "text": "rsync src/ host:/app",
                        },
                        "outcome": {},
                    },
                    {
                        "evaluation_id": "ok",
                        "timestamp": 1,
                        "status": "completed",
                        "result": "OK",
                        "duration_ms": 42,
                        "finding_id": None,
                        "rule": {"id": "rule", "name": "Rule"},
                        "trigger": {"hook": "afterShellExecution"},
                        "input": {
                            "json_pointer": "/command",
                            "text": "git push",
                        },
                        "outcome": {},
                    },
                ],
                "log_paths": [],
            })

        def perform(self, request, callback=None, timeout=4):
            self.added.append(request)
            callback({"ok": True})

    NSApplication.sharedApplication()
    model = Model()
    opened_findings = []
    case_updates = []
    manager = evaluation_history.EvaluationHistoryManager(
        model,
        lambda finding_id: opened_findings.append(finding_id),
        lambda rule_id, project_root:
            case_updates.append((rule_id, project_root)))
    manager.open("rule", "Rule", "/project")
    history = next(iter(manager.windows.values()))

    assert len(history.rows) == 2
    assert [str(column.title()) for column in history.table.tableColumns()] == [
        "Time", "Prediction", "Input", "Latency"]
    assert history.filtered_rows()[0]["evaluation_id"] == "warning"
    assert "rsync src/" in str(history.detail.string())
    assert "PREDICTION" in str(history.detail.string())
    assert "Last 2 · 1 OK · 1 findings · 0 errors" in str(
        history.summary_label.stringValue())
    history.copy_selected_input()
    assert NSPasteboard.generalPasteboard().stringForType_(
        NSPasteboardTypeString) == "rsync src/ host:/app"
    history.toggle_raw()
    assert '"evaluation_id": "warning"' in str(history.detail.string())
    history.toggle_raw()
    history.open_selected_finding()
    assert opened_findings == [7]
    history.expected_output.selectItemWithTitle_("OK")
    history.add_selected_validation_case()
    assert model.added[-1] == {
        "type": "add_validation_case",
        "rule_id": "rule",
        "project_root": "/project",
        "input": "rsync src/ host:/app",
        "expected": "OK",
    }
    assert case_updates == [("rule", "/project")]
    assert history._filter_keys == ["all", "OK", "WARNING"]
    history.filter.setSelectedSegment_(
        history._filter_keys.index("OK"))
    history.reload_table()
    assert [row["evaluation_id"] for row in history.filtered_rows()] == ["ok"]
    history.window.close()
