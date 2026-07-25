"""Persistent, table-backed native menu-bar popover."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

import objc
from AppKit import (
    NSButton,
    NSBezierPath,
    NSColor,
    NSControlStateValueOff,
    NSControlStateValueOn,
    NSFont,
    NSImageView,
    NSLineBreakByTruncatingTail,
    NSMenu,
    NSMenuItem,
    NSPopUpButton,
    NSProgressIndicator,
    NSProgressIndicatorStyleSpinning,
    NSSearchField,
    NSSegmentedControl,
    NSSegmentSwitchTrackingSelectOne,
    NSScrollView,
    NSSwitchButton,
    NSTableCellView,
    NSTableColumn,
    NSTableRowView,
    NSTableView,
    NSTableViewStylePlain,
    NSTextField,
    NSTrackingActiveInActiveApp,
    NSTrackingArea,
    NSTrackingInVisibleRect,
    NSTrackingMouseEnteredAndExited,
    NSView,
    NSViewHeightSizable,
    NSViewWidthSizable,
)
from Foundation import NSIndexSet, NSMakeRect, NSObject

from .layout import FOOTER_HEIGHT, POPOVER_MAX_HEIGHT, POPOVER_WIDTH
from .macos_controls import (
    RAPHoverButton,
    set_button_symbol,
    style_button,
    system_symbol,
)
from .model import UISnapshot

PAD = 14
HEADER_HEIGHT = 92
SEVERITY_RANK = {"critical": 3, "warn": 2, "info": 1}


def _relative_time(ts: float) -> str:
    delta = max(0, int(time.time() - float(ts or 0)))
    if delta < 60:
        return "now" if delta < 5 else f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m"
    if delta < 86400:
        return f"{delta // 3600}h"
    return f"{delta // 86400}d"


def _project_name(path: str) -> str:
    return Path(path).name or path or "Unknown project"


class RAPPersistentRoot(NSView):
    def isFlipped(self):
        return True


class RAPNativeTable(NSTableView):
    def keyDown_(self, event):
        if int(event.keyCode()) in (36, 76):
            owner = getattr(self, "owner", None)
            if owner:
                owner.activate_selected_row()
                return
        objc.super(RAPNativeTable, self).keyDown_(event)


class RAPTableRowView(NSTableRowView):
    """Native selection plus a subtle pointer-hover affordance."""

    def initWithFrame_(self, frame):
        self = objc.super(RAPTableRowView, self).initWithFrame_(frame)
        if self is None:
            return None
        self._hovered = False
        self._actionable = False
        self._row_key = ""
        self._tracking = None
        return self

    def updateTrackingAreas(self):
        if self._tracking is not None:
            self.removeTrackingArea_(self._tracking)
        objc.super(RAPTableRowView, self).updateTrackingAreas()
        options = (
            NSTrackingMouseEnteredAndExited
            | NSTrackingActiveInActiveApp
            | NSTrackingInVisibleRect
        )
        self._tracking = (
            NSTrackingArea.alloc().initWithRect_options_owner_userInfo_(
                self.bounds(), options, self, None))
        self.addTrackingArea_(self._tracking)

    def mouseEntered_(self, _event):
        if self._actionable:
            self._hovered = True
            self.setNeedsDisplay_(True)

    def mouseExited_(self, _event):
        self._hovered = False
        self.setNeedsDisplay_(True)

    def drawBackgroundInRect_(self, rect):
        objc.super(RAPTableRowView, self).drawBackgroundInRect_(rect)
        if self._hovered and not self.isSelected() and self._actionable:
            bounds = self.bounds()
            inset = NSMakeRect(
                bounds.origin.x + 4,
                bounds.origin.y + 2,
                max(0, bounds.size.width - 8),
                max(0, bounds.size.height - 4),
            )
            color = NSColor.selectedContentBackgroundColor(
            ).colorWithAlphaComponent_(0.09)
            color.setFill()
            NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
                inset, 6, 6).fill()

    @objc.python_method
    def configure(self, row_key: str, actionable: bool) -> None:
        self._row_key = row_key
        self._actionable = actionable
        if not actionable:
            self._hovered = False
        self.setNeedsDisplay_(True)

    @objc.python_method
    def hovered(self) -> bool:
        return bool(self._hovered)


class RAPTableCellView(NSTableCellView):
    """Top-down coordinates for compact, manually arranged native cells."""

    def isFlipped(self):
        return True


class RAPControlTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "callbacks", {}).get(int(sender.tag()))
        if callback:
            callback(sender)


class RAPMenuTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "callbacks", {}).pop(int(sender.tag()), None)
        owner = getattr(self, "owner", None)
        if callback and owner:
            owner.controller.defer_menu_action(callback)


class RAPTableAdapter(NSObject):
    def numberOfRowsInTableView_(self, _table):
        owner = getattr(self, "owner", None)
        return len(owner.rows) if owner else 0

    def tableView_heightOfRow_(self, _table, row):
        owner = getattr(self, "owner", None)
        return owner.row_height(owner.rows[int(row)]) if owner else 44

    def tableView_viewForTableColumn_row_(self, _table, _column, row):
        owner = getattr(self, "owner", None)
        return owner.row_view(owner.rows[int(row)]) if owner else None

    def tableViewSelectionDidChange_(self, _notification):
        owner = getattr(self, "owner", None)
        if owner:
            owner.selection_changed()

    def activate_(self, _sender):
        owner = getattr(self, "owner", None)
        if owner:
            owner.activate_clicked_row()

    def tableView_isGroupRow_(self, _table, row):
        owner = getattr(self, "owner", None)
        return bool(
            owner and owner.rows[int(row)].get("type") == "section")

    def tableView_shouldSelectRow_(self, _table, row):
        owner = getattr(self, "owner", None)
        return bool(
            owner and owner.row_is_actionable(owner.rows[int(row)]))

    def tableView_rowViewForRow_(self, table, row):
        owner = getattr(self, "owner", None)
        if owner is None:
            return None
        model = owner.rows[int(row)]
        identifier = "group-row" if model.get("type") == "section" else "content-row"
        view = table.makeViewWithIdentifier_owner_(identifier, owner)
        if view is None:
            view = RAPTableRowView.alloc().initWithFrame_(NSMakeRect(
                0, 0, POPOVER_WIDTH, owner.row_height(model)))
            view.setIdentifier_(identifier)
        view.configure(owner.row_key(model), owner.row_is_actionable(model))
        return view


class PersistentPopoverRenderer:
    """Build once; update stable controls and table row models."""

    def __init__(self, controller: Any) -> None:
        self.controller = controller
        self.rows: list[dict[str, Any]] = []
        self.snapshot = UISnapshot.loading()
        self._callbacks: dict[int, Callable[[Any], None]] = {}
        self._target = RAPControlTarget.alloc().init()
        self._target.callbacks = self._callbacks
        self._next_tag = 1
        self._row_tags: set[int] = set()
        self._building_row = False
        self._menu_callbacks: dict[int, Callable[[], None]] = {}
        self._menu_target = RAPMenuTarget.alloc().init()
        self._menu_target.callbacks = self._menu_callbacks
        self._menu_target.owner = self
        self._next_menu_tag = 1
        self._menus: list[NSMenu] = []
        self._adapter = RAPTableAdapter.alloc().init()
        self._adapter.owner = self
        self._selected_key = ""
        self._view_states: dict[str, dict[str, Any]] = {}
        self._build()

    def _wire(self, control, callback):
        tag = self._next_tag
        self._next_tag += 1
        self._callbacks[tag] = callback
        if self._building_row:
            self._row_tags.add(tag)
        control.setTag_(tag)
        control.setTarget_(self._target)
        control.setAction_("invoke:")
        return control

    def _button(
        self, title: str, frame, callback, *,
        role: str = "flat", accessibility: str | None = None,
    ) -> NSButton:
        button_class = (
            RAPHoverButton if role in ("flat", "icon") else NSButton)
        button = button_class.alloc().initWithFrame_(NSMakeRect(*frame))
        button.setTitle_(title)
        style_button(
            button, role=role,
            accessibility=accessibility or title.rstrip("…"))
        return self._wire(button, callback)

    def _icon_button(
        self, symbol: str, fallback: str, frame, callback, *,
        accessibility: str,
    ) -> NSButton:
        button = RAPHoverButton.alloc().initWithFrame_(NSMakeRect(*frame))
        style_button(
            button, role="icon", accessibility=accessibility,
            tooltip=accessibility)
        set_button_symbol(
            button, symbol, accessibility, fallback=fallback, point_size=13)
        return self._wire(button, callback)

    @staticmethod
    def _label(
        text: str, frame, *, size=11, bold=False, color=None, lines=1,
    ) -> NSTextField:
        label = NSTextField.labelWithString_(str(text))
        label.setFrame_(NSMakeRect(*frame))
        label.setFont_(
            NSFont.boldSystemFontOfSize_(size)
            if bold else NSFont.systemFontOfSize_(size))
        label.setTextColor_(color or NSColor.labelColor())
        label.setMaximumNumberOfLines_(lines)
        label.setLineBreakMode_(NSLineBreakByTruncatingTail)
        if lines > 1:
            label.cell().setWraps_(True)
        return label

    def _build(self) -> None:
        self.root = RAPPersistentRoot.alloc().initWithFrame_(
            NSMakeRect(0, 0, POPOVER_WIDTH, 500))
        self.root.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        self.title_label = self._label(
            "Rules as Programs", (PAD, 8, 230, 24), size=16, bold=True)
        self.root.addSubview_(self.title_label)
        self.status_label = self._label(
            "", (PAD, 34, 380, 18), size=10,
            color=NSColor.secondaryLabelColor())
        self.root.addSubview_(self.status_label)

        self.project_popup = NSPopUpButton.alloc().initWithFrame_pullsDown_(
            NSMakeRect(PAD, 56, 180, 27), False)
        self._wire(self.project_popup, self._project_changed)
        self.root.addSubview_(self.project_popup)
        self.add_button = self._button(
            "", (380, 55, 34, 29),
            self._add_rule,
            role="flat", accessibility="Add rule")
        set_button_symbol(
            self.add_button, "plus", "Add rule", fallback="+", point_size=14)
        self.root.addSubview_(self.add_button)

        self.back_button = self._button(
            "Findings", (PAD, 56, 78, 27),
            lambda _sender: self.controller.select_tab("inbox"))
        self.root.addSubview_(self.back_button)
        self.route_title = self._label(
            "", (100, 59, 220, 20), size=12, bold=True)
        self.root.addSubview_(self.route_title)

        self.mode_control = NSSegmentedControl.alloc().initWithFrame_(
            NSMakeRect(200, 56, 170, 27))
        self.mode_control.setSegmentCount_(2)
        self.mode_control.setLabel_forSegment_("Needs Review", 0)
        self.mode_control.setLabel_forSegment_("Reviewed", 1)
        self.mode_control.setTrackingMode_(NSSegmentSwitchTrackingSelectOne)
        self._wire(self.mode_control, lambda sender: self.controller.set_inbox_mode(
            "open" if sender.selectedSegment() == 0 else "history"))
        self.root.addSubview_(self.mode_control)

        self.search = NSSearchField.alloc().initWithFrame_(
            NSMakeRect(220, 8, 194, 27))
        self.search.setPlaceholderString_("Search rules")
        self._wire(self.search, lambda sender: self.controller.filter_rules(
            str(sender.stringValue())))
        self.root.addSubview_(self.search)

        self.scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(0, HEADER_HEIGHT, POPOVER_WIDTH, 360))
        self.scroll.setHasVerticalScroller_(False)
        self.scroll.setAutohidesScrollers_(True)
        self.scroll.setDrawsBackground_(False)
        if hasattr(self.scroll.contentView(), "setDrawsBackground_"):
            self.scroll.contentView().setDrawsBackground_(False)
        self.scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        self.table = RAPNativeTable.alloc().initWithFrame_(
            NSMakeRect(0, 0, POPOVER_WIDTH, 360))
        self.table.owner = self
        column = NSTableColumn.alloc().initWithIdentifier_("main")
        column.setWidth_(POPOVER_WIDTH)
        self.table_column = column
        self.table.addTableColumn_(column)
        self.table.setHeaderView_(None)
        self.table.setIntercellSpacing_((0, 0))
        self.table.setRowSizeStyle_(0)
        self.table.setBackgroundColor_(NSColor.clearColor())
        self.table.setUsesAlternatingRowBackgroundColors_(False)
        if hasattr(self.table, "setStyle_"):
            self.table.setStyle_(NSTableViewStylePlain)
        self.table.setDataSource_(self._adapter)
        self.table.setDelegate_(self._adapter)
        self.table.setAllowsEmptySelection_(True)
        self.table.setTarget_(self._adapter)
        self.table.setAction_("activate:")
        self.scroll.setDocumentView_(self.table)
        self.root.addSubview_(self.scroll)

        self.navigation = NSSegmentedControl.alloc().initWithFrame_(
            NSMakeRect(PAD, 7, 250, 27))
        self.navigation.setSegmentCount_(3)
        self.navigation.setTrackingMode_(NSSegmentSwitchTrackingSelectOne)
        for index, title in enumerate(("Findings", "Rules", "Projects")):
            self.navigation.setLabel_forSegment_(title, index)
        self._wire(self.navigation, self._route_changed)
        self.root.addSubview_(self.navigation)
        self.more_button = self._button(
            "More…", (346, 7, 68, 27),
            lambda sender: self.controller.show_app_menu(sender))
        self.root.addSubview_(self.more_button)

        self.confirmation_view = RAPPersistentRoot.alloc().initWithFrame_(
            self.root.bounds())
        self.confirmation_view.setAutoresizingMask_(
            NSViewWidthSizable | NSViewHeightSizable)
        self.confirmation_title = self._label(
            "", (32, 72, 366, 50), size=15, bold=True, lines=2)
        self.confirmation_message = self._label(
            "", (32, 130, 366, 220), size=11,
            color=NSColor.secondaryLabelColor(), lines=14)
        self.confirmation_cancel = self._button(
            "Cancel", (222, 370, 88, 32),
            lambda _sender: self.controller.cancel_confirmation(),
            role="secondary")
        self.confirmation_action = self._button(
            "Confirm", (318, 370, 96, 32),
            lambda _sender: self.controller.confirm_change(),
            role="destructive")
        for view in (
            self.confirmation_title, self.confirmation_message,
            self.confirmation_cancel, self.confirmation_action,
        ):
            self.confirmation_view.addSubview_(view)
        self.confirmation_view.setHidden_(True)
        self.root.addSubview_(self.confirmation_view)

    def _route_changed(self, sender) -> None:
        index = int(sender.selectedSegment())
        if index == 1:
            self.controller.open_rule_library()
        else:
            self.controller.select_tab(("inbox", "rules", "projects")[index])

    def _add_rule(self, sender) -> None:
        route = getattr(self.controller, "route", "inbox")
        if route == "rules":
            if getattr(
                self.controller, "rules_context", "library"
            ) == "library":
                self.controller._new_rule("")
            else:
                self.controller.show_add_rule_menu(sender)
            return
        self.controller.begin_add_rule(
            getattr(self.controller, "home_project", ""), sender)

    def _project_changed(self, sender) -> None:
        choices = getattr(self, "_project_choices", [])
        index = int(sender.indexOfSelectedItem())
        if 0 <= index < len(choices):
            path = choices[index].get("path", "")
            if getattr(self.controller, "route", "inbox") == "rules":
                self.controller.select_project(path)
            else:
                self.controller.select_home_project(path)

    def _sync_header(self) -> None:
        route = getattr(self.controller, "route", "inbox")
        route_index = {"inbox": 0, "rules": 1, "projects": 2}.get(route, 0)
        self.navigation.setSelectedSegment_(route_index)
        inbox = route == "inbox"
        self.project_popup.setHidden_(not inbox and route != "rules")
        self.add_button.setHidden_(not inbox and route != "rules")
        self.back_button.setHidden_(inbox)
        self.route_title.setHidden_(inbox)
        self.mode_control.setHidden_(not inbox)
        self.search.setHidden_(route != "rules")
        if inbox:
            self.project_popup.setFrame_(NSMakeRect(PAD, 56, 180, 27))
            self.mode_control.setFrame_(NSMakeRect(200, 56, 170, 27))
            self.add_button.setFrame_(NSMakeRect(380, 55, 34, 29))
            self.status_label.setHidden_(False)
            self.mode_control.setSelectedSegment_(
                0 if getattr(self.controller, "inbox_mode", "open") == "open"
                else 1)
        else:
            self.route_title.setStringValue_(
                "Rule Library" if route == "rules" else "Projects")
            if route == "rules":
                self.back_button.setFrame_(NSMakeRect(PAD, 56, 78, 27))
                self.route_title.setFrame_(NSMakeRect(100, 59, 100, 20))
                self.project_popup.setFrame_(NSMakeRect(208, 56, 126, 27))
                self.add_button.setFrame_(NSMakeRect(380, 55, 34, 29))
                self.status_label.setHidden_(True)
            else:
                self.status_label.setHidden_(False)
        projects = self.snapshot.projects
        library = getattr(self.controller, "rules_context", "library") == "library"
        self._project_choices = (
            [{"path": "", "name": "All Rules"}, *projects]
            if route == "rules"
            else [{"path": "", "name": "All Projects"}, *projects]
        )
        selected = (
            ""
            if route == "rules" and library
            else getattr(
                self.controller,
                "selected_project" if route == "rules" else "home_project",
                "",
            )
        )
        self.project_popup.removeAllItems()
        for item in self._project_choices:
            self.project_popup.addItemWithTitle_(
                item.get("name") or _project_name(item.get("path", "")))
        selected_index = next(
            (i for i, item in enumerate(self._project_choices)
             if item.get("path", "") == selected),
            0,
        )
        self.project_popup.selectItemAtIndex_(selected_index)
        self.search.setStringValue_(
            getattr(self.controller, "rules_filter", ""))

    def _models(self) -> list[dict[str, Any]]:
        route = getattr(self.controller, "route", "inbox")
        if route == "rules":
            return self._rule_models()
        if route == "projects":
            return self._project_models()
        return self._finding_models()

    def _finding_models(self) -> list[dict[str, Any]]:
        mode = getattr(self.controller, "inbox_mode", "open")
        if self.snapshot.status == "unavailable":
            return [{
                "type": "daemon_error",
                "title": "Rules cannot be checked",
                "message": self.snapshot.error or "The local daemon is unavailable.",
            }]
        if self.snapshot.status == "loading":
            return [{"type": "loading", "title": "Checking monitored projects…"}]
        if mode == "history" and getattr(
            self.controller, "history_loading", False
        ):
            return [{"type": "loading", "title": "Loading review history…"}]
        selected = getattr(self.controller, "home_project", "")
        issues = list(self.snapshot.data.get("health_issues") or []) if mode == "open" else []
        attention = list(self.snapshot.attention) if mode == "open" else []
        if selected:
            issues = [
                item for item in issues
                if item.get("project_root") in ("", selected)
                or selected in (item.get("affected_projects") or [])
            ]
            attention = [
                item for item in attention
                if item.get("project_root") == selected
            ]
        rows: list[dict[str, Any]] = []
        if issues:
            rows.append({
                "type": "section", "title": "Monitoring issues",
                "count": len(issues), "section_key": "issues"})
            rows.extend({"type": "issue", "value": item} for item in issues)
        if attention:
            rows.append({
                "type": "section", "title": "Needs reply",
                "count": len(attention), "section_key": "attention"})
            rows.extend({"type": "attention", "value": item} for item in attention)
        groups = (
            getattr(self.controller, "history_groups", [])
            if mode == "history"
            else [
                group for project_groups in self.snapshot.findings_by_project.values()
                for group in project_groups
            ]
        )
        if selected:
            groups = [
                group for group in groups
                if group.get("project_root") == selected
            ]
        stale_groups = [
            group for group in groups if group.get("stale")]
        groups = [group for group in groups if not group.get("stale")]
        if stale_groups:
            rows.append({
                "type": "section",
                "title": "Rule changed — needs recheck",
                "count": len(stale_groups),
                "section_key": "stale",
            })
            rows.extend({
                "type": "finding",
                "value": value,
                "mode": "stale",
            } for value in sorted(
                stale_groups,
                key=lambda item: float(
                    item.get("last_seen") or item.get("ts", 0)),
                reverse=True,
            ))
        grouped: dict[str, list[dict[str, Any]]] = {}
        for group in groups:
            grouped.setdefault(group.get("project_root", ""), []).append(group)
        ordered_projects = sorted(
            grouped.items(),
            key=lambda item: max(
                (
                    SEVERITY_RANK.get(value.get("severity", "info"), 0) * 10**12
                    + float(value.get("last_seen") or value.get("ts", 0))
                    for value in item[1]
                ),
                default=0,
            ),
            reverse=True,
        )
        for project, values in ordered_projects:
            rows.append({
                "type": "section",
                "title": _project_name(project),
                "project_root": project,
                "count": len(values),
                "section_key": f"project:{project}",
                "project_actions": mode == "open",
            })
            rows.extend({
                "type": "finding", "value": value, "mode": mode,
            } for value in sorted(
                values,
                key=lambda item: (
                    SEVERITY_RANK.get(item.get("severity", "info"), 0),
                    float(item.get("last_seen") or item.get("ts", 0)),
                ),
                reverse=True,
            ))
        if not rows:
            rows.append({
                "type": "empty",
                "title": (
                    "No reviewed findings yet"
                    if mode == "history" else "All reviewed"),
                "message": "",
            })
        return rows

    def _rule_models(self) -> list[dict[str, Any]]:
        if getattr(self.controller, "rules_loading", False):
            return [{"type": "loading", "title": "Loading rules…"}]
        data = getattr(self.controller, "rules_data", {}) or {}
        query = getattr(self.controller, "rules_filter", "").strip().lower()
        rows = []
        for error in data.get("errors") or []:
            rows.append({"type": "rule_error", "value": error})
        for rule in data.get("rules") or []:
            name = str(rule.get("name") or rule.get("title") or rule.get("id"))
            if query and query not in name.lower() and query not in str(
                rule.get("id", "")).lower():
                continue
            rows.append({"type": "rule", "value": rule})
        return rows or [{
            "type": "empty", "title": "No rules", "message": "Add a rule to begin."}]

    def _project_models(self) -> list[dict[str, Any]]:
        return [
            {"type": "project", "value": project}
            for project in self.snapshot.projects
        ] or [{
            "type": "empty",
            "title": "No Cursor projects found",
            "message": "Run rap init --scan in a Cursor project.",
        }]

    @staticmethod
    def row_key(row: dict[str, Any]) -> str:
        value = row.get("value") or {}
        if row.get("type") == "issue":
            identity = "|".join((
                str(value.get("code", "")),
                str(value.get("rule_id", "")),
                str(value.get("project_root", "")),
            ))
        elif row.get("type") == "finding":
            identity = str(
                value.get("fingerprint") or value.get("id", ""))
        elif row.get("type") == "section":
            identity = str(
                row.get("section_key")
                or row.get("project_root")
                or row.get("title", ""))
        else:
            identity = str(
                value.get("id") or value.get("fingerprint")
                or value.get("path") or row.get("title", ""))
        return ":".join((
            str(row.get("type", "")),
            identity,
        ))

    @staticmethod
    def row_height(row: dict[str, Any]) -> float:
        return {
            "section": 30,
            "issue": 78,
            "attention": 70,
            "finding": 48,
            "rule": 64,
            "rule_error": 72,
            "project": 72,
            "empty": 90,
            "loading": 60,
            "daemon_error": 96,
        }.get(row.get("type"), 48)

    def _cell(self, row: dict[str, Any]) -> NSTableCellView:
        height = self.row_height(row)
        return RAPTableCellView.alloc().initWithFrame_(
            NSMakeRect(0, 0, POPOVER_WIDTH, height))

    def row_view(self, row: dict[str, Any]) -> NSView:
        self._building_row = True
        try:
            return self._row_view(row)
        finally:
            self._building_row = False

    def _row_view(self, row: dict[str, Any]) -> NSView:
        kind = row.get("type")
        cell = self._cell(row)
        value = row.get("value") or {}
        if kind == "section":
            cell.addSubview_(self._label(
                row.get("title", ""), (PAD, 7, 190, 20),
                size=11, bold=True, color=NSColor.secondaryLabelColor()))
            if row.get("count") is not None:
                cell.addSubview_(self._label(
                    str(row.get("count", 0)), (202, 7, 28, 20),
                    size=10, color=NSColor.secondaryLabelColor()))
            project_root = str(row.get("project_root", ""))
            if row.get("project_actions") and project_root:
                cell.addSubview_(self._button(
                    "+ Rule", (232, 3, 56, 24),
                    lambda sender, path=project_root:
                    self.controller.begin_add_rule(path, sender)))
                cell.addSubview_(self._button(
                    "Rules", (290, 3, 52, 24),
                    lambda _sender, path=project_root:
                    self.controller.open_manage_rules(path)))
                cell.addSubview_(self._icon_button(
                    "checkmark.circle", "✓", (350, 1, 34, 27),
                    lambda _sender, path=project_root:
                    self.controller.done_project(path),
                    accessibility=(
                        f"Mark all findings in {_project_name(project_root)} "
                        "reviewed")))
        elif kind == "finding":
            severity = str(value.get("severity", "info"))
            severity_label = {
                "critical": "Critical",
                "warn": "Warning",
                "info": "Info",
            }.get(severity, "Info")
            symbol_name = {
                "critical": "exclamationmark.octagon.fill",
                "warn": "exclamationmark.triangle.fill",
                "info": "info.circle.fill",
            }.get(severity, "info.circle")
            symbol = system_symbol(symbol_name, severity.title(), point_size=13)
            if symbol:
                image = NSImageView.alloc().initWithFrame_(
                    NSMakeRect(PAD, 14, 16, 16))
                image.setImage_(symbol)
                image.setContentTintColor_({
                    "critical": NSColor.systemRedColor(),
                    "warn": NSColor.systemOrangeColor(),
                    "info": NSColor.systemBlueColor(),
                }.get(severity, NSColor.secondaryLabelColor()))
                cell.addSubview_(image)
            else:
                cell.addSubview_(self._label(
                    "!", (PAD, 14, 16, 16), size=11, bold=True))
            cell.addSubview_(self._label(
                severity_label, (34, 15, 56, 16), size=9.5,
                color=NSColor.secondaryLabelColor()))
            title = str(value.get("rule_title") or value.get("rule_id", "Rule"))
            if value.get("stale"):
                title += " · changed"
            elif value.get("review_reason") == "rule_deleted":
                title += " · deleted"
            cell.addSubview_(self._label(
                title, (94, 7, 148, 20), size=11.5, bold=True))
            occurrences = int(value.get("occurrences", 1) or 1)
            if occurrences > 1:
                cell.addSubview_(self._label(
                    f"×{occurrences}", (246, 9, 30, 18), size=9,
                    color=NSColor.secondaryLabelColor()))
            cell.addSubview_(self._label(
                _relative_time(value.get("last_seen") or value.get("ts", 0)),
                (278, 9, 38, 18), size=9,
                color=NSColor.secondaryLabelColor()))
            if row.get("mode") == "open":
                cell.addSubview_(self._icon_button(
                    "ellipsis.circle", "…", (360, 8, 34, 28),
                    lambda sender, item=value:
                    self.controller.show_finding_menu(sender, item),
                    accessibility=f"Actions for {title}"))
                cell.addSubview_(self._icon_button(
                    "checkmark.circle", "✓", (320, 8, 34, 28),
                    lambda _sender, item=value: self.controller.done_group(item),
                    accessibility=f"Mark {title} reviewed"))
            else:
                cell.addSubview_(self._icon_button(
                    "ellipsis.circle", "…", (360, 8, 34, 28),
                    lambda sender, item=value:
                    self.controller.show_finding_menu(sender, item),
                    accessibility=f"Actions for {title}"))
            cell.setAccessibilityLabel_(
                f"{severity_label}, {title}, {occurrences} occurrence"
                f"{'s' if occurrences != 1 else ''}, "
                f"{_relative_time(value.get('last_seen') or value.get('ts', 0))}")
        elif kind == "issue":
            cell.addSubview_(self._label(
                str(value.get("summary", "Monitoring issue")),
                (PAD, 7, 280, 20), size=11.5, bold=True))
            cell.addSubview_(self._label(
                str(value.get("impact", "")),
                (PAD, 30, 280, 34), size=9.5, lines=2,
                color=NSColor.secondaryLabelColor()))
            cell.addSubview_(self._button(
                "Retry", (302, 7, 52, 26),
                lambda _sender, item=value:
                self.controller.retry_health_issue(item)))
            cell.addSubview_(self._button(
                "Details", (356, 7, 64, 26),
                lambda _sender, item=value:
                self.controller.show_health_issue(item)))
            if value.get("rule_id"):
                cell.addSubview_(self._button(
                    "Test Rule", (330, 39, 90, 26),
                    lambda _sender, item=value:
                    self.controller.test_health_issue_rule(item)))
        elif kind == "attention":
            symbol = system_symbol(
                "questionmark.bubble.fill", "Needs reply", point_size=14)
            if symbol:
                image = NSImageView.alloc().initWithFrame_(
                    NSMakeRect(PAD, 10, 18, 18))
                image.setImage_(symbol)
                image.setContentTintColor_(NSColor.systemPurpleColor())
                cell.addSubview_(image)
            cell.addSubview_(self._label(
                _project_name(value.get("project_root", "")),
                (38, 5, 210, 18), size=10.5, bold=True))
            cell.addSubview_(self._label(
                _relative_time(value.get("created_at", 0)),
                (250, 5, 40, 18), size=9,
                color=NSColor.secondaryLabelColor()))
            cell.addSubview_(self._label(
                str(value.get("message", "Agent needs a reply")),
                (38, 25, 250, 38), size=10.5, lines=2))
            cell.addSubview_(self._button(
                "Open Cursor", (296, 7, 96, 26),
                lambda _sender, item=value:
                self.controller.open_attention_project(item)))
            cell.addSubview_(self._button(
                "Clear", (344, 38, 48, 24),
                lambda _sender, item=value:
                self.controller.dismiss_attention(item)))
        elif kind == "rule":
            name = str(value.get("name") or value.get("title") or value.get("id"))
            cell.addSubview_(self._label(
                name, (PAD, 8, 265, 20), size=11.5, bold=True))
            states = []
            if value.get("draft_changes"):
                states.append("Changes not deployed")
            if value.get("muted"):
                states.append("Findings hidden")
            if value.get("warm_status") == "failed":
                states.append("Check failed")
            cell.addSubview_(self._label(
                " · ".join(states) or "Deployed",
                (PAD, 31, 270, 18), size=9.5,
                color=NSColor.secondaryLabelColor()))
            cell.addSubview_(self._button(
                "Edit", (286, 8, 54, 26),
                lambda _sender, item=value: self.controller.edit_rule(item)))
            cell.addSubview_(self._button(
                "Actions…", (344, 8, 76, 26),
                lambda sender, item=value:
                self.controller.show_rule_menu(sender, item)))
            if getattr(
                self.controller, "rules_context", "library"
            ) == "project":
                switch = NSButton.alloc().initWithFrame_(
                    NSMakeRect(286, 36, 126, 24))
                switch.setButtonType_(NSSwitchButton)
                switch.setTitle_("Runs here")
                switch.setState_(
                    NSControlStateValueOn
                    if value.get("enabled") else NSControlStateValueOff)
                switch.setAccessibilityLabel_(f"Run {name} in this project")
                self._wire(
                    switch,
                    lambda sender, item=value: self.controller.toggle_rule(
                        item, sender.state() == NSControlStateValueOn))
                cell.addSubview_(switch)
        elif kind == "rule_error":
            cell.addSubview_(self._label(
                str(value.get("name") or value.get("id", "Rule error")),
                (PAD, 7, 270, 20), size=11.5, bold=True,
                color=NSColor.systemRedColor()))
            cell.addSubview_(self._label(
                str(value.get("load_error") or value.get("error", "")),
                (PAD, 30, 280, 34), size=9.5, lines=2))
            cell.addSubview_(self._button(
                "Open", (286, 7, 54, 26),
                lambda _sender, item=value:
                self.controller.open_rule_source(item)))
            cell.addSubview_(self._button(
                "Actions…", (344, 7, 76, 26),
                lambda sender, item=value:
                self.controller.show_rule_menu(sender, item)))
        elif kind == "project":
            name = str(value.get("name") or _project_name(value.get("path", "")))
            cell.addSubview_(self._label(
                name, (PAD, 7, 220, 20), size=11.5, bold=True))
            if value.get("open_count"):
                cell.addSubview_(self._label(
                    str(value.get("open_count")), (238, 7, 28, 20),
                    size=10, bold=True))
            activity = (
                "Agent active"
                if value.get("active")
                else (
                    f"Last event {_relative_time(value.get('last_event_ts'))}"
                    if value.get("last_event_ts") else "No agent activity"
                )
            )
            summary = (
                f"{str(value.get('status', 'idle')).replace('_', ' ').title()} · "
                f"{value.get('enabled_rule_count', 0)}/{value.get('rule_count', 0)} "
                f"rules · {activity}"
            )
            cell.addSubview_(self._label(
                summary, (PAD, 31, 260, 34), size=9.5, lines=2,
                color=NSColor.secondaryLabelColor()))
            switch = NSButton.alloc().initWithFrame_(NSMakeRect(278, 7, 38, 24))
            switch.setButtonType_(NSSwitchButton)
            switch.setTitle_("")
            switch.setState_(
                NSControlStateValueOn
                if value.get("monitoring") else NSControlStateValueOff)
            switch.setAccessibilityLabel_(f"Monitor {name}")
            self._wire(
                switch,
                lambda sender, item=value: self.controller.toggle_project(
                    item, sender.state() == NSControlStateValueOn))
            cell.addSubview_(switch)
            cell.addSubview_(self._button(
                "+ Rule", (278, 39, 54, 25),
                lambda sender, item=value:
                self.controller.begin_add_rule(item.get("path", ""), sender)))
            cell.addSubview_(self._button(
                "Rules", (334, 39, 50, 25),
                lambda _sender, item=value:
                self.controller.open_manage_rules(item.get("path", ""))))
            cell.addSubview_(self._icon_button(
                "ellipsis.circle", "…", (388, 7, 34, 27),
                lambda sender, item=value:
                self.controller.show_project_menu(sender, item),
                accessibility=f"Actions for {name}"))
        elif kind == "daemon_error":
            cell.addSubview_(self._label(
                row.get("title", ""), (PAD + 12, 12, 300, 22),
                size=12, bold=True, color=NSColor.systemRedColor()))
            cell.addSubview_(self._label(
                row.get("message", ""), (PAD + 12, 38, 300, 36),
                size=10, lines=2))
            cell.addSubview_(self._button(
                "Retry", (338, 12, 72, 28),
                lambda _sender: self.controller.retry(), role="primary"))
        else:
            cell.addSubview_(self._label(
                row.get("title", ""), (PAD + 12, 18, 380, 24),
                size=13, bold=True))
            if row.get("message"):
                cell.addSubview_(self._label(
                    row.get("message", ""), (PAD + 12, 44, 380, 30),
                    size=10, lines=2,
                    color=NSColor.secondaryLabelColor()))
            if kind == "loading":
                spinner = NSProgressIndicator.alloc().initWithFrame_(
                    NSMakeRect(390, 18, 18, 18))
                spinner.setStyle_(NSProgressIndicatorStyleSpinning)
                spinner.startAnimation_(None)
                cell.addSubview_(spinner)
        return cell

    def selection_changed(self) -> None:
        row = int(self.table.selectedRow())
        if 0 <= row < len(self.rows):
            self._selected_key = self.row_key(self.rows[row])

    @staticmethod
    def row_is_actionable(row: dict[str, Any]) -> bool:
        return row.get("type") in ("finding", "rule", "project")

    def activate_clicked_row(self) -> None:
        row = int(self.table.clickedRow())
        if 0 <= row < len(self.rows) and self.row_is_actionable(self.rows[row]):
            self._activate_row(self.rows[row])

    def activate_selected_row(self) -> None:
        row = int(self.table.selectedRow())
        if 0 <= row < len(self.rows) and self.row_is_actionable(self.rows[row]):
            self._activate_row(self.rows[row])

    def _activate_row(self, model: dict[str, Any]) -> None:
        value = model.get("value") or {}
        if model.get("type") == "finding":
            self.controller.open_finding(value)
        elif model.get("type") == "rule":
            self.controller.edit_rule(value)
        elif model.get("type") == "project":
            self.controller.open_manage_rules(value.get("path", ""))

    def _health_copy(self, snapshot: UISnapshot):
        if snapshot.status == "loading":
            return "Connecting…", NSColor.secondaryLabelColor()
        if snapshot.status == "unavailable":
            return "Daemon unavailable", NSColor.systemRedColor()
        if snapshot.daemon.get("health") == "warming":
            return "Preparing local rules…", NSColor.systemOrangeColor()
        if snapshot.daemon.get("health") == "paused":
            return "Monitoring paused", NSColor.secondaryLabelColor()
        return "", NSColor.secondaryLabelColor()

    def render(
        self, snapshot: UISnapshot, max_height: float = POPOVER_MAX_HEIGHT
    ) -> tuple[NSView, tuple[float, float]]:
        self.snapshot = snapshot
        confirmation = getattr(self.controller, "confirmation", None)
        self.confirmation_view.setHidden_(not bool(confirmation))
        main_views = (
            self.title_label, self.status_label, self.project_popup,
            self.add_button, self.back_button, self.route_title,
            self.mode_control, self.search, self.scroll,
            self.navigation, self.more_button,
        )
        for view in main_views:
            view.setHidden_(bool(confirmation))
        if confirmation:
            self.confirmation_title.setStringValue_(
                confirmation.get("title", "Confirm change"))
            self.confirmation_message.setStringValue_(
                confirmation.get("message", ""))
            self.confirmation_action.setTitle_(
                confirmation.get("confirm_title", "Confirm"))
        else:
            self._sync_header()
            status, color = self._health_copy(snapshot)
            banner = str(getattr(self.controller, "banner", "") or "")
            self.status_label.setStringValue_(banner or status)
            self.status_label.setTextColor_(color)
            route = getattr(self.controller, "route", "inbox")
            mode = (
                getattr(self.controller, "inbox_mode", "open")
                if route == "inbox" else ""
            )
            state_key = f"{route}:{mode}"
            state = self._view_states.setdefault(state_key, {})
            selected_row = int(self.table.selectedRow())
            if 0 <= selected_row < len(self.rows):
                state["selected_key"] = self.row_key(self.rows[selected_row])
            bounds = self.scroll.contentView().bounds()
            visible_rows = self.table.rowsInRect_(bounds)
            top_index = int(visible_rows.location)
            if 0 <= top_index < len(self.rows):
                top_rect = self.table.rectOfRow_(top_index)
                state["top_key"] = self.row_key(self.rows[top_index])
                state["top_offset"] = float(
                    bounds.origin.y - top_rect.origin.y)
            for tag in self._row_tags:
                self._callbacks.pop(tag, None)
            self._row_tags.clear()
            self.rows = self._models()
            self.table.reloadData()
            selected_index = next(
                (i for i, row in enumerate(self.rows)
                 if self.row_key(row) == state.get("selected_key")),
                -1,
            )
            if selected_index >= 0:
                self.table.selectRowIndexes_byExtendingSelection_(
                    NSIndexSet.indexSetWithIndex_(selected_index), False)
            top_index = next(
                (i for i, row in enumerate(self.rows)
                 if self.row_key(row) == state.get("top_key")),
                -1,
            )
            if top_index >= 0:
                top_rect = self.table.rectOfRow_(top_index)
                self.scroll.contentView().scrollToPoint_((
                    0,
                    max(
                        0,
                        top_rect.origin.y
                        + float(state.get("top_offset", 0)),
                    ),
                ))
            self.scroll.reflectScrolledClipView_(self.scroll.contentView())
        content_height = sum(self.row_height(row) for row in self.rows)
        height = (
            min(max_height, max(450.0, self.root.frame().size.height))
            if confirmation
            else max(
                170.0,
                min(
                    max_height,
                    HEADER_HEIGHT + FOOTER_HEIGHT + max(60, content_height),
                ),
            )
        )
        self.root.setFrameSize_((POPOVER_WIDTH, height))
        self.scroll.setFrame_(NSMakeRect(
            0, HEADER_HEIGHT, POPOVER_WIDTH,
            max(40, height - HEADER_HEIGHT - FOOTER_HEIGHT)))
        available_height = max(
            40, height - HEADER_HEIGHT - FOOTER_HEIGHT)
        self.scroll.setHasVerticalScroller_(
            bool(content_height > available_height + 1))
        self.table_column.setWidth_(self.scroll.contentSize().width)
        footer_y = height - FOOTER_HEIGHT
        self.navigation.setFrameOrigin_((PAD, footer_y + 7))
        self.more_button.setFrameOrigin_((346, footer_y + 7))
        self.confirmation_view.setFrame_(self.root.bounds())
        self.confirmation_cancel.setFrameOrigin_((222, height - 48))
        self.confirmation_action.setFrameOrigin_((318, height - 48))
        return self.root, (POPOVER_WIDTH, height)

    def popup_menu(
        self,
        sender: Any,
        items: list[tuple[str, Callable[[], None], bool]],
    ) -> None:
        menu = NSMenu.alloc().initWithTitle_("Actions")
        self._menus.append(menu)
        tags = []
        for title, callback, enabled in items:
            if title == "-":
                menu.addItem_(NSMenuItem.separatorItem())
                continue
            tag = self._next_menu_tag
            self._next_menu_tag += 1
            self._menu_callbacks[tag] = callback
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, "invoke:", "")
            item.setTag_(tag)
            item.setTarget_(self._menu_target)
            item.setAction_("invoke:")
            item.setEnabled_(enabled)
            menu.addItem_(item)
            tags.append(tag)
        view = (
            sender if sender is not None
            else getattr(self.controller, "content_view", None)
        )
        if view is not None:
            try:
                menu.popUpMenuPositioningItem_atLocation_inView_(
                    None, (0, view.bounds().size.height), view)
            finally:
                for tag in tags:
                    self._menu_callbacks.pop(tag, None)
                try:
                    self._menus.remove(menu)
                except ValueError:
                    pass
