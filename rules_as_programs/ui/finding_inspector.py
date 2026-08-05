"""Minimal native Inspector that expands one tray finding."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import objc
from AppKit import (
    NSApplication,
    NSBackingStoreBuffered,
    NSButton,
    NSColor,
    NSFont,
    NSImageView,
    NSLayoutConstraint,
    NSLineBreakByTruncatingTail,
    NSMenu,
    NSMenuItem,
    NSPopUpButton,
    NSScrollView,
    NSSearchField,
    NSTableCellView,
    NSTableColumn,
    NSTableView,
    NSTextField,
    NSTextView,
    NSUserInterfaceLayoutOrientationHorizontal,
    NSUserInterfaceLayoutOrientationVertical,
    NSView,
    NSViewWidthSizable,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable,
    NSWindowStyleMaskResizable,
    NSWindowStyleMaskTitled,
    NSWindowTitleHidden,
    NSWorkspace,
)
from Foundation import NSMakeRect, NSMakeSize, NSObject
from PyObjCTools import AppHelper

from .. import config
from .finding_presenter import present_finding
from .macos_controls import (
    RAPCommandWindow,
    set_button_symbol,
    style_button,
    system_symbol,
)
from .model import UIModel


def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


def _activate(*constraints) -> None:
    NSLayoutConstraint.activateConstraints_(
        [constraint for constraint in constraints if constraint])


class RAPInspectorTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "callbacks", {}).get(int(sender.tag()))
        if callback:
            callback(sender)


class RAPContextAdapter(NSObject):
    owner = None

    def numberOfRowsInTableView_(self, _table):
        return len(self.owner.filtered_context_events())

    def tableView_heightOfRow_(self, _table, row):
        event = self.owner.filtered_context_events()[int(row)]
        if event.get("id") != self.owner.expanded_event_id:
            return 60
        text = str(event.get("text", ""))
        return min(340, max(96, 72 + (text.count("\n") + len(text) // 92) * 15))

    def tableView_viewForTableColumn_row_(self, table, _column, row):
        event = self.owner.filtered_context_events()[int(row)]
        cell = NSTableCellView.alloc().init()
        expanded = event.get("id") == self.owner.expanded_event_id
        timestamp = self.owner.event_time(event)
        markers = []
        if event.get("is_trigger"):
            markers.extend(["Trigger", "Rule input"])
        kind = str(event.get("kind", "event"))
        kind_label = self.owner.label(
            " · ".join([self.owner.event_label(kind), timestamp, *markers]),
            size=10, bold=True)
        text = str(event.get("text", ""))
        body = self.owner.label(
            text if expanded else text.replace("\n", " ")[:240],
            size=10.5, lines=0 if expanded else 2, selectable=expanded)
        kind_label.setTranslatesAutoresizingMaskIntoConstraints_(False)
        body.setTranslatesAutoresizingMaskIntoConstraints_(False)
        cell.addSubview_(kind_label)
        cell.addSubview_(body)
        _activate(
            kind_label.leadingAnchor().constraintEqualToAnchor_constant_(
                cell.leadingAnchor(), 18),
            kind_label.topAnchor().constraintEqualToAnchor_constant_(
                cell.topAnchor(), 8),
            kind_label.trailingAnchor().constraintEqualToAnchor_constant_(
                cell.trailingAnchor(), -12),
            body.leadingAnchor().constraintEqualToAnchor_(
                kind_label.leadingAnchor()),
            body.topAnchor().constraintEqualToAnchor_constant_(
                kind_label.bottomAnchor(), 3),
            body.trailingAnchor().constraintEqualToAnchor_constant_(
                cell.trailingAnchor(), -12),
            body.bottomAnchor().constraintLessThanOrEqualToAnchor_constant_(
                cell.bottomAnchor(), -8),
        )
        cell.setAccessibilityLabel_(
            f"{kind_label.stringValue()}, {text}")
        return cell

    def tableViewSelectionDidChange_(self, _notification):
        row = int(self.owner.context_table.selectedRow())
        events = self.owner.filtered_context_events()
        if 0 <= row < len(events):
            event_id = str(events[row].get("id", ""))
            self.owner.expanded_event_id = (
                "" if self.owner.expanded_event_id == event_id else event_id)
            self.owner.context_table.noteHeightOfRowsWithIndexesChanged_(
                self.owner.index_set(row))
            self.owner.context_table.reloadData()


class RAPFindingInspector(NSObject):
    def init(self):
        self = objc.super(RAPFindingInspector, self).init()
        if self is None:
            return None
        self.manager = None
        self.model = None
        self.detail: dict[str, Any] = {}
        self.presentation: dict[str, Any] = {}
        self.window = None
        self._callbacks: dict[int, Callable[[Any], None]] = {}
        self._target = RAPInspectorTarget.alloc().init()
        self._target.callbacks = self._callbacks
        self._next_tag = 1
        self._menus: list[NSMenu] = []
        self.page = "detail"
        self.expanded_event_id = ""
        self.included_event_ids: set[str] = set()
        return self

    @objc.python_method
    def configure(
        self,
        manager: "FindingInspectorManager",
        model: UIModel,
        detail: dict[str, Any],
    ) -> None:
        self.manager = manager
        self.model = model
        self.detail = detail
        self.presentation = present_finding(detail)
        self._build_window()
        self._build_content()
        self._refresh()

    @objc.python_method
    def _build_window(self) -> None:
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
            | NSWindowStyleMaskMiniaturizable
        )
        self.window = RAPCommandWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 760, 360), mask,
            NSBackingStoreBuffered, False)
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
        self.window.setContentMinSize_(NSMakeSize(640, 240))
        self.window.setTitle_("")
        self.window.setTitleVisibility_(NSWindowTitleHidden)
        self.window.setTitlebarAppearsTransparent_(True)

    @objc.python_method
    def _wire(self, control, callback):
        tag = self._next_tag
        self._next_tag += 1
        self._callbacks[tag] = callback
        control.setTag_(tag)
        control.setTarget_(self._target)
        control.setAction_("invoke:")
        return control

    @objc.python_method
    def button(
        self, title: str, callback: Callable[[Any], None], *, role="flat",
        accessibility: str | None = None,
    ) -> NSButton:
        button = NSButton.alloc().init()
        button.setTitle_(title)
        style_button(
            button, role=role,
            accessibility=accessibility or title.rstrip("…"))
        return self._wire(button, callback)

    @objc.python_method
    def icon_button(
        self, symbol: str, fallback: str, callback: Callable[[Any], None],
        accessibility: str,
    ) -> NSButton:
        button = self.button(
            "", callback, role="icon", accessibility=accessibility)
        set_button_symbol(
            button, symbol, accessibility, fallback=fallback,
            point_size=13, weight="medium")
        button.setToolTip_(accessibility)
        return button

    @staticmethod
    def label(
        text: str, *, size=11, bold=False, color=None,
        lines=1, selectable=False,
    ) -> NSTextField:
        label = NSTextField.labelWithString_(str(text))
        label.setFont_(
            NSFont.boldSystemFontOfSize_(size)
            if bold else NSFont.systemFontOfSize_(size))
        label.setTextColor_(color or NSColor.labelColor())
        label.setMaximumNumberOfLines_(lines)
        label.setSelectable_(selectable)
        if lines == 1:
            label.cell().setLineBreakMode_(NSLineBreakByTruncatingTail)
        else:
            label.cell().setWraps_(True)
            label.cell().setScrollable_(False)
            label.setContentCompressionResistancePriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
        return label

    @staticmethod
    def stack(views, *, vertical=False, spacing=8):
        from AppKit import NSStackView
        stack = NSStackView.stackViewWithViews_(list(views))
        stack.setOrientation_(
            NSUserInterfaceLayoutOrientationVertical
            if vertical else NSUserInterfaceLayoutOrientationHorizontal)
        stack.setSpacing_(spacing)
        stack.setTranslatesAutoresizingMaskIntoConstraints_(False)
        return stack

    @staticmethod
    def index_set(row: int):
        from Foundation import NSIndexSet
        return NSIndexSet.indexSetWithIndex_(row)

    @objc.python_method
    def _build_content(self) -> None:
        root = self.window.contentView()
        self.header = NSView.alloc().init()
        self.header.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.page_container = NSView.alloc().init()
        self.page_container.setTranslatesAutoresizingMaskIntoConstraints_(False)
        root.addSubview_(self.header)
        root.addSubview_(self.page_container)
        _activate(
            self.header.topAnchor().constraintEqualToAnchor_(root.topAnchor()),
            self.header.leadingAnchor().constraintEqualToAnchor_(
                root.leadingAnchor()),
            self.header.trailingAnchor().constraintEqualToAnchor_(
                root.trailingAnchor()),
            self.header.heightAnchor().constraintEqualToConstant_(82),
            self.page_container.topAnchor().constraintEqualToAnchor_(
                self.header.bottomAnchor()),
            self.page_container.leadingAnchor().constraintEqualToAnchor_(
                root.leadingAnchor()),
            self.page_container.trailingAnchor().constraintEqualToAnchor_(
                root.trailingAnchor()),
            self.page_container.bottomAnchor().constraintEqualToAnchor_(
                root.bottomAnchor()),
        )
        self._build_header()
        self._build_detail_page()
        self._build_context_page()

    @objc.python_method
    def _build_header(self) -> None:
        self.project_label = self.label(
            "", size=10, color=NSColor.secondaryLabelColor())
        self.project_label.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.severity_image = NSImageView.alloc().init()
        self.severity_image.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.rule_button = self.button(
            "", lambda _sender: self.edit_rule(),
            accessibility="Edit rule")
        self.rule_button.setFont_(NSFont.systemFontOfSize_weight_(13, 0.5))
        self.age_label = self.label(
            "", size=10, color=NSColor.secondaryLabelColor())
        self.edit_button = self.icon_button(
            "pencil", "Edit", lambda _sender: self.edit_rule(), "Edit rule")
        self.review_button = self.icon_button(
            "checkmark", "✓", lambda _sender: self.mark_reviewed(),
            "Mark reviewed")
        self.more_button = self.icon_button(
            "ellipsis", "…", lambda sender: self.show_artifacts(sender),
            "More finding actions")
        row = self.stack([
            self.severity_image,
            self.rule_button,
            NSView.alloc().init(),
            self.age_label,
            self.edit_button,
            self.review_button,
            self.more_button,
        ], spacing=7)
        self.header.addSubview_(self.project_label)
        self.header.addSubview_(row)
        _activate(
            self.project_label.topAnchor().constraintEqualToAnchor_constant_(
                self.header.topAnchor(), 12),
            self.project_label.leadingAnchor().constraintEqualToAnchor_constant_(
                self.header.leadingAnchor(), 18),
            self.project_label.trailingAnchor().constraintLessThanOrEqualToAnchor_(
                self.header.trailingAnchor()),
            row.topAnchor().constraintEqualToAnchor_constant_(
                self.project_label.bottomAnchor(), 5),
            row.leadingAnchor().constraintEqualToAnchor_constant_(
                self.header.leadingAnchor(), 18),
            row.trailingAnchor().constraintEqualToAnchor_constant_(
                self.header.trailingAnchor(), -14),
            self.severity_image.widthAnchor().constraintEqualToConstant_(17),
            self.severity_image.heightAnchor().constraintEqualToConstant_(17),
            self.edit_button.widthAnchor().constraintEqualToConstant_(28),
            self.review_button.widthAnchor().constraintEqualToConstant_(28),
            self.more_button.widthAnchor().constraintEqualToConstant_(28),
        )

    @objc.python_method
    def _build_detail_page(self) -> None:
        page = NSView.alloc().init()
        page.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.page_container.addSubview_(page)
        _activate(
            page.topAnchor().constraintEqualToAnchor_(
                self.page_container.topAnchor()),
            page.leadingAnchor().constraintEqualToAnchor_(
                self.page_container.leadingAnchor()),
            page.trailingAnchor().constraintEqualToAnchor_(
                self.page_container.trailingAnchor()),
            page.bottomAnchor().constraintEqualToAnchor_(
                self.page_container.bottomAnchor()),
        )
        self.detail_page = page
        self.input_heading = self.label("Input", size=11, bold=True)
        input_header = self.stack([
            self.input_heading, NSView.alloc().init()])
        scroll = NSScrollView.alloc().init()
        scroll.setHasVerticalScroller_(True)
        scroll.setAutohidesScrollers_(True)
        scroll.setDrawsBackground_(False)
        scroll.setBorderType_(0)
        scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        editor = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 760, 480))
        editor.setEditable_(False)
        editor.setSelectable_(True)
        editor.setRichText_(False)
        editor.setFont_(NSFont.monospacedSystemFontOfSize_weight_(11, 0))
        editor.setDrawsBackground_(True)
        editor.setBackgroundColor_(NSColor.textBackgroundColor())
        editor.setTextContainerInset_((12, 12))
        editor.setHorizontallyResizable_(False)
        editor.setVerticallyResizable_(True)
        editor.setAutoresizingMask_(NSViewWidthSizable)
        editor.setMinSize_(NSMakeSize(0, 0))
        editor.textContainer().setWidthTracksTextView_(True)
        editor.setAccessibilityLabel_("Exact rule input")
        scroll.setDocumentView_(editor)
        self.input_scroll = scroll
        self.input_view = editor
        self.context_button = self.button(
            "Session Activity  ›", lambda _sender: self.show_context(),
            accessibility="Open surrounding context")
        self.context_button.setFont_(NSFont.systemFontOfSize_weight_(11, 0.4))
        input_header.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.context_button.setTranslatesAutoresizingMaskIntoConstraints_(False)
        page.addSubview_(input_header)
        page.addSubview_(scroll)
        page.addSubview_(self.context_button)
        self.context_height = (
            self.context_button.heightAnchor().constraintEqualToConstant_(34))
        _activate(
            input_header.topAnchor().constraintEqualToAnchor_constant_(
                page.topAnchor(), 8),
            input_header.leadingAnchor().constraintEqualToAnchor_constant_(
                page.leadingAnchor(), 18),
            input_header.trailingAnchor().constraintEqualToAnchor_constant_(
                page.trailingAnchor(), -18),
            input_header.heightAnchor().constraintEqualToConstant_(30),
            scroll.topAnchor().constraintEqualToAnchor_constant_(
                input_header.bottomAnchor(), 4),
            scroll.leadingAnchor().constraintEqualToAnchor_constant_(
                page.leadingAnchor(), 18),
            scroll.trailingAnchor().constraintEqualToAnchor_constant_(
                page.trailingAnchor(), -18),
            scroll.bottomAnchor().constraintEqualToAnchor_constant_(
                self.context_button.topAnchor(), -6),
            self.context_button.leadingAnchor().constraintEqualToAnchor_constant_(
                page.leadingAnchor(), 12),
            self.context_button.trailingAnchor().constraintEqualToAnchor_constant_(
                page.trailingAnchor(), -12),
            self.context_button.bottomAnchor().constraintEqualToAnchor_constant_(
                page.bottomAnchor(), -8),
            self.context_height,
        )

    @objc.python_method
    def _build_context_page(self) -> None:
        page = NSView.alloc().init()
        page.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.page_container.addSubview_(page)
        _activate(
            page.topAnchor().constraintEqualToAnchor_(
                self.page_container.topAnchor()),
            page.leadingAnchor().constraintEqualToAnchor_(
                self.page_container.leadingAnchor()),
            page.trailingAnchor().constraintEqualToAnchor_(
                self.page_container.trailingAnchor()),
            page.bottomAnchor().constraintEqualToAnchor_(
                self.page_container.bottomAnchor()),
        )
        self.context_page = page
        self.back_button = self.button(
            "‹ Details", lambda _sender: self.show_detail())
        self.context_heading = self.label(
            "Session Activity", size=11, bold=True)
        self.context_explanation = self.label(
            "Only the highlighted trigger field was evaluated.",
            size=9.5, color=NSColor.secondaryLabelColor())
        self.context_explanation.setTranslatesAutoresizingMaskIntoConstraints_(
            False)
        self.context_search = NSSearchField.alloc().init()
        self.context_search.setPlaceholderString_("Search")
        self.context_search.setSendsSearchStringImmediately_(True)
        self._wire(self.context_search, lambda _sender: self.reload_context())
        self.context_filter = NSPopUpButton.alloc().init()
        self.context_filter.addItemsWithTitles_(
            ["All events", "Messages", "Shell", "Files", "Tools"])
        self._wire(self.context_filter, lambda _sender: self.reload_context())
        navigation = self.stack([
            self.back_button,
            self.context_heading,
            NSView.alloc().init(),
            self.context_search,
            self.context_filter,
        ])
        _activate(
            self.context_search.widthAnchor().constraintEqualToConstant_(220),
            self.context_filter.widthAnchor().constraintEqualToConstant_(120),
        )
        table = NSTableView.alloc().init()
        column = NSTableColumn.alloc().initWithIdentifier_("event")
        column.setTitle_("")
        table.addTableColumn_(column)
        table.setHeaderView_(None)
        table.setUsesAlternatingRowBackgroundColors_(False)
        table.setAllowsMultipleSelection_(False)
        table.setIntercellSpacing_((0, 0))
        adapter = RAPContextAdapter.alloc().init()
        adapter.owner = self
        table.setDataSource_(adapter)
        table.setDelegate_(adapter)
        context_scroll = NSScrollView.alloc().init()
        context_scroll.setDocumentView_(table)
        context_scroll.setHasVerticalScroller_(True)
        context_scroll.setAutohidesScrollers_(True)
        context_scroll.setDrawsBackground_(False)
        context_scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.context_table = table
        self.context_adapter = adapter
        self.context_scroll = context_scroll
        self.earlier_button = self.button(
            "Earlier", lambda _sender: self.page_context(-1))
        self.page_label = self.label(
            "", size=9.5, color=NSColor.secondaryLabelColor())
        self.later_button = self.button(
            "Later", lambda _sender: self.page_context(1))
        pager = self.stack([
            self.earlier_button, NSView.alloc().init(),
            self.page_label, NSView.alloc().init(), self.later_button])
        self.context_pager = pager
        page.addSubview_(navigation)
        page.addSubview_(self.context_explanation)
        page.addSubview_(context_scroll)
        page.addSubview_(pager)
        _activate(
            navigation.topAnchor().constraintEqualToAnchor_constant_(
                page.topAnchor(), 6),
            navigation.leadingAnchor().constraintEqualToAnchor_constant_(
                page.leadingAnchor(), 12),
            navigation.trailingAnchor().constraintEqualToAnchor_constant_(
                page.trailingAnchor(), -12),
            navigation.heightAnchor().constraintEqualToConstant_(34),
            self.context_explanation.topAnchor().constraintEqualToAnchor_(
                navigation.bottomAnchor()),
            self.context_explanation.leadingAnchor().constraintEqualToAnchor_constant_(
                page.leadingAnchor(), 18),
            self.context_explanation.trailingAnchor().constraintEqualToAnchor_constant_(
                page.trailingAnchor(), -18),
            self.context_explanation.heightAnchor().constraintEqualToConstant_(18),
            context_scroll.topAnchor().constraintEqualToAnchor_constant_(
                self.context_explanation.bottomAnchor(), 4),
            context_scroll.leadingAnchor().constraintEqualToAnchor_(
                page.leadingAnchor()),
            context_scroll.trailingAnchor().constraintEqualToAnchor_(
                page.trailingAnchor()),
            context_scroll.bottomAnchor().constraintEqualToAnchor_(
                pager.topAnchor()),
            pager.leadingAnchor().constraintEqualToAnchor_constant_(
                page.leadingAnchor(), 12),
            pager.trailingAnchor().constraintEqualToAnchor_constant_(
                page.trailingAnchor(), -12),
            pager.bottomAnchor().constraintEqualToAnchor_constant_(
                page.bottomAnchor(), -6),
            pager.heightAnchor().constraintEqualToConstant_(32),
        )
        page.setHidden_(True)

    @objc.python_method
    def _refresh(self) -> None:
        self.presentation = present_finding(self.detail)
        p = self.presentation
        self.project_label.setStringValue_(
            Path(p["project_root"]).name or p["project_root"])
        self.rule_button.setTitle_(p["rule_name"])
        self.age_label.setStringValue_(p["relative_time"])
        severity = p["severity"]
        symbol_name = {
            "critical": "exclamationmark.octagon.fill",
            "warn": "exclamationmark.triangle.fill",
            "info": "info.circle.fill",
        }.get(severity, "info.circle")
        self.severity_image.setImage_(system_symbol(
            symbol_name, severity.title(), point_size=14, weight="semibold"))
        self.severity_image.setContentTintColor_({
            "critical": NSColor.systemRedColor(),
            "warn": NSColor.systemOrangeColor(),
            "info": NSColor.systemBlueColor(),
        }.get(severity, NSColor.secondaryLabelColor()))
        self.included_event_ids = set(
            p["input"].get("event_ids") or [])
        self._refresh_input()
        additional = int(p.get("additional_activity_count", 0))
        self.context_button.setHidden_(additional == 0)
        self.context_height.setConstant_(34 if additional else 0)
        self.context_button.setTitle_(
            f"Session Activity · {additional} additional "
            f"event{'s' if additional != 1 else ''}  ›")
        self.reload_context()
        self._show_page(self.page)

    @objc.python_method
    def _refresh_input(self) -> None:
        p = self.presentation
        rendered = p["input_text"]
        self.input_view.setString_(rendered)
        self.input_heading.setStringValue_(p.get("input_label", "Input"))
        if p.get("input_typography") in ("monospace", "path"):
            self.input_view.setFont_(
                NSFont.monospacedSystemFontOfSize_weight_(11, 0))
        else:
            self.input_view.setFont_(NSFont.systemFontOfSize_(12))
        lines = max(1, rendered.count("\n") + len(rendered) // 88 + 1)
        input_height = max(70, min(320, lines * 17 + 24))
        activity_height = 40 if p.get("additional_activity_count") else 0
        self._detail_height = 82 + 42 + input_height + activity_height + 24
        if self.page == "detail":
            self.window.setContentSize_(NSMakeSize(
                max(640, self.window.contentView().frame().size.width),
                self._detail_height))

    @objc.python_method
    def _show_page(self, page: str) -> None:
        self.page = page
        self.detail_page.setHidden_(page != "detail")
        self.context_page.setHidden_(page != "context")

    @objc.python_method
    def show_context(self) -> None:
        self._show_page("context")
        self.window.setContentSize_(NSMakeSize(
            max(640, self.window.contentView().frame().size.width), 640))
        self.context_table.reloadData()

    @objc.python_method
    def show_detail(self) -> None:
        self._show_page("detail")
        self.window.setContentSize_(NSMakeSize(
            max(640, self.window.contentView().frame().size.width),
            getattr(self, "_detail_height", 320)))

    @objc.python_method
    def filtered_context_events(self) -> list[dict[str, Any]]:
        query = str(self.context_search.stringValue()).strip().lower()
        selected = str(self.context_filter.titleOfSelectedItem())
        out = []
        for event in self.presentation.get("context_events", []):
            kind = str(event.get("kind", "")).lower()
            allowed = (
                selected == "All events"
                or selected == "Messages" and kind == "message"
                or selected == "Shell" and "shell" in kind
                or selected == "Files" and "file" in kind
                or selected == "Tools" and "tool" in kind
            )
            searchable = f"{kind} {event.get('text', '')}".lower()
            if allowed and (not query or query in searchable):
                out.append(event)
        return out

    @objc.python_method
    def reload_context(self) -> None:
        ledger = self.detail.get("ledger") or {}
        start = int(ledger.get("start", 0))
        end = int(ledger.get("end", 0))
        total = int(ledger.get("total", 0))
        paged = bool(ledger.get("has_earlier") or ledger.get("has_later"))
        self.context_pager.setHidden_(not paged)
        self.page_label.setStringValue_(
            f"{start + 1 if total else 0}–{end} of {total}")
        self.earlier_button.setEnabled_(bool(ledger.get("has_earlier")))
        self.later_button.setEnabled_(bool(ledger.get("has_later")))
        self.context_table.reloadData()

    @staticmethod
    def event_time(event: dict[str, Any]) -> str:
        import datetime
        timestamp = float(event.get("ts", 0) or 0)
        return (
            datetime.datetime.fromtimestamp(timestamp).strftime("%-I:%M:%S %p")
            if timestamp else "")

    @staticmethod
    def event_label(kind: str) -> str:
        return {
            "user_prompt": "You",
            "message": "Agent",
            "thought": "Agent thought",
            "shell_exec": "Shell",
            "shell_attempt": "Shell attempt",
            "file_edit": "File edit",
            "tool_use": "Tool",
            "tool_result": "Tool result",
            "tool_failure": "Tool failure",
            "subagent_start": "Subagent task",
            "subagent_stop": "Subagent result",
        }.get(kind, kind.replace("_", " ").title())

    @objc.python_method
    def page_context(self, direction: int) -> None:
        ledger = self.detail.get("ledger") or {}
        start = (
            max(0, int(ledger.get("start", 0)) - 60)
            if direction < 0 else int(ledger.get("end", 0)))
        finding_id = int((self.detail.get("finding") or {}).get("id", 0))

        def complete(result):
            if result.get("ok"):
                _on_main(lambda: self._apply_context_page(result))

        self.model.query({
            "type": "ledger_window",
            "id": finding_id,
            "start": start,
            "limit": 60,
        }, complete)

    @objc.python_method
    def _apply_context_page(self, result: dict[str, Any]) -> None:
        self.detail["ledger"] = result.get("ledger") or {}
        self.presentation = present_finding(self.detail)
        self.expanded_event_id = ""
        self.reload_context()

    @objc.python_method
    def edit_rule(self) -> None:
        self.manager.edit_rule(self.detail)

    @objc.python_method
    def mark_reviewed(self) -> None:
        finding = self.detail.get("finding", {})

        def complete(result):
            if result.get("ok"):
                _on_main(lambda: self.window.close())

        self.model.perform({
            "type": "review",
            "fingerprint": finding.get("fingerprint", ""),
        }, complete)

    @objc.python_method
    def show_artifacts(self, sender) -> None:
        menu = NSMenu.alloc().initWithTitle_("Finding actions")
        self._menus.append(menu)
        for title, callback in (
            ("Evaluation Details", self.show_evaluation_details),
            ("Recorded Rule", self.show_recorded_rule),
            ("Copy Audit JSON", self.copy_audit_json),
            ("Copy Context JSONL", self.copy_context_jsonl),
            ("Open Audit Log", self.open_audit),
            ("Open Ledger", self.open_ledger),
        ):
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, "invoke:", "")
            self._wire(item, lambda _sender, fn=callback: fn())
            menu.addItem_(item)
        menu.popUpMenuPositioningItem_atLocation_inView_(
            None, (0, sender.bounds().size.height), sender)

    @objc.python_method
    def _show_text_window(self, title: str, text: str) -> None:
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
        )
        window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 760, 600), mask,
            NSBackingStoreBuffered, False)
        window.setTitle_(title)
        scroll = NSScrollView.alloc().initWithFrame_(window.contentView().bounds())
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(True)
        scroll.setAutoresizingMask_(18)
        view = NSTextView.alloc().initWithFrame_(scroll.bounds())
        view.setEditable_(False)
        view.setSelectable_(True)
        view.setFont_(NSFont.monospacedSystemFontOfSize_weight_(11, 0))
        view.setString_(text)
        scroll.setDocumentView_(view)
        window.contentView().addSubview_(scroll)
        window.makeKeyAndOrderFront_(None)
        self._artifact_window = window

    def show_evaluation_details(self):
        evaluation = json.loads(json.dumps(
            self.presentation["evaluation"], ensure_ascii=False))
        evaluation.get("input", {}).pop("text", None)
        evaluation.get("rule", {}).pop("source", None)
        evaluation["recorded_at"] = self.presentation["occurred_at"]
        self._show_text_window(
            "Evaluation Details",
            json.dumps(evaluation, indent=2, ensure_ascii=False))

    def show_recorded_rule(self):
        source = str(
            (self.presentation["evaluation"].get("rule") or {}).get(
                "source", ""))
        self._show_text_window("Recorded Rule", source)

    def copy_audit_json(self):
        self._copy(json.dumps(
            self.detail.get("audit") or {}, indent=2, ensure_ascii=False))

    def copy_context_jsonl(self):
        self._copy("\n".join(
            json.dumps(event, ensure_ascii=False)
            for event in self.presentation["context_events"]))

    @staticmethod
    def _copy(text: str) -> None:
        from AppKit import NSPasteboard, NSPasteboardTypeString
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(text, NSPasteboardTypeString)

    def open_audit(self):
        path = config.project_log_file(self.presentation["project_root"])
        if path.exists():
            NSWorkspace.sharedWorkspace().openFile_(str(path))

    def open_ledger(self):
        path = str((self.detail.get("ledger") or {}).get("path", ""))
        if path:
            NSWorkspace.sharedWorkspace().openFile_(path)

    @objc.python_method
    def show(self) -> None:
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        self.window.makeKeyAndOrderFront_(None)
        self.window.center()

    def windowWillClose_(self, _notification):
        if self.manager:
            self.manager.closed(self)


class FindingInspectorManager:
    def __init__(
        self,
        model: UIModel,
        edit_rule: Callable[[dict[str, Any]], None],
    ) -> None:
        self.model = model
        self._edit_rule = edit_rule
        self.inspectors: dict[int, RAPFindingInspector] = {}

    def open(self, detail: dict[str, Any]) -> None:
        finding_id = int((detail.get("finding") or {}).get("id", 0))
        inspector = self.inspectors.get(finding_id)
        if inspector is None:
            inspector = RAPFindingInspector.alloc().init()
            inspector.configure(self, self.model, detail)
            self.inspectors[finding_id] = inspector
        else:
            inspector.detail = detail
            inspector._refresh()
        inspector.show()

    def edit_rule(self, detail: dict[str, Any]) -> None:
        finding = detail.get("finding", {})
        evaluation = detail.get("evaluation") or {}
        current = detail.get("current_rule") or {}
        payload = {
            "id": finding.get("rule_id"),
            "project_root": finding.get("project_root"),
            "_finding_context": {
                "finding": finding,
                "evaluation": evaluation,
                "rule_changed": detail.get("rule_changed", False),
            },
        }
        if not current.get("definition"):
            source = str((evaluation.get("rule") or {}).get("source", ""))
            if not source:
                return
            payload["_recorded_source"] = source
        self._edit_rule(payload)

    def closed(self, inspector: RAPFindingInspector) -> None:
        for finding_id, value in list(self.inspectors.items()):
            if value is inspector:
                self.inspectors.pop(finding_id, None)
