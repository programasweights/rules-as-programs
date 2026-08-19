"""Native, filtered history for all rule evaluation outcomes."""

from __future__ import annotations

import datetime
import json
import threading
from typing import Any, Callable

import objc
from AppKit import (
    NSApplication,
    NSBackingStoreBuffered,
    NSButton,
    NSColor,
    NSFont,
    NSLayoutConstraint,
    NSLineBreakByTruncatingTail,
    NSPopUpButton,
    NSPasteboard,
    NSPasteboardTypeString,
    NSSearchField,
    NSScrollView,
    NSSegmentedControl,
    NSStackView,
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
    NSWorkspace,
)
from Foundation import NSMakeRect, NSMakeSize, NSObject
from PyObjCTools import AppHelper

from .macos_controls import RAPCommandWindow, style_button
from .model import UIModel


def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


def _activate(*constraints) -> None:
    NSLayoutConstraint.activateConstraints_(
        [constraint for constraint in constraints if constraint])


class RAPEvaluationTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "callbacks", {}).get(int(sender.tag()))
        if callback:
            callback(sender)


class RAPEvaluationAdapter(NSObject):
    owner = None

    def numberOfRowsInTableView_(self, _table):
        return len(self.owner.filtered_rows())

    def tableView_heightOfRow_(self, _table, _row):
        return 52

    def tableView_viewForTableColumn_row_(self, _table, _column, row):
        value = self.owner.filtered_rows()[int(row)]
        identifier = str(_column.identifier())
        if identifier == "time":
            text = datetime.datetime.fromtimestamp(
                float(value.get("timestamp", 0))).strftime("%-I:%M:%S %p")
            color = NSColor.secondaryLabelColor()
            bold = False
        elif identifier == "prediction":
            text = self.owner.result_title(value)
            color = self.owner.result_color(
                "ERROR" if value.get("status") == "failed"
                else str(value.get("result", "")))
            bold = True
        elif identifier == "latency":
            duration = value.get("duration_ms")
            text = f"{duration} ms" if duration is not None else ""
            color = NSColor.secondaryLabelColor()
            bold = False
        else:
            input_text = str((value.get("input") or {}).get("text") or "")
            error = self.owner.error_title(value)
            text = input_text.replace("\n", " ")[:220]
            if error:
                text += f"\n{error}"
            color = NSColor.labelColor()
            bold = False
        label = self.owner.label(text, size=10.5, bold=bold, color=color)
        label.setMaximumNumberOfLines_(2 if identifier == "input" else 1)
        label.cell().setLineBreakMode_(NSLineBreakByTruncatingTail)
        cell = NSTableCellView.alloc().init()
        label.setTranslatesAutoresizingMaskIntoConstraints_(False)
        cell.addSubview_(label)
        _activate(
            label.leadingAnchor().constraintEqualToAnchor_constant_(
                cell.leadingAnchor(), 8),
            label.trailingAnchor().constraintEqualToAnchor_constant_(
                cell.trailingAnchor(), -8),
            label.centerYAnchor().constraintEqualToAnchor_(
                cell.centerYAnchor()),
        )
        return cell

    def tableViewSelectionDidChange_(self, _notification):
        self.owner.selection_changed()


class RAPEvaluationHistory(NSObject):
    def init(self):
        self = objc.super(RAPEvaluationHistory, self).init()
        if self is None:
            return None
        self.manager = None
        self.model = None
        self.rule_id = ""
        self.rule_name = ""
        self.project_root = ""
        self.rows: list[dict[str, Any]] = []
        self.log_paths: list[str] = []
        self.show_raw = False
        self._filter_keys = ["all"]
        self._callbacks: dict[int, Callable[[Any], None]] = {}
        self._next_tag = 1
        self._target = RAPEvaluationTarget.alloc().init()
        self._target.callbacks = self._callbacks
        return self

    @objc.python_method
    def configure(
        self,
        manager: "EvaluationHistoryManager",
        model: UIModel,
        rule_id: str,
        rule_name: str,
        project_root: str,
    ) -> None:
        self.manager = manager
        self.model = model
        self.rule_id = rule_id
        self.rule_name = rule_name or rule_id
        self.project_root = project_root
        self._build()
        self.reload()

    @staticmethod
    def label(text, *, size=11, bold=False, color=None):
        value = NSTextField.labelWithString_(str(text))
        value.setFont_(
            NSFont.boldSystemFontOfSize_(size)
            if bold else NSFont.systemFontOfSize_(size))
        value.setTextColor_(color or NSColor.labelColor())
        return value

    @staticmethod
    def stack(views, *, vertical=False, spacing=8):
        stack = NSStackView.stackViewWithViews_(list(views))
        stack.setOrientation_(
            NSUserInterfaceLayoutOrientationVertical
            if vertical else NSUserInterfaceLayoutOrientationHorizontal)
        stack.setSpacing_(spacing)
        stack.setTranslatesAutoresizingMaskIntoConstraints_(False)
        return stack

    @staticmethod
    def result_color(result: str):
        return {
            "INFO": NSColor.systemBlueColor(),
            "WARNING": NSColor.systemOrangeColor(),
            "CRITICAL": NSColor.systemRedColor(),
            "ERROR": NSColor.systemRedColor(),
            "OK": NSColor.systemGreenColor(),
        }.get(result, NSColor.secondaryLabelColor())

    @staticmethod
    def error_title(value: dict[str, Any]) -> str:
        outcome = value.get("outcome") or {}
        code = str(outcome.get("error_code", ""))
        return {
            "invalid_output": "Invalid or empty PAW result",
            "inference_timeout": "Inference timed out",
            "input_too_large": "Input too large",
            "input_field_missing": "Input field unavailable",
            "runtime_exception": "Rule execution failed",
        }.get(code, str(outcome.get("error", "")) or "Evaluation failed")

    @classmethod
    def result_title(cls, value: dict[str, Any]) -> str:
        if value.get("status") == "failed":
            title = cls.error_title(value)
            return f"ERROR · {title}"
        return str(value.get("result") or "RUNNING")

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
    def _button(self, title, callback):
        button = NSButton.alloc().init()
        button.setTitle_(title)
        style_button(button, role="flat", accessibility=title.rstrip("…"))
        return self._wire(button, callback)

    @objc.python_method
    def _build(self) -> None:
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
            | NSWindowStyleMaskMiniaturizable
        )
        self.window = RAPCommandWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 780, 600), mask,
            NSBackingStoreBuffered, False)
        self.window.setTitle_("Evaluation History")
        self.window.setContentMinSize_(NSMakeSize(640, 440))
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
        root = self.window.contentView()

        self.title_label = self.label(
            self.rule_name, size=14, bold=True)
        self.filter = NSSegmentedControl.alloc().init()
        self.filter.setSegmentCount_(1)
        self.filter.setLabel_forSegment_("All", 0)
        self.filter.setSelectedSegment_(0)
        self._wire(self.filter, lambda _sender: self.reload_table())
        self.search = NSSearchField.alloc().init()
        self.search.setPlaceholderString_("Search inputs")
        self.search.setSendsSearchStringImmediately_(True)
        self._wire(self.search, lambda _sender: self.reload_table())
        header = self.stack([
            self.title_label, NSView.alloc().init(),
            self.filter, self.search,
        ])
        self.summary_label = self.label(
            "", size=9.5, color=NSColor.secondaryLabelColor())
        self.summary_label.setTranslatesAutoresizingMaskIntoConstraints_(False)
        _activate(self.search.widthAnchor().constraintEqualToConstant_(190))

        table = NSTableView.alloc().init()
        for identifier, title, width in (
            ("time", "Time", 92),
            ("prediction", "Prediction", 170),
            ("input", "Input", 416),
            ("latency", "Latency", 80),
        ):
            column = NSTableColumn.alloc().initWithIdentifier_(identifier)
            column.setTitle_(title)
            column.setWidth_(width)
            table.addTableColumn_(column)
        table.setAllowsMultipleSelection_(False)
        adapter = RAPEvaluationAdapter.alloc().init()
        adapter.owner = self
        table.setDataSource_(adapter)
        table.setDelegate_(adapter)
        table_scroll = NSScrollView.alloc().init()
        table_scroll.setDocumentView_(table)
        table_scroll.setHasVerticalScroller_(True)
        table_scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.table = table
        self.adapter = adapter

        detail_scroll = NSScrollView.alloc().init()
        detail_scroll.setHasVerticalScroller_(True)
        detail_scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        detail = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 760, 190))
        detail.setEditable_(False)
        detail.setSelectable_(True)
        detail.setFont_(NSFont.monospacedSystemFontOfSize_weight_(10.5, 0))
        detail.setAutoresizingMask_(NSViewWidthSizable)
        detail.setHorizontallyResizable_(False)
        detail.textContainer().setWidthTracksTextView_(True)
        detail_scroll.setDocumentView_(detail)
        self.detail = detail
        self.detail_scroll = detail_scroll

        self.open_log_button = self._button(
            "Open Raw JSONL", lambda _sender: self.open_raw_log())
        self.copy_input_button = self._button(
            "Copy Input", lambda _sender: self.copy_selected_input())
        self.raw_toggle_button = self._button(
            "Raw JSON", lambda _sender: self.toggle_raw())
        self.activity_button = self._button(
            "View Activity", lambda _sender: self.open_selected_finding())
        self.expected_output = NSPopUpButton.alloc().init()
        self.expected_output.addItemsWithTitles_(
            ["OK", "INFO", "WARNING", "CRITICAL"])
        self.add_case_button = self._button(
            "Save as test",
            lambda _sender: self.add_selected_validation_case())
        footer = self.stack([
            self.open_log_button,
            self.copy_input_button,
            self.raw_toggle_button,
            self.activity_button,
            NSView.alloc().init(),
            self.label(
                "Expected", size=9.5,
                color=NSColor.secondaryLabelColor()),
            self.expected_output,
            self.add_case_button,
        ])

        for view in (header, footer):
            root.addSubview_(view)
        root.addSubview_(self.summary_label)
        root.addSubview_(table_scroll)
        root.addSubview_(detail_scroll)
        _activate(
            header.topAnchor().constraintEqualToAnchor_constant_(
                root.topAnchor(), 14),
            header.leadingAnchor().constraintEqualToAnchor_constant_(
                root.leadingAnchor(), 16),
            header.trailingAnchor().constraintEqualToAnchor_constant_(
                root.trailingAnchor(), -16),
            header.heightAnchor().constraintEqualToConstant_(30),
            self.summary_label.topAnchor().constraintEqualToAnchor_constant_(
                header.bottomAnchor(), 2),
            self.summary_label.leadingAnchor().constraintEqualToAnchor_constant_(
                root.leadingAnchor(), 18),
            self.summary_label.trailingAnchor().constraintEqualToAnchor_constant_(
                root.trailingAnchor(), -18),
            self.summary_label.heightAnchor().constraintEqualToConstant_(18),
            table_scroll.topAnchor().constraintEqualToAnchor_constant_(
                self.summary_label.bottomAnchor(), 6),
            table_scroll.leadingAnchor().constraintEqualToAnchor_(
                root.leadingAnchor()),
            table_scroll.trailingAnchor().constraintEqualToAnchor_(
                root.trailingAnchor()),
            table_scroll.bottomAnchor().constraintEqualToAnchor_(
                detail_scroll.topAnchor()),
            detail_scroll.leadingAnchor().constraintEqualToAnchor_(
                root.leadingAnchor()),
            detail_scroll.trailingAnchor().constraintEqualToAnchor_(
                root.trailingAnchor()),
            detail_scroll.heightAnchor().constraintEqualToConstant_(190),
            detail_scroll.bottomAnchor().constraintEqualToAnchor_constant_(
                footer.topAnchor(), -8),
            footer.leadingAnchor().constraintEqualToAnchor_constant_(
                root.leadingAnchor(), 12),
            footer.trailingAnchor().constraintEqualToAnchor_constant_(
                root.trailingAnchor(), -12),
            footer.bottomAnchor().constraintEqualToAnchor_constant_(
                root.bottomAnchor(), -8),
            footer.heightAnchor().constraintEqualToConstant_(28),
        )

    @objc.python_method
    def reload(self) -> None:
        def completed(result):
            _on_main(lambda: self._apply(result))

        request = {
            "type": "evaluation_history",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "limit": 1000,
        }
        if hasattr(self.model, "query"):
            self.model.query(request, completed)
        else:
            self.model.perform(request, completed)

    @objc.python_method
    def _apply(self, result: dict[str, Any]) -> None:
        if result.get("ok"):
            self.rows = list(result.get("evaluations") or [])
            self.log_paths = list(result.get("log_paths") or [])
            ok_count = sum(
                1 for row in self.rows if row.get("result") == "OK")
            error_count = sum(
                1 for row in self.rows if row.get("status") == "failed")
            finding_count = sum(
                1 for row in self.rows
                if row.get("result") in ("INFO", "WARNING", "CRITICAL"))
            compiler = next(
                (
                    str((row.get("rule") or {}).get("compiler", ""))
                    for row in self.rows
                    if (row.get("rule") or {}).get("compiler") is not None
                ),
                "",
            )
            compiler_label = compiler or "server default"
            self.summary_label.setStringValue_(
                f"Last {len(self.rows)} · {ok_count} OK · "
                f"{finding_count} findings · {error_count} errors · "
                f"{compiler_label}")
            self._update_filters()
            self.reload_table()
        else:
            self.detail.setString_(
                result.get("error", "Evaluation history is unavailable."))

    @objc.python_method
    def filtered_rows(self) -> list[dict[str, Any]]:
        segment = int(self.filter.selectedSegment())
        key = (
            self._filter_keys[segment]
            if 0 <= segment < len(self._filter_keys) else "all")
        query = str(self.search.stringValue()).strip().lower()
        rows = []
        for row in self.rows:
            result = str(row.get("result", ""))
            status = str(row.get("status", ""))
            if key == "errors" and status != "failed":
                continue
            if key not in ("all", "errors") and result != key:
                continue
            searchable = (
                f"{result} {(row.get('input') or {}).get('text', '')} "
                f"{(row.get('outcome') or {}).get('error', '')}").lower()
            if query and query not in searchable:
                continue
            rows.append(row)
        return rows

    @objc.python_method
    def _update_filters(self) -> None:
        counts = {
            level: sum(
                1 for row in self.rows if row.get("result") == level)
            for level in ("OK", "INFO", "WARNING", "CRITICAL")
        }
        errors = sum(
            1 for row in self.rows if row.get("status") == "failed")
        entries = [("all", f"All {len(self.rows)}")]
        entries.extend(
            (level, f"{level} {counts[level]}")
            for level in ("OK", "INFO", "WARNING", "CRITICAL")
            if counts[level]
        )
        if errors:
            entries.append(("errors", f"Errors {errors}"))
        self._filter_keys = [key for key, _label in entries]
        self.filter.setSegmentCount_(len(entries))
        for index, (_key, label) in enumerate(entries):
            self.filter.setLabel_forSegment_(label, index)
        self.filter.setSelectedSegment_(0)

    @objc.python_method
    def reload_table(self) -> None:
        self.table.reloadData()
        if self.filtered_rows():
            from Foundation import NSIndexSet
            self.table.selectRowIndexes_byExtendingSelection_(
                NSIndexSet.indexSetWithIndex_(0), False)
            self.selection_changed()
        else:
            self.detail.setString_(
                "No evaluations match this filter.")

    @objc.python_method
    def selection_changed(self) -> None:
        row = int(self.table.selectedRow())
        rows = self.filtered_rows()
        if not 0 <= row < len(rows):
            return
        value = rows[row]
        self.selected_evaluation = value
        expected = str(value.get("expected", ""))
        if expected:
            self.expected_output.selectItemWithTitle_(expected)
            self.add_case_button.setTitle_("Saved test")
        else:
            self.expected_output.selectItemWithTitle_(
                str(value.get("result") or "OK")
                if str(value.get("result") or "") in (
                    "OK", "INFO", "WARNING", "CRITICAL")
                else "OK")
            self.add_case_button.setTitle_("Save as test")
        self.activity_button.setEnabled_(bool(value.get("finding_id")))
        self._render_selected_detail()

    @objc.python_method
    def _render_selected_detail(self) -> None:
        value = getattr(self, "selected_evaluation", None)
        if not value:
            return
        outcome = value.get("outcome") or {}
        rendered = {
            "evaluation_id": value.get("evaluation_id"),
            "timestamp": value.get("timestamp"),
            "status": value.get("status"),
            "result": value.get("result"),
            "duration_ms": value.get("duration_ms"),
            "finding_id": value.get("finding_id"),
            "rule": value.get("rule"),
            "trigger": value.get("trigger"),
            "input": value.get("input"),
            "error_code": outcome.get("error_code"),
            "error": outcome.get("error"),
        }
        if self.show_raw:
            self.detail.setFont_(
                NSFont.monospacedSystemFontOfSize_weight_(10.5, 0))
            text = json.dumps(rendered, indent=2, ensure_ascii=False)
        else:
            input_text = str((value.get("input") or {}).get("text") or "")
            rule = value.get("rule") or {}
            trigger = value.get("trigger") or {}
            duration = value.get("duration_ms")
            lines = [
                self.result_title(value)
                + (f" · {duration} ms" if duration is not None else ""),
            ]
            error = self.error_title(value) if value.get(
                "status") == "failed" else ""
            if error:
                lines.extend(["", error])
            lines.extend(["", "INPUT", input_text or "(no input)"])
            if value.get("expected"):
                lines.extend([
                    "", "EXPECTED RESULT", str(value.get("expected"))])
            lines.extend([
                "", "PREDICTION", str(value.get("result") or "(no result)"),
                "", "TRIGGER",
                f"{trigger.get('hook', '')} · {trigger.get('event_id', '')}",
                "", "RULE VERSION",
                str(rule.get("compiler") or "Server default"),
                f"Source {str(rule.get('source_hash', ''))[:16]}",
                f"Program {rule.get('program_id', '')}",
            ])
            text = "\n".join(lines)
            self.detail.setFont_(NSFont.systemFontOfSize_(11.5))
        self.detail.setString_(text)

    @objc.python_method
    def toggle_raw(self) -> None:
        self.show_raw = not self.show_raw
        self.raw_toggle_button.setTitle_(
            "Summary" if self.show_raw else "Raw JSON")
        self._render_selected_detail()

    @objc.python_method
    def copy_selected_input(self) -> None:
        value = getattr(self, "selected_evaluation", None) or {}
        text = str((value.get("input") or {}).get("text") or "")
        if not text:
            return
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(text, NSPasteboardTypeString)
        self.copy_input_button.setTitle_("Copied ✓")

        def reset():
            _on_main(lambda: self.copy_input_button.setTitle_("Copy Input"))

        timer = threading.Timer(1.0, reset)
        timer.daemon = True
        timer.start()

    @objc.python_method
    def open_selected_finding(self) -> None:
        value = getattr(self, "selected_evaluation", None) or {}
        finding_id = value.get("finding_id")
        if finding_id and self.manager:
            self.manager.open_finding(int(finding_id))

    @objc.python_method
    def open_raw_log(self) -> None:
        path = next(
            (path for path in self.log_paths if path), "")
        if path:
            NSWorkspace.sharedWorkspace().openFile_(path)

    @objc.python_method
    def add_selected_validation_case(self) -> None:
        row = int(self.table.selectedRow())
        rows = self.filtered_rows()
        if not 0 <= row < len(rows):
            return
        input_text = str((rows[row].get("input") or {}).get("text") or "")
        if not input_text:
            return

        def completed(result):
            def apply():
                if result.get("ok"):
                    value = getattr(self, "selected_evaluation", None)
                    expected = str(
                        self.expected_output.titleOfSelectedItem())
                    if value is not None:
                        value["expected"] = expected
                    self.add_case_button.setTitle_("Saved test ✓")
                    self.detail.setString_(
                        "Added this observed input as a validation case with "
                        f"expected result {expected}.")
                    self.table.reloadData()
                    if self.manager:
                        self.manager.case_added(
                            self.rule_id, self.project_root)
                else:
                    self.detail.setString_(
                        result.get("error", "Could not add validation case."))
            _on_main(apply)

        self.model.perform({
            "type": "add_validation_case",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "input": input_text,
            "expected": str(self.expected_output.titleOfSelectedItem()),
        }, completed)

    @objc.python_method
    def show(self) -> None:
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        self.window.center()
        self.window.makeKeyAndOrderFront_(None)

    def windowWillClose_(self, _notification):
        if self.manager:
            self.manager.closed(self)


class EvaluationHistoryManager:
    def __init__(
        self,
        model: UIModel,
        open_finding: Callable[[int], None] | None = None,
        on_case_added: Callable[[str, str], None] | None = None,
    ) -> None:
        self.model = model
        self._open_finding = open_finding
        self._on_case_added = on_case_added
        self.windows: dict[tuple[str, str], RAPEvaluationHistory] = {}

    def open(
        self,
        rule_id: str,
        rule_name: str,
        project_root: str,
    ) -> None:
        key = (project_root, rule_id)
        window = self.windows.get(key)
        if window is None:
            window = RAPEvaluationHistory.alloc().init()
            window.configure(
                self, self.model, rule_id, rule_name, project_root)
            self.windows[key] = window
        else:
            window.reload()
        window.show()

    def closed(self, window: RAPEvaluationHistory) -> None:
        for key, value in list(self.windows.items()):
            if value is window:
                self.windows.pop(key, None)

    def open_finding(self, finding_id: int) -> None:
        if self._open_finding:
            self._open_finding(finding_id)

    def case_added(self, rule_id: str, project_root: str) -> None:
        if self._on_case_added:
            self._on_case_added(rule_id, project_root)
