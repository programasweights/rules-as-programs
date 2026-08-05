"""Evidence-first native Inspector for one finding."""

from __future__ import annotations

import json
import math
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import objc
from AppKit import (
    NSApplication,
    NSBackingStoreBuffered,
    NSButton,
    NSColor,
    NSEventModifierFlagCommand,
    NSEventModifierFlagControl,
    NSEventModifierFlagOption,
    NSEventModifierFlagShift,
    NSFont,
    NSMenu,
    NSMenuItem,
    NSLineBreakByTruncatingTail,
    NSPasteboard,
    NSPasteboardTypeString,
    NSPopUpButton,
    NSScrollView,
    NSSearchField,
    NSSegmentedControl,
    NSStackView,
    NSTextField,
    NSTextFinderActionShowFindInterface,
    NSTextView,
    NSUserInterfaceLayoutOrientationHorizontal,
    NSUserInterfaceLayoutOrientationVertical,
    NSView,
    NSViewController,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable,
    NSWindowStyleMaskResizable,
    NSWindowStyleMaskTitled,
    NSWorkspace,
)
from Foundation import NSMakeRect, NSMakeSize, NSObject
from PyObjCTools import AppHelper

from .. import config
from .finding_presenter import present_finding
from .macos_controls import ButtonRole, RAPCommandWindow, style_button
from .model import UIModel


def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


def _wrapped_line_count(text: str, columns: int = 82) -> int:
    count = 0
    for line in str(text or "").split("\n"):
        units = 0
        for character in line:
            if character == "\t":
                units += 4
            elif unicodedata.combining(character):
                continue
            else:
                units += (
                    2 if unicodedata.east_asian_width(character) in ("W", "F")
                    else 1)
        count += max(1, math.ceil(units / columns))
    return max(1, count)


class RAPInspectorTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "callbacks", {}).get(int(sender.tag()))
        if callback:
            callback(sender)


class RAPInspectorWindow(RAPCommandWindow):
    _rap_owner = None

    def performKeyEquivalent_(self, event):
        chars = str(event.charactersIgnoringModifiers() or "").lower()
        modifiers = int(event.modifierFlags())
        blocked = (
            NSEventModifierFlagControl
            | NSEventModifierFlagOption
            | NSEventModifierFlagShift
        )
        if (
            chars == "f"
            and modifiers & NSEventModifierFlagCommand
            and not modifiers & blocked
        ):
            owner = getattr(self, "_rap_owner", None)
            if owner:
                if owner.context_expanded:
                    self.makeFirstResponder_(owner.context_search)
                else:
                    self.makeFirstResponder_(owner.input_view)
                    sender = NSMenuItem.alloc().init()
                    sender.setTag_(NSTextFinderActionShowFindInterface)
                    owner.input_view.performTextFinderAction_(sender)
                return True
        return objc.super(RAPInspectorWindow, self).performKeyEquivalent_(event)


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
        self.input_mode = 0
        self.context_expanded = False
        self._context_built = False
        self._menus: list[NSMenu] = []
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
        self.window = RAPInspectorWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 760, 700), mask,
            NSBackingStoreBuffered, False)
        self.window._rap_owner = self
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
        self.window.setContentMinSize_(NSMakeSize(650, 520))

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
    def _button(
        self,
        title: str,
        callback: Callable[[Any], None],
        *,
        role: ButtonRole = "secondary",
        accessibility: str | None = None,
    ) -> NSButton:
        button = NSButton.alloc().init()
        button.setTitle_(title)
        style_button(
            button, role=role,
            accessibility=accessibility or title.rstrip("…"))
        return self._wire(button, callback)

    @staticmethod
    def _label(
        text: str,
        *,
        size: float = 11,
        bold: bool = False,
        color=None,
        lines: int = 1,
        selectable: bool = False,
    ) -> NSTextField:
        label = NSTextField.labelWithString_(str(text))
        label.setFont_(
            NSFont.boldSystemFontOfSize_(size)
            if bold else NSFont.systemFontOfSize_(size))
        label.setTextColor_(color or NSColor.labelColor())
        label.setMaximumNumberOfLines_(lines)
        label.setSelectable_(selectable)
        if lines != 1:
            label.cell().setWraps_(True)
            label.cell().setScrollable_(False)
            label.setPreferredMaxLayoutWidth_(680)
            label.setContentCompressionResistancePriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
            label.setContentHuggingPriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
        else:
            label.cell().setLineBreakMode_(NSLineBreakByTruncatingTail)
        return label

    @staticmethod
    def _stack(views, *, vertical=True, spacing=8) -> NSStackView:
        stack = NSStackView.stackViewWithViews_(list(views))
        stack.setOrientation_(
            NSUserInterfaceLayoutOrientationVertical
            if vertical else NSUserInterfaceLayoutOrientationHorizontal)
        stack.setSpacing_(spacing)
        stack.setTranslatesAutoresizingMaskIntoConstraints_(False)
        return stack

    @staticmethod
    def _activate(*constraints) -> None:
        from AppKit import NSLayoutConstraint
        NSLayoutConstraint.activateConstraints_(
            [constraint for constraint in constraints if constraint])

    @objc.python_method
    def _read_only_text(
        self, text: str, *, label: str, minimum_height: float = 120
    ) -> NSTextView:
        view = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 700, minimum_height))
        view.setEditable_(False)
        view.setSelectable_(True)
        view.setRichText_(False)
        view.setFont_(NSFont.monospacedSystemFontOfSize_weight_(11, 0))
        view.setDrawsBackground_(True)
        view.setBackgroundColor_(NSColor.controlBackgroundColor())
        view.setTextContainerInset_((8, 8))
        view.setHorizontallyResizable_(False)
        view.setVerticallyResizable_(True)
        view.textContainer().setWidthTracksTextView_(True)
        view.setString_(text)
        view.setAccessibilityLabel_(label)
        view.setTranslatesAutoresizingMaskIntoConstraints_(False)
        line_count = max(4, min(18, _wrapped_line_count(text)))
        height = view.heightAnchor().constraintEqualToConstant_(
            max(minimum_height, line_count * 17 + 20))
        self._activate(height)
        if label == "Evaluated input":
            self.input_height_constraint = height
        return view

    @objc.python_method
    def _build_content(self) -> None:
        root = self.window.contentView()
        header = NSView.alloc().init()
        header.setTranslatesAutoresizingMaskIntoConstraints_(False)
        scroll = NSScrollView.alloc().init()
        scroll.setHasVerticalScroller_(True)
        scroll.setAutohidesScrollers_(True)
        scroll.setDrawsBackground_(False)
        scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        root.addSubview_(header)
        root.addSubview_(scroll)
        self._activate(
            header.topAnchor().constraintEqualToAnchor_(root.topAnchor()),
            header.leadingAnchor().constraintEqualToAnchor_(root.leadingAnchor()),
            header.trailingAnchor().constraintEqualToAnchor_(root.trailingAnchor()),
            header.heightAnchor().constraintEqualToConstant_(82),
            scroll.topAnchor().constraintEqualToAnchor_(header.bottomAnchor()),
            scroll.leadingAnchor().constraintEqualToAnchor_(root.leadingAnchor()),
            scroll.trailingAnchor().constraintEqualToAnchor_(root.trailingAnchor()),
            scroll.bottomAnchor().constraintEqualToAnchor_(root.bottomAnchor()),
        )

        self.rule_button = self._button(
            "", lambda _sender: self.edit_rule(), role="flat",
            accessibility="Edit rule")
        self.rule_button.setFont_(NSFont.boldSystemFontOfSize_(17))
        self.meta_label = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=2)
        self.review_button = self._button(
            "Mark Reviewed", lambda _sender: self.mark_reviewed(),
            role="primary")
        self.artifacts_button = self._button(
            "More…", lambda sender: self.show_artifacts(sender), role="flat")
        title_stack = self._stack(
            [self.rule_button, self.meta_label],
            vertical=True, spacing=2)
        self._activate(
            title_stack.widthAnchor().constraintLessThanOrEqualToConstant_(430))
        header_stack = self._stack(
            [
                title_stack,
                NSView.alloc().init(),
                self.artifacts_button,
                self.review_button,
            ],
            vertical=False, spacing=10,
        )
        header.addSubview_(header_stack)
        self._activate(
            header_stack.leadingAnchor().constraintEqualToAnchor_constant_(
                header.leadingAnchor(), 18),
            header_stack.trailingAnchor().constraintEqualToAnchor_constant_(
                header.trailingAnchor(), -18),
            header_stack.centerYAnchor().constraintEqualToAnchor_(
                header.centerYAnchor()),
        )

        document = NSView.alloc().init()
        document.setTranslatesAutoresizingMaskIntoConstraints_(False)
        scroll.setDocumentView_(document)
        content = self._stack([], vertical=True, spacing=12)
        document.addSubview_(content)
        self._activate(
            document.topAnchor().constraintEqualToAnchor_(
                scroll.contentView().topAnchor()),
            document.leadingAnchor().constraintEqualToAnchor_(
                scroll.contentView().leadingAnchor()),
            document.widthAnchor().constraintEqualToAnchor_(
                scroll.contentView().widthAnchor()),
            content.topAnchor().constraintEqualToAnchor_constant_(
                document.topAnchor(), 18),
            content.leadingAnchor().constraintEqualToAnchor_constant_(
                document.leadingAnchor(), 20),
            content.trailingAnchor().constraintEqualToAnchor_constant_(
                document.trailingAnchor(), -20),
            content.bottomAnchor().constraintEqualToAnchor_constant_(
                document.bottomAnchor(), -24),
        )
        self.scroll = scroll
        self.content_stack = content

        content.addArrangedSubview_(self._label(
            "Finding", size=12, bold=True))
        self.finding_label = self._label(
            "", size=12, lines=4, selectable=True)
        self.finding_label.setAccessibilityLabel_("Finding")
        content.addArrangedSubview_(self.finding_label)

        input_heading = self._stack([], vertical=False, spacing=8)
        self.input_heading_label = self._label(
            "Input evaluated", size=12, bold=True)
        input_heading.addArrangedSubview_(self.input_heading_label)
        input_heading.addArrangedSubview_(NSView.alloc().init())
        self.input_mode_control = NSSegmentedControl.alloc().init()
        self.input_mode_control.setSegmentCount_(2)
        self.input_mode_control.setLabel_forSegment_("Structured", 0)
        self.input_mode_control.setLabel_forSegment_("Exact Text", 1)
        self.input_mode_control.setSelectedSegment_(0)
        self._wire(
            self.input_mode_control,
            lambda sender: self.set_input_mode(int(sender.selectedSegment())))
        input_heading.addArrangedSubview_(self.input_mode_control)
        self.copy_input_button = self._button(
            "Copy Input", lambda _sender: self.copy_exact_input(), role="flat")
        input_heading.addArrangedSubview_(self.copy_input_button)
        content.addArrangedSubview_(input_heading)
        self.input_status = self._label(
            "", size=9.5, color=NSColor.secondaryLabelColor(), lines=2)
        content.addArrangedSubview_(self.input_status)
        self.input_view = self._read_only_text(
            "", label="Evaluated input", minimum_height=180)
        content.addArrangedSubview_(self.input_view)

        content.addArrangedSubview_(self._label(
            "Output", size=12, bold=True))
        self.output_label = self._label(
            "", size=11, lines=3, selectable=True)
        self.output_label.setAccessibilityLabel_("Rule output")
        content.addArrangedSubview_(self.output_label)

        self.context_button = self._button(
            "Show Full Context",
            lambda _sender: self.toggle_context(),
            role="flat")
        content.addArrangedSubview_(self.context_button)
        self.context_preview = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(),
            lines=6, selectable=True)
        self.context_preview.setAccessibilityLabel_("Context preview")
        content.addArrangedSubview_(self.context_preview)
        self.context_earlier = self._button(
            "Earlier", lambda _sender: self.page_context(-1), role="flat")
        self.context_later = self._button(
            "Later", lambda _sender: self.page_context(1), role="flat")
        self.context_page_label = self._label(
            "", size=9.5, color=NSColor.secondaryLabelColor())
        self.context_search = NSSearchField.alloc().init()
        self.context_search.setPlaceholderString_("Search context")
        self.context_search.setAccessibilityLabel_("Search context")
        self.context_search.setSendsSearchStringImmediately_(True)
        self._wire(
            self.context_search,
            lambda _sender: self._rebuild_context())
        self.context_filter = NSPopUpButton.alloc().init()
        self.context_filter.addItemsWithTitles_(
            ["All events", "Messages", "Shell", "Files", "Tools"])
        self.context_filter.setAccessibilityLabel_("Filter context event type")
        self._wire(
            self.context_filter,
            lambda _sender: self._rebuild_context())
        self.context_navigation = self._stack([
            self.context_earlier,
            self.context_page_label,
            self.context_later,
            self.context_filter,
            self.context_search,
            NSView.alloc().init(),
        ], vertical=False, spacing=8)
        self.context_navigation.setHidden_(True)
        content.addArrangedSubview_(self.context_navigation)
        self.context_stack = self._stack([], vertical=True, spacing=6)
        self.context_stack.setAccessibilityLabel_("Full context")
        self.context_stack.setHidden_(True)
        content.addArrangedSubview_(self.context_stack)
        key_views = [
            self.rule_button,
            self.artifacts_button,
            self.review_button,
            self.input_mode_control,
            self.copy_input_button,
            self.input_view,
            self.context_button,
        ]
        for current, following in zip(
            key_views, key_views[1:] + key_views[:1]
        ):
            current.setNextKeyView_(following)
        self.window.setInitialFirstResponder_(self.rule_button)

    @objc.python_method
    def _refresh(self) -> None:
        self.presentation = present_finding(self.detail)
        p = self.presentation
        self.window.setTitle_(p["rule_name"])
        self.rule_button.setTitle_(p["rule_name"])
        lifecycle = (
            " · Rule deleted" if p["rule_deleted"]
            else " · Rule changed" if p["rule_changed"] else "")
        recorded_time = (
            datetime.fromtimestamp(p["occurred_at"]).astimezone().strftime(
                "%b %-d, %Y at %-I:%M:%S %p %Z")
            if p["occurred_at"] else "Time unavailable")
        self.meta_label.setStringValue_(
            f"{p['severity'].title()} · {Path(p['project_root']).name} · "
            f"{recorded_time} · {p['occurrences']} occurrence(s){lifecycle}")
        self.finding_label.setStringValue_(p["finding_message"])
        complete = bool(p["input"].get("recording_complete"))
        reason = str(p["input"].get("truncation_reason", ""))
        chars = int(
            (
                p["input"].get("char_count")
                if complete else
                p["input"].get("recorded_char_count")
            )
            or len(p["input_text"])
            or 0)
        digest = str(p["input"].get("sha256", ""))
        no_universal_input = reason in (
            "no_universal_deterministic_input", "untraced_fuzzy_input")
        input_role = str(p["input"].get("role", "evaluated_input"))
        self.input_heading_label.setStringValue_(
            "Recorded rule evidence"
            if input_role in ("recorded_evidence", "unavailable") else
            "Recorded input (legacy)"
            if input_role == "legacy_recording" else
            "Last PAW call input"
            if input_role == "unattributed_paw_call" else
            "Input evaluated")
        if no_universal_input:
            status = (
                "This fuzzy call bypassed ctx.paw, so its evaluated input "
                "was not observable."
                if reason == "untraced_fuzzy_input" else
                "No universal input exists for this deterministic Python rule.")
        else:
            status = (
                f"Complete recorded input · {chars} characters"
                if complete else
                f"Recorded input is incomplete · {chars} recorded characters")
            if reason == "rule_input_limit":
                status += " · Input was bounded before evaluation"
            if reason == "unattributed_paw_call":
                status += " · This finding could not be attributed to one PAW call"
            if p["input"].get("source_mapping_available") is False:
                status += " · Source mapping unavailable"
            if digest:
                status += f" · {digest[:12]}"
        self.input_status.setStringValue_(status)
        self.copy_input_button.setEnabled_(bool(p["input_text"]))
        self._refresh_input()
        evaluator = (
            "PAW fuzzy rule"
            if p["evaluation_kind"] == "paw"
            else "Composite Python and PAW rule"
            if p["evaluation_kind"] == "composite"
            else "Untraced fuzzy/Python rule"
            if p["evaluation_kind"] == "untraced_fuzzy"
            else "Evaluator unknown (legacy record)"
            if p["evaluation_kind"] == "legacy_unknown"
            else "Deterministic Python rule")
        raw = p["output_raw"] or "(no PAW output)"
        output_complete = bool(
            ((self.detail.get("evaluation") or {}).get("output") or {}).get(
                "recording_complete", True))
        self.output_label.setStringValue_(
            f"Rule output{' (recorded output is incomplete)' if not output_complete else ''}: "
            f"{raw}\n"
            f"Surfaced as: {p['output_severity'].title()} · {evaluator}")
        self.context_preview.setStringValue_(
            self._format_events(p["context_preview"]))
        self._context_built = False
        if self.context_expanded:
            self._rebuild_context()
        self._refresh_context_navigation()
        self.review_button.setHidden_(
            bool((self.detail.get("finding") or {}).get("acknowledged")))
        deleted_source_unavailable = (
            p["rule_deleted"]
            and not p["rule_editable"]
            and not p["recorded_source_complete"])
        self.rule_button.setTitle_(
            "Recorded Rule Source Unavailable"
            if deleted_source_unavailable else
            "Create Draft from Recorded Rule…"
            if p["rule_deleted"] and not p["rule_editable"]
            else p["rule_name"])
        self.rule_button.setEnabled_(not deleted_source_unavailable)

    @objc.python_method
    def _refresh_input(self) -> None:
        p = self.presentation
        exact = p["input_text"]
        if self.input_mode == 1:
            rendered = exact
        elif p["input_sections"]:
            rendered = "\n\n".join(
                f"{section['label']} · Included in evaluation\n"
                f"{section['text']}"
                for section in p["input_sections"])
        else:
            rendered = p["input_presentation"].formatted
        self.input_view.setString_(rendered)
        line_count = max(4, _wrapped_line_count(rendered))
        self.input_height_constraint.setConstant_(
            max(180, min(12000, line_count * 17 + 20)))

    @staticmethod
    def _format_events(events: list[dict[str, Any]]) -> str:
        rows = []
        for event in events:
            marker = "Trigger · " if event.get("is_trigger") else ""
            rows.append(
                f"{marker}{event.get('kind', 'event')}: "
                f"{str(event.get('text', ''))[:240]}"
                + ("…" if len(str(event.get("text", ""))) > 240 else ""))
        return "\n".join(rows) or "(no recorded context)"

    @objc.python_method
    def _rebuild_context(self) -> None:
        for view in list(self.context_stack.arrangedSubviews()):
            self.context_stack.removeArrangedSubview_(view)
            view.removeFromSuperview()
        included_ids = set(
            (self.detail.get("evaluation") or {}).get(
                "input", {}).get("event_ids") or [])
        query = str(self.context_search.stringValue()).strip().lower()
        selected_filter = str(self.context_filter.titleOfSelectedItem())
        for event in self.presentation["context_events"]:
            kind = str(event.get("kind", "")).lower()
            allowed = (
                selected_filter == "All events"
                or selected_filter == "Messages" and kind == "message"
                or selected_filter == "Shell" and "shell" in kind
                or selected_filter == "Files" and "file" in kind
                or selected_filter == "Tools" and "tool" in kind
            )
            if not allowed:
                continue
            searchable = (
                f"{event.get('kind', '')} {event.get('text', '')}".lower())
            if query and query not in searchable:
                continue
            markers = []
            if event.get("is_trigger"):
                markers.append("Trigger")
            if event.get("id") in included_ids:
                markers.append("Included in evaluation")
            heading = " · ".join([
                str(event.get("kind", "event")),
                *markers,
            ])
            event_text = str(event.get("text", ""))
            preview = event_text[:4000]
            row_views = [
                self._label(heading, size=10, bold=True),
                self._label(
                    preview + ("…" if len(event_text) > len(preview) else ""),
                    size=10, lines=0, selectable=True),
            ]
            if len(event_text) > len(preview):
                row_views.append(self._button(
                    "Show Full Payload…",
                    lambda _sender, title=heading, text=event_text:
                        self._show_text_window(title, text),
                    role="flat"))
            row = self._stack(row_views, vertical=True, spacing=2)
            row.setAccessibilityLabel_(
                f"{heading}: {preview}"
                + ("; full payload available"
                   if len(event_text) > len(preview) else ""))
            self.context_stack.addArrangedSubview_(row)
        self._context_built = True

    @objc.python_method
    def set_input_mode(self, mode: int) -> None:
        self.input_mode = 1 if mode else 0
        self._refresh_input()

    @objc.python_method
    def toggle_context(self) -> None:
        self.context_expanded = not self.context_expanded
        if self.context_expanded and not self._context_built:
            self._rebuild_context()
        self.context_stack.setHidden_(not self.context_expanded)
        self.context_navigation.setHidden_(not self.context_expanded)
        if self.context_expanded:
            self.context_button.setNextKeyView_(self.context_earlier)
            self.context_earlier.setNextKeyView_(self.context_later)
            self.context_later.setNextKeyView_(self.context_filter)
            self.context_filter.setNextKeyView_(self.context_search)
            self.context_search.setNextKeyView_(self.rule_button)
        else:
            self.context_button.setNextKeyView_(self.rule_button)
        self.context_button.setTitle_(
            "Hide Full Context" if self.context_expanded
            else "Show Full Context")
        self.context_button.setAccessibilityLabel_(
            "Hide Full Context" if self.context_expanded
            else "Show Full Context")

    @objc.python_method
    def _refresh_context_navigation(self) -> None:
        ledger = self.detail.get("ledger") or {}
        start = int(ledger.get("start", 0))
        end = int(ledger.get("end", 0))
        total = int(ledger.get("total", 0))
        self.context_page_label.setStringValue_(
            f"{start + 1 if total else 0}–{end} of {total}")
        self.context_earlier.setEnabled_(bool(ledger.get("has_earlier")))
        self.context_later.setEnabled_(bool(ledger.get("has_later")))

    @objc.python_method
    def page_context(self, direction: int) -> None:
        ledger = self.detail.get("ledger") or {}
        if direction < 0:
            start = max(0, int(ledger.get("start", 0)) - 60)
        else:
            start = int(ledger.get("end", 0))
        finding_id = int((self.detail.get("finding") or {}).get("id", 0))
        if not finding_id:
            return

        def complete(result):
            if not result.get("ok"):
                return

            def apply():
                self.detail["ledger"] = result.get("ledger") or {}
                self.presentation = present_finding(self.detail)
                self._rebuild_context()
                self._refresh_context_navigation()
            _on_main(apply)

        self.model.query({
            "type": "ledger_window",
            "id": finding_id,
            "start": start,
            "limit": 60,
        }, complete)

    @objc.python_method
    def copy_exact_input(self) -> None:
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(
            self.presentation.get("input_text", ""),
            NSPasteboardTypeString)
        complete = bool(
            (self.presentation.get("input") or {}).get("recording_complete"))
        self.input_status.setStringValue_(
            "Copied complete recorded input"
            if complete else
            "Copied recorded fragment · original input is incomplete")

    @objc.python_method
    def edit_rule(self) -> None:
        self.manager.edit_rule(self.detail)

    @objc.python_method
    def mark_reviewed(self) -> None:
        finding = self.detail.get("finding", {})
        fingerprint = finding.get("fingerprint", "")

        def complete(result):
            _on_main(lambda: (
                self.window.close() if result.get("ok")
                else self.meta_label.setStringValue_(
                    result.get("error", "Could not review finding"))
            ))

        self.model.perform({
            "type": "review",
            "fingerprint": fingerprint,
        }, complete)

    @objc.python_method
    def show_artifacts(self, sender) -> None:
        menu = NSMenu.alloc().initWithTitle_("Finding artifacts")
        self._menus.append(menu)
        items = [
            ("View Recorded Rule Spec", self.show_recorded_spec),
            ("View Recorded Python", self.show_recorded_python),
            ("Copy Audit Entry JSON", self.copy_audit_json),
            ("Copy Context JSONL", self.copy_context_jsonl),
            ("Open Audit Log", self.open_audit),
            ("Open Ledger", self.open_ledger),
            ("Copy Rule ID", self.copy_rule_id),
            ("Copy Project Path", self.copy_project_path),
        ]
        for title, callback in items:
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

    def show_recorded_spec(self):
        projection = self.detail.get("recorded_rule_projection") or {}
        self._show_text_window(
            "Recorded Rule Spec", str(projection.get("spec", "")))

    def show_recorded_python(self):
        self._show_text_window(
            "Recorded Rule Python",
            str((self.detail.get("audit") or {}).get("rule_source", "")))

    def copy_audit_json(self):
        self._copy(json.dumps(
            self.detail.get("audit") or {}, indent=2, ensure_ascii=False))

    def copy_context_jsonl(self):
        self._copy("\n".join(
            json.dumps(event, ensure_ascii=False)
            for event in self.presentation["context_events"]))

    def copy_rule_id(self):
        self._copy(str(
            (self.detail.get("finding") or {}).get("rule_id", "")))

    def copy_project_path(self):
        self._copy(self.presentation["project_root"])

    @staticmethod
    def _copy(text: str) -> None:
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
        current = detail.get("current_rule") or {}
        payload = {
            "id": finding.get("rule_id"),
            "project_root": finding.get("project_root"),
            "_finding_context": {
                "finding": finding,
                "evaluation": detail.get("evaluation") or {},
                "rule_changed": detail.get("rule_changed", False),
            },
        }
        if not current.get("definition"):
            source = str((detail.get("audit") or {}).get("rule_source", ""))
            if source and not source.endswith(" ...[truncated]"):
                payload["_recorded_source"] = source
            else:
                return
        self._edit_rule(payload)

    def closed(self, inspector: RAPFindingInspector) -> None:
        for finding_id, value in list(self.inspectors.items()):
            if value is inspector:
                self.inspectors.pop(finding_id, None)
