"""Resizable native inspector for one finding, its rule, and event context."""

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
    NSPasteboard,
    NSPasteboardTypeString,
    NSScrollView,
    NSTextField,
    NSTextView,
    NSViewHeightSizable,
    NSViewMinXMargin,
    NSViewMinYMargin,
    NSViewWidthSizable,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable,
    NSWindowStyleMaskResizable,
    NSWindowStyleMaskTitled,
    NSWorkspace,
)
from Foundation import NSMakeRange, NSMakeRect, NSObject
from PyObjCTools import AppHelper

from .. import config
from .macos_controls import (
    ButtonRole,
    RAPCommandWindow,
    RAPHoverButton,
    appkit_text_length,
    style_button,
)
from .macos_views import RAPFlippedView
from .model import UIModel

WINDOW_W = 820
WINDOW_H = 720
PAD = 18


def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


class RAPInspectorTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "_callbacks", {}).get(int(sender.tag()))
        if callback:
            callback()


class RAPFindingInspector(NSObject):
    def init(self):
        self = objc.super(RAPFindingInspector, self).init()
        if self is None:
            return None
        self.manager = None
        self.model = None
        self.detail: dict[str, Any] = {}
        self.window = None
        self.content_scroll = None
        self.raw_view = None
        self.rule_view = None
        self._key_views: list[Any] = []
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._target = RAPInspectorTarget.alloc().init()
        self._target._callbacks = self._callbacks
        self._next_tag = 1
        self.raw_json = False
        self.show_python = False
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
        self._build_window()
        self._render()

    @objc.python_method
    def _build_window(self) -> None:
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
            | NSWindowStyleMaskMiniaturizable
        )
        self.window = RAPCommandWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, WINDOW_W, WINDOW_H),
            mask,
            NSBackingStoreBuffered,
            False,
        )
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
        self.window.setAutorecalculatesKeyViewLoop_(True)
        self.window.setMinSize_((650, 520))
        self.window.setTitle_("Finding Inspector")

    @objc.python_method
    def _wire(self, button: NSButton, callback: Callable[[], None]) -> NSButton:
        tag = self._next_tag
        self._next_tag += 1
        self._callbacks[tag] = callback
        button.setTag_(tag)
        button.setTarget_(self._target)
        button.setAction_("invoke:")
        self._key_views.append(button)
        return button

    @objc.python_method
    def _button(
        self, title: str, frame: tuple[float, float, float, float],
        callback: Callable[[], None], *, focus_id: str,
        role: ButtonRole = "secondary",
    ) -> NSButton:
        button_class = (
            RAPHoverButton if role in ("flat", "icon") else NSButton)
        button = button_class.alloc().initWithFrame_(NSMakeRect(*frame))
        button.setTitle_(title)
        button.setIdentifier_(focus_id)
        style_button(button, role=role)
        return self._wire(button, callback)

    @staticmethod
    def _label(
        text: str,
        frame: tuple[float, float, float, float],
        *,
        size: float = 11,
        bold: bool = False,
        color=None,
        lines: int = 1,
        mono: bool = False,
    ) -> NSTextField:
        label = NSTextField.labelWithString_(str(text))
        label.setFrame_(NSMakeRect(*frame))
        label.setFont_(
            NSFont.userFixedPitchFontOfSize_(size) if mono
            else NSFont.boldSystemFontOfSize_(size) if bold
            else NSFont.systemFontOfSize_(size))
        label.setTextColor_(color or NSColor.labelColor())
        label.setMaximumNumberOfLines_(lines)
        if lines > 1:
            label.cell().setWraps_(True)
            label.cell().setScrollable_(False)
        return label

    @objc.python_method
    def _text_view(
        self, text: str, frame: tuple[float, float, float, float]
    ) -> tuple[NSScrollView, NSTextView]:
        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(*frame))
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(True)
        view = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, frame[2] - 16, frame[3]))
        view.setEditable_(False)
        view.setSelectable_(True)
        view.setRichText_(False)
        view.setFont_(NSFont.userFixedPitchFontOfSize_(10.5))
        view.setString_(text)
        scroll.setDocumentView_(view)
        self._key_views.append(view)
        return scroll, view

    @objc.python_method
    def _control_focus_key(self, view) -> str:
        if hasattr(view, "identifier") and view.identifier():
            return str(view.identifier())
        tag = int(view.tag()) if hasattr(view, "tag") else -1
        return f"{view.__class__.__name__}:{tag}"

    @objc.python_method
    def _capture_focus_state(self) -> tuple[str, int, int] | None:
        responder = self.window.firstResponder() if self.window else None
        for semantic, view in (
            ("rule", self.rule_view),
            ("raw", self.raw_view),
        ):
            if responder is not None and view is not None and responder == view:
                selected = responder.selectedRange()
                return (semantic, int(selected.location), int(selected.length))
        for view in self._key_views:
            if responder == view:
                return (f"control:{self._control_focus_key(view)}", 0, 0)
        return None

    @objc.python_method
    def _finish_key_loop(
        self, focus_state: tuple[str, int, int] | None, scroll_y: float
    ) -> None:
        self.window.recalculateKeyViewLoop()
        for current, following in zip(
            self._key_views, self._key_views[1:] + self._key_views[:1]
        ):
            current.setNextKeyView_(following)
        if focus_state is None:
            if self._key_views:
                self.window.setInitialFirstResponder_(self._key_views[0])
        else:
            semantic, location, length = focus_state
            if semantic.startswith("control:"):
                focus_key = semantic.removeprefix("control:")
                matched = False
                for view in self._key_views:
                    if self._control_focus_key(view) == focus_key:
                        self.window.makeFirstResponder_(view)
                        matched = True
                        break
                if not matched and self._key_views:
                    self.window.makeFirstResponder_(self._key_views[0])
                target = None
            else:
                target = self.rule_view if semantic == "rule" else self.raw_view
            if target is None:
                if not semantic.startswith("control:") and self._key_views:
                    self.window.makeFirstResponder_(self._key_views[0])
            else:
                self.window.makeFirstResponder_(target)
                text_length = appkit_text_length(target.string())
                start = min(max(0, location), text_length)
                size = min(max(0, length), text_length - start)
                selected = NSMakeRange(start, size)
                target.setSelectedRange_(selected)
                target.scrollRangeToVisible_(selected)
        if self.content_scroll is not None:
            clip = self.content_scroll.contentView()
            document = self.content_scroll.documentView()
            maximum = max(
                0.0,
                float(document.frame().size.height - clip.bounds().size.height),
            )
            clip.scrollToPoint_((0, min(max(0.0, scroll_y), maximum)))
            self.content_scroll.reflectScrolledClipView_(clip)

    @objc.python_method
    def _render(self) -> None:
        focus_state = self._capture_focus_state()
        scroll_y = (
            float(self.content_scroll.contentView().bounds().origin.y)
            if self.content_scroll is not None else 0.0
        )
        self._callbacks.clear()
        self._next_tag = 1
        self._key_views = []
        self.rule_view = None
        self.raw_view = None
        content = RAPFlippedView.alloc().initWithFrame_(
            NSMakeRect(0, 0, WINDOW_W, WINDOW_H))
        content.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        self.window.setContentView_(content)

        finding = self.detail.get("finding", {})
        title = finding.get("rule_title") or finding.get("rule_id", "Finding")
        severity = str(finding.get("severity", "info")).upper()
        project = Path(finding.get("project_root", "")).name
        content.addSubview_(self._label(
            title, (PAD, 14, 470, 26), size=17, bold=True))
        content.addSubview_(self._label(
            f"{severity} · {project} · {len(self.detail.get('occurrences', [])) or 1} occurrence(s)",
            (PAD, 42, 520, 18), size=10, color=NSColor.secondaryLabelColor()))
        edit = self._button(
            "Tune Rule", (WINDOW_W - 210, 16, 92, 30),
            lambda: self.manager.edit_rule(self.detail),
            focus_id="header.tune-rule")
        edit.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(edit)
        reviewed = self._button(
            "Mark Reviewed", (WINDOW_W - 112, 16, 98, 30),
            self.mark_reviewed, focus_id="header.mark-reviewed",
            role="primary")
        reviewed.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(reviewed)

        document_height = 1060
        scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(0, 70, WINDOW_W, WINDOW_H - 70))
        scroll.setHasVerticalScroller_(True)
        scroll.setDrawsBackground_(False)
        scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        document = RAPFlippedView.alloc().initWithFrame_(
            NSMakeRect(0, 0, WINDOW_W, document_height))
        document.setAutoresizingMask_(NSViewWidthSizable)
        scroll.setDocumentView_(document)
        content.addSubview_(scroll)
        self.content_scroll = scroll

        y = 18
        y = self._section(
            document, y, "Why it was flagged",
            str(finding.get("message", "")), height=54)
        decision = next(
            (str(item.get("output", "")) for item in reversed(
                self.detail.get("trace", [])) if item.get("type") == "paw"), "")
        if decision:
            y = self._section(document, y, "Decision", decision, height=34, mono=True)

        current_rule = self.detail.get("current_rule", {})
        audit = self.detail.get("audit") or {}
        snapshot_source = audit.get("rule_source", "")
        current_source = current_rule.get("source", "")
        source = snapshot_source or current_source
        projection = (
            self.detail.get("recorded_rule_projection")
            if snapshot_source else self.detail.get("current_rule_projection")
        ) or {}
        spec = str(projection.get("spec", ""))
        provenance = "Rule at the time of this finding" if snapshot_source else "Current rule source"
        if self.detail.get("rule_changed"):
            provenance += " · current rule has changed"
        runs = ", ".join(current_rule.get("on", []) or []) or "custom"
        reads = ", ".join(current_rule.get("inputs", []) or []) or "defined in Python"
        rule_copy = (
            f"{provenance}\nScope: {audit.get('rule_scope') or current_rule.get('scope', '')}"
            f"\nRuns when: {runs}\nReads: {reads}"
        )
        y = self._section(document, y, "Rule that ran", rule_copy, height=72)
        if source:
            document.addSubview_(self._button(
                (
                    "View PAW spec" if self.show_python and spec
                    else "Hide Python" if self.show_python
                    else "View Python"
                ),
                (PAD, y, 110, 26), self.toggle_source,
                focus_id="rule.toggle-source", role="flat"))
        document.addSubview_(self._button(
            "Tune Rule", (PAD + 118, y, 90, 26),
            lambda: self.manager.edit_rule(self.detail),
            focus_id="rule.tune", role="flat"))
        y += 36
        rule_text = source if self.show_python else spec
        rule_heading = "Python source" if self.show_python else "PAW rule specification"
        if not rule_text and not self.show_python:
            rule_text = "Custom Python rule — no PAW specification."
        document.addSubview_(self._label(
            rule_heading, (PAD, y, 220, 18), size=10, bold=True))
        y += 22
        rule_scroll, rule_view = self._text_view(
            rule_text, (PAD, y, WINDOW_W - 2 * PAD, 180))
        rule_scroll.setAutoresizingMask_(NSViewWidthSizable)
        document.addSubview_(rule_scroll)
        self.rule_view = rule_view
        y += 196

        timeline = self._readable_timeline()
        y = self._section(document, y, "Evidence timeline", timeline, height=190, mono=True)
        document.addSubview_(self._label(
            "Raw event log", (PAD, y, 180, 20), size=12, bold=True))
        document.addSubview_(self._button(
            "Copy", (WINDOW_W - 190, y - 4, 66, 26),
            self.copy_raw, focus_id="raw.copy", role="flat"))
        document.addSubview_(self._button(
            "JSON" if not self.raw_json else "Readable",
            (WINDOW_W - 116, y - 4, 96, 26),
            self.toggle_raw, focus_id="raw.toggle-format", role="flat"))
        y += 26
        raw_text = self._raw_log_text()
        raw_scroll, raw_view = self._text_view(
            raw_text, (PAD, y, WINDOW_W - 2 * PAD, 240))
        raw_scroll.setAutoresizingMask_(NSViewWidthSizable)
        document.addSubview_(raw_scroll)
        self.raw_view = raw_view
        y += 250
        ledger = self.detail.get("ledger", {})
        if ledger.get("has_earlier"):
            document.addSubview_(self._button(
                "Load earlier", (PAD, y, 92, 26),
                self.load_earlier, focus_id="ledger.load-earlier", role="flat"))
        document.addSubview_(self._button(
            "Jump to trigger", (PAD + 100, y, 110, 26),
            self.jump_to_trigger, focus_id="ledger.jump-trigger", role="flat"))
        if ledger.get("has_later"):
            document.addSubview_(self._button(
                "Load later", (PAD + 218, y, 88, 26),
                self.load_later, focus_id="ledger.load-later", role="flat"))
        document.addSubview_(self._button(
            "Open audit log", (WINDOW_W - 282, y, 116, 26),
            self.open_audit, focus_id="ledger.open-audit", role="flat"))
        document.addSubview_(self._button(
            "Open full ledger", (WINDOW_W - 158, y, 138, 26),
            self.open_ledger, focus_id="ledger.open-full", role="flat"))
        document.setFrameSize_((WINDOW_W, max(document_height, y + 50)))
        self._finish_key_loop(focus_state, scroll_y)

    @objc.python_method
    def _section(
        self, parent, y: float, title: str, body: str,
        *, height: float, mono: bool = False,
    ) -> float:
        parent.addSubview_(self._label(
            title, (PAD, y, WINDOW_W - 2 * PAD, 20), size=12, bold=True))
        y += 24
        parent.addSubview_(self._label(
            body, (PAD, y, WINDOW_W - 2 * PAD, height), size=10.5,
            lines=max(2, int(height // 15)), mono=mono,
            color=NSColor.secondaryLabelColor() if not mono else NSColor.labelColor()))
        return y + height + 18

    @objc.python_method
    def _readable_timeline(self) -> str:
        rows = []
        for event in self.detail.get("ledger", {}).get("events", []):
            marker = "→ TRIGGER" if event.get("is_trigger") else " "
            rows.append(f"{marker} [{event.get('kind', 'event')}] {event.get('text', '')}")
        probes = []
        for item in self.detail.get("trace", []):
            if item.get("type") == "run":
                probes.append(f"[probe] $ {item.get('cmd', '')}\n{item.get('output', '')}")
        return "\n\n".join([*rows, *probes]) or "(no event context captured)"

    @objc.python_method
    def _raw_log_text(self) -> str:
        events = self.detail.get("ledger", {}).get("events", [])
        if self.raw_json:
            return "\n".join(json.dumps(event, ensure_ascii=False) for event in events)
        return self._readable_timeline()

    @objc.python_method
    def toggle_source(self) -> None:
        self.show_python = not self.show_python
        self._render()

    @objc.python_method
    def toggle_raw(self) -> None:
        self.raw_json = not self.raw_json
        self._render()

    @objc.python_method
    def copy_raw(self) -> None:
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(self._raw_log_text(), NSPasteboardTypeString)

    @objc.python_method
    def mark_reviewed(self) -> None:
        finding = self.detail.get("finding", {})
        ids = [int(item["id"]) for item in self.detail.get("occurrences", []) if item.get("id")]
        ids = ids or [int(finding.get("id", 0))]

        def complete(result):
            _on_main(lambda: (
                self.window.close() if result.get("ok")
                else self.window.setTitle_(result.get("error", "Could not review finding"))
            ))
        self.model.done(ids, complete)

    @objc.python_method
    def _load_window(self, start: int) -> None:
        finding_id = self.detail.get("finding", {}).get("id")

        def complete(result):
            def apply():
                if result.get("ok"):
                    self.detail["ledger"] = result["ledger"]
                    self._render()
            _on_main(apply)
        self.model.perform({
            "type": "ledger_window", "id": finding_id,
            "start": max(0, start), "limit": 60,
        }, complete)

    @objc.python_method
    def load_earlier(self) -> None:
        self._load_window(int(self.detail.get("ledger", {}).get("start", 0)) - 60)

    @objc.python_method
    def load_later(self) -> None:
        self._load_window(int(self.detail.get("ledger", {}).get("end", 0)))

    @objc.python_method
    def jump_to_trigger(self) -> None:
        if not self.raw_view:
            return
        text = str(self.raw_view.string())
        needle = "TRIGGER" if not self.raw_json else '"is_trigger": true'
        index = text.find(needle)
        if index >= 0:
            self.raw_view.setSelectedRange_((index, len(needle)))
            self.raw_view.scrollRangeToVisible_((index, len(needle)))

    @objc.python_method
    def open_ledger(self) -> None:
        path = self.detail.get("ledger", {}).get("path", "")
        if path:
            NSWorkspace.sharedWorkspace().openFile_(path)

    @objc.python_method
    def open_audit(self) -> None:
        project = self.detail.get("finding", {}).get("project_root", "")
        path = config.project_log_file(project)
        if path.exists():
            NSWorkspace.sharedWorkspace().openFile_(str(path))

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
        finding_id = int(detail.get("finding", {}).get("id", 0))
        inspector = self.inspectors.get(finding_id)
        if inspector is None:
            inspector = RAPFindingInspector.alloc().init()
            inspector.configure(self, self.model, detail)
            self.inspectors[finding_id] = inspector
        else:
            inspector.detail = detail
            inspector._render()
        inspector.show()

    def edit_rule(self, detail: dict[str, Any]) -> None:
        finding = detail.get("finding", {})
        self._edit_rule({
            "id": finding.get("rule_id"),
            "project_root": finding.get("project_root"),
            "_finding_context": detail,
        })

    def closed(self, inspector: RAPFindingInspector) -> None:
        for finding_id, value in list(self.inspectors.items()):
            if value is inspector:
                self.inspectors.pop(finding_id, None)
