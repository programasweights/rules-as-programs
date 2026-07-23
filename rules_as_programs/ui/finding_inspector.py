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
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskMiniaturizable,
    NSWindowStyleMaskResizable,
    NSWindowStyleMaskTitled,
    NSWorkspace,
)
from Foundation import NSMakeRect, NSObject
from PyObjCTools import AppHelper

from .. import config
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
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._target = RAPInspectorTarget.alloc().init()
        self._target._callbacks = self._callbacks
        self._next_tag = 1
        self.raw_json = False
        self.show_source = True
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
        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, WINDOW_W, WINDOW_H),
            mask,
            NSBackingStoreBuffered,
            False,
        )
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
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
        return button

    @objc.python_method
    def _button(
        self, title: str, frame: tuple[float, float, float, float],
        callback: Callable[[], None],
    ) -> NSButton:
        button = NSButton.alloc().initWithFrame_(NSMakeRect(*frame))
        button.setTitle_(title)
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
        return scroll, view

    @objc.python_method
    def _render(self) -> None:
        self._callbacks.clear()
        self._next_tag = 1
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
            lambda: self.manager.edit_rule(self.detail))
        edit.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(edit)
        reviewed = self._button(
            "Mark Reviewed", (WINDOW_W - 112, 16, 98, 30), self.mark_reviewed)
        reviewed.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(reviewed)

        document_height = 1060 if self.show_source else 850
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
        document.addSubview_(self._button(
            "Hide Python" if self.show_source else "View Python",
            (PAD, y, 100, 26), self.toggle_source))
        document.addSubview_(self._button(
            "Tune Rule", (PAD + 108, y, 90, 26),
            lambda: self.manager.edit_rule(self.detail)))
        y += 36
        if self.show_source:
            source_scroll, _source_view = self._text_view(
                source or "(source unavailable)", (PAD, y, WINDOW_W - 2 * PAD, 180))
            source_scroll.setAutoresizingMask_(NSViewWidthSizable)
            document.addSubview_(source_scroll)
            y += 196

        timeline = self._readable_timeline()
        y = self._section(document, y, "Evidence timeline", timeline, height=190, mono=True)
        document.addSubview_(self._label(
            "Raw event log", (PAD, y, 180, 20), size=12, bold=True))
        document.addSubview_(self._button(
            "Copy", (WINDOW_W - 190, y - 4, 66, 26), self.copy_raw))
        document.addSubview_(self._button(
            "JSON" if not self.raw_json else "Readable",
            (WINDOW_W - 116, y - 4, 96, 26), self.toggle_raw))
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
                "Load earlier", (PAD, y, 92, 26), self.load_earlier))
        document.addSubview_(self._button(
            "Jump to trigger", (PAD + 100, y, 110, 26), self.jump_to_trigger))
        if ledger.get("has_later"):
            document.addSubview_(self._button(
                "Load later", (PAD + 218, y, 88, 26), self.load_later))
        document.addSubview_(self._button(
            "Open audit log", (WINDOW_W - 282, y, 116, 26), self.open_audit))
        document.addSubview_(self._button(
            "Open full ledger", (WINDOW_W - 158, y, 138, 26), self.open_ledger))
        document.setFrameSize_((WINDOW_W, max(document_height, y + 50)))

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
        self.show_source = not self.show_source
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
