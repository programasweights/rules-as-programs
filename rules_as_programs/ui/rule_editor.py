"""Function-focused native rule editor backed by canonical Python source."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import objc
from AppKit import (
    NSAlert,
    NSAlertFirstButtonReturn,
    NSAlertSecondButtonReturn,
    NSAlertStyleCritical,
    NSApplication,
    NSBackingStoreBuffered,
    NSButton,
    NSColor,
    NSControlStateValueOff,
    NSControlStateValueOn,
    NSEventModifierFlagCommand,
    NSFont,
    NSMenu,
    NSMenuItem,
    NSPasteboard,
    NSPasteboardTypeString,
    NSScrollView,
    NSSegmentedControl,
    NSSwitchButton,
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

from .. import rules_api, scaffold
from .macos_controls import (
    ButtonRole,
    RAPCommandWindow,
    appkit_text_length,
    style_button,
)
from .model import UIModel

WINDOW_W = 840
WINDOW_H = 720

RUN_OPTIONS = [
    ("message", "Agent replies"),
    ("shell_exec", "Command finishes"),
    ("file_edit", "File changes"),
    ("tool_result", "Tool result"),
    ("session_stop", "Turn ends"),
]
READ_OPTIONS = [
    ("message", "Latest reply"),
    ("thought", "Thoughts"),
    ("shell_exec", "Commands"),
    ("file_edit", "File edits"),
    ("tool_result", "Tool results"),
]


def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


class RAPRuleEditorTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "_callbacks", {}).get(int(sender.tag()))
        if callback:
            callback(sender)


class RAPRuleEditorTextDelegate(NSObject):
    def textDidChange_(self, _notification):
        owner = getattr(self, "owner", None)
        if owner:
            owner.editor_changed()

    def controlTextDidChange_(self, _notification):
        owner = getattr(self, "owner", None)
        if owner:
            owner.editor_changed()


class RAPRuleEditorDocument(NSObject):
    def init(self):
        self = objc.super(RAPRuleEditorDocument, self).init()
        if self is None:
            return None
        self.manager = None
        self.model = None
        self.rule: dict[str, Any] = {}
        self.project_root = ""
        self.rule_id = ""
        self.window = None
        self.editor = None
        self.spec_editor = None
        self.results = None
        self.status_label = None
        self.lifecycle_button = None
        self._callbacks: dict[int, Callable[[Any], None]] = {}
        self._target = RAPRuleEditorTarget.alloc().init()
        self._target._callbacks = self._callbacks
        self._text_delegate = RAPRuleEditorTextDelegate.alloc().init()
        self._text_delegate.owner = self
        self._next_tag = 1
        self._programmatic = False
        self._dirty = False
        self._busy = False
        self._close_after_save = False
        self._rename_confirmed = False
        self._lifecycle_confirmation_state: dict[str, int] | None = None
        self._external_control_state: list[tuple[Any, str, bool]] = []
        self.show_full = False
        self.full_source = ""
        self.function_source = ""
        self.spec = ""
        self.name = ""
        self.original_name = ""
        self.description = ""
        self.allowed_label = "OK"
        self.cases: list[tuple[str, str]] = []
        self.simple_fuzzy = False
        self.managed_fuzzy = False
        self.show_examples = False
        self.on: list[str] = []
        self.inputs: list[str] = []
        self.probes: dict[str, str] = {}
        self.channel = "finding"
        self.severity = "warn"
        self.custom = False
        self.inputs_inferred = False
        self.has_probes = False
        self._advanced_menus: list[NSMenu] = []
        self._key_views: list[Any] = []
        self._has_rendered = False
        self.name_field = None
        self.description_editor = None
        self.cases_editor = None
        self.finding_context: dict[str, Any] | None = None
        self._review_on_activate = False
        return self

    @objc.python_method
    def configure(
        self,
        manager: "RuleEditorManager",
        model: UIModel,
        rule: dict[str, Any],
        project_root: str,
    ) -> None:
        self.manager = manager
        self.model = model
        self.rule = dict(rule)
        self.project_root = project_root
        self.rule_id = str(rule.get("id", "rule"))
        self.finding_context = rule.get("_finding_context")
        self.full_source = str(rule.get("source", ""))
        self._apply_projection(
            rule.get("projection") or rules_api.source_projection(self.full_source))
        self.original_name = self.name
        self._build_window()
        self._render()

    @objc.python_method
    def _apply_projection(self, projection: dict[str, Any]) -> None:
        self.simple_fuzzy = bool(projection.get("simple_fuzzy"))
        self.managed_fuzzy = bool(projection.get("managed_fuzzy"))
        self.custom = (
            not projection.get("ok")
            or bool(projection.get("custom"))
        )
        self.name = str(
            projection.get("name")
            or self.rule.get("name")
            or self.rule.get("title")
            or "Rule"
        )
        self.function_source = projection.get("function_source", self.full_source)
        self.spec = projection.get("spec", "")
        self.description = (
            projection.get("description", "")
            if self.managed_fuzzy else projection.get("spec", "")
        )
        self.allowed_label = str(projection.get("allowed_label", "OK"))
        self.cases = list(projection.get("cases", []))
        self.on = list(projection.get("on", []))
        self.inputs = list(projection.get("inputs", []))
        self.probes = dict(projection.get("probes", {}))
        self.channel = str(projection.get("channel", "finding"))
        self.inputs_inferred = bool(projection.get("inputs_inferred"))
        self.has_probes = bool(projection.get("has_probes"))
        self.severity = str(projection.get("severity", "warn"))
        self.show_full = not self.simple_fuzzy or self.custom

    @objc.python_method
    def _build_window(self) -> None:
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
            | NSWindowStyleMaskMiniaturizable
        )
        self.window = RAPCommandWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, WINDOW_W, WINDOW_H), mask,
            NSBackingStoreBuffered, False)
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
        self.window.setAutorecalculatesKeyViewLoop_(True)
        self.window.setMinSize_((840, 560))
        self.window.setTitle_(f"Rule Editor — {self.name}")

    @objc.python_method
    def _wire(self, control, callback: Callable[[Any], None]):
        tag = self._next_tag
        self._next_tag += 1
        self._callbacks[tag] = callback
        control.setTag_(tag)
        control.setTarget_(self._target)
        control.setAction_("invoke:")
        if hasattr(control, "setNextKeyView_"):
            self._key_views.append(control)
        return control

    @objc.python_method
    def _button(
        self, title, frame, callback, *, role: ButtonRole = "secondary",
        accessibility: str | None = None,
    ):
        button = NSButton.alloc().initWithFrame_(NSMakeRect(*frame))
        button.setTitle_(title)
        style_button(
            button, role=role, accessibility=accessibility)
        return self._wire(button, callback)

    @staticmethod
    def _label(text, frame, size=11, bold=False, color=None):
        label = NSTextField.labelWithString_(str(text))
        label.setFrame_(NSMakeRect(*frame))
        label.setFont_(
            NSFont.boldSystemFontOfSize_(size) if bold
            else NSFont.systemFontOfSize_(size))
        label.setTextColor_(color or NSColor.labelColor())
        return label

    @objc.python_method
    def _checkbox(self, title, frame, checked, callback):
        button = NSButton.alloc().initWithFrame_(NSMakeRect(*frame))
        button.setButtonType_(NSSwitchButton)
        button.setTitle_(title)
        button.setState_(
            NSControlStateValueOn if checked else NSControlStateValueOff)
        button.setEnabled_(not self.custom and not self.show_full)
        return self._wire(button, callback)

    @objc.python_method
    def _text_scroll(self, text, frame):
        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(*frame))
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(True)
        scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        editor = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, frame[2] - 16, frame[3]))
        editor.setRichText_(False)
        editor.setAutomaticQuoteSubstitutionEnabled_(False)
        editor.setAutomaticDashSubstitutionEnabled_(False)
        editor.setAutomaticTextReplacementEnabled_(False)
        editor.setUsesFindBar_(True)
        editor.setAllowsUndo_(True)
        editor.setFont_(NSFont.userFixedPitchFontOfSize_(11.5))
        editor.setDelegate_(self._text_delegate)
        editor.setString_(text)
        scroll.setDocumentView_(editor)
        self._key_views.append(editor)
        return scroll, editor

    @objc.python_method
    def _capture(self) -> None:
        if self._programmatic or not self.editor:
            return
        if self.name_field:
            self.name = str(self.name_field.stringValue()).strip()
        if self.show_full:
            self.full_source = str(self.editor.string())
        elif self.simple_fuzzy:
            if self.description_editor:
                value = str(self.description_editor.string()).strip()
                if self.managed_fuzzy:
                    self.description = value
                else:
                    self.spec = value
                    self.cases = rules_api.spec_examples(value)
            if self.managed_fuzzy and self.cases_editor:
                self.cases = rules_api.spec_examples(
                    str(self.cases_editor.string()))
        else:
            self.function_source = str(self.editor.string())
            if self.spec_editor:
                self.spec = str(self.spec_editor.string())

    @objc.python_method
    def _compose(self) -> tuple[bool, str, str]:
        self._capture()
        if self.show_full or self.custom:
            projection = rules_api.source_projection(self.full_source)
            rule_id = str(projection.get("id") or self.rule_id)
            current_name = str(projection.get("name") or "")
            source = self.full_source
            if self.name and self.name != current_name:
                ok, source, error = rules_api.patch_rule_identity(
                    source, rule_id, self.name)
                if not ok:
                    return False, self.full_source, error
            return True, source, ""
        if self.managed_fuzzy:
            if not self.name:
                return False, self.full_source, "Rule name is required."
            if not self.description:
                return False, self.full_source, "Rule description is required."
            try:
                source = rules_api.generate_managed_fuzzy_source(
                    self.rule_id,
                    self.name,
                    self.description,
                    severity=self.severity,
                    on=self.on,
                    inputs=self.inputs,
                    probes=self.probes,
                    channel=self.channel,
                    cases=self.cases,
                )
            except ValueError as exc:
                return False, self.full_source, str(exc)
            return True, source, ""
        ok, source, error = rules_api.patch_source_projection(
            self.full_source,
            on=self.on,
            inputs=self.inputs,
            severity=self.severity,
            function_source=self.function_source,
            spec=self.spec if self.spec else None,
        )
        if not ok:
            return ok, source, error
        if self.name:
            ok, source, error = rules_api.patch_rule_identity(
                source, self.rule_id, self.name)
        return ok, source, error

    @objc.python_method
    def _control_focus_key(self, view) -> str:
        tag = int(view.tag()) if hasattr(view, "tag") else -1
        return f"{view.__class__.__name__}:{tag}"

    @objc.python_method
    def _capture_focus_state(self) -> tuple[str, int, int] | None:
        if not self.window:
            return None
        responder = self.window.firstResponder()
        if responder is None:
            return None
        name_editor = self.name_field.currentEditor() if self.name_field else None
        if name_editor is not None and responder == name_editor:
            selected = responder.selectedRange()
            return ("name", int(selected.location), int(selected.length))
        candidates = (
            ("description", self.description_editor),
            ("cases", self.cases_editor),
            ("source", self.editor if self.show_full else None),
            ("results", self.results),
        )
        for semantic, view in candidates:
            if view is not None and responder == view:
                selected = responder.selectedRange()
                return (semantic, int(selected.location), int(selected.length))
        for view in self._key_views:
            if responder == view:
                return (f"control:{self._control_focus_key(view)}", 0, 0)
        return None

    @objc.python_method
    def _restore_focus_state(
        self, state: tuple[str, int, int] | None
    ) -> None:
        if not self.window or not self.name_field:
            return
        targets = {
            "description": self.description_editor,
            "cases": self.cases_editor,
            "source": self.editor if self.show_full else None,
            "results": self.results,
        }
        if state is None:
            self.window.setInitialFirstResponder_(self.name_field)
            self.window.makeFirstResponder_(self.name_field)
            if not self._has_rendered and self.rule.get("new_draft"):
                self.name_field.selectText_(None)
            return
        semantic, location, length = state
        if semantic.startswith("control:"):
            focus_key = semantic.removeprefix("control:")
            for view in self._key_views:
                if self._control_focus_key(view) == focus_key:
                    self.window.makeFirstResponder_(view)
                    return
            semantic = "description"
        if semantic == "name":
            self.window.makeFirstResponder_(self.name_field)
            target = self.name_field.currentEditor()
        else:
            target = targets.get(semantic)
            if target is not None:
                self.window.makeFirstResponder_(target)
        if target is None:
            target = self.description_editor or self.editor or self.name_field
            self.window.makeFirstResponder_(target)
        if not hasattr(target, "setSelectedRange_"):
            return
        text_length = appkit_text_length(target.string())
        start = min(max(0, location), text_length)
        size = min(max(0, length), text_length - start)
        selected = NSMakeRange(start, size)
        target.setSelectedRange_(selected)
        if hasattr(target, "scrollRangeToVisible_"):
            target.scrollRangeToVisible_(selected)

    @objc.python_method
    def _finish_key_loop(
        self, focus_state: tuple[str, int, int] | None
    ) -> None:
        if not self.window:
            return
        self.window.recalculateKeyViewLoop()
        key_views = [
            view for view in self._key_views
            if view is not None
            and (not hasattr(view, "isEnabled") or view.isEnabled())
        ]
        for current, following in zip(
            key_views, key_views[1:] + key_views[:1]
        ):
            current.setNextKeyView_(following)
        self._restore_focus_state(focus_state)

    @objc.python_method
    def _lifecycle_action_title(self) -> str:
        if self.rule.get("new_draft"):
            return "Discard Draft"
        if (
            self.rule.get("scope") == "project"
            and self.rule.get("customized_from")
        ):
            return "Use Shared Version…"
        if self.rule.get("is_builtin"):
            return "Remove Installed Rule…"
        if self.rule.get("scope") == "global":
            return "Delete Shared Rule…"
        return "Delete Rule…"

    @objc.python_method
    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        if self.lifecycle_button is not None:
            self.lifecycle_button.setEnabled_(not busy)

    @objc.python_method
    def set_external_lifecycle_pending(self, pending: bool) -> None:
        if pending:
            if self._external_control_state:
                return
            state: list[tuple[Any, str, bool]] = []
            for view in dict.fromkeys(self._key_views):
                if hasattr(view, "isEditable") and hasattr(view, "setEditable_"):
                    state.append((view, "editable", bool(view.isEditable())))
                    view.setEditable_(False)
                elif hasattr(view, "isEnabled") and hasattr(view, "setEnabled_"):
                    state.append((view, "enabled", bool(view.isEnabled())))
                    view.setEnabled_(False)
            self._external_control_state = state
            self.window.makeFirstResponder_(None)
            self._set_busy(True)
            return
        state, self._external_control_state = self._external_control_state, []
        for view, kind, value in state:
            if kind == "editable":
                view.setEditable_(value)
            else:
                view.setEnabled_(value)
        self._set_busy(False)

    @objc.python_method
    def confirm_lifecycle_action(self) -> None:
        if self._busy:
            self._set_result("Wait for the current save or check to finish.")
            return
        if self.rule.get("new_draft") and not self._dirty:
            self.window.close()
            return
        definition = self.rule.get("definition") or {}
        if not self.rule.get("new_draft") and not definition:
            self._set_result("Reload this rule before removing it.")
            return
        reverting = bool(
            self.rule.get("scope") == "project"
            and self.rule.get("customized_from")
        )
        if self.rule.get("new_draft"):
            title = f"Discard draft “{self.name}”?"
            message = "This draft has not been saved, so no rule file will be deleted."
            confirm_title = "Discard Draft"
        elif reverting:
            title = f"Use the shared version of “{self.name}”?"
            message = (
                "This removes only the project customization and preserves this "
                "project's Run/Don't Run assignment."
            )
            confirm_title = "Use Shared Version"
        else:
            title = f"{self._lifecycle_action_title().rstrip('…')} “{self.name}”?"
            message = (
                "This removes exactly this definition. Existing finding and "
                "audit history will be kept."
            )
            confirm_title = (
                "Remove Rule" if self.rule.get("is_builtin") else "Delete Rule")
        source_path = definition.get("source_path", "")
        if source_path:
            message += f"\n\nSource: {source_path}"
        if self.manager and definition:
            state = self.manager.definition_state(definition)
            if state["busy"]:
                self._set_result(
                    "Another editor is saving this definition. Wait for it to finish.")
                return
            if state["dirty"]:
                message += (
                    f"\n\n{state['dirty']} open editor(s) have unsaved changes. "
                    "Those changes will be discarded."
                )
            self._lifecycle_confirmation_state = dict(state)
        else:
            self._lifecycle_confirmation_state = None
        alert = NSAlert.alloc().init()
        alert.setAlertStyle_(NSAlertStyleCritical)
        alert.setMessageText_(title)
        alert.setInformativeText_(message)
        confirm = alert.addButtonWithTitle_(confirm_title)
        if hasattr(confirm, "setContentTintColor_"):
            confirm.setContentTintColor_(NSColor.systemRedColor())
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response == NSAlertFirstButtonReturn:
                self._perform_lifecycle_action()
            else:
                self._lifecycle_confirmation_state = None

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def _perform_lifecycle_action(self) -> None:
        if self._busy:
            self._set_result("Wait for the current save or check to finish.")
            return
        if self.rule.get("new_draft"):
            self._dirty = False
            self.window.setDocumentEdited_(False)
            self.window.close()
            return
        definition = dict(self.rule.get("definition") or {})
        if (
            self.manager
            and definition
            and self._lifecycle_confirmation_state is not None
            and self.manager.definition_state(definition)
            != self._lifecycle_confirmation_state
        ):
            self._lifecycle_confirmation_state = None
            self._set_result(
                "Open editors changed after confirmation. Review and try again.")
            return
        self._lifecycle_confirmation_state = None
        reverting = bool(
            self.rule.get("scope") == "project"
            and self.rule.get("customized_from")
        )
        request = {
            "type": "revert_to_shared" if reverting else "delete_rule",
            "rule_id": self.rule_id,
            "definition": definition,
        }
        if reverting:
            request["project_root"] = (
                definition.get("project_root") or self.project_root)
        if self.manager:
            self.manager.set_definition_pending(definition, True)
        else:
            self._set_busy(True)
        self.status_label.setStringValue_(
            "Using shared version…" if reverting else "Removing rule…")

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    if self.manager:
                        self.manager.set_definition_pending(definition, False)
                    else:
                        self._set_busy(False)
                    self._set_result(
                        result.get("error", "The rule could not be removed."))
                    self.status_label.setStringValue_("Remove failed")
                    return
                self._dirty = False
                self.window.setDocumentEdited_(False)
                if self.manager:
                    self.manager.lifecycle_completed(self, result)
                else:
                    self._set_busy(False)
                self.window.close()
            _on_main(apply)

        self.model.perform(request, complete)

    @objc.python_method
    def _render(self) -> None:
        focus_state = self._capture_focus_state()
        self._capture()
        self._callbacks.clear()
        self._next_tag = 1
        self._key_views = []
        content = self.window.contentView()
        for view in list(content.subviews()):
            view.removeFromSuperview()
        width = content.frame().size.width or WINDOW_W
        height = content.frame().size.height or WINDOW_H

        content.addSubview_(self._label(
            "Name", (18, height - 38, 48, 20), 11, True))
        name_field = NSTextField.alloc().initWithFrame_(
            NSMakeRect(68, height - 44, 430, 27))
        name_field.setStringValue_(self.name)
        name_field.setEditable_(True)
        name_field.setDelegate_(self._text_delegate)
        name_field.setFont_(NSFont.systemFontOfSize_(14))
        name_field.setAutoresizingMask_(NSViewMinYMargin | NSViewWidthSizable)
        content.addSubview_(name_field)
        self.name_field = name_field
        self._key_views.append(name_field)
        scope = self.rule.get("scope", "project")
        if self.rule.get("new_draft"):
            draft = "Draft"
        elif self.rule.get("draft_changes"):
            draft = "Draft changes · previous revision active"
        elif self.rule.get("active_hash"):
            draft = "Active revision"
        elif self.rule.get("enabled"):
            draft = "Enabled legacy source · check to pin revision"
        else:
            draft = "Disabled · needs check"
        content.addSubview_(self._label(
            f"{scope} · {draft} · {Path(self.project_root).name or 'global'}",
            (18, height - 64, 550, 18), 10, False,
            NSColor.secondaryLabelColor()))

        enabled = NSButton.alloc().initWithFrame_(
            NSMakeRect(width - 170, height - 52, 152, 26))
        enabled.setButtonType_(NSSwitchButton)
        enabled.setTitle_(
            "Runs by default"
            if scope == "global" and not self.project_root
            else "Runs in this project")
        enabled.setState_(
            NSControlStateValueOn if self.rule.get("enabled") else NSControlStateValueOff)
        enabled.setEnabled_(
            not self.rule.get("new_draft")
            and bool(self.rule.get("active_hash") or self.rule.get("enabled")))
        enabled.setAutoresizingMask_(NSViewMinXMargin | NSViewMinYMargin)
        self._wire(enabled, lambda sender: self.toggle_enabled(
            sender.state() == NSControlStateValueOn))
        content.addSubview_(enabled)

        controls_y = height - 112
        if self.finding_context:
            finding = self.finding_context.get("finding", {})
            content.addSubview_(self._label(
                "Tune from finding", (18, height - 96, 110, 18), 10, True))
            content.addSubview_(self._label(
                str(finding.get("message", "")).replace("\n", " "),
                (130, height - 98, width - 392, 20), 10, False,
                NSColor.secondaryLabelColor()))
            content.addSubview_(self._button(
                "This should be allowed", (width - 252, height - 103, 132, 27),
                lambda _sender: self.add_finding_case(self.allowed_label)))
            content.addSubview_(self._button(
                "This is a violation", (width - 116, height - 103, 102, 27),
                lambda _sender: self.add_finding_case(
                    self._captured_severity_label())))
            controls_y -= 46
        y = controls_y
        content.addSubview_(self._label("Runs when", (18, y + 3, 72, 20), 10, True))
        x = 92
        for kind, label in RUN_OPTIONS:
            content.addSubview_(self._checkbox(
                label, (x, y, 135, 24), kind in self.on,
                lambda sender, value=kind: self.toggle_metadata(
                    self.on, value, sender.state() == NSControlStateValueOn)))
            x += 142

        y -= 31
        reads_title = "Reads (inferred)" if self.inputs_inferred else "Reads"
        content.addSubview_(self._label(reads_title, (18, y + 3, 90, 20), 10, True))
        x = 92
        for kind, label in READ_OPTIONS:
            content.addSubview_(self._checkbox(
                label, (x, y, 135, 24), kind in self.inputs,
                lambda sender, value=kind: self.toggle_metadata(
                    self.inputs, value, sender.state() == NSControlStateValueOn)))
            x += 142
        if self.has_probes:
            content.addSubview_(self._label(
                "Includes command checks in function",
                (width - 220, y - 18, 205, 16), 9, False,
                NSColor.secondaryLabelColor()))

        mode_y = y - 38
        mode = NSSegmentedControl.alloc().initWithFrame_(
            NSMakeRect(18, mode_y, 210, 26))
        mode.setSegmentCount_(2)
        mode.setLabel_forSegment_("Fuzzy Rule", 0)
        mode.setLabel_forSegment_("Advanced Python", 1)
        mode.setSelectedSegment_(1 if self.show_full else 0)
        mode.setEnabled_forSegment_(self.simple_fuzzy, 0)
        self._wire(mode, lambda sender: self.change_mode(sender.selectedSegment() == 1))
        content.addSubview_(mode)
        if self.managed_fuzzy and not self.show_full:
            content.addSubview_(self._button(
                "Hide examples" if self.show_examples else "Improve with examples",
                (238, mode_y, 160, 26),
                lambda _sender: self.toggle_examples()))
        if self.custom:
            content.addSubview_(self._label(
                "Custom Python — simple fields are read-only",
                (400, mode_y + 4, 320, 18), 10, False,
                NSColor.systemOrangeColor()))

        editor_bottom = 190
        editor_top = mode_y - 10
        self.description_editor = None
        self.cases_editor = None
        self.spec_editor = None
        if self.show_full or not self.simple_fuzzy:
            self._programmatic = True
            editor_scroll, editor = self._text_scroll(
                self.full_source,
                (18, editor_bottom, width - 36, max(150, editor_top - editor_bottom)))
            self._programmatic = False
            content.addSubview_(editor_scroll)
            self.editor = editor
        else:
            if self.managed_fuzzy:
                description_top = editor_top
                content.addSubview_(self._label(
                    "Rule description", (18, description_top - 22, 180, 18),
                    10, True))
                examples_height = 120 if self.show_examples else 0
                description_bottom = editor_bottom + examples_height
                description_height = max(
                    100, description_top - 24 - description_bottom)
                self._programmatic = True
                description_scroll, description_editor = self._text_scroll(
                    self.description,
                    (18, description_bottom, width - 36, description_height))
                self._programmatic = False
                content.addSubview_(description_scroll)
                self.description_editor = description_editor
                self.editor = description_editor
                if self.show_examples:
                    content.addSubview_(self._label(
                        "Input / Output cases",
                        (18, editor_bottom + 96, 180, 18), 10, True))
                    cases_text = "\n\n".join(
                        f"Input: {evidence}\nOutput: {label}"
                        for evidence, label in self.cases)
                    self._programmatic = True
                    cases_scroll, cases_editor = self._text_scroll(
                        cases_text, (18, editor_bottom, width - 36, 92))
                    self._programmatic = False
                    content.addSubview_(cases_scroll)
                    self.cases_editor = cases_editor
            else:
                content.addSubview_(self._label(
                    "PAW Decision", (18, editor_top - 22, 180, 18),
                    10, True))
                self._programmatic = True
                spec_scroll, spec_editor = self._text_scroll(
                    self.spec,
                    (18, editor_bottom, width - 36,
                     max(150, editor_top - editor_bottom - 26)))
                self._programmatic = False
                content.addSubview_(spec_scroll)
                self.description_editor = spec_editor
                self.spec_editor = spec_editor
                self.editor = spec_editor

        results_scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(18, 54, width - 36, 105))
        results_scroll.setHasVerticalScroller_(True)
        results_scroll.setAutoresizingMask_(NSViewWidthSizable)
        results = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, width - 52, 105))
        results.setEditable_(False)
        results.setSelectable_(True)
        results.setRichText_(False)
        results.setFont_(NSFont.userFixedPitchFontOfSize_(10))
        results.setString_(str(self.rule.get("_results", "Ready. Save or Check Rule.")))
        results_scroll.setDocumentView_(results)
        content.addSubview_(results_scroll)
        self.results = results
        self._key_views.append(results)

        lifecycle = self._button(
            self._lifecycle_action_title(), (18, 12, 148, 30),
            lambda _sender: self.confirm_lifecycle_action(),
            role="destructive",
            accessibility=self._lifecycle_action_title().rstrip("…"))
        lifecycle.setEnabled_(not self._busy)
        self.lifecycle_button = lifecycle
        content.addSubview_(lifecycle)
        self.status_label = self._label(
            "Unsaved" if self._dirty else "Ready",
            (174, 18, width - 526, 20), 10, False,
            NSColor.secondaryLabelColor())
        content.addSubview_(self.status_label)
        more = self._button(
            "More", (width - 330, 12, 70, 30), self.show_advanced)
        more.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(more)
        activate_title = (
            "Check & Activate" if self.rule.get("enabled")
            else "Check & Enable"
        )
        check = self._button(
            activate_title, (width - 274, 12, 124, 30),
            lambda _sender: self.save(activate=True))
        check.setKeyEquivalent_("\r")
        check.setKeyEquivalentModifierMask_(NSEventModifierFlagCommand)
        check.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(check)
        save = self._button(
            "Save Draft", (width - 142, 12, 74, 30),
            lambda _sender: self.save())
        save.setKeyEquivalent_("s")
        save.setKeyEquivalentModifierMask_(NSEventModifierFlagCommand)
        save.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(save)
        close = self._button(
            "Close", (width - 62, 12, 54, 30),
            lambda _sender: self.window.performClose_(None))
        close.setKeyEquivalent_("w")
        close.setKeyEquivalentModifierMask_(NSEventModifierFlagCommand)
        close.setAutoresizingMask_(NSViewMinXMargin)
        content.addSubview_(close)
        self._finish_key_loop(focus_state)
        self._has_rendered = True

    @objc.python_method
    def editor_changed(self) -> None:
        if self._programmatic:
            return
        if self.name_field:
            self.name = str(self.name_field.stringValue()).strip()
        self._dirty = True
        self.window.setDocumentEdited_(True)
        if self.status_label:
            function_name = scaffold.slugify(
                self.name or "rule").replace("-", "_")
            self.status_label.setStringValue_(
                f"Unsaved · Python function {function_name}")

    @objc.python_method
    def toggle_metadata(self, values: list[str], value: str, enabled: bool) -> None:
        if enabled and value not in values:
            values.append(value)
        elif not enabled and value in values:
            values.remove(value)
        self.editor_changed()

    @objc.python_method
    def change_mode(self, full: bool) -> None:
        ok, source, error = self._compose()
        if not ok:
            self._set_result(error)
            return
        self.full_source = source
        if not full:
            projection = rules_api.source_projection(self.full_source)
            self._apply_projection(projection)
            if self.custom:
                self._set_result(
                    projection.get("error", "Custom source requires Full Python."))
                return
        self.show_full = full
        self._render()

    @objc.python_method
    def toggle_examples(self) -> None:
        self._capture()
        self.show_examples = not self.show_examples
        self._render()

    @objc.python_method
    def add_finding_case(self, label: str) -> None:
        if not self.simple_fuzzy or not self.finding_context:
            self._set_result(
                "Captured cases require a managed fuzzy rule. Use Advanced Python.")
            return
        evidence = ""
        for item in reversed(self.finding_context.get("trace", [])):
            if item.get("type") == "paw" and item.get("input"):
                evidence = str(item["input"])
                break
            if item.get("type") == "evidence" and item.get("text"):
                evidence = str(item["text"])
                break
        if not evidence:
            self._set_result("No captured evidence is available for this finding.")
            return
        if self.managed_fuzzy:
            if (evidence, label) not in self.cases:
                self.cases.append((evidence, label))
            self.show_examples = True
        else:
            case = f"Input: {evidence}\nOutput: {label}"
            if case not in self.spec:
                self.spec = self.spec.rstrip() + "\n\n" + case
        self._review_on_activate = label == self.allowed_label
        self.editor_changed()
        self._render()

    @objc.python_method
    def _captured_severity_label(self) -> str:
        severity = str(
            (self.finding_context or {}).get("finding", {}).get(
                "severity", "warn")
        ).lower()
        return {
            "info": "INFO",
            "warn": "WARNING",
            "warning": "WARNING",
            "critical": "CRITICAL",
        }.get(severity, "WARNING")

    @objc.python_method
    def _set_result(self, text: str) -> None:
        self.rule["_results"] = text
        if self.results:
            self.results.setString_(text)

    @objc.python_method
    def save(self, activate: bool = False) -> None:
        if self._busy:
            return
        ok, source, error = self._compose()
        if not ok:
            self._set_result(error)
            return
        if (
            self.name != self.original_name
            and not self.rule.get("new_draft")
            and not self._rename_confirmed
        ):
            alert = NSAlert.alloc().init()
            alert.setMessageText_(f"Rename rule to “{self.name}”?")
            alert.setInformativeText_(
                "The immutable ID and folder stay unchanged. The Python "
                "function and matching Shared/project override Names will update; "
                "historical findings keep their recorded Name.")
            alert.addButtonWithTitle_("Rename")
            alert.addButtonWithTitle_("Cancel")

            def completed(response):
                if response == NSAlertFirstButtonReturn:
                    self._rename_confirmed = True
                    self.save(activate=activate)

            alert.beginSheetModalForWindow_completionHandler_(
                self.window, completed)
            return
        self._set_busy(True)
        self.status_label.setStringValue_("Saving…")

        def complete(result):
            def apply():
                self._set_busy(False)
                if not result.get("ok"):
                    self._rename_confirmed = False
                    self._close_after_save = False
                    self._set_result(result.get("error", "Save failed."))
                    self.status_label.setStringValue_("Save failed")
                    return
                old_id = self.rule_id
                self.rule_id = result.get("id", self.rule_id)
                self.rule.update(result)
                self.rule["new_draft"] = False
                saved_source = result.get("source") or source
                self.rule["source"] = saved_source
                self.full_source = saved_source
                self.original_name = self.name
                self._rename_confirmed = False
                self._dirty = False
                self.window.setDocumentEdited_(False)
                self.window.setTitle_(f"Rule Editor — {self.name}")
                self.status_label.setStringValue_("Saved")
                self._set_result(
                    "Draft saved. Previous active revision is unchanged.")
                if self.manager and old_id != self.rule_id:
                    self.manager.renamed(self, old_id, self.rule_id)
                if self._close_after_save:
                    self._close_after_save = False
                    self.window.close()
                else:
                    self._render()
                if activate:
                    self._activate()
            _on_main(apply)

        if self.name != self.original_name and not self.rule.get("new_draft"):
            request = {
                "type": "rename_rule",
                "rule_id": self.rule_id,
                "name": self.name,
                "source": source,
                "project_root": self.project_root,
            }
        else:
            request = {
                "type": "save_rule",
                "rule_id": self.rule_id,
                "source": source,
                "scope": self.rule.get("scope", "project"),
                "project_root": self.project_root,
                "new_draft": bool(self.rule.get("new_draft")),
                "strict": not self.custom,
            }
        self.model.perform(request, complete)

    @objc.python_method
    def _activate(self) -> None:
        self._set_busy(True)
        self._set_result("Checking and preparing rule…")

        def complete(result):
            def apply():
                self._set_busy(False)
                if result.get("ok"):
                    self.rule["enabled"] = bool(result.get("enabled", True))
                    active = result.get("active", {})
                    self.rule["active_hash"] = active.get("source_hash", "")
                    self.rule["working_hash"] = active.get("source_hash", "")
                    self.rule["draft_changes"] = False
                    self._set_result("Active revision is ready.")
                    if self._review_on_activate and self.finding_context:
                        ids = [
                            int(item["id"])
                            for item in self.finding_context.get("occurrences", [])
                            if item.get("id")
                        ]
                        finding_id = self.finding_context.get("finding", {}).get("id")
                        if not ids and finding_id:
                            ids = [int(finding_id)]
                        if ids:
                            self.model.perform({
                                "type": "review",
                                "ids": ids,
                                "reason": "false_positive",
                            })
                        self._review_on_activate = False
                    self._render()
                else:
                    self._set_result(
                        "Check failed — previous active revision still runs.\n"
                        + result.get("error", "Could not activate rule."))
            _on_main(apply)

        self.model.perform({
            "type": "activate_rule",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "enable": True,
        }, complete, timeout=180)

    @objc.python_method
    def check_rule(self) -> None:
        if self._busy:
            return
        ok, source, error = self._compose()
        if not ok:
            self._set_result(error)
            return
        self._set_busy(True)
        self._set_result("Validating source…")

        def validated(result):
            if not result.get("ok"):
                _on_main(lambda: (
                    self._set_busy(False),
                    self._set_result(result.get("error", "Rule is invalid."))))
                return

            def tested(test_result):
                def apply():
                    self._set_busy(False)
                    if not test_result.get("ok"):
                        self._set_result(test_result.get("error", "Check failed."))
                    elif not test_result.get("total"):
                        self._set_result("Source is valid. No PAW Input/Output cases found.")
                    else:
                        rows = [
                            f"[{'PASS' if row.get('ok') else 'FAIL'}] "
                            f"expected={row.get('want')!r} got={row.get('got')!r}"
                            for row in test_result.get("results", [])
                        ]
                        self._set_result(
                            f"{test_result.get('passed')}/{test_result.get('total')} "
                            "PAW cases passed\n" + "\n".join(rows))
                _on_main(apply)
            self.model.perform({
                "type": "test", "rule_id": self.rule_id,
                "project_root": self.project_root, "source": source,
            }, tested, timeout=180)

        self.model.perform({
            "type": "validate_rule", "source": source, "strict": not self.custom,
        }, validated)

    @objc.python_method
    def toggle_enabled(self, enabled: bool) -> None:
        if self.rule.get("new_draft"):
            return
        self.model.set_rule_enabled(
            self.rule_id, self.project_root, enabled,
            name=self.name,
            callback=lambda result: _on_main(
                lambda: self._enabled_result(result, enabled)))

    @objc.python_method
    def _enabled_result(self, result: dict[str, Any], enabled: bool) -> None:
        if result.get("ok"):
            self.rule["enabled"] = enabled
            self._set_result("Rule enabled." if enabled else "Rule disabled.")
        else:
            self._set_result(result.get("error", "Could not change rule state."))
        self._render()

    @objc.python_method
    def show_advanced(self, sender) -> None:
        menu = NSMenu.alloc().initWithTitle_("Advanced")
        self._advanced_menus.append(menu)
        for title, callback, enabled in [
            ("Compile and warm now", self.compile_now, bool(self.spec)),
            ("Open Python file", self.open_external, bool(self.rule.get("path"))),
            ("Copy Python path", self.copy_path, bool(self.rule.get("path"))),
            ("Copy Rule ID", self.copy_rule_id, True),
        ]:
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, "invoke:", "")
            self._wire(item, lambda _sender, fn=callback: fn())
            item.setEnabled_(enabled)
            menu.addItem_(item)
        menu.popUpMenuPositioningItem_atLocation_inView_(
            None, (0, sender.bounds().size.height), sender)

    @objc.python_method
    def compile_now(self) -> None:
        ok, source, error = self._compose()
        if not ok:
            self._set_result(error)
            return
        self._set_result("Compiling and warming…")
        self.model.perform({
            "type": "compile", "rule_id": self.rule_id,
            "project_root": self.project_root, "source": source,
        }, lambda result: _on_main(lambda: self._set_result(
            "PAW rule ready." if result.get("ok")
            else result.get("error", "Compile failed."))), timeout=180)

    @objc.python_method
    def open_external(self) -> None:
        path = str(self.rule.get("path", ""))
        if path:
            NSWorkspace.sharedWorkspace().openFile_(path)

    @objc.python_method
    def copy_path(self) -> None:
        path = str(self.rule.get("path", ""))
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(path, NSPasteboardTypeString)
        self._set_result("Path copied.")

    @objc.python_method
    def copy_rule_id(self) -> None:
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(self.rule_id, NSPasteboardTypeString)
        self._set_result(f"Rule ID {self.rule_id} copied.")

    @objc.python_method
    def show(self) -> None:
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        self.window.makeKeyAndOrderFront_(None)
        self.window.center()

    def windowShouldClose_(self, _sender):
        if self._busy:
            self._set_result("Wait for the current save or check to finish.")
            return False
        if not self._dirty:
            return True
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Save changes to this rule?")
        alert.setInformativeText_("The Python draft has unsaved changes.")
        alert.addButtonWithTitle_("Save")
        alert.addButtonWithTitle_("Discard")
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response == NSAlertFirstButtonReturn:
                self._close_after_save = True
                self.save()
            elif response == NSAlertSecondButtonReturn:
                self._dirty = False
                self.window.close()
        alert.beginSheetModalForWindow_completionHandler_(self.window, completed)
        return False

    def windowWillClose_(self, _notification):
        if self.manager:
            self.manager.closed(self)


class RuleEditorManager:
    def __init__(
        self,
        model: UIModel,
        on_changed: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.model = model
        self.on_changed = on_changed
        self.documents: dict[tuple[str, str], RAPRuleEditorDocument] = {}
        self._pending_sources: set[str] = set()

    def open(self, rule: dict[str, Any], project_root: str) -> None:
        key = (project_root or "", str(rule.get("id", "rule")))
        document = self.documents.get(key)
        if document is None:
            document = RAPRuleEditorDocument.alloc().init()
            document.configure(self, self.model, rule, project_root)
            self.documents[key] = document
        source_path = str(
            (document.rule.get("definition") or {}).get("source_path", ""))
        if source_path in self._pending_sources:
            document.set_external_lifecycle_pending(True)
        document.show()

    def closed(self, document: RAPRuleEditorDocument) -> None:
        for key, value in list(self.documents.items()):
            if value is document:
                self.documents.pop(key, None)

    def renamed(
        self, document: RAPRuleEditorDocument, old_id: str, new_id: str
    ) -> None:
        self.documents.pop((document.project_root, old_id), None)
        self.documents[(document.project_root, new_id)] = document

    def lifecycle_completed(
        self, document: RAPRuleEditorDocument, result: dict[str, Any]
    ) -> None:
        self.definition_removed(document.rule.get("definition") or {})
        if self.on_changed:
            self.on_changed(result)

    def definition_state(self, definition: dict[str, Any]) -> dict[str, int]:
        source_path = str(definition.get("source_path", ""))
        matching = [
            document for document in self.documents.values()
            if str((document.rule.get("definition") or {}).get(
                "source_path", "")) == source_path
        ]
        return {
            "open": len(matching),
            "dirty": sum(bool(document._dirty) for document in matching),
            "busy": sum(bool(document._busy) for document in matching),
        }

    def set_definition_pending(
        self, definition: dict[str, Any], pending: bool
    ) -> None:
        source_path = str(definition.get("source_path", ""))
        if not source_path:
            return
        if pending:
            self._pending_sources.add(source_path)
        else:
            self._pending_sources.discard(source_path)
        for document in list(self.documents.values()):
            current = document.rule.get("definition") or {}
            if str(current.get("source_path", "")) == source_path:
                document.set_external_lifecycle_pending(pending)

    def definition_removed(self, definition: dict[str, Any]) -> None:
        source_path = str(definition.get("source_path", ""))
        if not source_path:
            return
        self._pending_sources.discard(source_path)
        for document in list(self.documents.values()):
            current = document.rule.get("definition") or {}
            if str(current.get("source_path", "")) != source_path:
                continue
            document.set_external_lifecycle_pending(False)
            document._dirty = False
            document.window.setDocumentEdited_(False)
            document.window.close()
